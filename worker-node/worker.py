# LIVE QUEUE WORKER + DASHBOARD REPORTING
# Flow: receive SQS reference -> download S3 JSON -> validate -> commit to
# PostgreSQL -> acknowledge/delete SQS message. Failed tasks stay for retry.
# Changes from the prototype: Docker service configuration, stricter validation,
# safe nested S3 keys, transaction-based writes without a global Redis lock,
# and worker heartbeats/events for the dashboard. No autoscaling is performed.
# PostgreSQL correctness and Redis monitoring are separate responsibilities.

import json
import logging
import math
import os
import time
import socket
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

import boto3
import psycopg2
import redis
from botocore.config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# Each container gets its own hostname; this identifies the reporting instance.
# Recreating a container may change it. This is not a Kubernetes replica count.
WORKER_ID = socket.gethostname()

ENDPOINT = os.getenv("AWS_ENDPOINT", "http://localstack:4566")

# The socket read timeout exceeds the 20-second SQS long-poll wait below.
# AWS credentials/region are supplied through Compose environment variables.
sqs = boto3.client(
    "sqs",
    endpoint_url=ENDPOINT,
    config=Config(
        connect_timeout=5,
        read_timeout=25,
        retries={"max_attempts": 2},
    ),
)

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    config=Config(
        connect_timeout=5,
        read_timeout=10,
        retries={"max_attempts": 2},
    ),
)

# Redis is used only for best-effort UI reporting here, not a database mutex
# or an authoritative processed-task ledger. Short timeouts limit its impact.
monitor = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    decode_responses=True,
    socket_connect_timeout=0.5,
    socket_timeout=0.5,
)

worker_state = {
    "id": WORKER_ID,
    "status": "idle",
    "task": None,
}

# Inside Docker use postgres:5432; Windows pgAdmin uses the published host
# port (currently 5433). Query/lock timeouts bound common database stalls.
DB_PARAMS = {
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB", "dataclean_db"),
    "user": os.getenv("POSTGRES_USER", "admin"),
    "password": os.environ["POSTGRES_PASSWORD"],
    "connect_timeout": 5,
    "options": "-c statement_timeout=15000 -c lock_timeout=5000",
}

queue_url = sqs.get_queue_url(QueueName="task-queue")["QueueUrl"]

# This lock protects shared state within THIS Python process only.
# It does not serialize database writes across workers like the old Redis lock.
state_lock = threading.Lock()

# Reject booleans (Python otherwise treats them as integers), numeric strings,
# NaN and infinity so malformed values cannot silently enter the database.
def numeric(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")

    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")

    return float(value)


# Validate required fields and normalize types. This does not repair missing
# GPS data or infer real speeds. Invalid records raise and follow retry/DLQ flow.
# Return values are in the exact order used by the INSERT placeholders below.
def clean_record(content):
    data = json.loads(content)

    if not isinstance(data, dict):
        raise ValueError("Record must be a JSON object")

    vehicle_id = data.get("vehicle_id")
    if (
        not isinstance(vehicle_id, str)
        or not vehicle_id.strip()
        or len(vehicle_id.strip()) > 50
    ):
        raise ValueError("Invalid camera identifier")

    latitude = numeric(data.get("latitude"), "latitude")
    longitude = numeric(data.get("longitude"), "longitude")
    speed = numeric(data.get("speed_kmh"), "speed_kmh")

    if not -90 <= latitude <= 90:
        raise ValueError("Latitude outside valid range")

    if not -180 <= longitude <= 180:
        raise ValueError("Longitude outside valid range")

    if not 0 <= speed <= 300 or not speed.is_integer():
        raise ValueError("Invalid speed placeholder/value")

    timestamp = data.get("timestamp")
    if not isinstance(timestamp, str):
        raise ValueError("Missing timestamp")

    observed_at = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    # A timezone-aware input is normalized to UTC. A naive input is preserved;
    # our current producer emits naive UTC, so other producers must do likewise.
    if observed_at.tzinfo is not None:
        observed_at = (
            observed_at.astimezone(timezone.utc)
            .replace(tzinfo=None)
        )

    return (
        vehicle_id.strip(),
        observed_at,
        latitude,
        longitude,
        int(speed),
    )


# One latest row per camera, not a historical row for every message.
# The UNIQUE(vehicle_id) constraint and atomic UPSERT make repeat delivery safe.
# Older/equal timestamps leave the current row untouched, avoiding stale retries
# overwriting newer data. rowcount=0 therefore means a successful no-op.
def store_record(record):
    connection = psycopg2.connect(**DB_PARAMS)

    try:
        # Commit on success; rollback if an exception escapes.
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO cleansed_traffic
                        (
                            vehicle_id,
                            recorded_timestamp,
                            latitude,
                            longitude,
                            speed_kmh
                        )
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (vehicle_id)
                    DO UPDATE SET
                        recorded_timestamp = EXCLUDED.recorded_timestamp,
                        latitude = EXCLUDED.latitude,
                        longitude = EXCLUDED.longitude,
                        speed_kmh = EXCLUDED.speed_kmh,
                        processed_at = CURRENT_TIMESTAMP
                    WHERE EXCLUDED.recorded_timestamp
                          > cleansed_traffic.recorded_timestamp
                    """,
                    record,
                )
                changed = cursor.rowcount

        return changed
    finally:
        connection.close()


# A heartbeat proves this process is reporting, not that all dependencies work.
# Hold the local lock through publication so an older snapshot cannot overwrite
# a newer processing state. The API marks reports older than 15s unavailable;
# Redis expires the entry after 120s. Neither timeout proves Kubernetes deletion.
def publish_heartbeat():
    try:
        with state_lock:
            snapshot = dict(worker_state)
            snapshot["last_seen"] = time.time()
            # Keep an expired worker visible briefly as "unavailable".
            # After 120 seconds without a report, remove it from discovery.
            monitor.set(
                f"dataclean:worker:{WORKER_ID}",
                json.dumps(snapshot),
                ex=120,
            )
    except redis.RedisError:
        # Monitoring failure must not discard processing tasks.
        pass


# Publish transitions immediately; the background loop also refreshes them
# while this thread waits on SQS/S3/PostgreSQL. task is the SQS message ID.
def report_status(status, task=None):
    with state_lock:
        worker_state["status"] = status
        worker_state["task"] = task

    publish_heartbeat()


# Redis Streams retain recent event IDs so browser polls can deduplicate them.
# Approximate trimming keeps roughly 1,000 entries; this is not an audit log.
# Events may be missing during Redis outages. Processing must continue anyway.
def report_event(kind, task, detail=""):
    try:
        monitor.xadd(
            "dataclean:events",
            {
                "source": "worker",
                "worker_id": WORKER_ID,
                "kind": kind,
                "task": task or "",
                "detail": str(detail)[:200],
                "timestamp": str(time.time()),
            },
            maxlen=1000,
            approximate=True,
        )
    except redis.RedisError:
        pass


def heartbeat_loop():
    # Separate thread: stays alive during SQS long polling.
    while True:
        publish_heartbeat()
        time.sleep(3)


# Define all helpers and start reporting BEFORE entering the infinite loop.
# The daemon thread exits with the worker process; it does not create new workers.
threading.Thread(
    target=heartbeat_loop,
    name="worker-heartbeat",
    daemon=True,
).start()

logging.info("Worker %s started; waiting for tasks", WORKER_ID)

# Each instance claims one message at a time; multiple instances compete on SQS.
# Visibility is a temporary lease, not an exactly-once guarantee. This version
# does not extend the lease for tasks taking longer than 120s, so duplicate
# processing remains possible and database idempotency is still necessary.
while True:
    try:
        response = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
            VisibilityTimeout=120,
        )
    except Exception as exc:
        report_status("queue unavailable")
        logging.error("Queue polling failed: %s", exc)
        time.sleep(5)
        continue

    if not response.get("Messages"):
        report_status("idle")

    for message in response.get("Messages", []):

        task_id = message["MessageId"]
        report_status("processing", task_id)
        report_event("claimed", task_id)
        time.sleep(0.3)

        try:
            body = json.loads(message["Body"])

            if not isinstance(body, dict):
                raise ValueError("Task must be a JSON object")

            file_url = body.get("file_url")
            if not isinstance(file_url, str):
                raise ValueError("Task is missing file_url")

            # Preserve the full key: live/abc.json must not become just "live".
            # Accept only the configured raw bucket and a plain S3 object URI.
            location = urlsplit(file_url)
            key = location.path.lstrip("/")

            if (
                location.scheme != "s3"
                or location.netloc != "lta-traffic-raw"
                or not key
                or location.query
                or location.fragment
            ):
                raise ValueError("Invalid S3 file reference")

            logging.info("Processing %s", key)

            result = s3.get_object(
                Bucket=location.netloc,
                Key=key,
            )

            stream = result["Body"]
            try:
                content = stream.read().decode("utf-8")
            finally:
                stream.close()

            report_event("downloaded", task_id)
            time.sleep(0.3)
            record = clean_record(content)
            changed = store_record(record)

            # This event follows a completed DB transaction, before queue ack.
            # If acknowledgment fails, a later retry safely becomes a no-op.
            report_event(
                "stored" if changed else "unchanged",
                task_id,
                record[0],
            )
            time.sleep(0.2)

            # Crucially, acknowledge only after the transaction succeeds.
            sqs.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=message["ReceiptHandle"],
            )

            logging.info(
                "Acknowledged %s: %s",
                record[0],
                "stored" if changed else "duplicate/older observation",
            )

        except Exception as exc:
            # No delete here: SQS can deliver the task again after visibility
            # expires. Repeated failures, including invalid records, eventually
            # move to the DLQ configured in bootstrap.py. Nothing is "fixed"
            # merely by retrying; inspect DLQ tasks to diagnose persistent errors.
            logging.error(
                "Task %s failed; retained for retry: %s",
                message.get("MessageId"),
                exc,
            )
            report_event("failed", task_id, type(exc).__name__)

        finally:
            # Idle means this worker is no longer handling the current attempt,
            # not that it succeeded. Consult the stored/unchanged/failed events.
            report_status("idle")
