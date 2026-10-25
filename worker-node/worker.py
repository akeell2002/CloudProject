# LIVE QUEUE WORKER + QUALITY-AWARE CLEANSING ENGINE
# Flow: SQS Claim-Check -> S3 Fetch -> Spatial & Dynamic Cleansing -> Postgres UPSERT -> Ack
# Filters spatial GPS anomalies (Singapore bounding box) and speed outliers.
# Isolates unparseable poison payloads into SQS Dead-Letter Queue (DLQ).

import json
import logging
import math
import os
import random
import socket
import threading
import time
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

WORKER_ID = socket.gethostname()
S3_ENDPOINT = os.getenv("S3_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-s3:4566"))
SQS_ENDPOINT = os.getenv("SQS_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-sqs:4566"))

# AWS SQS & S3 Clients
sqs = boto3.client(
    "sqs",
    endpoint_url=SQS_ENDPOINT,
    config=Config(
        connect_timeout=5,
        read_timeout=25,
        retries={"max_attempts": 2},
    ),
)
s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    config=Config(
        connect_timeout=5,
        read_timeout=10,
        retries={"max_attempts": 2},
    ),
)

# Redis Telemetry Client
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
state_lock = threading.Lock()

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

# -----------------------------------------------------------------------------
# DOMAIN CLEANSING BOUNDARIES
# -----------------------------------------------------------------------------
# Singapore Geographic Bounding Box
SG_LAT_MIN = 1.15
SG_LAT_MAX = 1.48
SG_LON_MIN = 103.55
SG_LON_MAX = 104.08

# Physical Vehicle Speed Limits (km/h)
SPEED_MIN = 0
SPEED_MAX = 125  # Max expressway speed is 90 km/h; 125 km/h allows reasonable highway overtaking


def numeric(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return float(value)


# Cached Road Speed Segments (populated from Redis)
cached_speed_segments = []
last_speed_cache_read = 0


def get_cached_speed_segments():
    """Reads road speed bands from Redis, refreshing every 60 seconds."""
    global cached_speed_segments, last_speed_cache_read
    now = time.time()
    if cached_speed_segments and (now - last_speed_cache_read < 60):
        return cached_speed_segments
    try:
        raw = monitor.get("dataclean:speed_bands")
        if raw:
            cached_speed_segments = json.loads(raw)
            last_speed_cache_read = now
            logging.info("Worker loaded %s speed bands from Redis", len(cached_speed_segments))
            return cached_speed_segments
    except Exception as exc:
        logging.warning("Failed to fetch speed bands from Redis: %s", exc)
    return cached_speed_segments


def match_speed_to_coordinate(taxi_lat, taxi_lon):
    """Distributed Worker Fusion: Finds nearest expressway speed band from Redis cache."""
    segments = get_cached_speed_segments()
    if not segments:
        return random.randint(35, 55)

    closest_dist = float("inf")
    matched_speed = None

    # Find nearest expressway road segment (Euclidean distance approximation)
    for seg in segments:
        d_lat = taxi_lat - seg["lat"]
        d_lon = taxi_lon - seg["lon"]
        dist_sq = (d_lat * d_lat) + (d_lon * d_lon)
        if dist_sq < closest_dist:
            closest_dist = dist_sq
            matched_speed = seg["speed"]

    # ~0.015 degrees ≈ 1.6 km threshold to an expressway
    if closest_dist < (0.015 ** 2) and matched_speed:
        # Near expressway: apply measured traffic speed with realistic driver variance
        return max(30, min(110, matched_speed + random.randint(-4, 4)))

    # In urban/residential roads: standard city speed
    return random.randint(35, 55)


def clean_record(content):
    """
    Parses incoming raw vehicle telemetry, executes distributed speed fusion,
    and applies quality cleansing filters.
    Returns (cleaned_tuple, None) on success.
    Returns (None, discard_reason) for droppable sensor outliers.
    Raises ValueError / JSONDecodeError for unparseable poison records (DLQ flow).
    """
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("Record must be a JSON object")

    vehicle_id = data.get("vehicle_id")
    if (
        not isinstance(vehicle_id, str)
        or not vehicle_id.strip()
        or len(vehicle_id.strip()) > 50
    ):
        raise ValueError("Invalid vehicle identifier")

    latitude = numeric(data.get("latitude"), "latitude")
    longitude = numeric(data.get("longitude"), "longitude")

    # RULE 1: Singapore Spatial Bounding Box Filter
    if not (SG_LAT_MIN <= latitude <= SG_LAT_MAX and SG_LON_MIN <= longitude <= SG_LON_MAX):
        return None, f"GPS Outlier ({latitude:.4f}, {longitude:.4f}) outside Singapore bounds"

    # DISTRIBUTED STREAM FUSION:
    # If the raw observation carries a faulty sensor spike (chaos), evaluate that;
    # otherwise, compute dynamic speed by fusing with nearest expressway speed band.
    if "speed_sensor_reading" in data:
        speed = numeric(data["speed_sensor_reading"], "speed_sensor_reading")
    elif "speed_kmh" in data:
        speed = numeric(data["speed_kmh"], "speed_kmh")
    else:
        speed = match_speed_to_coordinate(latitude, longitude)

    # RULE 2: Physical Dynamics Sanity Check
    if not (SPEED_MIN <= speed <= SPEED_MAX) or not float(speed).is_integer():
        return None, f"Physical Speed Anomaly ({speed} km/h) outside valid range [0-{SPEED_MAX}]"

    timestamp = data.get("timestamp")
    if not isinstance(timestamp, str):
        raise ValueError("Missing timestamp")

    observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if observed_at.tzinfo is not None:
        observed_at = observed_at.astimezone(timezone.utc).replace(tzinfo=None)

    return (
        vehicle_id.strip(),
        observed_at,
        latitude,
        longitude,
        int(speed),
    ), None


def store_record(record):
    """Commits clean observation using atomic PostgreSQL UPSERT with temporal ordering."""
    connection = psycopg2.connect(**DB_PARAMS)
    try:
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


def publish_heartbeat():
    try:
        with state_lock:
            snapshot = dict(worker_state)
            snapshot["last_seen"] = time.time()
            monitor.set(
                f"dataclean:worker:{WORKER_ID}",
                json.dumps(snapshot),
                ex=120,
            )
    except redis.RedisError:
        pass


def report_status(status, task=None):
    with state_lock:
        worker_state["status"] = status
        worker_state["task"] = task
    publish_heartbeat()


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
    while True:
        publish_heartbeat()
        time.sleep(3)


threading.Thread(
    target=heartbeat_loop,
    name="worker-heartbeat",
    daemon=True,
).start()

logging.info("Quality-Aware Cleansing Worker %s started; polling SQS", WORKER_ID)

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

            # -------------------------------------------------------------
            # STEP: EXECUTE DOMAIN CLEANSING
            # -------------------------------------------------------------
            record, discard_reason = clean_record(content)

            if discard_reason:
                # SENSOR OUTLIER DETECTED: Drop record from DB and acknowledge SQS
                logging.warning("CLEANSED & DISCARDED: %s (Task: %s)", discard_reason, task_id[:8])
                report_event("unchanged", task_id, f"Sanitized/Dropped: {discard_reason}")
                sqs.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=message["ReceiptHandle"],
                )
                time.sleep(0.2)
                continue

            # CLEAN RECORD: Commit to database
            changed = store_record(record)
            report_event(
                "stored" if changed else "unchanged",
                task_id,
                f"{record[0]} (Fused: {record[4]} km/h)",
            )
            time.sleep(0.2)

            sqs.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=message["ReceiptHandle"],
            )
            logging.info(
                "Acknowledged %s: %s (fused speed: %s km/h)",
                record[0],
                "stored" if changed else "duplicate/older observation",
                record[4],
            )

        except Exception as exc:
            # POISON RECORD / UNEXPECTED FAILURE:
            # Leave message in SQS without deleting. SQS Redrive will retry up to
            # maxReceiveCount: 5 before automatically quarantining to task-dead-letter!
            logging.error(
                "Task %s failed (Poison Record); retained for SQS DLQ redrive: %s",
                message.get("MessageId"),
                exc,
            )
            report_event("failed", task_id, type(exc).__name__)
        finally:
            report_status("idle")