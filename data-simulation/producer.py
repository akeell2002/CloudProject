# LIVE DATA PRODUCER
# Fetches real DataMall camera metadata and streams observations continuously
# through S3 and SQS (claim-check pattern) with Redis real-time telemetry.

import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone

import boto3
import requests
from botocore.config import Config

try:
    import redis
except ImportError:
    redis = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

POLL_SECONDS = max(5, int(os.getenv("POLL_SECONDS", "10")))

API_URL = (
    "https://datamall2.mytransport.sg/"
    "ltaodataservice/Traffic-Imagesv2"
)

API_KEY = os.environ.get("LTA_ACCOUNT_KEY", "").strip()
if not API_KEY:
    raise RuntimeError("Set a valid LTA_ACCOUNT_KEY in the root .env file")

ENDPOINT = os.getenv("AWS_ENDPOINT", "http://localstack:4566")
BUCKET = "lta-traffic-raw"
QUEUE_NAME = "task-queue"

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

PRODUCER_ID = "producer-1"
producer_state = {
    "id": PRODUCER_ID,
    "status": "starting",
    "batch_count": 0,
    "sent_total": 0,
    "last_batch_size": 0,
    "last_seen": time.time(),
}
state_lock = threading.Lock()

monitor = None
if redis is not None:
    try:
        monitor = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
    except Exception as exc:
        logging.warning("Redis monitoring client setup failed: %s", exc)


def publish_heartbeat():
    if monitor is None:
        return
    try:
        with state_lock:
            snapshot = dict(producer_state)
            snapshot["last_seen"] = time.time()
            monitor.set(
                "dataclean:producer",
                json.dumps(snapshot),
                ex=60,
            )
    except Exception:
        pass


def report_event(kind, detail="", task=""):
    if monitor is None:
        return
    try:
        monitor.xadd(
            "dataclean:events",
            {
                "source": "producer",
                "producer_id": PRODUCER_ID,
                "worker_id": "producer",  # Backward-compatible fallback for older cached clients
                "kind": kind,
                "detail": str(detail)[:200],
                "task": task or "",
                "timestamp": str(time.time()),
            },
            maxlen=1000,
            approximate=True,
        )
    except Exception:
        pass


def heartbeat_loop():
    while True:
        publish_heartbeat()
        time.sleep(3)


threading.Thread(
    target=heartbeat_loop,
    name="producer-heartbeat",
    daemon=True,
).start()

config = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 2},
)

s3 = boto3.client("s3", endpoint_url=ENDPOINT, config=config)
sqs = boto3.client("sqs", endpoint_url=ENDPOINT, config=config)

queue_url = sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]

logging.info("Live producer started; continuous streaming enabled")

while True:
    try:
        with state_lock:
            producer_state["status"] = "fetching LTA API"
        publish_heartbeat()

        response = requests.get(
            API_URL,
            headers={
                "AccountKey": API_KEY,
                "Accept": "application/json",
            },
            timeout=20,
        )
        response.raise_for_status()

        payload = response.json()
        cameras = payload.get("value") if isinstance(payload, dict) else None

        if not isinstance(cameras, list):
            raise ValueError("Unexpected DataMall response: missing value list")

        valid_cameras = [
            c for c in cameras
            if isinstance(c, dict) and c.get("CameraID")
        ]

        report_event("fetched", f"{len(valid_cameras)} cameras from LTA DataMall")

        with state_lock:
            producer_state["status"] = "streaming"
            producer_state["last_batch_size"] = len(valid_cameras)
            producer_state["batch_count"] += 1
        publish_heartbeat()

        # Pace observations evenly across the cycle so packets flow continuously
        # without a long dead gap between API polls.
        item_delay = max(0.25, min(1.5, POLL_SECONDS / max(1, len(valid_cameras))))
        sent = 0

        for camera in valid_cameras:
            # Capture fresh UTC timestamp per observation as it streams
            ingested_at = (
                datetime.now(timezone.utc)
                .replace(tzinfo=None)
                .isoformat()
            )
            cam_id = f"CAM-{camera['CameraID']}"

            record = {
                "vehicle_id": cam_id,
                "timestamp": ingested_at,
                "latitude": camera.get("Latitude"),
                "longitude": camera.get("Longitude"),
                "speed_kmh": 0,
            }

            key = f"live/{uuid.uuid4()}.json"

            report_event("fetched", f"Ingesting {cam_id} from LTA", key)

            s3.put_object(
                Bucket=BUCKET,
                Key=key,
                Body=json.dumps(record).encode("utf-8"),
                ContentType="application/json",
            )
            report_event("uploaded", f"{cam_id} raw JSON -> S3", key)

            sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps({
                    "file_url": f"s3://{BUCKET}/{key}"
                }),
            )
            report_event("queued", f"{cam_id} claim-check -> SQS", key)

            sent += 1
            with state_lock:
                producer_state["sent_total"] += 1
            publish_heartbeat()

            time.sleep(item_delay)

        logging.info("Streamed %s camera observations", sent)

    except Exception as exc:
        logging.error("Producer cycle failed: %s", exc)
        report_event("producer_error", str(exc))
        time.sleep(5)

    finally:
        with state_lock:
            producer_state["status"] = "polling next batch"
        publish_heartbeat()

    # Brief pause before fetching the next batch so flow stays continuous
    time.sleep(2)
