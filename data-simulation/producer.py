# LIVE DATA PRODUCER
# Despite the folder name, this script fetches real DataMall camera metadata.
# Flow: DataMall response -> one normalized JSON object per camera in S3 ->
# one SQS message carrying that object's address (the claim-check pattern).
# Changes from the prototype: environment-based configuration, all cameras in
# each response instead of one random camera, and a minimum 60-second pause.
# This is separate from the dashboard's browser-only Demo animation.

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

import boto3
import requests
from botocore.config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

API_URL = (
    "https://datamall2.mytransport.sg/"
    "ltaodataservice/Traffic-Imagesv2"
)

# Compose injects this from the ignored root .env file. Never hardcode or log
# the key. A missing/empty setting stops startup rather than making bad requests.
API_KEY = os.environ["LTA_ACCOUNT_KEY"].strip()
if not API_KEY:
    raise RuntimeError("Set a valid LTA_ACCOUNT_KEY in the root .env file")

# Docker service DNS works across containers; 127.0.0.1 would mean this one.
# boto3 reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and region from Compose.
ENDPOINT = os.getenv("AWS_ENDPOINT", "http://localstack:4566")
BUCKET = "lta-traffic-raw"
QUEUE_NAME = "task-queue"
# Delay after each batch finishes, not an exact wall-clock scheduling interval.
POLL_SECONDS = max(60, int(os.getenv("POLL_SECONDS", "60")))

config = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 2},
)

s3 = boto3.client("s3", endpoint_url=ENDPOINT, config=config)
sqs = boto3.client("sqs", endpoint_url=ENDPOINT, config=config)

# bootstrap.py creates this queue first. Resolve its actual URL by name.
queue_url = sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]

logging.info("Live producer started; polling every %s seconds", POLL_SECONDS)

while True:
    try:
        response = requests.get(
            API_URL,
            headers={
                "AccountKey": API_KEY,
                "Accept": "application/json",
            },
            timeout=20,
        )
        response.raise_for_status()

        # Validate the response structure before iterating. An empty list is
        # valid and simply produces zero tasks in this cycle.
        payload = response.json()
        cameras = payload.get("value") if isinstance(payload, dict) else None

        if not isinstance(cameras, list):
            raise ValueError("Unexpected DataMall response: missing value list")

        # Time our producer received this batch, NOT the image capture time.
        # Every record in the batch shares this timestamp. Convert to UTC first,
        # then remove timezone metadata to match the current SQL TIMESTAMP column.
        # The database stores UTC by convention; the column does not retain a zone.
        ingested_at = (
            datetime.now(timezone.utc)
            .replace(tzinfo=None)
            .isoformat()
        )

        sent = 0

        for camera in cameras:
            if not isinstance(camera, dict) or not camera.get("CameraID"):
                logging.warning("Skipping camera without an identifier")
                continue

            # Preserve the existing database field names for compatibility:
            # vehicle_id identifies a CAMERA, and speed_kmh is not measured speed.
            # Missing coordinates are left as None for worker validation.
            # S3 stores this normalized record, not the full API response/image.
            record = {
                "vehicle_id": f"CAM-{camera['CameraID']}",
                "timestamp": ingested_at,
                "latitude": camera.get("Latitude"),
                "longitude": camera.get("Longitude"),
                # Compatibility with the existing schema, not measured speed.
                "speed_kmh": 0,
            }

            # A unique object key preserves each fetched record independently.
            # Database deduplication is by camera/timestamp, not this random key.
            key = f"live/{uuid.uuid4()}.json"

            # Upload first; only queue a reference after upload succeeds.
            # These are separate operations, not an atomic transaction: a crash
            # between them can leave an unqueued S3 object. Recovery/replay for
            # that ingestion gap is not implemented by this script.
            s3.put_object(
                Bucket=BUCKET,
                Key=key,
                Body=json.dumps(record).encode("utf-8"),
                ContentType="application/json",
            )

            sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps({
                    "file_url": f"s3://{BUCKET}/{key}"
                }),
            )
            sent += 1

        logging.info("Queued %s camera observations", sent)

    # A failed cycle is logged and the next cycle fetches a fresh batch. Tasks
    # already queued remain valid, but this is not a durable retry of the batch.
    except Exception as exc:
        logging.error("Producer cycle failed: %s", exc)

    time.sleep(POLL_SECONDS)