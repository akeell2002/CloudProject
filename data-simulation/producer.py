# MULTI-SOURCE MUNICIPAL STREAM FUSION PRODUCER + CHAOS INJECTOR
# Fuses LTA Taxi-Availability (moving GPS) with TrafficSpeedBandsv2 (road speeds)
# Injects controlled real-world sensor chaos, and streams Claim-Check tasks.

import json
import logging
import math
import os
import random
import string
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

# Configuration & Endpoints
POLL_SECONDS = max(10, int(os.getenv("POLL_SECONDS", "15")))
TAXI_API_URL = "https://datamall2.mytransport.sg/ltaodataservice/Taxi-Availability"
SPEED_API_URL = "https://datamall2.mytransport.sg/ltaodataservice/v4/TrafficSpeedBands"

API_KEY = os.environ.get("LTA_ACCOUNT_KEY", "").strip()
if not API_KEY:
    raise RuntimeError("Set a valid LTA_ACCOUNT_KEY in the root .env file")

S3_ENDPOINT = os.getenv("S3_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-s3:4566"))
SQS_ENDPOINT = os.getenv("SQS_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-sqs:4566"))
BUCKET = "lta-traffic-raw"
QUEUE_NAME = "task-queue"
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

PRODUCER_ID = "producer-1"
producer_state = {
    "id": PRODUCER_ID,
    "status": "starting",
    # These heartbeat fields distinguish an observed stop from the API request
    # and let the dashboard detect older producer images without stop support.
    "ingestion_paused": False,
    "ingestion_control_supported": True,
    "batch_count": 0,
    "sent_total": 0,
    "last_batch_size": 0,
    "speed_bands_cached": 0,
    "last_seen": time.time(),
}
state_lock = threading.Lock()

# Redis Monitoring Setup
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
            monitor.set("dataclean:producer", json.dumps(snapshot), ex=60)
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
                "worker_id": "producer",
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


# Must match the dashboard API key; it controls ingestion only, not queued work.
INGESTION_CONTROL_KEY = "dataclean:ingestion:paused"


def wait_for_ingestion(running_status="streaming"):
    """Pause at a safe boundary, never between an S3 upload and its SQS send.

    Heartbeats continue on their own thread. If control cannot be read, hold new
    ingestion until Redis recovers so a stop request is not silently ignored.
    """
    while True:
        unavailable = False
        try:
            if monitor is None:
                raise RuntimeError("Redis control unavailable")
            # Re-read on every check so a Resume command can release this loop.
            paused = monitor.get(INGESTION_CONTROL_KEY) == "1"
        except Exception:
            paused = True
            unavailable = True
        status = "ingestion control unavailable" if unavailable else (
            "ingestion stopped" if paused else running_status
        )
        with state_lock:
            changed = (producer_state["ingestion_paused"] != paused
                       or producer_state["status"] != status)
            producer_state["ingestion_paused"] = paused
            producer_state["status"] = status
        # Publish transitions immediately; the background heartbeat still runs
        # while this thread waits, so a stopped producer remains visible as online.
        if changed:
            publish_heartbeat()
        if not paused:
            return
        # Poll without busy-waiting; resume normally takes at most one polling interval
        # plus Redis/network time once the producer is at this safe boundary.
        time.sleep(0.5)


def heartbeat_loop():
    while True:
        publish_heartbeat()
        time.sleep(3)


threading.Thread(
    target=heartbeat_loop,
    name="producer-heartbeat",
    daemon=True,
).start()

# LocalStack S3 and SQS Clients
config = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 2},
)
s3 = boto3.client("s3", endpoint_url=S3_ENDPOINT, config=config)
sqs = boto3.client("sqs", endpoint_url=SQS_ENDPOINT, config=config)
queue_url = sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]

# Fixed fleet of 45 vehicles to test deduplication & UPSERT over time
FLEET_POOL = [
    f"TAXI-SH{random.choice(string.ascii_uppercase)}{random.randint(1000, 9999)}{random.choice(string.ascii_uppercase)}"
    for _ in range(45)
]

# Raw Speed Bands Ingest State
last_speed_fetch_time = 0


def refresh_speed_bands():
    """Fetches raw expressway speed bands from LTA DataMall and caches raw JSON directly into Redis.
    Following the cloud ELT pattern, the Producer performs zero parsing — preserving raw Bronze data.
    """
    global last_speed_fetch_time
    now = time.time()
    if now - last_speed_fetch_time < 300:
        return  # Cache is still valid (5 minute refresh cycle)

    headers = {"AccountKey": API_KEY, "Accept": "application/json"}
    try:
        logging.info("Ingesting raw road speed bands from TrafficSpeedBandsv2 into Redis Bronze cache...")
        resp = requests.get(SPEED_API_URL, headers=headers, timeout=15)
        if resp.status_code == 200:
            raw_items = resp.json().get("value", [])
            if raw_items and monitor is not None:
                # Stores 100% UNTOUCHED, RAW LTA items directly into Redis
                monitor.set("dataclean:speed_bands", json.dumps(raw_items), ex=600)
                last_speed_fetch_time = now
                with state_lock:
                    producer_state["speed_bands_cached"] = len(raw_items)
                logging.info("Ingested %s raw LTA speed band items into Redis Bronze cache", len(raw_items))
                report_event("fetched", f"Cached {len(raw_items)} raw LTA road segments into Redis")
    except Exception as err:
        logging.warning("Speed bands ingest skipped: %s", err)


fleet_history = {}
logging.info("Municipal Stream Producer active (Raw Ingest -> S3 Bronze Layer)")

while True:
    try:
        # Honor a saved stop before starting the next round of external API requests.
        wait_for_ingestion("fetching speed bands")
        refresh_speed_bands()

        with state_lock:
            producer_state["status"] = "fetching LTA Taxis"
        publish_heartbeat()

        # Check again after the speed-band request, which may take time.
        wait_for_ingestion("fetching LTA Taxis")
        # Ingest live roaming taxis
        response = requests.get(
            TAXI_API_URL,
            headers={"AccountKey": API_KEY, "Accept": "application/json"},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        taxis = payload.get("value") if isinstance(payload, dict) else None

        if not isinstance(taxis, list) or len(taxis) == 0:
            logging.warning("No taxi records returned; waiting before retry")
            time.sleep(5)
            continue

        report_event("fetched", f"Received {len(taxis)} live taxis from LTA DataMall")

        with state_lock:
            producer_state["status"] = "streaming"
            producer_state["last_batch_size"] = min(len(taxis), 40)
            producer_state["batch_count"] += 1
        publish_heartbeat()

        # Sample 35 active taxis per batch, maintaining trajectory continuity per vehicle
        sample_size = min(len(taxis), 35)
        available_taxis = list(taxis)
        assigned_batch = []

        for i in range(sample_size):
            vehicle_id = FLEET_POOL[i]
            prev_coord = fleet_history.get(vehicle_id)

            if prev_coord and available_taxis:
                # Find nearest taxi to last known location (prevents random teleporting)
                best_idx = 0
                best_dist = float("inf")
                # Search up to 400 taxis for closest spatial proximity
                for idx, t in enumerate(available_taxis[:400]):
                    t_lat = t.get("Latitude", 0)
                    t_lon = t.get("Longitude", 0)
                    dist = (t_lat - prev_coord[0]) ** 2 + (t_lon - prev_coord[1]) ** 2
                    if dist < best_dist:
                        best_dist = dist
                        best_idx = idx
                matched_taxi = available_taxis.pop(best_idx)
            elif available_taxis:
                matched_taxi = available_taxis.pop(random.randrange(len(available_taxis)))
            else:
                break

            fleet_history[vehicle_id] = (matched_taxi.get("Latitude"), matched_taxi.get("Longitude"))
            assigned_batch.append((vehicle_id, matched_taxi))

        item_delay = 0.6  # 0.6s pacing ensures fluid packet movement on dashboard

        sent = 0
        for vehicle_id, taxi in assigned_batch:
            # Check before each record, not just each batch. Once this check passes,
            # finish its S3 upload and SQS notification together before stopping.
            wait_for_ingestion()
            ingested_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            real_lat = taxi.get("Latitude")
            real_lon = taxi.get("Longitude")

            # -------------------------------------------------------------
            # THE CHAOS GENERATOR (Controlled Sensor Noise)
            # -------------------------------------------------------------
            dice = random.random()
            key = f"live/{uuid.uuid4()}.json"

            # Ingest packet: LTA DataMall -> Producer
            report_event("fetched", f"Ingesting {vehicle_id} from LTA", key)

            if dice < 0.05:
                # 5% POISON RECORD: Truncated JSON to trigger SQS DLQ quarantine
                broken_payload = '{"vehicle_id": "' + vehicle_id + '", "timestamp": "' + ingested_at + '", "incomplete": true'
                s3.put_object(
                    Bucket=BUCKET,
                    Key=key,
                    Body=broken_payload.encode("utf-8"),
                    ContentType="application/json",
                )
                report_event("uploaded", f"[POISON] Broken JSON -> S3", key)
                sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=json.dumps({"file_url": f"s3://{BUCKET}/{key}"}),
                )
                report_event("queued", f"[POISON] Broken JSON syntax -> SQS", key)
                logging.info("Injected POISON record: %s", key)

            elif dice < 0.15:
                # 10% DIRTY GPS: Tunnel dropout / sensor overflow outside Singapore
                bad_coords = random.choice([
                    (999.99, -999.99),    # Extreme hardware overflow
                    (0.0, 0.0),           # GPS lock lost (Null Island)
                    (1.05, 103.20),       # Coordinates in the Singapore Strait
                ])
                record = {
                    "vehicle_id": vehicle_id,
                    "timestamp": ingested_at,
                    "latitude": bad_coords[0],
                    "longitude": bad_coords[1],
                }
                s3.put_object(
                    Bucket=BUCKET,
                    Key=key,
                    Body=json.dumps(record).encode("utf-8"),
                    ContentType="application/json",
                )
                report_event("uploaded", f"[DIRTY GPS] Outlier payload -> S3", key)
                sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=json.dumps({"file_url": f"s3://{BUCKET}/{key}"}),
                )
                report_event("queued", f"[DIRTY GPS] Outlier ({bad_coords[0]}, {bad_coords[1]}) -> SQS", key)
                logging.info("Injected DIRTY GPS record for %s", vehicle_id)

            elif dice < 0.20:
                # 5% DIRTY SPEED SENSOR: Sensor spike or negative physical speed
                bad_speed = random.choice([-25, 290, 480])
                record = {
                    "vehicle_id": vehicle_id,
                    "timestamp": ingested_at,
                    "latitude": real_lat,
                    "longitude": real_lon,
                    "speed_sensor_reading": bad_speed,
                }
                s3.put_object(
                    Bucket=BUCKET,
                    Key=key,
                    Body=json.dumps(record).encode("utf-8"),
                    ContentType="application/json",
                )
                report_event("uploaded", f"[DIRTY SPEED] Spiked payload -> S3", key)
                sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=json.dumps({"file_url": f"s3://{BUCKET}/{key}"}),
                )
                report_event("queued", f"[DIRTY SPEED] Invalid speed ({bad_speed} km/h) -> SQS", key)
                logging.info("Injected DIRTY SPEED record for %s", vehicle_id)

            else:
                # 80% BRONZE LAKE RECORD: Raw Taxi Availability telemetry in S3
                # Authentic messy raw GPS: untrimmed lowercase vehicle string,
                # stringified coordinates with sensor noise, and IoT gateway telemetry.
                # Notice: S3 has NO speed band! Speed bands are cached in Redis.
                record = {
                    "odata.metadata": "https://datamall2.mytransport.sg/ltaodataservice/$metadata#TaxiAvailability",
                    "vehicle_source": f"  {vehicle_id.lower()}  \r\n",
                    "vehicle_id": vehicle_id,
                    "StartLat": str(real_lat),
                    "StartLon": str(real_lon),
                    "latitude": str(real_lat),
                    "longitude": str(real_lon),
                    "CreateDate": ingested_at,
                    "timestamp": ingested_at,
                    "gateway_telemetry": {
                        "battery_mv": "12450",
                        "rssi_dbm": "-74",
                        "firmware_rev": "v1.4b-prod"
                    }
                }
                s3.put_object(
                    Bucket=BUCKET,
                    Key=key,
                    Body=json.dumps(record).encode("utf-8"),
                    ContentType="application/json",
                )
                report_event("uploaded", f"{vehicle_id} raw Taxi GPS -> S3", key)
                sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=json.dumps({"file_url": f"s3://{BUCKET}/{key}"}),
                )
                report_event("queued", f"{vehicle_id} raw Taxi GPS -> SQS", key)

            sent += 1
            with state_lock:
                producer_state["sent_total"] += 1
            publish_heartbeat()
            time.sleep(item_delay)

        logging.info("Batch complete: Streamed %s fused observations", sent)

    except Exception as exc:
        logging.error("Producer cycle encountered an error: %s", exc)
        report_event("producer_error", str(exc))
        time.sleep(5)
    finally:
        with state_lock:
            producer_state["status"] = "waiting for next batch"
        publish_heartbeat()

    time.sleep(3)