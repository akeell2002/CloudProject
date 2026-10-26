# LIVE QUEUE WORKER + QUALITY-AWARE CLEANSING ENGINE
# Mode 1 (Default / Cloud Native): High-Performance Google gRPC Server
#   - Coordinator dispatches tasks via Google RPC (traffic.proto)
#   - Worker fetches raw JSON from S3 Bronze Lake
#   - Executes distributed speed fusion with Redis road segments
#   - Cleanses GPS / speed anomalies and commits idempotent PostgreSQL UPSERT
#   - Returns binary TaskResponse to Coordinator
# Mode 2 (Fallback): Direct SQS Claim-Check Pull

import json
import logging
import math
import os
import random
import socket
import threading
import time
from concurrent import futures
from datetime import datetime, timezone
from urllib.parse import urlsplit

import boto3
import grpc
import psycopg2
import redis
from botocore.config import Config

import traffic_pb2
import traffic_pb2_grpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

WORKER_ID = socket.gethostname()
try:
    WORKER_IP = socket.gethostbyname(socket.gethostname())
except Exception:
    WORKER_IP = WORKER_ID

GRPC_PORT = int(os.getenv("GRPC_PORT", "50051"))
WORKER_MODE = os.getenv("WORKER_MODE", "grpc").lower()

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
    "ip": WORKER_IP,
    "status": "idle",
    "task": None,
    "grpc_port": GRPC_PORT,
    "endpoint": f"{WORKER_IP}:{GRPC_PORT}",
    "mode": WORKER_MODE,
}
state_lock = threading.Lock()

DB_PARAMS = {
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB", "dataclean_db"),
    "user": os.getenv("POSTGRES_USER", "admin"),
    "password": os.environ.get("POSTGRES_PASSWORD", "admin"),
    "connect_timeout": 5,
    "options": "-c statement_timeout=15000 -c lock_timeout=5000",
}

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
    """
    Cleanses and typecasts raw sensor data into numeric floats.
    Accepts numbers and valid numeric strings (e.g. '1.3521').
    Rejects booleans, non-numeric strings, and non-finite values.
    """
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    try:
        val = float(value)
    except (ValueError, TypeError):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(val):
        raise ValueError(f"{name} must be finite")
    return val


# In-Memory Memoized Road Speed Segments (cleansed from Redis Bronze cache)
cached_speed_segments = []
last_speed_cache_read = 0


def get_cached_speed_segments():
    """Reads raw LTA speed bands from Redis, cleans & parses them in-memory,
    and caches the clean list in local RAM with a 60-second TTL (Memoization pattern).
    """
    global cached_speed_segments, last_speed_cache_read
    now = time.time()
    if cached_speed_segments and (now - last_speed_cache_read < 60):
        return cached_speed_segments

    try:
        raw = monitor.get("dataclean:speed_bands")
        if raw:
            raw_items = json.loads(raw)
            cleaned = []
            for item in raw_items:
                # Fallback if already clean dictionary
                if "lat" in item and "lon" in item and "speed" in item:
                    cleaned.append(item)
                    continue

                # 1. Parse coordinates from raw Location polyline string or StartLat/StartLon
                lat, lon = None, None
                if "StartLat" in item and "StartLon" in item:
                    try:
                        lat = float(item["StartLat"])
                        lon = float(item["StartLon"])
                    except (ValueError, TypeError):
                        pass
                elif "Location" in item and isinstance(item["Location"], str):
                    parts = item["Location"].split()
                    if len(parts) >= 2:
                        try:
                            lat = float(parts[0])
                            lon = float(parts[1])
                        except ValueError:
                            pass

                # 2. Typecast string boundaries & derive median speed
                speed = None
                if "MinimumSpeed" in item and "MaximumSpeed" in item:
                    try:
                        min_s = int(item["MinimumSpeed"])
                        max_s = int(item["MaximumSpeed"])
                        speed = (min_s + max_s) // 2
                    except (ValueError, TypeError):
                        pass

                # 3. Fallback to discrete SpeedBand tier code (1-8)
                if speed is None and "SpeedBand" in item:
                    try:
                        band = int(item["SpeedBand"])
                        speed = band * 10
                    except (ValueError, TypeError):
                        pass

                if lat and lon and speed:
                    road_name = str(item.get("RoadName", "Expressway")).split("(")[0].strip()
                    cleaned.append({
                        "road": road_name,
                        "lat": lat,
                        "lon": lon,
                        "speed": speed,
                    })

            if cleaned:
                cached_speed_segments = cleaned
                last_speed_cache_read = now
                logging.info("Worker Pod cleansed & memoized %s speed bands from Redis (60s TTL)", len(cached_speed_segments))
                return cached_speed_segments
    except Exception as exc:
        logging.warning("Failed to fetch/clean speed bands from Redis: %s", exc)

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
    Raises ValueError / JSONDecodeError for unparseable poison records.
    """
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("Record must be a JSON object")

    # 1. Text Normalization: trim whitespace & uppercase standardize
    raw_id = data.get("vehicle_source") or data.get("vehicle_id")
    if (
        not isinstance(raw_id, str)
        or not raw_id.strip()
        or len(raw_id.strip()) > 50
    ):
        raise ValueError("Invalid vehicle identifier")
    vehicle_id = raw_id.strip().upper()

    # 2. Type-Casting & Coordinate Precision Normalization
    raw_lat = data.get("latitude") if "latitude" in data else data.get("StartLat") if "StartLat" in data else data.get("Latitude")
    raw_lon = data.get("longitude") if "longitude" in data else data.get("StartLon") if "StartLon" in data else data.get("Longitude")
    latitude = round(numeric(raw_lat, "latitude"), 4)
    longitude = round(numeric(raw_lon, "longitude"), 4)

    # RULE 1: Singapore Spatial Bounding Box Filter
    if not (SG_LAT_MIN <= latitude <= SG_LAT_MAX and SG_LON_MIN <= longitude <= SG_LON_MAX):
        return None, f"GPS Outlier ({latitude:.4f}, {longitude:.4f}) outside Singapore bounds"

    # DISTRIBUTED STREAM FUSION:
    # If the raw observation carries a faulty sensor spike (chaos), evaluate that;
    # otherwise, Worker queries Redis speed cache to match road speed for these coordinates!
    if "speed_sensor_reading" in data:
        speed = numeric(data["speed_sensor_reading"], "speed_sensor_reading")
    elif "speed_kmh" in data:
        speed = numeric(data["speed_kmh"], "speed_kmh")
    else:
        # Queries Redis road speed cache:
        speed = match_speed_to_coordinate(latitude, longitude)

    # RULE 2: Physical Dynamics Sanity Check
    if not (SPEED_MIN <= speed <= SPEED_MAX) or not float(speed).is_integer():
        return None, f"Physical Speed Anomaly ({speed} km/h) outside valid range [0-{SPEED_MAX}]"

    raw_ts = data.get("timestamp") or data.get("CreateDate")
    if not isinstance(raw_ts, str):
        raise ValueError("Missing timestamp")

    try:
        observed_at = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    except ValueError:
        observed_at = datetime.now(timezone.utc)
    if observed_at.tzinfo is not None:
        observed_at = observed_at.astimezone(timezone.utc).replace(tzinfo=None)

    # Notice: gateway_telemetry and odata.metadata are pruned away!
    return (
        vehicle_id,
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


# -----------------------------------------------------------------------------
# GOOGLE RPC (gRPC) WORKER SERVICE IMPLEMENTATION
# -----------------------------------------------------------------------------
class WorkerServiceServicer(traffic_pb2_grpc.WorkerServiceServicer):
    """Handles task execution requests dispatched from the Centralized Coordinator."""

    def ProcessTask(self, request, context):
        task_id = request.task_id
        file_url = request.file_url

        report_status("processing", task_id)
        report_event("claimed", task_id, f"gRPC from Coordinator")
        time.sleep(0.1)

        try:
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

            # -------------------------------------------------------------
            # STEP: AT-MOST-ONCE DEDUPLICATION (Redis Cache Filter)
            # -------------------------------------------------------------
            if monitor.exists(file_url):
                logging.info("Duplicate task detected: %s. Discarding to prevent redundant compute.", file_url)
                report_event("unchanged", task_id, "Duplicate task filtered (Redis cache hit)")
                return traffic_pb2.TaskResponse(
                    success=True,
                    vehicle_id="",
                    status="unchanged",
                    detail="Duplicate task filtered (Redis cache hit)",
                    speed_kmh=0,
                )

            logging.info("gRPC Worker processing S3 object: %s", key)
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
            time.sleep(0.1)

            # Execute quality domain cleansing
            record, discard_reason = clean_record(content)

            if discard_reason:
                logging.warning("CLEANSED & DISCARDED: %s (Task: %s)", discard_reason, task_id[:8])
                report_event("unchanged", task_id, f"Sanitized/Dropped: {discard_reason}")
                monitor.set(file_url, "completed", ex=86400)
                return traffic_pb2.TaskResponse(
                    success=True,
                    vehicle_id="",
                    status="discarded",
                    detail=discard_reason,
                    speed_kmh=0,
                )

            # Valid clean record: commit to PostgreSQL
            changed = store_record(record)
            # Record in Redis history (At-Most-Once completion record)
            monitor.set(file_url, "completed", ex=86400)

            report_event(
                "stored" if changed else "unchanged",
                task_id,
                f"{record[0]} (Fused: {record[4]} km/h)",
            )
            logging.info(
                "Acknowledged %s: %s (fused speed: %s km/h)",
                record[0],
                "stored" if changed else "duplicate/older observation",
                record[4],
            )
            return traffic_pb2.TaskResponse(
                success=True,
                vehicle_id=record[0],
                status="stored" if changed else "unchanged",
                detail=f"Fused speed: {record[4]} km/h",
                speed_kmh=record[4],
            )

        except Exception as exc:
            logging.error("Task %s failed: %s", task_id, exc)
            report_event("failed", task_id, type(exc).__name__)
            # Return success=False to notify Coordinator not to delete from SQS
            return traffic_pb2.TaskResponse(
                success=False,
                vehicle_id="",
                status="failed",
                detail=str(exc),
                speed_kmh=0,
            )
        finally:
            report_status("idle")

    def HealthCheck(self, request, context):
        with state_lock:
            status = worker_state["status"]
            active = 1 if status == "processing" else 0
        return traffic_pb2.HealthResponse(
            worker_id=WORKER_ID,
            status=status,
            active_tasks=active,
        )


def serve_grpc():
    """Starts Google RPC (gRPC) server for Coordinator dispatching."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    traffic_pb2_grpc.add_WorkerServiceServicer_to_server(WorkerServiceServicer(), server)
    server.add_insecure_port(f"[::]:{GRPC_PORT}")
    server.start()
    logging.info(
        "Google RPC (gRPC) Worker %s started on port %s (IP: %s)",
        WORKER_ID,
        GRPC_PORT,
        WORKER_IP,
    )
    server.wait_for_termination()


def serve_sqs_pull():
    """Legacy direct SQS pull mode (used only if WORKER_MODE=pull)."""
    try:
        queue_url = sqs.get_queue_url(QueueName="task-queue")["QueueUrl"]
    except Exception as exc:
        logging.error("Failed to get SQS queue url: %s", exc)
        return

    logging.info("Quality-Aware Cleansing Worker %s started; direct SQS pull mode", WORKER_ID)

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
            try:
                body = json.loads(message["Body"])
                file_url = body.get("file_url")
                location = urlsplit(file_url)
                result = s3.get_object(Bucket=location.netloc, Key=location.path.lstrip("/"))
                with result["Body"] as stream:
                    content = stream.read().decode("utf-8")

                record, discard_reason = clean_record(content)
                if discard_reason:
                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
                    continue
                store_record(record)
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            except Exception as exc:
                logging.error("Task %s failed: %s", task_id, exc)
            finally:
                report_status("idle")


if __name__ == "__main__":
    if WORKER_MODE == "pull":
        serve_sqs_pull()
    else:
        serve_grpc()
