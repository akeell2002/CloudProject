"""Read-only monitoring API for the CloudProject Packet Tracer-style dashboard.

This service intentionally does not change worker/producer behavior. It reads
SQS queue attributes, Redis reachability, and existing PostgreSQL rows.
"""
from __future__ import annotations

import os
import time
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:  # Allows front-end preview without local Postgres bindings.
    psycopg2 = None

try:
    import redis
except ImportError:
    redis = None

BASE = Path(__file__).resolve().parent
app = FastAPI(title="CloudProject Dashboard", version="0.1.0")


@app.middleware("http")
async def disable_browser_cache(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


app.mount("/assets", StaticFiles(directory=str(BASE / "static")), name="assets")

S3_ENDPOINT = os.getenv("S3_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-s3:4566"))
SQS_ENDPOINT = os.getenv("SQS_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-sqs:4566"))
QUEUE_URL = os.getenv("SQS_QUEUE_URL", "http://localstack-sqs:4566/000000000000/task-queue")
DB_HOST = os.getenv("POSTGRES_HOST", "postgres")
DB_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME = os.getenv("POSTGRES_DB", "dataclean_db")
DB_USER = os.getenv("POSTGRES_USER", "admin")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "admin")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


def get_queue() -> dict[str, Any]:
    try:
        client = boto3.client(
            "sqs",
            endpoint_url=SQS_ENDPOINT,
            region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
            config=Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1}),
        )
        result = client.get_queue_attributes(
            QueueUrl=QUEUE_URL,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )
        attrs = result.get("Attributes", {})
        dlq_count = 0
        try:
            dlq_url = client.get_queue_url(QueueName="task-dead-letter")["QueueUrl"]
            dlq_attrs = client.get_queue_attributes(
                QueueUrl=dlq_url,
                AttributeNames=["ApproximateNumberOfMessages"],
            ).get("Attributes", {})
            dlq_count = int(dlq_attrs.get("ApproximateNumberOfMessages", 0))
        except Exception:
            pass

        return {
            "online": True,
            "pending": int(attrs.get("ApproximateNumberOfMessages", 0)),
            "inflight": int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)),
            "dlq": dlq_count,
            "error": None,
        }
    except Exception as exc:
        return {"online": False, "pending": None, "inflight": None, "error": type(exc).__name__}


def get_database() -> dict[str, Any]:
    if psycopg2 is None:
        return {"online": False, "records": None, "latest": [], "error": "psycopg2 unavailable"}
    try:
        with psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER,
            password=DB_PASSWORD, connect_timeout=2,
        ) as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Because vehicle_id is UNIQUE, this counts current rows (latest per ID),
                # *not* how many processing events have occurred over time.
                cursor.execute("SELECT COUNT(*) AS total FROM cleansed_traffic")
                total = cursor.fetchone()["total"]
                cursor.execute("""
                    SELECT vehicle_id, recorded_timestamp, latitude, longitude,
                           speed_kmh, processed_at
                    FROM cleansed_traffic
                    ORDER BY recorded_timestamp DESC, id DESC
                    LIMIT 20
                """)
                latest = []
                for row in cursor.fetchall():
                    latest.append({
                        "vehicle_id": str(row["vehicle_id"]),
                        "recorded_timestamp": row["recorded_timestamp"].isoformat() if row["recorded_timestamp"] else None,
                        "latitude": float(row["latitude"]),
                        "longitude": float(row["longitude"]),
                        "speed_kmh": int(row["speed_kmh"]),
                        "processed_at": row["processed_at"].isoformat() if row["processed_at"] else None,
                    })
                return {"online": True, "records": int(total), "latest": latest, "error": None}
    except Exception as exc:
        return {"online": False, "records": None, "latest": [], "error": type(exc).__name__}


def get_redis() -> dict[str, Any]:
    if redis is None:
        return {"online": False, "error": "redis client unavailable"}
    try:
        client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, socket_connect_timeout=2, socket_timeout=2)
        return {"online": bool(client.ping()), "error": None}
    except Exception as exc:
        return {"online": False, "error": type(exc).__name__}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "dashboard-api"}

def get_producer_telemetry():
    unavailable = {
        "connected": False,
        "status": "unavailable",
        "last_seen": None,
        "sent_total": 0,
        "last_batch_size": 0,
    }
    if redis is None:
        return unavailable

    try:
        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        raw = client.get("dataclean:producer")
        if not raw:
            return unavailable
        data = json.loads(raw)
        age = max(0, time.time() - float(data.get("last_seen", 0)))
        return {
            "connected": age <= 15,
            "status": data.get("status", "running") if age <= 15 else "unavailable",
            "last_seen": float(data.get("last_seen", 0)),
            "sent_total": int(data.get("sent_total", 0)),
            "last_batch_size": int(data.get("last_batch_size", 0)),
            "batch_count": int(data.get("batch_count", 0)),
            "speed_bands_cached": int(data.get("speed_bands_cached", 0)),
        }
    except Exception:
        return unavailable


def get_worker_telemetry():
    unavailable = {
        "connected": False,
        "replicas": None,
        "items": [],
        "events": [],
    }

    if redis is None:
        return unavailable

    try:
        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )

        now = time.time()
        workers = []

        for key in client.scan_iter(match="dataclean:worker:*"):
            raw = client.get(key)
            if not raw:
                continue

            try:
                item = json.loads(raw)
                age = max(0, now - float(item["last_seen"]))

                workers.append({
                    "id": str(item["id"]),
                    "status": (
                        item["status"] if age <= 15 else "unavailable"
                    ),
                    "task": item.get("task"),
                    "last_seen": float(item["last_seen"]),
                    "online": age <= 15,
                })
            except (ValueError, KeyError, TypeError):
                continue

        workers.sort(key=lambda item: item["id"])

        # A bounded recent-event feed, not a permanent audit log.
        recent = client.xrevrange("dataclean:events", count=200)

        events = [
            {"id": event_id, **fields}
            for event_id, fields in reversed(recent)
        ]

        return {
            "connected": True,
            "replicas": sum(item["online"] for item in workers),
            "items": workers,
            "events": events,
        }

    except redis.RedisError:
        return unavailable



@app.get("/api/snapshot")
def snapshot() -> dict[str, Any]:
    """Read-only snapshot. No synthetic metrics or invented pod counts."""
    queue = get_queue()
    database = get_database()
    cache = get_redis()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "queue": queue,
        "database": database,
        "redis": cache,
        "workers": get_worker_telemetry(),
        "producer": get_producer_telemetry(),
        "metric_note": "SQS counts are approximate; DB count is current rows, not total processing events",
    }
