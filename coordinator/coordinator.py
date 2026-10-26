# DISTRIBUTED COORDINATOR POD
# Architecture Role (from CSC3104 Project Proposal GROUP04):
#   - Decoupled Ingestion Consumer: Pulls Claim-Check notifications from SQS
#   - Worker Registry & Telemetry: Discovers healthy workers via Redis heartbeats
#   - High-Throughput Dispatcher: Routes tasks to workers via Google RPC (gRPC / HTTP2)
#   - Reliability Manager: Acknowledges (deletes) SQS messages only on successful worker execution

import json
import logging
import os
import socket
import threading
import time
from urllib.parse import urlsplit

import boto3
import grpc
import redis
from botocore.config import Config

import traffic_pb2
import traffic_pb2_grpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [COORDINATOR] %(levelname)s %(message)s",
)

COORDINATOR_ID = socket.gethostname()
SQS_ENDPOINT = os.getenv("SQS_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-sqs:4566"))
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

sqs = boto3.client(
    "sqs",
    endpoint_url=SQS_ENDPOINT,
    config=Config(
        connect_timeout=5,
        read_timeout=25,
        retries={"max_attempts": 2},
    ),
)

monitor = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
    socket_connect_timeout=1.0,
    socket_timeout=1.0,
)

stats = {
    "dispatched_count": 0,
    "failed_count": 0,
    "last_worker": None,
    "status": "starting",
}
stats_lock = threading.Lock()
grpc_channels = {}  # Cache of gRPC channels per worker endpoint
rr_index = 0


def report_event(kind, task, detail=""):
    try:
        monitor.xadd(
            "dataclean:events",
            {
                "source": "coordinator",
                "worker_id": COORDINATOR_ID,
                "kind": kind,
                "task": task or "",
                "detail": str(detail)[:200],
                "timestamp": str(time.time()),
            },
            maxlen=1000,
            approximate=True,
        )
    except Exception:
        pass


def publish_coordinator_heartbeat():
    while True:
        try:
            with stats_lock:
                snapshot = dict(stats)
                snapshot["id"] = COORDINATOR_ID
                snapshot["last_seen"] = time.time()
                workers = get_active_workers()
                snapshot["active_workers"] = len(workers)
                monitor.set(
                    "dataclean:coordinator",
                    json.dumps(snapshot),
                    ex=60,
                )
        except Exception:
            pass
        time.sleep(3)


def get_active_workers():
    """Queries Redis worker registry to find online, healthy worker pods."""
    workers = []
    now = time.time()
    try:
        for key in monitor.scan_iter(match="dataclean:worker:*"):
            raw = monitor.get(key)
            if not raw:
                continue
            try:
                info = json.loads(raw)
                age = now - float(info.get("last_seen", 0))
                # Consider active if heartbeat received within last 15 seconds
                if age <= 15:
                    endpoint = info.get("endpoint")
                    if not endpoint:
                        ip = info.get("ip", "worker")
                        port = info.get("grpc_port", 50051)
                        endpoint = f"{ip}:{port}"
                    info["resolved_endpoint"] = endpoint
                    workers.append(info)
            except Exception:
                continue
    except Exception as exc:
        logging.warning("Error scanning Redis workers: %s", exc)

    workers.sort(key=lambda w: w.get("id", ""))
    return workers


def get_grpc_stub(endpoint):
    """Retrieves or creates a cached persistent gRPC channel & stub."""
    if endpoint not in grpc_channels:
        channel = grpc.insecure_channel(endpoint)
        stub = traffic_pb2_grpc.WorkerServiceStub(channel)
        grpc_channels[endpoint] = (channel, stub)
    return grpc_channels[endpoint][1]


def select_best_worker(workers):
    """
    Intelligent Scheduling Algorithm:
    1. Filter workers that are currently 'idle'
    2. If multiple idle, use Round-Robin for even load balancing
    3. If all busy, pick the one with least recently assigned work
    """
    global rr_index
    if not workers:
        return None

    idle_workers = [w for w in workers if w.get("status") == "idle"]
    candidates = idle_workers if idle_workers else workers

    selected = candidates[rr_index % len(candidates)]
    rr_index = (rr_index + 1) % len(candidates)
    return selected


def wait_for_queue():
    """Polls until SQS task-queue is provisioned by bootstrap service."""
    while True:
        try:
            url = sqs.get_queue_url(QueueName="task-queue")["QueueUrl"]
            logging.info("Connected to SQS queue: %s", url)
            return url
        except Exception as exc:
            logging.info("Waiting for SQS task-queue to be initialized... (%s)", exc)
            time.sleep(3)


def main():
    queue_url = wait_for_queue()

    with stats_lock:
        stats["status"] = "running"

    threading.Thread(
        target=publish_coordinator_heartbeat,
        name="coordinator-heartbeat",
        daemon=True,
    ).start()

    logging.info(
        "Centralized Coordinator %s active; starting SQS -> gRPC dispatch loop",
        COORDINATOR_ID,
    )

    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=2,
                VisibilityTimeout=120,
            )
        except Exception as exc:
            logging.error("SQS polling failed: %s", exc)
            time.sleep(3)
            continue

        messages = response.get("Messages", [])
        if not messages:
            continue

        for message in messages:
            task_id = message["MessageId"]
            receipt_handle = message["ReceiptHandle"]

            # 1. Parse Task Payload
            try:
                body = json.loads(message["Body"])
                file_url = body.get("file_url")
                if not file_url:
                    raise ValueError("Task message missing file_url")
            except Exception as exc:
                logging.error("Malformed SQS message body for %s: %s; dropping", task_id, exc)
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
                continue

            # 2. Discover Healthy Workers via Redis Registry
            active_workers = get_active_workers()
            if not active_workers:
                logging.warning(
                    "No healthy worker pods registered in Redis; retrying in 2s (Task %s preserved)",
                    task_id[:8],
                )
                time.sleep(2)
                continue

            # 3. Schedule Task (Intelligent Round-Robin / Idle-First)
            target = select_best_worker(active_workers)
            target_id = target.get("id", "unknown")
            endpoint = target["resolved_endpoint"]

            logging.info(
                "Dispatching task %s to Worker %s (%s) via Google RPC (gRPC)",
                task_id[:8],
                target_id[:8],
                endpoint,
            )
            report_event("dispatched", task_id, f"Target: Worker {target_id[:8]} ({endpoint})")

            # 4. Invoke Worker via Google RPC (gRPC)
            try:
                stub = get_grpc_stub(endpoint)
                request = traffic_pb2.TaskRequest(
                    task_id=task_id,
                    file_url=file_url,
                    timestamp=int(time.time()),
                )

                # Execute gRPC with 30s timeout
                resp = stub.ProcessTask(request, timeout=30.0)

                if resp.success:
                    # Successful processing or clean discard: delete from SQS
                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
                    with stats_lock:
                        stats["dispatched_count"] += 1
                        stats["last_worker"] = target_id

                    logging.info(
                        "Task %s completed by Worker %s [Status: %s, Detail: %s] -> SQS Acknowledged",
                        task_id[:8],
                        target_id[:8],
                        resp.status,
                        resp.detail,
                    )
                else:
                    # Worker reported an unrecoverable poison / processing error
                    with stats_lock:
                        stats["failed_count"] += 1
                    logging.error(
                        "Worker %s reported failure on task %s: %s. Preserving in SQS for DLQ redrive.",
                        target_id[:8],
                        task_id[:8],
                        resp.detail,
                    )

            except grpc.RpcError as rpc_err:
                with stats_lock:
                    stats["failed_count"] += 1
                logging.error(
                    "gRPC communication error with worker %s (%s): %s. Preserving in SQS for redrive.",
                    target_id[:8],
                    endpoint,
                    rpc_err,
                )
                # Invalidate cached channel in case of connection drop
                grpc_channels.pop(endpoint, None)
                time.sleep(1)
            except Exception as exc:
                with stats_lock:
                    stats["failed_count"] += 1
                logging.error("Unexpected dispatch error: %s", exc)
                time.sleep(1)


if __name__ == "__main__":
    main()
