"""Reset local CloudProject demo data after its producer/workers are stopped.

Called by start-project.bat inside the dashboard image, using its dependencies
and Compose service connections. Never drop databases or Docker volumes.
Raw S3 objects are retained; the producer creates fresh objects on its next run.
"""
import argparse
import logging
import os
import time
from urllib.parse import urlsplit

import boto3
import psycopg2
import redis
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-local-reset", action="store_true")
    args = parser.parse_args()
    if not args.confirm_local_reset:
        parser.error("This deletes local demo data; pass --confirm-local-reset")

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    endpoint = os.environ.get("AWS_ENDPOINT", "")
    db_name = os.environ.get("POSTGRES_DB", "")
    # Explicitly restrict this helper to the project's local Compose services.
    if (urlsplit(endpoint).hostname != "localstack"
            or os.environ.get("POSTGRES_HOST") != "postgres"
            or db_name != "dataclean_db"
            or os.environ.get("REDIS_HOST") != "redis"):
        raise RuntimeError("Reset allowed only for local CloudProject services")

    queue = boto3.client(
        "sqs", endpoint_url=endpoint,
        config=Config(connect_timeout=3, read_timeout=5,
                      retries={"max_attempts": 1}),
    )
    cache = redis.Redis(
        host="redis", port=int(os.getenv("REDIS_PORT", "6379")),
        socket_connect_timeout=3, socket_timeout=3,
    )
    connection = psycopg2.connect(
        host="postgres", port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=db_name, user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"], connect_timeout=5,
        options="-c statement_timeout=15000 -c lock_timeout=5000",
    )
    try:
        # Verify connections/table before beginning the non-atomic reset.
        cache.ping()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM public.cleansed_traffic")
                previous_rows = cursor.fetchone()[0]
        urls = [queue.get_queue_url(QueueName=name)["QueueUrl"]
                for name in ("task-queue", "task-dead-letter")]

        # Purge removes pending AND in-flight messages. It is asynchronous;
        # keep producers/workers stopped for the full purge window so new tasks
        # are not discarded and old tasks cannot repopulate the cleared table.
        for url in urls:
            try:
                queue.purge_queue(QueueUrl=url)
            except ClientError as exc:
                if not exc.response["Error"]["Code"].endswith("PurgeQueueInProgress"):
                    raise
                logging.info("A queue purge is already running; waiting for it")
        for remaining in range(65, 0, -5):
            logging.info("Waiting for queue purge: %s seconds remaining", remaining)
            time.sleep(5)

        with connection:
            with connection.cursor() as cursor:
                # Scope is this table and its owned ID sequence only. No CASCADE.
                cursor.execute(
                    "TRUNCATE TABLE public.cleansed_traffic RESTART IDENTITY"
                )

        # Never FLUSHALL: Redis may contain unrelated application keys.
        keys = list(cache.scan_iter(match="dataclean:worker:*"))
        keys.append("dataclean:events")
        for offset in range(0, len(keys), 100):
            cache.delete(*keys[offset:offset + 100])
        logging.info("Reset complete: removed %s camera rows; queues and worker reports cleared", previous_rows)
        logging.info("Raw S3 objects and all other databases/tables were retained")
    finally:
        connection.close()
        cache.close()


if __name__ == "__main__":
    main()
