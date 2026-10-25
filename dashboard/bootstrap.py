# STARTUP INITIALIZATION (one-shot Compose service)
# Creates the LocalStack resources used by producer.py and worker.py.
# Compose waits for this script to exit successfully before starting processing.
# Changes from the initial prototype: startup retries, a dead-letter queue, and
# explicit retry settings on the main queue. No Kubernetes configuration here.
# Rerunning reuses existing resources and reapplies the queue settings below;
# it does not empty queues, remove S3 objects, or initialize PostgreSQL.

import json
import logging
import os
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(message)s")

# Inside Docker, localstack-s3 and localstack-sqs are the Compose service names.
s3_endpoint = os.getenv("S3_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-s3:4566"))
sqs_endpoint = os.getenv("SQS_ENDPOINT", os.getenv("AWS_ENDPOINT", "http://localstack-sqs:4566"))
config = Config(
    connect_timeout=2,
    read_timeout=3,
    retries={"max_attempts": 1},
)

s3 = boto3.client("s3", endpoint_url=s3_endpoint, config=config)
sqs = boto3.client("sqs", endpoint_url=sqs_endpoint, config=config)


def initialize():
    bucket = "lta-traffic-raw"

    # Create the bucket only if it is missing. Authentication/network errors
    # must propagate to the startup retry loop instead of masquerading as 404s.
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        code = str(exc.response["Error"]["Code"])
        if code not in {"404", "NoSuchBucket", "NotFound"}:
            raise
        s3.create_bucket(Bucket=bucket)

    # The dead-letter queue retains repeatedly failing tasks for inspection.
    # 1,209,600 seconds = 14 days; this is not permanent archival storage.
    dlq_url = sqs.create_queue(
        QueueName="task-dead-letter",
        Attributes={"MessageRetentionPeriod": "1209600"},
    )["QueueUrl"]

    # RedrivePolicy needs the queue ARN (resource identity), not its HTTP URL.
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=dlq_url,
        AttributeNames=["QueueArn"],
    )["Attributes"]["QueueArn"]

    queue_url = sqs.create_queue(QueueName="task-queue")["QueueUrl"]

    # Receiving a task hides it for 120 seconds; it does not delete it.
    # Without a successful acknowledgment, it can be delivered again.
    # maxReceiveCount bounds repeated deliveries before SQS moves it to the DLQ;
    # it is a receive-count threshold, not a count of Python exceptions.
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "VisibilityTimeout": "120",
            "RedrivePolicy": json.dumps({
                "deadLetterTargetArn": dlq_arn,
                "maxReceiveCount": "5",
            }),
        },
    )

    logging.info("S3 bucket, task queue and dead-letter queue ready")


# Container startup does not imply LocalStack is ready to accept requests.
# Retry up to 30 times, then fail visibly so dependent services do not start.
# Total elapsed time includes SDK/network retries as well as these sleeps.
for attempt in range(1, 31):
    try:
        initialize()
        break
    except Exception as exc:
        logging.warning(
            "Initialization attempt %s/30 failed: %s",
            attempt,
            exc,
        )
        if attempt == 30:
            raise
        time.sleep(3)
