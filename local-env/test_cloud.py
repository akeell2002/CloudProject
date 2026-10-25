import boto3

# 1. Connect to isolated mock cloud containers: S3 on port 4566, SQS on port 4567
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:4566', aws_access_key_id='test', aws_secret_access_key='test', region_name='us-east-1')
sqs = boto3.client('sqs', endpoint_url='http://127.0.0.1:4567', aws_access_key_id='test', aws_secret_access_key='test', region_name='us-east-1')

print("Testing Separated S3 and SQS Containers...\n")

# 2. Verify or create S3 bucket on localstack-s3
try:
    s3.head_bucket(Bucket='lta-traffic-raw')
    print("[OK] S3 Bucket 'lta-traffic-raw' is active on localstack-s3 (port 4566)!")
except Exception:
    s3.create_bucket(Bucket='lta-traffic-raw')
    print("[OK] S3 Bucket 'lta-traffic-raw' created on localstack-s3 (port 4566)!")

# 3. Verify or create SQS queue on localstack-sqs
queue_url = sqs.get_queue_url(QueueName='task-queue')['QueueUrl']
print(f"[OK] SQS Queue verified on localstack-sqs (port 4567) at: {queue_url}")
