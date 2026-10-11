import boto3
import json
import uuid
import random
import time
from datetime import datetime

s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
sqs = boto3.client('sqs', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')

bucket_name = 'lta-traffic-raw'
queue_url = "http://127.0.0.1:4566/000000000000/task-queue"

print("LTA Traffic Producer started. Generating data...")

while True:
    data={
        "vehicle_id": f"SG-{random.randint(1000, 9999)}",
        "timestamp": str(datetime.now()),
        "latitude": random.choice([1.3521, 999.99]), 
        "longitude": random.choice([103.8198, -999.99]),
        "speed_kmh": random.randint(0, 120)
    }

    fake_data_payload = json.dumps(data)

    file_name = f"traffic_data_{uuid.uuid4()}.json"

    s3.put_object(Bucket=bucket_name, Key=file_name, Body=fake_data_payload)
    print(f"Uploaded heavy file to S3: {file_name}")

    s3_url = f"s3://{bucket_name}/{file_name}"

    message_body = json.dumps({"file_url": s3_url})
    sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)
    print(f"Sent message to SQS with Claim-Check: {s3_url}")

    time.sleep(3)  # Simulate a delay between data generation