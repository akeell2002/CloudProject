import boto3
import json
import uuid
import time
import random
from datetime import datetime
import requests

s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
sqs = boto3.client('sqs', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')

bucket_name = 'lta-traffic-raw'
queue_url = "http://127.0.0.1:4566/000000000000/task-queue"

LTA_API_URL = "https://datamall2.mytransport.sg/ltaodataservice/Traffic-Imagesv2"
HEADERS = {
    "AccountKey": "lEcQ8QS7Qym7wXyoOAbnJA==",
    "accept": "application/json"
}

def fetch_live_lta_traffic():
    """Fetches real-time traffic snapshot data from LTA DataMall."""
    response = requests.get(LTA_API_URL, headers=HEADERS, timeout=10)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch data from LTA API. Status code: {response.status_code}")
        return None

print("🚗 Live LTA DataMall Producer started. Fetching real telemetry...")

while True:
    try:
        live_payload = fetch_live_lta_traffic()

        if live_payload and "value" in live_payload and len(live_payload["value"]) > 0:
            # Extract one real camera record from the live array
            camera = random.choice(live_payload["value"])
            
            # Format it to perfectly match your PostgreSQL schema
            data = {
                "vehicle_id": f"CAM-{camera['CameraID']}",
                "timestamp": str(datetime.now()),
                "latitude": camera["Latitude"], 
                "longitude": camera["Longitude"],
                "speed_kmh": 0  # Cameras don't track speed natively, defaulting to 0
            }

            json_data = json.dumps(data)
            file_name = f"lta_traffic_{uuid.uuid4()}.json"

            # Upload to S3 and trigger Claim-Check SQS
            s3.put_object(Bucket=bucket_name, Key=file_name, Body=json_data)
            print(f"\nStored live LTA record in S3: {file_name} (Camera {camera['CameraID']})")

            s3_url = f"s3://{bucket_name}/{file_name}"
            message_body = json.dumps({"file_url": s3_url})
            sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)
            print(f" Enqueued Claim-Check pointer to SQS: {s3_url}")
        else:
            print("No data retrieved in this iteration.")

    except Exception as e:
        print(f"Error occurred: {e}")

    time.sleep(10)