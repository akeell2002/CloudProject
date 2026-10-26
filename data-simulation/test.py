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

LTA_API_URL = "http://datamall2.mytransport.sg/ltaodataservice/RoadWorks"
LTA_API_URL = "http://datamall2.mytransport.sg/ltaodataservice/PCDRealTime"
LTA_API_URL = "http://datamall2.mytransport.sg/ltaodataservice/TrafficSpeedBandsv2"
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

if __name__ == "__main__":
    print(fetch_live_lta_traffic()["value"][0])
    