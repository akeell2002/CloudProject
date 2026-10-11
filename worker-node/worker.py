import boto3
import redis
import json
import time

sqs = boto3.client('sqs', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
cache = redis.Redis(host='127.0.0.1', port =6379, decode_responses=True)

queue_url = "http://127.0.0.1:4566/000000000000/task-queue"

def clean_traffic_data(file_content):
    print("Cleaning data...")
    return "clean_data"

print("Worker Node started. polling SQS for tasks...")

while True:
    # Poll SQS for messages
    response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)

    if 'Messages' in response:
        message = response['Messages'][0] # Get the first message
        receipt_handle = message['ReceiptHandle'] #The ID needed to delete the message later
        body = json.loads(message['Body']) # The message body is a JSON string, so we parse it

        s3_url = body['file_url']
        print(f"\nRecieved task! Claim-Check points to : {s3_url}")

        bucket = s3_url.split('/')[2] # Extract the bucket name from the S3 URL
        file_key = s3_url.split('/')[3] # Extract the file key from the S3 URL

        try:
            print(f"Simulating download of {file_key} from S3 bucket {bucket}...")

            clean_traffic_data("dummy_content") # Simulate cleaning the data

            print("Attempting to acquire Redis lock...") 
            lock_acquired = cache.set("db_write_lock", "locked", nx=True, ex=10) # Try to acquire a lock with a 10-second expiration
            
            if lock_acquired:
                print("Lock acquired! Writing clean data to PostgreSQL database...")
                time.sleep(1) # Simulating the time it takes to write to the database
                
                # Release the lock for the next worker
                cache.delete("db_write_lock")
                print("Lock released.")
                
                # Delete the message from SQS
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle) # Delete the message from SQS
                print("Task complete. Message deleted from SQS queue.")
            else:
                print("Another worker is writing to the database. Will retry later.")

        except Exception as e:
            print(f"Error processing file: {e}")
    else:
        print("No new tasks. Waiting...")
        
    time.sleep(2) # Pause before asking the queue again