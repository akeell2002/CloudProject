import boto3
import redis
import json
import time
import psycopg2
import psycopg2.extras

sqs = boto3.client('sqs', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
cache = redis.Redis(host='127.0.0.1', port =6379, decode_responses=True)

queue_url = "http://127.0.0.1:4566/000000000000/task-queue"

DB_PARAMS = {
    "host": "127.0.0.1", 
    "port": "5432",
    "user": "admin",
    "password": "admin",
    "database": "dataclean_db"
}

def clean_traffic_data(file_content):
    print("Parsing and cleaning data...")
    try:
        data = json.loads(file_content)
        lat = data.get("latitude", 0)
        lon = data.get("longitude", 0)

        # Drop corrupted simulated outliers
        if lat > 90 or lat < -90 or lon > 180 or lon < -180:
            print(f"Invalid GPS coordinates ({lat}, {lon}). Dropping record.")
            return None

        return data
    except (json.JSONDecodeError, TypeError) as err:
        print(f"Payload parse failure: {err}")
        return None

print("Worker Node started. Polling SQS for tasks...")

while True:
    # Poll SQS for messages
    response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)

    if 'Messages' in response:
        message = response['Messages'][0] # Get the first message
        receipt_handle = message['ReceiptHandle'] #The ID needed to delete the message later
        body = json.loads(message['Body']) # The message body is a JSON string, so we parse it

        s3_url = body['file_url']

        # Duplicate Filtering (At-most once)
        # Check the Redis history to see if we already processed this task
        if cache.exists(s3_url):
            print(f"Duplicate task detected: {s3_url}. Discarding to prevent redundant compute.")
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            continue # Instantly skip the rest of the loop and go back to waiting

        print(f"\nRecieved task! Claim-Check points to : {s3_url}")

        bucket = s3_url.split('/')[2] # Extract the bucket name from the S3 URL
        file_key = s3_url.split('/')[3] # Extract the file key from the S3 URL

        try:
            print(f"Downloading {file_key} from S3 bucket {bucket}...")
            s3_response = s3.get_object(Bucket=bucket, Key=file_key)
            file_content = s3_response['Body'].read().decode('utf-8')

            cleaned_record = clean_traffic_data(file_content)

            # Try to acquire a lock with a 10-second expiration
            if cleaned_record:
                print("Attempting to acquire Redis lock...")
                lock_acquired = cache.set("db_write_lock", "locked", nx=True, ex=10)

                if lock_acquired:
                    print("Lock acquired! Writing clean data to PostgreSQL database...")

                    try:
                        #Open Connection
                        conn = psycopg2.connect(**DB_PARAMS)
                        cur = conn.cursor()

                        insert_query = """
                            INSERT INTO cleansed_traffic 
                            (vehicle_id, recorded_timestamp, latitude, longitude, speed_kmh)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (vehicle_id) 
                            DO UPDATE SET 
                                recorded_timestamp = EXCLUDED.recorded_timestamp,
                                latitude = EXCLUDED.latitude,
                                longitude = EXCLUDED.longitude,
                                speed_kmh = EXCLUDED.speed_kmh;
                        """

                        cur.execute(insert_query, (
                            cleaned_record['vehicle_id'], 
                            cleaned_record['timestamp'], 
                            cleaned_record['latitude'], 
                            cleaned_record['longitude'], 
                            cleaned_record['speed_kmh']
                        ))

                        #commit transaction
                        conn.commit()
                        print(f"Successfully saved vehicle {cleaned_record['vehicle_id']} to database!")

                    except Exception as db_err:
                        print(f"Database error: {db_err}")
                        if conn:
                            conn.rollback()
                    finally:
                        if cur: cur.close()
                        if conn: conn.close()

                    cache.delete("db_write_lock")
                    print("Lock released.")
                    cache.set(s3_url, "completed", ex=86400) # Clears the history

                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle) #Delete the message from SQS

                else:
                    print("Another worker is writing the database. Try again later.")

            else:
                print("Data was corrupted. Discarding and remvoing from the queue")
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle) #Delete the message from SQS

        except Exception as e:
            print(f"Error processing file: {e}")
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

    else:
        print("No new tasks. Waiting...")
        time.sleep(2) #Pause again before asking the queue again