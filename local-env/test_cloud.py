import boto3

# 1. Connect to your local fake AWS (LocalStack) on port 4566
# We use dummy credentials because LocalStack doesn't need real passwords
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:4566', aws_access_key_id='test', aws_secret_access_key='test', region_name='us-east-1')
sqs = boto3.client('sqs', endpoint_url='http://127.0.0.1:4566', aws_access_key_id='test', aws_secret_access_key='test', region_name='us-east-1')

print("☁️ Testing Mock Cloud...\n")

# 2. Create a fake S3 bucket for the LTA traffic data
s3.create_bucket(Bucket='lta-traffic-raw')
print("✅ S3 Bucket 'lta-traffic-raw' created successfully!")

# 3. Create a fake SQS queue
queue = sqs.create_queue(QueueName='task-queue')
queue_url = queue['QueueUrl']
print(f"✅ SQS Queue created at: {queue_url}")

# 4. Send a test "Claim-Check" message into the queue
#sqs.send_message(QueueUrl=queue_url, MessageBody='{"file_url": "s3://lta-traffic-raw/test_data.json"}')
#print("✅ Test message successfully sent to the queue!")