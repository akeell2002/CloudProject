#Start from python base image
FROM python:3.11-slim

#Prevent python from buffering log output
ENV PYTHONUNBUFFERED=1

#Set working directory inside container
WORKDIR /app

#Copy requirement and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#Copy worker script and protobuf definitions into container
COPY traffic_pb2.py traffic_pb2_grpc.py worker.py ./

EXPOSE 50051

#Default command to execute when the container starts 
CMD [ "python", "worker.py" ]
