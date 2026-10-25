FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY traffic_pb2.py traffic_pb2_grpc.py coordinator.py ./

CMD ["python", "coordinator.py"]
