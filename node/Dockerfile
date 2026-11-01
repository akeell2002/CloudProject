FROM python:3.11-slim

# Avoid writing .pyc files and buffer stdout for real-time logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# Install dependencies
COPY node/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and protobuf contracts
COPY proto /app/proto
COPY node /app/node

# Default ports: 50051 for gRPC mesh, 8080 for ActivityPub HTTP /inbox
EXPOSE 50051 8080

CMD ["python", "-m", "node.main"]
