FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY node/requirements.txt /app/node_requirements.txt
RUN pip install --no-cache-dir -r /app/node_requirements.txt
COPY proto /app/proto
COPY node /app/node
COPY dashboard /app/dashboard
EXPOSE 8090
CMD ["python", "-m", "dashboard.server", "--host", "0.0.0.0"]
