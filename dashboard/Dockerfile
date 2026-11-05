FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY dashboard /app/dashboard
EXPOSE 8090
CMD ["python", "-m", "dashboard.server", "--host", "0.0.0.0"]
