# 🚦 DataClean Engine (CSC3104 — Group 04)

Distributed, fault-tolerant municipal traffic data cleansing system for Singapore LTA DataMall.

---

## ⚡ How to Run (Step-by-Step)

1. **Start Docker Desktop** and make sure it is running.
2. **Configure your API key**:
   * Open the `.env` file in the project root (or copy `.env.example` to `.env`).
   * Add your LTA DataMall key: `LTA_ACCOUNT_KEY=your_key_here`
3. **Launch the system**:
   * Double-click `start-project.bat` (or run `.\start-project.bat` in PowerShell).
   * It will automatically build the images, start all 8 containers, reset old test data, and start streaming live data.
4. **Open the Web UI**:
   * Open your browser to: **[http://localhost:8000](http://localhost:8000)**
   * Select **● Live** to see real-time packets, gRPC dispatches, and cleansed database records.
5. **How to Stop**:
   * Press `Ctrl + C` in the batch terminal, then run:
     ```bash
     docker compose --env-file .env -f local-env/docker-compose.yml -f local-env/docker-compose.dashboard.yml down
     ```

---

## 📁 What Each Folder & File Does

| Folder / File | What It Does (In Simple Terms) |
| :--- | :--- |
| **`coordinator/`** | **The Dispatcher:** Consumes task tickets from SQS, checks Redis to see which worker is alive and idle, and sends tasks to workers over Google gRPC. Deletes messages from SQS only when the worker confirms success. |
| **`data-simulation/`** | **The Producer:** Ingests live taxi GPS & road speed bands from LTA DataMall. Uploads raw data to S3, caches 500 road speed bands in Redis, and sends a task ticket to SQS. Also injects chaos/dirty data (speed spikes, bad GPS) to test fault tolerance. |
| **`worker-node/`** | **The Cleaner (gRPC Server):** Runs on port `50051`. Receives tasks via gRPC, streams raw data from S3, filters out GPS & speed anomalies, fuses expressway speed bands, and saves clean records to PostgreSQL. |
| **`background-watcher/`** | **Failure Recovery & Watchdog:** Straggler mitigation and failure recovery service. Monitors Redis state tracker for dead worker nodes and stranded tasks. |
| **`k8s-manifests/`** | **Kubernetes Blueprints:** YAML manifests for deploying, scaling, and networking the pods on a cloud Kubernetes cluster. |
| **`.github/workflows/`** | **CI/CD Pipelines:** Automated GitHub Actions workflows for continuous integration and container builds. |
| **`dashboard/`** | **The Web UI & API:** Runs FastAPI (`server.py`) and serves the real-time Packet Tracer-style monitoring dashboard (`static/`). Also contains `bootstrap.py` which creates the S3 bucket and SQS queues on startup. |
| **`local-env/`** | **Docker Infrastructure:** Contains `docker-compose.yml` (for S3, SQS, Redis, PostgreSQL) and `init.sql` (creates the database table). |
| **`proto/`** | **gRPC Contract:** Contains `traffic.proto` which defines the exact binary messages (`TaskRequest`, `TaskResponse`) sent between the Coordinator and Worker. |
| **`scripts/`** | **Utility Scripts:** Contains `reset_project.py` used by `start-project.bat` to clear demo queues and test database records on a fresh restart without touching S3 archives. |
| **`test-case/`** | **Idempotence Test (`test.ipynb`):** Jupyter Notebook that proves duplicate tasks are filtered by Redis (At-Most-Once) and safe against crashes via PostgreSQL `ON CONFLICT DO UPDATE` (At-Least-Once). |
| **`start-project.bat`** | One-click script to build, clean, and run the whole system. |
| **`reset-data.bat`** | Open up a new terminal, run the script to clear project queues, records and monitoring counters |
| **`.env`** | Secrets and environment configuration (stores `LTA_ACCOUNT_KEY`). |

---

## ⚠️ Important Things for the Team to Know

1. **Separated Containers (Microservices):**
   * S3 and SQS run in **completely separate containers** (`localstack-s3` on port `4566` and `localstack-sqs` on port `4567`). They are not lumped together.
2. **Google RPC (gRPC) Inter-Service Communication:**
   * Instead of slow HTTP REST, the **Coordinator talks to Workers using Google gRPC over HTTP/2 (port 50051)** with Protocol Buffers (`traffic.proto`).
3. **Database Credentials & Table:**
   * **Host:** `localhost` (Port: `5433` on your host machine, `5432` inside Docker)
   * **Database:** `dataclean_db`
   * **User / Password:** `admin` / `admin`
   * **Table:** `cleansed_traffic`
   * *You can connect via pgAdmin 4 using these credentials.*
4. **Idempotence & Fault Tolerance:**
   * If a message is sent twice, Redis catches it and drops it.
   * If Redis is wiped, PostgreSQL `ON CONFLICT (vehicle_id) DO UPDATE` ensures existing records are updated in place with zero duplicate rows.
   * Open `test-case/test.ipynb` and run the 4 cells to see this automated test in action.
5. **Dead-Letter Queue (DLQ):**
   * If corrupted or poisoned data arrives that cannot be parsed, the Coordinator refuses to delete it from SQS. After 5 retries, AWS SQS automatically moves it to `task-dead-letter`.
