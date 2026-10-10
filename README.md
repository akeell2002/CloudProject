# DataClean Engine 🚦

Welcome to the **DataClean Engine** repository for CSC3104 (Group 04). 

This project is a distributed, fault-tolerant data cleansing engine. We take messy, high-velocity traffic telemetry from Singapore's LTA DataMall, clean it concurrently across multiple worker pods, and securely save the sanitized data into a sharded PostgreSQL database. Our system is built to survive pod crashes, memory limits, and heavily corrupted data without losing a single record.

## 📂 Directory Structure

Here is how our project is organized. Every team member has a specific folder to work in to prevent merge conflicts.

*   **`.github/workflows/` (The Robot Reviewer)**
    *   *What it does:* Contains our CI/CD pipelines.
    *   *Why we need it:* Whenever someone opens a Pull Request, the scripts here will automatically test our code and build our Docker containers to make sure nothing is broken.

*   **`background-watcher/` (The Safety Net)**
    *   *What it does:* The straggler mitigation and failure recovery service.
    *   *Why we need it:* This service constantly monitors our Redis state tracker. If a worker pod crashes or takes too long on a corrupted file, this watcher detects the timeout and re-queues the task so another pod can take over.

*   **`data-simulation/` (The Chaos Maker)**
    *   *What it does:* Python scripts for testing and historical data replay.
    *   *Why we need it:* We use these scripts to download old LTA DataMall traffic data and intentionally inject "noise" (like deleting GPS coordinates or breaking JSON schemas). This gives our workers realistic, messy data to clean and proves our fault tolerance works.

*   **`k8s-manifests/` (The Blueprint)**
    *   *What it does:* Kubernetes configuration files (YAML).
    *   *Why we need it:* These files tell Kubernetes exactly how to deploy, network, and automatically scale our worker pods and services.

*   **`local-env/` (The Mock Cloud)**
    *   *What it does:* A `docker-compose.yml` environment for local development.
    *   *Why we need it:* This spins up local, free versions of AWS S3 (via MinIO), AWS SQS (via LocalStack), Redis, and PostgreSQL. It allows everyone to test their code on their own laptop without spending AWS credits.

*   **`worker-node/` (The Muscle)**
    *   *What it does:* The core cleansing application.
    *   *Why we need it:* These are the pods that do the actual heavy lifting. They poll the SQS queue, download the heavy JSON from S3, parse and clean the data, secure a Redis mutex lock, and write the clean records to PostgreSQL.

### 📄 Root Files
*   **`.gitignore`**: Tells Git which files to ignore (like local `.env` files with passwords, massive dataset downloads, or `node_modules`).
*   **`GROUP04_INSTRUCTIONS.pdf`**: A placeholder for the final testing manual we will submit to the professor.

## 🛠️ Getting Started (Local Setup)

To spin up your local mock cloud, ensure you have Docker Desktop installed, then run:

1. Navigate to the local environment folder: `cd local-env`
2. Start the mock cloud services: `docker-compose up -d`
3. Verify the containers (MinIO, LocalStack, Redis, Postgres) are running: `docker ps`

## 🚦 Git Workflow Rules (CRITICAL)

To keep our development fast and avoid breaking each other's code, we follow a strict branching strategy.

1. **NEVER push directly to the `main` branch.** The `main` branch must always contain a working, stable version of the project.
2. **Create a Feature Branch:** When you start working on your folder, create a new branch off of `main`. Use a descriptive name (e.g., `git checkout -b setup/local-compose` or `git checkout -b feat/redis-lock`).
3. **Open a Pull Request (PR):** When your code is working locally, push your branch to GitHub and open a PR. Have at least one other team member review and approve it before merging it into `main`.