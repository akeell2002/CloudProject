# Fault-Tolerance & Distributed Consensus Tests

This directory contains a Jupyter Notebook (`fault_tolerance_tests.ipynb`) designed to verify the distributed fault-tolerance mechanisms of the data-cleansing worker node. 

In distributed systems, a process or communication channel can fail, or messages may be delivered more than once due to network timeouts or dropped acknowledgments[cite: 12, 14]. To handle this, the system implements both **At-Most-Once** and **At-Least-Once** execution semantics[cite: 11].

## Prerequisites
Ensure your local infrastructure is running via Docker Compose:
* `local-env-localstack-1` (Port 4566)
* `local-env-redis-1` (Port 6379)
* `local-env-postgres-1` (Port 5432)
* `worker_node` (Must be running and actively tailing logs to observe test results)

---

## Notebook Structure & Test Execution

### Cell 1: Client Setup & Initialization
* **What it does:** Initializes the `boto3` client to communicate with the LocalStack SQS queue and the `redis` client to access the local Redis cache. 
* **How it works:** It establishes the connections required to inject test messages directly into the worker's queue and define the `TEST_FILE_URL` representing a file that the worker has already successfully processed.

### Cell 2: Testing Dynamic Duplicate Filtering (At-Most-Once Semantics)
* **What it does:** Verifies that the system can intercept redundant tasks to prevent unnecessary S3 downloads or database connections. 
* **How it is carried out:** 
  1. The cell ensures the `TEST_FILE_URL` is marked as completed in the Redis history[cite: 11]. 
  2. It injects a duplicate SQS message containing that URL. 
  3. The worker cross-references the incoming message against the cache, immediately drops the task, and deletes the message from the queue. You will see `Duplicate task detected... Discarding` in the worker logs.

### Cell 3: Testing Database Idempotency (At-Least-Once Safety Net)
* **What it does:** Simulates a failure scenario where the worker or Redis cache crashes after a database write but before the completion history is saved, forcing the system to re-execute the task[cite: 11].
* **How it is carried out:** 
  1. The cell executes `cache.flushall()` to wipe the Redis memory, simulating lost state. 
  2. It re-injects the exact same SQS message. Because the cache is empty, the filter lets the task through. 
  3. The worker downloads the file and attempts the database insertion. Relying on idempotent database operations, PostgreSQL safely updates the existing row in-place via `ON CONFLICT DO UPDATE` instead of crashing with a `UniqueViolation` error[cite: 14].

### Cell 4: Automated Database State Verification
* **What it does:** Mathematically proves that the system's idempotency mechanisms maintained absolute data consistency without creating duplicate records.
* **How it is carried out:** The cell uses the `subprocess` module to run a direct SQL query against the database container: `SELECT vehicle_id, COUNT(*) FROM cleansed_traffic GROUP BY vehicle_id HAVING COUNT(*) > 1;`. It asserts that the query returns exactly `(0 rows)`.