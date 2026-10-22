### What I Did ###
## This is a small record of the changes I have made to the base code so people can understand what I have done ##

--- 22/10/26 to 23/10/26 ---
1) Redesigned the dashboard with a brighter theme, left-side metrics, a central topology canvas, right-side controls/activity logs, and clickable component popups.
2) Integrated the DataMall producer and processing worker into Docker Compose alongside LocalStack, Redis, PostgreSQL and the dashboard.
3) Configured service connections through environment variables and moved the API key configuration into .env.
4) Updated the producer to enqueue batches of camera records through the S3/SQS claim-check pattern.
5) Improved worker validation and database handling. Successful tasks are acknowledged after the database commit; failed tasks remain available for retry.
6) Added a dead-letter queue for repeatedly failing tasks.
7) Removed the global Redis database-write lock and used PostgreSQL UPSERTs to keep the latest observation per camera.
8) Added Redis worker heartbeats and processing events, plus dashboard code for dynamic worker nodes, status reporting and event-driven animations.
9) Connected pgAdmin to CloudProject’s PostgreSQL container through host port 5433.
10) Added explanatory comments to bootstrap.py, producer.py and worker.py.
11) Updated start-project.bat to reset local demonstration data before startup. Reset logic is maintained separately in scripts/reset_project.py.


--- Producer Changes ---
- Replaced hardcoded localhost addresses with configurable Docker service connections.
Why: Inside a container, localhost points to that container itself. Service names let it reach LocalStack.

- Moved the API key from source code into environment configuration.
Why: Keeps credentials out of committed code and allows key changes without editing Python.

- Changed from selecting one random camera to queuing all cameras in each API response.
Why: Uses the full fetched dataset and provides more tasks for distributed processing.

- Increased the polling pause from 10 to at least 60 seconds.
Why: Reduces unnecessary API requests when the source data hasn’t changed.

- Standardized batch ingestion timestamps to UTC.
Why: Keeps timestamps consistent across machines regardless of their local timezone.


--- Worker Changes ---
- Updated connections for Docker Compose.
Why: Lets the worker reach services in other containers instead of trying to connect to itself.

- Fixed S3 path parsing to support keys such as live/file.json.
Why: The old parsing extracted only live, causing the worker to request the wrong object.

- Added stricter validation of required fields, coordinates, timestamps and numeric values.
Why: Prevents incomplete or malformed records from reaching the database.

- Fixed acknowledgments so failed tasks remain available for retry.
Why: Previously, a task could be deleted even when its database write failed, losing the record.

- Removed the global Redis write lock; PostgreSQL handles concurrent writes through transactions and UPSERTs.
Why: The shared lock restricted database writes to one worker at a time, limiting parallel processing.

- Prevented older observations from overwriting newer records.
Why: Retried or delayed tasks can arrive out of order; the database should retain the latest observation.

- Added Redis heartbeats and task events for live dashboard monitoring.
Why: Lets the dashboard discover reporting workers, display their status and animate actual processing events.

The overall architecture stayed the same: producer → S3/SQS → worker → PostgreSQL.