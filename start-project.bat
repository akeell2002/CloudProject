@echo off
setlocal
cd /d "%~dp0"

rem Every launch resets ONLY local CloudProject demo rows, queues and reports.
rem Do not run independent producer/worker processes during this reset.
if not exist ".env" (
    echo Missing .env. Set LTA_ACCOUNT_KEY in the project root.
    goto failed
)
if not exist "scripts\reset_project.py" (
    echo Missing scripts\reset_project.py.
    goto failed
)

docker info >nul 2>&1
if errorlevel 1 (
    echo Start Docker Desktop and try again.
    goto failed
)

set "COMPOSE=docker compose --env-file .env -f local-env/docker-compose.yml -f local-env/docker-compose.dashboard.yml"
echo This launch will clear CloudProject camera rows, queued tasks and worker reports.
echo Other databases and raw S3 files are retained.
echo Building images before stopping the existing pipeline...
%COMPOSE% build dashboard producer worker coordinator bootstrap
if errorlevel 1 goto failed

echo Stopping ingestion and all Compose worker replicas...
%COMPOSE% stop producer coordinator worker
if errorlevel 1 goto failed

echo Starting local infrastructure...
%COMPOSE% up -d --wait postgres redis localstack-s3 localstack-sqs
if errorlevel 1 goto failed

echo Ensuring the bucket and queues exist...
%COMPOSE% run --rm --no-deps -T bootstrap
if errorlevel 1 goto failed

rem Run the Python helper inside Docker; no host Python installation needed.
echo Resetting demo data. Queue cleanup takes about 65 seconds...
%COMPOSE% run --rm --no-deps -T dashboard python - --confirm-local-reset < "scripts\reset_project.py"
if errorlevel 1 goto failed

echo Starting the fresh Live pipeline...
%COMPOSE% up -d dashboard producer worker coordinator
if errorlevel 1 goto failed

echo.
echo =============================================
echo   CloudProject started with fresh demo data
echo   Dashboard: http://localhost:8000
echo   Select Live. Ctrl+click the URL to open it.
echo   Refresh the browser to clear its old activity log.
echo   New records may appear immediately after startup.
echo =============================================
pause
exit /b 0

:failed
echo.
echo Startup did not complete. Check the error above.
echo If processing was stopped, it remains stopped until a successful startup.
echo No database volumes were deleted. A partial reset may need a rerun.
pause
exit /b 1
