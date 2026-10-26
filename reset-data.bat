@echo off
setlocal
cd /d "%~dp0"

rem Use the same Compose project as start-project.bat.
set "COMPOSE=docker compose --env-file .env -f local-env/docker-compose.yml -f local-env/docker-compose.dashboard.yml"

if not exist ".env" (
    echo ERROR: Missing .env. Run this from your configured project.
    goto failed
)

if not exist "scripts\reset_project.py" (
    echo ERROR: Missing scripts\reset_project.py.
    goto failed
)

docker info >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker Desktop is not available.
    goto failed
)

rem The dashboard must already be running.
rem Its container has the Python dependencies needed by the reset script.
%COMPOSE% exec -T dashboard python -c "pass"
if errorlevel 1 (
    echo ERROR: Start the project with start-project.bat first.
    goto failed
)

echo.
echo ================================================
echo   Resetting CloudProject demo data
echo ================================================
echo Clears the traffic table, both queues and
echo pipeline monitoring counters.
echo Other tables and raw S3 files are retained.
echo.

rem Stop processing before deleting data.
echo [1/3] Stopping producer, coordinator and workers...
%COMPOSE% stop producer coordinator worker
if errorlevel 1 goto failed

rem Execute the existing Python reset helper inside the dashboard.
rem Pass the local script through stdin; no rebuild is needed.
echo.
echo [2/3] Clearing data. Queue cleanup takes about 65 seconds...
%COMPOSE% exec -T dashboard python - --confirm-local-reset < "scripts\reset_project.py"
if errorlevel 1 goto failed

rem Start existing containers, preserving their images and replica count.
echo.
echo [3/3] Restarting the pipeline...
%COMPOSE% start worker coordinator
if errorlevel 1 goto failed

%COMPOSE% start producer
if errorlevel 1 goto failed

echo.
echo ================================================
echo   Reset complete. Fresh ingestion has resumed.
echo   Dashboard: http://localhost:8000
echo ================================================
echo Refresh your browser to clear its old activity log.
echo New records may appear immediately.
echo.
pause
exit /b 0

:failed
echo.
echo Reset did not complete. Check the error above.
echo Processing may be stopped or only partly restarted.
echo Fix the error before running this script again.
echo.
pause
exit /b 1