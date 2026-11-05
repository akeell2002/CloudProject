@echo off
cd /d "%~dp0"
echo =======================================================
echo    FEDCONSENSUS: FULL RESET (CLEAN SLATE)
echo =======================================================
echo Stopping containers and wiping persistent volumes...
docker compose down -v
if errorlevel 1 exit /b 1
echo.
echo Rebuilding and starting fresh cluster...
docker compose up -d --build
if errorlevel 1 exit /b 1
echo.
echo Clean cluster is running!
echo Dashboard available at: http://localhost:8090
