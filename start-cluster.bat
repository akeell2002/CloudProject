@echo off
cd /d "%~dp0"
echo =======================================================
echo    FEDCONSENSUS: LAUNCHING 5-NODE DOCKER FLEET
echo =======================================================

docker-compose down
docker-compose build
docker-compose up -d

echo.
echo Cluster is booting! Checking container health...
timeout /t 3 /nobreak >nul
docker-compose ps

echo.
echo Test endpoints:
echo   Python dashboard: http://localhost:8091
echo   Docker dashboard: http://localhost:8090
echo   fednode-0: http://localhost:8080/health  (gRPC: localhost:50051)
echo   fednode-1: http://localhost:8081/health  (gRPC: localhost:50052)
echo   fednode-2: http://localhost:8082/health  (gRPC: localhost:50053)
echo   fednode-3: http://localhost:8083/health  (gRPC: localhost:50054)
echo   fednode-4: http://localhost:8084/health  (gRPC: localhost:50055)
echo.
echo To inspect logs: docker-compose logs -f
echo To stop cluster: docker-compose down
echo.
echo Starting Python dashboard on port 8091. Press Ctrl+C to stop it.
python -m dashboard.server --port 8091
