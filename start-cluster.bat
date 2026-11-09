@echo off
cd /d "%~dp0"
echo =======================================================
echo    FEDCONSENSUS: LAUNCHING 5-NODE DOCKER FLEET
echo =======================================================

docker compose down
if errorlevel 1 exit /b 1

rem Operator credential for node /fault, /reputation, /peers. Generated once into the
rem gitignored .env (read by docker compose and by a host-run dashboard). Never echoed.
set "HAS_OPERATOR_TOKEN="
if exist ".env" (
    findstr /b /c:"FEDCONSENSUS_OPERATOR_TOKEN=" ".env" >nul 2>&1 && set "HAS_OPERATOR_TOKEN=1"
)
if not defined HAS_OPERATOR_TOKEN (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$b = New-Object byte[] 32; $r = [Security.Cryptography.RandomNumberGenerator]::Create(); $r.GetBytes($b); $r.Dispose(); $hex = -join ($b | ForEach-Object { $_.ToString('x2') }); $p = Join-Path (Get-Location) '.env'; $prefix = ''; if ((Test-Path $p) -and (Get-Item $p).Length -gt 0) { $raw = [IO.File]::ReadAllText($p); if (-not $raw.EndsWith([string][char]10)) { $prefix = [Environment]::NewLine } }; [IO.File]::AppendAllText($p, $prefix + 'FEDCONSENSUS_OPERATOR_TOKEN=' + $hex + [Environment]::NewLine)"
    if errorlevel 1 exit /b 1
    echo Generated FEDCONSENSUS_OPERATOR_TOKEN in .env
)
set "HAS_OPERATOR_TOKEN="
echo Operator token: stored in .env. A host-run dashboard reads it from .env.

docker compose build
if errorlevel 1 exit /b 1
docker compose up -d
if errorlevel 1 exit /b 1

echo.
echo Cluster is booting! Checking container health...
timeout /t 3 /nobreak >nul
docker compose ps

echo.
echo Test endpoints:
echo   Dashboard: http://127.0.0.1:8090
echo   fednode-0: http://localhost:8080/health  (gRPC: localhost:50051)
echo   fednode-1: http://localhost:8081/health  (gRPC: localhost:50052)
echo   fednode-2: http://localhost:8082/health  (gRPC: localhost:50053)
echo   fednode-3: http://localhost:8083/health  (gRPC: localhost:50054)
echo   fednode-4: http://localhost:8084/health  (gRPC: localhost:50055)
echo.
echo To inspect logs: docker compose logs -f
echo To stop cluster: docker compose down
