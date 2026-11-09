@echo off
cd /d "%~dp0"
echo =======================================================
echo    FEDCONSENSUS: FULL RESET (CLEAN SLATE)
echo =======================================================
echo Stopping containers and wiping persistent volumes...
docker compose down -v
if errorlevel 1 exit /b 1

rem Operator credential for node /fault, /reputation, /peers (same block as start-cluster.bat).
rem Generated once into the gitignored .env; an existing token is kept. Never echoed.
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

echo.
echo Rebuilding and starting fresh cluster...
docker compose up -d --build
if errorlevel 1 exit /b 1
echo.
echo Clean cluster is running!
echo Dashboard available at: http://127.0.0.1:8090
