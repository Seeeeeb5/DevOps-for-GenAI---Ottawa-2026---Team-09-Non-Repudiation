# One-click demo runner for Windows PowerShell
# Usage: .\scripts\run_all.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

# Create data and logs directories
New-Item -ItemType Directory -Force -Path "data" | Out-Null
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

# Clean up old data so each run is fresh
if (Test-Path "data/ledger.db") { Remove-Item "data/ledger.db" }
if (Test-Path "data/ledger_key.pem") { Remove-Item "data/ledger_key.pem" }

Write-Host "=" * 72
Write-Host "STARTING SERVICES"
Write-Host "=" * 72

# Start broker (port 8081)
$broker = Start-Process -NoNewWindow -PassThru -FilePath "python" `
    -ArgumentList "-m uvicorn broker.app:app --port 8081 --log-level warning" `
    -RedirectStandardOutput "logs/broker.log" -RedirectStandardError "logs/broker_err.log"
Write-Host "  broker    PID=$($broker.Id)  http://127.0.0.1:8081"

# Start target (port 8082)
$target = Start-Process -NoNewWindow -PassThru -FilePath "python" `
    -ArgumentList "-m uvicorn target.app:app --port 8082 --log-level warning" `
    -RedirectStandardOutput "logs/target.log" -RedirectStandardError "logs/target_err.log"
Write-Host "  target    PID=$($target.Id)  http://127.0.0.1:8082"

Start-Sleep -Seconds 2

# Start proxy (port 8080)
$proxy = Start-Process -NoNewWindow -PassThru -FilePath "python" `
    -ArgumentList "-m uvicorn proxy.app:app --port 8080 --log-level warning" `
    -RedirectStandardOutput "logs/proxy.log" -RedirectStandardError "logs/proxy_err.log"
Write-Host "  proxy     PID=$($proxy.Id)  http://127.0.0.1:8080"

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "All services running. Dashboard: http://127.0.0.1:8080/"
Write-Host ""

# Run the demo agent (6 acts)
Write-Host "=" * 72
Write-Host "RUNNING DEMO AGENT"
Write-Host "=" * 72
python agent/demo_agent.py

Write-Host ""

# Run attack scenarios
Write-Host "=" * 72
Write-Host "RUNNING ATTACK SCENARIOS"
Write-Host "=" * 72
python attacks/run_attacks.py

Write-Host ""

# Run investigator in offline mode
Write-Host "=" * 72
Write-Host "RUNNING INVESTIGATOR (offline mode)"
Write-Host "=" * 72
python agent/investigator.py --offline

Write-Host ""

# Verify the ledger
Write-Host "=" * 72
Write-Host "VERIFYING LEDGER INTEGRITY"
Write-Host "=" * 72
python ledger/verify.py --db data/ledger.db --key data/ledger_key.pem

Write-Host ""
Write-Host "=" * 72
Write-Host "ALL DONE. Dashboard still live at http://127.0.0.1:8080/"
Write-Host "Press Enter to shut down services..."
Write-Host "=" * 72
Read-Host

# Cleanup
Write-Host "Shutting down..."
Stop-Process -Id $broker.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $proxy.Id -Force -ErrorAction SilentlyContinue
Write-Host "Done."
