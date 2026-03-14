# CryptGuard - Multi-process Startup Script
# This script starts the DPI Engine Bridge and the React Frontend in parallel.

Write-Host "--- CryptGuard Startup ---" -ForegroundColor Cyan

# 1. Start the Python Bridge Server (DPI Simulation & JSON API)
Write-Host "[1/2] Launching DPI Bridge Server..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python server.py" -WindowStyle Normal

# 2. Start the React Frontend
Write-Host "[2/2] Launching Frontend Dashboard..." -ForegroundColor Yellow
cd frontend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "npm run dev" -WindowStyle Normal

Write-Host "`nProject is starting!" -ForegroundColor Green
Write-Host "1. DPI data will be served at http://localhost:5000/api/stats"
Write-Host "2. Dashboard UI will be available at http://localhost:5173"
Write-Host "Check the newly opened terminal windows for logs."
