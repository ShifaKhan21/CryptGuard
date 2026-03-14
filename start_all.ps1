# CryptGuard - Full Project Launcher
Write-Host "=== CryptGuard Startup ===" -ForegroundColor Cyan

# Kill any old instances of the bridge
Get-Process | Where-Object { $_.CommandLine -like "*server.py*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Also free port 5000 if anything is using it
$port5000 = netstat -ano | findstr ":5000" | findstr "LISTENING"
if ($port5000) {
    $pid5000 = ($port5000 -split "\s+")[-1]
    Stop-Process -Id $pid5000 -Force -ErrorAction SilentlyContinue
    Write-Host "Freed port 5000." -ForegroundColor Yellow
}

Start-Sleep 1

# Start Python Bridge
Write-Host "[1/2] Starting DPI Bridge Server..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit -Command python server.py" -WorkingDirectory $PSScriptRoot

Start-Sleep 2

# Start Frontend
Write-Host "[2/2] Starting Frontend Dashboard..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit -Command npm run dev" -WorkingDirectory (Join-Path $PSScriptRoot "frontend")

Write-Host ""
Write-Host "Project is live!" -ForegroundColor Cyan
Write-Host "  Bridge API  -> http://localhost:5000/api/stats" -ForegroundColor White
Write-Host "  Dashboard   -> http://localhost:5173" -ForegroundColor White
