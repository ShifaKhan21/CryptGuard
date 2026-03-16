@echo off
title CryptGuard Launcher
echo ==========================================
echo       🛡️ CryptGuard System Launcher 🛡️
echo ==========================================
echo.

:: Check for Wireshark
if not exist "C:\Program Files\Wireshark\tshark.exe" (
    echo [ERROR] Wireshark/tshark not found at C:\Program Files\Wireshark\
    echo Please install Wireshark first: https://www.wireshark.org/
    pause
    exit /b
)

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+
    pause
    exit /b
)

:: Check for Node
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js not found. Please install Node.js.
    pause
    exit /b
)

echo [1/2] Starting AI API Server...
start "CryptGuard API" cmd /k "python api_server.py"

echo [2/2] Starting Dashboard UI...
cd web_ui
start "CryptGuard Dashboard" cmd /k "npm run dev"

echo.
echo ==========================================
echo SUCCESS: Everything is starting up!
echo Dashboard: http://localhost:5173
echo ==========================================
echo.
pause
