@echo off
chcp 65001 >nul
title LAN File Server

:: Change to script directory
cd /d "%~dp0"

echo.
echo ================================================
echo          LAN File Server Launcher
echo ================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found!
    echo Please install Python and add to PATH
    echo.
    pause
    exit /b 1
)

:: Check if server.py exists
if not exist "server.py" (
    echo Error: server.py not found!
    echo Please run this script in the correct directory
    echo.
    pause
    exit /b 1
)

echo [Info] Starting LAN File Server...
echo.
echo Press Ctrl+C to stop the server
echo.

:: Start server (disable Ctrl+C confirmation)
python server.py

echo.
echo Server stopped
timeout /t 2 >nul