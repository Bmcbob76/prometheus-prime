@echo off
title PROMETHEUS PRIME - GUI V2
color 0A

echo.
echo ========================================================================
echo    🔥 PROMETHEUS PRIME - PRODUCTION GUI V2
echo ========================================================================
echo.
echo    ✅ Fully Working Buttons
echo    ✅ Tooltips on All Elements
echo    ✅ Real Operation Execution
echo    ✅ Status Indicators
echo    ✅ Progress Tracking
echo.
echo    Authority Level: 11.0
echo    Commander: Bobby Don McWilliams II
echo.
echo ========================================================================
echo.

cd /d "%~dp0"

echo [1/2] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do echo [OK] Python %%v
echo.

echo [2/2] Launching GUI V2...
echo.
python prometheus_gui_v2.py

if errorlevel 1 (
    echo.
    echo [ERROR] GUI failed to launch
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo    GUI closed normally
echo ========================================================================
pause
