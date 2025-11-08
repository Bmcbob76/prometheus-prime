@echo off
title PROMETHEUS PRIME - EPIC LAUNCHER
color 0A

echo.
echo ========================================================================
echo.
echo          ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗
echo          ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝
echo          ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗
echo          ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║
echo          ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║
echo          ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝
echo.
echo                              ██████╗ ██████╗ ██╗███╗   ███╗███████╗
echo                              ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝
echo                              ██████╔╝██████╔╝██║██╔████╔██║█████╗
echo                              ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝
echo                              ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗
echo                              ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝
echo.
echo          Authority Level: 11.0
echo          Sovereign Architect: Commander Bobby Don McWilliams II
echo.
echo ========================================================================
echo.

REM Determine script location
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [OK] Python version: %PYVER%
echo.

echo [2/5] Creating virtual environment...
if exist "venv" (
    echo [OK] Virtual environment already exists
) else (
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
)
echo.

echo [3/5] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)
echo [OK] Virtual environment activated
echo.

echo [4/5] Installing launcher dependencies...
echo.
echo    Installing pygame for graphics...
pip install pygame --quiet
echo    Installing elevenlabs for voice...
pip install elevenlabs --quiet
echo    Installing python-dotenv for config...
pip install python-dotenv --quiet
echo.
echo [OK] Launcher dependencies installed
echo.

echo [5/5] Launching PROMETHEUS PRIME...
echo.
echo ========================================================================
echo                   🔥 INITIATING EPIC LAUNCHER 🔥
echo ========================================================================
echo.
echo    Press ESC during launch to skip
echo    Press SPACE during announcement to skip
echo.
echo ========================================================================
echo.

REM Set API key path
set DOTENV_PATH=P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env

REM Launch the epic launcher
python prometheus_launcher.py

if errorlevel 1 (
    echo.
    echo [ERROR] Launcher encountered an error
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo                   ✅ PROMETHEUS PRIME READY ✅
echo ========================================================================
echo.
echo    What would you like to do?
echo.
echo    [1] Launch GUI
echo    [2] Launch MCP Server
echo    [3] Launch Autonomous Mode
echo    [4] Test Expert Knowledge
echo    [5] Test API Integration
echo    [6] Exit
echo.
set /p choice="Enter choice (1-6): "

if "%choice%"=="1" (
    echo.
    echo Launching GUI...
    python prometheus_prime_ultimate_gui.py
)

if "%choice%"=="2" (
    echo.
    echo Launching MCP Server...
    python mcp_server_complete.py
)

if "%choice%"=="3" (
    echo.
    echo ========================================================================
    echo    WARNING: Autonomous mode operates independently
    echo    Ensure proper authorization and monitoring
    echo ========================================================================
    pause
    python src\autonomous\prometheus_autonomous.py
)

if "%choice%"=="4" (
    echo.
    echo Testing Expert Knowledge...
    python prometheus_expert_knowledge.py
    pause
)

if "%choice%"=="5" (
    echo.
    echo Testing API Integration...
    python prometheus_api_integration.py
    pause
)

echo.
echo ========================================================================
echo    Thank you for using PROMETHEUS PRIME
echo    Sovereign Architect: Commander Bobby Don McWilliams II
echo ========================================================================
echo.
pause
