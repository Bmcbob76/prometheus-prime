@echo off
REM ============================================================================
REM PROMETHEUS PRIME - QUICK P DRIVE SETUP
REM One-click installation to P:\ECHO_PRIME\prometheus_prime_new
REM ============================================================================

title PROMETHEUS PRIME - P DRIVE QUICK SETUP
color 0A

echo.
echo  ███████████                                           █████    █████
echo ░░███░░░░░███                                         ░░███    ░░███
echo  ░███    ░███ ████████   ██████  █████████████   ██████ ███████  ░███████   ██████  █████ ████  ██████
echo  ░██████████ ░░███░░███ ███░░███░░███░░███░░███ ███░░███░░░███░   ░███░░███ ███░░███░░███ ░███  ███░░███
echo  ░███░░░░░░   ░███ ░░░ ░███ ░███ ░███ ░███ ░███░███████   ░███    ░███ ░███░███████  ░███ ░███ ░███ ░░░
echo  ░███         ░███     ░███ ░███ ░███ ░███ ░███░███░░░    ░███ ███░███ ░███░███░░░   ░███ ░███ ░███  ███
echo  █████        █████    ░░██████  █████░███ █████░░██████   ░░█████ ████ █████░░██████  ░░████████░░██████
echo ░░░░░        ░░░░░      ░░░░░░  ░░░░░ ░░░ ░░░░░  ░░░░░░     ░░░░░ ░░░░ ░░░░░  ░░░░░░    ░░░░░░░░  ░░░░░░
echo.
echo                          ULTIMATE P DRIVE INSTALLATION
echo                          Authority Level: 11.0
echo.
echo ============================================================================
echo.

REM Check if running from current directory
if not exist "prometheus_prime_ultimate_gui.py" (
    echo [ERROR] Please run this script from the Prometheus Prime directory!
    echo Current directory: %CD%
    pause
    exit /b 1
)

echo [STEP 1/4] Checking prerequisites...
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+ first.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
) else (
    echo [OK] Python is installed
    python --version
)

REM Check P: drive
if not exist P:\ (
    echo [ERROR] P: drive not found!
    echo Please ensure P: drive is mounted.
    pause
    exit /b 1
) else (
    echo [OK] P: drive is accessible
)

echo.
echo [STEP 2/4] Installing to P:\ECHO_PRIME\prometheus_prime_new...
echo.

REM Run main installation
call INSTALL_P_DRIVE.bat

echo.
echo [STEP 3/4] Configuring environment...
echo.

REM Open .env file in notepad for user to configure
echo Opening configuration file for API key setup...
timeout /t 2 >nul
start notepad "P:\ECHO_PRIME\prometheus_prime_new\.env"

echo.
echo IMPORTANT: Please add your API keys to the .env file:
echo.
echo   OPENAI_API_KEY=sk-your-actual-key
echo   ANTHROPIC_API_KEY=sk-ant-your-actual-key
echo   ELEVENLABS_API_KEY=your-actual-key
echo.
echo Press any key after you've saved your API keys...
pause >nul

echo.
echo [STEP 4/4] Installing Python dependencies...
echo.
echo This may take 5-10 minutes...
echo.

cd /d P:\ECHO_PRIME\prometheus_prime_new
pip install anthropic openai elevenlabs pyaudio SpeechRecognition pydub noisereduce vosk librosa opencv-python face-recognition pytesseract pillow mss screeninfo psutil scapy httpx redis 2>nul

if errorlevel 1 (
    echo [WARNING] Some dependencies may have failed to install
    echo You can retry later with: INSTALL_DEPENDENCIES.bat
) else (
    echo [OK] Dependencies installed successfully
)

echo.
echo ============================================================================
echo                    INSTALLATION COMPLETE!
echo ============================================================================
echo.
echo Installation Location: P:\ECHO_PRIME\prometheus_prime_new
echo Memory Location: P:\MEMORY_ORCHESTRATION
echo.
echo QUICK START OPTIONS:
echo.
echo 1. Launch GUI:          cd /d P:\ECHO_PRIME\prometheus_prime_new
echo                         LAUNCH_GUI.bat
echo.
echo 2. Test System:         TEST_EXPERT_KNOWLEDGE.bat
echo.
echo 3. View Documentation:  Browse *.md files in installation directory
echo.
echo DOCUMENTATION FILES:
echo   - P_DRIVE_INSTALLATION_GUIDE.md (Complete setup guide)
echo   - PROMETHEUS_AUTONOMY_STATUS.md (Autonomy capabilities)
echo   - GUI_USAGE_GUIDE.md (GUI interface guide)
echo   - PROMETHEUS_209_TOOLS.md (Tool reference)
echo.
echo Authority Level: 11.0
echo Status: Ready for deployment
echo.
echo Press any key to open installation directory...
pause >nul

explorer P:\ECHO_PRIME\prometheus_prime_new

echo.
echo Thank you for installing PROMETHEUS PRIME ULTIMATE!
echo.
pause
