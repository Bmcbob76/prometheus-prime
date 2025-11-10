@echo off
REM ============================================================================
REM PROMETHEUS PRIME - P DRIVE INSTALLATION SCRIPT
REM Authority Level: 11.0
REM Target: P:\ECHO_PRIME\prometheus_prime_new
REM ============================================================================

echo.
echo ========================================================================
echo    PROMETHEUS PRIME ULTIMATE - P DRIVE INSTALLATION
echo    Authority Level: 11.0
echo    Operator: Commander Bobby Don McWilliams II
echo ========================================================================
echo.

REM Check if P: drive exists
if not exist P:\ (
    echo [ERROR] P: drive not found!
    echo Please ensure P: drive is mounted and accessible.
    pause
    exit /b 1
)

REM Create directory structure
echo [1/8] Creating directory structure...
if not exist "P:\ECHO_PRIME" mkdir "P:\ECHO_PRIME"
if not exist "P:\ECHO_PRIME\prometheus_prime_new" mkdir "P:\ECHO_PRIME\prometheus_prime_new"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\capabilities" mkdir "P:\ECHO_PRIME\prometheus_prime_new\capabilities"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\src" mkdir "P:\ECHO_PRIME\prometheus_prime_new\src"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\logs" mkdir "P:\ECHO_PRIME\prometheus_prime_new\logs"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\config" mkdir "P:\ECHO_PRIME\prometheus_prime_new\config"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\models" mkdir "P:\ECHO_PRIME\prometheus_prime_new\models"

REM Create memory directories
echo [2/8] Creating memory system directories...
if not exist "P:\MEMORY_ORCHESTRATION" mkdir "P:\MEMORY_ORCHESTRATION"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_operations" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_operations"

REM Copy all Python files
echo [3/8] Copying Python modules...
xcopy /Y /Q "*.py" "P:\ECHO_PRIME\prometheus_prime_new\" 2>nul
xcopy /Y /Q /S "capabilities\*.py" "P:\ECHO_PRIME\prometheus_prime_new\capabilities\" 2>nul
xcopy /Y /Q /S "src\*.py" "P:\ECHO_PRIME\prometheus_prime_new\src\" 2>nul

REM Copy documentation
echo [4/8] Copying documentation...
xcopy /Y /Q "*.md" "P:\ECHO_PRIME\prometheus_prime_new\" 2>nul

REM Copy configuration files
echo [5/8] Copying configuration files...
if exist ".env.example" copy /Y ".env.example" "P:\ECHO_PRIME\prometheus_prime_new\.env.example"
if exist "requirements.txt" copy /Y "requirements.txt" "P:\ECHO_PRIME\prometheus_prime_new\requirements.txt"

REM Create .env file if not exists
echo [6/8] Creating environment configuration...
if not exist "P:\ECHO_PRIME\prometheus_prime_new\.env" (
    (
        echo # PROMETHEUS PRIME CONFIGURATION
        echo # Authority Level: 11.0
        echo.
        echo # API Keys
        echo OPENAI_API_KEY=your-openai-key-here
        echo ANTHROPIC_API_KEY=your-anthropic-key-here
        echo ELEVENLABS_API_KEY=your-elevenlabs-key-here
        echo.
        echo # Prometheus Settings
        echo PROMETHEUS_AUTHORITY_LEVEL=11.0
        echo PROMETHEUS_COMMANDER=Bobby Don McWilliams II
        echo PROMETHEUS_MEMORY_PATH=P:\MEMORY_ORCHESTRATION
        echo.
        echo # Operational Settings
        echo PROMETHEUS_STEALTH_MODE=false
        echo PROMETHEUS_DEFENSE_MODE=true
        echo PROMETHEUS_AUTO_CRYSTALLIZE=true
        echo.
        echo # Voice Settings
        echo PROMETHEUS_VOICE_ENABLED=true
        echo PROMETHEUS_VOICE_PROFILE=tactical
    ) > "P:\ECHO_PRIME\prometheus_prime_new\.env"
    echo Created .env configuration file
)

REM Create launch scripts
echo [7/8] Creating launch scripts...

REM GUI Launch Script
(
    echo @echo off
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python prometheus_prime_ultimate_gui.py
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\LAUNCH_GUI.bat"

REM Expert Knowledge Test
(
    echo @echo off
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python prometheus_expert_knowledge.py
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\TEST_EXPERT_KNOWLEDGE.bat"

REM MCP Server Launch
(
    echo @echo off
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python mcp_server_complete.py
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\LAUNCH_MCP_SERVER.bat"

REM Autonomous Mode
(
    echo @echo off
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python src\autonomous\prometheus_autonomous.py
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\LAUNCH_AUTONOMOUS.bat"

REM Install Dependencies
(
    echo @echo off
    echo echo Installing Prometheus Prime dependencies...
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo pip install anthropic openai elevenlabs pyaudio SpeechRecognition pydub noisereduce vosk librosa opencv-python face-recognition pytesseract pillow mss screeninfo psutil scapy httpx redis
    echo echo.
    echo echo Dependencies installed!
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\INSTALL_DEPENDENCIES.bat"

REM Check installation
echo [8/8] Verifying installation...
if exist "P:\ECHO_PRIME\prometheus_prime_new\prometheus_prime_ultimate_gui.py" (
    echo [OK] GUI installed
) else (
    echo [WARNING] GUI file not found
)

if exist "P:\ECHO_PRIME\prometheus_prime_new\prometheus_expert_knowledge.py" (
    echo [OK] Expert knowledge installed
) else (
    echo [WARNING] Expert knowledge file not found
)

if exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals" (
    echo [OK] Memory system ready
) else (
    echo [WARNING] Memory directories not created
)

echo.
echo ========================================================================
echo    INSTALLATION COMPLETE!
echo ========================================================================
echo.
echo Installation Path: P:\ECHO_PRIME\prometheus_prime_new
echo Memory Path: P:\MEMORY_ORCHESTRATION
echo.
echo NEXT STEPS:
echo.
echo 1. Edit API keys in: P:\ECHO_PRIME\prometheus_prime_new\.env
echo 2. Install dependencies: INSTALL_DEPENDENCIES.bat
echo 3. Launch GUI: LAUNCH_GUI.bat
echo 4. Test system: TEST_EXPERT_KNOWLEDGE.bat
echo.
echo Authority Level: 11.0
echo Status: Ready for deployment
echo.
pause
