@echo off
REM ============================================================================
REM PROMETHEUS PRIME - P DRIVE INSTALLATION WITH ECHO PRIME API INTEGRATION
REM Authority Level: 11.0
REM Target: P:\ECHO_PRIME\prometheus_prime_new
REM API Keychain: P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
REM ============================================================================

echo.
echo ========================================================================
echo    PROMETHEUS PRIME ULTIMATE - P DRIVE INSTALLATION
echo    WITH ECHO PRIME API INTEGRATION
echo    Authority Level: 11.0
echo ========================================================================
echo.

REM Check if P: drive exists
if not exist P:\ (
    echo [ERROR] P: drive not found!
    echo Please ensure P: drive is mounted and accessible.
    pause
    exit /b 1
)

REM Check if Echo Prime API keychain exists
if not exist "P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env" (
    echo [WARNING] Echo Prime API keychain not found!
    echo Expected location: P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
    echo.
    echo Will create local configuration instead...
    set USE_ECHO_KEYCHAIN=false
) else (
    echo [OK] Found Echo Prime API keychain
    set USE_ECHO_KEYCHAIN=true
)

REM Create directory structure
echo [1/9] Creating directory structure...
if not exist "P:\ECHO_PRIME" mkdir "P:\ECHO_PRIME"
if not exist "P:\ECHO_PRIME\prometheus_prime_new" mkdir "P:\ECHO_PRIME\prometheus_prime_new"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\capabilities" mkdir "P:\ECHO_PRIME\prometheus_prime_new\capabilities"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\src" mkdir "P:\ECHO_PRIME\prometheus_prime_new\src"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\src\autonomous" mkdir "P:\ECHO_PRIME\prometheus_prime_new\src\autonomous"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\src\ai_brain" mkdir "P:\ECHO_PRIME\prometheus_prime_new\src\ai_brain"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\src\voice" mkdir "P:\ECHO_PRIME\prometheus_prime_new\src\voice"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\src\memory" mkdir "P:\ECHO_PRIME\prometheus_prime_new\src\memory"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\logs" mkdir "P:\ECHO_PRIME\prometheus_prime_new\logs"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\config" mkdir "P:\ECHO_PRIME\prometheus_prime_new\config"
if not exist "P:\ECHO_PRIME\prometheus_prime_new\models" mkdir "P:\ECHO_PRIME\prometheus_prime_new\models"

REM Create memory directories
echo [2/9] Creating memory system directories...
if not exist "P:\MEMORY_ORCHESTRATION" mkdir "P:\MEMORY_ORCHESTRATION"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_S" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_S"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_A" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_A"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_B" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_B"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_C" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_C"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_D" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_D"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_E" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_E"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_F" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_F"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_G" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_G"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_H" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_crystals\TIER_H"
if not exist "P:\MEMORY_ORCHESTRATION\prometheus_operations" mkdir "P:\MEMORY_ORCHESTRATION\prometheus_operations"

REM Copy all Python files
echo [3/9] Copying Python modules...
xcopy /Y /Q "*.py" "P:\ECHO_PRIME\prometheus_prime_new\" 2>nul
xcopy /Y /Q /S "capabilities\*.py" "P:\ECHO_PRIME\prometheus_prime_new\capabilities\" 2>nul
xcopy /Y /Q /S "src\*.py" "P:\ECHO_PRIME\prometheus_prime_new\src\" 2>nul

REM Copy documentation
echo [4/9] Copying documentation...
xcopy /Y /Q "*.md" "P:\ECHO_PRIME\prometheus_prime_new\" 2>nul

REM Copy configuration files
echo [5/9] Copying configuration files...
if exist "requirements.txt" copy /Y "requirements.txt" "P:\ECHO_PRIME\prometheus_prime_new\requirements.txt"

REM Create API integration configuration
echo [6/9] Configuring API integration...
if "%USE_ECHO_KEYCHAIN%"=="true" (
    REM Create symlink to Echo Prime keychain
    echo Using Echo Prime API keychain: P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env

    REM Create config file pointing to Echo keychain
    (
        echo # PROMETHEUS PRIME - ECHO PRIME API INTEGRATION
        echo # This configuration uses the Echo Prime API keychain
        echo #
        echo # API Keychain Location:
        echo # P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
        echo #
        echo # All API keys are loaded from Echo Prime keychain automatically
        echo # No additional configuration needed!
        echo.
        echo PROMETHEUS_API_KEYCHAIN=P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
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

    echo [OK] Configured to use Echo Prime API keychain
) else (
    REM Create local .env
    echo Creating local configuration file...
    (
        echo # PROMETHEUS PRIME CONFIGURATION
        echo # Authority Level: 11.0
        echo #
        echo # NOTE: Echo Prime API keychain not found
        echo # Add your API keys below or create keychain at:
        echo # P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
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

    echo [WARNING] Created local .env - you need to configure API keys
)

REM Create launch scripts
echo [7/9] Creating launch scripts...

REM GUI Launch Script
(
    echo @echo off
    echo title PROMETHEUS PRIME - Ultimate GUI
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python prometheus_prime_ultimate_gui.py
    echo if errorlevel 1 pause
) > "P:\ECHO_PRIME\prometheus_prime_new\LAUNCH_GUI.bat"

REM Expert Knowledge Test
(
    echo @echo off
    echo title PROMETHEUS PRIME - Expert Knowledge Test
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python prometheus_expert_knowledge.py
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\TEST_EXPERT_KNOWLEDGE.bat"

REM API Integration Test
(
    echo @echo off
    echo title PROMETHEUS PRIME - API Integration Test
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python prometheus_api_integration.py
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\TEST_API_INTEGRATION.bat"

REM MCP Server Launch
(
    echo @echo off
    echo title PROMETHEUS PRIME - MCP Server
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo python mcp_server_complete.py
    echo if errorlevel 1 pause
) > "P:\ECHO_PRIME\prometheus_prime_new\LAUNCH_MCP_SERVER.bat"

REM Autonomous Mode
(
    echo @echo off
    echo title PROMETHEUS PRIME - Autonomous Mode
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo echo.
    echo echo ========================================================================
    echo echo    PROMETHEUS PRIME - AUTONOMOUS MODE
    echo echo    WARNING: This mode operates autonomously
    echo echo    Ensure proper authorization and monitoring
    echo echo ========================================================================
    echo echo.
    echo pause
    echo python src\autonomous\prometheus_autonomous.py
    echo if errorlevel 1 pause
) > "P:\ECHO_PRIME\prometheus_prime_new\LAUNCH_AUTONOMOUS.bat"

REM Install Dependencies
(
    echo @echo off
    echo title PROMETHEUS PRIME - Dependency Installation
    echo echo ========================================================================
    echo echo    PROMETHEUS PRIME - Installing Dependencies
    echo echo ========================================================================
    echo echo.
    echo cd /d P:\ECHO_PRIME\prometheus_prime_new
    echo echo [1/2] Installing core dependencies...
    echo pip install anthropic openai elevenlabs python-dotenv
    echo echo.
    echo echo [2/2] Installing all dependencies...
    echo pip install pyaudio SpeechRecognition pydub noisereduce vosk librosa opencv-python face-recognition pytesseract pillow mss screeninfo psutil scapy httpx redis
    echo echo.
    echo echo ========================================================================
    echo echo    Dependencies installation complete!
    echo echo ========================================================================
    echo pause
) > "P:\ECHO_PRIME\prometheus_prime_new\INSTALL_DEPENDENCIES.bat"

REM Check installation
echo [8/9] Verifying installation...

set INSTALL_OK=true

if exist "P:\ECHO_PRIME\prometheus_prime_new\prometheus_prime_ultimate_gui.py" (
    echo [OK] GUI installed
) else (
    echo [ERROR] GUI file not found
    set INSTALL_OK=false
)

if exist "P:\ECHO_PRIME\prometheus_prime_new\prometheus_expert_knowledge.py" (
    echo [OK] Expert knowledge installed
) else (
    echo [ERROR] Expert knowledge file not found
    set INSTALL_OK=false
)

if exist "P:\ECHO_PRIME\prometheus_prime_new\prometheus_api_integration.py" (
    echo [OK] API integration installed
) else (
    echo [ERROR] API integration file not found
    set INSTALL_OK=false
)

if exist "P:\MEMORY_ORCHESTRATION\prometheus_crystals" (
    echo [OK] Memory system ready
) else (
    echo [ERROR] Memory directories not created
    set INSTALL_OK=false
)

if "%USE_ECHO_KEYCHAIN%"=="true" (
    if exist "P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env" (
        echo [OK] Echo Prime API keychain integrated
    ) else (
        echo [WARNING] Echo Prime keychain not accessible
    )
)

REM Create startup documentation
echo [9/9] Creating documentation...
(
    echo # PROMETHEUS PRIME - QUICK START GUIDE
    echo.
    echo Installation Complete!
    echo.
    echo ## Location
    echo Installation: P:\ECHO_PRIME\prometheus_prime_new
    echo Memory: P:\MEMORY_ORCHESTRATION
    if "%USE_ECHO_KEYCHAIN%"=="true" (
        echo API Keychain: P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
    )
    echo.
    echo ## Launch Scripts
    echo.
    echo - LAUNCH_GUI.bat - Launch Ultimate GUI
    echo - TEST_EXPERT_KNOWLEDGE.bat - Test expert system
    echo - TEST_API_INTEGRATION.bat - Test API integration
    echo - LAUNCH_MCP_SERVER.bat - Launch MCP server
    echo - LAUNCH_AUTONOMOUS.bat - Launch autonomous mode
    echo - INSTALL_DEPENDENCIES.bat - Install Python packages
    echo.
    echo ## First Steps
    echo.
    echo 1. Install dependencies: INSTALL_DEPENDENCIES.bat
    echo 2. Test API integration: TEST_API_INTEGRATION.bat
    echo 3. Test expert system: TEST_EXPERT_KNOWLEDGE.bat
    echo 4. Launch GUI: LAUNCH_GUI.bat
    echo.
    echo ## Documentation
    echo.
    echo - P_DRIVE_INSTALLATION_GUIDE.md
    echo - PROMETHEUS_AUTONOMY_STATUS.md
    echo - GUI_USAGE_GUIDE.md
    echo - PROMETHEUS_209_TOOLS.md
    echo.
    echo Authority Level: 11.0
    echo Status: Ready for deployment
) > "P:\ECHO_PRIME\prometheus_prime_new\QUICK_START.txt"

echo.
echo ========================================================================
echo    INSTALLATION COMPLETE!
echo ========================================================================
echo.
echo Installation Path: P:\ECHO_PRIME\prometheus_prime_new
echo Memory Path: P:\MEMORY_ORCHESTRATION
if "%USE_ECHO_KEYCHAIN%"=="true" (
    echo API Keychain: P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
    echo.
    echo [OK] Using Echo Prime API keychain - All APIs automatically available!
) else (
    echo.
    echo [WARNING] Echo Prime API keychain not found
    echo You need to configure API keys in: P:\ECHO_PRIME\prometheus_prime_new\.env
)
echo.
echo NEXT STEPS:
echo.
echo 1. Install dependencies: INSTALL_DEPENDENCIES.bat
echo 2. Test API integration: TEST_API_INTEGRATION.bat
echo 3. Test expert system: TEST_EXPERT_KNOWLEDGE.bat
echo 4. Launch GUI: LAUNCH_GUI.bat
echo.
echo See QUICK_START.txt for complete guide
echo.
echo Authority Level: 11.0
echo Status: %INSTALL_OK%
echo.
pause
