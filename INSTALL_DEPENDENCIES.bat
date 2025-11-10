@echo off
title PROMETHEUS PRIME - Dependency Installation
echo ========================================================================
echo    PROMETHEUS PRIME - Installing Dependencies
echo ========================================================================
echo.
cd /d P:\ECHO_PRIME\prometheus_prime_new

REM Detect Python version
echo Detecting Python version...
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo Python version: %PYVER%
echo.

REM Check if Python 3.14+
echo %PYVER% | findstr /C:"3.14" >nul
if %errorlevel%==0 (
    echo [INFO] Python 3.14 detected - using compatible requirements
    echo [INFO] Note: librosa/numba not compatible with Python 3.14 yet
    echo [INFO] See PYTHON_314_COMPATIBILITY.md for details
    set REQUIREMENTS_FILE=requirements_py314_compatible.txt
) else (
    echo [INFO] Using full requirements including audio analysis
    set REQUIREMENTS_FILE=requirements.txt
)
echo.
echo [1/3] Installing core dependencies...
pip install anthropic openai elevenlabs python-dotenv
echo.
echo [2/3] Installing from %REQUIREMENTS_FILE%...
pip install -r %REQUIREMENTS_FILE%
echo.
echo [3/3] Verifying installation...
python -c "from prometheus_expert_knowledge import PrometheusExpertise; print^('✅ Expert system OK'^)"
python -c "from prometheus_api_integration import PrometheusAPIIntegration; print^('✅ API integration OK'^)"
echo.
echo ========================================================================
echo    Dependencies installation complete!
echo ========================================================================
echo.
echo %PYVER% | findstr /C:"3.14" >nul
if %errorlevel%==0 (
    echo [NOTE] You are using Python 3.14
    echo [NOTE] Advanced audio analysis (librosa) not available
    echo [NOTE] All other features (209 tools, GUI, autonomous, etc.) work perfectly
    echo [NOTE] See PYTHON_314_COMPATIBILITY.md for more info
)
echo.
pause
