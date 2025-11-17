@echo off
cls
echo.
echo ========================================
echo PROMETHEUS PRIME - COMPLETE SETUP
echo ========================================
echo.
echo This will:
echo 1. Fix git line endings
echo 2. Switch to correct branch
echo 3. Integrate all 27,485+ files
echo 4. Install OMEGA browser
echo 5. Verify everything works
echo.
echo Starting in 3 seconds...
timeout /t 3 /nobreak > nul
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0DO_EVERYTHING_NOW.ps1"

echo.
echo ========================================
echo Press any key to exit...
pause > nul
