@echo off
echo.
echo ========================================
echo OMEGA PRIME ECHO BROWSER INSTALLATION
echo ========================================
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0INSTALL_OMEGA_BROWSER.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Installation failed!
    pause
    exit /b 1
)

echo.
echo Press any key to exit...
pause > nul
