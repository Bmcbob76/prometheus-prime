@echo off
REM ========================================
REM PROMETHEUS PRIME - GIT TO PC INTEGRATION
REM ========================================
REM Simple batch version for quick integration
REM ========================================

echo ========================================
echo PROMETHEUS PRIME - GIT INTEGRATION
echo ========================================
echo.

REM Run the PowerShell script with execution policy bypass
echo Running integration script...
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0INTEGRATE_GIT_TO_PC.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Integration failed!
    echo Please check the output above for details.
    pause
    exit /b 1
)

echo.
echo ========================================
echo INTEGRATION COMPLETE!
echo ========================================
echo.
echo Press any key to exit...
pause > nul
