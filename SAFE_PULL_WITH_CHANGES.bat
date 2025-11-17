@echo off
echo.
echo ========================================
echo SAFE GIT PULL - Handles Changes
echo ========================================
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0SAFE_PULL_WITH_CHANGES.ps1"

echo.
pause
