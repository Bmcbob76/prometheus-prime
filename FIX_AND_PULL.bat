@echo off
echo.
echo ========================================
echo FIX AND PULL - Automatic Solution
echo ========================================
echo.
echo This will:
echo 1. Stash your local changes
echo 2. Pull latest code from git
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0FIX_AND_PULL.ps1"

echo.
pause
