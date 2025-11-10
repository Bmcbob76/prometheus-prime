@echo off
title PROMETHEUS PRIME - Autonomous Mode
cd /d P:\ECHO_PRIME\prometheus_prime_new
echo.
echo ========================================================================
echo    PROMETHEUS PRIME - AUTONOMOUS MODE
echo    WARNING: This mode operates autonomously
echo    Ensure proper authorization and monitoring
echo ========================================================================
echo.
pause
python src\autonomous\prometheus_autonomous.py
if errorlevel 1 pause
