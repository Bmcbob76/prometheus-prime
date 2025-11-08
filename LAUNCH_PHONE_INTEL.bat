@echo off
REM 🎯 PROMETHEUS PRIME - PHONE INTELLIGENCE LAUNCHER
REM Twilio CNAM Lookup with Smart Caching

echo.
echo ============================================================
echo    PROMETHEUS PRIME - PHONE INTELLIGENCE
echo    Twilio Caller Name Lookup + Smart Caching
echo    Authority Level: 11.0
echo ============================================================
echo.

REM Install twilio if needed
H:\Tools\python.exe -m pip install --quiet twilio python-dotenv

echo.
H:\Tools\python.exe P:\ECHO_PRIME\MLS_CLEAN\PRODUCTION\GATEWAYS\PROMETHEUS_PRIME\phone_intelligence.py %*

pause
