@echo off
echo ============================================================
echo  PROMETHEUS PRIME - DOMAIN INTELLIGENCE
echo  Authority Level: 11.0
echo ============================================================
echo.

cd /d %~dp0

echo Starting Domain Intelligence Module...
H:\Tools\python.exe domain_intelligence.py

if errorlevel 1 (
    echo.
    echo ERROR: Domain Intelligence failed to start
    echo Check API keys in .env file
    pause
)
