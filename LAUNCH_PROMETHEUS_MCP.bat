@echo off
REM 🎯 PROMETHEUS PRIME MCP SERVER LAUNCHER
REM Authority Level: 11.0

echo ========================================
echo 🎯 PROMETHEUS PRIME MCP SERVER
echo    Authority Level: 11.0
echo ========================================

cd /d "%~dp0"

echo.
echo 🔧 Starting MCP server...
H:\Tools\python.exe prometheus_prime_mcp.py

pause