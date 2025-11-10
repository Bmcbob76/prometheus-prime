@echo off
title PROMETHEUS PRIME - MCP Server
cd /d P:\ECHO_PRIME\prometheus_prime_new
python mcp_server_complete.py
if errorlevel 1 pause
