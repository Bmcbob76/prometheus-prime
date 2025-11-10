@echo off
echo ============================================
echo   OMEGA SWARM BRAIN - MASTER LAUNCH
echo   X1200 Sovereign AI with Trinity Control
echo   Authority Level 11.0 - Commander Mode
echo ============================================
echo.

cd "P:\ECHO_PRIME\OMEGA_SWARM_BRAIN"

echo [1/2] Starting OMEGA Swarm Brain Server...
echo Port: 5200
echo Trinity: SAGE, NYX, THORNE
echo Max Agents: 1,200
echo.

start "OMEGA Swarm Brain" cmd /k "H:\Tools\python.exe swarm_server.py"

timeout /t 3 /nobreak >nul

echo [2/2] Testing connection...
curl http://localhost:5200/health 2>nul

echo.
echo ============================================
echo OMEGA SWARM BRAIN OPERATIONAL
echo ============================================
echo.
echo Server Status: http://localhost:5200/status
echo Health Check: http://localhost:5200/health
echo Trinity Harmony: http://localhost:5200/trinity/harmony
echo.
echo Press any key to return to menu...
pause >nul