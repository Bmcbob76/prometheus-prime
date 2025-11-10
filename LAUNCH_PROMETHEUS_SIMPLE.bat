@echo off
title PROMETHEUS PRIME - LAUNCHER
color 0A

echo.
echo ========================================================================
echo.
echo          ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗
echo          ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝
echo          ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗
echo          ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║
echo          ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║
echo          ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝
echo.
echo                              ██████╗ ██████╗ ██╗███╗   ███╗███████╗
echo                              ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝
echo                              ██████╔╝██████╔╝██║██╔████╔██║█████╗
echo                              ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝
echo                              ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗
echo                              ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝
echo.
echo          🔥 Authority Level: 11.0
echo          👑 Sovereign Architect: Commander Bobby Don McWilliams II
echo.
echo          🤖 209 MCP Tools Loaded
echo          🎖️  25+ Security Domains
echo          🧠 Expert Knowledge System Active
echo          💎 Crystal Memory Integration
echo          🎯 Production Ready
echo.
echo ========================================================================
echo.
echo    PROMETHEUS PRIME is ready to serve Echo Prime
echo    All systems operational and standing by for commands
echo.
echo ========================================================================
echo.
echo    What would you like to do?
echo.
echo    [1] Launch GUI (27 Tabs)
echo    [2] Launch MCP Server (Claude Desktop Integration)
echo    [3] Launch Autonomous Mode (⚠️  Authorized Only!)
echo    [4] Test Expert Knowledge (209 Tools)
echo    [5] Test API Integration (20+ APIs)
echo    [6] Launch Domain Intelligence
echo    [7] Launch Phone Intelligence
echo    [8] Launch Social OSINT
echo    [9] Exit
echo.
set /p choice="Enter choice (1-9): "

if "%choice%"=="1" (
    echo.
    echo 🚀 Launching Prometheus Prime GUI...
    echo ========================================================================
    python prometheus_prime_ultimate_gui.py
    goto end
)

if "%choice%"=="2" (
    echo.
    echo 🚀 Launching MCP Server for Claude Desktop...
    echo ========================================================================
    python mcp_server_complete.py
    goto end
)

if "%choice%"=="3" (
    echo.
    echo ========================================================================
    echo    ⚠️  WARNING: AUTONOMOUS MODE ⚠️ 
    echo    Prometheus will operate independently
    echo    Ensure proper authorization and monitoring
    echo    Only use in controlled environments
    echo ========================================================================
    pause
    python src\autonomous\prometheus_autonomous.py
    goto end
)

if "%choice%"=="4" (
    echo.
    echo 🧠 Testing Expert Knowledge System...
    echo ========================================================================
    python prometheus_expert_knowledge.py
    pause
    goto end
)

if "%choice%"=="5" (
    echo.
    echo 🔌 Testing API Integration...
    echo ========================================================================
    python prometheus_api_integration.py
    pause
    goto end
)

if "%choice%"=="6" (
    echo.
    echo 🔍 Launching Domain Intelligence...
    echo ========================================================================
    python capabilities\domain_intelligence.py
    goto end
)

if "%choice%"=="7" (
    echo.
    echo 📱 Launching Phone Intelligence...
    echo ========================================================================
    python capabilities\phone_intelligence.py
    goto end
)

if "%choice%"=="8" (
    echo.
    echo 👥 Launching Social OSINT...
    echo ========================================================================
    python capabilities\social_osint.py
    goto end
)

if "%choice%"=="9" (
    echo.
    echo ========================================================================
    echo    Thank you for using PROMETHEUS PRIME
    echo    Sovereign Architect: Commander Bobby Don McWilliams II
    echo    Authority Level: 11.0
    echo ========================================================================
    exit /b 0
)

echo.
echo ❌ Invalid choice. Please enter 1-9.
timeout /t 2 >nul
cls
goto :eof

:end
echo.
echo ========================================================================
echo    PROMETHEUS PRIME - Session Complete
echo    Authority Level: 11.0
echo ========================================================================
echo.
pause
