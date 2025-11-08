@echo off
REM 🎯 PROMETHEUS PRIME - COMPLETE INSTALLATION
REM Authority Level: 11.0

echo ========================================
echo 🎯 PROMETHEUS PRIME INSTALLATION
echo    Complete Offensive/Defensive Platform
echo ========================================

cd /d "%~dp0"

echo.
echo 📦 Installing Python dependencies...
H:\Tools\python.exe -m pip install -r requirements.txt --break-system-packages

echo.
echo ✅ Python dependencies installed!

echo.
echo 📋 EXTERNAL TOOLS CHECKLIST:
echo.
echo ⬜ Nmap - https://nmap.org/download.html
echo ⬜ Android SDK Platform Tools (ADB) - https://developer.android.com/tools/releases/platform-tools
echo ⬜ libimobiledevice (optional for iOS) - https://libimobiledevice.org/
echo ⬜ Metasploit Framework (optional) - https://www.metasploit.com/
echo ⬜ Exploit-DB/SearchSploit (optional) - https://www.exploit-db.com/
echo.
echo 🔑 API KEYS REQUIRED:
echo.
echo Configure these in: P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env
echo.
echo • TWILIO_ACCOUNT_SID
echo • TWILIO_AUTH_TOKEN
echo • REDDIT_CLIENT_ID
echo • REDDIT_CLIENT_SECRET
echo • WHOISXML_API_KEY
echo • HIBP_API_KEY
echo • VIRUSTOTAL_API_KEY
echo • SHODAN_API_KEY
echo • ABUSEIPDB_API_KEY
echo.
echo ========================================
echo ✅ INSTALLATION COMPLETE
echo ========================================
echo.
echo 🚀 To start:
echo    LAUNCH_PROMETHEUS_MCP.bat
echo.
pause
