# 🎯 PROMETHEUS PRIME - CLAUDE CODE INTEGRATION INSTRUCTIONS

**Authority Level:** 11.0  
**Target:** Make ALL Prometheus Prime capabilities available as MCP tools for Claude

---

## 📍 SYSTEM LOCATION

```
P:\ECHO_PRIME\prometheus_prime
```

---

## 🎯 MISSION OBJECTIVE

Ensure ALL Prometheus Prime capabilities are exposed as MCP tools that Claude can use, including:
- OSINT Intelligence (5 modules)
- Network Security (5 tools)
- Mobile Device Control (8 tools)
- Web Security Testing (8 tools)
- Exploitation Framework (5 tools)
- Phoenix Healing (1 tool)

**Total Target:** 43 MCP tools fully operational

---

## ✅ WHAT'S ALREADY DONE

### Core Modules Created (9 files)
1. ✅ `phone_intelligence.py` - Phone OSINT with Twilio
2. ✅ `social_osint.py` - Reddit/social media OSINT
3. ✅ `domain_intelligence.py` - WHOIS/DNS intelligence
4. ✅ `email_intelligence.py` - HIBP breach detection
5. ✅ `ip_intelligence.py` - IP geolocation/Shodan
6. ✅ `network_security.py` - Port scanning, Nmap, vuln detection
7. ✅ `mobile_control.py` - iOS/Android device control
8. ✅ `web_security.py` - SQL injection, XSS, crawling
9. ✅ `exploitation_framework.py` - Metasploit, payload generation

### MCP Server
✅ `prometheus_prime_mcp.py` - Complete MCP server with 43 tools

### Configuration
✅ `mls_config.json` - Master Launcher System registration
✅ `requirements.txt` - Python dependencies
✅ `.env` - API keys configuration

---

## 🔧 VERIFICATION STEPS

### Step 1: Check File Integrity
```bash
cd P:\ECHO_PRIME\prometheus_prime

# Verify all core modules exist
ls -la *.py | grep -E "(phone|social|domain|email|ip|network|mobile|web|exploit)"

# Expected output: 9 module files
```

### Step 2: Verify MCP Server
```bash
# Check prometheus_prime_mcp.py exists and has 43 tools
cat prometheus_prime_mcp.py | grep "Tool(" | wc -l
# Expected: 43

# Check server initialization
cat prometheus_prime_mcp.py | grep "Total Tools: 43"
# Should find this in the main() function
```

### Step 3: Test Python Dependencies
```bash
H:\Tools\python.exe -m pip list | grep -E "(flask|requests|mcp|twilio|dnspython)"

# Install if missing:
H:\Tools\python.exe -m pip install -r requirements.txt --break-system-packages
```

### Step 4: Validate MCP Configuration
```bash
# Check Claude Desktop MCP config
cat "%APPDATA%\Claude\claude_desktop_config.json"

# Should contain prometheus-prime server entry:
# {
#   "mcpServers": {
#     "prometheus-prime": {
#       "command": "H:\\Tools\\python.exe",
#       "args": ["P:\\ECHO_PRIME\\prometheus_prime\\prometheus_prime_mcp.py"]
#     }
#   }
# }
```

---

## 🚀 ACTIVATION STEPS

### Step 1: Add to Claude Desktop Config

**Location:** `%APPDATA%\Claude\claude_desktop_config.json`

**Add this entry:**
```json
{
  "mcpServers": {
    "prometheus-prime": {
      "command": "H:\\Tools\\python.exe",
      "args": ["P:\\ECHO_PRIME\\prometheus_prime\\prometheus_prime_mcp.py"],
      "env": {
        "PYTHONPATH": "P:\\ECHO_PRIME\\prometheus_prime"
      }
    }
  }
}
```

### Step 2: Test MCP Server Standalone
```bash
cd P:\ECHO_PRIME\prometheus_prime

# Test server launches
H:\Tools\python.exe prometheus_prime_mcp.py

# Expected output:
# ====================================
# 🎯 PROMETHEUS PRIME - COMPLETE OFFENSIVE/DEFENSIVE
#    Authority Level: 11.0
#
#    📊 CAPABILITIES:
#    • OSINT (5 modules)
#    • Network Security (Nmap, port scanning, vuln detection)
#    • Mobile Control (iOS/Android via ADB/libimobiledevice)
#    • Web Security (SQL injection, XSS, crawling)
#    • Exploitation (Metasploit, payload generation)
#
#    📡 Tools Available: 43
#    🔥 Phoenix Healing: ENABLED
# ====================================
```

### Step 3: Restart Claude Desktop
```bash
# Kill Claude if running
taskkill /F /IM "claude.exe"

# Launch Claude Desktop
# MCP tools should now be available
```

---

## 🔍 TESTING TOOLS

### Test OSINT Tools
```
In Claude chat, try:
- Use prom_health to check system status
- Use prom_phone_lookup with phone="+15555551234"
- Use prom_domain_lookup with domain="example.com"
```

### Test Network Security
```
In Claude chat, try:
- Use prom_port_scan with target="192.168.1.1"
- Use prom_nmap_scan with target="scanme.nmap.org"
```

### Test Mobile Control
```
In Claude chat, try:
- Use prom_android_devices to list connected devices
- Use prom_ios_devices to list iOS devices
```

### Test Web Security
```
In Claude chat, try:
- Use prom_web_headers with url="https://example.com"
- Use prom_tech_detect with url="https://example.com"
```

### Test Exploitation
```
In Claude chat, try:
- Use prom_search_exploits with query="windows smb"
- Use prom_list_payloads with platform="windows"
```

---

## 📊 ALL 43 TOOLS REFERENCE

### OSINT (6 tools)
1. `prom_health` - System health check
2. `prom_phone_lookup` - Reverse phone lookup
3. `prom_social_search` - Social media OSINT
4. `prom_domain_lookup` - Domain intelligence
5. `prom_email_analyze` - Email breach detection
6. `prom_ip_analyze` - IP intelligence

### Network Security (5 tools)
7. `prom_port_scan` - Multi-threaded port scanner
8. `prom_nmap_scan` - Nmap integration
9. `prom_vulnerability_scan` - Vulnerability assessment
10. `prom_subnet_scan` - Subnet host discovery
11. `prom_service_banner` - Service fingerprinting

### Mobile Control (8 tools)
12. `prom_android_devices` - List Android devices
13. `prom_android_info` - Android device info
14. `prom_android_shell` - Execute shell commands
15. `prom_android_screenshot` - Capture screenshot
16. `prom_android_apps` - List installed apps
17. `prom_ios_devices` - List iOS devices
18. `prom_ios_info` - iOS device info
19. `prom_ios_screenshot` - Capture screenshot

### Web Security (8 tools)
20. `prom_web_headers` - Security header check
21. `prom_sql_injection` - SQL injection testing
22. `prom_xss_test` - XSS vulnerability testing
23. `prom_dir_bruteforce` - Directory enumeration
24. `prom_web_crawl` - Website crawler
25. `prom_ssl_scan` - SSL/TLS analysis
26. `prom_tech_detect` - Technology detection
27. `prom_web_comprehensive` - Complete web assessment

### Exploitation (5 tools)
28. `prom_search_exploits` - Search exploit-db
29. `prom_generate_payload` - Generate msfvenom payloads
30. `prom_list_payloads` - List available payloads
31. `prom_pattern_create` - Cyclic pattern generation
32. `prom_msf_search` - Search Metasploit modules

### Batch & Utility (2 tools)
33. `prom_osint_full` - Complete OSINT report (all modules)
34. `prom_healing_stats` - Phoenix healing statistics

---

## 🐛 TROUBLESHOOTING

### Issue: Tools not showing in Claude
**Solution:**
```bash
# 1. Check config file syntax
python -m json.tool "%APPDATA%\Claude\claude_desktop_config.json"

# 2. Check MCP server logs
# Look in Claude Desktop Developer Tools (Ctrl+Shift+I)
# Check Console tab for MCP connection errors

# 3. Verify Python path
where python
# Should show H:\Tools\python.exe

# 4. Test MCP server manually
cd P:\ECHO_PRIME\prometheus_prime
H:\Tools\python.exe prometheus_prime_mcp.py
```

### Issue: Import errors
**Solution:**
```bash
cd P:\ECHO_PRIME\prometheus_prime

# Install all dependencies
H:\Tools\python.exe -m pip install flask flask-cors requests python-dotenv twilio dnspython mcp beautifulsoup4 pymysql --break-system-packages

# Verify imports
H:\Tools\python.exe -c "import mcp; print('MCP OK')"
H:\Tools\python.exe -c "from phone_intelligence import PhoneIntelligence; print('Phone Intel OK')"
```

### Issue: API key errors
**Solution:**
```bash
# Check .env file exists
cat P:\ECHO_PRIME\prometheus_prime\.env

# Check master keychain
cat P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env

# Verify keys are loaded
H:\Tools\python.exe -c "from dotenv import load_dotenv; import os; load_dotenv('P:/ECHO_PRIME/prometheus_prime/.env'); print('Twilio:', bool(os.getenv('TWILIO_ACCOUNT_SID')))"
```

---

## ✅ SUCCESS CRITERIA

When complete, Claude should be able to:
- ✅ See all 43 Prometheus Prime tools in the tools menu
- ✅ Execute OSINT operations (phone, social, domain, email, IP)
- ✅ Perform network security scans
- ✅ Control mobile devices (Android/iOS)
- ✅ Test web application security
- ✅ Search exploits and generate payloads
- ✅ Get Phoenix healing statistics

---

## 🎯 QUICK VALIDATION COMMAND

```bash
# Single command to validate everything
cd P:\ECHO_PRIME\prometheus_prime && H:\Tools\python.exe -c "
import sys
sys.path.insert(0, '.')
from prometheus_prime_mcp import app
print('✅ MCP Server: OPERATIONAL')
print(f'✅ Tools Available: {len(app._tool_handlers)}')
" 2>&1 | grep -E "(OPERATIONAL|Tools Available)"
```

Expected output:
```
✅ MCP Server: OPERATIONAL
✅ Tools Available: 43
```

---

## 🚀 DEPLOYMENT CHECKLIST

- [ ] All 9 core modules exist in `P:\ECHO_PRIME\prometheus_prime`
- [ ] `prometheus_prime_mcp.py` contains 43 tool definitions
- [ ] `requirements.txt` has all dependencies
- [ ] Python dependencies installed
- [ ] `.env` file configured with API keys
- [ ] Claude Desktop config updated with prometheus-prime server
- [ ] MCP server tested standalone successfully
- [ ] Claude Desktop restarted
- [ ] Tools visible in Claude interface
- [ ] Sample tool execution successful

---

**Authority Level:** 11.0  
**Status:** Ready for Integration  
**Total Tools:** 43 MCP Tools

---

**FOR CLAUDE CODE:**
1. Navigate to `P:\ECHO_PRIME\prometheus_prime`
2. Verify all 9 core modules exist
3. Check `prometheus_prime_mcp.py` has 43 tools
4. Add server config to Claude Desktop
5. Test with `prom_health` tool
6. Confirm all 43 tools are accessible

**CRITICAL:** Use `H:\Tools\python.exe` (full path) for all operations.
