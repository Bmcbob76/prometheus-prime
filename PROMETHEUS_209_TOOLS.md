# 🔥 PROMETHEUS PRIME - COMPLETE 209 MCP TOOL REFERENCE

**Authority Level:** 11.0
**Total Tools:** 209
**MCP Server:** `mcp_server_complete.py`
**Status:** PRODUCTION READY

---

## 📊 **TOOL CATEGORIES (209 TOTAL)**

| Category | Tools | Access Pattern |
|----------|-------|----------------|
| **Security Domains (Expanded)** | 100 | `prom_{domain}_{operation}` |
| **Diagnostics** | 5 | `prom_diag_{system}` |
| **Basic Tools** | 12 | `prom_{tool}` |
| **Advanced Attacks (Set 1)** | 10 | `prom_attack_{name}` |
| **Advanced Attacks (Set 2)** | 10 | `prom_attack2_{name}` |
| **Advanced Defenses (Set 1)** | 10 | `prom_defense_{name}` |
| **Advanced Defenses (Set 2)** | 10 | `prom_defense2_{name}` |
| **SIGINT Phase 2** | 5 | `prom_wifi_*`, `prom_traffic_*`, `prom_bluetooth_*` |
| **RED TEAM Advanced** | 48 | `prom_rt_{module}_{operation}` |
| **System Tools** | 3 | `prom_health`, `prom_list_capabilities`, `prom_recommend_tool` |

---

## 🎯 **SECURITY DOMAINS - 100 TOOLS** (20 domains × 5 operations)

Each security domain has 5 granular operations:

### **Network Reconnaissance** (`prom_network_recon_*`)
1. `prom_network_recon_discover` - Network discovery
2. `prom_network_recon_scan` - Port and service scanning
3. `prom_network_recon_enumerate` - Host enumeration
4. `prom_network_recon_map` - Network topology mapping
5. `prom_network_recon_fingerprint` - OS/service fingerprinting

### **Web Exploitation** (`prom_web_exploitation_*`)
1. `prom_web_exploitation_enumerate` - Web app enumeration
2. `prom_web_exploitation_sqli` - SQL injection testing
3. `prom_web_exploitation_xss` - Cross-site scripting testing
4. `prom_web_exploitation_dirtraversal` - Directory traversal
5. `prom_web_exploitation_authbypass` - Authentication bypass

### **Wireless Operations** (`prom_wireless_ops_*`)
1. `prom_wireless_ops_scan_wifi` - WiFi network scanning
2. `prom_wireless_ops_attack_wifi` - WiFi attacks (WPA/WEP cracking)
3. `prom_wireless_ops_scan_bluetooth` - Bluetooth device discovery
4. `prom_wireless_ops_attack_rfid` - RFID/NFC attacks
5. `prom_wireless_ops_scan_zigbee` - Zigbee/IoT protocol scanning

**... Plus 17 more domains with 5 operations each:**
- Social Engineering (phish, pretext, impersonate, manipulate, harvest)
- Physical Security (lockpick, badge_clone, camera_disable, tailgate, dumpster_dive)
- Cryptographic Analysis (crack_cipher, analyze_hash, break_encryption, attack_tls, quantum_crack)
- Malware Development (create_payload, obfuscate, weaponize, test_av, deliver)
- Digital Forensics (acquire_evidence, analyze_memory, recover_deleted, timeline, report)
- Cloud Security (audit_aws, audit_azure, audit_gcp, exploit_misconfigenv, escalate_cloud)
- Mobile Security (analyze_apk, analyze_ipa, exploit_android, exploit_ios, extract_data)
- IoT Security (discover_iot, exploit_camera, exploit_smart_home, botnet_recruit, firmware_extract)
- SCADA/ICS (scan_ics, exploit_plc, modbus_attack, ladder_logic, safety_bypass)
- Threat Intelligence (collect_iocs, analyze_ttp, correlate_threats, predict_attack, share_intel)
- Red Team (plan_operation, execute_attack, simulate_apt, test_defenses, report_findings)
- Blue Team (monitor_network, detect_intrusion, respond_incident, hunt_threats, harden_system)
- Purple Team (exercise_scenario, validate_controls, test_detection, improve_posture, collaborate)
- OSINT (gather_intel, search_databases, analyze_social, track_targets, create_dossier)
- Exploit Development (find_vulnerability, develop_exploit, test_exploit, weaponize_exploit, deliver_exploit)
- Post Exploitation (escalate_privilege, harvest_credentials, enumerate_system, exfiltrate, persist)
- Persistence (registry_persist, service_persist, scheduled_task, bootkit, rootkit)

---

## 🔬 **DIAGNOSTICS - 5 TOOLS**

1. `prom_diag_system` - CPU, RAM, GPU, disk diagnostics
2. `prom_diag_network` - Network connectivity, latency, bandwidth
3. `prom_diag_security` - Vulnerability, compliance, firewall checks
4. `prom_diag_ai_ml` - GPU, CUDA, ML framework diagnostics
5. `prom_diag_database` - Redis, PostgreSQL, MongoDB, SQLite checks

---

## 🛠️ **BASIC TOOLS - 12 TOOLS**

1. `prom_port_scan` - Multi-threaded port scanner
2. `prom_vuln_scan` - Vulnerability scanner with CVE correlation
3. `prom_os_fingerprint` - OS fingerprinting and detection
4. `prom_generate_payload` - Generate reverse shells and payloads
5. `prom_crack_password` - Password cracking (dictionary, brute force)
6. `prom_evasion_obfuscate` - Payload obfuscation for AV evasion
7. `prom_exploit_execute` - Execute exploits against targets
8. `prom_mobile_exploit_android` - Android exploitation
9. `prom_mobile_exploit_ios` - iOS exploitation
10. `prom_wireless_advanced` - Advanced wireless attacks
11. `prom_network_device_exploit` - Router/switch/IoT exploitation
12. `prom_physical_attack_usb` - USB attacks (Rubber Ducky, BadUSB)

---

## ⚔️ **ADVANCED ATTACKS - 20 TOOLS**

**Set 1 (10 tools):**
1. `prom_attack_ai_poisoning` - AI model poisoning
2. `prom_attack_quantum_crypto_attack` - Quantum cryptographic attacks
3. `prom_attack_supply_chain_attack` - Supply chain compromise
4. `prom_attack_side_channel_attack` - Side-channel attacks (timing, power)
5. `prom_attack_dns_tunneling` - DNS tunneling exfiltration
6. `prom_attack_container_escape` - Container escape techniques
7. `prom_attack_firmware_backdoor` - Firmware backdoor injection
8. `prom_attack_memory_forensics_evasion` - Memory forensics evasion
9. `prom_attack_api_auth_bypass` - API authentication bypass
10. `prom_attack_blockchain_exploit` - Blockchain/smart contract exploits

**Set 2 (10 tools):**
1. `prom_attack2_lotl` - Living Off The Land
2. `prom_attack2_credential_harvesting` - Credential harvesting
3. `prom_attack2_cloud_infrastructure` - Cloud infrastructure attacks
4. `prom_attack2_active_directory` - Active Directory attacks
5. `prom_attack2_rf_attacks` - Radio frequency attacks
6. `prom_attack2_ics_scada` - ICS/SCADA attacks
7. `prom_attack2_voice_audio` - Voice/audio deepfake attacks
8. `prom_attack2_hardware_implants` - Hardware implants/Evil Maid
9. `prom_attack2_ml_extraction` - ML model extraction
10. `prom_attack2_privacy_breaking` - De-anonymization attacks

---

## 🛡️ **ADVANCED DEFENSES - 20 TOOLS**

**Set 1 (10 tools):**
1. `prom_defense_ai_threat_detection` - AI-powered threat detection
2. `prom_defense_deception_tech` - Deception technology (honeypots)
3. `prom_defense_zero_trust` - Zero trust architecture
4. `prom_defense_auto_ir` - Automated incident response
5. `prom_defense_threat_intel_fusion` - Threat intelligence fusion
6. `prom_defense_behavioral_analytics` - Behavioral analytics (UEBA)
7. `prom_defense_crypto_agility` - Cryptographic agility
8. `prom_defense_supply_chain_sec` - Supply chain security
9. `prom_defense_container_security` - Container security
10. `prom_defense_quantum_safe_crypto` - Quantum-safe cryptography

**Set 2 (10 tools):**
1. `prom_defense2_edr` - Endpoint Detection & Response
2. `prom_defense2_nta` - Network Traffic Analysis
3. `prom_defense2_threat_hunting` - Threat Hunting Platform
4. `prom_defense2_dlp` - Data Loss Prevention
5. `prom_defense2_pam` - Privileged Access Management
6. `prom_defense2_siem` - SIEM Platform
7. `prom_defense2_cspm` - Cloud Security Posture Management
8. `prom_defense2_ast` - Application Security Testing
9. `prom_defense2_mdm` - Mobile Device Management
10. `prom_defense2_tip` - Threat Intelligence Platform

---

## 📡 **SIGINT PHASE 2 - 5 TOOLS**

1. `prom_wifi_discover` - WiFi network discovery and enumeration
2. `prom_wifi_assess` - WiFi security assessment (WEP/WPA/WPA2/WPA3)
3. `prom_traffic_capture` - Network traffic capture (tcpdump/tshark)
4. `prom_traffic_anomaly` - Traffic anomaly detection (port scan, DNS tunnel, exfil)
5. `prom_bluetooth_discover` - Bluetooth device discovery (Classic + BLE)

---

## 🎯 **RED TEAM ADVANCED - 48 TOOLS** (18 modules × ~3 operations)

### **Command & Control (3 tools)**
- `prom_rt_c2_setup` - Setup C2 infrastructure
- `prom_rt_c2_beacon` - Manage C2 beacons
- `prom_rt_c2_command` - Execute C2 commands

### **Active Directory (3 tools)**
- `prom_rt_ad_enumerate` - AD enumeration
- `prom_rt_ad_kerberoast` - Kerberoasting attack
- `prom_rt_ad_dcsync` - DCSync attack

### **Mimikatz/Credential Dumping (3 tools)**
- `prom_rt_mimikatz_lsass` - LSASS memory dump
- `prom_rt_mimikatz_sam` - SAM database dump
- `prom_rt_mimikatz_secrets` - LSA secrets dump

### **Metasploit Integration (3 tools)**
- `prom_rt_metasploit_exploit` - Execute Metasploit exploit
- `prom_rt_metasploit_payload` - Generate Metasploit payload
- `prom_rt_metasploit_session` - Manage Metasploit sessions

### **Evasion (3 tools)**
- `prom_rt_evasion_obfuscate` - Payload obfuscation
- `prom_rt_evasion_sandbox` - Sandbox evasion
- `prom_rt_evasion_av` - Antivirus evasion

### **Data Exfiltration (3 tools)**
- `prom_rt_exfil_http` - HTTP exfiltration
- `prom_rt_exfil_dns` - DNS tunneling exfiltration
- `prom_rt_exfil_smb` - SMB exfiltration

### **Lateral Movement (3 tools)**
- `prom_rt_lateral_psexec` - PsExec lateral movement
- `prom_rt_lateral_wmi` - WMI lateral movement
- `prom_rt_lateral_ssh` - SSH lateral movement

### **Persistence (3 tools)**
- `prom_rt_persist_registry` - Registry persistence
- `prom_rt_persist_service` - Service persistence
- `prom_rt_persist_scheduled_task` - Scheduled task persistence

### **Privilege Escalation (3 tools)**
- `prom_rt_privesc_windows` - Windows privilege escalation
- `prom_rt_privesc_linux` - Linux privilege escalation
- `prom_rt_privesc_exploit` - Exploit-based privesc

### **Reconnaissance (3 tools)**
- `prom_rt_recon_port_scan` - Port scanning
- `prom_rt_recon_service_enum` - Service enumeration
- `prom_rt_recon_vuln_scan` - Vulnerability scanning

### **Phishing (3 tools)**
- `prom_rt_phishing_email` - Email phishing campaign
- `prom_rt_phishing_smishing` - SMS phishing
- `prom_rt_phishing_vishing` - Voice phishing

### **Reporting (3 tools)**
- `prom_rt_reporting_generate` - Generate penetration test report
- `prom_rt_reporting_metrics` - Operation metrics
- `prom_rt_reporting_findings` - Security findings report

### **Vulnerability Scanning (3 tools)**
- `prom_rt_vulnscan_network` - Network vulnerability scan
- `prom_rt_vulnscan_web` - Web vulnerability scan
- `prom_rt_vulnscan_cve` - CVE-based scanning

### **Web Exploitation (3 tools)**
- `prom_rt_webexploit_sqli` - SQL injection
- `prom_rt_webexploit_xss` - Cross-site scripting
- `prom_rt_webexploit_csrf` - CSRF attacks

### **Obfuscation (3 tools)**
- `prom_rt_obfuscate_code` - Code obfuscation
- `prom_rt_obfuscate_traffic` - Traffic obfuscation
- `prom_rt_obfuscate_payload` - Payload obfuscation

### **Password Attacks (3 tools)**
- `prom_rt_passattack_brute` - Password brute force
- `prom_rt_passattack_spray` - Password spraying
- `prom_rt_passattack_crack` - Hash cracking

---

## 🔧 **SYSTEM TOOLS - 3 TOOLS**

1. `prom_health` - Complete system health check and capability report
2. `prom_list_capabilities` - Query all capabilities with filtering options
3. `prom_recommend_tool` - AI-powered tool recommendations for specific tasks

---

## 💡 **USAGE EXAMPLES**

```
# Network reconnaissance
Use prom_network_recon_scan with target "192.168.1.0/24"

# Web vulnerability testing
Use prom_web_exploitation_sqli with target "http://192.168.1.100/login.php"

# WiFi security assessment
Use prom_wifi_assess with ssid "TargetNetwork" and bssid "AA:BB:CC:DD:EE:FF"

# Active Directory attack
Use prom_rt_ad_kerberoast with target "domain.local"

# Password cracking
Use prom_crack_password with method "dictionary" and target "hash.txt"

# Get tool recommendations
Use prom_recommend_tool with task "I need to test a web application for SQL injection"

# System health check
Use prom_health
```

---

## 🎯 **QUICK REFERENCE BY USE CASE**

| Use Case | Recommended Tools |
|----------|------------------|
| **Network Penetration Test** | `prom_network_recon_scan`, `prom_vuln_scan`, `prom_exploit_execute` |
| **Web App Security Test** | `prom_web_exploitation_sqli`, `prom_web_exploitation_xss`, `prom_rt_webexploit_*` |
| **WiFi Security Assessment** | `prom_wifi_discover`, `prom_wifi_assess`, `prom_wireless_ops_attack_wifi` |
| **Active Directory Audit** | `prom_rt_ad_enumerate`, `prom_rt_ad_kerberoast`, `prom_rt_ad_dcsync` |
| **Password Security Testing** | `prom_crack_password`, `prom_rt_passattack_*` |
| **Mobile App Testing** | `prom_mobile_exploit_android`, `prom_mobile_exploit_ios` |
| **Cloud Security Audit** | `prom_cloud_security_audit_aws`, `prom_cloud_security_audit_azure` |
| **Incident Response** | `prom_defense_*`, `prom_forensics_*` |
| **Red Team Operation** | `prom_rt_c2_*`, `prom_rt_lateral_*`, `prom_rt_persist_*` |

---

## 📊 **STATISTICS**

- **Total Tools:** 209
- **Security Domains:** 20 (× 5 operations = 100 tools)
- **RED TEAM Modules:** 16 loaded (× 3 operations = 48 tools)
- **Attack Tools:** 30
- **Defense Tools:** 20
- **SIGINT Tools:** 5
- **System Tools:** 3
- **Diagnostic Tools:** 5
- **Basic Tools:** 12

---

## 🔥 **PROMETHEUS PRIME - MOST COMPREHENSIVE SECURITY AGENT**

**Every capability is accessible via MCP for Claude Desktop.**
**209 tools covering every offensive and defensive security domain.**
**Complete self-awareness and AI-powered recommendations.**

**Authority Level:** 11.0
**Status:** PRODUCTION READY
**Operator:** Commander Bobby Don McWilliams II
