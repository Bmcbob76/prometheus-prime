# 🔥 PROMETHEUS PRIME - COMPLETE MCP INTEGRATION GUIDE

**Authority Level:** 11.0
**Operator:** Commander Bobby Don McWilliams II
**Status:** FULL CAPABILITY INTEGRATION

---

## 📊 OVERVIEW

This guide integrates **ALL** Prometheus Prime capabilities as MCP tools for Claude Desktop, providing complete offensive/defensive security operations through natural language.

### 🎯 TOTAL CAPABILITIES EXPOSED

| Category | Count | Description |
|----------|-------|-------------|
| **Security Domains** | 20 | Complete offensive/defensive capabilities |
| **Diagnostic Systems** | 5 | System, Network, Security, AI/ML, Database |
| **Basic Tools** | 12+ | Scanner, Exploits, Payloads, Evasion, etc. |
| **Advanced Attacks (Set 1)** | 10 | AI poisoning, Quantum, Supply chain, etc. |
| **Advanced Attacks (Set 2)** | 10 | LOTL, Credential harvest, AD attacks, etc. |
| **Advanced Defenses (Set 1)** | 10 | AI detection, Deception, Zero Trust, etc. |
| **Advanced Defenses (Set 2)** | 10 | EDR, SIEM, Threat Hunting, etc. |
| **TOTAL MCP TOOLS** | **77+** | Complete security operations suite |

---

## 🚀 QUICK START

### Step 1: Install MCP SDK

```bash
# Install MCP Python SDK
pip install mcp

# Or with the included requirements
pip install -r mcp_requirements.txt
```

### Step 2: Configure Claude Desktop

**Windows Path:** `%APPDATA%\Claude\claude_desktop_config.json`
**Linux/Mac Path:** `~/.config/Claude/claude_desktop_config.json`

Add this configuration:

```json
{
  "mcpServers": {
    "prometheus-prime": {
      "command": "python",
      "args": ["/absolute/path/to/prometheus-prime/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/prometheus-prime"
      }
    }
  }
}
```

**Example (Linux):**
```json
{
  "mcpServers": {
    "prometheus-prime": {
      "command": "/usr/bin/python3",
      "args": ["/home/user/prometheus-prime/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/home/user/prometheus-prime"
      }
    }
  }
}
```

### Step 3: Test MCP Server

```bash
cd /home/user/prometheus-prime
python mcp_server.py
```

Expected output:
```
======================================================================
🔥 PROMETHEUS PRIME ULTIMATE - MCP SERVER
======================================================================
Authority Level: 11.0
Operator: Commander Bobby Don McWilliams II

📊 COMPLETE OFFENSIVE/DEFENSIVE CAPABILITIES:
   • 20 Security Domains
   • 5 Diagnostic Systems
   • 12 Basic Tools
   • 20 Advanced Attacks
   • 20 Advanced Defenses

📡 Total MCP Tools: 77+
🔥 Phoenix Healing: ENABLED
======================================================================
```

### Step 4: Restart Claude Desktop

Restart Claude Desktop to load the MCP server. You should see all Prometheus Prime tools available.

---

## 📋 COMPLETE TOOL REFERENCE

### 🎯 SECURITY DOMAINS (20 Tools)

All security domains are accessible via `prom_{domain_name}`:

1. **prom_network_recon** - Network reconnaissance (port scan, service enum, OS fingerprint, network map, traceroute)
2. **prom_web_exploitation** - Web exploitation (SQLi, XSS, directory traversal, API security)
3. **prom_wireless_ops** - Wireless operations (WiFi/Bluetooth attacks, RF analysis)
4. **prom_social_engineering** - Social engineering (phishing, pretexting, vishing)
5. **prom_physical_security** - Physical security (lockpicking, RFID cloning, facility assessment)
6. **prom_crypto_analysis** - Cryptographic analysis (hash cracking, crypto weakness detection)
7. **prom_malware_dev** - Malware development (dropper creation, ransomware, rootkits)
8. **prom_forensics** - Digital forensics (disk/memory/network forensics)
9. **prom_cloud_security** - Cloud security (AWS/Azure/GCP auditing, S3 scanning)
10. **prom_mobile_security** - Mobile security (Android/iOS exploitation, APK analysis)
11. **prom_iot_security** - IoT security (device scanning, firmware analysis, Zigbee)
12. **prom_scada_ics** - SCADA/ICS security (industrial control system security)
13. **prom_threat_intel** - Threat intelligence (APT tracking, IOC analysis)
14. **prom_red_team** - Red team operations (full offensive campaigns)
15. **prom_blue_team** - Blue team defense (threat monitoring, hunting, IR)
16. **prom_purple_team** - Purple team integration (control validation, continuous improvement)
17. **prom_osint** - OSINT reconnaissance (open-source intelligence gathering)
18. **prom_exploit_dev** - Exploit development (0-day development, ROP chains, shellcode)
19. **prom_post_exploitation** - Post-exploitation (lateral movement, privilege escalation)
20. **prom_persistence** - Persistence mechanisms (registry, scheduled tasks, services, backdoors)

**Example Usage:**
```
User: Use prom_network_recon to scan 192.168.1.1
Claude: [Executes port_scan operation on target]

User: Use prom_web_exploitation to test SQL injection on https://example.com
Claude: [Executes sql_injection_test operation]
```

---

### 🔬 DIAGNOSTIC SYSTEMS (5 Tools)

1. **prom_diag_system** - Complete system diagnostics
   - CPU, RAM, GPU, disk, network monitoring
   - Python environment verification
   - API key configuration check
   - Performance benchmarks
   - Health score (0-100)

2. **prom_diag_network** - Network diagnostics
   - Internet connectivity testing
   - DNS resolution and server testing
   - Latency measurements (RTT, jitter)
   - Bandwidth testing
   - Route tracing
   - Health score (0-100)

3. **prom_diag_security** - Security diagnostics
   - Vulnerability scanning
   - Configuration auditing
   - CIS compliance checking
   - Firewall status
   - Security updates
   - Risk and security scores

4. **prom_diag_aiml** - AI/ML diagnostics
   - GPU detection and monitoring
   - CUDA/cuDNN verification
   - PyTorch/TensorFlow health checks
   - Inference performance benchmarks
   - Model quantization support
   - Health score (0-100)

5. **prom_diag_database** - Database diagnostics
   - Redis, PostgreSQL, MongoDB, SQLite, Elasticsearch
   - Connection health monitoring
   - Query performance benchmarking
   - Replication status checking
   - Health score (0-100)

**Example Usage:**
```
User: Use prom_diag_system to check system health
Claude: [Returns comprehensive system diagnostics with health score]

User: Use prom_diag_security to audit security posture
Claude: [Returns security assessment with risk score and recommendations]
```

---

### 🛠️ BASIC TOOLS (12+ Tools)

1. **prom_port_scan** - Multi-threaded port scanner
   - TCP, SYN, UDP, stealth scanning
   - Service version detection
   - Banner grabbing

2. **prom_vuln_scan** - Vulnerability scanner
   - CVE correlation
   - Risk scoring
   - Exploit matching

3. **prom_generate_payload** - Payload generator
   - Multi-platform shellcode (Windows, Linux, macOS)
   - Reverse/bind shells, Meterpreter
   - Fileless payloads
   - Advanced encoding

4. **prom_crack_password** - Password cracker
   - Dictionary attacks
   - Brute force
   - Rainbow tables
   - Hash cracking (MD5, SHA, NTLM)

5. **prom_evasion_obfuscate** - Payload obfuscation
   - XOR, AES, Base64 encoding
   - Polymorphic code generation
   - AV/EDR evasion

6. **prom_search_exploits** - Exploit database search
   - Search by CVE, software, keyword
   - Exploit-DB integration
   - Metasploit module search

**Example Usage:**
```
User: Use prom_port_scan to scan 192.168.1.100 ports 1-1000
Claude: [Executes port scan and returns results]

User: Use prom_generate_payload to create a Windows reverse shell
Claude: [Generates payload with encoding options]
```

---

### ⚔️ ADVANCED ATTACKS SET 1 (10 Tools)

1. **prom_attack_ai_poisoning** - AI model poisoning
   - Training data poisoning
   - Model backdoors
   - Adversarial examples

2. **prom_attack_quantum_crypto** - Quantum cryptography attacks
   - Shor's algorithm simulation
   - Grover's search
   - Lattice-based attacks

3. **prom_attack_supply_chain** - Supply chain attacks
   - Dependency confusion
   - Typosquatting
   - CI/CD pipeline compromise

4. **prom_attack_side_channel** - Side-channel attacks
   - Timing attacks
   - Power analysis
   - Electromagnetic attacks

5. **prom_attack_dns_tunneling** - DNS tunneling
   - Data exfiltration via DNS
   - C2 over DNS
   - Covert channels

6. **prom_attack_container_escape** - Container escape
   - Docker breakout techniques
   - Kubernetes escape
   - Privileged container exploitation

7. **prom_attack_firmware_backdoor** - Firmware backdoors
   - UEFI bootkits
   - NIC firmware implants
   - HDD firmware persistence

8. **prom_attack_memory_evasion** - Memory forensics evasion
   - DKOM techniques
   - Process hiding
   - Memory encryption

9. **prom_attack_api_bypass** - API authentication bypass
   - JWT attacks
   - OAuth exploitation
   - Rate limit bypass

10. **prom_attack_blockchain** - Blockchain exploits
    - Smart contract vulnerabilities
    - Reentrancy attacks
    - Flash loan exploits
    - MEV (Miner Extractable Value)

---

### ⚔️ ADVANCED ATTACKS SET 2 (10 Tools)

11. **prom_attack_lotl** - Living Off The Land
    - PowerShell abuse
    - WMI exploitation
    - certutil, bitsadmin attacks

12. **prom_attack_credential_harvest** - Credential harvesting
    - LSASS dumping
    - Kerberoasting
    - NTDS.dit extraction
    - Browser credential theft

13. **prom_attack_cloud_infra** - Cloud infrastructure attacks
    - S3 bucket exploitation
    - IAM privilege escalation
    - Azure token theft

14. **prom_attack_active_directory** - Active Directory attacks
    - Golden Ticket
    - Silver Ticket
    - DCSync
    - Zerologon (CVE-2020-1472)

15. **prom_attack_rf** - Radio Frequency attacks
    - IMSI catcher
    - SS7 exploitation
    - SDR replay attacks
    - BLE spoofing

16. **prom_attack_ics_scada** - ICS/SCADA attacks
    - Modbus attacks
    - Stuxnet-style PLC attacks
    - DNP3 exploitation

17. **prom_attack_voice_audio** - Voice/audio attacks
    - Voice deepfakes (ElevenLabs)
    - Ultrasonic attacks
    - Laser microphone surveillance

18. **prom_attack_hardware_implant** - Hardware implants
    - USB Rubber Ducky
    - O.MG Cable attacks
    - Evil Maid attacks

19. **prom_attack_ml_extraction** - ML model extraction
    - Model stealing
    - Membership inference
    - Model inversion

20. **prom_attack_privacy_breaking** - Privacy breaking
    - Tor de-anonymization
    - Metadata analysis
    - Stylometry
    - Traffic correlation

---

### 🛡️ ADVANCED DEFENSES SET 1 (10 Tools)

1. **prom_defense_ai_threat** - AI-powered threat detection
   - ML-based anomaly detection
   - Behavioral analysis
   - Zero-day detection

2. **prom_defense_deception** - Deception technology
   - Honeypots
   - Honeytokens
   - Canary systems

3. **prom_defense_zero_trust** - Zero Trust Architecture
   - Micro-segmentation
   - Continuous authentication
   - Least privilege enforcement

4. **prom_defense_auto_ir** - Automated Incident Response
   - SOAR platform
   - AI-driven playbooks
   - Automated containment

5. **prom_defense_threat_fusion** - Threat intelligence fusion
   - Multi-source aggregation
   - Correlation engine
   - IOC enrichment

6. **prom_defense_behavioral** - Behavioral analytics
   - UEBA (User and Entity Behavior Analytics)
   - Insider threat detection
   - Anomaly scoring

7. **prom_defense_crypto_agility** - Cryptographic agility
   - Rapid crypto migration
   - Algorithm flexibility
   - Post-quantum readiness

8. **prom_defense_supply_chain_sec** - Supply chain security
   - SBOM generation
   - Dependency verification
   - Artifact signing

9. **prom_defense_container_sec** - Container security
   - Image scanning
   - Runtime protection
   - Policy enforcement

10. **prom_defense_quantum_safe** - Quantum-safe cryptography
    - NIST PQC algorithms
    - CRYSTALS-Kyber
    - CRYSTALS-Dilithium
    - FALCON, SPHINCS+

---

### 🛡️ ADVANCED DEFENSES SET 2 (10 Tools)

11. **prom_defense_edr** - Endpoint Detection and Response
    - Behavioral monitoring
    - Automated response
    - Forensic capabilities

12. **prom_defense_nta** - Network Traffic Analysis
    - Deep packet inspection
    - SSL/TLS inspection
    - Baseline anomaly detection

13. **prom_defense_threat_hunting** - Threat Hunting Platform
    - Hypothesis-driven hunts
    - IOC hunting
    - TTP hunting
    - MITRE ATT&CK mapping

14. **prom_defense_dlp** - Data Loss Prevention
    - Content inspection
    - Contextual analysis
    - Encryption enforcement

15. **prom_defense_pam** - Privileged Access Management
    - Credential vaulting
    - Just-in-time access
    - Session recording

16. **prom_defense_siem** - Security Information and Event Management
    - Log aggregation (500k+ events/sec)
    - Correlation rules
    - Real-time alerting

17. **prom_defense_cspm** - Cloud Security Posture Management
    - Configuration audit
    - Drift detection
    - Compliance monitoring

18. **prom_defense_ast** - Application Security Testing
    - SAST (Static)
    - DAST (Dynamic)
    - RASP (Runtime)
    - Dependency scanning

19. **prom_defense_mdm** - Mobile Device Management
    - Device enrollment
    - Policy enforcement
    - Mobile threat defense

20. **prom_defense_tip** - Threat Intelligence Platform
    - Intel collection
    - Enrichment
    - STIX/TAXII sharing

---

### ❤️ SYSTEM HEALTH

**prom_health** - Complete system health check
- Status of all 20 security domains
- Total capabilities count
- Authority level verification
- Operator confirmation

---

## 🎓 USAGE EXAMPLES

### Example 1: Network Reconnaissance
```
User: Use prom_network_recon to scan scanme.nmap.org
Claude: Executing network reconnaissance...
{
  "operation": "port_scan",
  "target": "scanme.nmap.org",
  "results": {
    "open_ports": [22, 80, 443],
    "services": ["SSH", "HTTP", "HTTPS"]
  }
}
```

### Example 2: Security Diagnostics
```
User: Use prom_diag_security to audit my system
Claude: Running security diagnostics...
{
  "security_score": 75,
  "risk_score": 12,
  "critical_issues": 0,
  "high_issues": 2,
  "recommendations": [
    "Enable disk encryption (HIGH)",
    "Close 2 suspicious open ports (HIGH)"
  ]
}
```

### Example 3: Advanced Attack Simulation
```
User: Use prom_attack_active_directory to show Golden Ticket attack technique
Claude: Retrieving Golden Ticket attack information...
{
  "attack": "Golden Ticket",
  "description": "Forge Kerberos TGT with KRBTGT hash",
  "requirements": ["KRBTGT account NTLM hash", "Domain SID"],
  "stealth": "No authentication to DC required"
}
```

### Example 4: Defense Implementation
```
User: Use prom_defense_edr to enable behavioral monitoring
Claude: Configuring EDR behavioral monitoring...
{
  "defense": "EDR Behavioral Monitoring",
  "monitoring_techniques": [
    "Process creation/termination",
    "File system modifications",
    "Registry changes",
    "Network connections"
  ]
}
```

---

## 🔧 TROUBLESHOOTING

### Issue: MCP server not showing in Claude

**Solution:**
1. Check Claude Desktop config file syntax:
   ```bash
   python -m json.tool ~/.config/Claude/claude_desktop_config.json
   ```

2. Verify Python path in config
3. Check MCP server logs in Claude Desktop Developer Tools (Ctrl+Shift+I)
4. Restart Claude Desktop completely

### Issue: Import errors when running server

**Solution:**
```bash
cd /home/user/prometheus-prime

# Install all dependencies
pip install -r requirements.txt
pip install mcp

# Test imports
python -c "from mcp.server import Server; print('MCP OK')"
python -c "from capabilities.network_recon import NetworkRecon; print('Capabilities OK')"
```

### Issue: Tools not executing

**Solution:**
1. Check tool execution logs in Claude Desktop console
2. Verify all module dependencies are installed
3. Test MCP server standalone:
   ```bash
   python mcp_server.py
   ```
4. Check for permission issues

---

## ✅ VERIFICATION CHECKLIST

- [ ] MCP SDK installed (`pip install mcp`)
- [ ] All Prometheus Prime dependencies installed
- [ ] Claude Desktop config updated with correct paths
- [ ] MCP server tested standalone successfully
- [ ] Claude Desktop restarted
- [ ] `prom_health` tool accessible in Claude
- [ ] Sample tool execution successful (e.g., `prom_diag_system`)
- [ ] All 77+ tools visible in Claude interface

---

## 🎯 SUCCESS CRITERIA

When properly configured, you should be able to:

✅ Execute network reconnaissance operations
✅ Run complete system diagnostics
✅ Perform security audits
✅ Test attack techniques (authorized environments only)
✅ Implement defensive measures
✅ Monitor AI/ML system health
✅ Check database performance
✅ Access all 77+ Prometheus Prime capabilities via natural language

---

## ⚠️ SECURITY NOTICE

**ALL** tools require **AUTHORIZED USE ONLY**. This system is designed for:

✅ Penetration testing (with authorization)
✅ Security research (controlled environments)
✅ Red team exercises (authorized)
✅ CTF competitions
✅ Educational purposes

❌ **NEVER** use for unauthorized access or malicious activities

---

## 📞 SUPPORT

For issues or questions:
1. Check troubleshooting section above
2. Review Claude Desktop MCP documentation
3. Verify all dependencies installed
4. Check system logs

---

**Authority Level:** 11.0
**Status:** FULL OPERATIONAL CAPABILITY
**Total MCP Tools:** 77+
**All Systems:** READY

🔥 **PROMETHEUS PRIME ULTIMATE - COMPLETE MCP INTEGRATION** 🔥
