# 🔥 PROMETHEUS PRIME - QUICK START GUIDE

**Voice ID:** `BVZ5M1JnNXres6AkVgxe`  
**Authority:** 9.9  
**Status:** FULLY OPERATIONAL

---

## ⚡ INSTANT USAGE

### **Test Voice Integration**
```bash
H:\Tools\python.exe E:\prometheus_prime\test_voice_integration.py
```
**Expected output:**
```
✅ 15 capabilities available
✅ Prometheus Prime reporting: 15 capabilities ready...
✅ All tests passed! Voice integration working!
```

---

## 🎤 VOICE COMMANDS

### **Basic Commands**
```python
# Import voice system
import sys
sys.path.insert(0, r'E:\ECHO_XV4\MLS\servers\personalities')
from prometheus_prime_voice_integration import prometheus_command, speak

# Status check
prometheus_command("status", speak_response=True)

# List capabilities
prometheus_command("list capabilities", speak_response=True)

# Execute capability
prometheus_command("execute nmap_scan targets=10.0.0.5", speak_response=True)
```

### **Direct Bridge Access**
```python
# Import bridge
import sys
sys.path.insert(0, r'E:\prometheus_prime')
from prometheus_voice_bridge import execute_capability, list_capabilities

# List all capabilities
caps = list_capabilities()
print(f"Capabilities: {caps}")

# Execute nmap scan
result = execute_capability("nmap_scan", targets="10.0.0.5", top_ports=1000)
print(result)

# Execute AD attack
result = execute_capability("ad_attack", attack_type="kerberoast", target="dc01")
print(result)
```

---

## 🛡️ AVAILABLE CAPABILITIES

### **Tier 1: CLI-Native (Secure, Scope-Gated)**
1. `nmap_scan` - Network reconnaissance
2. `crack_password` - Password cracking
3. `psexec` - Lateral movement (SMB)
4. `wmiexec` - Lateral movement (WMI)

### **Tier 2: Bridge-Native (Direct Python)**
5. `ad_attack` - Active Directory attacks
6. `exploit_gen` - Exploit development
7. `mimikatz` - Credential dumping
8. `privesc` - Privilege escalation
9. `persistence` - Persistence mechanisms
10. `c2_operation` - Command & Control
11. `web_exploit` - Web exploitation
12. `mobile_exploit` - Mobile attacks
13. `cloud_exploit` - Cloud exploitation
14. `vuln_scan` - Vulnerability scanning
15. `metasploit` - Metasploit integration

---

## 📝 EXAMPLES

### **Example 1: Network Scan**
```python
from prometheus_voice_bridge import execute_capability

result = execute_capability(
    "nmap_scan",
    targets="192.168.1.0/24",
    top_ports=100
)
print(result)
```

### **Example 2: Kerberoast Attack**
```python
result = execute_capability(
    "ad_attack",
    attack_type="kerberoast",
    target="dc01.lab.local"
)
print(result)
```

### **Example 3: Web SQL Injection**
```python
result = execute_capability(
    "web_exploit",
    exploit_type="sqli",
    url="http://target.com/login"
)
print(result)
```

### **Example 4: Cloud S3 Enumeration**
```python
result = execute_capability(
    "cloud_exploit",
    exploit_type="s3_enum",
    platform="aws"
)
print(result)
```

### **Example 5: Privilege Escalation**
```python
result = execute_capability(
    "privesc",
    technique="uac_bypass",
    target="workstation01"
)
print(result)
```

---

## 🔧 TROUBLESHOOTING

### **Voice Not Playing**
Check pygame mixer:
```python
import pygame
pygame.mixer.init()
print("Mixer initialized:", pygame.mixer.get_init())
```

### **Capability Not Found**
List all capabilities:
```python
from prometheus_voice_bridge import list_capabilities
print(list_capabilities())
```

### **CLI Command Fails**
Test agent CLI directly:
```bash
H:\Tools\python.exe E:\prometheus_prime\prometheus_prime_agent.py config show
```

---

## 📁 KEY FILES

```
E:\prometheus_prime\
├── prometheus_voice_bridge.py              # Voice-to-capability bridge
├── prometheus_prime_agent.py               # Secure CLI (6 commands)
├── test_voice_integration.py               # Integration test
└── PROMETHEUS_VOICE_DEPLOYMENT_COMPLETE.md # Full documentation

E:\ECHO_XV4\MLS\servers\personalities\
├── prometheus_prime_voice_integration.py   # Voice system
├── prometheus_prime_personality.py         # Personality
└── personality_config.json                 # Voice ID config
```

---

## 🚀 NEXT STEPS

1. **Test voice integration** - Run test script
2. **Try basic commands** - Status, list, execute
3. **Execute capabilities** - Nmap, AD attacks, exploits
4. **Review documentation** - Full deployment guide
5. **Extend CLI** (optional) - Add remaining 24 capabilities

---

## ✅ VERIFICATION CHECKLIST

- [ ] Test script runs successfully
- [ ] Voice integration accessible
- [ ] Bridge returns 15 capabilities
- [ ] Status command works
- [ ] List command works
- [ ] Execute command works
- [ ] Nmap scan executes (if target available)
- [ ] Voice output plays (if speakers connected)

---

**Prometheus Prime is ready for deployment, Commander.**

🔥 **STAND READY** 🔥
