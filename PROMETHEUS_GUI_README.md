# 🔥 PROMETHEUS PRIME - Web-Based Command & Control GUI

**Authority Level: 11.0**
**Commander: Bobby Don McWilliams II**

## 📋 Overview

Complete web-based graphical user interface for Prometheus Prime penetration testing platform. Provides manual control of all tools across 11 domains plus autonomous operation capabilities.

---

## 🎯 Features

### ✅ Domain Organization
- **11 Security Domains** with dedicated panels
- **50+ Tools** organized by attack category
- **Real-time execution** logging and monitoring
- **WebSocket communication** for live updates

### 🔧 Tool Categories

1. **🔍 Reconnaissance** - Information gathering and OSINT
   - Nmap Port Scanner
   - Subdomain Enumeration
   - WHOIS Lookup
   - DNS Enumeration
   - OSINT Intelligence

2. **🌐 Web Application** - Web vulnerability testing
   - SQL Injection Scanner (SQLMap)
   - XSS Scanner
   - Directory Brute Force
   - CMS Scanner
   - API Fuzzer

3. **🌐 Network Attacks** - Network-based attacks
   - ARP Spoofing
   - Packet Sniffer
   - SYN Flood
   - SSL Strip

4. **📡 Wireless** - WiFi penetration testing
   - WiFi Monitor Mode
   - Network Scanner
   - WPA/WPA2 Cracker
   - Evil Twin AP

5. **🔑 Password Attacks** - Credential attacks
   - Hash Cracker (Hashcat)
   - SSH Brute Force
   - FTP Brute Force
   - Web Form Brute Force

6. **💥 Exploitation** - Exploit frameworks
   - Metasploit Framework
   - Exploit Database Search
   - Buffer Overflow Generator
   - Shellcode Generator

7. **🎯 Post-Exploitation** - Post-compromise activities
   - Credential Dumper
   - Lateral Movement
   - Data Exfiltration
   - Persistence Mechanisms

8. **⬆️ Privilege Escalation** - Privilege escalation
   - Linux PrivEsc Scripts
   - Windows PrivEsc Scripts
   - Kernel Exploit Suggester
   - SUID Binary Finder

9. **🎭 Social Engineering** - Social engineering attacks
   - Phishing Page Generator
   - Email Spoofing
   - Malicious QR Codes

10. **🔐 Cryptography** - Cryptanalysis
    - SSL/TLS Scanner
    - Classical Cipher Cracker
    - RSA Attack Tools

11. **🤖 AUTONOMOUS** - AI-powered autonomous operations
    - Full Autonomous Engagement (6-phase)
    - AI Decision Engine (5-model consensus)
    - Omniscience Intelligence (220K CVEs, 50K exploits)
    - Phoenix Auto-Healing
    - Sovereign Override (Authority Level 11.0)

---

## 🚀 Installation

### Prerequisites
```bash
pip install flask flask-socketio python-socketio
```

### Quick Start
```bash
# Navigate to prometheus-prime directory
cd /home/user/prometheus-prime

# Run the GUI server
python3 prometheus_web_gui.py
```

### Access the GUI
Open your browser and navigate to:
```
http://localhost:5000
```

---

## 📖 Usage Guide

### Manual Tool Execution

1. **Select Domain** - Click on domain tab in left sidebar
2. **Choose Tool** - Browse tools in the selected domain
3. **Configure Parameters**:
   - Enter target (if required): IP address, domain, or URL
   - Add options: Additional tool-specific parameters
4. **Execute** - Click "Execute [Tool Name]" button
5. **Monitor Output** - View results in execution log at bottom

### Example: Running Nmap Scan
```
1. Click "🔍 Reconnaissance" in sidebar
2. Find "Nmap Port Scanner" tool card
3. Enter target: "192.168.1.100"
4. Enter options: "-sV -O" (optional)
5. Click "Execute Nmap Port Scanner"
6. Monitor output in console
```

### Autonomous Mode

#### Full Autonomous Engagement
1. Click **"🤖 AUTONOMOUS"** tab
2. In "Full Autonomous Engagement" card:
   - **Target**: Enter primary target (e.g., `192.168.1.100`)
   - **Scope**: Define authorized scope (e.g., `192.168.1.0/24`)
   - **Contract Number**: Enter engagement contract (e.g., `CONTRACT-2025-001`)
3. Ensure "Autonomous Decisions" toggle is **ON** (green)
4. Click **"START AUTONOMOUS ENGAGEMENT"**
5. Monitor 6-phase execution in real-time
6. Click **"EMERGENCY STOP"** if needed

#### AI Decision Engine
- Select decision type (Exploit Choice, Tool Selection, Risk Assessment)
- Provide context for the decision
- Click "Query AI Consensus"
- System consults 5 AI models:
  1. Claude Sonnet 4.5 - Strategic reasoning
  2. GPT-4 - Tactical analysis
  3. Gemini Pro - Risk assessment
  4. Cohere Command - Alternative perspectives
  5. Claude Opus - Critical validation

#### Omniscience Intelligence
- Choose query type (CVE, Exploit Database, MITRE ATT&CK)
- Enter search term (e.g., "apache", "CVE-2023-1234")
- Click "Search Intelligence"
- Access 220K+ CVEs, 50K+ exploits, 600+ MITRE techniques

#### Phoenix Auto-Healing
- Select error type that needs healing
- Click "Trigger Healing"
- System autonomously recovers from errors

---

## 🎨 Interface Features

### Status Bar (Top)
- **System Status**: Current operational state
- **Active Tools**: Number of tools currently running
- **Autonomous Mode**: ON/OFF status
- **Authority Level**: Current authority level (default: 11.0)

### Sidebar (Left)
- Domain navigation tabs
- Highlights active domain
- Autonomous tab with special red border

### Content Area (Center)
- Tool cards organized in responsive grid
- Each tool card includes:
  - Tool name and description
  - Target input (if required)
  - Options input
  - Execute button

### Execution Log (Bottom)
- Real-time logging of all operations
- Timestamped entries
- Color-coded by status:
  - Green border: Success
  - Red border: Error
  - Default: Information

---

## 🔐 Security Considerations

### Authorization Requirements
- **NEVER** use these tools without explicit written authorization
- All engagements require signed contracts
- Scope verification is mandatory
- Unauthorized access is illegal

### Autonomous Mode Warnings
- Authority Level 11.0 provides **full access**
- Sovereign Override **bypasses all safety protocols**
- Always verify scope before autonomous engagement
- Advisory system remains active even with override
- Complete audit trail maintained

### Safe Usage
1. Obtain signed penetration testing contract
2. Verify scope is accurate and authorized
3. Document all activities
4. Follow engagement rules of engagement
5. Report findings responsibly

---

## 🛠️ Advanced Configuration

### Custom Port
```python
# Edit prometheus_web_gui.py
run_gui(host='0.0.0.0', port=8080)  # Change port to 8080
```

### Remote Access
```python
# Allow access from other machines
run_gui(host='0.0.0.0', port=5000)
# Access from: http://<your-ip>:5000
```

### Production Mode
```python
# Edit prometheus_web_gui.py, change debug flag
socketio.run(app, host=host, port=port, debug=False)
```

---

## 📊 Tool Integration Status

### Currently Simulated (Demo Mode)
All tool executions currently return simulated output for demonstration purposes.

### Integration Steps for Real Tools
To integrate actual tool execution:

1. **Edit `execute_tool()` function** in `prometheus_web_gui.py`
2. **Replace simulation** with actual subprocess calls
3. **Example**:
```python
# Instead of simulated output
result = {"output": "Simulated output"}

# Use actual tool execution
import subprocess
proc = subprocess.run(['nmap', '-sV', target], capture_output=True, text=True)
result = {"output": proc.stdout}
```

---

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Find process using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or use different port
python3 prometheus_web_gui.py --port 8080
```

### WebSocket Connection Issues
- Ensure Flask-SocketIO is installed: `pip install flask-socketio`
- Check firewall settings
- Try disabling browser extensions

### Tool Execution Fails
- Verify tool is installed on system
- Check tool is in PATH
- Review execution permissions
- Check target is reachable

---

## 📈 Architecture

```
┌─────────────────────────────────────────┐
│         PROMETHEUS WEB GUI              │
│                                         │
│  ┌───────────┐      ┌──────────────┐  │
│  │  Flask    │◄────►│  WebSocket   │  │
│  │  Backend  │      │  (Real-time) │  │
│  └─────┬─────┘      └──────────────┘  │
│        │                                │
│        ▼                                │
│  ┌──────────────────────────────────┐  │
│  │   Tool Execution Engine          │  │
│  │  - Subprocess management         │  │
│  │  - Output capture                │  │
│  │  - Error handling                │  │
│  └──────────────────────────────────┘  │
│        │                                │
│        ▼                                │
│  ┌──────────────────────────────────┐  │
│  │   Prometheus Prime Systems       │  │
│  │  - Autonomous Engagement         │  │
│  │  - Decision Engine               │  │
│  │  - Phoenix Healing               │  │
│  │  - Omniscience KB                │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

---

## 🎯 Keyboard Shortcuts

- **Ctrl+L**: Clear execution log
- **Ctrl+S**: Download execution log
- **Ctrl+E**: Emergency stop (Autonomous mode)
- **Ctrl+R**: Refresh system status

---

## 📝 Logging

### Execution Log
- All tool executions logged with timestamps
- Stored in memory during session
- Accessible via `/api/logs` endpoint

### Export Logs
```bash
curl http://localhost:5000/api/logs > execution_log.json
```

---

## 🔄 Updates and Maintenance

### Adding New Tools
1. Edit `TOOL_DOMAINS` dictionary in `prometheus_web_gui.py`
2. Add tool definition with:
   - `id`: Unique identifier
   - `name`: Display name
   - `target`: Boolean (requires target input?)
   - `command`: Command to execute

Example:
```python
{
    "id": "new_tool",
    "name": "New Tool Name",
    "target": True,
    "command": "new_tool"
}
```

### Adding New Domains
1. Add domain to `TOOL_DOMAINS` dictionary
2. Add corresponding tab in HTML sidebar
3. Tools will be automatically rendered

---

## 💡 Tips & Best Practices

1. **Always verify scope** before executing tools
2. **Start with reconnaissance** before exploitation
3. **Use autonomous mode** for complete engagements
4. **Monitor execution log** for errors and status
5. **Document findings** as you discover them
6. **Respect rate limits** to avoid detection
7. **Use Phoenix healing** when encountering errors

---

## 🆘 Support

For issues, questions, or feature requests:
- Check execution log for error messages
- Verify tool is installed on system
- Ensure proper authorization for target
- Review PROMETHEUS_GUI_README.md

---

## ⚖️ Legal Disclaimer

**WARNING**: These tools are for authorized security testing only.

- Obtain written authorization before use
- Unauthorized access is illegal
- Always follow rules of engagement
- Document all activities
- Report findings responsibly

**Authority Level 11.0 does not grant legal authorization.**

Only signed contracts and proper authorization grant legal permission to test systems.

---

**Authority Level: 11.0**
**Status: OPERATIONAL**
**Classification: AUTHORIZED USE ONLY**

🔥 **PROMETHEUS PRIME - Command & Control GUI Ready** 🔥
