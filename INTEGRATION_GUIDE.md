# 🔌 PROMETHEUS PRIME INTEGRATION GUIDE

**For:** MLS Launcher & ECHO PRIME GUI Developers
**Authority Level:** 11.0
**Last Updated:** 2025-11-10

---

## 🎯 QUICK INTEGRATION OVERVIEW

Prometheus Prime provides a **standardized MCP (Model Context Protocol) server** that exposes 100+ security tools and OSINT capabilities through a unified REST API.

### **Integration Points:**
1. **MLS Launcher** → Auto-start Prometheus Prime services
2. **ECHO PRIME GUI** → Connect to REST API endpoints
3. **Other Agents** → Inter-agent communication via MCP

---

## 🚀 MLS LAUNCHER INTEGRATION

### **Services to Launch:**

```json
{
  "prometheus_prime": {
    "services": [
      {
        "name": "Prometheus Security Arsenal",
        "script": "prometheus_security_arsenal.py",
        "port": 8765,
        "protocol": "MCP",
        "auto_start": true,
        "dependencies": ["vault_service"]
      },
      {
        "name": "OSINT API Server",
        "script": "osint_api_server.py",
        "port": 8766,
        "protocol": "REST",
        "auto_start": true,
        "dependencies": []
      },
      {
        "name": "Prometheus Voice Bridge",
        "script": "prometheus_voice_bridge.py",
        "port": 8767,
        "protocol": "WebSocket",
        "auto_start": false,
        "dependencies": ["elevenlabs_api"]
      }
    ],
    "working_directory": "P:\\ECHO_PRIME\\prometheus_prime\\prometheus-prime",
    "python_interpreter": "python",
    "environment": {
      "PROMETHEUS_AUTHORITY_LEVEL": "11.0",
      "PROMETHEUS_VAULT_PATH": "./vault_data",
      "PROMETHEUS_LOG_LEVEL": "INFO"
    }
  }
}
```

### **Launch Script Example (PowerShell):**

```powershell
# MLS_LAUNCH_PROMETHEUS.ps1

$PROMETHEUS_DIR = "P:\ECHO_PRIME\prometheus_prime\prometheus-prime"
Set-Location $PROMETHEUS_DIR

# Start Security Arsenal MCP Server
Write-Host "Starting Prometheus Security Arsenal..."
Start-Process python -ArgumentList "prometheus_security_arsenal.py" -NoNewWindow -PassThru

# Wait for service to be ready
Start-Sleep -Seconds 2

# Start OSINT API Server
Write-Host "Starting OSINT API Server..."
Start-Process python -ArgumentList "osint_api_server.py" -NoNewWindow -PassThru

# Verify services are running
$services = @(
    @{Name="Security Arsenal"; Port=8765},
    @{Name="OSINT API"; Port=8766}
)

foreach ($service in $services) {
    $connection = Test-NetConnection -ComputerName localhost -Port $service.Port -WarningAction SilentlyContinue
    if ($connection.TcpTestSucceeded) {
        Write-Host "✅ $($service.Name) running on port $($service.Port)"
    } else {
        Write-Host "❌ $($service.Name) failed to start"
    }
}
```

### **Launch Script Example (Batch):**

```batch
@echo off
REM LAUNCH_PROMETHEUS_PRIME.bat

cd /d P:\ECHO_PRIME\prometheus_prime\prometheus-prime

echo Starting Prometheus Prime Agent...

REM Start Security Arsenal
start /B python prometheus_security_arsenal.py

REM Wait 2 seconds
timeout /t 2 /nobreak >nul

REM Start OSINT API
start /B python osint_api_server.py

echo Prometheus Prime services started.
echo Security Arsenal: http://localhost:8765
echo OSINT API: http://localhost:8766

pause
```

---

## 🖥️ ECHO PRIME GUI INTEGRATION

### **Tab Structure:**

```
ECHO PRIME GUI
└── Prometheus Prime Tab
    ├── Dashboard (Overview)
    ├── Security Arsenal
    │   ├── Password Cracking
    │   ├── Wireless Security
    │   ├── Forensics
    │   ├── Post-Exploitation
    │   ├── Reverse Engineering
    │   └── API Reverse Engineering
    ├── OSINT Intelligence
    │   ├── Phone Intel
    │   ├── Email Intel
    │   ├── IP Intel
    │   ├── Domain Intel
    │   └── Social Media
    ├── Promethian Vault
    │   ├── Credential Manager
    │   ├── Secret Storage
    │   └── Access Logs
    └── Settings
        ├── Authority Level
        ├── API Keys
        └── Preferences
```

### **REST API Endpoints:**

#### **Security Arsenal (Port 8765)**

```http
# List all available tools
GET /api/tools/list
Response: {
  "categories": [
    {
      "name": "password_cracking",
      "tools": ["hash_identify", "hash_generate", "john_crack", ...]
    },
    {
      "name": "wireless_security",
      "tools": ["wifi_scan", "monitor_mode_enable", "deauth_attack", ...]
    }
  ]
}

# Execute a tool
POST /api/tools/execute
Request: {
  "category": "password_cracking",
  "tool": "hash_identify",
  "args": {
    "hash_string": "5f4dcc3b5aa765d61d8327deb882cf99"
  }
}
Response: {
  "status": "success",
  "result": {
    "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
    "length": 32,
    "possible_types": ["MD5", "NTLM", "MD4"]
  }
}

# Get tool documentation
GET /api/tools/info/{category}/{tool_name}
Response: {
  "tool": "hash_identify",
  "description": "Identify hash type based on length and format",
  "parameters": [
    {
      "name": "hash_string",
      "type": "str",
      "required": true,
      "description": "The hash to identify"
    }
  ],
  "returns": "Dictionary with possible hash types"
}
```

#### **OSINT Intelligence (Port 8766)**

```http
# Phone Intelligence
POST /api/osint/phone
Request: {
  "phone_number": "+1234567890"
}
Response: {
  "status": "success",
  "data": {
    "number": "+1234567890",
    "carrier": "Verizon",
    "location": "New York, NY",
    "type": "Mobile",
    "valid": true
  }
}

# Email Intelligence
POST /api/osint/email
Request: {
  "email_address": "test@example.com"
}
Response: {
  "status": "success",
  "data": {
    "email": "test@example.com",
    "valid": true,
    "disposable": false,
    "mx_records": ["mail.example.com"],
    "data_breaches": [...]
  }
}

# IP Intelligence
POST /api/osint/ip
Request: {
  "ip_address": "8.8.8.8"
}
Response: {
  "status": "success",
  "data": {
    "ip": "8.8.8.8",
    "organization": "Google LLC",
    "country": "United States",
    "asn": "AS15169",
    "open_ports": [...]
  }
}
```

### **WebSocket Integration (Real-time Updates):**

```javascript
// JavaScript example for ECHO PRIME GUI
const ws = new WebSocket('ws://localhost:8765/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  switch(data.type) {
    case 'tool_progress':
      updateProgressBar(data.tool, data.progress);
      break;
    case 'tool_complete':
      displayResults(data.tool, data.result);
      break;
    case 'alert':
      showNotification(data.message, data.severity);
      break;
  }
};

// Execute tool with real-time updates
function executeTool(category, tool, args) {
  ws.send(JSON.stringify({
    action: 'execute_tool',
    category: category,
    tool: tool,
    args: args
  }));
}
```

### **GUI Code Example (Python/Tkinter):**

```python
import tkinter as tk
import requests

class PrometheusTab:
    def __init__(self, parent):
        self.frame = tk.Frame(parent)
        self.api_base = "http://localhost:8765"

        # Create dashboard
        self.create_dashboard()

    def create_dashboard(self):
        # Title
        tk.Label(self.frame, text="Prometheus Prime Security Arsenal",
                font=("Arial", 16, "bold")).pack(pady=10)

        # Tool categories
        categories = self.get_categories()
        for category in categories:
            btn = tk.Button(self.frame, text=category['name'],
                          command=lambda c=category: self.show_category(c))
            btn.pack(pady=5)

    def get_categories(self):
        response = requests.get(f"{self.api_base}/api/tools/list")
        return response.json()['categories']

    def execute_tool(self, category, tool, args):
        response = requests.post(f"{self.api_base}/api/tools/execute",
                                json={
                                    "category": category,
                                    "tool": tool,
                                    "args": args
                                })
        return response.json()
```

---

## 🔐 AUTHENTICATION & AUTHORIZATION

### **Authority Level System:**

All Prometheus Prime tools require authority level verification:

```python
# GUI sends authority level with each request
headers = {
    "X-Authority-Level": "11.0",
    "X-User-ID": "commander_bob",
    "Authorization": "Bearer <vault_token>"
}

response = requests.post(
    "http://localhost:8765/api/tools/execute",
    headers=headers,
    json={...}
)
```

### **Promethian Vault Integration:**

```python
# Retrieve credentials from vault
vault_response = requests.post(
    "http://localhost:8765/api/vault/retrieve",
    headers={"Authorization": f"Bearer {master_key}"},
    json={
        "credential_id": "target_ssh_key",
        "decrypt": True
    }
)

credentials = vault_response.json()['data']
```

---

## 📊 STATUS MONITORING

### **Health Check Endpoint:**

```http
GET /api/health
Response: {
  "status": "healthy",
  "services": {
    "security_arsenal": "running",
    "osint_api": "running",
    "vault": "running"
  },
  "uptime": 3600,
  "tools_available": 100,
  "active_jobs": 3
}
```

### **MLS Dashboard Integration:**

```python
# Periodic health check
def check_prometheus_health():
    try:
        response = requests.get("http://localhost:8765/api/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            update_dashboard_status("Prometheus Prime", "ONLINE", data)
        else:
            update_dashboard_status("Prometheus Prime", "ERROR", None)
    except:
        update_dashboard_status("Prometheus Prime", "OFFLINE", None)

# Run every 30 seconds
schedule.every(30).seconds.do(check_prometheus_health)
```

---

## 🔄 INTER-AGENT COMMUNICATION

### **Message Bus Protocol:**

```python
# Prometheus Prime publishes events
from mcp_message_bus import MessageBus

bus = MessageBus()

# Publish event when scan completes
bus.publish("prometheus.scan.complete", {
    "agent": "prometheus_prime",
    "scan_type": "network",
    "targets_found": 25,
    "vulnerabilities": 5,
    "timestamp": "2025-11-10T12:00:00Z"
})

# Subscribe to events from other agents
def handle_target_discovered(event):
    target = event['data']['target']
    # Automatically scan new target
    scan_target(target)

bus.subscribe("network_monitor.target_discovered", handle_target_discovered)
```

### **Shared Data Models:**

```python
# Standard data model for security findings
class SecurityFinding:
    def __init__(self, severity, title, description, target, remediation):
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.title = title
        self.description = description
        self.target = target
        self.remediation = remediation
        self.timestamp = datetime.now()
        self.agent = "prometheus_prime"

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
            "agent": self.agent
        }

# Other agents can consume this standard format
```

---

## 📝 CONFIGURATION

### **Prometheus Prime Configuration File:**

```json
{
  "prometheus_prime": {
    "agent_id": "prometheus_prime_001",
    "authority_level": 11.0,
    "mcp_server": {
      "host": "0.0.0.0",
      "port": 8765,
      "max_connections": 100
    },
    "osint_api": {
      "host": "0.0.0.0",
      "port": 8766,
      "rate_limit": 100
    },
    "vault": {
      "path": "./vault_data",
      "encryption": "AES-256-GCM",
      "backup_enabled": true
    },
    "logging": {
      "level": "INFO",
      "file": "./logs/prometheus.log",
      "max_size": "100MB"
    },
    "external_arsenals": {
      "beef": {
        "enabled": true,
        "path": "./BEEF"
      },
      "exploitdb": {
        "enabled": true,
        "path": "L:\\exploitdb"
      },
      "arsenal": {
        "enabled": true,
        "path": "./Orange-cyberdefense"
      }
    }
  }
}
```

---

## 🧪 TESTING INTEGRATION

### **MLS Launcher Test:**

```powershell
# Test service startup
.\LAUNCH_PROMETHEUS_PRIME.bat

# Verify services
Test-NetConnection -ComputerName localhost -Port 8765
Test-NetConnection -ComputerName localhost -Port 8766

# Test API endpoint
Invoke-WebRequest -Uri "http://localhost:8765/api/health"
```

### **GUI Test:**

```python
# Test API connection from GUI
import requests

def test_prometheus_connection():
    try:
        # Health check
        health = requests.get("http://localhost:8765/api/health", timeout=5)
        assert health.status_code == 200

        # List tools
        tools = requests.get("http://localhost:8765/api/tools/list", timeout=5)
        assert tools.status_code == 200
        assert len(tools.json()['categories']) > 0

        # Execute simple tool
        result = requests.post("http://localhost:8765/api/tools/execute",
                              json={
                                  "category": "password_cracking",
                                  "tool": "hash_generate",
                                  "args": {"plaintext": "test", "algorithm": "md5"}
                              })
        assert result.status_code == 200

        print("✅ All tests passed!")
        return True
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
```

---

## 📚 DOCUMENTATION REFERENCES

- **ECHO_PRIME_ARCHITECTURE.md** - System architecture overview
- **SECURITY_ARSENAL_README.md** - Complete tool documentation
- **API_REVERSE_ENGINEERING_README.md** - API tools guide
- **SECURITY_TOOLKIT_AUDIT_REPORT.md** - Code audit results

---

## 🎯 NEXT STEPS FOR INTEGRATION

1. **MLS Developer:**
   - Add Prometheus Prime to service registry
   - Create launch scripts in MLS directory
   - Configure service monitoring

2. **GUI Developer:**
   - Create Prometheus Prime tab in master GUI
   - Implement REST API client
   - Add WebSocket event handlers
   - Design dashboard visualizations

3. **Other Agent Developers:**
   - Subscribe to Prometheus Prime events
   - Use shared data models
   - Implement inter-agent workflows

---

**Contact:** Commander Bob (Authority Level 11.0)
**Repository:** https://github.com/Bmcbob76/prometheus-prime
**Status:** READY FOR INTEGRATION ✅
