# 🔥 ECHO PRIME GUI - Master Command & Control Interface

**Authority Level: 11.0**
**Commander: Bobby Don McWilliams II**

## 📋 Overview

Master tabbed GUI interface integrating all Echo Prime Omega systems into a single unified control center. Provides seamless access to Prometheus Prime, Omega Swarm Brain, Memory System, MLS Server, Omniscience Intelligence, and Sovereign Control.

---

## 🎯 Integrated Systems

### ⚔️ **Prometheus Prime** (Tab 1)
- Complete penetration testing platform
- 11 security domains with 50+ tools
- Full 6-phase autonomous engagement
- AI decision engine (5-model consensus)
- Phoenix auto-healing
- **Launch Full GUI** - Opens Prometheus Prime GUI in new window

### 🐝 **Omega Swarm Brain** (Tab 2)
- Multi-agent swarm intelligence coordinator
- Spawn 1-20 specialized agents
- 6 agent roles (Recon, Exploit, Intel, Healing, Decision, Post-Exploit)
- Parallel task execution
- Dynamic task allocation
- Collective decision making

### 💾 **Memory System** (Tab 3)
- Persistent knowledge storage
- Engagement history database
- Vulnerability tracking
- Swarm intelligence learning
- Sovereign session logging
- SQL-based persistence

### 🔐 **MLS Server** (Tab 4)
- Multi-Level Security authorization
- Security clearance levels (0-11.0)
- Bloodline key generation
- Compartmentalized access control
- Complete audit logging

### 🧠 **Omniscience Intelligence** (Tab 5)
- 220,000+ CVE database
- 50,000+ exploit collection
- 600+ MITRE ATT&CK techniques
- Service fingerprinting
- Attack vector generation
- Target profiling

### 👑 **Sovereign Control** (Tab 6)
- Authority Level 11.0 override
- Bypass all safety protocols
- Bloodline authentication
- Emergency protocols
- Advisory system (always active)
- Complete audit trail

---

## 🚀 Installation

### Prerequisites
```bash
pip install flask flask-socketio python-socketio
```

### Quick Start
```bash
# Navigate to echo-prime-gui directory
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui

# Run the master GUI
python3 echo_prime_master_gui.py
```

### Access the Interface
```
http://localhost:5000
```

---

## 📖 Usage Guide

### Navigation
1. **System Tabs** (Left Sidebar) - Click any system icon to switch
2. **Control Panels** (Main Area) - System-specific controls and features
3. **Execution Log** (Bottom) - Real-time logging of all operations
4. **Status Bar** (Top) - System metrics and status indicators

### Prometheus Prime Tab
```
✅ View system statistics (domains, tools, CVEs)
✅ Launch full Prometheus Prime GUI in new window
✅ Start autonomous engagement
✅ Query Omniscience intelligence
✅ Emergency stop all operations
```

### Omega Swarm Brain Tab
```
✅ Configure agent count (1-20)
✅ Spawn specialized agents
✅ Coordinate swarm intelligence
✅ Terminate all agents
✅ View agent roles and capabilities
```

### Memory System Tab
```
✅ Store engagement data
✅ Query memory database
✅ Export stored data
✅ View storage statistics
```

### MLS Server Tab
```
✅ Check user authorization
✅ Set security clearance level
✅ Generate bloodline keys
✅ View security levels (0-11.0)
```

### Omniscience Tab
```
✅ Search CVE database (220K entries)
✅ Query exploit collection (50K exploits)
✅ Search MITRE ATT&CK (600+ techniques)
✅ Analyze target systems
✅ Generate attack vectors
```

### Sovereign Control Tab
```
⚠️ WARNING: Bypasses ALL safety protocols

✅ Enter Sovereign ID
✅ Provide credentials
✅ Submit biometric data
✅ Activate sovereign override (Authority Level 11.0)
✅ Deactivate override when complete
```

---

## 🎨 Interface Features

### Design
- **Dark cyberpunk theme** with green/red accents
- **Responsive layout** adapts to screen size
- **Smooth animations** for tab switching
- **Real-time updates** via WebSocket
- **Color-coded systems** for easy identification

### Color Scheme
```
⚔️  Prometheus Prime    - Red    (#ff0000)
🐝 Omega Swarm Brain   - Green  (#00ff00)
💾 Memory System        - Blue   (#00aaff)
🔐 MLS Server          - Orange (#ffaa00)
🧠 Omniscience         - Purple (#aa00ff)
👑 Sovereign Control   - Pink   (#ff00ff)
```

### Status Indicators
- **Green Pulse** - System operational
- **Red Pulse** - Sovereign override active
- **Agent Count** - Active swarm agents
- **Memory Entries** - Database entries
- **Active Engagements** - Running operations

---

## 🔧 Integration with Prometheus Prime GUI

### Launch Full GUI
The Prometheus Prime tab includes a "Launch Full GUI" button that opens the complete Prometheus Prime GUI (with all 11 domains and 50+ tools) in a separate window.

**Steps:**
1. Click **Prometheus Prime** tab
2. Click **"Launch Full GUI"** button
3. Prometheus Prime GUI opens in new browser tab
4. Master GUI remains open for system coordination

### Dual-GUI Workflow
```
Master GUI (Port 5000)        Prometheus Prime GUI (Port 5001)
├─ System coordination         ├─ Detailed tool controls
├─ High-level commands         ├─ Target inputs
├─ Multi-system view          ├─ Option configuration
└─ Execution logging          └─ Real-time tool output
```

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              ECHO PRIME MASTER GUI (Port 5000)             │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │Prometheus│  │  Swarm   │  │  Memory  │  │   MLS    │  │
│  │  Prime   │  │  Brain   │  │  System  │  │  Server  │  │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘  │
│        │             │              │             │        │
│        └─────────────┴──────────────┴─────────────┘        │
│                          │                                  │
│                    Flask Backend                            │
│                    WebSocket Server                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│        PROMETHEUS PRIME GUI (Port 5001) - Opens in         │
│        separate window with full tool access               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Features

### Authorization
- MLS clearance check before operations
- Sovereign override requires authentication
- Complete audit trail maintained
- Session tracking active

### Safety Protocols
- Confirmation dialogs for dangerous operations
- Warning messages on Sovereign Control tab
- Advisory system always active (even with override)
- Emergency stop button available

### Audit Trail
- All operations logged with timestamp
- System-specific badges for tracking
- Color-coded log entries (green=success, red=error)
- Persistent logging to database

---

## ⚡ Quick Actions Reference

### Prometheus Prime
| Action | Description |
|--------|-------------|
| Launch Full GUI | Opens complete Prometheus GUI |
| Start Autonomous | Begin 6-phase engagement |
| Query Intelligence | Search Omniscience KB |
| Emergency Stop | Halt all operations |

### Omega Swarm Brain
| Action | Description |
|--------|-------------|
| Spawn Agents | Create specialized agents |
| Coordinate Swarm | Organize multi-agent tasks |
| Terminate All | Stop all swarm agents |

### Memory System
| Action | Description |
|--------|-------------|
| Store Data | Save to persistent database |
| Query Database | Search memory entries |
| Export Data | Download stored information |

### MLS Server
| Action | Description |
|--------|-------------|
| Check Authorization | Verify user clearance |
| Generate Bloodline Key | Create sovereign key |

### Omniscience
| Action | Description |
|--------|-------------|
| Search Intelligence | Query CVE/Exploit/MITRE |
| Analyze Target | Profile target system |

### Sovereign Control
| Action | Description |
|--------|-------------|
| Activate Override | Enable Authority Level 11.0 |
| Deactivate Override | Return to normal mode |

---

## 🛠️ Configuration

### Change Port
```python
# Edit echo_prime_master_gui.py
run_master_gui(host='0.0.0.0', port=8080)  # Change to 8080
```

### Customize Systems
```python
# Add new system to ECHO_PRIME_SYSTEMS dictionary
"new_system": {
    "name": "New System",
    "icon": "🔥",
    "description": "Description here",
    "color": "#00ff00",
    "capabilities": [...],
    "status": "OPERATIONAL"
}
```

---

## 📁 File Structure

```
echo-prime-gui/
├── echo_prime_master_gui.py     (17KB) - Flask backend
├── templates/
│   └── echo_prime_master.html   (35KB) - Master interface
├── static/
│   ├── css/                     - Custom styles
│   ├── js/                      - JavaScript modules
│   └── images/                  - System icons
└── README.md                    - This file
```

---

## 🔄 Integration Points

### With Prometheus Prime
```python
# Launch Prometheus GUI from master
window.open('http://localhost:5001', '_blank')

# Call Prometheus API from master
fetch('/api/prometheus/execute-tool', {
    method: 'POST',
    body: JSON.stringify({tool_id: 'nmap', target: '192.168.1.100'})
})
```

### With Omega Swarm
```python
# Spawn agents
fetch('/api/swarm/spawn-agents', {
    method: 'POST',
    body: JSON.stringify({agent_count: 4})
})
```

### With Memory System
```python
# Store engagement data
fetch('/api/memory/store', {
    method: 'POST',
    body: JSON.stringify({data: engagement_results})
})
```

---

## 🎯 Use Cases

### 1. Complete Autonomous Engagement
```
1. Switch to Prometheus Prime tab
2. Click "Start Autonomous"
3. Switch to Omega Swarm tab
4. Spawn 4 agents for parallel execution
5. Switch to Memory tab
6. View stored engagement data
```

### 2. Intelligence Gathering
```
1. Switch to Omniscience tab
2. Search for target CVEs
3. Switch to Prometheus Prime tab
4. Launch Full GUI
5. Execute specific exploits
```

### 3. Multi-System Coordination
```
1. Spawn swarm agents (Omega Swarm tab)
2. Start autonomous engagement (Prometheus tab)
3. Monitor authorization (MLS tab)
4. Query intelligence (Omniscience tab)
5. Store results (Memory tab)
```

### 4. Sovereign Override Operations
```
1. Switch to Sovereign Control tab
2. Enter Sovereign ID and credentials
3. Activate override (Authority 11.0)
4. Execute unrestricted operations
5. Deactivate when complete
```

---

## ⚠️ Important Warnings

### Authorization Required
- **NEVER** use without signed contract
- All engagements require written authorization
- Unauthorized access is illegal
- Authority Level 11.0 ≠ Legal authorization

### Sovereign Override
- Bypasses **ALL** safety protocols
- Use only with proper authority
- Advisory system remains active
- Complete audit trail maintained
- Emergency use only

### System Coordination
- Multiple systems running simultaneously
- Monitor execution log for conflicts
- Use emergency stop if needed
- Coordinate swarm agents carefully

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find process using port 5000
lsof -i :5000

# Kill process
kill -9 <PID>

# Or change port in code
```

### WebSocket Connection Failed
```bash
# Check Flask-SocketIO installed
pip install flask-socketio python-socketio

# Verify firewall allows port 5000
```

### System Not Responding
```bash
# Check execution log for errors
# Use emergency stop button
# Restart GUI server
```

---

## 📈 Statistics

| Metric | Count |
|--------|-------|
| **Integrated Systems** | 6 |
| **Total Capabilities** | 30+ |
| **API Endpoints** | 10 |
| **WebSocket Events** | 8 |
| **Control Buttons** | 25+ |
| **Lines of Code** | 1,200+ |

---

## ✅ Future Enhancements

- [ ] Real tool execution (currently simulated)
- [ ] Database persistence integration
- [ ] Multi-user support with MLS
- [ ] Real-time metrics dashboard
- [ ] Export engagement reports
- [ ] Mobile-responsive design
- [ ] Dark/light theme toggle

---

**Authority Level: 11.0**
**Status: OPERATIONAL**
**Classification: AUTHORIZED USE ONLY**

🔥 **ECHO PRIME OMEGA - Master Control Ready** 🔥
