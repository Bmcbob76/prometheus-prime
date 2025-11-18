# 🎯 ECHO PRIME OMEGA - MASTER GUI

**Authority Level:** 11.0
**Architecture:** Modular Auto-Discovery Tab System
**Version:** 1.0

---

## 🚀 OVERVIEW

The Echo Prime Omega Master GUI is a **modular, auto-discovery web interface** that unifies all Echo Prime systems into a single command and control platform. Each system (Prometheus Prime, Omega Swarm Brain, Memory System, etc.) gets its own tab that's automatically discovered and loaded.

### Key Features

- ✅ **Auto-Discovery**: Drop a tab folder in `tabs/`, it loads automatically
- ✅ **Zero Configuration**: No manual registration required
- ✅ **Complete Isolation**: Each tab is self-contained
- ✅ **Flask Blueprint Architecture**: Professional modular design
- ✅ **Real-Time Updates**: WebSocket support for all tabs
- ✅ **Professional UI**: Cyberpunk-themed dark interface
- ✅ **Standalone Testing**: Test tabs independently before integration

---

## 📁 PROJECT STRUCTURE

```
echo-prime-gui/
├── echo_prime_master_gui.py      # Master GUI with auto-discovery engine
├── requirements.txt               # Python dependencies
├── README.md                      # This file
├── static/                        # Shared static assets
│   ├── css/
│   └── js/
├── templates/                     # Master GUI templates
│   └── echo_prime_master.html     # Main interface
└── tabs/                          # Tab modules (auto-discovered)
    ├── README.md                  # Tab development guide
    ├── prometheus-prime/          # Prometheus Prime tab
    │   ├── tab_config.json        # Configuration
    │   ├── backend.py             # Flask Blueprint
    │   ├── templates/             # Tab templates
    │   │   └── prometheus-prime/
    │   │       └── frontend.html  # Tab GUI
    │   └── static/                # Tab assets
    │       ├── css/
    │       └── js/
    ├── omega-swarm-brain/         # Additional tabs...
    ├── memory-system/
    ├── mls-server/
    ├── omniscience/
    └── sovereign-control/
```

---

## 🛠️ INSTALLATION

### Prerequisites

- Python 3.8+
- pip package manager

### Install Dependencies

```bash
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui
pip install -r requirements.txt
```

---

## 🚀 USAGE

### Start Master GUI

```bash
python echo_prime_master_gui.py
```

### Access Interface

Open your browser to:
```
http://localhost:5500
```

### What Happens on Startup

1. **Tab Discovery**: Master GUI scans `tabs/` directory
2. **Validation**: Checks each folder for `tab_config.json` and `backend.py`
3. **Loading**: Dynamically imports and initializes valid tabs
4. **Registration**: Registers Flask Blueprints and WebSocket handlers
5. **Ready**: All tabs accessible from master interface

### Expected Output

```
======================================================================
🚀 ECHO PRIME OMEGA - MASTER GUI
   Auto-Discovery Tab Architecture
   Authority Level: 11.0
======================================================================

======================================================================
🔍 AUTO-DISCOVERY: Scanning tabs/ directory...
======================================================================

📁 Checking: prometheus-prime/
   📄 Loading tab_config.json...
   ✅ Config valid: Prometheus Prime (Order: 1)
   📦 Loading backend.py...
   ✅ Backend loaded successfully
   🔧 Initializing tab...
   ✅ LOADED: Prometheus Prime
      Icon: ⚔️, Order: 1
      Routes: /tab/prometheus-prime

======================================================================
✅ AUTO-DISCOVERY COMPLETE: 1 tab(s) loaded
   1. ⚔️ Prometheus Prime
======================================================================

======================================================================
🎯 MASTER GUI READY
   Status: OPERATIONAL
   Tabs Loaded: 1
   Authority Level: 11.0
   Access at: http://localhost:5500
======================================================================
```

---

## 🎨 CREATING NEW TABS

Want to add a new system to the Master GUI? Just follow these steps:

### 1. Create Tab Directory

```bash
mkdir -p tabs/your-system-name/templates/your-system-name
mkdir -p tabs/your-system-name/static/{css,js}
```

### 2. Create `tab_config.json`

```json
{
  "id": "your_system_name",
  "name": "Your System Name",
  "icon": "🔧",
  "description": "Brief description of your system",
  "color": "#00ff00",
  "order": 7,
  "enabled": true,
  "authority_level": 11.0,
  "routes": {
    "main": "/tab/your-system-name",
    "api": "/api/your-system-name"
  },
  "capabilities": [
    "Capability 1",
    "Capability 2"
  ],
  "stats": {
    "stat_1": 0,
    "stat_2": "0%"
  }
}
```

### 3. Create `backend.py`

See `tabs/prometheus-prime/backend.py` for a complete example.

Minimum required:

```python
from flask import Blueprint, render_template, jsonify
from pathlib import Path
import json

# Load config
CONFIG_FILE = Path(__file__).parent / 'tab_config.json'
with open(CONFIG_FILE, 'r') as f:
    TAB_CONFIG = json.load(f)

# Create Blueprint
tab_blueprint = Blueprint(
    TAB_CONFIG['id'],
    __name__,
    url_prefix=TAB_CONFIG['routes']['main']
)

@tab_blueprint.route('/')
def index():
    return render_template(f"{TAB_CONFIG['id']}/frontend.html", config=TAB_CONFIG)

def initialize(app, socketio):
    """Called by Master GUI during discovery"""
    app.register_blueprint(tab_blueprint)
    print(f"✅ Initialized: {TAB_CONFIG['name']} Tab")
    return {"id": TAB_CONFIG['id'], "name": TAB_CONFIG['name']}
```

### 4. Create `templates/your-system-name/frontend.html`

See `tabs/prometheus-prime/templates/prometheus-prime/frontend.html` for a complete example.

### 5. Restart Master GUI

The tab will be automatically discovered and loaded!

---

## 🧪 TESTING

### Test Individual Tab

Each tab can be tested standalone:

```bash
cd tabs/prometheus-prime
python backend.py
```

Access at: `http://localhost:5001/tab/prometheus-prime`

### Test Master GUI Integration

```bash
python echo_prime_master_gui.py
```

Access at: `http://localhost:5500`

---

## 📡 API ENDPOINTS

### Master GUI Endpoints

- `GET /` - Main interface
- `GET /api/tabs` - Get all discovered tabs
- `GET /api/system/status` - Get master system status
- `GET /api/system/stats` - Get aggregated stats from all tabs

### Tab Endpoints

Each tab has its own routes under `/tab/[tab-name]` and `/api/[tab-name]`

Example (Prometheus Prime):
- `GET /tab/prometheus-prime` - Prometheus Prime tab interface
- `GET /api/prometheus-prime/status` - Get Prometheus status
- `POST /api/prometheus-prime/start` - Start Prometheus system
- `POST /api/prometheus-prime/start-autonomous` - Start autonomous engagement

---

## 🔌 WEBSOCKET EVENTS

### Master GUI Events

- `connect` → `master_connected` - Client connects to Master GUI
- `request_tabs` → `tabs_list` - Request list of all tabs
- `master_ping` → `master_pong` - Health check

### Tab Events

Each tab can define its own WebSocket events:
- `[tab-id]_connect` - Connect to specific tab
- `[tab-id]_update` - Receive updates from tab
- `[tab-id]_request_update` - Request update from tab

---

## 🎯 CURRENT TABS

### 1. ⚔️ Prometheus Prime (Order: 1)

**Description:** Autonomous Penetration Testing System
**Route:** `/tab/prometheus-prime`
**Capabilities:**
- Full 6-phase autonomous engagement
- 11 security domains with 50+ tools
- 220,000+ CVE database
- 50,000+ exploit arsenal

---

## 🔧 CONFIGURATION

### Tab Configuration Schema

Each `tab_config.json` must include:

**Required Fields:**
- `id` - Unique identifier (lowercase, underscores)
- `name` - Display name
- `icon` - Emoji or symbol
- `order` - Display order (1-N)
- `enabled` - true/false

**Optional Fields:**
- `description` - Brief description
- `color` - Primary color (hex)
- `authority_level` - Required authority level
- `routes` - URL route prefixes
- `capabilities` - List of capabilities
- `stats` - Statistics to display

---

## 🚨 TROUBLESHOOTING

### Tab Not Loading

1. **Check logs** during startup for error messages
2. **Verify files**:
   - `tab_config.json` exists and is valid JSON
   - `backend.py` exists and has `initialize()` function
   - `templates/[tab-name]/frontend.html` exists
3. **Check enabled**: Make sure `enabled: true` in tab_config.json
4. **Restart Master GUI** after making changes

### Port Already in Use

```bash
# Change port in echo_prime_master_gui.py
socketio.run(app, port=5501)  # Use different port
```

### Import Errors

```bash
# Make sure all dependencies are installed
pip install -r requirements.txt
```

---

## 📚 DOCUMENTATION

For complete integration guide and examples, see:
- `MODULAR_TAB_SYSTEM_INTEGRATION.md` - Complete integration guide
- `tabs/README.md` - Tab development guide
- `tabs/prometheus-prime/` - Complete working example

---

## 🎯 ROADMAP

### Completed
- [x] Auto-discovery architecture
- [x] Prometheus Prime tab
- [x] Flask Blueprint system
- [x] WebSocket support
- [x] Professional UI theme

### Planned
- [ ] Omega Swarm Brain tab
- [ ] Memory System tab
- [ ] MLS Server tab
- [ ] Omniscience tab
- [ ] Sovereign Control tab
- [ ] Master dashboard with aggregated stats
- [ ] Inter-tab communication
- [ ] System-wide event bus

---

## 👑 AUTHORITY LEVEL

**Authority Level:** 11.0

This Master GUI requires and operates at **Authority Level 11.0**, providing complete control over all Echo Prime Omega systems.

---

## 📞 SUPPORT

For issues or questions:
1. Check `MODULAR_TAB_SYSTEM_INTEGRATION.md`
2. Review example in `tabs/prometheus-prime/`
3. Check logs during startup for errors

---

**STATUS:** ✅ OPERATIONAL
**VERSION:** 1.0
**LAST UPDATED:** 2025-11-12

---

**END OF README**
