# 🎯 TAB DEVELOPMENT GUIDE

**Echo Prime Omega - Modular Tab Architecture**
**Authority Level:** 11.0

---

## 📖 OVERVIEW

This directory contains all system tabs that are automatically discovered and loaded by the Echo Prime Master GUI. Each subdirectory represents a self-contained system tab.

---

## 🏗️ TAB ARCHITECTURE

Each tab is a **complete, isolated module** with its own:
- Configuration (tab_config.json)
- Backend logic (backend.py - Flask Blueprint)
- Frontend GUI (templates/[tab-name]/frontend.html)
- Static assets (static/)

---

## 📋 CREATING A NEW TAB

### Step 1: Create Directory Structure

```bash
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui/tabs

# Replace "your-system-name" with your actual system name
mkdir -p your-system-name/templates/your-system-name
mkdir -p your-system-name/static/{css,js}
```

### Step 2: Create `tab_config.json`

This file defines your tab's metadata and configuration.

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
    "Capability 2",
    "Capability 3"
  ],
  "stats": {
    "stat_1": 0,
    "stat_2": "0%",
    "stat_3": "IDLE"
  }
}
```

#### Configuration Field Reference

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `id` | ✅ Yes | Unique identifier (lowercase, underscores) | `"prometheus_prime"` |
| `name` | ✅ Yes | Display name for the tab | `"Prometheus Prime"` |
| `icon` | ✅ Yes | Emoji or symbol for tab | `"⚔️"` |
| `order` | ✅ Yes | Display order (1-N) | `1` |
| `enabled` | ✅ Yes | Whether tab is active | `true` |
| `description` | No | Brief system description | `"Autonomous Penetration Testing"` |
| `color` | No | Primary color (hex) | `"#ff0000"` |
| `authority_level` | No | Required authority level | `11.0` |
| `routes.main` | No | Main route prefix | `"/tab/prometheus-prime"` |
| `routes.api` | No | API route prefix | `"/api/prometheus-prime"` |
| `capabilities` | No | List of capabilities | `["Capability 1", "Capability 2"]` |
| `stats` | No | Statistics to display | `{"tools": 50, "domains": 11}` |

### Step 3: Create `backend.py`

This file contains your Flask Blueprint with all API endpoints and WebSocket handlers.

**Minimum Required Template:**

```python
"""
[YOUR SYSTEM NAME] Tab Backend
Auto-loaded by Echo Prime Master GUI
"""

from flask import Blueprint, render_template, request, jsonify
from flask_socketio import emit
import json
from datetime import datetime
from pathlib import Path

# Load tab configuration
CONFIG_FILE = Path(__file__).parent / 'tab_config.json'
with open(CONFIG_FILE, 'r') as f:
    TAB_CONFIG = json.load(f)

# Create Flask Blueprint
tab_blueprint = Blueprint(
    TAB_CONFIG['id'],
    __name__,
    url_prefix=TAB_CONFIG['routes']['main'],
    template_folder='templates',
    static_folder='static'
)

# System state
system_state = {
    "active": False,
    "status": "IDLE",
    "stats": TAB_CONFIG.get('stats', {}),
    "last_update": None
}

# ==================== ROUTES ====================

@tab_blueprint.route('/')
def index():
    """Render tab frontend"""
    template_path = f"{TAB_CONFIG['id']}/frontend.html"
    return render_template(template_path, config=TAB_CONFIG)

@tab_blueprint.route('/api/status', methods=['GET'])
def get_status():
    """Get current system status"""
    return jsonify({
        "success": True,
        "state": system_state,
        "config": TAB_CONFIG
    })

@tab_blueprint.route('/api/start', methods=['POST'])
def start_system():
    """Start the system"""
    system_state["active"] = True
    system_state["status"] = "ACTIVE"
    system_state["last_update"] = datetime.now().isoformat()

    return jsonify({
        "success": True,
        "message": f"{TAB_CONFIG['name']} started",
        "state": system_state
    })

@tab_blueprint.route('/api/stop', methods=['POST'])
def stop_system():
    """Stop the system"""
    system_state["active"] = False
    system_state["status"] = "STOPPED"
    system_state["last_update"] = datetime.now().isoformat()

    return jsonify({
        "success": True,
        "message": f"{TAB_CONFIG['name']} stopped",
        "state": system_state
    })

# ==================== WEBSOCKET HANDLERS ====================

socketio_instance = None

def init_socketio(socketio):
    """Initialize WebSocket handlers"""
    global socketio_instance
    socketio_instance = socketio

    @socketio.on(f'{TAB_CONFIG["id"]}_connect')
    def handle_connect(data):
        emit(f'{TAB_CONFIG["id"]}_status', {
            "connected": True,
            "state": system_state
        })

    @socketio.on(f'{TAB_CONFIG["id"]}_request_update')
    def handle_update_request():
        emit(f'{TAB_CONFIG["id"]}_update', {
            "state": system_state,
            "timestamp": datetime.now().isoformat()
        })

def broadcast_update(update_data):
    """Broadcast update to all connected clients"""
    if socketio_instance:
        socketio_instance.emit(f'{TAB_CONFIG["id"]}_update', {
            "data": update_data,
            "state": system_state,
            "timestamp": datetime.now().isoformat()
        })

# ==================== INITIALIZATION ====================

def initialize(app, socketio):
    """
    Called by Master GUI during tab discovery

    Args:
        app: Flask application instance
        socketio: SocketIO instance

    Returns:
        dict: Tab information
    """
    # Register Blueprint
    app.register_blueprint(tab_blueprint)

    # Initialize WebSocket handlers
    init_socketio(socketio)

    print(f"✅ Initialized: {TAB_CONFIG['name']} Tab")
    print(f"   Routes: {TAB_CONFIG['routes']['main']}")

    return {
        "id": TAB_CONFIG['id'],
        "name": TAB_CONFIG['name'],
        "blueprint": tab_blueprint,
        "config": TAB_CONFIG
    }

# ==================== STANDALONE TESTING ====================

if __name__ == '__main__':
    from flask import Flask
    from flask_socketio import SocketIO

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*")

    initialize(app, socketio)

    print(f"\n🚀 Running {TAB_CONFIG['name']} Tab in standalone mode")
    print(f"   Access at: http://localhost:5001{TAB_CONFIG['routes']['main']}")

    socketio.run(app, debug=True, port=5001)
```

### Step 4: Create `templates/[tab-name]/frontend.html`

This file contains your tab's GUI interface.

**Minimum Required Template:**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ config.name }} - Echo Prime Omega</title>
    <style>
        :root {
            --primary-color: {{ config.color }};
            --bg-dark: #0a0a0a;
            --text-primary: #00ff00;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--bg-dark);
            color: var(--text-primary);
            padding: 20px;
        }

        .tab-header {
            text-align: center;
            border: 2px solid var(--primary-color);
            padding: 30px;
            margin-bottom: 30px;
        }

        .tab-header h2 {
            color: var(--primary-color);
            font-size: 3em;
        }

        .control-btn {
            background: var(--primary-color);
            border: none;
            color: #000;
            padding: 15px 30px;
            margin: 10px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-size: 1.1em;
        }

        .control-btn:hover {
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="tab-header">
        <h2>{{ config.icon }} {{ config.name }}</h2>
        <p>{{ config.description }}</p>
    </div>

    <div class="controls">
        <button class="control-btn" onclick="startSystem()">Start System</button>
        <button class="control-btn" onclick="stopSystem()">Stop System</button>
    </div>

    <div id="log"></div>

    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script>
        const CONFIG = {{ config|tojson }};
        const socket = io();

        async function startSystem() {
            const response = await fetch(`${CONFIG.routes.main}/api/start`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            });
            const data = await response.json();
            console.log(data);
        }

        async function stopSystem() {
            const response = await fetch(`${CONFIG.routes.main}/api/stop`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            });
            const data = await response.json();
            console.log(data);
        }

        socket.on('connect', () => {
            console.log('Connected to Master GUI');
            socket.emit(`${CONFIG.id}_connect`, {});
        });
    </script>
</body>
</html>
```

### Step 5: Test Your Tab

#### Test Standalone

```bash
cd your-system-name
python backend.py
```

Access at: `http://localhost:5001/tab/your-system-name`

#### Test Integrated

```bash
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui
python echo_prime_master_gui.py
```

Access at: `http://localhost:5500`

Your tab should appear automatically!

---

## ✅ TAB REQUIREMENTS CHECKLIST

Before your tab will be discovered:

- [ ] Directory created in `tabs/`
- [ ] `tab_config.json` exists and is valid JSON
- [ ] Required fields in tab_config.json: `id`, `name`, `icon`, `order`, `enabled`
- [ ] `enabled` is set to `true`
- [ ] `backend.py` exists
- [ ] `backend.py` has `initialize(app, socketio)` function
- [ ] `templates/[tab-name]/frontend.html` exists
- [ ] Tab tested standalone successfully

---

## 🔍 AUTO-DISCOVERY PROCESS

When the Master GUI starts:

1. **Scan**: Master GUI scans `tabs/` directory for subdirectories
2. **Validate**: For each directory:
   - Check for `tab_config.json`
   - Check for `backend.py`
   - Validate JSON structure
   - Verify required fields
   - Check if `enabled: true`
3. **Load**: If valid:
   - Dynamically import `backend.py`
   - Call `initialize(app, socketio)`
   - Register Flask Blueprint
   - Initialize WebSocket handlers
4. **Sort**: Tabs loaded in order specified by `order` field
5. **Ready**: All tabs accessible from master interface

---

## 📚 EXAMPLES

### Complete Example: Prometheus Prime

See `prometheus-prime/` for a complete, production-ready example with:
- Full configuration (`tab_config.json`)
- Complete backend with 13 API endpoints (`backend.py`)
- Professional GUI with cyberpunk theme (`frontend.html`)
- WebSocket real-time updates
- Comprehensive logging

Study this example when building your tab!

---

## 🎨 STYLING GUIDELINES

### Color Themes

Each tab should use its own primary color defined in `tab_config.json`:

- **Prometheus Prime**: `#ff0000` (Red) - Offensive security
- **Omega Swarm Brain**: `#00ffff` (Cyan) - Multi-agent coordination
- **Memory System**: `#9400d3` (Purple) - Knowledge management
- **MLS Server**: `#ffa500` (Orange) - MCP protocol
- **Omniscience**: `#ffff00` (Yellow) - Sensory systems
- **Sovereign Control**: `#ffd700` (Gold) - Ultimate authority

### UI Conventions

- Dark background (`#0a0a0a`)
- Primary text color (`#00ff00` green)
- Monospace font (`'Courier New', monospace`)
- Border glow effects on hover
- Cyberpunk aesthetic

---

## 🚨 COMMON ISSUES

### Tab Not Loading

**Issue:** Tab doesn't appear in Master GUI

**Solutions:**
1. Check `enabled: true` in tab_config.json
2. Verify all required fields in tab_config.json
3. Check console for error messages during startup
4. Ensure `initialize()` function exists in backend.py
5. Verify directory name matches `id` in tab_config.json

### Import Errors

**Issue:** `ModuleNotFoundError` or import errors

**Solutions:**
1. Ensure all imports are available
2. Check Python path
3. Install required dependencies: `pip install -r requirements.txt`

### Template Not Found

**Issue:** `TemplateNotFound` error

**Solutions:**
1. Verify `templates/[tab-name]/frontend.html` exists
2. Check directory name matches `id` in tab_config.json
3. Ensure template_folder set correctly in Blueprint

---

## 📞 SUPPORT

For tab development help:
1. Study `prometheus-prime/` example
2. Review `../MODULAR_TAB_SYSTEM_INTEGRATION.md`
3. Check Master GUI logs for error messages
4. Test standalone first before integrating

---

## 🎯 PLANNED TABS

- [ ] **Omega Swarm Brain** - Multi-agent coordination system
- [ ] **Memory System** - Crystal Memory persistence
- [ ] **MLS Server** - Model Context Protocol server
- [ ] **Omniscience** - Complete sensory & monitoring
- [ ] **Sovereign Control** - Ultimate system authority

---

**Authority Level:** 11.0
**Last Updated:** 2025-11-12

---

**END OF GUIDE**
