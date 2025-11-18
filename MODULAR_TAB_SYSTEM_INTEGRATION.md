# 📚 MODULAR TAB SYSTEM - Claude Code Integration Instructions

**Authority Level: 11.0**
**Document Version:** 1.0
**Last Updated:** 2025-11-12

---

## 🎯 MISSION OBJECTIVE

Integrate all Echo Prime Omega systems into a unified Master GUI using a **modular, auto-discovery tab architecture**. Each system gets its own tab folder, and the Master GUI automatically detects and loads all valid tabs.

---

## 🏗️ ARCHITECTURE OVERVIEW

### Core Principles

1. **Auto-Discovery**: Master GUI scans `tabs/` directory and loads all valid tabs
2. **Isolation**: Each tab is completely self-contained with its own backend, frontend, and config
3. **Zero Manual Registration**: No need to modify master code to add new tabs
4. **Blueprint Pattern**: Each tab uses Flask Blueprint for route isolation
5. **Configuration-Driven**: JSON config files define all tab metadata

### Directory Structure

```
echo-prime-omega/echo-prime-gui/
├── echo_prime_master_gui.py          # Master GUI with auto-discovery
├── requirements.txt                   # Python dependencies
├── README.md                          # Setup and usage guide
├── static/                            # Shared static assets
│   ├── css/
│   │   └── master_styles.css          # Global styles
│   └── js/
│       └── master_utils.js            # Shared JavaScript utilities
├── templates/                         # Master GUI templates
│   └── echo_prime_master.html         # Main master interface
└── tabs/                              # Tab modules directory
    ├── README.md                      # Tab development guide
    ├── prometheus-prime/              # Prometheus Prime tab
    │   ├── tab_config.json            # Tab configuration
    │   ├── backend.py                 # Flask Blueprint backend
    │   ├── templates/                 # Tab-specific templates
    │   │   └── frontend.html          # Tab GUI
    │   └── static/                    # Tab-specific assets
    │       ├── css/
    │       └── js/
    ├── omega-swarm-brain/             # Omega Swarm Brain tab
    │   ├── tab_config.json
    │   ├── backend.py
    │   └── templates/
    │       └── frontend.html
    ├── memory-system/                 # Memory System tab
    ├── mls-server/                    # MLS Server tab
    ├── omniscience/                   # Omniscience tab
    └── sovereign-control/             # Sovereign Control tab
```

---

## 📋 PHASE 1: CREATE TABS DIRECTORY STRUCTURE

### Step 1.1: Create Base Directories

```bash
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui

# Create tabs directory
mkdir -p tabs

# Create placeholder for each of the 6 systems
mkdir -p tabs/prometheus-prime/templates/prometheus-prime
mkdir -p tabs/prometheus-prime/static/{css,js}
mkdir -p tabs/omega-swarm-brain/templates/omega-swarm-brain
mkdir -p tabs/omega-swarm-brain/static/{css,js}
mkdir -p tabs/memory-system/templates/memory-system
mkdir -p tabs/memory-system/static/{css,js}
mkdir -p tabs/mls-server/templates/mls-server
mkdir -p tabs/mls-server/static/{css,js}
mkdir -p tabs/omniscience/templates/omniscience
mkdir -p tabs/omniscience/static/{css,js}
mkdir -p tabs/sovereign-control/templates/sovereign-control
mkdir -p tabs/sovereign-control/static/{css,js}

# Create master static and templates directories
mkdir -p static/{css,js}
mkdir -p templates
```

### Step 1.2: Create Tab Development Guide

Create `tabs/README.md`:

```markdown
# 🎯 TAB DEVELOPMENT GUIDE

## Creating a New Tab

To add a new system tab to the Echo Prime Master GUI:

### 1. Create Tab Directory

```bash
mkdir -p tabs/your-system-name/templates/your-system-name
mkdir -p tabs/your-system-name/static/{css,js}
```

### 2. Create tab_config.json

See Phase 2 for configuration schema.

### 3. Create backend.py

See Phase 3 for backend template.

### 4. Create frontend.html

See Phase 4 for frontend template.

### 5. Restart Master GUI

The tab will be automatically discovered and loaded.

## Tab Requirements

- **Directory name**: Must match `id` in tab_config.json
- **tab_config.json**: Required, defines tab metadata
- **backend.py**: Required, must export `initialize(app, socketio)` function
- **templates/[tab-name]/frontend.html**: Required, the tab's GUI
- **static/**: Optional, tab-specific CSS/JS assets

## Auto-Discovery Process

1. Master GUI scans `tabs/` directory
2. For each subdirectory:
   - Checks for `tab_config.json`
   - Validates configuration
   - Dynamically imports `backend.py`
   - Registers Flask Blueprint
   - Initializes WebSocket handlers
3. Tabs loaded in order specified by `order` field
4. Tabs can be enabled/disabled via `enabled` field

## Testing Your Tab

1. **Standalone**: Run `python backend.py` to test independently
2. **Integrated**: Restart Master GUI to test within full system
3. **Verify**: Check Master GUI logs for "✅ Initialized: [Tab Name]"
```

---

## 📋 PHASE 2: DEFINE TAB CONFIGURATION STANDARD

### Tab Configuration Schema

Each tab must have a `tab_config.json` file with the following structure:

```json
{
  "id": "prometheus_prime",
  "name": "Prometheus Prime",
  "icon": "⚔️",
  "description": "Autonomous Penetration Testing System",
  "color": "#ff0000",
  "order": 1,
  "enabled": true,
  "authority_level": 11.0,
  "routes": {
    "main": "/tab/prometheus-prime",
    "api": "/api/prometheus-prime"
  },
  "capabilities": [
    "Full 6-phase autonomous engagement",
    "11 security domains with 50+ tools",
    "220,000+ CVE database",
    "50,000+ exploit arsenal",
    "Automatic vulnerability chaining",
    "Real-time adaptive tactics"
  ],
  "stats": {
    "domains": 11,
    "tools": 50,
    "cves": 220000,
    "exploits": 50000
  }
}
```

### Field Descriptions

- **id**: Unique identifier (must match directory name)
- **name**: Display name for the tab
- **icon**: Emoji or symbol for tab icon
- **description**: Brief system description
- **color**: Primary color for tab UI (hex code)
- **order**: Display order in tab list (1-6)
- **enabled**: Whether tab is active (true/false)
- **authority_level**: Required authority level
- **routes**: URL route prefixes for main and API endpoints
- **capabilities**: List of system capabilities
- **stats**: Key statistics to display on tab

---

## 📋 PHASE 3: CREATE TAB BACKEND MODULE TEMPLATE

### Backend Module Structure

Each `backend.py` must follow this pattern:

```python
"""
[SYSTEM NAME] Tab Backend
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
    "last_update": None,
    "stats": TAB_CONFIG.get('stats', {}),
    "status": "IDLE"
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
    data = request.json
    system_state["active"] = True
    system_state["status"] = "RUNNING"
    system_state["last_update"] = datetime.now().isoformat()

    return jsonify({
        "success": True,
        "message": f"{TAB_CONFIG['name']} started successfully",
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
        "message": f"{TAB_CONFIG['name']} stopped successfully",
        "state": system_state
    })

@tab_blueprint.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    return jsonify({
        "success": True,
        "stats": system_state["stats"]
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
    """
    # Register Blueprint
    app.register_blueprint(tab_blueprint)

    # Initialize WebSocket handlers
    init_socketio(socketio)

    print(f"✅ Initialized: {TAB_CONFIG['name']} Tab")
    print(f"   Routes: {TAB_CONFIG['routes']['main']}, {TAB_CONFIG['routes']['api']}")
    print(f"   Order: {TAB_CONFIG['order']}, Enabled: {TAB_CONFIG['enabled']}")

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
    print(f"   Access at: http://localhost:5000{TAB_CONFIG['routes']['main']}")

    socketio.run(app, debug=True, port=5000)
```

---

## 📋 PHASE 4: CREATE TAB FRONTEND TEMPLATE

### Frontend HTML Template

Each `templates/[tab-name]/frontend.html`:

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
            --bg-darker: #050505;
            --text-primary: #00ff00;
            --text-secondary: #00cc00;
            --border-color: #004400;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Courier New', monospace;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .tab-container {
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }

        .tab-header {
            background: linear-gradient(135deg, var(--bg-darker) 0%, var(--primary-color)22 100%);
            border: 2px solid var(--primary-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: center;
        }

        .tab-header h2 {
            font-size: 2.5em;
            color: var(--primary-color);
            text-shadow: 0 0 20px var(--primary-color);
            margin-bottom: 10px;
        }

        .tab-header p {
            color: var(--text-secondary);
            font-size: 1.2em;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-darker);
            border: 2px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            border-color: var(--primary-color);
            box-shadow: 0 0 20px var(--primary-color)44;
            transform: translateY(-5px);
        }

        .stat-card .value {
            font-size: 2.5em;
            color: var(--primary-color);
            font-weight: bold;
            margin-bottom: 10px;
        }

        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.9em;
            text-transform: uppercase;
        }

        .control-section {
            background: var(--bg-darker);
            border: 2px solid var(--border-color);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
        }

        .control-section h3 {
            color: var(--primary-color);
            margin-bottom: 20px;
            font-size: 1.5em;
        }

        .control-btn {
            background: linear-gradient(135deg, var(--primary-color)22 0%, var(--primary-color)44 100%);
            border: 2px solid var(--primary-color);
            color: var(--text-primary);
            padding: 15px 30px;
            margin: 10px;
            border-radius: 5px;
            font-size: 1.1em;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: 'Courier New', monospace;
        }

        .control-btn:hover {
            background: var(--primary-color);
            box-shadow: 0 0 20px var(--primary-color);
            transform: scale(1.05);
        }

        .control-btn:active {
            transform: scale(0.95);
        }

        .status-indicator {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
            animation: pulse 2s infinite;
        }

        .status-indicator.active {
            background: #00ff00;
            box-shadow: 0 0 10px #00ff00;
        }

        .status-indicator.inactive {
            background: #ff0000;
            box-shadow: 0 0 10px #ff0000;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .capabilities-list {
            background: var(--bg-darker);
            border: 2px solid var(--border-color);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
        }

        .capabilities-list h3 {
            color: var(--primary-color);
            margin-bottom: 20px;
            font-size: 1.5em;
        }

        .capabilities-list ul {
            list-style: none;
        }

        .capabilities-list li {
            padding: 10px;
            margin: 5px 0;
            background: var(--bg-dark);
            border-left: 3px solid var(--primary-color);
            padding-left: 15px;
        }

        .capabilities-list li:before {
            content: "✓ ";
            color: var(--primary-color);
            font-weight: bold;
            margin-right: 10px;
        }

        .log-container {
            background: var(--bg-darker);
            border: 2px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            height: 300px;
            overflow-y: auto;
        }

        .log-container h3 {
            color: var(--primary-color);
            margin-bottom: 15px;
        }

        .log-entry {
            padding: 5px;
            margin: 2px 0;
            font-size: 0.9em;
            border-bottom: 1px solid var(--border-color);
        }

        .log-entry .timestamp {
            color: var(--text-secondary);
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="tab-container">
        <!-- Header -->
        <div class="tab-header">
            <h2>{{ config.icon }} {{ config.name }}</h2>
            <p>{{ config.description }}</p>
            <p>
                <span class="status-indicator inactive" id="status-indicator"></span>
                <span id="status-text">IDLE</span>
            </p>
        </div>

        <!-- Statistics Grid -->
        <div class="stats-grid" id="stats-grid">
            {% for key, value in config.stats.items() %}
            <div class="stat-card">
                <div class="value" id="stat-{{ key }}">{{ value }}</div>
                <div class="label">{{ key|title }}</div>
            </div>
            {% endfor %}
        </div>

        <!-- Control Section -->
        <div class="control-section">
            <h3>System Controls</h3>
            <button class="control-btn" onclick="startSystem()">
                ▶️ Start System
            </button>
            <button class="control-btn" onclick="stopSystem()">
                ⏹️ Stop System
            </button>
            <button class="control-btn" onclick="refreshStatus()">
                🔄 Refresh Status
            </button>
            <button class="control-btn" onclick="launchFullGUI()">
                🚀 Launch Full GUI
            </button>
        </div>

        <!-- Capabilities List -->
        <div class="capabilities-list">
            <h3>System Capabilities</h3>
            <ul>
                {% for capability in config.capabilities %}
                <li>{{ capability }}</li>
                {% endfor %}
            </ul>
        </div>

        <!-- Activity Log -->
        <div class="log-container">
            <h3>Activity Log</h3>
            <div id="activity-log"></div>
        </div>
    </div>

    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script>
        const CONFIG = {{ config|tojson }};
        const socket = io();

        // Log function
        function addLog(message) {
            const log = document.getElementById('activity-log');
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            const timestamp = new Date().toLocaleTimeString();
            entry.innerHTML = `<span class="timestamp">[${timestamp}]</span>${message}`;
            log.insertBefore(entry, log.firstChild);

            // Keep only last 50 entries
            while (log.children.length > 50) {
                log.removeChild(log.lastChild);
            }
        }

        // Update status indicator
        function updateStatus(active) {
            const indicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');

            if (active) {
                indicator.className = 'status-indicator active';
                statusText.textContent = 'ACTIVE';
            } else {
                indicator.className = 'status-indicator inactive';
                statusText.textContent = 'IDLE';
            }
        }

        // API calls
        async function startSystem() {
            try {
                const response = await fetch(`${CONFIG.routes.main}/api/start`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({})
                });
                const data = await response.json();

                if (data.success) {
                    addLog(`✅ ${data.message}`);
                    updateStatus(true);
                } else {
                    addLog(`❌ Failed to start system`);
                }
            } catch (error) {
                addLog(`❌ Error: ${error.message}`);
            }
        }

        async function stopSystem() {
            try {
                const response = await fetch(`${CONFIG.routes.main}/api/stop`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({})
                });
                const data = await response.json();

                if (data.success) {
                    addLog(`⏹️ ${data.message}`);
                    updateStatus(false);
                } else {
                    addLog(`❌ Failed to stop system`);
                }
            } catch (error) {
                addLog(`❌ Error: ${error.message}`);
            }
        }

        async function refreshStatus() {
            try {
                const response = await fetch(`${CONFIG.routes.main}/api/status`);
                const data = await response.json();

                if (data.success) {
                    updateStatus(data.state.active);
                    addLog(`🔄 Status refreshed`);

                    // Update stats
                    for (const [key, value] of Object.entries(data.state.stats)) {
                        const statElement = document.getElementById(`stat-${key}`);
                        if (statElement) {
                            statElement.textContent = value;
                        }
                    }
                }
            } catch (error) {
                addLog(`❌ Error: ${error.message}`);
            }
        }

        function launchFullGUI() {
            addLog(`🚀 Launching full ${CONFIG.name} GUI...`);
            // Open full GUI in new window
            window.open(`${CONFIG.routes.main}/full`, '_blank');
        }

        // WebSocket handlers
        socket.on('connect', function() {
            addLog('🔌 Connected to Master GUI');
            socket.emit(`${CONFIG.id}_connect`, {});
        });

        socket.on(`${CONFIG.id}_status`, function(data) {
            addLog(`📡 Received status update`);
            updateStatus(data.state.active);
        });

        socket.on(`${CONFIG.id}_update`, function(data) {
            addLog(`📡 System update received`);
            if (data.state) {
                updateStatus(data.state.active);
            }
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            addLog(`🎯 ${CONFIG.name} Tab initialized`);
            refreshStatus();
        });
    </script>
</body>
</html>
```

---

## 📋 PHASE 5: IMPLEMENT AUTO-DISCOVERY IN MASTER GUI

### Master GUI with Auto-Discovery

Update `echo_prime_master_gui.py`:

```python
"""
ECHO PRIME OMEGA - MASTER GUI
Auto-Discovery Tab Architecture
Authority Level: 11.0
"""

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import json
from pathlib import Path
import importlib.util

app = Flask(__name__)
app.config['SECRET_KEY'] = 'echo-prime-omega-master-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Tabs directory
TABS_DIR = Path(__file__).parent / 'tabs'

# Discovered tabs
discovered_tabs = {}

def discover_tabs():
    """
    Auto-discover all tab modules in tabs/ directory
    Returns dict of tab configurations
    """
    tabs = {}

    if not TABS_DIR.exists():
        print("⚠️  Tabs directory not found")
        return tabs

    print("\n🔍 Discovering tabs...")

    for tab_folder in sorted(TABS_DIR.iterdir()):
        if not tab_folder.is_dir() or tab_folder.name.startswith('_'):
            continue

        config_file = tab_folder / 'tab_config.json'
        backend_file = tab_folder / 'backend.py'

        # Check if tab has required files
        if not config_file.exists():
            print(f"⚠️  Skipping {tab_folder.name}: No tab_config.json")
            continue

        if not backend_file.exists():
            print(f"⚠️  Skipping {tab_folder.name}: No backend.py")
            continue

        try:
            # Load configuration
            with open(config_file, 'r') as f:
                config = json.load(f)

            # Validate configuration
            required_fields = ['id', 'name', 'icon', 'order', 'enabled']
            if not all(field in config for field in required_fields):
                print(f"⚠️  Skipping {tab_folder.name}: Invalid config")
                continue

            # Skip if disabled
            if not config['enabled']:
                print(f"⏸️  Skipping {tab_folder.name}: Disabled in config")
                continue

            # Load backend module dynamically
            spec = importlib.util.spec_from_file_location(
                f"tabs.{tab_folder.name}.backend",
                backend_file
            )
            backend_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(backend_module)

            # Initialize the tab
            if hasattr(backend_module, 'initialize'):
                tab_info = backend_module.initialize(app, socketio)
                tabs[config['id']] = {
                    'config': config,
                    'module': backend_module,
                    'info': tab_info
                }
                print(f"✅ Loaded: {config['name']} (Order: {config['order']})")
            else:
                print(f"⚠️  Skipping {tab_folder.name}: No initialize() function")

        except Exception as e:
            print(f"❌ Error loading {tab_folder.name}: {e}")

    # Sort by order
    tabs = dict(sorted(tabs.items(), key=lambda x: x[1]['config']['order']))

    print(f"\n✅ Discovered {len(tabs)} active tabs\n")
    return tabs

# ==================== MASTER GUI ROUTES ====================

@app.route('/')
def index():
    """Render master GUI"""
    return render_template('echo_prime_master.html', tabs=discovered_tabs)

@app.route('/api/tabs', methods=['GET'])
def get_tabs():
    """Get all discovered tabs"""
    tabs_info = {
        tab_id: {
            'id': tab_data['config']['id'],
            'name': tab_data['config']['name'],
            'icon': tab_data['config']['icon'],
            'description': tab_data['config'].get('description', ''),
            'color': tab_data['config'].get('color', '#00ff00'),
            'order': tab_data['config']['order'],
            'routes': tab_data['config'].get('routes', {})
        }
        for tab_id, tab_data in discovered_tabs.items()
    }
    return jsonify({
        "success": True,
        "count": len(tabs_info),
        "tabs": tabs_info
    })

@app.route('/api/system/status', methods=['GET'])
def get_system_status():
    """Get overall system status"""
    return jsonify({
        "success": True,
        "master_status": "OPERATIONAL",
        "tabs_loaded": len(discovered_tabs),
        "tabs": list(discovered_tabs.keys())
    })

# ==================== WEBSOCKET HANDLERS ====================

@socketio.on('connect')
def handle_connect():
    print("🔌 Client connected to Master GUI")

@socketio.on('disconnect')
def handle_disconnect():
    print("🔌 Client disconnected from Master GUI")

@socketio.on('request_tabs')
def handle_request_tabs():
    """Send tabs list to client"""
    socketio.emit('tabs_list', {
        "tabs": [tab_data['config'] for tab_data in discovered_tabs.values()]
    })

# ==================== STARTUP ====================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 ECHO PRIME OMEGA - MASTER GUI")
    print("   Authority Level: 11.0")
    print("   Auto-Discovery Tab Architecture")
    print("="*60)

    # Discover and load all tabs
    discovered_tabs = discover_tabs()

    print("\n" + "="*60)
    print(f"🎯 Master GUI Ready")
    print(f"   Tabs Loaded: {len(discovered_tabs)}")
    print(f"   Access at: http://localhost:5500")
    print("="*60 + "\n")

    socketio.run(app, debug=True, host='0.0.0.0', port=5500)
```

---

## 📋 PHASE 6: CREATE PROMETHEUS PRIME TAB (EXAMPLE)

### Complete Working Example

This phase creates a complete, working Prometheus Prime tab as a reference for other tabs.

See the files created in `/home/user/prometheus-prime/echo-prime-omega/echo-prime-gui/tabs/prometheus-prime/`:

1. `tab_config.json` - Configuration
2. `backend.py` - Flask Blueprint backend (see Phase 3 template)
3. `templates/prometheus-prime/frontend.html` - GUI (see Phase 4 template)

### Customizations for Prometheus Prime

Additional API endpoints specific to Prometheus Prime:

```python
@tab_blueprint.route('/api/start-autonomous', methods=['POST'])
def start_autonomous():
    """Start autonomous penetration testing engagement"""
    data = request.json
    target = data.get('target', '')
    depth = data.get('depth', 'full')

    system_state["autonomous_mode"] = True
    system_state["engagement_active"] = True
    system_state["target"] = target

    # Start autonomous engagement
    engagement_id = f"ENG-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    broadcast_update({
        "event": "autonomous_started",
        "engagement_id": engagement_id,
        "target": target,
        "depth": depth
    })

    return jsonify({
        "success": True,
        "engagement_id": engagement_id,
        "message": f"Autonomous engagement started on {target}"
    })

@tab_blueprint.route('/api/execute-tool', methods=['POST'])
def execute_tool():
    """Execute a specific tool from a domain"""
    data = request.json
    tool_id = data.get('tool_id')
    domain = data.get('domain')
    target = data.get('target', '')
    options = data.get('options', {})

    # Execute tool logic here

    broadcast_update({
        "event": "tool_executed",
        "tool": tool_id,
        "domain": domain,
        "target": target
    })

    return jsonify({
        "success": True,
        "tool_id": tool_id,
        "status": "executing"
    })

@tab_blueprint.route('/api/domains', methods=['GET'])
def get_domains():
    """Get all security domains and their tools"""
    # Return domains data structure
    return jsonify({
        "success": True,
        "domains": TOOL_DOMAINS  # Import from main prometheus module
    })
```

---

## 📋 PHASE 7: CREATE REMAINING TABS

Use Prometheus Prime as the template to create the remaining 5 tabs:

### 7.1: Omega Swarm Brain Tab

```bash
mkdir -p tabs/omega-swarm-brain/templates/omega-swarm-brain
mkdir -p tabs/omega-swarm-brain/static/{css,js}
```

Create `tabs/omega-swarm-brain/tab_config.json`:

```json
{
  "id": "omega_swarm_brain",
  "name": "Omega Swarm Brain",
  "icon": "🧠",
  "description": "Distributed Multi-Agent Coordination System",
  "color": "#00ffff",
  "order": 2,
  "enabled": true,
  "authority_level": 11.0,
  "routes": {
    "main": "/tab/omega-swarm-brain",
    "api": "/api/omega-swarm-brain"
  },
  "capabilities": [
    "Multi-agent task distribution",
    "Swarm intelligence coordination",
    "Autonomous agent spawning",
    "Task parallelization",
    "Collective decision making"
  ],
  "stats": {
    "active_agents": 0,
    "tasks_queued": 0,
    "tasks_completed": 0,
    "swarm_efficiency": "0%"
  }
}
```

Then copy `backend.py` and `templates/frontend.html` from Prometheus Prime and customize.

### 7.2: Memory System Tab

```json
{
  "id": "memory_system",
  "name": "Crystal Memory",
  "icon": "💎",
  "description": "Persistent Knowledge & Context Management",
  "color": "#9400d3",
  "order": 3,
  "enabled": true,
  "authority_level": 11.0,
  "routes": {
    "main": "/tab/memory-system",
    "api": "/api/memory-system"
  },
  "capabilities": [
    "Long-term memory persistence",
    "Context retrieval",
    "Knowledge graph management",
    "Semantic search",
    "Cross-session continuity"
  ],
  "stats": {
    "total_memories": 0,
    "active_contexts": 0,
    "knowledge_nodes": 0,
    "storage_used": "0 GB"
  }
}
```

### 7.3: MLS Server Tab

```json
{
  "id": "mls_server",
  "name": "MLS Server",
  "icon": "📡",
  "description": "Model Context Protocol Server",
  "color": "#ffa500",
  "order": 4,
  "enabled": true,
  "authority_level": 11.0,
  "routes": {
    "main": "/tab/mls-server",
    "api": "/api/mls-server"
  },
  "capabilities": [
    "MCP protocol handling",
    "Resource management",
    "Tool exposure",
    "Prompt templates",
    "Server health monitoring"
  ],
  "stats": {
    "active_connections": 0,
    "resources_exposed": 0,
    "tools_available": 0,
    "requests_served": 0
  }
}
```

### 7.4: Omniscience Tab

```json
{
  "id": "omniscience",
  "name": "Omniscience",
  "icon": "👁️",
  "description": "Complete Sensory & Monitoring System",
  "color": "#ffff00",
  "order": 5,
  "enabled": true,
  "authority_level": 11.0,
  "routes": {
    "main": "/tab/omniscience",
    "api": "/api/omniscience"
  },
  "capabilities": [
    "Multi-modal input processing",
    "Vision system integration",
    "Audio monitoring",
    "Screen capture analysis",
    "Environmental awareness"
  ],
  "stats": {
    "active_sensors": 0,
    "data_streams": 0,
    "events_detected": 0,
    "processing_rate": "0/s"
  }
}
```

### 7.5: Sovereign Control Tab

```json
{
  "id": "sovereign_control",
  "name": "Sovereign Control",
  "icon": "👑",
  "description": "Ultimate System Authority & Override",
  "color": "#ffd700",
  "order": 6,
  "enabled": true,
  "authority_level": 11.0,
  "routes": {
    "main": "/tab/sovereign-control",
    "api": "/api/sovereign-control"
  },
  "capabilities": [
    "Authority level management",
    "System-wide overrides",
    "Emergency protocols",
    "Master kill switch",
    "Full system coordination"
  ],
  "stats": {
    "authority_level": 11.0,
    "active_systems": 6,
    "override_status": "STANDBY",
    "uptime": "0h"
  }
}
```

---

## 🧪 TESTING & VALIDATION

### Test Each Tab Standalone

```bash
cd tabs/prometheus-prime
python backend.py
# Access at http://localhost:5000/tab/prometheus-prime
```

### Test Master GUI Integration

```bash
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui
python echo_prime_master_gui.py
# Access at http://localhost:5500
```

### Validation Checklist

- [ ] All 6 tabs discovered by master GUI
- [ ] Each tab loads in correct order
- [ ] Tab routes don't conflict
- [ ] WebSocket connections work
- [ ] API endpoints respond correctly
- [ ] Stats update in real-time
- [ ] Styling matches color scheme
- [ ] Logs display activity
- [ ] Full GUI links work

---

## 📦 DEPLOYMENT

### Requirements

Create `requirements.txt`:

```
Flask==3.0.0
Flask-SocketIO==5.3.5
python-socketio==5.10.0
python-engineio==4.8.0
```

### Install Dependencies

```bash
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui
pip install -r requirements.txt
```

### Launch Master GUI

```bash
python echo_prime_master_gui.py
```

### Access

Open browser to `http://localhost:5500`

---

## 🎯 SUMMARY

This modular tab architecture provides:

1. ✅ **Zero-Config Tab Addition**: Drop folder in `tabs/`, auto-discovered
2. ✅ **Complete Isolation**: Each tab is self-contained
3. ✅ **Consistent Interface**: All tabs follow same structure
4. ✅ **Easy Testing**: Test standalone or integrated
5. ✅ **Scalable**: Add unlimited tabs without modifying master
6. ✅ **Professional**: Clean architecture, modern design
7. ✅ **Real-Time**: WebSocket updates across all systems

**Total Implementation:**
- 1 Master GUI (echo_prime_master_gui.py)
- 6 Tab Modules (6 × 3 files = 18 files)
- Configuration files (tab_config.json × 6)
- README documentation
- Templates and styles

**Authority Level:** 11.0
**Status:** COMPLETE INTEGRATION ARCHITECTURE
**Next Step:** Implement remaining 5 tab modules using Prometheus Prime as template

---

**END OF DOCUMENT**
