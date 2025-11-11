# 🔥 CLAUDE CODE INTEGRATION INSTRUCTIONS
## Echo Prime Omega - Modular Tabbed GUI System

**Authority Level: 11.0**
**Commander: Bobby Don McWilliams II**

---

## 🎯 MISSION OBJECTIVE

Integrate ALL Echo Prime Omega systems as modular, auto-loading tabbed GUIs in the master control interface. Each system gets its own folder in the `tabs/` directory, and the master GUI automatically discovers and loads all available tabs.

---

## 🏗️ ARCHITECTURE OVERVIEW

```
echo-prime-omega/
└── echo-prime-gui/
    ├── echo_prime_master_gui.py          # Master backend (auto-loads tabs)
    ├── templates/
    │   └── echo_prime_master.html        # Master frontend (dynamic tabs)
    ├── tabs/                              # ← TAB MODULES DIRECTORY
    │   ├── prometheus-prime/              # Tab 1: Prometheus Prime
    │   │   ├── tab_config.json            # Tab configuration
    │   │   ├── backend.py                 # Tab backend logic
    │   │   ├── frontend.html              # Tab frontend GUI
    │   │   └── static/                    # Tab-specific assets
    │   ├── omega-swarm-brain/             # Tab 2: Omega Swarm
    │   │   ├── tab_config.json
    │   │   ├── backend.py
    │   │   ├── frontend.html
    │   │   └── static/
    │   ├── memory-system/                 # Tab 3: Memory System
    │   │   ├── tab_config.json
    │   │   ├── backend.py
    │   │   ├── frontend.html
    │   │   └── static/
    │   ├── mls-server/                    # Tab 4: MLS Server
    │   │   ├── tab_config.json
    │   │   ├── backend.py
    │   │   ├── frontend.html
    │   │   └── static/
    │   ├── omniscience/                   # Tab 5: Omniscience
    │   │   ├── tab_config.json
    │   │   ├── backend.py
    │   │   ├── frontend.html
    │   │   └── static/
    │   └── sovereign-control/             # Tab 6: Sovereign Control
    │       ├── tab_config.json
    │       ├── backend.py
    │       ├── frontend.html
    │       └── static/
    ├── static/
    │   ├── css/
    │   └── js/
    └── README.md
```

---

## 📋 IMPLEMENTATION STEPS

### PHASE 1: Create Tabs Directory Structure

#### Step 1.1: Create Base Directory
```bash
cd /home/user/prometheus-prime/echo-prime-omega/echo-prime-gui
mkdir -p tabs
```

#### Step 1.2: Create All Tab Folders
```bash
# Create folder for each system
mkdir -p tabs/prometheus-prime/{static,templates}
mkdir -p tabs/omega-swarm-brain/{static,templates}
mkdir -p tabs/memory-system/{static,templates}
mkdir -p tabs/mls-server/{static,templates}
mkdir -p tabs/omniscience/{static,templates}
mkdir -p tabs/sovereign-control/{static,templates}
```

---

### PHASE 2: Define Tab Configuration Standard

Each tab folder MUST contain a `tab_config.json` file with this structure:

#### File: `tabs/{tab-name}/tab_config.json`
```json
{
  "id": "prometheus_prime",
  "name": "Prometheus Prime",
  "icon": "⚔️",
  "description": "Autonomous Penetration Testing System",
  "color": "#ff0000",
  "order": 1,
  "enabled": true,
  "routes": {
    "main": "/tab/prometheus-prime",
    "api": "/api/prometheus-prime"
  },
  "capabilities": [
    "Full 6-phase autonomous engagement",
    "11 security domains with 50+ tools",
    "AI decision engine (5-model consensus)",
    "Phoenix auto-healing",
    "Omniscience intelligence"
  ],
  "requires": [
    "flask",
    "flask-socketio"
  ],
  "author": "Bobby Don McWilliams II",
  "version": "1.0.0",
  "authority_level": 11.0
}
```

---

### PHASE 3: Create Tab Backend Module

Each tab folder MUST contain a `backend.py` file that provides:
1. Flask Blueprint for routes
2. API endpoints
3. WebSocket handlers
4. Business logic

#### Template: `tabs/{tab-name}/backend.py`
```python
"""
{Tab Name} Backend Module
Authority Level: 11.0
"""

from flask import Blueprint, render_template, request, jsonify
from flask_socketio import emit
import json

# Create Blueprint
tab_blueprint = Blueprint(
    'prometheus_prime',  # Blueprint name
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/tab/prometheus-prime'
)

# Tab state
tab_state = {
    "active": False,
    "operations": [],
    "stats": {}
}


@tab_blueprint.route('/')
def index():
    """Render tab frontend"""
    return render_template('frontend.html')


@tab_blueprint.route('/api/status')
def get_status():
    """Get tab status"""
    return jsonify(tab_state)


@tab_blueprint.route('/api/execute', methods=['POST'])
def execute_operation():
    """Execute tab operation"""
    data = request.json

    # Process operation
    result = {
        "success": True,
        "message": "Operation executed",
        "data": data
    }

    # Update state
    tab_state["operations"].append(result)

    return jsonify(result)


def init_socketio(socketio):
    """Initialize WebSocket handlers for this tab"""

    @socketio.on('tab_event')
    def handle_tab_event(data):
        emit('tab_response', {"status": "received", "data": data})


def initialize(app, socketio):
    """Initialize tab module"""
    # Register blueprint
    app.register_blueprint(tab_blueprint)

    # Initialize WebSocket handlers
    init_socketio(socketio)

    print(f"✅ Initialized: Prometheus Prime Tab")
```

---

### PHASE 4: Create Tab Frontend

Each tab folder MUST contain a `frontend.html` file with the tab's GUI.

#### Template: `tabs/{tab-name}/frontend.html`
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prometheus Prime - Echo Prime Omega</title>
    <style>
        /* Tab-specific styles */
        .tab-container {
            padding: 30px;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }

        .tab-header {
            border-bottom: 3px solid #ff0000;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        .tab-header h2 {
            color: #ff0000;
            font-size: 2.5em;
        }

        .control-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .control-card {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 20px;
        }

        .control-btn {
            padding: 15px 30px;
            background: #00ff00;
            color: #000;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            font-size: 1em;
            margin-top: 15px;
        }

        .control-btn:hover {
            background: #ff0000;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="tab-container">
        <div class="tab-header">
            <h2>⚔️ PROMETHEUS PRIME</h2>
            <p>Autonomous Penetration Testing System</p>
        </div>

        <div class="control-grid">
            <div class="control-card">
                <h3>Quick Actions</h3>
                <button class="control-btn" onclick="executeAction('launch_gui')">
                    Launch Full GUI
                </button>
                <button class="control-btn" onclick="executeAction('start_autonomous')">
                    Start Autonomous
                </button>
            </div>

            <div class="control-card">
                <h3>Statistics</h3>
                <div id="stats-display">
                    Loading...
                </div>
            </div>
        </div>

        <div id="output-log" style="margin-top: 30px; padding: 20px; background: rgba(0,0,0,0.9); border: 2px solid #00ff00; border-radius: 10px;">
            <h3>Execution Log</h3>
            <div id="log-entries"></div>
        </div>
    </div>

    <script>
        async function executeAction(action) {
            const response = await fetch('/tab/prometheus-prime/api/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action: action})
            });

            const result = await response.json();
            logMessage(`Executed: ${action}`);
        }

        async function loadStats() {
            const response = await fetch('/tab/prometheus-prime/api/status');
            const status = await response.json();
            document.getElementById('stats-display').innerHTML = JSON.stringify(status, null, 2);
        }

        function logMessage(msg) {
            const logDiv = document.getElementById('log-entries');
            const entry = document.createElement('div');
            entry.innerHTML = `[${new Date().toLocaleTimeString()}] ${msg}`;
            logDiv.appendChild(entry);
        }

        // Load stats on page load
        window.onload = loadStats;
    </script>
</body>
</html>
```

---

### PHASE 5: Implement Auto-Discovery in Master GUI

#### Step 5.1: Update Master Backend

Modify `echo_prime_master_gui.py` to auto-discover and load all tabs:

```python
"""
Echo Prime Omega - Master GUI with Auto-Loading Tabs
"""

import os
import json
import importlib.util
from pathlib import Path
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'echo-prime-omega-authority-level-11'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Auto-discover and load tabs
TABS_DIR = Path(__file__).parent / 'tabs'
loaded_tabs = {}


def discover_tabs():
    """Auto-discover all tab modules in tabs/ directory"""
    tabs = {}

    if not TABS_DIR.exists():
        print("⚠️  No tabs directory found")
        return tabs

    for tab_folder in TABS_DIR.iterdir():
        if not tab_folder.is_dir():
            continue

        config_file = tab_folder / 'tab_config.json'
        backend_file = tab_folder / 'backend.py'

        if not config_file.exists():
            print(f"⚠️  Skipping {tab_folder.name}: No tab_config.json")
            continue

        # Load configuration
        with open(config_file, 'r') as f:
            config = json.load(f)

        if not config.get('enabled', True):
            print(f"⏭️  Skipping {tab_folder.name}: Disabled in config")
            continue

        # Load backend module if exists
        backend_module = None
        if backend_file.exists():
            spec = importlib.util.spec_from_file_location(
                f"tabs.{tab_folder.name}.backend",
                backend_file
            )
            backend_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(backend_module)

            # Initialize tab
            if hasattr(backend_module, 'initialize'):
                backend_module.initialize(app, socketio)

        tabs[config['id']] = {
            'config': config,
            'backend': backend_module,
            'path': tab_folder
        }

        print(f"✅ Loaded tab: {config['name']} ({config['icon']})")

    return tabs


# Discover all tabs
loaded_tabs = discover_tabs()


@app.route('/')
def index():
    """Serve master GUI"""
    return render_template('echo_prime_master.html')


@app.route('/api/tabs')
def get_tabs():
    """Get all loaded tabs"""
    tabs_info = {
        tab_id: {
            'config': tab_data['config'],
            'path': str(tab_data['path'])
        }
        for tab_id, tab_data in loaded_tabs.items()
    }
    return jsonify(tabs_info)


@app.route('/api/tabs/<tab_id>')
def get_tab(tab_id):
    """Get specific tab info"""
    if tab_id in loaded_tabs:
        return jsonify(loaded_tabs[tab_id]['config'])
    return jsonify({"error": "Tab not found"}), 404


def run_master_gui(host='0.0.0.0', port=5000):
    """Run the master GUI server"""
    print("=" * 60)
    print("🔥 ECHO PRIME OMEGA - Master Control")
    print("   Authority Level: 11.0")
    print(f"   Server: http://{host}:{port}")
    print("=" * 60)
    print(f"\n   Loaded {len(loaded_tabs)} tabs:")

    for tab_id, tab_data in sorted(
        loaded_tabs.items(),
        key=lambda x: x[1]['config'].get('order', 999)
    ):
        config = tab_data['config']
        print(f"   {config['icon']} {config['name']}")

    print("\n" + "=" * 60)
    print("   Press Ctrl+C to stop\n")

    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    run_master_gui()
```

---

#### Step 5.2: Update Master Frontend

Modify `templates/echo_prime_master.html` to dynamically load tabs:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>🔥 ECHO PRIME OMEGA - Master Control</title>
    <!-- ... existing styles ... -->
</head>
<body>
    <div class="master-header">
        <h1>🔥 ECHO PRIME OMEGA</h1>
        <div class="subtitle">Ultimate Security Intelligence Platform | Authority Level: 11.0</div>
    </div>

    <div class="main-container">
        <!-- Sidebar will be dynamically populated -->
        <div class="system-tabs" id="tabs-sidebar">
            <!-- Tabs loaded dynamically -->
        </div>

        <!-- Content area will be dynamically populated -->
        <div class="content-area" id="tabs-content">
            <!-- Tab content loaded dynamically -->
        </div>
    </div>

    <script>
        let allTabs = {};

        // Auto-load all tabs
        async function loadAllTabs() {
            const response = await fetch('/api/tabs');
            allTabs = await response.json();

            // Sort by order
            const sortedTabs = Object.entries(allTabs).sort(
                (a, b) => (a[1].config.order || 999) - (b[1].config.order || 999)
            );

            // Generate sidebar tabs
            const sidebar = document.getElementById('tabs-sidebar');
            sidebar.innerHTML = '';

            sortedTabs.forEach(([tabId, tabData], index) => {
                const config = tabData.config;

                // Create tab button
                const tabDiv = document.createElement('div');
                tabDiv.className = 'system-tab' + (index === 0 ? ' active' : '');
                tabDiv.dataset.tabId = tabId;
                tabDiv.style.borderColor = config.color;
                tabDiv.innerHTML = `
                    <div class="icon">${config.icon}</div>
                    <div class="name">${config.name}</div>
                    <div class="status operational">OPERATIONAL</div>
                `;
                tabDiv.onclick = () => switchTab(tabId);
                sidebar.appendChild(tabDiv);

                // Create content iframe
                const contentDiv = document.createElement('div');
                contentDiv.className = 'system-panel' + (index === 0 ? ' active' : '');
                contentDiv.id = `panel-${tabId}`;
                contentDiv.innerHTML = `
                    <iframe src="${config.routes.main}"
                            style="width:100%; height:calc(100vh - 200px); border:none;">
                    </iframe>
                `;
                document.getElementById('tabs-content').appendChild(contentDiv);
            });

            console.log(`✅ Loaded ${sortedTabs.length} tabs`);
        }

        function switchTab(tabId) {
            // Hide all panels
            document.querySelectorAll('.system-panel').forEach(panel => {
                panel.classList.remove('active');
            });

            // Show selected panel
            document.getElementById(`panel-${tabId}`).classList.add('active');

            // Update sidebar
            document.querySelectorAll('.system-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelector(`[data-tab-id="${tabId}"]`).classList.add('active');
        }

        // Load tabs on page load
        window.onload = loadAllTabs;
    </script>
</body>
</html>
```

---

### PHASE 6: Create Tab Modules for All Systems

#### Tab 1: Prometheus Prime (`tabs/prometheus-prime/`)

**tab_config.json:**
```json
{
  "id": "prometheus_prime",
  "name": "Prometheus Prime",
  "icon": "⚔️",
  "description": "Autonomous Penetration Testing System",
  "color": "#ff0000",
  "order": 1,
  "enabled": true,
  "routes": {
    "main": "/tab/prometheus-prime",
    "api": "/api/prometheus-prime"
  },
  "capabilities": [
    "Full 6-phase autonomous engagement",
    "11 security domains with 50+ tools",
    "AI decision engine (5-model consensus)",
    "Phoenix auto-healing",
    "Omniscience intelligence (220K CVEs)"
  ]
}
```

**backend.py:**
```python
from flask import Blueprint, render_template, request, jsonify
import sys
from pathlib import Path

# Add Prometheus Prime src to path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "Prometheus-Prime" / "src"))

tab_blueprint = Blueprint('prometheus_prime', __name__, url_prefix='/tab/prometheus-prime')

@tab_blueprint.route('/')
def index():
    return render_template('prometheus-prime/frontend.html')

@tab_blueprint.route('/api/launch-gui', methods=['POST'])
def launch_gui():
    # Launch full Prometheus GUI in new window
    return jsonify({"success": True, "url": "http://localhost:5001"})

@tab_blueprint.route('/api/start-autonomous', methods=['POST'])
def start_autonomous():
    # Start autonomous engagement
    return jsonify({"success": True, "engagement_id": "ENG-001"})

def initialize(app, socketio):
    app.register_blueprint(tab_blueprint)
    print("✅ Initialized: Prometheus Prime Tab")
```

---

#### Tab 2: Omega Swarm Brain (`tabs/omega-swarm-brain/`)

**tab_config.json:**
```json
{
  "id": "omega_swarm",
  "name": "Omega Swarm Brain",
  "icon": "🐝",
  "description": "Multi-Agent Swarm Intelligence Coordinator",
  "color": "#00ff00",
  "order": 2,
  "enabled": true,
  "routes": {
    "main": "/tab/omega-swarm",
    "api": "/api/omega-swarm"
  },
  "capabilities": [
    "Multi-agent parallel execution",
    "6 specialized agent roles",
    "Dynamic task allocation",
    "Swarm intelligence optimization",
    "Collective decision making"
  ]
}
```

**backend.py:**
```python
from flask import Blueprint, render_template, request, jsonify

tab_blueprint = Blueprint('omega_swarm', __name__, url_prefix='/tab/omega-swarm')

swarm_state = {"agents": []}

@tab_blueprint.route('/')
def index():
    return render_template('omega-swarm-brain/frontend.html')

@tab_blueprint.route('/api/spawn-agents', methods=['POST'])
def spawn_agents():
    data = request.json
    count = data.get('count', 4)

    agents = []
    for i in range(count):
        agents.append({
            "id": f"agent_{i}",
            "role": ["recon", "exploit", "intel", "healing"][i % 4],
            "status": "active"
        })

    swarm_state["agents"] = agents
    return jsonify({"success": True, "agents": agents})

def initialize(app, socketio):
    app.register_blueprint(tab_blueprint)
    print("✅ Initialized: Omega Swarm Brain Tab")
```

---

#### Tab 3: Memory System (`tabs/memory-system/`)

**tab_config.json:**
```json
{
  "id": "memory_system",
  "name": "Memory System",
  "icon": "💾",
  "description": "Persistent Knowledge & Intelligence Storage",
  "color": "#00aaff",
  "order": 3,
  "enabled": true,
  "routes": {
    "main": "/tab/memory-system",
    "api": "/api/memory-system"
  }
}
```

---

#### Tab 4: MLS Server (`tabs/mls-server/`)

**tab_config.json:**
```json
{
  "id": "mls_server",
  "name": "MLS Server",
  "icon": "🔐",
  "description": "Multi-Level Security Authorization",
  "color": "#ffaa00",
  "order": 4,
  "enabled": true,
  "routes": {
    "main": "/tab/mls-server",
    "api": "/api/mls-server"
  }
}
```

---

#### Tab 5: Omniscience (`tabs/omniscience/`)

**tab_config.json:**
```json
{
  "id": "omniscience",
  "name": "Omniscience Intelligence",
  "icon": "🧠",
  "description": "Complete Security Intelligence Database",
  "color": "#aa00ff",
  "order": 5,
  "enabled": true,
  "routes": {
    "main": "/tab/omniscience",
    "api": "/api/omniscience"
  }
}
```

---

#### Tab 6: Sovereign Control (`tabs/sovereign-control/`)

**tab_config.json:**
```json
{
  "id": "sovereign_control",
  "name": "Sovereign Control",
  "icon": "👑",
  "description": "Authority Level 11.0 Override System",
  "color": "#ff00ff",
  "order": 6,
  "enabled": true,
  "routes": {
    "main": "/tab/sovereign-control",
    "api": "/api/sovereign-control"
  }
}
```

---

### PHASE 7: Testing

#### Step 7.1: Test Auto-Discovery
```bash
cd echo-prime-omega/echo-prime-gui
python3 echo_prime_master_gui.py

# Should output:
# ✅ Loaded tab: Prometheus Prime (⚔️)
# ✅ Loaded tab: Omega Swarm Brain (🐝)
# ✅ Loaded tab: Memory System (💾)
# ✅ Loaded tab: MLS Server (🔐)
# ✅ Loaded tab: Omniscience Intelligence (🧠)
# ✅ Loaded tab: Sovereign Control (👑)
```

#### Step 7.2: Test Tab Loading
```bash
# Open browser
http://localhost:5000

# Should see:
# - All 6 tabs in left sidebar
# - Click each tab to load its content
# - Each tab loads in iframe
```

---

## 📊 SUCCESS CRITERIA

✅ **Auto-Discovery Working**
- Master GUI scans `tabs/` directory
- Loads all tab configs automatically
- Initializes all backends
- No manual registration needed

✅ **Modular Architecture**
- Each tab in separate folder
- Self-contained with config, backend, frontend
- Can be enabled/disabled via config
- Order controlled via config

✅ **Dynamic Loading**
- Sidebar generated from discovered tabs
- Content iframes created dynamically
- Tab switching works smoothly
- All routes registered automatically

✅ **Complete Integration**
- All 6 systems integrated
- Each system has full GUI
- APIs work independently
- WebSocket events handled

---

## 🎯 ADDING NEW TABS

To add a new tab, simply:

### Step 1: Create Folder
```bash
mkdir -p tabs/new-system/{static,templates}
```

### Step 2: Create Config
```json
// tabs/new-system/tab_config.json
{
  "id": "new_system",
  "name": "New System",
  "icon": "🔥",
  "description": "New system description",
  "color": "#00ff00",
  "order": 7,
  "enabled": true,
  "routes": {
    "main": "/tab/new-system",
    "api": "/api/new-system"
  }
}
```

### Step 3: Create Backend
```python
# tabs/new-system/backend.py
from flask import Blueprint, render_template

tab_blueprint = Blueprint('new_system', __name__, url_prefix='/tab/new-system')

@tab_blueprint.route('/')
def index():
    return render_template('new-system/frontend.html')

def initialize(app, socketio):
    app.register_blueprint(tab_blueprint)
    print("✅ Initialized: New System Tab")
```

### Step 4: Create Frontend
```html
<!-- tabs/new-system/frontend.html -->
<!DOCTYPE html>
<html>
<head><title>New System</title></head>
<body>
    <h1>🔥 New System</h1>
    <p>System content here</p>
</body>
</html>
```

### Step 5: Restart Master GUI
```bash
# Tab automatically discovered and loaded!
python3 echo_prime_master_gui.py
```

---

## 🔧 TROUBLESHOOTING

### Tab Not Loading

**Check:**
1. `tab_config.json` exists and is valid JSON
2. `enabled` is set to `true`
3. `backend.py` has no syntax errors
4. `initialize()` function exists in backend
5. Folder name matches config `id`

### Routes Conflicting

**Solution:**
- Each tab must have unique `url_prefix`
- Use tab ID in prefix: `/tab/{tab-id}`
- Check no duplicate route definitions

### Template Not Found

**Solution:**
- Templates must be in `templates/{tab-folder-name}/`
- Use `render_template('{tab-folder}/frontend.html')`
- Check file paths are correct

---

## 📈 STATISTICS

| Metric | Value |
|--------|-------|
| **Total Tabs** | 6 (extensible) |
| **Auto-Discovery** | ✅ Yes |
| **Modular** | ✅ Yes |
| **Hot-Reload** | ✅ Yes (restart server) |
| **Config-Driven** | ✅ Yes |
| **Order Control** | ✅ Yes (via config) |
| **Enable/Disable** | ✅ Yes (via config) |

---

## ✅ DELIVERABLES FOR CLAUDE CODE

When implementation is complete, you should have:

1. ✅ **tabs/** directory with 6 system folders
2. ✅ **tab_config.json** in each folder
3. ✅ **backend.py** in each folder
4. ✅ **frontend.html** in each folder
5. ✅ **Auto-discovery** working in master GUI
6. ✅ **Dynamic loading** of all tabs
7. ✅ **All systems** integrated and functional

---

**Authority Level: 11.0**
**Status: IMPLEMENTATION READY**
**Classification: INTEGRATION BLUEPRINT**

---

*This document provides complete instructions for Claude Code to implement the modular, auto-loading tabbed GUI architecture for Echo Prime Omega.*
