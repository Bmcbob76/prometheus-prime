"""
ECHO PRIME OMEGA - MASTER GUI
Auto-Discovery Tab Architecture
Authority Level: 11.0

This Master GUI automatically discovers and loads all tab modules
from the tabs/ directory without requiring manual registration.

Each tab is a self-contained module with:
- tab_config.json (configuration)
- backend.py (Flask Blueprint)
- templates/[tab-name]/frontend.html (GUI)
"""

from flask import Flask, render_template, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
import json
from pathlib import Path
import importlib.util
import sys
from datetime import datetime

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'echo-prime-omega-master-key-authority-11.0'
app.config['JSON_SORT_KEYS'] = False

# SocketIO setup
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Tabs directory
TABS_DIR = Path(__file__).parent / 'tabs'

# Discovered tabs storage
discovered_tabs = {}

# System state
system_state = {
    "master_status": "INITIALIZING",
    "tabs_loaded": 0,
    "startup_time": datetime.now().isoformat(),
    "authority_level": 11.0
}

def discover_tabs():
    """
    Auto-discover all tab modules in tabs/ directory

    Scans the tabs/ directory for valid tab modules and loads them dynamically.
    Each tab must have:
    - tab_config.json (configuration file)
    - backend.py (Flask Blueprint with initialize() function)

    Returns:
        dict: Dictionary of discovered tabs {tab_id: tab_data}
    """
    tabs = {}

    if not TABS_DIR.exists():
        print("⚠️  Tabs directory not found, creating...")
        TABS_DIR.mkdir(parents=True, exist_ok=True)
        return tabs

    print("\n" + "="*70)
    print("🔍 AUTO-DISCOVERY: Scanning tabs/ directory...")
    print("="*70)

    # Scan all subdirectories in tabs/
    tab_folders = sorted([f for f in TABS_DIR.iterdir() if f.is_dir() and not f.name.startswith('_')])

    if not tab_folders:
        print("⚠️  No tab folders found in tabs/ directory")
        return tabs

    for tab_folder in tab_folders:
        config_file = tab_folder / 'tab_config.json'
        backend_file = tab_folder / 'backend.py'

        print(f"\n📁 Checking: {tab_folder.name}/")

        # Validate required files
        if not config_file.exists():
            print(f"   ⚠️  SKIP: No tab_config.json found")
            continue

        if not backend_file.exists():
            print(f"   ⚠️  SKIP: No backend.py found")
            continue

        try:
            # Load and validate configuration
            print(f"   📄 Loading tab_config.json...")
            with open(config_file, 'r') as f:
                config = json.load(f)

            # Validate required configuration fields
            required_fields = ['id', 'name', 'icon', 'order', 'enabled']
            missing_fields = [field for field in required_fields if field not in config]

            if missing_fields:
                print(f"   ❌ INVALID CONFIG: Missing fields: {', '.join(missing_fields)}")
                continue

            # Check if tab is enabled
            if not config['enabled']:
                print(f"   ⏸️  DISABLED: Skipping (enabled=false in config)")
                continue

            print(f"   ✅ Config valid: {config['name']} (Order: {config['order']})")

            # Load backend module dynamically
            print(f"   📦 Loading backend.py...")
            module_name = f"tabs.{tab_folder.name}.backend"

            spec = importlib.util.spec_from_file_location(module_name, backend_file)
            if spec is None:
                print(f"   ❌ ERROR: Could not create module spec")
                continue

            backend_module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = backend_module  # Add to sys.modules
            spec.loader.exec_module(backend_module)

            # Verify initialize function exists
            if not hasattr(backend_module, 'initialize'):
                print(f"   ❌ ERROR: No initialize() function in backend.py")
                continue

            print(f"   ✅ Backend loaded successfully")

            # Initialize the tab (register Blueprint, WebSocket handlers)
            print(f"   🔧 Initializing tab...")
            tab_info = backend_module.initialize(app, socketio)

            # Store tab data
            tabs[config['id']] = {
                'config': config,
                'module': backend_module,
                'info': tab_info,
                'folder': tab_folder.name
            }

            print(f"   ✅ LOADED: {config['name']}")
            print(f"      Icon: {config['icon']}, Order: {config['order']}")
            print(f"      Routes: {config.get('routes', {}).get('main', 'N/A')}")

        except json.JSONDecodeError as e:
            print(f"   ❌ JSON ERROR: Invalid tab_config.json - {e}")
        except Exception as e:
            print(f"   ❌ LOAD ERROR: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()

    # Sort tabs by order
    tabs = dict(sorted(tabs.items(), key=lambda x: x[1]['config']['order']))

    print("\n" + "="*70)
    if tabs:
        print(f"✅ AUTO-DISCOVERY COMPLETE: {len(tabs)} tab(s) loaded")
        for tab_id, tab_data in tabs.items():
            print(f"   {tab_data['config']['order']}. {tab_data['config']['icon']} {tab_data['config']['name']}")
    else:
        print("⚠️  AUTO-DISCOVERY COMPLETE: No tabs loaded")
    print("="*70 + "\n")

    return tabs


# ==================== MASTER GUI ROUTES ====================

@app.route('/')
def index():
    """Render master GUI with all discovered tabs"""
    return render_template('echo_prime_master.html', tabs=discovered_tabs, system_state=system_state)


@app.route('/api/tabs', methods=['GET'])
def get_tabs():
    """
    Get all discovered tabs information

    Returns:
        JSON with list of all tabs and their configurations
    """
    tabs_info = {}
    for tab_id, tab_data in discovered_tabs.items():
        tabs_info[tab_id] = {
            'id': tab_data['config']['id'],
            'name': tab_data['config']['name'],
            'icon': tab_data['config'].get('icon', '🔧'),
            'description': tab_data['config'].get('description', ''),
            'color': tab_data['config'].get('color', '#00ff00'),
            'order': tab_data['config']['order'],
            'routes': tab_data['config'].get('routes', {}),
            'enabled': tab_data['config'].get('enabled', True),
            'authority_level': tab_data['config'].get('authority_level', 11.0),
            'capabilities': tab_data['config'].get('capabilities', []),
            'stats': tab_data['config'].get('stats', {})
        }

    return jsonify({
        "success": True,
        "count": len(tabs_info),
        "tabs": tabs_info,
        "system_state": system_state
    })


@app.route('/api/system/status', methods=['GET'])
def get_system_status():
    """
    Get overall Echo Prime Omega system status

    Returns:
        JSON with master system status and loaded tabs
    """
    return jsonify({
        "success": True,
        "master_status": system_state["master_status"],
        "tabs_loaded": system_state["tabs_loaded"],
        "startup_time": system_state["startup_time"],
        "authority_level": system_state["authority_level"],
        "tabs": list(discovered_tabs.keys())
    })


@app.route('/api/system/stats', methods=['GET'])
def get_system_stats():
    """
    Get aggregated statistics from all tabs

    Returns:
        JSON with combined stats from all systems
    """
    all_stats = {}
    for tab_id, tab_data in discovered_tabs.items():
        all_stats[tab_id] = {
            'name': tab_data['config']['name'],
            'stats': tab_data['config'].get('stats', {})
        }

    return jsonify({
        "success": True,
        "system_stats": all_stats,
        "total_tabs": len(discovered_tabs)
    })


# ==================== WEBSOCKET HANDLERS ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection to Master GUI"""
    print("🔌 Client connected to Master GUI")
    emit('master_connected', {
        "message": "Connected to Echo Prime Omega Master GUI",
        "authority_level": system_state["authority_level"],
        "tabs_loaded": system_state["tabs_loaded"],
        "timestamp": datetime.now().isoformat()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print("🔌 Client disconnected from Master GUI")


@socketio.on('request_tabs')
def handle_request_tabs():
    """Send tabs list to client"""
    tabs_list = [
        {
            'id': tab_data['config']['id'],
            'name': tab_data['config']['name'],
            'icon': tab_data['config'].get('icon', '🔧'),
            'order': tab_data['config']['order'],
            'color': tab_data['config'].get('color', '#00ff00'),
            'routes': tab_data['config'].get('routes', {})
        }
        for tab_data in discovered_tabs.values()
    ]

    emit('tabs_list', {
        "success": True,
        "count": len(tabs_list),
        "tabs": tabs_list,
        "timestamp": datetime.now().isoformat()
    })


@socketio.on('master_ping')
def handle_ping():
    """Handle ping from client"""
    emit('master_pong', {
        "timestamp": datetime.now().isoformat(),
        "status": system_state["master_status"]
    })


# ==================== STARTUP & MAIN ====================

def initialize_master_gui():
    """Initialize the Master GUI and discover all tabs"""
    global discovered_tabs, system_state

    print("\n" + "="*70)
    print("🚀 ECHO PRIME OMEGA - MASTER GUI")
    print("   Auto-Discovery Tab Architecture")
    print("   Authority Level: 11.0")
    print("="*70)

    # Update system state
    system_state["master_status"] = "DISCOVERING_TABS"

    # Discover and load all tabs
    discovered_tabs = discover_tabs()
    system_state["tabs_loaded"] = len(discovered_tabs)

    # Update system state
    if discovered_tabs:
        system_state["master_status"] = "OPERATIONAL"
    else:
        system_state["master_status"] = "NO_TABS_LOADED"

    print("\n" + "="*70)
    print(f"🎯 MASTER GUI READY")
    print(f"   Status: {system_state['master_status']}")
    print(f"   Tabs Loaded: {system_state['tabs_loaded']}")
    print(f"   Authority Level: {system_state['authority_level']}")
    print(f"   Access at: http://localhost:5500")
    print("="*70 + "\n")


if __name__ == '__main__':
    # Initialize Master GUI and discover tabs
    initialize_master_gui()

    # Run the Flask-SocketIO application
    socketio.run(
        app,
        debug=True,
        host='0.0.0.0',
        port=5500,
        allow_unsafe_werkzeug=True  # For development only
    )
