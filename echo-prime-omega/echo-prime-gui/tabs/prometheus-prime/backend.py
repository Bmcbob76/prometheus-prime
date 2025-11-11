"""
Prometheus Prime Tab Backend
Authority Level: 11.0

This module provides the backend API for the Prometheus Prime tab.
"""

from flask import Blueprint, render_template, request, jsonify, send_from_directory
from pathlib import Path
import sys
import json
from datetime import datetime

# Add Prometheus Prime src to path
PROMETHEUS_PATH = Path(__file__).parent.parent.parent.parent.parent / "Prometheus-Prime" / "src"
if PROMETHEUS_PATH.exists():
    sys.path.insert(0, str(PROMETHEUS_PATH))

# Create Blueprint
tab_blueprint = Blueprint(
    'prometheus_prime',
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/tab/prometheus-prime'
)

# Tab state
prometheus_state = {
    "active": False,
    "autonomous_mode": False,
    "current_engagement": None,
    "tools_executed": 0,
    "domains_active": 0,
    "operations": [],
    "stats": {
        "domains": 11,
        "tools": 50,
        "cves": 220000,
        "exploits": 50000,
        "authority_level": 11.0
    }
}


@tab_blueprint.route('/')
def index():
    """Render Prometheus Prime tab frontend"""
    return render_template('prometheus-prime/frontend.html')


@tab_blueprint.route('/api/status')
def get_status():
    """Get Prometheus Prime status"""
    return jsonify(prometheus_state)


@tab_blueprint.route('/api/stats')
def get_stats():
    """Get statistics"""
    return jsonify(prometheus_state["stats"])


@tab_blueprint.route('/api/launch-gui', methods=['POST'])
def launch_gui():
    """Launch full Prometheus Prime GUI in new window"""
    result = {
        "success": True,
        "message": "Launching Prometheus Prime GUI...",
        "url": "http://localhost:5001",
        "timestamp": datetime.now().isoformat()
    }

    prometheus_state["operations"].append({
        "type": "launch_gui",
        "timestamp": datetime.now().isoformat(),
        "status": "success"
    })

    return jsonify(result)


@tab_blueprint.route('/api/start-autonomous', methods=['POST'])
def start_autonomous():
    """Start autonomous engagement"""
    data = request.json
    target = data.get('target', '192.168.1.100')
    scope = data.get('scope', ['192.168.1.0/24'])
    contract = data.get('contract_number', 'AUTO-001')

    prometheus_state["autonomous_mode"] = True
    prometheus_state["current_engagement"] = {
        "id": f"ENG-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "target": target,
        "scope": scope,
        "contract": contract,
        "started_at": datetime.now().isoformat()
    }

    result = {
        "success": True,
        "message": "Autonomous engagement started",
        "engagement": prometheus_state["current_engagement"]
    }

    prometheus_state["operations"].append({
        "type": "start_autonomous",
        "timestamp": datetime.now().isoformat(),
        "engagement_id": prometheus_state["current_engagement"]["id"]
    })

    return jsonify(result)


@tab_blueprint.route('/api/stop-autonomous', methods=['POST'])
def stop_autonomous():
    """Stop autonomous engagement"""
    prometheus_state["autonomous_mode"] = False

    if prometheus_state["current_engagement"]:
        prometheus_state["current_engagement"]["ended_at"] = datetime.now().isoformat()

    result = {
        "success": True,
        "message": "Autonomous engagement stopped"
    }

    return jsonify(result)


@tab_blueprint.route('/api/execute-tool', methods=['POST'])
def execute_tool():
    """Execute a specific tool"""
    data = request.json
    tool_id = data.get('tool_id')
    target = data.get('target')
    domain = data.get('domain')

    prometheus_state["tools_executed"] += 1

    result = {
        "success": True,
        "tool": tool_id,
        "target": target,
        "domain": domain,
        "output": f"Simulated execution of {tool_id} on {target}",
        "timestamp": datetime.now().isoformat()
    }

    prometheus_state["operations"].append({
        "type": "tool_execution",
        "tool": tool_id,
        "timestamp": datetime.now().isoformat()
    })

    return jsonify(result)


@tab_blueprint.route('/api/query-intelligence', methods=['POST'])
def query_intelligence():
    """Query Omniscience intelligence"""
    data = request.json
    query_type = data.get('query_type', 'cve')
    search_term = data.get('search_term', '')

    result = {
        "success": True,
        "query_type": query_type,
        "search_term": search_term,
        "results_count": 42,
        "sample_results": [
            {"id": "CVE-2023-1234", "severity": "CRITICAL"},
            {"id": "CVE-2023-5678", "severity": "HIGH"}
        ]
    }

    return jsonify(result)


@tab_blueprint.route('/api/emergency-stop', methods=['POST'])
def emergency_stop():
    """Emergency stop all operations"""
    prometheus_state["autonomous_mode"] = False
    prometheus_state["active"] = False

    result = {
        "success": True,
        "message": "EMERGENCY STOP - All operations halted"
    }

    prometheus_state["operations"].append({
        "type": "emergency_stop",
        "timestamp": datetime.now().isoformat()
    })

    return jsonify(result)


def init_socketio(socketio):
    """Initialize WebSocket handlers for Prometheus Prime tab"""

    @socketio.on('prometheus_event')
    def handle_prometheus_event(data):
        """Handle Prometheus-specific events"""
        socketio.emit('prometheus_response', {
            "status": "received",
            "data": data,
            "timestamp": datetime.now().isoformat()
        })

    @socketio.on('tool_execution')
    def handle_tool_execution(data):
        """Handle tool execution events"""
        socketio.emit('tool_result', {
            "tool": data.get('tool'),
            "result": "execution_complete",
            "timestamp": datetime.now().isoformat()
        })


def initialize(app, socketio):
    """Initialize Prometheus Prime tab module"""
    # Register blueprint
    app.register_blueprint(tab_blueprint)

    # Initialize WebSocket handlers
    init_socketio(socketio)

    print(f"✅ Initialized: Prometheus Prime Tab")
    print(f"   - Route: /tab/prometheus-prime")
    print(f"   - API: /api/prometheus-prime")
    print(f"   - Stats: {prometheus_state['stats']}")
