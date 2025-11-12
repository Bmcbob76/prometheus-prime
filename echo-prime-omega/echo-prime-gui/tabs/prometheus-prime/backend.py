"""
PROMETHEUS PRIME Tab Backend
Auto-loaded by Echo Prime Master GUI
Authority Level: 11.0
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

# Prometheus Prime system state
prometheus_state = {
    "active": False,
    "autonomous_mode": False,
    "engagement_active": False,
    "target": None,
    "current_phase": None,
    "last_update": None,
    "stats": TAB_CONFIG.get('stats', {}),
    "status": "IDLE",
    "active_engagements": [],
    "recent_findings": [],
    "tool_activity": []
}

# Security domains (simplified for tab - full version in main Prometheus GUI)
SECURITY_DOMAINS = {
    "reconnaissance": {"name": "Reconnaissance", "icon": "🔍", "tools": 8},
    "vulnerability_assessment": {"name": "Vulnerability Assessment", "icon": "🎯", "tools": 6},
    "web_application": {"name": "Web Application", "icon": "🌐", "tools": 7},
    "network_attacks": {"name": "Network Attacks", "icon": "🔥", "tools": 5},
    "wireless": {"name": "Wireless", "icon": "📡", "tools": 4},
    "password_attacks": {"name": "Password Attacks", "icon": "🔐", "tools": 6},
    "exploitation": {"name": "Exploitation", "icon": "💥", "tools": 8},
    "post_exploitation": {"name": "Post-Exploitation", "icon": "👁️", "tools": 5},
    "privilege_escalation": {"name": "Privilege Escalation", "icon": "⬆️", "tools": 4},
    "social_engineering": {"name": "Social Engineering", "icon": "🎭", "tools": 3},
    "cryptography": {"name": "Cryptography", "icon": "🔒", "tools": 4}
}

# 6-Phase Engagement Workflow
ENGAGEMENT_PHASES = {
    1: "Reconnaissance & Intelligence Gathering",
    2: "Vulnerability Assessment & Analysis",
    3: "Exploitation & Initial Access",
    4: "Post-Exploitation & Privilege Escalation",
    5: "Persistence & Data Exfiltration",
    6: "Reporting & Remediation Guidance"
}

# ==================== ROUTES ====================

@tab_blueprint.route('/')
def index():
    """Render Prometheus Prime tab frontend"""
    template_path = f"{TAB_CONFIG['id']}/frontend.html"
    return render_template(template_path, config=TAB_CONFIG)

@tab_blueprint.route('/api/status', methods=['GET'])
def get_status():
    """Get current Prometheus Prime status"""
    return jsonify({
        "success": True,
        "state": prometheus_state,
        "config": TAB_CONFIG,
        "domains": SECURITY_DOMAINS,
        "phases": ENGAGEMENT_PHASES
    })

@tab_blueprint.route('/api/start', methods=['POST'])
def start_system():
    """Start Prometheus Prime system"""
    prometheus_state["active"] = True
    prometheus_state["status"] = "ACTIVE"
    prometheus_state["last_update"] = datetime.now().isoformat()

    broadcast_update({
        "event": "system_started",
        "timestamp": prometheus_state["last_update"]
    })

    return jsonify({
        "success": True,
        "message": "Prometheus Prime system activated",
        "state": prometheus_state
    })

@tab_blueprint.route('/api/stop', methods=['POST'])
def stop_system():
    """Stop Prometheus Prime system"""
    prometheus_state["active"] = False
    prometheus_state["autonomous_mode"] = False
    prometheus_state["engagement_active"] = False
    prometheus_state["status"] = "STOPPED"
    prometheus_state["last_update"] = datetime.now().isoformat()

    broadcast_update({
        "event": "system_stopped",
        "timestamp": prometheus_state["last_update"]
    })

    return jsonify({
        "success": True,
        "message": "Prometheus Prime system stopped",
        "state": prometheus_state
    })

@tab_blueprint.route('/api/stats', methods=['GET'])
def get_stats():
    """Get Prometheus Prime statistics"""
    return jsonify({
        "success": True,
        "stats": prometheus_state["stats"]
    })

@tab_blueprint.route('/api/start-autonomous', methods=['POST'])
def start_autonomous():
    """Start autonomous penetration testing engagement"""
    data = request.json
    target = data.get('target', '')
    depth = data.get('depth', 'full')
    scope = data.get('scope', 'comprehensive')

    if not target:
        return jsonify({
            "success": False,
            "error": "Target required for autonomous engagement"
        }), 400

    # Generate engagement ID
    engagement_id = f"ENG-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    # Update state
    prometheus_state["autonomous_mode"] = True
    prometheus_state["engagement_active"] = True
    prometheus_state["target"] = target
    prometheus_state["current_phase"] = 1
    prometheus_state["status"] = "AUTONOMOUS ENGAGEMENT"
    prometheus_state["last_update"] = datetime.now().isoformat()

    # Add to active engagements
    engagement = {
        "id": engagement_id,
        "target": target,
        "depth": depth,
        "scope": scope,
        "phase": 1,
        "started": datetime.now().isoformat(),
        "status": "running"
    }
    prometheus_state["active_engagements"].append(engagement)
    prometheus_state["stats"]["active_engagements"] += 1

    # Broadcast update
    broadcast_update({
        "event": "autonomous_started",
        "engagement_id": engagement_id,
        "target": target,
        "depth": depth,
        "phase": 1,
        "phase_name": ENGAGEMENT_PHASES[1]
    })

    return jsonify({
        "success": True,
        "engagement_id": engagement_id,
        "message": f"Autonomous engagement started on {target}",
        "phase": 1,
        "phase_name": ENGAGEMENT_PHASES[1],
        "state": prometheus_state
    })

@tab_blueprint.route('/api/stop-autonomous', methods=['POST'])
def stop_autonomous():
    """Stop autonomous engagement"""
    prometheus_state["autonomous_mode"] = False
    prometheus_state["engagement_active"] = False
    prometheus_state["current_phase"] = None
    prometheus_state["status"] = "ACTIVE"
    prometheus_state["last_update"] = datetime.now().isoformat()

    broadcast_update({
        "event": "autonomous_stopped",
        "timestamp": prometheus_state["last_update"]
    })

    return jsonify({
        "success": True,
        "message": "Autonomous engagement stopped",
        "state": prometheus_state
    })

@tab_blueprint.route('/api/execute-tool', methods=['POST'])
def execute_tool():
    """Execute a specific tool from a domain"""
    data = request.json
    tool_id = data.get('tool_id')
    domain = data.get('domain')
    target = data.get('target', '')
    options = data.get('options', {})

    if not tool_id or not domain:
        return jsonify({
            "success": False,
            "error": "tool_id and domain are required"
        }), 400

    # Create execution record
    execution = {
        "tool_id": tool_id,
        "domain": domain,
        "target": target,
        "options": options,
        "timestamp": datetime.now().isoformat(),
        "status": "executing"
    }

    # Add to tool activity
    prometheus_state["tool_activity"].insert(0, execution)
    if len(prometheus_state["tool_activity"]) > 50:
        prometheus_state["tool_activity"] = prometheus_state["tool_activity"][:50]

    # Broadcast update
    broadcast_update({
        "event": "tool_executed",
        "tool": tool_id,
        "domain": domain,
        "target": target,
        "execution": execution
    })

    return jsonify({
        "success": True,
        "message": f"Executing {tool_id} on {target if target else 'default target'}",
        "execution": execution,
        "state": prometheus_state
    })

@tab_blueprint.route('/api/domains', methods=['GET'])
def get_domains():
    """Get all security domains"""
    return jsonify({
        "success": True,
        "count": len(SECURITY_DOMAINS),
        "domains": SECURITY_DOMAINS
    })

@tab_blueprint.route('/api/phases', methods=['GET'])
def get_phases():
    """Get 6-phase engagement workflow"""
    return jsonify({
        "success": True,
        "phases": ENGAGEMENT_PHASES,
        "current_phase": prometheus_state.get("current_phase")
    })

@tab_blueprint.route('/api/engagements', methods=['GET'])
def get_engagements():
    """Get active engagements"""
    return jsonify({
        "success": True,
        "count": len(prometheus_state["active_engagements"]),
        "engagements": prometheus_state["active_engagements"]
    })

@tab_blueprint.route('/api/findings', methods=['GET'])
def get_findings():
    """Get recent security findings"""
    return jsonify({
        "success": True,
        "count": len(prometheus_state["recent_findings"]),
        "findings": prometheus_state["recent_findings"]
    })

@tab_blueprint.route('/api/activity', methods=['GET'])
def get_activity():
    """Get recent tool activity"""
    return jsonify({
        "success": True,
        "count": len(prometheus_state["tool_activity"]),
        "activity": prometheus_state["tool_activity"]
    })

# ==================== WEBSOCKET HANDLERS ====================

socketio_instance = None

def init_socketio(socketio):
    """Initialize WebSocket handlers for Prometheus Prime"""
    global socketio_instance
    socketio_instance = socketio

    @socketio.on(f'{TAB_CONFIG["id"]}_connect')
    def handle_connect(data):
        """Handle client connection"""
        emit(f'{TAB_CONFIG["id"]}_status', {
            "connected": True,
            "state": prometheus_state,
            "timestamp": datetime.now().isoformat()
        })

    @socketio.on(f'{TAB_CONFIG["id"]}_request_update')
    def handle_update_request():
        """Handle update request from client"""
        emit(f'{TAB_CONFIG["id"]}_update', {
            "state": prometheus_state,
            "timestamp": datetime.now().isoformat()
        })

    @socketio.on(f'{TAB_CONFIG["id"]}_ping')
    def handle_ping():
        """Handle ping from client"""
        emit(f'{TAB_CONFIG["id"]}_pong', {
            "timestamp": datetime.now().isoformat()
        })

def broadcast_update(update_data):
    """Broadcast update to all connected clients"""
    if socketio_instance:
        socketio_instance.emit(f'{TAB_CONFIG["id"]}_update', {
            "data": update_data,
            "state": prometheus_state,
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
    print(f"   Routes: {TAB_CONFIG['routes']['main']}, {TAB_CONFIG['routes']['api']}")
    print(f"   Order: {TAB_CONFIG['order']}, Enabled: {TAB_CONFIG['enabled']}")
    print(f"   Authority Level: {TAB_CONFIG['authority_level']}")

    return {
        "id": TAB_CONFIG['id'],
        "name": TAB_CONFIG['name'],
        "blueprint": tab_blueprint,
        "config": TAB_CONFIG,
        "state": prometheus_state
    }

# ==================== STANDALONE TESTING ====================

if __name__ == '__main__':
    from flask import Flask
    from flask_socketio import SocketIO

    print("\n" + "="*60)
    print(f"🚀 {TAB_CONFIG['name']} - Standalone Mode")
    print(f"   Authority Level: {TAB_CONFIG['authority_level']}")
    print("="*60 + "\n")

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'prometheus-prime-secret'
    socketio = SocketIO(app, cors_allowed_origins="*")

    initialize(app, socketio)

    print("\n" + "="*60)
    print(f"✅ {TAB_CONFIG['name']} Ready")
    print(f"   Access at: http://localhost:5001{TAB_CONFIG['routes']['main']}")
    print("="*60 + "\n")

    socketio.run(app, debug=True, host='0.0.0.0', port=5001)
