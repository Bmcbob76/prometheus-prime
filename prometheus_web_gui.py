#!/usr/bin/env python3
"""
🔥 PROMETHEUS PRIME - Web-Based Command & Control GUI
Authority Level: 11.0
Complete GUI for manual and autonomous operation of all Prometheus capabilities
"""

import sys
import json
import asyncio
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

# Flask app initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'prometheus-prime-authority-level-11'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state
prometheus_state = {
    "autonomous_mode": False,
    "sovereign_override": False,
    "current_engagement": None,
    "execution_log": [],
    "system_status": "READY",
    "active_tools": []
}

# Tool definitions organized by domain
TOOL_DOMAINS = {
    "reconnaissance": {
        "name": "Reconnaissance",
        "icon": "🔍",
        "description": "Information gathering and OSINT",
        "tools": [
            {"id": "nmap", "name": "Nmap Port Scanner", "target": True, "command": "nmap"},
            {"id": "subdomain_enum", "name": "Subdomain Enumeration", "target": True, "command": "sublist3r"},
            {"id": "whois", "name": "WHOIS Lookup", "target": True, "command": "whois"},
            {"id": "dns_enum", "name": "DNS Enumeration", "target": True, "command": "dnsenum"},
            {"id": "osint", "name": "OSINT Intelligence", "target": True, "command": "osint_db"}
        ]
    },
    "web_application": {
        "name": "Web Application",
        "icon": "🌐",
        "description": "Web app vulnerability testing",
        "tools": [
            {"id": "sqlmap", "name": "SQL Injection Scanner", "target": True, "command": "sqlmap"},
            {"id": "xss_scan", "name": "XSS Scanner", "target": True, "command": "xsser"},
            {"id": "dir_brute", "name": "Directory Brute Force", "target": True, "command": "gobuster"},
            {"id": "cms_scan", "name": "CMS Scanner", "target": True, "command": "wpscan"},
            {"id": "api_fuzz", "name": "API Fuzzer", "target": True, "command": "ffuf"}
        ]
    },
    "network_attacks": {
        "name": "Network Attacks",
        "icon": "🌐",
        "description": "Network-based attacks",
        "tools": [
            {"id": "arp_spoof", "name": "ARP Spoofing", "target": True, "command": "arpspoof"},
            {"id": "packet_sniff", "name": "Packet Sniffer", "target": False, "command": "tcpdump"},
            {"id": "syn_flood", "name": "SYN Flood", "target": True, "command": "hping3"},
            {"id": "ssl_strip", "name": "SSL Strip", "target": False, "command": "sslstrip"}
        ]
    },
    "wireless": {
        "name": "Wireless",
        "icon": "📡",
        "description": "WiFi penetration testing",
        "tools": [
            {"id": "wifi_monitor", "name": "Monitor Mode", "target": False, "command": "airmon-ng"},
            {"id": "wifi_scan", "name": "Network Scanner", "target": False, "command": "airodump-ng"},
            {"id": "wpa_crack", "name": "WPA/WPA2 Cracker", "target": True, "command": "aircrack-ng"},
            {"id": "evil_twin", "name": "Evil Twin AP", "target": False, "command": "hostapd"}
        ]
    },
    "password_attacks": {
        "name": "Password Attacks",
        "icon": "🔑",
        "description": "Password cracking and brute force",
        "tools": [
            {"id": "hashcat", "name": "Hash Cracker", "target": False, "command": "hashcat"},
            {"id": "ssh_brute", "name": "SSH Brute Force", "target": True, "command": "hydra"},
            {"id": "ftp_brute", "name": "FTP Brute Force", "target": True, "command": "hydra"},
            {"id": "web_brute", "name": "Web Form Brute Force", "target": True, "command": "hydra"}
        ]
    },
    "exploitation": {
        "name": "Exploitation",
        "icon": "💥",
        "description": "Exploit frameworks and payloads",
        "tools": [
            {"id": "metasploit", "name": "Metasploit Framework", "target": True, "command": "msfconsole"},
            {"id": "exploit_search", "name": "Exploit Search", "target": False, "command": "searchsploit"},
            {"id": "buffer_overflow", "name": "Buffer Overflow Generator", "target": False, "command": "msfvenom"},
            {"id": "shellcode_gen", "name": "Shellcode Generator", "target": False, "command": "msfvenom"}
        ]
    },
    "post_exploitation": {
        "name": "Post-Exploitation",
        "icon": "🎯",
        "description": "Post-compromise activities",
        "tools": [
            {"id": "credential_dump", "name": "Credential Dumper", "target": False, "command": "mimikatz"},
            {"id": "lateral_movement", "name": "Lateral Movement", "target": True, "command": "psexec"},
            {"id": "data_exfil", "name": "Data Exfiltration", "target": False, "command": "exfiltrate"},
            {"id": "persistence", "name": "Persistence", "target": False, "command": "persistence"}
        ]
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "icon": "⬆️",
        "description": "Escalate privileges on compromised systems",
        "tools": [
            {"id": "linux_privesc", "name": "Linux PrivEsc", "target": False, "command": "linpeas.sh"},
            {"id": "windows_privesc", "name": "Windows PrivEsc", "target": False, "command": "winpeas.exe"},
            {"id": "kernel_exploit", "name": "Kernel Exploit Suggester", "target": False, "command": "les.sh"},
            {"id": "suid_finder", "name": "SUID Binary Finder", "target": False, "command": "find"}
        ]
    },
    "social_engineering": {
        "name": "Social Engineering",
        "icon": "🎭",
        "description": "Social engineering attacks",
        "tools": [
            {"id": "phishing_page", "name": "Phishing Page Generator", "target": True, "command": "setoolkit"},
            {"id": "email_spoof", "name": "Email Spoofing", "target": False, "command": "sendemail"},
            {"id": "qr_code", "name": "Malicious QR Code", "target": False, "command": "qr_gen"}
        ]
    },
    "cryptography": {
        "name": "Cryptography",
        "icon": "🔐",
        "description": "Cryptanalysis and crypto attacks",
        "tools": [
            {"id": "ssl_scan", "name": "SSL/TLS Scanner", "target": True, "command": "sslscan"},
            {"id": "cipher_crack", "name": "Cipher Cracker", "target": False, "command": "cipher_crack"},
            {"id": "rsa_attack", "name": "RSA Attack", "target": False, "command": "rsatool"}
        ]
    },
    "autonomous": {
        "name": "Autonomous Systems",
        "icon": "🤖",
        "description": "AI-powered autonomous capabilities",
        "tools": [
            {"id": "full_engagement", "name": "Full Autonomous Engagement", "target": True, "command": "autonomous_engagement"},
            {"id": "ai_decision", "name": "AI Decision Engine", "target": False, "command": "decision_engine"},
            {"id": "intelligence_query", "name": "Omniscience Intelligence", "target": False, "command": "knowledge_base"},
            {"id": "phoenix_heal", "name": "Phoenix Auto-Healing", "target": False, "command": "phoenix_healing"},
            {"id": "sovereign_override", "name": "Sovereign Override (11.0)", "target": False, "command": "sovereign_override"}
        ]
    }
}


@app.route('/')
def index():
    """Serve main GUI"""
    return render_template('prometheus_gui.html')


@app.route('/api/domains')
def get_domains():
    """Get all tool domains"""
    return jsonify(TOOL_DOMAINS)


@app.route('/api/system-status')
def system_status():
    """Get current system status"""
    return jsonify(prometheus_state)


@app.route('/api/execute-tool', methods=['POST'])
def execute_tool():
    """Execute a tool with provided parameters"""
    data = request.json
    tool_id = data.get('tool_id')
    target = data.get('target', '')
    options = data.get('options', {})

    # Log execution
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "tool_id": tool_id,
        "target": target,
        "options": options,
        "status": "started"
    }
    prometheus_state["execution_log"].append(log_entry)
    prometheus_state["active_tools"].append(tool_id)

    # Emit start event
    socketio.emit('tool_started', log_entry)

    # Simulate execution (replace with actual tool calls)
    result = {
        "success": True,
        "tool_id": tool_id,
        "message": f"Tool {tool_id} executed",
        "output": f"Simulated output for {tool_id}",
        "timestamp": datetime.now().isoformat()
    }

    # Update log
    log_entry["status"] = "completed"
    log_entry["result"] = result
    prometheus_state["active_tools"].remove(tool_id)

    socketio.emit('tool_completed', log_entry)

    return jsonify(result)


@app.route('/api/autonomous/start', methods=['POST'])
def start_autonomous():
    """Start autonomous engagement"""
    data = request.json
    prometheus_state["autonomous_mode"] = True
    prometheus_state["system_status"] = "AUTONOMOUS_ACTIVE"

    result = {
        "success": True,
        "message": "Autonomous mode activated",
        "engagement_id": f"ENG-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    }

    socketio.emit('autonomous_started', result)
    return jsonify(result)


@app.route('/api/autonomous/stop', methods=['POST'])
def stop_autonomous():
    """Stop autonomous engagement"""
    prometheus_state["autonomous_mode"] = False
    prometheus_state["system_status"] = "READY"

    result = {"success": True, "message": "Autonomous mode deactivated"}
    socketio.emit('autonomous_stopped', result)
    return jsonify(result)


@app.route('/api/logs')
def get_logs():
    """Get execution logs"""
    return jsonify(prometheus_state["execution_log"][-100:])  # Last 100 entries


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'message': 'Connected to Prometheus Prime'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')


def run_gui(host='0.0.0.0', port=5000):
    """Run the GUI server"""
    print("🔥 PROMETHEUS PRIME - Web-Based C2 GUI")
    print(f"   Authority Level: 11.0")
    print(f"   Server: http://{host}:{port}")
    print(f"   Access: http://localhost:{port}")
    print("\n   Press Ctrl+C to stop\n")
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    run_gui()
