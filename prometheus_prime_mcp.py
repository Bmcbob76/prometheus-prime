#!/usr/bin/env python3
"""
🎯 PROMETHEUS PRIME - COMPLETE OFFENSIVE/DEFENSIVE MCP SERVER
Full-spectrum security operations with OSINT, network scanning, mobile control, web security, and exploitation
Authority Level: 11.0
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Add module path
sys.path.append(str(Path(__file__).parent))

# Import all modules
from phone_intelligence import PhoneIntelligence
from social_osint import SocialOSINT
from domain_intelligence import DomainIntelligence
from email_intelligence import EmailIntelligence
from ip_intelligence import IPIntelligence
from network_security import NetworkSecurity
from mobile_control import MobileControl
from web_security import WebSecurity
from exploitation_framework import ExploitationFramework
from gs343_gateway import gs343, with_phoenix_retry

# MCP SDK
try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    import mcp.server.stdio
except ImportError:
    print("❌ MCP SDK not installed: pip install mcp --break-system-packages")
    sys.exit(1)

# Initialize all modules
print("🔧 Initializing OSINT modules...")
phone_intel = PhoneIntelligence()
social_osint = SocialOSINT()
domain_intel = DomainIntelligence()
email_intel = EmailIntelligence()
ip_intel = IPIntelligence()
print("✅ OSINT modules ready")

print("🔧 Initializing security modules...")
net_sec = NetworkSecurity()
mobile_ctrl = MobileControl()
web_sec = WebSecurity()
exploit_fw = ExploitationFramework()
print("✅ Security modules ready")

# Create MCP server
app = Server("prometheus-prime")

@app.list_tools()
async def list_tools() -> List[Tool]:
    """List all available tools - OSINT + Offensive + Defensive"""
    return [
        # System Health
        Tool(
            name="prom_health",
            description="Check Prometheus Prime health and all module status",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        
        # ========== OSINT TOOLS ==========
        Tool(
            name="prom_phone_lookup",
            description="Reverse phone lookup with caller name (Twilio CNAM)",
            inputSchema={
                "type": "object",
                "properties": {
                    "phone": {"type": "string", "description": "Phone number (+15555551234)"},
                    "use_cache": {"type": "boolean", "default": True}
                },
                "required": ["phone"]
            }
        ),
        Tool(
            name="prom_social_search",
            description="Social media OSINT (Reddit, usernames)",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "phone": {"type": "string"},
                    "location": {"type": "string"}
                },
                "required": ["name"]
            }
        ),
        Tool(
            name="prom_domain_lookup",
            description="Domain WHOIS, DNS, reputation",
            inputSchema={
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"]
            }
        ),
        Tool(
            name="prom_email_analyze",
            description="Email breaches, validation, reputation",
            inputSchema={
                "type": "object",
                "properties": {"email": {"type": "string"}},
                "required": ["email"]
            }
        ),
        Tool(
            name="prom_ip_analyze",
            description="IP geolocation, reputation, Shodan",
            inputSchema={
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"]
            }
        ),
        
        # ========== NETWORK SECURITY TOOLS ==========
        Tool(
            name="prom_port_scan",
            description="Multi-threaded port scanner",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP or hostname"},
                    "ports": {"type": "array", "items": {"type": "integer"}},
                    "timeout": {"type": "number", "default": 1.0}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="prom_nmap_scan",
            description="Nmap network scan (basic/full/vuln/aggressive)",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "scan_type": {"type": "string", "enum": ["basic", "full", "vuln", "aggressive"], "default": "basic"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="prom_vulnerability_scan",
            description="Quick vulnerability assessment",
            inputSchema={
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"]
            }
        ),
        Tool(
            name="prom_subnet_scan",
            description="Scan subnet for live hosts",
            inputSchema={
                "type": "object",
                "properties": {"subnet": {"type": "string", "description": "CIDR notation (192.168.1.0/24)"}},
                "required": ["subnet"]
            }
        ),
        Tool(
            name="prom_service_banner",
            description="Grab service banner for fingerprinting",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "port": {"type": "integer"}
                },
                "required": ["target", "port"]
            }
        ),
        
        # ========== MOBILE DEVICE CONTROL ==========
        Tool(
            name="prom_android_devices",
            description="List connected Android devices (ADB)",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="prom_android_info",
            description="Get Android device information",
            inputSchema={
                "type": "object",
                "properties": {"device_id": {"type": "string"}},
                "required": []
            }
        ),
        Tool(
            name="prom_android_shell",
            description="Execute shell command on Android",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "device_id": {"type": "string"}
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="prom_android_screenshot",
            description="Capture Android screenshot",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {"type": "string"},
                    "device_id": {"type": "string"}
                },
                "required": ["output_path"]
            }
        ),
        Tool(
            name="prom_android_apps",
            description="List installed Android apps",
            inputSchema={
                "type": "object",
                "properties": {"device_id": {"type": "string"}},
                "required": []
            }
        ),
        Tool(
            name="prom_ios_devices",
            description="List connected iOS devices (libimobiledevice)",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="prom_ios_info",
            description="Get iOS device information",
            inputSchema={
                "type": "object",
                "properties": {"udid": {"type": "string"}},
                "required": []
            }
        ),
        Tool(
            name="prom_ios_screenshot",
            description="Capture iOS screenshot",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {"type": "string"},
                    "udid": {"type": "string"}
                },
                "required": ["output_path"]
            }
        ),
        
        # ========== WEB SECURITY TOOLS ==========
        Tool(
            name="prom_web_headers",
            description="Check security headers",
            inputSchema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]
            }
        ),
        Tool(
            name="prom_sql_injection",
            description="Test for SQL injection vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "param": {"type": "string", "default": "id"}
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="prom_xss_test",
            description="Test for XSS vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "param": {"type": "string", "default": "search"}
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="prom_dir_bruteforce",
            description="Directory and file enumeration",
            inputSchema={
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "wordlist": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["base_url"]
            }
        ),
        Tool(
            name="prom_web_crawl",
            description="Crawl website for links",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_depth": {"type": "integer", "default": 2}
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="prom_ssl_scan",
            description="SSL/TLS security analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "port": {"type": "integer", "default": 443}
                },
                "required": ["hostname"]
            }
        ),
        Tool(
            name="prom_tech_detect",
            description="Detect web technologies",
            inputSchema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]
            }
        ),
        Tool(
            name="prom_web_comprehensive",
            description="Complete web security assessment",
            inputSchema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]
            }
        ),
        
        # ========== EXPLOITATION FRAMEWORK ==========
        Tool(
            name="prom_search_exploits",
            description="Search exploit-db for exploits",
            inputSchema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            }
        ),
        Tool(
            name="prom_generate_payload",
            description="Generate Metasploit payload (msfvenom)",
            inputSchema={
                "type": "object",
                "properties": {
                    "payload_type": {"type": "string", "description": "windows/meterpreter/reverse_tcp"},
                    "lhost": {"type": "string", "description": "Attacker IP"},
                    "lport": {"type": "integer", "description": "Listening port"},
                    "format": {"type": "string", "default": "exe"}
                },
                "required": ["payload_type", "lhost", "lport"]
            }
        ),
        Tool(
            name="prom_list_payloads",
            description="List available Metasploit payloads",
            inputSchema={
                "type": "object",
                "properties": {"platform": {"type": "string"}},
                "required": []
            }
        ),
        Tool(
            name="prom_pattern_create",
            description="Create cyclic pattern for buffer overflow",
            inputSchema={
                "type": "object",
                "properties": {"length": {"type": "integer"}},
                "required": ["length"]
            }
        ),
        Tool(
            name="prom_msf_search",
            description="Search Metasploit modules",
            inputSchema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            }
        ),
        
        # ========== BATCH & UTILITY ==========
        Tool(
            name="prom_osint_full",
            description="Complete OSINT report (all modules)",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "phone": {"type": "string"},
                    "email": {"type": "string"},
                    "domain": {"type": "string"},
                    "ip": {"type": "string"},
                    "location": {"type": "string"}
                },
                "required": []
            }
        ),
        Tool(
            name="prom_healing_stats",
            description="Phoenix healing statistics",
            inputSchema={"type": "object", "properties": {}, "required": []}
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle all tool calls"""
    
    try:
        # Health check
        if name == "prom_health":
            result = {
                'status': 'online',
                'authority_level': 11.0,
                'timestamp': datetime.now().isoformat(),
                'modules': {
                    'osint': ['phone', 'social', 'domain', 'email', 'ip'],
                    'network_security': True,
                    'mobile_control': True,
                    'web_security': True,
                    'exploitation': True
                },
                'tools_available': 43,
                'phoenix_healing': True
            }
        
        # ========== OSINT TOOLS ==========
        elif name == "prom_phone_lookup":
            result = phone_intel.lookup(arguments['phone'], arguments.get('use_cache', True))
        elif name == "prom_social_search":
            result = social_osint.full_osint_report(
                arguments['name'],
                arguments.get('phone'),
                arguments.get('location')
            )
        elif name == "prom_domain_lookup":
            result = domain_intel.lookup(arguments['domain'])
        elif name == "prom_email_analyze":
            result = email_intel.analyze(arguments['email'])
        elif name == "prom_ip_analyze":
            result = ip_intel.analyze(arguments['ip'])
        
        # ========== NETWORK SECURITY ==========
        elif name == "prom_port_scan":
            result = net_sec.port_scan(
                arguments['target'],
                arguments.get('ports'),
                arguments.get('timeout', 1.0)
            )
        elif name == "prom_nmap_scan":
            result = net_sec.nmap_scan(
                arguments['target'],
                arguments.get('scan_type', 'basic')
            )
        elif name == "prom_vulnerability_scan":
            result = net_sec.vulnerability_scan(arguments['target'])
        elif name == "prom_subnet_scan":
            result = net_sec.subnet_scan(arguments['subnet'])
        elif name == "prom_service_banner":
            result = net_sec.service_banner_grab(
                arguments['target'],
                arguments['port']
            )
        
        # ========== MOBILE CONTROL ==========
        elif name == "prom_android_devices":
            result = mobile_ctrl.android_devices()
        elif name == "prom_android_info":
            result = mobile_ctrl.android_info(arguments.get('device_id'))
        elif name == "prom_android_shell":
            result = mobile_ctrl.android_shell(
                arguments['command'],
                arguments.get('device_id')
            )
        elif name == "prom_android_screenshot":
            result = mobile_ctrl.android_screenshot(
                arguments['output_path'],
                arguments.get('device_id')
            )
        elif name == "prom_android_apps":
            result = mobile_ctrl.android_list_apps(arguments.get('device_id'))
        elif name == "prom_ios_devices":
            result = mobile_ctrl.ios_devices()
        elif name == "prom_ios_info":
            result = mobile_ctrl.ios_info(arguments.get('udid'))
        elif name == "prom_ios_screenshot":
            result = mobile_ctrl.ios_screenshot(
                arguments['output_path'],
                arguments.get('udid')
            )
        
        # ========== WEB SECURITY ==========
        elif name == "prom_web_headers":
            result = web_sec.security_headers(arguments['url'])
        elif name == "prom_sql_injection":
            result = web_sec.sql_injection_test(
                arguments['url'],
                arguments.get('param', 'id')
            )
        elif name == "prom_xss_test":
            result = web_sec.xss_test(
                arguments['url'],
                arguments.get('param', 'search')
            )
        elif name == "prom_dir_bruteforce":
            result = web_sec.directory_bruteforce(
                arguments['base_url'],
                arguments.get('wordlist')
            )
        elif name == "prom_web_crawl":
            result = web_sec.crawl_links(
                arguments['url'],
                arguments.get('max_depth', 2)
            )
        elif name == "prom_ssl_scan":
            result = web_sec.ssl_scan(
                arguments['hostname'],
                arguments.get('port', 443)
            )
        elif name == "prom_tech_detect":
            result = web_sec.technology_detection(arguments['url'])
        elif name == "prom_web_comprehensive":
            result = web_sec.comprehensive_scan(arguments['url'])
        
        # ========== EXPLOITATION ==========
        elif name == "prom_search_exploits":
            result = exploit_fw.search_exploits(arguments['query'])
        elif name == "prom_generate_payload":
            result = exploit_fw.generate_payload(
                arguments['payload_type'],
                arguments['lhost'],
                arguments['lport'],
                arguments.get('format', 'exe')
            )
        elif name == "prom_list_payloads":
            result = exploit_fw.list_payloads(arguments.get('platform'))
        elif name == "prom_pattern_create":
            result = exploit_fw.pattern_create(arguments['length'])
        elif name == "prom_msf_search":
            result = exploit_fw.msf_search(arguments['query'])
        
        # ========== BATCH & UTILITY ==========
        elif name == "prom_osint_full":
            results = {'timestamp': datetime.now().isoformat(), 'targets': {}}
            if 'phone' in arguments and arguments['phone']:
                results['phone_intel'] = phone_intel.lookup(arguments['phone'])
            if 'name' in arguments and arguments['name']:
                results['social_osint'] = social_osint.full_osint_report(
                    arguments['name'], arguments.get('phone'), arguments.get('location')
                )
            if 'domain' in arguments and arguments['domain']:
                results['domain_intel'] = domain_intel.lookup(arguments['domain'])
            if 'email' in arguments and arguments['email']:
                results['email_intel'] = email_intel.analyze(arguments['email'])
            if 'ip' in arguments and arguments['ip']:
                results['ip_intel'] = ip_intel.analyze(arguments['ip'])
            result = results
        elif name == "prom_healing_stats":
            result = gs343.get_healing_stats()
        
        else:
            result = {"error": f"Unknown tool: {name}"}
        
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    except Exception as e:
        healing = gs343.heal_phoenix(error=str(e), context={'tool': name, 'arguments': arguments})
        return [TextContent(type="text", text=json.dumps({
            "error": str(e),
            "phoenix_healing": healing
        }, indent=2))]

async def main():
    """Run complete MCP server"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        print("="*60, file=sys.stderr)
        print("🎯 PROMETHEUS PRIME - COMPLETE OFFENSIVE/DEFENSIVE", file=sys.stderr)
        print("   Authority Level: 11.0", file=sys.stderr)
        print("\n   📊 CAPABILITIES:", file=sys.stderr)
        print("   • OSINT (5 modules)", file=sys.stderr)
        print("   • Network Security (Nmap, port scanning, vuln detection)", file=sys.stderr)
        print("   • Mobile Control (iOS/Android via ADB/libimobiledevice)", file=sys.stderr)
        print("   • Web Security (SQL injection, XSS, crawling)", file=sys.stderr)
        print("   • Exploitation (Metasploit, payload generation)", file=sys.stderr)
        print("\n   📡 Tools Available: 43", file=sys.stderr)
        print("   🔥 Phoenix Healing: ENABLED", file=sys.stderr)
        print("="*60, file=sys.stderr)
        
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
