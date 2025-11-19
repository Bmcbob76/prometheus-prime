#!/usr/bin/env python3
"""
PyManager Port Manager
Detect and resolve port conflicts for HTTP servers
"""

import socket
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple


class PortManager:
    """Detect and resolve port conflicts"""

    # Port ranges for different categories
    PORT_RANGES = {
        'gateways': (9400, 9499),
        'omega_systems': (5200, 5299),
        'prometheus': (8200, 8299),
        'development': (8000, 8099),
        'ml_services': (7000, 7099),
    }

    # Known gateway port assignments
    KNOWN_PORTS = {
        'network_guardian': 9410,
        'developer_gateway': 9420,
        'gs343_gateway': 9430,
        'healing_orchestrator': 9440,
        'omega_swarm_brain': 5250,
        'prometheus': 8200,
    }

    def __init__(self, config: Dict):
        self.config = config
        self.auto_fix_enabled = config.get('auto_fixes', {}).get('port_conflicts', True)

    def is_port_in_use(self, port: int, host: str = 'localhost') -> bool:
        """Check if port is currently in use"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                return result == 0
        except socket.error:
            return False

    def find_free_port(self, requested_port: int, category: str = 'gateways') -> int:
        """
        Find next available port if requested is taken

        Args:
            requested_port: Desired port number
            category: Port range category

        Returns:
            Free port number
        """
        # If requested port is free, use it
        if not self.is_port_in_use(requested_port):
            return requested_port

        # Otherwise search in range
        start, end = self.PORT_RANGES.get(category, (requested_port, requested_port + 100))

        # Try ports in range
        for port in range(start, end + 1):
            if not self.is_port_in_use(port):
                if self.config.get('verbose', False):
                    print(f"[PyManager] Port {requested_port} in use, using {port} instead", file=sys.stderr)
                return port

        # If no free port in range, try sequential from requested
        for port in range(requested_port + 1, requested_port + 1000):
            if not self.is_port_in_use(port):
                print(f"⚠️  Port {requested_port} in use, using {port} instead", file=sys.stderr)
                return port

        raise RuntimeError(f"No free ports available near {requested_port}")

    def detect_port_from_script(self, script_path: Path) -> Optional[Tuple[int, str]]:
        """
        Detect port number and framework from script

        Returns:
            (port_number, category) or None
        """
        if not script_path.exists():
            return None

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Common patterns for port definitions
            patterns = [
                r'port\s*=\s*(\d+)',
                r'PORT\s*=\s*(\d+)',
                r'--port[= ](\d+)',
                r'\.run\([^)]*port\s*=\s*(\d+)',
                r'uvicorn\.run\([^)]*port\s*=\s*(\d+)',
                r'app\.run\([^)]*port\s*=\s*(\d+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, content)
                if match:
                    port = int(match.group(1))

                    # Determine category
                    category = self.categorize_port(port, script_path)

                    return port, category

        except (UnicodeDecodeError, PermissionError):
            pass

        return None

    def categorize_port(self, port: int, script_path: Path) -> str:
        """Determine port category based on port number and script name"""
        script_name = script_path.name.lower()

        # Check known gateways
        for gateway_name, gateway_port in self.KNOWN_PORTS.items():
            if gateway_name in script_name:
                return 'gateways'

        # By port range
        if 9400 <= port <= 9499:
            return 'gateways'
        elif 5200 <= port <= 5299:
            return 'omega_systems'
        elif 8200 <= port <= 8299:
            return 'prometheus'
        elif 8000 <= port <= 8099:
            return 'development'
        elif 7000 <= port <= 7099:
            return 'ml_services'

        return 'gateways'  # Default

    def get_wrapper_for_port_fix(self, original_port: int, new_port: int) -> str:
        """Generate code to override port in script"""
        wrapper = f'''import sys
import os

# PyManager Auto-Fix: Port Conflict Resolution
# Original port {original_port} was in use, using {new_port}
os.environ['PORT'] = '{new_port}'
os.environ['PYMANAGER_PORT_OVERRIDE'] = '{new_port}'

# Monkey-patch common port variables
_original_port = {original_port}
_new_port = {new_port}

'''
        return wrapper

    def inject_port_fix(self, script_path: Path) -> Optional[str]:
        """
        Check for port conflicts and generate fix if needed

        Returns:
            Wrapper code to inject, or None
        """
        if not self.auto_fix_enabled:
            return None

        # Detect port from script
        port_info = self.detect_port_from_script(script_path)
        if not port_info:
            return None

        original_port, category = port_info

        # Check if port is in use
        if not self.is_port_in_use(original_port):
            return None  # No conflict

        # Find alternative port
        new_port = self.find_free_port(original_port, category)

        if new_port == original_port:
            return None  # No change needed

        # Generate wrapper
        return self.get_wrapper_for_port_fix(original_port, new_port)

    def list_occupied_ports(self, port_range: Tuple[int, int] = None):
        """List all occupied ports in range"""
        if port_range is None:
            # Check all known ranges
            ranges_to_check = list(self.PORT_RANGES.values())
        else:
            ranges_to_check = [port_range]

        occupied = []

        for start, end in ranges_to_check:
            for port in range(start, end + 1):
                if self.is_port_in_use(port):
                    occupied.append(port)

        return occupied

    def show_port_status(self):
        """Display status of all port ranges"""
        print("=" * 60)
        print("PyManager Port Status")
        print("=" * 60)

        for category, (start, end) in self.PORT_RANGES.items():
            print(f"\n{category.upper()}: {start}-{end}")

            occupied = []
            for port in range(start, min(start + 20, end + 1)):  # Check first 20
                if self.is_port_in_use(port):
                    occupied.append(port)

            if occupied:
                print(f"  Occupied: {', '.join(map(str, occupied))}")
            else:
                print(f"  All clear (checked {start}-{start+19})")

        print("\n" + "=" * 60)


def main():
    """CLI for port manager"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='PyManager Port Manager')
    parser.add_argument('command', choices=['check', 'status', 'find'],
                        help='Command to execute')
    parser.add_argument('--port', type=int, help='Port number')
    parser.add_argument('--category', choices=list(PortManager.PORT_RANGES.keys()),
                        default='gateways', help='Port category')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent
    config_file = manager_dir / 'pymanager.json'

    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    # Create manager
    manager = PortManager(config)

    # Execute command
    if args.command == 'check':
        if args.port is None:
            print("❌ --port required")
            sys.exit(1)

        if manager.is_port_in_use(args.port):
            print(f"⚠️  Port {args.port} is IN USE")
            sys.exit(1)
        else:
            print(f"✅ Port {args.port} is FREE")
            sys.exit(0)

    elif args.command == 'status':
        manager.show_port_status()

    elif args.command == 'find':
        if args.port is None:
            # Find first free port in category
            start, end = PortManager.PORT_RANGES[args.category]
            free_port = manager.find_free_port(start, args.category)
        else:
            # Find free port near requested
            free_port = manager.find_free_port(args.port, args.category)

        print(f"Free port: {free_port}")


if __name__ == '__main__':
    main()
