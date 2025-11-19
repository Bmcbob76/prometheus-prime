"""
PyManager CLI Entry Point
Allows running: python -m pymanager <command>
"""

import sys
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        prog='pymanager',
        description='PyManager - Universal Python Version Manager'
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Info command
    subparsers.add_parser('info', help='Show PyManager information')

    # Versions command
    subparsers.add_parser('versions', help='List available Python versions')

    # Profile commands
    profile_parser = subparsers.add_parser('profile', help='Manage framework profiles')
    profile_parser.add_argument('action', choices=['list', 'show', 'install', 'activate'])
    profile_parser.add_argument('name', nargs='?', help='Profile name')
    profile_parser.add_argument('--force', action='store_true', help='Force reinstall')

    # Port commands
    port_parser = subparsers.add_parser('port', help='Port management')
    port_parser.add_argument('action', choices=['check', 'status', 'find'])
    port_parser.add_argument('--port', type=int, help='Port number')
    port_parser.add_argument('--category', default='gateways', help='Port category')

    args = parser.parse_args()

    # Execute command
    if args.command == 'info' or args.command is None:
        from .dispatcher import PyManagerDispatcher
        dispatcher = PyManagerDispatcher()
        dispatcher.show_info()

    elif args.command == 'versions':
        from .dispatcher import PyManagerDispatcher
        dispatcher = PyManagerDispatcher()
        dispatcher.show_versions()

    elif args.command == 'profile':
        if args.action == 'list':
            from .profile_manager import ProfileManager
            import json
            manager_dir = Path(__file__).parent.parent
            config_file = manager_dir / 'pymanager.json'
            with open(config_file) as f:
                config = json.load(f)
            pm = ProfileManager(manager_dir, config)
            profiles = pm.list_profiles()
            print("Available Profiles:")
            print("=" * 60)
            for name, info in profiles.items():
                print(f"  {name:20} [Python {info['python']}] ({info['packages']} packages)")
            print("=" * 60)

        elif args.action == 'show':
            from .profile_manager import ProfileManager
            import json
            manager_dir = Path(__file__).parent.parent
            config_file = manager_dir / 'pymanager.json'
            with open(config_file) as f:
                config = json.load(f)
            pm = ProfileManager(manager_dir, config)
            pm.show_profile(args.name)

        elif args.action == 'install':
            from .profile_manager import ProfileManager
            import json
            manager_dir = Path(__file__).parent.parent
            config_file = manager_dir / 'pymanager.json'
            with open(config_file) as f:
                config = json.load(f)
            pm = ProfileManager(manager_dir, config)
            pm.install_profile(args.name, force=args.force)

        elif args.action == 'activate':
            from .profile_manager import ProfileManager
            import json
            manager_dir = Path(__file__).parent.parent
            config_file = manager_dir / 'pymanager.json'
            with open(config_file) as f:
                config = json.load(f)
            pm = ProfileManager(manager_dir, config)
            pm.activate_profile(args.name)

    elif args.command == 'port':
        from .port_manager import PortManager
        import json
        manager_dir = Path(__file__).parent.parent
        config_file = manager_dir / 'pymanager.json'
        with open(config_file) as f:
            config = json.load(f)
        pm = PortManager(config)

        if args.action == 'check':
            if args.port is None:
                print("❌ --port required")
                sys.exit(1)
            if pm.is_port_in_use(args.port):
                print(f"⚠️  Port {args.port} is IN USE")
                sys.exit(1)
            else:
                print(f"✅ Port {args.port} is FREE")
                sys.exit(0)

        elif args.action == 'status':
            pm.show_port_status()

        elif args.action == 'find':
            if args.port:
                free_port = pm.find_free_port(args.port, args.category)
            else:
                start, end = PortManager.PORT_RANGES[args.category]
                free_port = pm.find_free_port(start, args.category)
            print(f"Free port: {free_port}")


if __name__ == '__main__':
    main()
