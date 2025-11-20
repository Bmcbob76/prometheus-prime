#!/usr/bin/env python3
"""
PyManager Health Monitor
Monitor system health and Python environment status
"""

import psutil
import platform
from pathlib import Path
from typing import Dict


class HealthMonitor:
    """Monitor system and Python environment health"""

    def __init__(self, config: Dict):
        self.config = config

    def check_system_health(self) -> Dict:
        """Check overall system health"""
        health = {
            'cpu': {
                'usage_percent': psutil.cpu_percent(interval=1),
                'count': psutil.cpu_count(),
            },
            'memory': {
                'total_gb': psutil.virtual_memory().total / (1024**3),
                'available_gb': psutil.virtual_memory().available / (1024**3),
                'percent': psutil.virtual_memory().percent,
            },
            'disk': {
                'total_gb': psutil.disk_usage('/').total / (1024**3),
                'free_gb': psutil.disk_usage('/').free / (1024**3),
                'percent': psutil.disk_usage('/').percent,
            },
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'python_version': platform.python_version(),
            }
        }

        return health

    def check_pymanager_health(self, manager_dir: Path) -> Dict:
        """Check PyManager installation health"""
        health = {
            'installation': {
                'directory_exists': manager_dir.exists(),
                'config_exists': (manager_dir / 'pymanager.json').exists(),
                'core_exists': (manager_dir / 'core').exists(),
            },
            'cache': {
                'enabled': self.config.get('cache', {}).get('enabled', False),
                'directory': str(Path.home() / '.pymanager' / 'cache'),
            },
            'extensions': self.count_extensions(manager_dir),
        }

        return health

    def count_extensions(self, manager_dir: Path) -> Dict:
        """Count available extensions"""
        ext_dir = manager_dir / 'core' / 'extensions'

        if not ext_dir.exists():
            return {'count': 0, 'modules': []}

        modules = [f.stem for f in ext_dir.glob('*.py') if f.stem != '__init__']

        return {
            'count': len(modules),
            'modules': modules
        }

    def get_health_status(self) -> str:
        """Determine overall health status"""
        system = self.check_system_health()

        cpu_ok = system['cpu']['usage_percent'] < 80
        mem_ok = system['memory']['percent'] < 80
        disk_ok = system['disk']['percent'] < 90

        if cpu_ok and mem_ok and disk_ok:
            return "HEALTHY"
        elif cpu_ok and mem_ok:
            return "WARNING"
        else:
            return "CRITICAL"

    def show_dashboard(self, manager_dir: Path):
        """Display health monitoring dashboard"""
        system = self.check_system_health()
        pymanager = self.check_pymanager_health(manager_dir)
        status = self.get_health_status()

        status_icon = {
            'HEALTHY': '✅',
            'WARNING': '⚠️ ',
            'CRITICAL': '❌'
        }

        print("=" * 70)
        print(f"PyManager Health Dashboard")
        print("=" * 70)
        print(f"\nOverall Status: {status_icon.get(status, '❓')} {status}")
        print()

        # System health
        print("System Resources:")
        print(f"  CPU Usage: {system['cpu']['usage_percent']:.1f}% ({system['cpu']['count']} cores)")
        print(f"  Memory: {system['memory']['percent']:.1f}% ({system['memory']['available_gb']:.1f}GB free)")
        print(f"  Disk: {system['disk']['percent']:.1f}% ({system['disk']['free_gb']:.1f}GB free)")
        print()

        # Platform
        print("Platform:")
        print(f"  OS: {system['platform']['system']} {system['platform']['release']}")
        print(f"  Python: {system['platform']['python_version']}")
        print()

        # PyManager
        print("PyManager:")
        print(f"  Installation: {'✅' if pymanager['installation']['directory_exists'] else '❌'}")
        print(f"  Config: {'✅' if pymanager['installation']['config_exists'] else '❌'}")
        print(f"  Cache: {'✅ Enabled' if pymanager['cache']['enabled'] else '❌ Disabled'}")
        print(f"  Extensions: {pymanager['extensions']['count']} modules")
        print()

        print("=" * 70)


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description='PyManager Health Monitor')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    manager_dir = Path(__file__).parent.parent.parent

    config_file = manager_dir / 'pymanager.json'
    config = {}
    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)

    monitor = HealthMonitor(config)

    if args.json:
        import json
        health = {
            'system': monitor.check_system_health(),
            'pymanager': monitor.check_pymanager_health(manager_dir),
            'status': monitor.get_health_status()
        }
        print(json.dumps(health, indent=2))
    else:
        monitor.show_dashboard(manager_dir)


if __name__ == '__main__':
    main()
