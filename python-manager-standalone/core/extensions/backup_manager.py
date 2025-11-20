#!/usr/bin/env python3
"""
PyManager Backup Manager
Backup and restore Python environments
"""

import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List


class BackupManager:
    """Backup and restore Python environments"""

    def __init__(self, config: Dict):
        self.config = config
        self.backup_dir = Path.home() / '.pymanager' / 'backups'
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, venv_path: Path, name: str = None) -> Path:
        """Create backup of virtual environment"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = name or f"backup_{timestamp}"

        print(f"💾 Creating backup: {backup_name}")

        # Get installed packages
        pip = venv_path / ('Scripts/pip.exe' if venv_path.name == 'Scripts' else 'bin/pip')

        try:
            result = subprocess.run(
                [str(pip), 'freeze'],
                capture_output=True,
                text=True,
                check=True
            )

            packages = result.stdout

            # Save backup
            backup_file = self.backup_dir / f"{backup_name}.json"

            backup_data = {
                'name': backup_name,
                'timestamp': timestamp,
                'venv_path': str(venv_path),
                'packages': packages.split('\n'),
                'python_version': self.get_python_version(venv_path)
            }

            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)

            print(f"✅ Backup saved: {backup_file}")
            return backup_file

        except subprocess.CalledProcessError as e:
            print(f"❌ Backup failed: {e}")
            return None

    def get_python_version(self, venv_path: Path) -> str:
        """Get Python version from venv"""
        python = venv_path / ('Scripts/python.exe' if venv_path.name == 'Scripts' else 'bin/python')

        try:
            result = subprocess.run(
                [str(python), '--version'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip() or result.stderr.strip()
        except:
            return "unknown"

    def restore_backup(self, backup_name: str, target_venv: Path) -> bool:
        """Restore backup to venv"""
        backup_file = self.backup_dir / f"{backup_name}.json"

        if not backup_file.exists():
            print(f"❌ Backup not found: {backup_name}")
            return False

        print(f"📦 Restoring backup: {backup_name}")

        with open(backup_file, 'r') as f:
            backup_data = json.load(f)

        # Install packages
        pip = target_venv / ('Scripts/pip.exe' if target_venv.name == 'Scripts' else 'bin/pip')

        for package in backup_data['packages']:
            if not package.strip():
                continue

            try:
                subprocess.run(
                    [str(pip), 'install', package],
                    check=True,
                    capture_output=True
                )
                print(f"  ✅ {package}")
            except:
                print(f"  ❌ {package}")

        print(f"✅ Restore complete")
        return True

    def list_backups(self):
        """List all backups"""
        backups = []

        for backup_file in self.backup_dir.glob('*.json'):
            with open(backup_file, 'r') as f:
                data = json.load(f)
                backups.append(data)

        print("Available Backups:")
        print("=" * 70)

        for backup in sorted(backups, key=lambda x: x['timestamp'], reverse=True):
            print(f"  {backup['name']}")
            print(f"    Created: {backup['timestamp']}")
            print(f"    Python: {backup['python_version']}")
            print(f"    Packages: {len([p for p in backup['packages'] if p.strip()])}")
            print()

        print("=" * 70)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Backup Manager')
    parser.add_argument('command', choices=['create', 'restore', 'list'],
                        help='Command to execute')
    parser.add_argument('--venv', type=str, help='Virtual environment path')
    parser.add_argument('--name', type=str, help='Backup name')

    args = parser.parse_args()

    manager = BackupManager({})

    if args.command == 'create':
        if not args.venv:
            print("❌ --venv required")
            return
        manager.create_backup(Path(args.venv), args.name)

    elif args.command == 'restore':
        if not args.name or not args.venv:
            print("❌ --name and --venv required")
            return
        manager.restore_backup(args.name, Path(args.venv))

    elif args.command == 'list':
        manager.list_backups()


if __name__ == '__main__':
    main()
