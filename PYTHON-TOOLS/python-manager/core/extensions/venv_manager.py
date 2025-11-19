#!/usr/bin/env python3
"""
PyManager Virtual Environment Manager
Auto-detect, create, and manage virtual environments
"""

import sys
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class VenvManager:
    """Manage virtual environments for Python projects"""

    def __init__(self, config: Dict):
        self.config = config
        self.venv_config = config.get('venv', {})
        self.auto_detect = self.venv_config.get('auto_detect', True)
        self.auto_activate = self.venv_config.get('auto_activate', False)

    def detect_venv(self, start_path: Path) -> Optional[Path]:
        """
        Detect virtual environment in directory tree

        Checks for:
        - .venv/
        - venv/
        - env/
        - virtualenv/
        """
        venv_names = ['.venv', 'venv', 'env', 'virtualenv', '.env']

        current = start_path if start_path.is_dir() else start_path.parent

        # Walk up directory tree
        while current != current.parent:
            for venv_name in venv_names:
                venv_path = current / venv_name

                # Check if it's a valid venv
                if self.is_valid_venv(venv_path):
                    return venv_path

            current = current.parent

        return None

    def is_valid_venv(self, venv_path: Path) -> bool:
        """Check if directory is a valid virtual environment"""
        if not venv_path.exists() or not venv_path.is_dir():
            return False

        # Check for activation script
        if sys.platform == 'win32':
            activate = venv_path / 'Scripts' / 'activate.bat'
            python = venv_path / 'Scripts' / 'python.exe'
        else:
            activate = venv_path / 'bin' / 'activate'
            python = venv_path / 'bin' / 'python'

        return activate.exists() and python.exists()

    def get_venv_python(self, venv_path: Path) -> Optional[Path]:
        """Get Python executable from venv"""
        if sys.platform == 'win32':
            python = venv_path / 'Scripts' / 'python.exe'
        else:
            python = venv_path / 'bin' / 'python'

        return python if python.exists() else None

    def create_venv(self, venv_path: Path, python_version: str = None) -> bool:
        """Create new virtual environment"""
        print(f"🔧 Creating virtual environment at {venv_path}")

        try:
            # Determine Python executable
            if python_version:
                # Use specific Python version
                from ..dispatcher import PyManagerDispatcher
                dispatcher = PyManagerDispatcher()
                python_exe = dispatcher.get_python_executable(python_version)
            else:
                # Use current Python
                python_exe = Path(sys.executable)

            # Create venv
            subprocess.run(
                [str(python_exe), '-m', 'venv', str(venv_path)],
                check=True,
                capture_output=True
            )

            print(f"✅ Virtual environment created")
            return True

        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create venv: {e.stderr.decode()}")
            return False

    def install_requirements(self, venv_path: Path, requirements_file: Path) -> bool:
        """Install requirements in venv"""
        pip = venv_path / ('Scripts/pip.exe' if sys.platform == 'win32' else 'bin/pip')

        if not pip.exists():
            print(f"❌ Pip not found in venv")
            return False

        print(f"📦 Installing requirements from {requirements_file}")

        try:
            subprocess.run(
                [str(pip), 'install', '-r', str(requirements_file)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )

            print("✅ Requirements installed")
            return True

        except subprocess.CalledProcessError as e:
            print(f"❌ Installation failed: {e.stdout.decode()}")
            return False

    def list_packages(self, venv_path: Path) -> List[str]:
        """List installed packages in venv"""
        pip = venv_path / ('Scripts/pip.exe' if sys.platform == 'win32' else 'bin/pip')

        try:
            result = subprocess.run(
                [str(pip), 'list', '--format=freeze'],
                capture_output=True,
                text=True,
                check=True
            )

            return result.stdout.strip().split('\n')

        except subprocess.CalledProcessError:
            return []

    def get_venv_info(self, venv_path: Path) -> Dict:
        """Get information about virtual environment"""
        info = {
            'path': str(venv_path),
            'valid': self.is_valid_venv(venv_path),
            'python_version': None,
            'packages': [],
        }

        if not info['valid']:
            return info

        # Get Python version
        python = self.get_venv_python(venv_path)
        if python:
            try:
                result = subprocess.run(
                    [str(python), '--version'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                info['python_version'] = result.stdout.strip() or result.stderr.strip()
            except:
                pass

        # Get packages
        info['packages'] = self.list_packages(venv_path)

        return info

    def auto_setup_project(self, project_dir: Path, python_version: str = '3.11') -> bool:
        """
        Auto-setup project with venv and requirements

        Creates .venv, installs requirements.txt if present
        """
        venv_path = project_dir / '.venv'

        # Create venv
        if not self.create_venv(venv_path, python_version):
            return False

        # Install requirements if exists
        requirements = project_dir / 'requirements.txt'
        if requirements.exists():
            self.install_requirements(venv_path, requirements)

        print(f"\n✅ Project setup complete!")
        print(f"   Venv: {venv_path}")

        # Show activation command
        if sys.platform == 'win32':
            activate = venv_path / 'Scripts' / 'activate.bat'
        else:
            activate = venv_path / 'bin' / 'activate'

        print(f"\nActivate with:")
        if sys.platform == 'win32':
            print(f"  {activate}")
        else:
            print(f"  source {activate}")

        return True


def main():
    """CLI for venv management"""
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Virtual Environment Manager')
    parser.add_argument('command', choices=['detect', 'create', 'info', 'setup'],
                        help='Command to execute')
    parser.add_argument('--path', type=str, default='.', help='Project path')
    parser.add_argument('--version', type=str, help='Python version for venv')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent.parent
    config_file = manager_dir / 'pymanager.json'

    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    # Create manager
    venv_mgr = VenvManager(config)
    path = Path(args.path).resolve()

    # Execute command
    if args.command == 'detect':
        venv = venv_mgr.detect_venv(path)
        if venv:
            print(f"✅ Found venv: {venv}")
            info = venv_mgr.get_venv_info(venv)
            print(f"   Python: {info['python_version']}")
            print(f"   Packages: {len(info['packages'])}")
        else:
            print("❌ No venv detected")

    elif args.command == 'create':
        venv_path = path / '.venv'
        venv_mgr.create_venv(venv_path, args.version)

    elif args.command == 'info':
        venv = venv_mgr.detect_venv(path)
        if venv:
            info = venv_mgr.get_venv_info(venv)
            print(f"Virtual Environment Info:")
            print(f"  Path: {info['path']}")
            print(f"  Valid: {info['valid']}")
            print(f"  Python: {info['python_version']}")
            print(f"\n  Packages ({len(info['packages'])}):")
            for pkg in info['packages'][:20]:
                print(f"    {pkg}")
        else:
            print("❌ No venv detected")

    elif args.command == 'setup':
        venv_mgr.auto_setup_project(path, args.version or '3.11')


if __name__ == '__main__':
    main()
