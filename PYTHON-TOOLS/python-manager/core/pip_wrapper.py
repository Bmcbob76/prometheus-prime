#!/usr/bin/env python3
"""
PyManager Pip Wrapper - Version-Aware Package Management
Routes pip commands to correct Python version's pip
"""

import sys
import subprocess
from pathlib import Path
from dispatcher import PyManagerDispatcher


class PipWrapper:
    """Version-aware pip wrapper"""

    def __init__(self):
        self.dispatcher = PyManagerDispatcher()

    def get_pip_for_version(self, version: str) -> Path:
        """Get pip executable for specified Python version"""
        python_exe = self.dispatcher.get_python_executable(version)

        # Get pip path (same directory as Python)
        python_dir = python_exe.parent
        pip_exe = python_dir / 'Scripts' / 'pip.exe' if python_exe.name == 'python.exe' else python_dir / 'pip'

        # Try alternative locations
        if not pip_exe.exists():
            pip_exe = python_dir / 'pip'
        if not pip_exe.exists():
            pip_exe = python_dir / 'pip3'

        # Fallback: use python -m pip
        if not pip_exe.exists():
            return None  # Will use -m pip

        return pip_exe

    def detect_target_version(self) -> str:
        """
        Detect which Python version to install packages for
        Priority:
        1. Explicit version in command (pip3.11 install)
        2. Current directory .pyversion
        3. Global default
        """
        # Check if invoked as pipX.Y
        script_name = Path(sys.argv[0]).stem
        if script_name.startswith('pip'):
            version_part = script_name[3:]  # Remove 'pip'
            if version_part and version_part[0].isdigit():
                return version_part

        # Check for .pyversion in current directory
        cwd = Path.cwd()
        version = self.dispatcher.find_pyversion_file(cwd)
        if version:
            return version

        # Use default
        return self.dispatcher.config.get('default_version', '3.11')

    def execute_pip(self, args: list) -> int:
        """Execute pip with detected version"""
        version = self.detect_target_version()
        python_exe = self.dispatcher.get_python_executable(version)

        # Try to find pip
        pip_exe = self.get_pip_for_version(version)

        # Verbose output
        if self.dispatcher.config.get('verbose', False):
            print(f"[PyManager Pip] Using Python {version}", file=sys.stderr)
            print(f"[PyManager Pip] Python: {python_exe}", file=sys.stderr)

        # Execute pip
        if pip_exe and pip_exe.exists():
            cmd = [str(pip_exe)] + args
        else:
            # Fallback to python -m pip
            cmd = [str(python_exe), '-m', 'pip'] + args

        try:
            result = subprocess.run(
                cmd,
                stdout=sys.stdout,
                stderr=sys.stderr,
                stdin=sys.stdin
            )
            return result.returncode
        except KeyboardInterrupt:
            return 130
        except Exception as e:
            print(f"[PyManager Pip] Error: {e}", file=sys.stderr)
            return 1

    def show_info(self):
        """Show pip wrapper information"""
        print("PyManager Pip Wrapper")
        print("=" * 60)
        print("Version-aware pip that installs to correct Python environment")
        print()
        print("Usage:")
        print("  pip install <package>      # Install to current/default version")
        print("  pip3.11 install <package>  # Install to Python 3.11")
        print("  pip3.9 install <package>   # Install to Python 3.9")
        print()
        print("Version Detection:")
        print("  1. Command name (pip3.11)")
        print("  2. Directory .pyversion file")
        print("  3. Global default")
        print("=" * 60)


def main():
    """Entry point for pip wrapper"""
    wrapper = PipWrapper()

    # Handle info request
    if len(sys.argv) > 1 and sys.argv[1] in ['--pm-info', '--pymanager-info']:
        wrapper.show_info()
        return 0

    # Execute pip
    exit_code = wrapper.execute_pip(sys.argv[1:])
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
