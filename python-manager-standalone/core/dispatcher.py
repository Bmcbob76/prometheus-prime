#!/usr/bin/env python3
"""
PyManager Dispatcher - Core Routing Logic
Routes Python calls to correct version based on detection hierarchy
WITH AUTO-FIX INJECTION for dependency conflicts, async issues, and port conflicts
"""

import sys
import subprocess
import json
import tempfile
from pathlib import Path
from typing import Optional, Dict

# Import managers
try:
    from .dependency_manager import DependencyManager, AutoFixInjector
    from .port_manager import PortManager
except ImportError:
    # Allow running as standalone script
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from dependency_manager import DependencyManager, AutoFixInjector
    from port_manager import PortManager


class PyManagerDispatcher:
    """Main dispatcher for routing Python execution to correct version"""

    def __init__(self):
        self.manager_dir = Path(__file__).parent.parent.resolve()
        self.config_file = self.manager_dir / "pymanager.json"
        self.config = self.load_config()

        # Initialize managers
        self.dependency_manager = DependencyManager(self.config)
        self.auto_fix_injector = AutoFixInjector(self.config)
        self.port_manager = PortManager(self.config)

    def load_config(self) -> Dict:
        """Load configuration from pymanager.json"""
        if not self.config_file.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_file}\n"
                "Run install.py first to set up PyManager."
            )

        with open(self.config_file, 'r') as f:
            return json.load(f)

    def detect_version_from_shebang(self, script_path: Path) -> Optional[str]:
        """
        Check if script has PyManager shebang directive
        Format: #!pymanager:3.11 or #!pymanager:ml
        """
        if not script_path.exists() or not script_path.is_file():
            return None

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if first_line.startswith('#!pymanager:'):
                    version = first_line.split(':', 1)[1].strip()
                    return version
        except (UnicodeDecodeError, PermissionError):
            pass

        return None

    def find_pyversion_file(self, start_path: Path) -> Optional[str]:
        """
        Walk up directory tree looking for .pyversion file
        Returns version string if found, None otherwise
        """
        current = start_path if start_path.is_dir() else start_path.parent

        # Walk up to root
        while current != current.parent:
            pyversion_file = current / '.pyversion'
            if pyversion_file.exists():
                version = pyversion_file.read_text().strip()
                return version
            current = current.parent

        return None

    def check_directory_override(self, script_path: Path) -> Optional[str]:
        """Check if script path matches any directory overrides in config"""
        directory_overrides = self.config.get('directory_overrides', {})

        # Convert to Path and check
        script_str = str(script_path.resolve())
        for dir_pattern, version in directory_overrides.items():
            if script_str.startswith(dir_pattern):
                return version

        return None

    def detect_version(self, script_path: Path) -> str:
        """
        Detect required Python version using priority hierarchy:
        1. File shebang (#!pymanager:3.11)
        2. Directory .pyversion file (recursive up)
        3. Directory overrides in config
        4. Global default in config
        5. Fallback to highest installed version
        """
        # Priority 1: Shebang
        version = self.detect_version_from_shebang(script_path)
        if version:
            return version

        # Priority 2: .pyversion file
        version = self.find_pyversion_file(script_path)
        if version:
            return version

        # Priority 3: Directory override
        version = self.check_directory_override(script_path)
        if version:
            return version

        # Priority 4: Global default
        return self.config.get('default_version', '3.11')

    def get_python_executable(self, version: str) -> Path:
        """
        Get full path to Python executable for specified version
        Supports both version numbers (3.11) and aliases (ml, legacy)
        """
        versions = self.config.get('versions', {})

        if version not in versions:
            # Try to find closest match
            available = ', '.join(versions.keys())
            raise ValueError(
                f"Python version '{version}' not configured in PyManager.\n"
                f"Available versions: {available}\n"
                f"Edit {self.config_file} to add this version."
            )

        rel_path = versions[version]
        python_exe = self.manager_dir / rel_path

        if not python_exe.exists():
            raise FileNotFoundError(
                f"Python executable not found: {python_exe}\n"
                f"Version '{version}' is configured but installation is missing.\n"
                f"Install Python {version} or update {self.config_file}"
            )

        return python_exe

    def execute(self, args: list) -> int:
        """
        Main execution method
        Routes to correct Python version and executes with provided args
        WITH AUTO-FIX INJECTION
        """
        # If no args, show PyManager info
        if len(args) == 0:
            self.show_info()
            return 0

        # Special commands
        if args[0] in ['--pymanager-info', '--pm-info']:
            self.show_info()
            return 0

        if args[0] == '--pymanager-versions':
            self.show_versions()
            return 0

        # Detect script path
        script_path = Path(args[0]).resolve()

        # Handle interactive mode or flags
        if not script_path.exists():
            # Pass to default Python (might be flag like --version)
            default_version = self.config.get('default_version', '3.11')
            python_exe = self.get_python_executable(default_version)
            return self.run_python(python_exe, args)

        # Detect version (initial)
        detected_version = self.detect_version(script_path)

        # Validate and fix version based on dependencies
        final_version = self.dependency_manager.validate_and_fix_version(
            script_path,
            detected_version
        )

        # Get Python executable
        python_exe = self.get_python_executable(final_version)

        # Log if verbose mode enabled
        if self.config.get('verbose', False):
            if final_version != detected_version:
                print(f"[PyManager] Version adjusted: {detected_version} → {final_version}", file=sys.stderr)
            print(f"[PyManager] Routing to Python {final_version}: {python_exe}", file=sys.stderr)

        # Check if auto-fixes needed
        wrapper_code = self.generate_auto_fixes(script_path)

        if wrapper_code:
            # Execute with wrapper injection
            return self.run_python_with_wrapper(python_exe, script_path, args[1:], wrapper_code)
        else:
            # Execute normally
            return self.run_python(python_exe, args)

    def generate_auto_fixes(self, script_path: Path) -> Optional[str]:
        """
        Generate auto-fix wrapper code for script

        Returns:
            Wrapper code to prepend, or None if no fixes needed
        """
        fixes = []

        # Get async/import fix wrapper
        auto_fix_wrapper = self.auto_fix_injector.generate_wrapper_script(script_path)
        if auto_fix_wrapper:
            fixes.append(auto_fix_wrapper)

        # Get port conflict fix
        port_fix = self.port_manager.inject_port_fix(script_path)
        if port_fix:
            fixes.append(port_fix)

        if not fixes:
            return None

        return ''.join(fixes)

    def run_python_with_wrapper(self, python_exe: Path, script_path: Path, script_args: list, wrapper_code: str) -> int:
        """
        Execute Python script with injected wrapper code

        Creates temporary script with wrapper prepended to original
        """
        try:
            # Read original script
            with open(script_path, 'r', encoding='utf-8') as f:
                original_code = f.read()

            # Remove shebang from original (already processed)
            lines = original_code.split('\n')
            if lines and lines[0].startswith('#!'):
                lines = lines[1:]
                original_code = '\n'.join(lines)

            # Combine wrapper + original
            combined_code = wrapper_code + original_code

            # Create temporary script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as tmp:
                tmp.write(combined_code)
                tmp_path = tmp.name

            if self.config.get('verbose', False):
                print(f"[PyManager] Auto-fixes injected", file=sys.stderr)

            # Execute temporary script
            result = subprocess.run(
                [str(python_exe), tmp_path] + script_args,
                stdout=sys.stdout,
                stderr=sys.stderr,
                stdin=sys.stdin
            )

            # Clean up
            try:
                Path(tmp_path).unlink()
            except:
                pass

            return result.returncode

        except Exception as e:
            print(f"[PyManager] Wrapper injection failed: {e}", file=sys.stderr)
            print(f"[PyManager] Falling back to direct execution", file=sys.stderr)
            # Fallback to normal execution
            return self.run_python(python_exe, [str(script_path)] + script_args)

    def run_python(self, python_exe: Path, args: list) -> int:
        """Execute Python with given arguments and return exit code"""
        try:
            result = subprocess.run(
                [str(python_exe)] + args,
                stdout=sys.stdout,
                stderr=sys.stderr,
                stdin=sys.stdin
            )
            return result.returncode
        except KeyboardInterrupt:
            return 130
        except Exception as e:
            print(f"[PyManager] Execution error: {e}", file=sys.stderr)
            return 1

    def show_info(self):
        """Display PyManager information"""
        print("=" * 60)
        print("PyManager - Universal Python Version Router")
        print("=" * 60)
        print(f"Manager Directory: {self.manager_dir}")
        print(f"Config File: {self.config_file}")
        print(f"Default Version: {self.config.get('default_version', 'N/A')}")
        print(f"\nAvailable Versions:")
        for version, path in self.config.get('versions', {}).items():
            full_path = self.manager_dir / path
            status = "✓" if full_path.exists() else "✗"
            print(f"  {status} {version:10} -> {path}")
        print("\nCommands:")
        print("  python <script.py>        # Auto-route to correct version")
        print("  python --pm-info          # Show this info")
        print("  python --pymanager-versions # List all versions")
        print("\nVersion Detection Priority:")
        print("  1. File shebang: #!pymanager:3.11")
        print("  2. Directory .pyversion file")
        print("  3. Directory overrides (config)")
        print("  4. Global default")
        print("=" * 60)

    def show_versions(self):
        """Show available Python versions"""
        print("Configured Python Versions:")
        for version, path in self.config.get('versions', {}).items():
            full_path = self.manager_dir / path
            if full_path.exists():
                # Try to get actual version
                try:
                    result = subprocess.run(
                        [str(full_path), '--version'],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    actual_version = result.stdout.strip() or result.stderr.strip()
                    print(f"  {version:10} -> {actual_version}")
                except:
                    print(f"  {version:10} -> {path} (installed)")
            else:
                print(f"  {version:10} -> NOT INSTALLED")


def main():
    """Entry point for PyManager dispatcher"""
    try:
        dispatcher = PyManagerDispatcher()
        exit_code = dispatcher.execute(sys.argv[1:])
        sys.exit(exit_code)
    except Exception as e:
        print(f"[PyManager ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
