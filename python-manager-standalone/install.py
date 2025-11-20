#!/usr/bin/env python3
"""
PyManager Installer - PATH Hijack Setup
Adds PyManager to system PATH (first position) for total Python control
"""

import os
import sys
import platform
import subprocess
import shutil
import json
from pathlib import Path


class PyManagerInstaller:
    """Handles installation and PATH configuration for PyManager"""

    def __init__(self):
        self.manager_dir = Path(__file__).parent.resolve()
        self.config_file = self.manager_dir / "pymanager.json"
        self.is_windows = platform.system() == "Windows"

    def detect_existing_pythons(self):
        """Auto-detect Python installations on system"""
        pythons = {}

        if self.is_windows:
            # Common Windows Python locations
            search_paths = [
                Path("C:/Python*"),
                Path("C:/Program Files/Python*"),
                Path.home() / "AppData/Local/Programs/Python/Python*",
                Path("H:/Tools/python"),
            ]

            # Find using where command
            try:
                result = subprocess.run(
                    ['where', 'python'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split('\n'):
                    if line.strip():
                        py_path = Path(line.strip())
                        if py_path.exists():
                            version = self.get_python_version(py_path)
                            if version:
                                pythons[version] = str(py_path)
            except:
                pass

        else:
            # Linux/Mac - use which
            for py_cmd in ['python3.11', 'python3.10', 'python3.9', 'python3.8', 'python3']:
                try:
                    result = subprocess.run(
                        ['which', py_cmd],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    if result.returncode == 0:
                        py_path = Path(result.stdout.strip())
                        if py_path.exists():
                            version = self.get_python_version(py_path)
                            if version:
                                pythons[version] = str(py_path)
                except:
                    pass

        return pythons

    def get_python_version(self, python_exe: Path) -> str | None:
        """Get Python version from executable"""
        try:
            result = subprocess.run(
                [str(python_exe), '--version'],
                capture_output=True,
                text=True,
                timeout=2
            )
            output = result.stdout or result.stderr
            # Parse "Python 3.11.5" -> "3.11"
            if 'Python' in output:
                version = output.split()[1]
                major_minor = '.'.join(version.split('.')[:2])
                return major_minor
        except:
            pass
        return None

    def create_default_config(self, detected_pythons: dict):
        """Create default pymanager.json configuration"""
        config = {
            "default_version": "3.11",
            "versions": {},
            "directory_overrides": {},
            "verbose": False,
            "auto_detect": True
        }

        # Add detected Pythons
        for version, path in detected_pythons.items():
            config["versions"][version] = path

        # If no Pythons detected, use placeholder
        if not config["versions"]:
            config["versions"] = {
                "3.11": "pythons/py311/python.exe" if self.is_windows else "pythons/py311/bin/python3",
                "3.9": "pythons/py39/python.exe" if self.is_windows else "pythons/py39/bin/python3",
                "3.8": "pythons/py38/python.exe" if self.is_windows else "pythons/py38/bin/python3",
            }
            config["_note"] = "No Python installations detected. Update paths manually."

        # Add aliases
        if "3.11" in config["versions"]:
            config["versions"]["ml"] = config["versions"]["3.11"]
            config["versions"]["latest"] = config["versions"]["3.11"]

        if "3.8" in config["versions"]:
            config["versions"]["legacy"] = config["versions"]["3.8"]

        # Save config
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Created config: {self.config_file}")
        print(f"   Detected {len(detected_pythons)} Python installations")

    def add_to_path_windows(self):
        """Add PyManager to Windows PATH (HKEY_CURRENT_USER)"""
        try:
            import winreg

            # Open user environment key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                'Environment',
                0,
                winreg.KEY_ALL_ACCESS
            )

            # Get current PATH
            try:
                current_path, _ = winreg.QueryValueEx(key, 'PATH')
            except FileNotFoundError:
                current_path = ""

            # Parse PATH
            paths = [p.strip() for p in current_path.split(';') if p.strip()]

            # Remove any existing PyManager entries
            paths = [p for p in paths if 'PyManager' not in p and 'python-manager' not in p]

            # Add PyManager as FIRST entry
            manager_path = str(self.manager_dir)
            paths.insert(0, manager_path)

            # Write back
            new_path = ';'.join(paths)
            winreg.SetValueEx(key, 'PATH', 0, winreg.REG_EXPAND_SZ, new_path)
            winreg.CloseKey(key)

            print(f"✅ Added to PATH (first position): {manager_path}")
            print("⚠️  RESTART your terminal/PowerShell for PATH changes to take effect")
            return True

        except ImportError:
            print("❌ winreg module not available (not on Windows?)")
            return False
        except Exception as e:
            print(f"❌ Failed to update PATH: {e}")
            return False

    def add_to_path_unix(self):
        """Add PyManager to Unix PATH (.bashrc, .zshrc)"""
        manager_path = str(self.manager_dir)
        export_line = f'export PATH="{manager_path}:$PATH"  # PyManager'

        shell_rcs = [
            Path.home() / '.bashrc',
            Path.home() / '.zshrc',
            Path.home() / '.profile',
        ]

        updated = False
        for rc_file in shell_rcs:
            if rc_file.exists():
                # Check if already added
                content = rc_file.read_text()
                if 'PyManager' in content:
                    continue

                # Append to RC file
                with open(rc_file, 'a') as f:
                    f.write(f'\n# PyManager - Python Version Router\n')
                    f.write(f'{export_line}\n')

                print(f"✅ Added to {rc_file.name}")
                updated = True

        if updated:
            print("⚠️  Run 'source ~/.bashrc' (or restart terminal) to activate")
            return True
        else:
            print("❌ No shell RC files found. Add manually:")
            print(f"   {export_line}")
            return False

    def build_manager_executable(self):
        """Build python.exe/python from dispatcher.py using PyInstaller"""
        print("\n🔨 Building PyManager executable...")

        # Check if PyInstaller is installed
        try:
            subprocess.run(['pyinstaller', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("⚠️  PyInstaller not found. Install with: pip install pyinstaller")
            print("   Skipping executable build. Use 'python core/dispatcher.py' instead.")
            return False

        # Build spec
        exe_name = 'python.exe' if self.is_windows else 'python'
        spec_content = f"""
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['core/dispatcher.py'],
    pathex=[],
    binaries=[],
    datas=[('pymanager.json', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='{exe_name}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
        spec_file = self.manager_dir / 'pymanager.spec'
        spec_file.write_text(spec_content)

        # Run PyInstaller
        try:
            subprocess.run(
                ['pyinstaller', 'pymanager.spec', '--clean'],
                cwd=str(self.manager_dir),
                check=True
            )
            print("✅ Executable built successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Build failed: {e}")
            return False

    def create_symlinks(self):
        """Create symlinks for python3, pip, etc."""
        exe_name = 'python.exe' if self.is_windows else 'python'
        python_exe = self.manager_dir / 'dist' / exe_name

        if not python_exe.exists():
            print("⚠️  Skipping symlinks (executable not built)")
            return

        # Create python3 symlink
        symlinks = {
            'python3.exe' if self.is_windows else 'python3': python_exe,
        }

        for link_name, target in symlinks.items():
            link_path = self.manager_dir / link_name
            try:
                if link_path.exists():
                    link_path.unlink()
                if self.is_windows:
                    # Windows: copy instead of symlink
                    shutil.copy2(target, link_path)
                else:
                    # Unix: real symlink
                    link_path.symlink_to(target)
                print(f"✅ Created: {link_name}")
            except Exception as e:
                print(f"⚠️  Failed to create {link_name}: {e}")

    def install(self):
        """Main installation routine"""
        print("=" * 70)
        print("PyManager Installation - System-Wide Python PATH Hijack")
        print("=" * 70)

        # Step 1: Detect existing Pythons
        print("\n[1/5] Detecting existing Python installations...")
        detected = self.detect_existing_pythons()
        for version, path in detected.items():
            print(f"  Found: Python {version} at {path}")

        # Step 2: Create config
        print("\n[2/5] Creating configuration...")
        self.create_default_config(detected)

        # Step 3: Add to PATH
        print("\n[3/5] Adding to system PATH...")
        if self.is_windows:
            success = self.add_to_path_windows()
        else:
            success = self.add_to_path_unix()

        if not success:
            print("⚠️  Manual PATH setup required")

        # Step 4: Build executable (optional)
        print("\n[4/5] Building PyManager executable...")
        built = self.build_manager_executable()

        # Step 5: Create symlinks
        if built:
            print("\n[5/5] Creating symlinks...")
            self.create_symlinks()

        # Summary
        print("\n" + "=" * 70)
        print("✅ PyManager Installation Complete!")
        print("=" * 70)
        print("\nNext Steps:")
        print("1. RESTART your terminal/shell")
        print("2. Verify: 'python --pm-info'")
        print("3. Test: 'python <your_script.py>'")
        print("\nConfiguration:")
        print(f"  Edit: {self.config_file}")
        print("  Add Python versions")
        print("  Set directory overrides")
        print("\nVersion Control Methods:")
        print("  1. File shebang: #!pymanager:3.11")
        print("  2. Create .pyversion file in project directory")
        print("  3. Set global default in config")
        print("=" * 70)


def main():
    """Entry point for installer"""
    installer = PyManagerInstaller()
    installer.install()


if __name__ == '__main__':
    main()
