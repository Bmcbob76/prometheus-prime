#!/usr/bin/env python3
"""
PyManager Uninstaller - Remove PATH Hijack
Removes PyManager from system PATH and restores original state
"""

import os
import sys
import platform
from pathlib import Path
import shutil


class PyManagerUninstaller:
    """Handles complete removal of PyManager"""

    def __init__(self):
        self.manager_dir = Path(__file__).parent.resolve()
        self.is_windows = platform.system() == "Windows"

    def remove_from_path_windows(self):
        """Remove PyManager from Windows PATH"""
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
                print("⚠️  PATH variable not found")
                return False

            # Parse PATH and remove PyManager entries
            paths = [p.strip() for p in current_path.split(';') if p.strip()]
            original_count = len(paths)

            # Filter out PyManager paths
            paths = [p for p in paths if 'PyManager' not in p and 'python-manager' not in p]
            removed_count = original_count - len(paths)

            if removed_count == 0:
                print("ℹ️  PyManager not found in PATH")
                return True

            # Write back
            new_path = ';'.join(paths)
            winreg.SetValueEx(key, 'PATH', 0, winreg.REG_EXPAND_SZ, new_path)
            winreg.CloseKey(key)

            print(f"✅ Removed {removed_count} PyManager entries from PATH")
            return True

        except ImportError:
            print("❌ winreg module not available")
            return False
        except Exception as e:
            print(f"❌ Failed to update PATH: {e}")
            return False

    def remove_from_path_unix(self):
        """Remove PyManager from Unix shell RC files"""
        shell_rcs = [
            Path.home() / '.bashrc',
            Path.home() / '.zshrc',
            Path.home() / '.profile',
        ]

        removed = False
        for rc_file in shell_rcs:
            if not rc_file.exists():
                continue

            # Read file
            lines = rc_file.read_text().splitlines()
            original_count = len(lines)

            # Filter out PyManager lines
            filtered_lines = []
            skip_next = False
            for line in lines:
                if 'PyManager' in line or skip_next:
                    skip_next = False
                    continue
                if line.strip() == '# PyManager - Python Version Router':
                    skip_next = True
                    continue
                filtered_lines.append(line)

            if len(filtered_lines) < original_count:
                # Write back
                rc_file.write_text('\n'.join(filtered_lines) + '\n')
                print(f"✅ Cleaned {rc_file.name}")
                removed = True

        if removed:
            print("⚠️  Run 'source ~/.bashrc' (or restart terminal) to apply")
            return True
        else:
            print("ℹ️  PyManager not found in shell RC files")
            return True

    def clean_build_artifacts(self):
        """Remove build artifacts"""
        artifacts = ['build', 'dist', '__pycache__', '*.spec']

        print("\n🧹 Cleaning build artifacts...")
        for item in ['build', 'dist', '__pycache__']:
            item_path = self.manager_dir / item
            if item_path.exists():
                shutil.rmtree(item_path)
                print(f"   Removed: {item}/")

        # Remove spec files
        for spec_file in self.manager_dir.glob('*.spec'):
            spec_file.unlink()
            print(f"   Removed: {spec_file.name}")

    def backup_config(self):
        """Backup pymanager.json before uninstall"""
        config_file = self.manager_dir / 'pymanager.json'
        if config_file.exists():
            backup_file = self.manager_dir / 'pymanager.json.backup'
            shutil.copy2(config_file, backup_file)
            print(f"💾 Config backed up to: {backup_file}")
            return True
        return False

    def uninstall(self):
        """Main uninstallation routine"""
        print("=" * 70)
        print("PyManager Uninstaller - Removing System-Wide Python PATH Hijack")
        print("=" * 70)

        # Confirm
        print(f"\n⚠️  This will remove PyManager from: {self.manager_dir}")
        print("   - Remove from system PATH")
        print("   - Clean build artifacts")
        print("   - Backup configuration")
        print()
        response = input("Continue? [y/N]: ").strip().lower()

        if response not in ['y', 'yes']:
            print("❌ Uninstall cancelled")
            return

        # Backup config
        print("\n[1/3] Backing up configuration...")
        self.backup_config()

        # Remove from PATH
        print("\n[2/3] Removing from system PATH...")
        if self.is_windows:
            success = self.remove_from_path_windows()
        else:
            success = self.remove_from_path_unix()

        if success:
            print("⚠️  RESTART your terminal for PATH changes to take effect")

        # Clean artifacts
        print("\n[3/3] Cleaning build artifacts...")
        self.clean_build_artifacts()

        # Summary
        print("\n" + "=" * 70)
        print("✅ PyManager Uninstall Complete!")
        print("=" * 70)
        print("\nWhat was done:")
        print("  ✅ Removed from system PATH")
        print("  ✅ Cleaned build artifacts")
        print("  ✅ Backed up configuration")
        print("\nWhat remains:")
        print(f"  • Source files: {self.manager_dir}")
        print(f"  • Configuration backup: pymanager.json.backup")
        print("\nTo completely remove:")
        print(f"  rm -rf {self.manager_dir}  # (or delete folder manually)")
        print("\nTo reinstall:")
        print("  python install.py")
        print("=" * 70)


def main():
    """Entry point for uninstaller"""
    uninstaller = PyManagerUninstaller()
    uninstaller.uninstall()


if __name__ == '__main__':
    main()
