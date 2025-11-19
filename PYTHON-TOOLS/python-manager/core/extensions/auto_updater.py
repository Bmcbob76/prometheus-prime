#!/usr/bin/env python3
"""
PyManager Auto-Updater - Automatic Version Management
Auto-download and install Python versions, update PyManager itself
"""

import sys
import subprocess
import json
import platform
import urllib.request
import urllib.error
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class PythonDownloader:
    """Download and install Python versions automatically"""

    # Official Python download URLs
    PYTHON_URLS = {
        'windows': {
            '3.11': 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe',
            '3.10': 'https://www.python.org/ftp/python/3.10.14/python-3.10.14-amd64.exe',
            '3.9': 'https://www.python.org/ftp/python/3.9.19/python-3.9.19-amd64.exe',
        },
        'darwin': {  # macOS
            '3.11': 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-macos11.pkg',
            '3.10': 'https://www.python.org/ftp/python/3.10.14/python-3.10.14-macos11.pkg',
            '3.9': 'https://www.python.org/ftp/python/3.9.19/python-3.9.19-macos11.pkg',
        },
    }

    def __init__(self, manager_dir: Path):
        self.manager_dir = manager_dir
        self.pythons_dir = manager_dir / 'pythons'
        self.pythons_dir.mkdir(exist_ok=True)

        self.system = platform.system().lower()

    def get_download_url(self, version: str) -> Optional[str]:
        """Get download URL for Python version"""
        system_urls = self.PYTHON_URLS.get(self.system, {})
        return system_urls.get(version)

    def download_python(self, version: str, output_file: Path) -> bool:
        """Download Python installer"""
        url = self.get_download_url(version)

        if not url:
            print(f"❌ No download URL for Python {version} on {self.system}")
            return False

        print(f"📥 Downloading Python {version} from {url}")

        try:
            def progress_hook(block_num, block_size, total_size):
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\r   Progress: {percent:.1f}% ({downloaded}/{total_size} bytes)", end='')

            urllib.request.urlretrieve(url, output_file, reporthook=progress_hook)
            print()  # Newline after progress
            print(f"✅ Downloaded to {output_file}")
            return True

        except urllib.error.URLError as e:
            print(f"❌ Download failed: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return False

    def install_python_windows(self, installer_path: Path, install_dir: Path) -> bool:
        """Install Python on Windows"""
        print(f"🔧 Installing Python to {install_dir}")

        try:
            # Silent install with all features
            result = subprocess.run([
                str(installer_path),
                '/quiet',
                f'TargetDir={install_dir}',
                'InstallAllUsers=0',
                'PrependPath=0',  # Don't modify PATH
                'Include_pip=1',
                'Include_test=0',
            ], check=True)

            print("✅ Installation complete")
            return True

        except subprocess.CalledProcessError as e:
            print(f"❌ Installation failed: {e}")
            return False

    def install_python_macos(self, installer_path: Path, install_dir: Path) -> bool:
        """Install Python on macOS"""
        print(f"🔧 Installing Python (requires sudo)")

        try:
            # macOS installer requires sudo
            subprocess.run([
                'sudo', 'installer',
                '-pkg', str(installer_path),
                '-target', '/'
            ], check=True)

            # Python on macOS installs to /Library/Frameworks/Python.framework
            # Create symlink to our pythons directory
            framework_version = installer_path.name.split('-')[1][:4]  # e.g., "3.11"
            framework_path = Path(f'/Library/Frameworks/Python.framework/Versions/{framework_version}/bin/python3')

            if framework_path.exists():
                (install_dir / 'python3').symlink_to(framework_path)
                print("✅ Installation complete")
                return True
            else:
                print("⚠️  Installation succeeded but Python not found at expected location")
                return False

        except subprocess.CalledProcessError as e:
            print(f"❌ Installation failed: {e}")
            return False

    def auto_install_python(self, version: str) -> bool:
        """
        Automatically download and install Python version

        Returns:
            Success status
        """
        print("=" * 70)
        print(f"Auto-Installing Python {version}")
        print("=" * 70)

        # Check if already installed
        version_dir = self.pythons_dir / f'py{version.replace(".", "")}'
        if version_dir.exists():
            print(f"⚠️  Python {version} already installed at {version_dir}")
            return True

        # Download installer
        installer_name = f'python-{version}-installer'
        installer_ext = '.exe' if self.system == 'windows' else '.pkg'
        installer_path = self.pythons_dir / (installer_name + installer_ext)

        if not self.download_python(version, installer_path):
            return False

        # Install
        version_dir.mkdir(exist_ok=True)

        if self.system == 'windows':
            success = self.install_python_windows(installer_path, version_dir)
        elif self.system == 'darwin':
            success = self.install_python_macos(installer_path, version_dir)
        else:
            print(f"❌ Automatic installation not supported on {self.system}")
            print("   Please install Python manually")
            success = False

        # Cleanup installer
        try:
            installer_path.unlink()
        except:
            pass

        if success:
            print("\n" + "=" * 70)
            print(f"✅ Python {version} installed successfully!")
            print(f"   Location: {version_dir}")
            print("=" * 70)

        return success


class PyManagerUpdater:
    """Update PyManager itself"""

    GITHUB_REPO = "Bmcbob76/python-manager"
    GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

    def __init__(self, manager_dir: Path):
        self.manager_dir = manager_dir
        self.current_version = self.get_current_version()

    def get_current_version(self) -> str:
        """Get current PyManager version"""
        try:
            version_file = self.manager_dir / 'VERSION'
            if version_file.exists():
                return version_file.read_text().strip()

            # Try to get from __init__.py
            init_file = self.manager_dir / 'core' / '__init__.py'
            if init_file.exists():
                content = init_file.read_text()
                for line in content.split('\n'):
                    if '__version__' in line:
                        version = line.split('=')[1].strip().strip('"\'')
                        return version

        except:
            pass

        return "unknown"

    def check_for_updates(self) -> Optional[Dict]:
        """Check if updates are available"""
        try:
            req = urllib.request.Request(
                self.GITHUB_API,
                headers={'Accept': 'application/vnd.github.v3+json'}
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read())

            latest_version = data.get('tag_name', '').lstrip('v')
            current_version = self.current_version.lstrip('v')

            if latest_version and latest_version != current_version:
                return {
                    'version': latest_version,
                    'url': data.get('html_url'),
                    'download_url': data.get('zipball_url'),
                    'release_notes': data.get('body', 'No release notes available'),
                }

        except Exception as e:
            print(f"⚠️  Could not check for updates: {e}")

        return None

    def show_update_info(self):
        """Display update information"""
        print("=" * 70)
        print("PyManager Update Check")
        print("=" * 70)
        print(f"Current Version: {self.current_version}")

        update_info = self.check_for_updates()

        if update_info:
            print(f"Latest Version:  {update_info['version']}")
            print()
            print("🎉 New version available!")
            print()
            print("Release Notes:")
            print(update_info['release_notes'][:500])
            print()
            print(f"Download: {update_info['url']}")
            print()
            print("To update:")
            print("  1. Visit the URL above")
            print("  2. Download latest release")
            print("  3. Extract and run install.py")
        else:
            print()
            print("✅ You are running the latest version")

        print("=" * 70)


class AutoUpdateManager:
    """Manage automatic updates for Python and PyManager"""

    def __init__(self, config: Dict, manager_dir: Path):
        self.config = config
        self.manager_dir = manager_dir

        self.python_downloader = PythonDownloader(manager_dir)
        self.pymanager_updater = PyManagerUpdater(manager_dir)

        # Auto-update configuration
        auto_update_config = config.get('auto_update', {})
        self.auto_install_python = auto_update_config.get('auto_install_python', False)
        self.check_for_updates = auto_update_config.get('check_for_updates', True)

    def ensure_python_version(self, version: str) -> bool:
        """
        Ensure Python version is available, auto-install if not

        Returns:
            True if version is available or was successfully installed
        """
        # Check if version exists
        versions = self.config.get('versions', {})

        if version in versions:
            python_path = self.manager_dir / versions[version]
            if python_path.exists():
                return True

        # Not found, attempt auto-install if enabled
        if self.auto_install_python:
            print(f"⚙️  Python {version} not found, attempting auto-install...")
            return self.python_downloader.auto_install_python(version)
        else:
            print(f"❌ Python {version} not found")
            print("   Enable auto-install with: python -m pymanager.auto_updater enable-auto-install")
            return False

    def check_pymanager_updates(self):
        """Check for PyManager updates"""
        if not self.check_for_updates:
            return

        self.pymanager_updater.show_update_info()


def main():
    """CLI for auto-updater"""
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Auto-Updater')
    parser.add_argument('command', choices=[
        'check-updates',
        'install-python',
        'enable-auto-install',
        'disable-auto-install'
    ], help='Command to execute')
    parser.add_argument('--version', help='Python version to install (e.g., 3.11)')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent.parent
    config_file = manager_dir / 'pymanager.json'

    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    # Create updater
    updater = AutoUpdateManager(config, manager_dir)

    # Execute command
    if args.command == 'check-updates':
        updater.check_pymanager_updates()

    elif args.command == 'install-python':
        if not args.version:
            print("❌ --version required")
            sys.exit(1)

        success = updater.python_downloader.auto_install_python(args.version)
        sys.exit(0 if success else 1)

    elif args.command == 'enable-auto-install':
        config.setdefault('auto_update', {})['auto_install_python'] = True
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Auto-install Python enabled")

    elif args.command == 'disable-auto-install':
        config.setdefault('auto_update', {})['auto_install_python'] = False
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Auto-install Python disabled")


if __name__ == '__main__':
    main()
