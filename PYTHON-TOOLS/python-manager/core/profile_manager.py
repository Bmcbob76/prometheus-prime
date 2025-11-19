#!/usr/bin/env python3
"""
PyManager Profile Manager
Manage pre-configured dependency profiles and virtual environments
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional


class ProfileManager:
    """Manage framework stack profiles and virtual environments"""

    def __init__(self, manager_dir: Path, config: Dict):
        self.manager_dir = manager_dir
        self.config = config
        self.profiles_dir = manager_dir / 'profiles'
        self.venvs_dir = manager_dir / 'venvs'

        # Create directories if needed
        self.profiles_dir.mkdir(exist_ok=True)
        self.venvs_dir.mkdir(exist_ok=True)

    def load_profile(self, profile_name: str) -> Optional[Dict]:
        """Load profile from config or file"""
        # Check config first
        framework_stacks = self.config.get('framework_stacks', {})
        if profile_name in framework_stacks:
            return framework_stacks[profile_name]

        # Check profiles directory
        profile_file = self.profiles_dir / f"{profile_name}.json"
        if profile_file.exists():
            with open(profile_file, 'r') as f:
                return json.load(f)

        return None

    def list_profiles(self):
        """List all available profiles"""
        profiles = {}

        # From config
        framework_stacks = self.config.get('framework_stacks', {})
        for name, profile in framework_stacks.items():
            profiles[name] = {
                'source': 'config',
                'python': profile.get('python', '3.11'),
                'packages': len(profile.get('packages', {})),
            }

        # From files
        for profile_file in self.profiles_dir.glob('*.json'):
            name = profile_file.stem
            if name not in profiles:
                try:
                    with open(profile_file, 'r') as f:
                        profile = json.load(f)
                    profiles[name] = {
                        'source': 'file',
                        'python': profile.get('python', '3.11'),
                        'packages': len(profile.get('packages', {})),
                    }
                except:
                    pass

        return profiles

    def create_venv(self, venv_path: Path, python_version: str) -> bool:
        """Create virtual environment with specified Python version"""
        # Get Python executable
        from dispatcher import PyManagerDispatcher

        dispatcher = PyManagerDispatcher()
        python_exe = dispatcher.get_python_executable(python_version)

        print(f"Creating venv at {venv_path} with Python {python_version}...")

        try:
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

    def pip_install(self, venv_path: Path, package_spec: str) -> bool:
        """Install package in virtual environment"""
        # Get pip from venv
        if sys.platform == 'win32':
            pip_exe = venv_path / 'Scripts' / 'pip.exe'
        else:
            pip_exe = venv_path / 'bin' / 'pip'

        if not pip_exe.exists():
            print(f"❌ Pip not found in venv: {pip_exe}")
            return False

        try:
            subprocess.run(
                [str(pip_exe), 'install', package_spec],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            return True

        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package_spec}: {e.stdout.decode()}")
            return False

    def install_profile(self, profile_name: str, force: bool = False) -> bool:
        """
        Install profile: create venv and install all dependencies

        Args:
            profile_name: Name of profile to install
            force: Recreate venv if exists

        Returns:
            Success status
        """
        # Load profile
        profile = self.load_profile(profile_name)
        if not profile:
            print(f"❌ Profile '{profile_name}' not found")
            print("\nAvailable profiles:")
            for name in self.list_profiles():
                print(f"  • {name}")
            return False

        # Get profile details
        python_version = profile.get('python', '3.11')
        packages = profile.get('packages', {})

        print("=" * 60)
        print(f"Installing Profile: {profile_name}")
        print("=" * 60)
        print(f"Python Version: {python_version}")
        print(f"Packages: {len(packages)}")
        print()

        # Create venv path
        venv_path = self.venvs_dir / profile_name

        # Check if exists
        if venv_path.exists():
            if not force:
                print(f"⚠️  Profile venv already exists: {venv_path}")
                print("   Use --force to recreate")
                return False
            else:
                # Remove existing venv
                import shutil
                shutil.rmtree(venv_path)
                print(f"🗑️  Removed existing venv")

        # Create venv
        if not self.create_venv(venv_path, python_version):
            return False

        # Install packages
        print(f"\n📦 Installing {len(packages)} packages...")
        failed = []

        for package, version_spec in packages.items():
            package_str = f"{package}{version_spec}"
            print(f"   Installing {package_str}...", end=' ')

            if self.pip_install(venv_path, package_str):
                print("✅")
            else:
                print("❌")
                failed.append(package_str)

        # Summary
        print("\n" + "=" * 60)
        if not failed:
            print(f"✅ Profile '{profile_name}' installed successfully!")
        else:
            print(f"⚠️  Profile '{profile_name}' installed with {len(failed)} failures")
            print("Failed packages:")
            for pkg in failed:
                print(f"  • {pkg}")

        print(f"\nVirtual Environment: {venv_path}")
        print("\nActivate with:")
        if sys.platform == 'win32':
            print(f"  {venv_path}\\Scripts\\activate.bat")
        else:
            print(f"  source {venv_path}/bin/activate")

        print("=" * 60)

        return len(failed) == 0

    def create_profile(self, profile_name: str, python_version: str, packages: Dict[str, str]):
        """Create a new profile definition"""
        profile = {
            'python': python_version,
            'packages': packages,
            'description': f'Custom profile: {profile_name}',
        }

        # Save to file
        profile_file = self.profiles_dir / f"{profile_name}.json"
        with open(profile_file, 'w') as f:
            json.dump(profile, f, indent=2)

        print(f"✅ Profile '{profile_name}' created at {profile_file}")

    def show_profile(self, profile_name: str):
        """Display profile details"""
        profile = self.load_profile(profile_name)
        if not profile:
            print(f"❌ Profile '{profile_name}' not found")
            return

        print("=" * 60)
        print(f"Profile: {profile_name}")
        print("=" * 60)
        print(f"Python Version: {profile.get('python', 'N/A')}")
        print(f"Description: {profile.get('description', 'N/A')}")

        packages = profile.get('packages', {})
        print(f"\nPackages ({len(packages)}):")
        for package, version in packages.items():
            print(f"  • {package}{version}")

        auto_fixes = profile.get('auto_fixes', [])
        if auto_fixes:
            print(f"\nAuto-Fixes:")
            for fix in auto_fixes:
                print(f"  • {fix}")

        print("=" * 60)

    def activate_profile(self, profile_name: str):
        """Activate a profile's virtual environment"""
        venv_path = self.venvs_dir / profile_name

        if not venv_path.exists():
            print(f"❌ Profile '{profile_name}' venv not found")
            print(f"   Install first: python -m pymanager install-stack {profile_name}")
            return

        # Show activation command
        print(f"Activate {profile_name} profile:")
        if sys.platform == 'win32':
            activate_script = venv_path / 'Scripts' / 'activate.bat'
            print(f"  {activate_script}")
        else:
            activate_script = venv_path / 'bin' / 'activate'
            print(f"  source {activate_script}")


def main():
    """CLI interface for profile manager"""
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Profile Manager')
    parser.add_argument('command', choices=['list', 'show', 'install', 'activate'],
                        help='Command to execute')
    parser.add_argument('profile', nargs='?', help='Profile name')
    parser.add_argument('--force', action='store_true', help='Force reinstall')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent
    config_file = manager_dir / 'pymanager.json'

    if not config_file.exists():
        print(f"❌ Config not found: {config_file}")
        sys.exit(1)

    with open(config_file, 'r') as f:
        config = json.load(f)

    # Create manager
    manager = ProfileManager(manager_dir, config)

    # Execute command
    if args.command == 'list':
        profiles = manager.list_profiles()
        print("Available Profiles:")
        print("=" * 60)
        for name, info in profiles.items():
            source = info['source']
            python = info['python']
            packages = info['packages']
            print(f"  {name:20} [Python {python}] ({packages} packages) [{source}]")
        print("=" * 60)

    elif args.command == 'show':
        if not args.profile:
            print("❌ Profile name required")
            sys.exit(1)
        manager.show_profile(args.profile)

    elif args.command == 'install':
        if not args.profile:
            print("❌ Profile name required")
            sys.exit(1)
        success = manager.install_profile(args.profile, force=args.force)
        sys.exit(0 if success else 1)

    elif args.command == 'activate':
        if not args.profile:
            print("❌ Profile name required")
            sys.exit(1)
        manager.activate_profile(args.profile)


if __name__ == '__main__':
    main()
