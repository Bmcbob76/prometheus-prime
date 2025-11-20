#!/usr/bin/env python3
"""
PyManager Build Script
Builds standalone executable using PyInstaller
"""

import subprocess
import sys
import platform
from pathlib import Path
import shutil


def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        result = subprocess.run(
            ['pyinstaller', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        print(f"✅ PyInstaller found: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ PyInstaller not found")
        print("   Install with: pip install pyinstaller")
        return False


def build_executable():
    """Build PyManager executable"""
    manager_dir = Path(__file__).parent.resolve()
    is_windows = platform.system() == "Windows"
    exe_name = 'python' + ('.exe' if is_windows else '')

    print("=" * 60)
    print("PyManager Build - Creating Standalone Executable")
    print("=" * 60)

    # Check PyInstaller
    if not check_pyinstaller():
        return False

    # Build command
    build_args = [
        'pyinstaller',
        '--onefile',                    # Single executable
        '--name', exe_name,              # Output name
        '--clean',                       # Clean build
        '--noconfirm',                   # Overwrite without asking
        '--console',                     # Console app
        '--add-data', f'pymanager.json{os.pathsep}.',  # Include config
        'core/dispatcher.py',            # Main script
    ]

    # Add icon if exists
    icon_file = manager_dir / 'python.ico'
    if icon_file.exists() and is_windows:
        build_args.extend(['--icon', str(icon_file)])

    # Additional options for smaller size
    build_args.extend([
        '--strip',                       # Strip symbols (Unix)
        '--noupx',                       # Skip UPX (can cause issues)
    ])

    print(f"\n🔨 Building {exe_name}...")
    print(f"   Command: {' '.join(build_args)}")

    try:
        result = subprocess.run(
            build_args,
            cwd=str(manager_dir),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        print("✅ Build successful!")

        # Check output
        dist_dir = manager_dir / 'dist'
        exe_path = dist_dir / exe_name

        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"\n📦 Executable created:")
            print(f"   Path: {exe_path}")
            print(f"   Size: {size_mb:.2f} MB")

            # Create symlinks/copies
            create_aliases(exe_path, dist_dir, is_windows)

            # Copy config to dist
            config_src = manager_dir / 'pymanager.json'
            config_dst = dist_dir / 'pymanager.json'
            if config_src.exists():
                shutil.copy2(config_src, config_dst)
                print(f"   Config: {config_dst}")

            print("\n✅ Build complete! Executable ready in dist/")
            print(f"\n🚀 Next steps:")
            print(f"   1. Copy dist/{exe_name} to your desired location")
            print(f"   2. Add that location to PATH (first position)")
            print(f"   3. Copy pymanager.json to same directory")
            print(f"   4. Restart terminal and test: {exe_name} --pm-info")

            return True
        else:
            print(f"❌ Executable not found at {exe_path}")
            return False

    except subprocess.CalledProcessError as e:
        print(f"\n❌ Build failed!")
        print(e.stdout)
        return False


def create_aliases(exe_path: Path, dist_dir: Path, is_windows: bool):
    """Create python3, python3.exe aliases"""
    aliases = ['python3']
    if is_windows:
        aliases = ['python3.exe']

    for alias in aliases:
        alias_path = dist_dir / alias
        try:
            if alias_path.exists():
                alias_path.unlink()

            if is_windows:
                # Windows: copy the exe
                shutil.copy2(exe_path, alias_path)
            else:
                # Unix: create symlink
                alias_path.symlink_to(exe_path.name)

            print(f"   Alias: {alias_path}")
        except Exception as e:
            print(f"   ⚠️  Could not create {alias}: {e}")


def clean_build():
    """Clean build artifacts"""
    manager_dir = Path(__file__).parent.resolve()
    clean_dirs = ['build', 'dist', '__pycache__']
    clean_files = ['*.spec']

    print("\n🧹 Cleaning build artifacts...")
    for dir_name in clean_dirs:
        dir_path = manager_dir / dir_name
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"   Removed: {dir_name}/")

    for pattern in clean_files:
        for file in manager_dir.glob(pattern):
            file.unlink()
            print(f"   Removed: {file.name}")


def main():
    """Main build entry point"""
    import os

    if len(sys.argv) > 1 and sys.argv[1] == 'clean':
        clean_build()
        print("✅ Clean complete")
        return

    # Build
    success = build_executable()

    if success:
        print("\n" + "=" * 60)
        print("✅ Build Successful!")
        print("=" * 60)
    else:
        print("\n❌ Build failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
