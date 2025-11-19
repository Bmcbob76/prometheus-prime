#!/usr/bin/env python3
"""
PyManager Remote Executor
Execute scripts on remote machines via SSH
"""

import subprocess
from pathlib import Path
from typing import Dict, Optional


class RemoteExecutor:
    """Execute Python scripts on remote machines"""

    def __init__(self, config: Dict):
        self.config = config
        self.remote_hosts = config.get('remote', {}).get('hosts', {})

    def execute_remote(self, host: str, script_path: Path, python_version: str = '3.11') -> bool:
        """Execute script on remote host via SSH"""
        print(f"🌐 Executing {script_path.name} on {host}")

        # Read script content
        with open(script_path, 'r') as f:
            script_content = f.read()

        # Create remote execution command
        remote_cmd = f"python{python_version} -c '{script_content}'"

        try:
            # Execute via SSH
            result = subprocess.run(
                ['ssh', host, remote_cmd],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                print(f"✅ Success")
                print(result.stdout)
                return True
            else:
                print(f"❌ Failed (exit code: {result.returncode})")
                print(result.stderr)
                return False

        except subprocess.TimeoutExpired:
            print(f"❌ Timeout")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False

    def copy_and_execute(self, host: str, script_path: Path, remote_path: str = '/tmp/script.py') -> bool:
        """Copy script to remote host and execute"""
        print(f"🌐 Copying and executing {script_path.name} on {host}")

        try:
            # Copy file via SCP
            subprocess.run(
                ['scp', str(script_path), f'{host}:{remote_path}'],
                check=True,
                capture_output=True
            )

            # Execute remotely
            result = subprocess.run(
                ['ssh', host, f'python {remote_path}'],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Cleanup
            subprocess.run(
                ['ssh', host, f'rm {remote_path}'],
                capture_output=True
            )

            if result.returncode == 0:
                print(f"✅ Success")
                return True
            else:
                print(f"❌ Failed")
                return False

        except Exception as e:
            print(f"❌ Error: {e}")
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Remote Executor')
    parser.add_argument('script', help='Script to execute')
    parser.add_argument('--host', required=True, help='Remote host')
    parser.add_argument('--method', choices=['inline', 'copy'], default='copy',
                        help='Execution method')

    args = parser.parse_args()

    executor = RemoteExecutor({})
    script = Path(args.script)

    if args.method == 'inline':
        executor.execute_remote(args.host, script)
    else:
        executor.copy_and_execute(args.host, script)


if __name__ == '__main__':
    main()
