#!/usr/bin/env python3
"""
PyManager Parallel Executor
Run multiple Python scripts concurrently
"""

import subprocess
import concurrent.futures
import time
from pathlib import Path
from typing import Dict, List, Tuple


class ParallelExecutor:
    """Execute multiple scripts in parallel"""

    def __init__(self, config: Dict):
        self.config = config
        self.max_workers = config.get('parallel', {}).get('max_workers', 4)

    def execute_script(self, script_path: Path, python_exe: Path = None) -> Tuple[int, float, str]:
        """Execute single script and return (exit_code, duration, output)"""
        start_time = time.time()

        python = python_exe or Path('python')

        try:
            result = subprocess.run(
                [str(python), str(script_path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            duration = time.time() - start_time
            output = result.stdout + result.stderr

            return result.returncode, duration, output

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return -1, duration, "TIMEOUT"
        except Exception as e:
            duration = time.time() - start_time
            return -1, duration, str(e)

    def execute_parallel(self, scripts: List[Path], max_workers: int = None) -> Dict:
        """Execute multiple scripts in parallel"""
        workers = max_workers or self.max_workers

        print(f"🚀 Executing {len(scripts)} scripts in parallel (max {workers} workers)")

        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all tasks
            future_to_script = {
                executor.submit(self.execute_script, script): script
                for script in scripts
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_script):
                script = future_to_script[future]

                try:
                    exit_code, duration, output = future.result()

                    results[str(script)] = {
                        'exit_code': exit_code,
                        'duration': duration,
                        'success': exit_code == 0,
                        'output': output
                    }

                    status = "✅" if exit_code == 0 else "❌"
                    print(f"  {status} {script.name} ({duration:.2f}s)")

                except Exception as e:
                    results[str(script)] = {
                        'exit_code': -1,
                        'duration': 0,
                        'success': False,
                        'output': str(e)
                    }
                    print(f"  ❌ {script.name} (error)")

        # Summary
        successful = sum(1 for r in results.values() if r['success'])
        total_time = max(r['duration'] for r in results.values())

        print(f"\n📊 Summary:")
        print(f"   Total scripts: {len(scripts)}")
        print(f"   Successful: {successful}")
        print(f"   Failed: {len(scripts) - successful}")
        print(f"   Total time: {total_time:.2f}s")

        return results


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description='PyManager Parallel Executor')
    parser.add_argument('scripts', nargs='+', help='Scripts to execute')
    parser.add_argument('--workers', type=int, help='Max parallel workers')

    args = parser.parse_args()

    config = {}
    executor = ParallelExecutor(config)

    scripts = [Path(s) for s in args.scripts]
    executor.execute_parallel(scripts, args.workers)


if __name__ == '__main__':
    main()
