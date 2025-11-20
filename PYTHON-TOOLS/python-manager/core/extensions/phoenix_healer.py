"""
Phoenix Healer - Autonomous Error Recovery System
==================================================

Named after the Phoenix - rises from the ashes (recovers from errors).

This system monitors Python execution, detects errors using Guilty Spark 343,
and automatically applies fixes. It ensures "everything heals" by maintaining
a learning database of successful fixes.

Features:
- Real-time error detection and healing
- Integration with GS343 error database
- Automatic pip package installation
- Dependency conflict resolution
- Environment repair and recovery
- Learning system that improves over time
- Healing success tracking

Version: 1.0.0
"""

import subprocess
import sys
import os
import re
import json
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from dataclasses import dataclass, asdict
import tempfile
import shutil

try:
    from .guilty_spark_343 import GuildySpark343, ErrorPattern
except ImportError:
    from guilty_spark_343 import GuildySpark343, ErrorPattern


@dataclass
class HealingRecord:
    """Record of a successful healing operation"""
    timestamp: str
    error_id: str
    error_text: str
    fix_applied: str
    success: bool
    execution_time: float
    python_version: str
    healing_method: str  # auto_install, version_switch, code_fix, env_repair


class PhoenixHealer:
    """
    Phoenix Healer - The Resurrector

    Monitors execution, detects errors, and automatically heals them
    using knowledge from Guilty Spark 343.

    "From the ashes, it rises again."
    """

    def __init__(self, gs343: Optional[GuildySpark343] = None):
        self.gs343 = gs343 or GuildySpark343()

        # Healing configuration
        self.healing_enabled = True
        self.auto_install_packages = True
        self.auto_switch_python = True
        self.max_healing_attempts = 3

        # Healing history
        self.healing_history: List[HealingRecord] = []
        self.healing_log_path = Path(__file__).parent.parent.parent / 'data' / 'phoenix_healing.json'
        self.healing_log_path.parent.mkdir(parents=True, exist_ok=True)

        self.load_healing_history()

    def heal(self, error_text: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Main healing function - detects error and applies fix.

        Returns healing result with success status and actions taken.
        """
        start_time = datetime.now()

        # Detect error using GS343
        solution = self.gs343.get_solution(error_text)

        if not solution:
            return {
                'success': False,
                'message': 'Unknown error - no healing pattern found',
                'error_analyzed': False,
            }

        print(f"\n[PHOENIX] Error detected: {solution['name']} ({solution['error_id']})")
        print(f"[PHOENIX] Severity: {solution['severity']} | Category: {solution['category']}")
        print(f"[PHOENIX] Confidence: {solution['confidence']*100:.0f}%")

        if not self.healing_enabled:
            return {
                'success': False,
                'message': 'Healing disabled',
                'solution': solution,
            }

        # Apply healing based on category
        healing_result = self._apply_healing(solution, error_text, context or {})

        # Record healing attempt
        record = HealingRecord(
            timestamp=datetime.now().isoformat(),
            error_id=solution['error_id'],
            error_text=error_text[:500],  # Truncate
            fix_applied=healing_result.get('fix_applied', 'none'),
            success=healing_result['success'],
            execution_time=(datetime.now() - start_time).total_seconds(),
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
            healing_method=healing_result.get('method', 'unknown'),
        )

        self.healing_history.append(record)
        self.save_healing_history()

        return healing_result

    def _apply_healing(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Apply appropriate healing method based on error category"""

        category = solution['category']

        # CATEGORY: IMPORT ERRORS
        if category == 'import':
            return self._heal_import_error(solution, error_text, context)

        # CATEGORY: DEPENDENCY ERRORS
        elif category == 'dependency':
            return self._heal_dependency_error(solution, error_text, context)

        # CATEGORY: ASYNC ERRORS
        elif category == 'async':
            return self._heal_async_error(solution, error_text, context)

        # CATEGORY: RUNTIME ERRORS
        elif category == 'runtime':
            return self._heal_runtime_error(solution, error_text, context)

        # CATEGORY: IO ERRORS
        elif category == 'io':
            return self._heal_io_error(solution, error_text, context)

        # CATEGORY: NETWORK ERRORS
        elif category == 'network':
            return self._heal_network_error(solution, error_text, context)

        # CATEGORY: DATABASE ERRORS
        elif category == 'database':
            return self._heal_database_error(solution, error_text, context)

        # CATEGORY: MEMORY ERRORS
        elif category == 'memory':
            return self._heal_memory_error(solution, error_text, context)

        # CATEGORY: ENCODING ERRORS
        elif category == 'encoding':
            return self._heal_encoding_error(solution, error_text, context)

        else:
            return {
                'success': False,
                'message': f'No healing method for category: {category}',
                'solution': solution,
            }

    def _heal_import_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal import errors by installing missing packages"""

        # Extract module name from error
        match = re.search(r"No module named '([^']+)'", error_text)
        if not match:
            return {'success': False, 'message': 'Could not extract module name'}

        module_name = match.group(1)

        # Get base package name (remove sub-modules)
        package_name = module_name.split('.')[0]

        print(f"[PHOENIX] Attempting to install missing package: {package_name}")

        if not self.auto_install_packages:
            return {
                'success': False,
                'message': 'Auto-install disabled',
                'recommendation': f'pip install {package_name}',
            }

        # Attempt installation
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', package_name],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                print(f"[PHOENIX] ✓ Successfully installed {package_name}")
                return {
                    'success': True,
                    'message': f'Installed {package_name}',
                    'fix_applied': f'pip install {package_name}',
                    'method': 'auto_install',
                }
            else:
                print(f"[PHOENIX] ✗ Failed to install {package_name}: {result.stderr}")
                return {
                    'success': False,
                    'message': f'Installation failed: {result.stderr[:200]}',
                }

        except subprocess.TimeoutExpired:
            return {'success': False, 'message': 'Installation timeout'}
        except Exception as e:
            return {'success': False, 'message': f'Installation error: {e}'}

    def _heal_dependency_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal dependency version conflicts"""

        # Check if fix_code is available
        if not solution.get('fix_code'):
            return {'success': False, 'message': 'No automatic fix available'}

        fix_code = solution['fix_code']

        # If it's a pip install command, execute it
        if fix_code.startswith('pip install'):
            print(f"[PHOENIX] Applying dependency fix: {fix_code}")

            try:
                # Extract pip command
                cmd_parts = fix_code.split()
                result = subprocess.run(
                    [sys.executable, '-m'] + cmd_parts,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )

                if result.returncode == 0:
                    print(f"[PHOENIX] ✓ Dependency fix applied successfully")
                    return {
                        'success': True,
                        'message': 'Fixed dependency conflict',
                        'fix_applied': fix_code,
                        'method': 'dependency_fix',
                    }
                else:
                    return {
                        'success': False,
                        'message': f'Fix failed: {result.stderr[:200]}',
                    }

            except Exception as e:
                return {'success': False, 'message': f'Error applying fix: {e}'}

        else:
            return {
                'success': False,
                'message': 'Manual fix required',
                'recommendation': fix_code,
            }

    def _heal_async_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal async/await errors"""

        # For event loop errors, we can inject nest_asyncio
        if 'event loop is already running' in error_text.lower():
            print(f"[PHOENIX] Applying async fix: Installing nest_asyncio")

            try:
                # Install nest_asyncio if not present
                subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', 'nest_asyncio'],
                    capture_output=True,
                    timeout=60,
                )

                # Create fix injection code
                fix_code = "import nest_asyncio; nest_asyncio.apply()"

                return {
                    'success': True,
                    'message': 'Event loop fix applied',
                    'fix_applied': fix_code,
                    'method': 'code_fix',
                    'injection_code': fix_code,
                }

            except Exception as e:
                return {'success': False, 'message': f'Async fix failed: {e}'}

        return {
            'success': False,
            'message': 'Manual async fix required',
            'recommendation': solution.get('solution', ''),
        }

    def _heal_runtime_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal runtime errors (limited automatic fixes)"""

        # Most runtime errors require code changes
        return {
            'success': False,
            'message': 'Runtime error requires code modification',
            'recommendation': solution.get('solution', ''),
            'fix_code': solution.get('fix_code'),
        }

    def _heal_io_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal I/O errors"""

        # For FileNotFoundError, try to create missing directories
        if 'FileNotFoundError' in error_text or 'No such file or directory' in error_text:
            match = re.search(r"'([^']+)'", error_text)
            if match:
                file_path = match.group(1)
                parent_dir = Path(file_path).parent

                try:
                    if not parent_dir.exists():
                        parent_dir.mkdir(parents=True, exist_ok=True)
                        return {
                            'success': True,
                            'message': f'Created missing directory: {parent_dir}',
                            'fix_applied': f'mkdir -p {parent_dir}',
                            'method': 'env_repair',
                        }
                except Exception as e:
                    return {'success': False, 'message': f'Failed to create directory: {e}'}

        return {
            'success': False,
            'message': 'I/O error requires manual intervention',
            'recommendation': solution.get('solution', ''),
        }

    def _heal_network_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal network errors (mostly informational)"""
        return {
            'success': False,
            'message': 'Network error cannot be automatically fixed',
            'recommendation': solution.get('solution', ''),
        }

    def _heal_database_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal database errors"""
        return {
            'success': False,
            'message': 'Database error requires manual intervention',
            'recommendation': solution.get('solution', ''),
        }

    def _heal_memory_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal memory errors"""

        # For recursion errors, try increasing limit
        if 'RecursionError' in error_text:
            try:
                current_limit = sys.getrecursionlimit()
                new_limit = current_limit * 2
                sys.setrecursionlimit(new_limit)

                return {
                    'success': True,
                    'message': f'Increased recursion limit: {current_limit} → {new_limit}',
                    'fix_applied': f'sys.setrecursionlimit({new_limit})',
                    'method': 'env_repair',
                }
            except Exception as e:
                return {'success': False, 'message': f'Failed to adjust recursion limit: {e}'}

        return {
            'success': False,
            'message': 'Memory error requires system resources',
            'recommendation': solution.get('solution', ''),
        }

    def _heal_encoding_error(self, solution: Dict, error_text: str, context: Dict) -> Dict:
        """Heal encoding errors (informational)"""
        return {
            'success': False,
            'message': 'Encoding error requires code modification',
            'recommendation': solution.get('solution', ''),
            'fix_code': solution.get('fix_code'),
        }

    def get_stats(self) -> Dict:
        """Get healing statistics"""
        total = len(self.healing_history)
        if total == 0:
            return {'total_healing_attempts': 0}

        successful = sum(1 for r in self.healing_history if r.success)

        methods = {}
        for record in self.healing_history:
            methods[record.healing_method] = methods.get(record.healing_method, 0) + 1

        return {
            'total_healing_attempts': total,
            'successful_healings': successful,
            'success_rate': successful / total * 100,
            'healing_methods': methods,
            'recent_healings': [asdict(r) for r in self.healing_history[-10:]],
        }

    def load_healing_history(self):
        """Load healing history from file"""
        if self.healing_log_path.exists():
            try:
                with open(self.healing_log_path, 'r') as f:
                    data = json.load(f)
                    self.healing_history = [HealingRecord(**r) for r in data]
                print(f"[PHOENIX] Loaded {len(self.healing_history)} healing records")
            except Exception as e:
                print(f"[PHOENIX] Warning: Failed to load healing history: {e}")

    def save_healing_history(self):
        """Save healing history to file"""
        try:
            data = [asdict(r) for r in self.healing_history]
            with open(self.healing_log_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[PHOENIX] Warning: Failed to save healing history: {e}")


# CLI Interface
if __name__ == "__main__":
    import sys

    healer = PhoenixHealer()

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "stats":
            stats = healer.get_stats()
            print("\n=== PHOENIX HEALER - Statistics ===\n")
            print(f"Total Healing Attempts: {stats.get('total_healing_attempts', 0)}")
            print(f"Successful Healings: {stats.get('successful_healings', 0)}")
            print(f"Success Rate: {stats.get('success_rate', 0):.1f}%\n")

            if 'healing_methods' in stats:
                print("Healing Methods:")
                for method, count in sorted(stats['healing_methods'].items()):
                    print(f"  {method:20} {count:4}")

        elif command == "heal":
            if len(sys.argv) > 2:
                error_text = " ".join(sys.argv[2:])
                result = healer.heal(error_text)

                print("\n=== HEALING RESULT ===\n")
                print(f"Success: {result['success']}")
                print(f"Message: {result.get('message', 'N/A')}")
                if result.get('fix_applied'):
                    print(f"Fix Applied: {result['fix_applied']}")
                if result.get('recommendation'):
                    print(f"Recommendation: {result['recommendation']}")
            else:
                print("Usage: python phoenix_healer.py heal <error_message>")

        else:
            print("Unknown command")
            print("Usage: python phoenix_healer.py [stats|heal]")
    else:
        print("\nPhoenix Healer - The Resurrector")
        print("Autonomous error recovery system")
        print("\nCommands:")
        print("  python -m pymanager.extensions.phoenix_healer stats")
        print("  python -m pymanager.extensions.phoenix_healer heal <error>")
