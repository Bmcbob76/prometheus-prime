"""
Predictive Healer - Pre-Execution Error Detection & Prevention
===============================================================

This system scans Python code BEFORE execution to detect potential errors
and fix them proactively. Prevents errors before they happen.

Features:
- AST-based code analysis
- Import dependency detection
- Syntax validation
- Security vulnerability scanning
- Auto-fix suggestions before execution

Version: 1.0.0 (Phase 3 - Bonus)
"""

import ast
import sys
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass


@dataclass
class PredictedIssue:
    """An issue detected before execution"""
    issue_type: str  # 'missing_import', 'syntax_error', 'security_risk', etc.
    severity: str  # 'critical', 'high', 'medium', 'low'
    line_number: Optional[int]
    message: str
    suggestion: str
    auto_fixable: bool = False
    fix_code: Optional[str] = None


class PredictiveHealer:
    """
    Scans code before execution to predict and prevent errors.

    Uses AST parsing, static analysis, and heuristics to catch issues early.
    """

    def __init__(self):
        self.stdlib_modules = self._get_stdlib_modules()

    def _get_stdlib_modules(self) -> Set[str]:
        """Get list of Python standard library modules"""
        # Common stdlib modules (partial list for performance)
        return {
            'os', 'sys', 'json', 'datetime', 'time', 'random', 'math', 're',
            'collections', 'itertools', 'functools', 'pathlib', 'subprocess',
            'typing', 'dataclasses', 'abc', 'copy', 'pickle', 'io', 'urllib',
            'http', 'logging', 'argparse', 'configparser', 'tempfile', 'shutil',
            'asyncio', 'threading', 'multiprocessing', 'queue', 'socket',
            'sqlite3', 'csv', 'xml', 'html', 'email', 'base64', 'hashlib',
            'hmac', 'secrets', 'uuid', 'decimal', 'fractions', 'statistics',
            'unittest', 'doctest', 'pdb', 'trace', 'traceback', 'warnings',
            'contextlib', 'weakref', 'gc', 'inspect', 'dis', 'ast', 'importlib',
        }

    def scan_file(self, file_path: Path) -> List[PredictedIssue]:
        """
        Scan a Python file for potential issues.

        Returns list of issues found, sorted by severity.
        """
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()

            # Issue 1: Syntax errors
            syntax_issues = self._check_syntax(code, file_path)
            issues.extend(syntax_issues)

            # If syntax errors, can't parse AST
            if syntax_issues:
                return issues

            # Parse AST
            tree = ast.parse(code, filename=str(file_path))

            # Issue 2: Missing imports
            import_issues = self._check_imports(tree, code)
            issues.extend(import_issues)

            # Issue 3: Async/await issues
            async_issues = self._check_async_patterns(tree)
            issues.extend(async_issues)

            # Issue 4: Common mistakes
            pattern_issues = self._check_common_patterns(code)
            issues.extend(pattern_issues)

            # Issue 5: Security vulnerabilities
            security_issues = self._check_security(tree, code)
            issues.extend(security_issues)

        except Exception as e:
            issues.append(PredictedIssue(
                issue_type='scan_error',
                severity='medium',
                line_number=None,
                message=f'Failed to scan file: {e}',
                suggestion='Check file encoding or permissions',
                auto_fixable=False,
            ))

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        issues.sort(key=lambda i: (severity_order.get(i.severity, 999), i.line_number or 0))

        return issues

    def _check_syntax(self, code: str, file_path: Path) -> List[PredictedIssue]:
        """Check for syntax errors"""
        issues = []

        try:
            compile(code, str(file_path), 'exec')
        except SyntaxError as e:
            issues.append(PredictedIssue(
                issue_type='syntax_error',
                severity='critical',
                line_number=e.lineno,
                message=f'Syntax error: {e.msg}',
                suggestion=f'Fix syntax error at line {e.lineno}',
                auto_fixable=False,
            ))

        return issues

    def _check_imports(self, tree: ast.AST, code: str) -> List[PredictedIssue]:
        """Check for potentially missing imports"""
        issues = []

        # Extract all imports
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module.split('.')[0])

        # Common third-party modules that need installation
        common_packages = {
            'numpy': 'numpy',
            'pandas': 'pandas',
            'matplotlib': 'matplotlib',
            'sklearn': 'scikit-learn',
            'cv2': 'opencv-python',
            'PIL': 'Pillow',
            'torch': 'torch',
            'tensorflow': 'tensorflow',
            'requests': 'requests',
            'flask': 'Flask',
            'django': 'Django',
            'fastapi': 'fastapi',
            'sqlalchemy': 'SQLAlchemy',
            'bs4': 'beautifulsoup4',
            'yaml': 'pyyaml',
        }

        for module_name in imported_modules:
            # Skip stdlib modules
            if module_name in self.stdlib_modules:
                continue

            # Check if module is likely third-party
            if module_name in common_packages:
                # Find line number
                line_num = None
                for node in ast.walk(tree):
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        if hasattr(node, 'names'):
                            for alias in node.names:
                                if alias.name.startswith(module_name):
                                    line_num = node.lineno
                                    break
                        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(module_name):
                            line_num = node.lineno
                            break

                package_name = common_packages[module_name]
                issues.append(PredictedIssue(
                    issue_type='missing_import',
                    severity='high',
                    line_number=line_num,
                    message=f'Module "{module_name}" may not be installed',
                    suggestion=f'Install with: pip install {package_name}',
                    auto_fixable=True,
                    fix_code=f'pip install {package_name}',
                ))

        return issues

    def _check_async_patterns(self, tree: ast.AST) -> List[PredictedIssue]:
        """Check for async/await issues"""
        issues = []

        # Check for coroutines that might not be awaited
        for node in ast.walk(tree):
            # asyncio.run() usage
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id == 'asyncio' and node.func.attr == 'run':
                            # Good usage
                            continue

                # Async function calls that might not be awaited
                if isinstance(node.func, ast.Name):
                    # This is a simple heuristic - in real code would need type info
                    pass

        return issues

    def _check_common_patterns(self, code: str) -> List[PredictedIssue]:
        """Check for common mistake patterns"""
        issues = []

        # Pattern 1: Mutable default arguments
        mutable_default = r'def\s+\w+\([^)]*=\s*(\[\]|\{\})\)'
        for match in re.finditer(mutable_default, code):
            line_num = code[:match.start()].count('\n') + 1
            issues.append(PredictedIssue(
                issue_type='mutable_default',
                severity='medium',
                line_number=line_num,
                message='Mutable default argument ([] or {}) detected',
                suggestion='Use None and initialize inside function',
                auto_fixable=False,
            ))

        # Pattern 2: Bare except
        bare_except = r'except\s*:'
        for match in re.finditer(bare_except, code):
            line_num = code[:match.start()].count('\n') + 1
            issues.append(PredictedIssue(
                issue_type='bare_except',
                severity='low',
                line_number=line_num,
                message='Bare except clause catches all exceptions',
                suggestion='Specify exception type: except Exception:',
                auto_fixable=False,
            ))

        return issues

    def _check_security(self, tree: ast.AST, code: str) -> List[PredictedIssue]:
        """Check for security vulnerabilities"""
        issues = []

        # Security issue 1: eval() usage
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec']:
                        issues.append(PredictedIssue(
                            issue_type='security_risk',
                            severity='critical',
                            line_number=node.lineno,
                            message=f'Use of {node.func.id}() detected - security risk',
                            suggestion=f'Avoid {node.func.id}(), use safer alternatives',
                            auto_fixable=False,
                        ))

        # Security issue 2: Shell injection risk
        shell_risk = r'subprocess\.(call|run|Popen)\([^)]*shell=True'
        for match in re.finditer(shell_risk, code):
            line_num = code[:match.start()].count('\n') + 1
            issues.append(PredictedIssue(
                issue_type='security_risk',
                severity='high',
                line_number=line_num,
                message='subprocess with shell=True - potential command injection',
                suggestion='Use shell=False and pass arguments as list',
                auto_fixable=False,
            ))

        # Security issue 3: SQL injection risk
        sql_risk = r'(execute|cursor)\s*\([^)]*%|\.format\('
        for match in re.finditer(sql_risk, code):
            line_num = code[:match.start()].count('\n') + 1
            if 'execute' in code[max(0, match.start()-50):match.start()]:
                issues.append(PredictedIssue(
                    issue_type='security_risk',
                    severity='high',
                    line_number=line_num,
                    message='Potential SQL injection - string formatting in query',
                    suggestion='Use parameterized queries with placeholders',
                    auto_fixable=False,
                ))

        return issues

    def auto_fix_imports(self, issues: List[PredictedIssue]) -> List[str]:
        """
        Automatically fix missing imports by installing packages.

        Returns list of packages that were installed.
        """
        installed = []

        for issue in issues:
            if issue.issue_type == 'missing_import' and issue.auto_fixable and issue.fix_code:
                print(f"[PREDICTIVE] Auto-fixing: {issue.message}")
                print(f"[PREDICTIVE] Running: {issue.fix_code}")

                # Extract package name from fix_code
                if issue.fix_code.startswith('pip install'):
                    import subprocess
                    try:
                        result = subprocess.run(
                            [sys.executable, '-m'] + issue.fix_code.split(),
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )

                        if result.returncode == 0:
                            print(f"[PREDICTIVE] ✓ Installed successfully")
                            installed.append(issue.fix_code.split()[-1])
                        else:
                            print(f"[PREDICTIVE] ✗ Installation failed: {result.stderr[:200]}")

                    except Exception as e:
                        print(f"[PREDICTIVE] Error: {e}")

        return installed

    def generate_report(self, issues: List[PredictedIssue]) -> str:
        """Generate human-readable report of issues"""
        if not issues:
            return "✅ No issues detected! Code looks clean."

        report_parts = []
        report_parts.append("=" * 70)
        report_parts.append("PREDICTIVE HEALER - Code Analysis Report")
        report_parts.append("=" * 70)
        report_parts.append(f"\nTotal Issues Found: {len(issues)}\n")

        # Group by severity
        by_severity = {}
        for issue in issues:
            if issue.severity not in by_severity:
                by_severity[issue.severity] = []
            by_severity[issue.severity].append(issue)

        for severity in ["critical", "high", "medium", "low"]:
            if severity not in by_severity:
                continue

            severity_issues = by_severity[severity]
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[severity]

            report_parts.append(f"\n{icon} {severity.upper()} ({len(severity_issues)} issues)")
            report_parts.append("-" * 70)

            for issue in severity_issues:
                loc = f"Line {issue.line_number}" if issue.line_number else "Unknown location"
                report_parts.append(f"\n  [{loc}] {issue.message}")
                report_parts.append(f"  💡 {issue.suggestion}")

                if issue.auto_fixable and issue.fix_code:
                    report_parts.append(f"  🔧 Auto-fix: {issue.fix_code}")

        report_parts.append("\n" + "=" * 70)

        return "\n".join(report_parts)
