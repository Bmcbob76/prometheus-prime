#!/usr/bin/env python3
"""
PyManager Security Validator - Security Hardening
Validates scripts, paths, and Python executables for security threats
"""

import re
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import subprocess


class SecurityValidator:
    """Security validation for PyManager operations"""

    # Dangerous code patterns that should trigger warnings
    DANGEROUS_PATTERNS = [
        (r'eval\s*\(', 'eval() detected - code injection risk'),
        (r'exec\s*\(', 'exec() detected - code execution risk'),
        (r'__import__\s*\(', '__import__() detected - dynamic import risk'),
        (r'compile\s*\(.*?\bexec\b', 'compile() with exec mode - code execution risk'),
        (r'os\.system\s*\(', 'os.system() detected - command injection risk'),
        (r'subprocess\.call\s*\(.*?shell\s*=\s*True', 'subprocess with shell=True - command injection risk'),
        (r'pickle\.loads?\s*\(', 'pickle.load() detected - deserialization risk'),
        (r'yaml\.load\s*\((?!.*?Loader)', 'yaml.load() without safe loader - deserialization risk'),
        (r'input\s*\([^)]*\)\s*\)', 'input() in dangerous context'),
        (r'open\s*\(.*?[\'\"]w[\'\"].*?\)\s*\.write\s*\(.*?input', 'Writing user input to file'),
    ]

    # Blocked directory patterns (paths that should NEVER be executed)
    BLOCKED_PATHS = [
        r'.*[\\/]Temp[\\/].*\.py$',
        r'.*[\\/]AppData[\\/]Local[\\/]Temp[\\/].*\.py$',
        r'.*[\\/]\.tmp[\\/].*\.py$',
        r'^[\\/]tmp[\\/].*\.py$',
        r'.*\.tmp\.py$',
        r'.*[\\/]Downloads[\\/].*\.py$',  # Suspicious
    ]

    # Allowed directory patterns (paths that are always safe)
    ALLOWED_PATHS = [
        r'.*[\\/]ECHO_PRIME[\\/].*',
        r'.*[\\/]Projects[\\/].*',
        r'.*[\\/]Development[\\/].*',
        r'.*[\\/]Code[\\/].*',
        r'.*[\\/]src[\\/].*',
    ]

    # Known malicious package names
    MALICIOUS_PACKAGES = [
        'requests2',  # Typosquatting of 'requests'
        'python3-dateutil',  # Typosquatting of 'python-dateutil'
        'urllib4',  # Typosquatting of 'urllib3'
        'setup-tools',  # Typosquatting of 'setuptools'
    ]

    def __init__(self, config: Dict):
        self.config = config
        self.security_config = config.get('security', {})
        self.enabled = self.security_config.get('enabled', True)
        self.strict_mode = self.security_config.get('strict_mode', False)

        # Load custom patterns from config
        self.custom_blocked_paths = self.security_config.get('blocked_paths', [])
        self.custom_allowed_paths = self.security_config.get('allowed_paths', [])

    def validate_script_path(self, script_path: Path) -> Tuple[bool, Optional[str]]:
        """
        Validate script path for security

        Returns:
            (is_safe, reason)
        """
        if not self.enabled:
            return True, None

        script_str = str(script_path.resolve())

        # Check blocked paths first
        for pattern in self.BLOCKED_PATHS + self.custom_blocked_paths:
            if re.match(pattern, script_str, re.IGNORECASE):
                return False, f"Blocked path pattern: {pattern}"

        # Check allowed paths (if strict mode)
        if self.strict_mode:
            is_allowed = False
            for pattern in self.ALLOWED_PATHS + self.custom_allowed_paths:
                if re.match(pattern, script_str, re.IGNORECASE):
                    is_allowed = True
                    break

            if not is_allowed:
                return False, f"Path not in allowed list (strict mode enabled)"

        # Check if file exists and is readable
        if not script_path.exists():
            return False, "File does not exist"

        if not script_path.is_file():
            return False, "Path is not a file"

        try:
            # Test readability
            with open(script_path, 'r') as f:
                f.read(1)
        except PermissionError:
            return False, "Permission denied"
        except Exception as e:
            return False, f"Cannot read file: {e}"

        return True, None

    def scan_script_content(self, script_path: Path) -> List[Tuple[str, str, int]]:
        """
        Scan script for dangerous code patterns

        Returns:
            List of (pattern_description, matched_code, line_number)
        """
        if not self.enabled:
            return []

        warnings = []

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            for pattern, description in self.DANGEROUS_PATTERNS:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        warnings.append((description, line.strip(), i))

        except Exception as e:
            # Silently fail - security scanning is best-effort
            pass

        return warnings

    def validate_python_executable(self, python_path: Path) -> Tuple[bool, Optional[str]]:
        """
        Validate Python executable for security

        Returns:
            (is_safe, reason)
        """
        if not self.enabled:
            return True, None

        # Check if exists
        if not python_path.exists():
            return False, "Python executable not found"

        # Check if actually executable
        if not python_path.is_file():
            return False, "Python path is not a file"

        # Try to get version (validates it's actually Python)
        try:
            result = subprocess.run(
                [str(python_path), '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                return False, "Python executable validation failed"

            version_output = result.stdout or result.stderr

            if 'Python' not in version_output:
                return False, "Not a valid Python executable"

        except subprocess.TimeoutExpired:
            return False, "Python executable timeout"
        except Exception as e:
            return False, f"Python validation error: {e}"

        # Optional: Check hash against known good hashes
        if self.security_config.get('verify_python_hashes', False):
            known_hashes = self.security_config.get('python_hashes', {})
            if known_hashes:
                current_hash = self._hash_file(python_path)
                python_version = version_output.split()[1]

                if python_version in known_hashes:
                    if current_hash != known_hashes[python_version]:
                        return False, f"Python executable hash mismatch (possible tampering)"

        return True, None

    def check_malicious_imports(self, imports: List[str]) -> List[str]:
        """
        Check for known malicious package names

        Returns:
            List of malicious package names found
        """
        if not self.enabled:
            return []

        malicious_found = []

        for imp in imports:
            if imp.lower() in [p.lower() for p in self.MALICIOUS_PACKAGES]:
                malicious_found.append(imp)

        # Add custom malicious packages from config
        custom_malicious = self.security_config.get('malicious_packages', [])
        for imp in imports:
            if imp.lower() in [p.lower() for p in custom_malicious]:
                malicious_found.append(imp)

        return malicious_found

    def validate_wrapper_injection(self, wrapper_code: str) -> Tuple[bool, Optional[str]]:
        """
        Validate auto-fix wrapper code before injection

        Returns:
            (is_safe, reason)
        """
        if not self.enabled:
            return True, None

        # Check for dangerous patterns in wrapper
        for pattern, description in self.DANGEROUS_PATTERNS:
            if re.search(pattern, wrapper_code, re.IGNORECASE):
                return False, f"Dangerous pattern in wrapper: {description}"

        # Ensure wrapper doesn't modify sys.path to dangerous locations
        if re.search(r'sys\.path.*[\\/]tmp[\\/]', wrapper_code, re.IGNORECASE):
            return False, "Wrapper attempts to add /tmp to sys.path"

        return True, None

    def _hash_file(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Generate hash of file"""
        hasher = hashlib.new(algorithm)

        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return ""

    def generate_security_report(self, script_path: Path) -> Dict:
        """
        Generate comprehensive security report for script

        Returns:
            Security report dict
        """
        report = {
            'script_path': str(script_path),
            'path_validation': None,
            'content_warnings': [],
            'malicious_imports': [],
            'overall_risk': 'UNKNOWN',
            'recommendations': [],
        }

        # Validate path
        is_safe, reason = self.validate_script_path(script_path)
        report['path_validation'] = {
            'is_safe': is_safe,
            'reason': reason
        }

        if not is_safe:
            report['overall_risk'] = 'HIGH'
            report['recommendations'].append(f"Do not execute: {reason}")
            return report

        # Scan content
        warnings = self.scan_script_content(script_path)
        report['content_warnings'] = [
            {'description': desc, 'code': code, 'line': line}
            for desc, code, line in warnings
        ]

        # Check imports (would need to parse script)
        # This is a simplified version
        try:
            from ..dependency_manager import DependencyManager
            dep_mgr = DependencyManager(self.config)
            imports = dep_mgr.scan_script_imports(script_path)
            malicious = self.check_malicious_imports(imports)
            report['malicious_imports'] = malicious
        except:
            pass

        # Determine overall risk
        risk_score = 0

        if not report['path_validation']['is_safe']:
            risk_score += 100

        risk_score += len(report['content_warnings']) * 10
        risk_score += len(report['malicious_imports']) * 50

        if risk_score == 0:
            report['overall_risk'] = 'LOW'
            report['recommendations'].append("Script appears safe to execute")
        elif risk_score < 20:
            report['overall_risk'] = 'MEDIUM'
            report['recommendations'].append("Review warnings before execution")
        else:
            report['overall_risk'] = 'HIGH'
            report['recommendations'].append("Do not execute without careful review")

        return report

    def show_security_report(self, script_path: Path):
        """Display security report for script"""
        report = self.generate_security_report(script_path)

        print("=" * 70)
        print("PyManager Security Report")
        print("=" * 70)
        print(f"Script: {report['script_path']}")
        print()

        # Path validation
        print("Path Validation:")
        if report['path_validation']['is_safe']:
            print("  ✅ Path is safe")
        else:
            print(f"  ❌ BLOCKED: {report['path_validation']['reason']}")
        print()

        # Content warnings
        if report['content_warnings']:
            print(f"Content Warnings ({len(report['content_warnings'])}):")
            for warning in report['content_warnings'][:10]:  # Show first 10
                print(f"  ⚠️  Line {warning['line']}: {warning['description']}")
                print(f"     {warning['code']}")
            if len(report['content_warnings']) > 10:
                print(f"  ... and {len(report['content_warnings']) - 10} more")
            print()
        else:
            print("Content Warnings:")
            print("  ✅ No dangerous patterns detected")
            print()

        # Malicious imports
        if report['malicious_imports']:
            print(f"Malicious Imports ({len(report['malicious_imports'])}):")
            for imp in report['malicious_imports']:
                print(f"  ❌ {imp}")
            print()

        # Overall risk
        risk_color = {
            'LOW': '✅',
            'MEDIUM': '⚠️ ',
            'HIGH': '❌',
            'UNKNOWN': '❓'
        }

        print(f"Overall Risk: {risk_color.get(report['overall_risk'], '❓')} {report['overall_risk']}")
        print()

        # Recommendations
        print("Recommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")

        print("=" * 70)


def main():
    """CLI for security validation"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='PyManager Security Validator')
    parser.add_argument('command', choices=['scan', 'validate', 'enable', 'disable'],
                        help='Command to execute')
    parser.add_argument('script', nargs='?', help='Script path to scan/validate')
    parser.add_argument('--strict', action='store_true', help='Enable strict mode')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent.parent
    config_file = manager_dir / 'pymanager.json'

    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    # Create validator
    validator = SecurityValidator(config)

    # Execute command
    if args.command == 'scan':
        if not args.script:
            print("❌ Script path required")
            sys.exit(1)

        script_path = Path(args.script)
        validator.show_security_report(script_path)

    elif args.command == 'validate':
        if not args.script:
            print("❌ Script path required")
            sys.exit(1)

        script_path = Path(args.script)
        is_safe, reason = validator.validate_script_path(script_path)

        if is_safe:
            print(f"✅ Script path is safe: {script_path}")
            sys.exit(0)
        else:
            print(f"❌ Script path is BLOCKED: {reason}")
            sys.exit(1)

    elif args.command == 'enable':
        config.setdefault('security', {})['enabled'] = True
        if args.strict:
            config['security']['strict_mode'] = True

        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print("✅ Security validation enabled")
        if args.strict:
            print("✅ Strict mode enabled")

    elif args.command == 'disable':
        config.setdefault('security', {})['enabled'] = False

        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print("✅ Security validation disabled")


if __name__ == '__main__':
    main()
