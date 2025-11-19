#!/usr/bin/env python3
"""
PyManager Dependency Manager
Auto-detect and block incompatible dependency combinations
Forces version downgrades when necessary for stability
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class DependencyManager:
    """Auto-detect and enforce dependency compatibility"""

    # Python versions known to have compatibility issues with packages
    BLOCKED_COMBINATIONS = {
        "3.14": ["numpy", "scipy", "opencv-python", "pandas", "scikit-learn", "matplotlib"],
        "3.13": ["tensorflow<2.16", "keras<3.0"],
        "3.12": ["tensorflow<2.15"],
    }

    # Recommended package versions per Python version
    RECOMMENDED_VERSIONS = {
        "numpy": {
            "3.11": ">=1.23.0,<2.0.0",
            "3.10": ">=1.21.0,<1.24.0",
            "3.9": ">=1.19.0,<1.22.0",
            "3.8": ">=1.19.0,<1.21.0",
        },
        "torch": {
            "3.11": "2.1.0",
            "3.10": "1.13.0",
            "3.9": "1.12.0",
        },
        "tensorflow": {
            "3.11": ">=2.15.0",
            "3.10": ">=2.10.0",
            "3.9": ">=2.9.0",
        },
        "fastapi": {
            "3.11": "0.104.1",  # Stable with Pydantic v1
            "3.10": "0.104.1",
            "3.9": "0.95.0",
        },
        "pydantic": {
            "fastapi_0.104": "^1.10.13",  # FastAPI 0.104.x requires Pydantic v1
            "fastapi_0.109": "^2.0.0",    # FastAPI 0.109+ supports Pydantic v2
        },
    }

    # ECHO_PRIME specific fixes
    ECHO_PRIME_FIXES = {
        "uses_numpy": "force_python_311",
        "uses_scipy": "force_python_311",
        "uses_pandas": "force_python_311",
        "uses_asyncio_create_task": "inject_event_loop_wrapper",
        "imports_developer_gateway": "inject_path_to_gateways_dir",
        "imports_network_guardian": "inject_path_to_gateways_dir",
        "imports_gs343_gateway": "inject_path_to_gateways_dir",
        "fastapi_with_pydantic": "force_pydantic_v1",
        "uses_torch": "force_python_311",
        "uses_tensorflow": "force_python_311",
    }

    def __init__(self, config: Dict):
        self.config = config
        self.auto_fixes_enabled = config.get('auto_fixes', {})

    def scan_script_imports(self, script_path: Path) -> List[str]:
        """Extract all import statements from script"""
        imports = []

        if not script_path.exists() or not script_path.is_file():
            return imports

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Match: import numpy, from numpy import X, import numpy as np
            import_patterns = [
                r'^\s*import\s+(\w+)',
                r'^\s*from\s+(\w+)',
            ]

            for line in content.split('\n'):
                for pattern in import_patterns:
                    match = re.match(pattern, line)
                    if match:
                        package = match.group(1)
                        imports.append(package)

        except (UnicodeDecodeError, PermissionError):
            pass

        return list(set(imports))  # Deduplicate

    def check_compatibility(self, python_version: str, script_path: Path) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check if script's dependencies are compatible with Python version

        Returns:
            (is_compatible, recommended_version, reason)
        """
        # Scan script for imports
        imports = self.scan_script_imports(script_path)

        # Check blocked combinations
        blocked_packages = self.BLOCKED_COMBINATIONS.get(python_version, [])

        for imported in imports:
            # Check if imported package is blocked
            for blocked in blocked_packages:
                # Handle version specifiers like "tensorflow<2.16"
                blocked_package = blocked.split('<')[0].split('>')[0].split('=')[0]

                if imported == blocked_package:
                    # Find compatible version
                    recommended = self.find_compatible_version(imported)
                    reason = f"Python {python_version} incompatible with {imported}"
                    return False, recommended, reason

        # Check ECHO_PRIME specific patterns
        if self.auto_fixes_enabled.get('numpy_compatibility', True):
            if 'numpy' in imports or 'scipy' in imports or 'pandas' in imports:
                if python_version in ['3.14', '3.13']:
                    return False, "3.11", f"Python {python_version} unstable with numpy/scipy/pandas"

        return True, None, None

    def find_compatible_version(self, package: str) -> str:
        """Find best Python version for package"""
        # Default to Python 3.11 for most scientific packages
        if package in ['numpy', 'scipy', 'pandas', 'torch', 'tensorflow', 'sklearn', 'opencv']:
            return "3.11"

        # FastAPI works well on 3.10+
        if package in ['fastapi', 'uvicorn', 'starlette']:
            return "3.11"

        # Default fallback
        return "3.11"

    def parse_requirements_file(self, requirements_path: Path) -> List[Tuple[str, str]]:
        """Parse requirements.txt and extract package==version pairs"""
        packages = []

        if not requirements_path.exists():
            return packages

        try:
            with open(requirements_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Parse: package==1.2.3 or package>=1.2.3
                    match = re.match(r'([a-zA-Z0-9_-]+)\s*([=<>!]+)\s*(.+)', line)
                    if match:
                        package, operator, version = match.groups()
                        packages.append((package, f"{operator}{version}"))
                    else:
                        # Just package name
                        packages.append((line, ""))

        except (UnicodeDecodeError, PermissionError):
            pass

        return packages

    def check_requirements_compatibility(self, python_version: str, requirements_path: Path) -> List[str]:
        """
        Check requirements.txt for incompatibilities

        Returns:
            List of warning messages
        """
        warnings = []
        packages = self.parse_requirements_file(requirements_path)

        blocked_packages = self.BLOCKED_COMBINATIONS.get(python_version, [])

        for package_name, version_spec in packages:
            for blocked in blocked_packages:
                blocked_package = blocked.split('<')[0].split('>')[0].split('=')[0]

                if package_name.lower() == blocked_package.lower():
                    recommended = self.find_compatible_version(package_name)
                    warnings.append(
                        f"⚠️  {package_name}{version_spec} may be incompatible with Python {python_version}\n"
                        f"   Recommended: Use Python {recommended}"
                    )

        return warnings

    def get_recommended_version_for_script(self, script_path: Path) -> Optional[str]:
        """
        Analyze script and recommend best Python version

        Returns:
            Recommended Python version or None if current is fine
        """
        imports = self.scan_script_imports(script_path)

        # ECHO_PRIME gateway scripts → Python 3.11
        script_name = script_path.name.lower()
        if any(pattern in script_name for pattern in ['gateway', 'guardian', 'orchestrator']):
            return "3.11"

        # Scientific computing → Python 3.11
        scientific_packages = {'numpy', 'scipy', 'pandas', 'sklearn', 'torch', 'tensorflow'}
        if imports and scientific_packages.intersection(set(imports)):
            return "3.11"

        # FastAPI → Python 3.11
        if 'fastapi' in imports:
            return "3.11"

        # Check directory for requirements.txt
        requirements = script_path.parent / 'requirements.txt'
        if requirements.exists():
            packages = self.parse_requirements_file(requirements)
            package_names = {p[0].lower() for p in packages}

            if scientific_packages.intersection(package_names):
                return "3.11"

        return None

    def auto_downgrade_version(self, script_path: Path, current_version: str, reason: str) -> str:
        """
        Auto-switch to compatible Python version

        Returns:
            Recommended version
        """
        recommended = self.get_recommended_version_for_script(script_path)

        if recommended and recommended != current_version:
            if self.config.get('verbose', False):
                print(f"[PyManager] Auto-switching: {current_version} → {recommended}", file=sys.stderr)
                print(f"[PyManager] Reason: {reason}", file=sys.stderr)

            return recommended

        # Default to 3.11 if issues detected
        return "3.11"

    def validate_and_fix_version(self, script_path: Path, detected_version: str) -> str:
        """
        Main validation method - checks compatibility and fixes if needed

        Returns:
            Final Python version to use (may differ from detected_version)
        """
        # Skip validation if auto-fixes disabled
        if not self.auto_fixes_enabled.get('dependency_blocking', True):
            return detected_version

        # Check compatibility
        is_compatible, recommended_version, reason = self.check_compatibility(
            detected_version,
            script_path
        )

        # If incompatible, auto-switch version
        if not is_compatible and recommended_version:
            if self.config.get('verbose', False):
                print(f"[PyManager] Dependency conflict detected!", file=sys.stderr)
                print(f"[PyManager] {reason}", file=sys.stderr)
                print(f"[PyManager] Auto-switching: {detected_version} → {recommended_version}", file=sys.stderr)

            return recommended_version

        return detected_version


class AutoFixInjector:
    """Inject auto-fix wrappers for common issues"""

    ASYNC_FIX_PATTERNS = [
        "network_guardian",
        "healing_orchestrator",
        "gateway_http",
        "asyncio",
    ]

    IMPORT_PATH_FIXES = {
        "developer_gateway": "P:\\ECHO_PRIME\\MLS_CLEAN\\PRODUCTION\\GATEWAYS",
        "gs343_gateway": "P:\\ECHO_PRIME\\MLS_CLEAN\\PRODUCTION\\GATEWAYS\\GS343_GATEWAY",
        "network_guardian": "P:\\ECHO_PRIME\\MLS_CLEAN\\PRODUCTION\\GATEWAYS\\NETWORK_GUARDIAN",
        "gateway": "P:\\ECHO_PRIME\\MLS_CLEAN\\PRODUCTION\\GATEWAYS",
    }

    def __init__(self, config: Dict):
        self.config = config
        self.auto_fixes = config.get('auto_fixes', {})

    def needs_async_fix(self, script_path: Path) -> bool:
        """Detect if script needs async event loop fix"""
        if not self.auto_fixes.get('async_event_loop', True):
            return False

        script_name = script_path.name.lower()

        # Check filename patterns
        if any(pattern in script_name for pattern in self.ASYNC_FIX_PATTERNS):
            return True

        # Check script content for async usage
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Look for problematic patterns
            if 'asyncio.create_task' in content or 'asyncio.run' in content:
                if 'RuntimeError' in content or 'event loop' in content.lower():
                    return True

        except (UnicodeDecodeError, PermissionError):
            pass

        return False

    def get_async_fix_wrapper(self) -> str:
        """Generate async event loop fix wrapper"""
        return '''import asyncio
import sys

# PyManager Auto-Fix: Ensure event loop exists
try:
    loop = asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

'''

    def needs_import_path_fix(self, script_path: Path) -> Optional[str]:
        """Detect if script needs import path injection"""
        if not self.auto_fixes.get('import_paths', True):
            return None

        script_name = script_path.name.lower()
        script_content_lower = ""

        # Check script content
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                script_content_lower = f.read().lower()
        except:
            pass

        # Check patterns
        for pattern, path_to_add in self.IMPORT_PATH_FIXES.items():
            if pattern in script_name or pattern in script_content_lower:
                return path_to_add

        return None

    def get_import_path_fix(self, path_to_add: str) -> str:
        """Generate import path injection code"""
        return f'''import sys
from pathlib import Path

# PyManager Auto-Fix: Add gateway directory to path
_gateway_path = Path(r"{path_to_add}")
if _gateway_path.exists() and str(_gateway_path) not in sys.path:
    sys.path.insert(0, str(_gateway_path))

'''

    def generate_wrapper_script(self, original_script: Path) -> Optional[str]:
        """
        Generate complete wrapper with all necessary fixes

        Returns:
            Wrapper code to prepend, or None if no fixes needed
        """
        fixes = []

        # Async fix
        if self.needs_async_fix(original_script):
            fixes.append(self.get_async_fix_wrapper())

        # Import path fix
        import_path = self.needs_import_path_fix(original_script)
        if import_path:
            fixes.append(self.get_import_path_fix(import_path))

        if not fixes:
            return None

        # Combine all fixes
        wrapper = "# PyManager Auto-Fixes Applied\n"
        wrapper += ''.join(fixes)
        wrapper += "\n# Original script execution below\n"

        return wrapper
