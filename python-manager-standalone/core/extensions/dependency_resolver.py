#!/usr/bin/env python3
"""
PyManager Dependency Resolver
Intelligent dependency conflict resolution using pip's resolver
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


class DependencyResolver:
    """Resolve dependency conflicts intelligently"""

    def __init__(self, config: Dict):
        self.config = config

    def parse_requirements(self, requirements_file: Path) -> List[Tuple[str, str]]:
        """Parse requirements.txt"""
        packages = []

        if not requirements_file.exists():
            return packages

        with open(requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse package==version
                if '==' in line:
                    pkg, ver = line.split('==', 1)
                    packages.append((pkg.strip(), ver.strip()))
                elif '>=' in line:
                    pkg, ver = line.split('>=', 1)
                    packages.append((pkg.strip(), f'>={ver.strip()}'))
                else:
                    packages.append((line, 'latest'))

        return packages

    def check_conflicts(self, packages: List[Tuple[str, str]]) -> Dict:
        """Check for dependency conflicts"""
        conflicts = {
            'incompatible_versions': [],
            'known_conflicts': [],
            'recommendations': []
        }

        # Known conflict patterns
        known = {
            ('tensorflow', 'numpy'): 'TensorFlow requires specific NumPy versions',
            ('fastapi', 'pydantic'): 'FastAPI 0.104 requires Pydantic v1, 0.109+ uses v2',
        }

        pkg_dict = dict(packages)

        # Check known conflicts
        for (pkg1, pkg2), msg in known.items():
            if pkg1 in pkg_dict and pkg2 in pkg_dict:
                conflicts['known_conflicts'].append({
                    'packages': [pkg1, pkg2],
                    'message': msg,
                    'versions': {pkg1: pkg_dict[pkg1], pkg2: pkg_dict[pkg2]}
                })

        return conflicts

    def resolve_conflicts(self, requirements_file: Path) -> Dict:
        """Attempt to resolve conflicts automatically"""
        packages = self.parse_requirements(requirements_file)
        conflicts = self.check_conflicts(packages)

        resolution = {
            'conflicts_found': len(conflicts['incompatible_versions']) + len(conflicts['known_conflicts']),
            'resolved': [],
            'unresolved': conflicts,
            'recommendations': []
        }

        # Auto-resolution strategies
        if ('fastapi', 'pydantic') in [tuple(c['packages']) for c in conflicts['known_conflicts']]:
            resolution['recommendations'].append({
                'action': 'downgrade',
                'package': 'fastapi',
                'version': '0.104.1',
                'reason': 'Compatible with Pydantic v1'
            })

        return resolution

    def generate_lock_file(self, requirements_file: Path, output_file: Path):
        """Generate requirements lock file with pinned versions"""
        print(f"📝 Generating lock file from {requirements_file}")

        try:
            # Use pip-compile if available
            result = subprocess.run(
                ['pip-compile', str(requirements_file), '--output-file', str(output_file)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                print(f"✅ Lock file created: {output_file}")
                return True

        except FileNotFoundError:
            print("⚠️  pip-tools not installed. Install with: pip install pip-tools")

        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Dependency Resolver')
    parser.add_argument('command', choices=['check', 'resolve', 'lock'],
                        help='Command to execute')
    parser.add_argument('--file', type=str, default='requirements.txt',
                        help='Requirements file')

    args = parser.parse_args()

    config = {}
    resolver = DependencyResolver(config)
    req_file = Path(args.file)

    if args.command == 'check':
        packages = resolver.parse_requirements(req_file)
        conflicts = resolver.check_conflicts(packages)

        print(f"Dependency Analysis:")
        print(f"  Packages: {len(packages)}")
        print(f"  Conflicts: {len(conflicts['known_conflicts'])}")

        if conflicts['known_conflicts']:
            print("\nKnown Conflicts:")
            for c in conflicts['known_conflicts']:
                print(f"  ⚠️  {c['message']}")

    elif args.command == 'resolve':
        resolution = resolver.resolve_conflicts(req_file)
        print(f"Resolution:")
        print(f"  Conflicts Found: {resolution['conflicts_found']}")

        if resolution['recommendations']:
            print("\nRecommendations:")
            for rec in resolution['recommendations']:
                print(f"  • {rec['action']} {rec['package']} to {rec['version']}")
                print(f"    Reason: {rec['reason']}")

    elif args.command == 'lock':
        lock_file = req_file.parent / 'requirements-lock.txt'
        resolver.generate_lock_file(req_file, lock_file)


if __name__ == '__main__':
    main()
