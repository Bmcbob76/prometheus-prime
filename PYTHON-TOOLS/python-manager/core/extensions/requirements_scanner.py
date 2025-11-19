#!/usr/bin/env python3
"""
PyManager Requirements Scanner
Auto-generate requirements.txt from imports
"""

import re
import ast
from pathlib import Path
from typing import Set, Dict


class RequirementsScanner:
    """Scan project and generate requirements.txt"""

    # Map import names to package names
    IMPORT_TO_PACKAGE = {
        'cv2': 'opencv-python',
        'sklearn': 'scikit-learn',
        'PIL': 'Pillow',
        'yaml': 'PyYAML',
        'bs4': 'beautifulsoup4',
    }

    def __init__(self, config: Dict):
        self.config = config

    def scan_file(self, file_path: Path) -> Set[str]:
        """Extract imports from Python file"""
        imports = set()

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])

        except Exception as e:
            # Fallback to regex if AST parsing fails
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Match import statements
                import_pattern = r'^\s*(?:from|import)\s+([a-zA-Z0-9_]+)'
                for match in re.finditer(import_pattern, content, re.MULTILINE):
                    imports.add(match.group(1))
            except:
                pass

        return imports

    def scan_project(self, project_dir: Path) -> Set[str]:
        """Scan all Python files in project"""
        all_imports = set()

        for py_file in project_dir.rglob('*.py'):
            # Skip venv and build directories
            if any(p in py_file.parts for p in ['.venv', 'venv', 'env', 'build', 'dist', '__pycache__']):
                continue

            imports = self.scan_file(py_file)
            all_imports.update(imports)

        return all_imports

    def filter_stdlib(self, imports: Set[str]) -> Set[str]:
        """Remove standard library imports"""
        stdlib = {
            'os', 'sys', 'pathlib', 'json', 'time', 'datetime', 'collections',
            're', 'subprocess', 'threading', 'multiprocessing', 'socket',
            'urllib', 'http', 'email', 'logging', 'argparse', 'typing',
            'itertools', 'functools', 'operator', 'math', 'random', 'string',
            'io', 'tempfile', 'shutil', 'glob', 'pickle', 'csv', 'xml', 'html',
            'unittest', 'doctest', 'pdb', 'traceback', 'warnings', 'abc',
            'contextlib', 'copy', 'pprint', 'enum', 'dataclasses', 'asyncio',
        }

        return {imp for imp in imports if imp not in stdlib}

    def map_to_package_names(self, imports: Set[str]) -> Set[str]:
        """Map import names to PyPI package names"""
        packages = set()

        for imp in imports:
            # Use mapping if exists, otherwise use import name
            package = self.IMPORT_TO_PACKAGE.get(imp, imp)
            packages.add(package)

        return packages

    def generate_requirements(self, project_dir: Path, output_file: Path = None):
        """Generate requirements.txt"""
        print(f"🔍 Scanning project: {project_dir}")

        # Scan imports
        imports = self.scan_project(project_dir)
        print(f"   Found {len(imports)} imports")

        # Filter stdlib
        third_party = self.filter_stdlib(imports)
        print(f"   Third-party: {len(third_party)}")

        # Map to package names
        packages = self.map_to_package_names(third_party)

        # Generate output
        output = output_file or project_dir / 'requirements.txt'

        with open(output, 'w') as f:
            for package in sorted(packages):
                f.write(f"{package}\n")

        print(f"\n✅ Generated {output}")
        print(f"   Packages: {len(packages)}")

        return packages


def main():
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Requirements Scanner')
    parser.add_argument('--path', type=str, default='.', help='Project path')
    parser.add_argument('--output', type=str, help='Output file')

    args = parser.parse_args()

    scanner = RequirementsScanner({})
    output = Path(args.output) if args.output else None
    scanner.generate_requirements(Path(args.path), output)


if __name__ == '__main__':
    main()
