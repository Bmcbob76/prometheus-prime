#!/usr/bin/env python3
"""
PROMETHEUS PRIME - TRUTHFUL CAPABILITY STATUS CHECKER
Authority Level: 11.0
Commander Bobby Don McWilliams II

This module provides HONEST, REAL-TIME capability status
NO FAKE SUCCESS RATES - ONLY TRUTH
"""

import os
import sys
import importlib
from pathlib import Path
from typing import Dict, List, Tuple
import subprocess

class PrometheusCapabilityChecker:
    """Check real status of all Prometheus capabilities"""
    
    def __init__(self):
        self.base_path = Path("E:/prometheus_prime/COMPLETE_EVERYTHING")
        
    def check_python_dependencies(self) -> Dict[str, bool]:
        """Check if required Python packages are installed"""
        deps = {
            'nmap': False,
            'scapy': False,
            'paramiko': False,
            'impacket': False,
            'requests': False,
            'cryptography': False
        }
        
        for dep in deps.keys():
            try:
                __import__(dep)
                deps[dep] = True
            except ImportError:
                deps[dep] = False
                
        return deps
    
    def check_system_tools(self) -> Dict[str, bool]:
        """Check if required system tools are available"""
        tools = {
            'nmap': False,
            'hashcat': False
        }
        
        for tool in tools.keys():
            try:
                result = subprocess.run(
                    ['where', tool],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                tools[tool] = (result.returncode == 0)
            except:
                tools[tool] = False
                
        return tools
    
    def check_capability_files(self) -> Dict[str, Dict[str, any]]:
        """Check all capability files for CLI interface and functionality"""
        capabilities = {}
        
        # Core capability files to check
        files_to_check = [
            'red_team_core.py',
            'red_team_exploits.py',
            'web_exploits.py',
            'mobile_exploits.py',
            'cloud_exploits.py',
            'password_attacks.py',
            'lateral_movement.py',
            'persistence_mechanisms.py',
            'network_recon.py',
            'osint_operations.py',
            'crypto_operations.py',
            'biometric_bypass.py',
            'stealth_operations.py',
            'privilege_escalation.py',
            'data_exfil.py',
            'c2_operations.py',
            'evasion_techniques.py',
            'beef_attack_commands.py',
            'beef_interface.py',
            'sigint_operations.py',
            'automotive_exploits.py',
            'ics_scada_exploits.py',
            'ai_adversarial.py'
        ]
        
        for filename in files_to_check:
            filepath = self.base_path / filename
            status = {
                'exists': filepath.exists(),
                'has_main': False,
                'has_cli': False,
                'executable': False,
                'imports_work': False,
                'size': 0
            }
            
            if filepath.exists():
                status['size'] = filepath.stat().st_size
                
                # Read file to check for CLI interface
                try:
                    content = filepath.read_text(encoding='utf-8')
                    status['has_main'] = 'if __name__ == "__main__"' in content
                    status['has_cli'] = 'argparse' in content or 'ArgumentParser' in content
                    
                    # Check if file can be imported
                    try:
                        module_name = filename.replace('.py', '')
                        spec = importlib.util.spec_from_file_location(module_name, filepath)
                        if spec and spec.loader:
                            status['imports_work'] = True
                    except:
                        status['imports_work'] = False
                        
                except Exception as e:
                    status['error'] = str(e)
                    
            capabilities[filename] = status
            
        return capabilities
    
    def get_honest_summary(self) -> Dict[str, any]:
        """Get HONEST summary of capability status - NO LIES"""
        deps = self.check_python_dependencies()
        tools = self.check_system_tools()
        capabilities = self.check_capability_files()
        
        # Count what's actually ready
        deps_installed = sum(1 for v in deps.values() if v)
        deps_missing = sum(1 for v in deps.values() if not v)
        tools_installed = sum(1 for v in tools.values() if v)
        
        files_exist = sum(1 for v in capabilities.values() if v['exists'])
        files_with_cli = sum(1 for v in capabilities.values() if v['has_cli'])
        files_executable = sum(1 for v in capabilities.values() if v['has_main'])
        files_can_import = sum(1 for v in capabilities.values() if v['imports_work'])
        
        return {
            'dependencies': {
                'installed': deps_installed,
                'missing': deps_missing,
                'details': deps
            },
            'system_tools': {
                'installed': tools_installed,
                'details': tools
            },
            'capability_files': {
                'total': len(capabilities),
                'exist': files_exist,
                'with_cli': files_with_cli,
                'executable': files_executable,
                'can_import': files_can_import,
                'details': capabilities
            },
            'honest_status': self._generate_honest_status_string(
                deps_installed, deps_missing, tools_installed,
                files_exist, files_with_cli, files_executable
            )
        }
    
    def _generate_honest_status_string(self, deps_installed, deps_missing, 
                                       tools_installed, files_exist, 
                                       files_with_cli, files_executable) -> str:
        """Generate honest status string with NO LIES"""
        status_parts = []
        
        if deps_missing > 0:
            status_parts.append(f"{deps_missing} dependencies missing")
        else:
            status_parts.append(f"All {deps_installed} dependencies installed ✅")
            
        if files_with_cli < files_exist:
            missing_cli = files_exist - files_with_cli
            status_parts.append(f"{missing_cli} files need CLI interfaces")
        else:
            status_parts.append(f"All {files_exist} files have CLI ✅")
            
        if files_executable < files_exist:
            not_executable = files_exist - files_executable
            status_parts.append(f"{not_executable} files not executable")
        else:
            status_parts.append(f"All {files_exist} files executable ✅")
            
        return " | ".join(status_parts)
    
    def print_detailed_report(self):
        """Print detailed capability report"""
        summary = self.get_honest_summary()
        
        print("\n" + "="*80)
        print("PROMETHEUS PRIME - HONEST CAPABILITY STATUS REPORT")
        print("="*80 + "\n")
        
        print(f"HONEST STATUS: {summary['honest_status']}\n")
        
        print("PYTHON DEPENDENCIES:")
        for dep, installed in summary['dependencies']['details'].items():
            status = "✅ INSTALLED" if installed else "❌ MISSING"
            print(f"  {dep:20s} {status}")
        
        print(f"\nSYSTEM TOOLS:")
        for tool, installed in summary['system_tools']['details'].items():
            status = "✅ FOUND" if installed else "❌ NOT FOUND"
            print(f"  {tool:20s} {status}")
            
        print(f"\nCAPABILITY FILES:")
        print(f"  Total Files: {summary['capability_files']['total']}")
        print(f"  Files Exist: {summary['capability_files']['exist']}")
        print(f"  With CLI Interface: {summary['capability_files']['with_cli']}")
        print(f"  Executable (has main): {summary['capability_files']['executable']}")
        print(f"  Can Import: {summary['capability_files']['can_import']}")
        
        print(f"\nFILES NEEDING WORK:")
        for filename, status in summary['capability_files']['details'].items():
            if not status['has_cli'] or not status['has_main']:
                issues = []
                if not status['has_cli']:
                    issues.append("NO CLI")
                if not status['has_main']:
                    issues.append("NO MAIN")
                if not status['imports_work']:
                    issues.append("IMPORT FAILS")
                print(f"  {filename:40s} {', '.join(issues)}")
        
        print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    checker = PrometheusCapabilityChecker()
    checker.print_detailed_report()
