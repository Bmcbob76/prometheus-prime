#!/usr/bin/env python3
"""
PERSISTENCE MECHANISMS - System Persistence Techniques
Authority Level: 9.9
"""

import subprocess
import winreg
from pathlib import Path
from typing import Dict
import logging

logger = logging.getLogger(__name__)

class PersistenceMechanisms:
    """Windows persistence techniques"""
    
    def registry_run_key(self, name: str, command: str, add: bool = True) -> Dict:
        """Add/remove registry run key persistence"""
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            
            if add:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
                winreg.CloseKey(key)
                return {'status': 'success', 'action': 'added', 'name': name}
            else:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.DeleteValue(key, name)
                winreg.CloseKey(key)
                return {'status': 'success', 'action': 'removed', 'name': name}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def scheduled_task(self, name: str, command: str, trigger: str = 'daily') -> Dict:
        """Create scheduled task persistence"""
        try:
            cmd = f'schtasks /create /tn "{name}" /tr "{command}" /sc {trigger} /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return {
                'status': 'success' if result.returncode == 0 else 'failed',
                'name': name,
                'trigger': trigger
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def startup_folder(self, name: str, command: str) -> Dict:
        """Add to startup folder"""
        try:
            startup_path = Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
            bat_file = startup_path / f"{name}.bat"
            
            with open(bat_file, 'w') as f:
                f.write(f"@echo off\n{command}")
            
            return {'status': 'success', 'path': str(bat_file)}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def service_installation(self, name: str, binary_path: str) -> Dict:
        """Install as Windows service"""
        try:
            cmd = f'sc create {name} binPath= "{binary_path}" start= auto'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return {
                'status': 'success' if result.returncode == 0 else 'failed',
                'service_name': name
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def list_persistence(self) -> Dict:
        """List current persistence mechanisms"""
        mechanisms = {
            'registry_run': [],
            'scheduled_tasks': [],
            'services': []
        }
        
        try:
            # Check registry
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Run")
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    mechanisms['registry_run'].append({'name': name, 'command': value})
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
            
            # Check scheduled tasks
            result = subprocess.run('schtasks /query /fo csv /nh', 
                                  shell=True, capture_output=True, text=True)
            for line in result.stdout.split('\n')[:10]:  # Limit output
                if line.strip():
                    mechanisms['scheduled_tasks'].append(line.strip())
        except Exception as e:
            logger.error(f"Error listing persistence: {e}")
        
        return {'status': 'success', 'mechanisms': mechanisms}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Persistence Mechanisms")
    parser.add_argument('--list', action='store_true', help='List persistence mechanisms')
    parser.add_argument('--registry', nargs=2, metavar=('NAME', 'COMMAND'))
    parser.add_argument('--task', nargs=2, metavar=('NAME', 'COMMAND'))
    parser.add_argument('--startup', nargs=2, metavar=('NAME', 'COMMAND'))
    parser.add_argument('--remove-registry', help='Remove registry persistence')
    
    args = parser.parse_args()
    
    pm = PersistenceMechanisms()
    
    if args.list:
        result = pm.list_persistence()
        print("Current Persistence Mechanisms:")
        print(f"Registry Run Keys: {len(result['mechanisms']['registry_run'])}")
        for item in result['mechanisms']['registry_run']:
            print(f"  {item['name']}: {item['command'][:50]}")
    
    if args.registry:
        result = pm.registry_run_key(args.registry[0], args.registry[1])
        print(f"Registry Persistence: {result['status']}")
    
    if args.task:
        result = pm.scheduled_task(args.task[0], args.task[1])
        print(f"Scheduled Task: {result['status']}")
