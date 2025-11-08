#!/usr/bin/env python3
"""
📱 MOBILE DEVICE CONTROL MODULE
iOS and Android device management and control
Authority Level: 11.0
"""

import subprocess
import json
import os
from datetime import datetime
from typing import Dict, Any, List

class MobileControl:
    """Mobile device management for iOS and Android"""
    
    def __init__(self):
        self.adb_path = self._find_adb()
        self.idevice_available = self._check_idevice()
        
        print("📱 Mobile Control Module initialized")
        print(f"   ADB: {'✅' if self.adb_path else '❌'}")
        print(f"   libimobiledevice: {'✅' if self.idevice_available else '❌'}")
    
    def _find_adb(self) -> str:
        """Locate ADB executable"""
        try:
            result = subprocess.run(['where', 'adb'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
        
        # Common locations
        common_paths = [
            r'C:\Android\platform-tools\adb.exe',
            r'C:\Users\{}\AppData\Local\Android\Sdk\platform-tools\adb.exe'.format(os.getenv('USERNAME')),
            r'D:\Android\platform-tools\adb.exe'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _check_idevice(self) -> bool:
        """Check if libimobiledevice tools are available"""
        try:
            subprocess.run(['ideviceinfo', '--help'], capture_output=True, timeout=2)
            return True
        except:
            return False
    
    # ==================== ANDROID (ADB) ====================
    
    def android_devices(self) -> Dict[str, Any]:
        """List connected Android devices"""
        if not self.adb_path:
            return {'error': 'ADB not found. Install Android Platform Tools'}
        
        try:
            result = subprocess.run(
                [self.adb_path, 'devices', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            devices = []
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        devices.append({
                            'serial': parts[0],
                            'state': parts[1],
                            'details': ' '.join(parts[2:]) if len(parts) > 2 else ''
                        })
            
            return {
                'platform': 'android',
                'devices': devices,
                'count': len(devices),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def android_info(self, device_id: str = None) -> Dict[str, Any]:
        """Get Android device information"""
        if not self.adb_path:
            return {'error': 'ADB not found'}
        
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(['-s', device_id])
        
        info = {}
        
        # Device properties
        props = [
            'ro.product.model',
            'ro.product.manufacturer',
            'ro.build.version.release',
            'ro.build.version.sdk',
            'ro.serialno',
            'gsm.operator.alpha'
        ]
        
        for prop in props:
            try:
                result = subprocess.run(
                    cmd + ['shell', 'getprop', prop],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                info[prop] = result.stdout.strip()
            except:
                info[prop] = 'N/A'
        
        return {
            'device_id': device_id or 'default',
            'info': info,
            'timestamp': datetime.now().isoformat()
        }
    
    def android_shell(self, command: str, device_id: str = None) -> Dict[str, Any]:
        """Execute shell command on Android device"""
        if not self.adb_path:
            return {'error': 'ADB not found'}
        
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(['-s', device_id])
        cmd.extend(['shell', command])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'command': command,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'returncode': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def android_install_apk(self, apk_path: str, device_id: str = None) -> Dict[str, Any]:
        """Install APK on Android device"""
        if not self.adb_path:
            return {'error': 'ADB not found'}
        
        if not os.path.exists(apk_path):
            return {'error': f'APK not found: {apk_path}'}
        
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(['-s', device_id])
        cmd.extend(['install', '-r', apk_path])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            success = 'Success' in result.stdout
            
            return {
                'apk': apk_path,
                'success': success,
                'output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def android_screenshot(self, output_path: str, device_id: str = None) -> Dict[str, Any]:
        """Capture screenshot from Android device"""
        if not self.adb_path:
            return {'error': 'ADB not found'}
        
        device_path = '/sdcard/screenshot.png'
        
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(['-s', device_id])
        
        try:
            # Capture screenshot
            subprocess.run(
                cmd + ['shell', 'screencap', '-p', device_path],
                timeout=5
            )
            
            # Pull to local
            subprocess.run(
                cmd + ['pull', device_path, output_path],
                timeout=10
            )
            
            # Clean up device
            subprocess.run(
                cmd + ['shell', 'rm', device_path],
                timeout=5
            )
            
            return {
                'screenshot': output_path,
                'success': os.path.exists(output_path),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def android_list_apps(self, device_id: str = None) -> Dict[str, Any]:
        """List installed applications"""
        result = self.android_shell('pm list packages', device_id)
        
        if 'error' in result:
            return result
        
        packages = []
        for line in result['output'].split('\n'):
            if line.startswith('package:'):
                packages.append(line.replace('package:', '').strip())
        
        return {
            'apps': packages,
            'count': len(packages),
            'timestamp': datetime.now().isoformat()
        }
    
    def android_pull_file(self, device_path: str, local_path: str, device_id: str = None) -> Dict[str, Any]:
        """Pull file from Android device"""
        if not self.adb_path:
            return {'error': 'ADB not found'}
        
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(['-s', device_id])
        cmd.extend(['pull', device_path, local_path])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'device_path': device_path,
                'local_path': local_path,
                'success': os.path.exists(local_path),
                'output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def android_push_file(self, local_path: str, device_path: str, device_id: str = None) -> Dict[str, Any]:
        """Push file to Android device"""
        if not self.adb_path:
            return {'error': 'ADB not found'}
        
        if not os.path.exists(local_path):
            return {'error': f'File not found: {local_path}'}
        
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(['-s', device_id])
        cmd.extend(['push', local_path, device_path])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'local_path': local_path,
                'device_path': device_path,
                'success': 'pushed' in result.stdout.lower(),
                'output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    # ==================== iOS (libimobiledevice) ====================
    
    def ios_devices(self) -> Dict[str, Any]:
        """List connected iOS devices"""
        if not self.idevice_available:
            return {'error': 'libimobiledevice not installed'}
        
        try:
            result = subprocess.run(
                ['idevice_id', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            udids = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            return {
                'platform': 'ios',
                'devices': udids,
                'count': len(udids),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def ios_info(self, udid: str = None) -> Dict[str, Any]:
        """Get iOS device information"""
        if not self.idevice_available:
            return {'error': 'libimobiledevice not installed'}
        
        cmd = ['ideviceinfo']
        if udid:
            cmd.extend(['-u', udid])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            info = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip()] = value.strip()
            
            return {
                'udid': udid or 'default',
                'info': info,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def ios_screenshot(self, output_path: str, udid: str = None) -> Dict[str, Any]:
        """Capture screenshot from iOS device"""
        if not self.idevice_available:
            return {'error': 'libimobiledevice not installed'}
        
        cmd = ['idevicescreenshot']
        if udid:
            cmd.extend(['-u', udid])
        cmd.append(output_path)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'screenshot': output_path,
                'success': os.path.exists(output_path),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def ios_syslog(self, udid: str = None, duration: int = 10) -> Dict[str, Any]:
        """Capture iOS system log"""
        if not self.idevice_available:
            return {'error': 'libimobiledevice not installed'}
        
        cmd = ['idevicesyslog']
        if udid:
            cmd.extend(['-u', udid])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration
            )
            
            return {
                'log': result.stdout,
                'lines': len(result.stdout.split('\n')),
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired as e:
            return {
                'log': e.stdout.decode('utf-8', errors='ignore'),
                'lines': len(e.stdout.decode('utf-8', errors='ignore').split('\n')),
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def ios_install_app(self, ipa_path: str, udid: str = None) -> Dict[str, Any]:
        """Install IPA on iOS device"""
        if not self.idevice_available:
            return {'error': 'libimobiledevice not installed'}
        
        if not os.path.exists(ipa_path):
            return {'error': f'IPA not found: {ipa_path}'}
        
        cmd = ['ideviceinstaller', '-i', ipa_path]
        if udid:
            cmd.extend(['-u', udid])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            success = result.returncode == 0
            
            return {
                'ipa': ipa_path,
                'success': success,
                'output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}


def main():
    """Test mobile control"""
    mc = MobileControl()
    
    print("\n1. Android Devices")
    print("2. iOS Devices")
    print("3. Android Info")
    print("4. iOS Info")
    
    choice = input("\nSelect: ").strip()
    
    if choice == '1':
        result = mc.android_devices()
        print(json.dumps(result, indent=2))
    elif choice == '2':
        result = mc.ios_devices()
        print(json.dumps(result, indent=2))
    elif choice == '3':
        result = mc.android_info()
        print(json.dumps(result, indent=2))
    elif choice == '4':
        result = mc.ios_info()
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
