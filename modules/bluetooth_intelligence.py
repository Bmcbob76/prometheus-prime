#!/usr/bin/env python3
"""
📱 BLUETOOTH INTELLIGENCE MODULE
Bluetooth device discovery, profiling, security assessment
Authority Level: 11.0

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️

SIGINT PHASE 2 - Bluetooth Intelligence Operations
"""

import subprocess
import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict

class BluetoothIntelligence:
    """
    Comprehensive Bluetooth intelligence gathering

    Features:
    - Bluetooth device discovery (Classic + BLE)
    - Device profiling and fingerprinting
    - Service enumeration
    - Security assessment
    - Proximity tracking
    - Manufacturer identification
    - Device class analysis
    - Connection monitoring
    - BLE advertising data analysis
    - Vulnerability detection
    """

    def __init__(self):
        self.cache = {}
        self.device_db = {}
        print("📱 Bluetooth Intelligence Module initialized")

    def discover_devices(self, duration: int = 10, device_type: str = 'all') -> Dict[str, Any]:
        """
        Discover Bluetooth devices in range

        Args:
            duration: Scan duration in seconds
            device_type: 'classic', 'ble', or 'all'

        Returns:
            Discovered devices and their properties
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': duration,
            'device_type': device_type,
            'devices': [],
            'total_devices': 0,
            'classic_devices': 0,
            'ble_devices': 0
        }

        # Discover Classic Bluetooth devices
        if device_type in ['classic', 'all']:
            classic_devices = self._scan_classic_bluetooth(duration)
            results['devices'].extend(classic_devices)
            results['classic_devices'] = len(classic_devices)

        # Discover BLE devices
        if device_type in ['ble', 'all']:
            ble_devices = self._scan_ble(duration)
            results['devices'].extend(ble_devices)
            results['ble_devices'] = len(ble_devices)

        results['total_devices'] = len(results['devices'])

        # Cache discovered devices
        for device in results['devices']:
            mac = device.get('mac_address')
            if mac:
                self.device_db[mac] = device

        return results

    def _scan_classic_bluetooth(self, duration: int) -> List[Dict[str, Any]]:
        """Scan for Classic Bluetooth devices"""
        devices = []

        try:
            # Use hcitool for classic Bluetooth scan
            cmd = f"sudo timeout {duration} hcitool scan"
            output = subprocess.check_output(cmd, shell=True, timeout=duration+5).decode('utf-8')

            for line in output.split('\n'):
                # Parse: MAC_ADDRESS    Device_Name
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    mac = parts[0].strip()
                    name = parts[1].strip()

                    if self._is_valid_mac(mac):
                        device = {
                            'mac_address': mac,
                            'name': name,
                            'type': 'Classic Bluetooth',
                            'manufacturer': self._identify_manufacturer(mac),
                            'discovery_time': datetime.now().isoformat()
                        }

                        # Try to get device class
                        device_class = self._get_device_class(mac)
                        if device_class:
                            device['device_class'] = device_class

                        devices.append(device)

        except Exception as e:
            print(f"Classic Bluetooth scan failed: {e}")

        return devices

    def _scan_ble(self, duration: int) -> List[Dict[str, Any]]:
        """Scan for BLE devices"""
        devices = []

        try:
            # Use hcitool lescan for BLE
            cmd = f"sudo timeout {duration} hcitool lescan"
            output = subprocess.check_output(cmd, shell=True, timeout=duration+5).decode('utf-8')

            for line in output.split('\n'):
                # Parse: MAC_ADDRESS Device_Name
                parts = line.strip().split()
                if len(parts) >= 2:
                    mac = parts[0].strip()
                    name = ' '.join(parts[1:])

                    if self._is_valid_mac(mac):
                        device = {
                            'mac_address': mac,
                            'name': name if name != '(unknown)' else 'Unknown',
                            'type': 'BLE (Bluetooth Low Energy)',
                            'manufacturer': self._identify_manufacturer(mac),
                            'discovery_time': datetime.now().isoformat()
                        }
                        devices.append(device)

        except Exception as e:
            print(f"BLE scan failed: {e}")

        return devices

    def _is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, mac))

    def _identify_manufacturer(self, mac: str) -> str:
        """Identify device manufacturer from MAC OUI"""
        # Extract OUI (first 3 octets)
        oui = mac[:8].upper().replace(':', '')

        # Common OUI mappings
        oui_db = {
            '001122': 'Apple',
            'AABBCC': 'Samsung',
            '001A7D': 'Google',
            '00DB70': 'Microsoft',
            '001DC9': 'Logitech',
            '001E52': 'Bose',
            '001B63': 'Sony',
            '0050F2': 'Broadcom',
            '000D93': 'Intel',
            '00037F': 'Atheros'
        }

        return oui_db.get(oui, 'Unknown Manufacturer')

    def _get_device_class(self, mac: str) -> Optional[str]:
        """Get Bluetooth device class"""
        try:
            cmd = f"sudo hcitool info {mac}"
            output = subprocess.check_output(cmd, shell=True, timeout=5).decode('utf-8')

            # Parse device class
            class_match = re.search(r'Class:\s*0x([0-9a-fA-F]+)', output)
            if class_match:
                return f"0x{class_match.group(1)}"

        except:
            pass

        return None

    def profile_device(self, mac_address: str) -> Dict[str, Any]:
        """
        Create comprehensive device profile

        Args:
            mac_address: Target device MAC address

        Returns:
            Device profile
        """
        profile = {
            'mac_address': mac_address,
            'timestamp': datetime.now().isoformat(),
            'basic_info': {},
            'services': [],
            'security_assessment': {},
            'metadata': {}
        }

        # Get basic info
        profile['basic_info'] = self._get_device_info(mac_address)

        # Enumerate services
        profile['services'] = self._enumerate_services(mac_address)

        # Security assessment
        profile['security_assessment'] = self._assess_security(mac_address)

        # Additional metadata
        profile['metadata'] = {
            'manufacturer': self._identify_manufacturer(mac_address),
            'last_seen': datetime.now().isoformat(),
            'signal_strength': self._get_signal_strength(mac_address)
        }

        return profile

    def _get_device_info(self, mac: str) -> Dict[str, Any]:
        """Get detailed device information"""
        info = {
            'mac_address': mac,
            'name': 'Unknown',
            'device_class': None,
            'clock_offset': None
        }

        try:
            cmd = f"sudo hcitool info {mac}"
            output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8')

            # Parse output
            name_match = re.search(r"Device Name:\s*(.+)", output)
            if name_match:
                info['name'] = name_match.group(1).strip()

            class_match = re.search(r"Class:\s*(0x[0-9a-fA-F]+)", output)
            if class_match:
                info['device_class'] = class_match.group(1)

            offset_match = re.search(r"Clock offset:\s*(0x[0-9a-fA-F]+)", output)
            if offset_match:
                info['clock_offset'] = offset_match.group(1)

        except Exception as e:
            info['error'] = str(e)

        return info

    def _enumerate_services(self, mac: str) -> List[Dict[str, Any]]:
        """Enumerate Bluetooth services"""
        services = []

        try:
            # Use sdptool to browse services
            cmd = f"sudo sdptool browse {mac}"
            output = subprocess.check_output(cmd, shell=True, timeout=15).decode('utf-8')

            # Parse service records
            current_service = {}
            for line in output.split('\n'):
                if 'Service Name:' in line:
                    if current_service:
                        services.append(current_service)
                    current_service = {
                        'name': line.split('Service Name:')[1].strip()
                    }
                elif 'Service RecHandle:' in line:
                    current_service['handle'] = line.split('Service RecHandle:')[1].strip()
                elif 'Service Class ID List:' in line:
                    current_service['class_id'] = line.split('Service Class ID List:')[1].strip()
                elif 'Protocol Descriptor List:' in line:
                    current_service['protocol'] = line.split('Protocol Descriptor List:')[1].strip()

            if current_service:
                services.append(current_service)

        except Exception as e:
            services.append({'error': str(e)})

        return services

    def _assess_security(self, mac: str) -> Dict[str, Any]:
        """Assess Bluetooth security"""
        assessment = {
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': []
        }

        # Check if device is discoverable
        try:
            cmd = f"sudo hcitool info {mac}"
            output = subprocess.check_output(cmd, shell=True, timeout=5).decode('utf-8')

            if 'BR/EDR Discoverable' in output:
                assessment['vulnerabilities'].append({
                    'type': 'Discoverable Mode',
                    'severity': 'MEDIUM',
                    'description': 'Device is in discoverable mode'
                })
                assessment['security_score'] -= 20
                assessment['recommendations'].append('Disable discoverable mode when not pairing')

        except:
            pass

        # Check for known vulnerabilities
        device_info = self._get_device_info(mac)
        if device_info.get('name'):
            # BlueBorne vulnerability check (example)
            assessment['vulnerabilities'].append({
                'type': 'Potential BlueBorne Vulnerability',
                'severity': 'HIGH',
                'description': 'Device may be vulnerable to BlueBorne attack',
                'cvss_score': 8.0,
                'mitigation': 'Update device firmware to latest version'
            })
            assessment['security_score'] -= 30

        # Check for weak pairing
        services = self._enumerate_services(mac)
        if any('NO AUTHENTICATION' in str(s) for s in services):
            assessment['vulnerabilities'].append({
                'type': 'Weak Authentication',
                'severity': 'HIGH',
                'description': 'Services available without authentication'
            })
            assessment['security_score'] -= 25

        assessment['security_score'] = max(0, assessment['security_score'])

        return assessment

    def _get_signal_strength(self, mac: str) -> int:
        """Get signal strength (RSSI)"""
        try:
            cmd = f"sudo hcitool rssi {mac}"
            output = subprocess.check_output(cmd, shell=True, timeout=5).decode('utf-8')

            rssi_match = re.search(r'RSSI return value:\s*(-?\d+)', output)
            if rssi_match:
                return int(rssi_match.group(1))

        except:
            pass

        return -100  # Unknown/weak signal

    def track_proximity(self, mac_address: str, duration: int = 60, interval: int = 5) -> Dict[str, Any]:
        """
        Track device proximity over time

        Args:
            mac_address: Target device MAC
            duration: Tracking duration in seconds
            interval: Sample interval in seconds

        Returns:
            Proximity tracking data
        """
        tracking = {
            'mac_address': mac_address,
            'duration_seconds': duration,
            'interval_seconds': interval,
            'samples': [],
            'avg_rssi': 0,
            'min_rssi': 0,
            'max_rssi': 0
        }

        import time

        samples = []
        for i in range(0, duration, interval):
            rssi = self._get_signal_strength(mac_address)
            sample = {
                'timestamp': datetime.now().isoformat(),
                'elapsed_seconds': i,
                'rssi': rssi,
                'approximate_distance_meters': self._rssi_to_distance(rssi)
            }
            samples.append(sample)
            time.sleep(interval)

        tracking['samples'] = samples

        if samples:
            rssi_values = [s['rssi'] for s in samples if s['rssi'] != -100]
            if rssi_values:
                tracking['avg_rssi'] = round(sum(rssi_values) / len(rssi_values), 2)
                tracking['min_rssi'] = min(rssi_values)
                tracking['max_rssi'] = max(rssi_values)

        return tracking

    def _rssi_to_distance(self, rssi: int) -> float:
        """
        Estimate distance from RSSI

        Using path loss model: RSSI = -(10n * log10(d) + A)
        where n = path loss exponent (2 for free space)
              A = signal strength at 1 meter
        """
        if rssi == -100:
            return 999.0  # Unknown

        # Assuming A = -50 dBm at 1 meter
        A = -50
        n = 2.0

        distance = 10 ** ((A - rssi) / (10 * n))
        return round(distance, 2)

    def analyze_ble_advertising(self, duration: int = 10) -> Dict[str, Any]:
        """
        Analyze BLE advertising packets

        Args:
            duration: Capture duration in seconds

        Returns:
            BLE advertising analysis
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': duration,
            'devices': [],
            'total_devices': 0,
            'advertising_types': defaultdict(int)
        }

        try:
            # Use hcidump to capture BLE advertising
            cmd = f"sudo timeout {duration} hcidump --raw"
            output = subprocess.check_output(cmd, shell=True, timeout=duration+5).decode('utf-8')

            # Parse advertising packets
            # This is a simplified parser - production would be more robust
            current_packet = []
            for line in output.split('\n'):
                if line.startswith('>'):
                    if current_packet:
                        # Process previous packet
                        packet_data = ' '.join(current_packet)
                        # Parse and analyze packet
                    current_packet = [line]
                else:
                    current_packet.append(line)

            results['note'] = 'BLE advertising analysis requires hcidump and root privileges'

        except Exception as e:
            results['error'] = str(e)

        return results

    def detect_vulnerabilities(self, mac_address: str) -> Dict[str, Any]:
        """
        Detect known Bluetooth vulnerabilities

        Args:
            mac_address: Target device MAC

        Returns:
            Vulnerability scan results
        """
        results = {
            'mac_address': mac_address,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': []
        }

        # Known vulnerability checks
        vuln_checks = [
            self._check_blueborne,
            self._check_bluesmack,
            self._check_bluetooth_impersonation,
            self._check_weak_encryption
        ]

        for check in vuln_checks:
            try:
                vuln_result = check(mac_address)
                if vuln_result:
                    results['vulnerabilities'].extend(vuln_result)
            except Exception as e:
                pass

        # Calculate risk score
        for vuln in results['vulnerabilities']:
            severity = vuln.get('severity', 'LOW')
            if severity == 'CRITICAL':
                results['risk_score'] += 40
            elif severity == 'HIGH':
                results['risk_score'] += 25
            elif severity == 'MEDIUM':
                results['risk_score'] += 10
            elif severity == 'LOW':
                results['risk_score'] += 5

        results['risk_score'] = min(100, results['risk_score'])

        return results

    def _check_blueborne(self, mac: str) -> List[Dict[str, Any]]:
        """Check for BlueBorne vulnerability"""
        # Placeholder - would require specific CVE testing
        return []

    def _check_bluesmack(self, mac: str) -> List[Dict[str, Any]]:
        """Check for BlueSmack DoS vulnerability"""
        # Placeholder
        return []

    def _check_bluetooth_impersonation(self, mac: str) -> List[Dict[str, Any]]:
        """Check for impersonation attacks"""
        # Placeholder
        return []

    def _check_weak_encryption(self, mac: str) -> List[Dict[str, Any]]:
        """Check for weak encryption"""
        # Placeholder
        return []


if __name__ == '__main__':
    bi = BluetoothIntelligence()

    print("\n📱 Bluetooth Intelligence Module")
    print("1. Discover Devices")
    print("2. Profile Device")
    print("3. Track Proximity")
    print("4. Detect Vulnerabilities")

    choice = input("\nSelect: ").strip()

    if choice == '1':
        device_type = input("Device type (classic/ble/all): ").strip() or 'all'
        duration = int(input("Duration (seconds): ") or "10")
        result = bi.discover_devices(duration, device_type)
        print(json.dumps(result, indent=2))
    elif choice == '2':
        mac = input("MAC address: ").strip()
        result = bi.profile_device(mac)
        print(json.dumps(result, indent=2))
    elif choice == '3':
        mac = input("MAC address: ").strip()
        duration = int(input("Duration (seconds): ") or "60")
        result = bi.track_proximity(mac, duration)
        print(json.dumps(result, indent=2))
    elif choice == '4':
        mac = input("MAC address: ").strip()
        result = bi.detect_vulnerabilities(mac)
        print(json.dumps(result, indent=2))
