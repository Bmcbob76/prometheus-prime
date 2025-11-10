#!/usr/bin/env python3
"""
📡 WIFI INTELLIGENCE MODULE
WiFi network reconnaissance, security assessment, client tracking
Authority Level: 11.0

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️

SIGINT PHASE 2 - WiFi Intelligence Operations
"""

import subprocess
import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import time

class WiFiIntelligence:
    """
    Comprehensive WiFi network intelligence gathering

    Features:
    - WiFi network discovery and enumeration
    - Security assessment (WEP, WPA, WPA2, WPA3)
    - Client device tracking and profiling
    - Signal strength analysis
    - Channel utilization monitoring
    - Hidden SSID detection
    - Rogue AP detection
    - WPS vulnerability assessment
    """

    def __init__(self):
        self.interface = None
        self.monitor_mode = False
        self.cache = {}
        print("📡 WiFi Intelligence Module initialized")

    def discover_networks(self, interface: str = 'wlan0', duration: int = 30) -> Dict[str, Any]:
        """
        Discover WiFi networks in range

        Args:
            interface: Wireless interface name
            duration: Scan duration in seconds

        Returns:
            Dictionary with discovered networks and their properties
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'interface': interface,
            'duration_seconds': duration,
            'networks': [],
            'total_networks': 0,
            'security_breakdown': {
                'OPEN': 0,
                'WEP': 0,
                'WPA': 0,
                'WPA2': 0,
                'WPA3': 0,
                'ENTERPRISE': 0
            }
        }

        # Try multiple scanning methods
        networks = self._scan_with_iwlist(interface, duration)
        if not networks:
            networks = self._scan_with_nmcli(duration)
        if not networks:
            networks = self._scan_with_iw(interface, duration)

        for network in networks:
            # Categorize security
            security = network.get('security', 'UNKNOWN')
            if 'WPA3' in security:
                results['security_breakdown']['WPA3'] += 1
            elif 'WPA2' in security or 'WPA-PSK' in security:
                results['security_breakdown']['WPA2'] += 1
            elif 'WPA' in security:
                results['security_breakdown']['WPA'] += 1
            elif 'WEP' in security:
                results['security_breakdown']['WEP'] += 1
            elif 'ENTERPRISE' in security or '802.1X' in security:
                results['security_breakdown']['ENTERPRISE'] += 1
            elif 'OPEN' in security or security == '':
                results['security_breakdown']['OPEN'] += 1

        results['networks'] = networks
        results['total_networks'] = len(networks)

        return results

    def _scan_with_iwlist(self, interface: str, duration: int) -> List[Dict[str, Any]]:
        """Scan using iwlist tool"""
        try:
            cmd = f"sudo iwlist {interface} scan"
            output = subprocess.check_output(cmd, shell=True, timeout=duration+5).decode('utf-8')

            networks = []
            current_network = {}

            for line in output.split('\n'):
                line = line.strip()

                if 'Cell' in line and 'Address:' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {
                        'bssid': line.split('Address: ')[-1].strip(),
                        'method': 'iwlist'
                    }
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[-1].strip('"')
                    current_network['ssid'] = essid if essid else '<Hidden>'
                elif 'Channel:' in line:
                    current_network['channel'] = line.split('Channel:')[-1].strip()
                elif 'Quality=' in line:
                    quality_match = re.search(r'Quality=(\d+)/(\d+)', line)
                    if quality_match:
                        current_network['quality'] = f"{quality_match.group(1)}/{quality_match.group(2)}"
                    signal_match = re.search(r'Signal level=(-?\d+)', line)
                    if signal_match:
                        current_network['signal_dbm'] = int(signal_match.group(1))
                elif 'Encryption key:' in line:
                    current_network['encrypted'] = 'on' in line.lower()
                elif 'IE: IEEE 802.11i/WPA2' in line:
                    current_network['security'] = 'WPA2'
                elif 'IE: WPA Version' in line:
                    current_network['security'] = 'WPA'
                elif 'WEP' in line:
                    current_network['security'] = 'WEP'

            if current_network:
                networks.append(current_network)

            return networks
        except Exception as e:
            print(f"iwlist scan failed: {e}")
            return []

    def _scan_with_nmcli(self, duration: int) -> List[Dict[str, Any]]:
        """Scan using nmcli (NetworkManager)"""
        try:
            # Trigger rescan
            subprocess.run("nmcli device wifi rescan", shell=True, stderr=subprocess.DEVNULL, timeout=5)
            time.sleep(2)

            # Get networks
            cmd = "nmcli -f SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY device wifi list"
            output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8')

            networks = []
            lines = output.split('\n')[1:]  # Skip header

            for line in lines:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) >= 5:
                    network = {
                        'ssid': parts[0] if parts[0] != '--' else '<Hidden>',
                        'bssid': parts[1] if len(parts) > 1 else 'Unknown',
                        'channel': parts[3] if len(parts) > 3 else 'Unknown',
                        'signal_dbm': int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else -100,
                        'security': ' '.join(parts[7:]) if len(parts) > 7 else 'OPEN',
                        'method': 'nmcli'
                    }
                    networks.append(network)

            return networks
        except Exception as e:
            print(f"nmcli scan failed: {e}")
            return []

    def _scan_with_iw(self, interface: str, duration: int) -> List[Dict[str, Any]]:
        """Scan using iw tool"""
        try:
            cmd = f"sudo iw dev {interface} scan"
            output = subprocess.check_output(cmd, shell=True, timeout=duration+5).decode('utf-8')

            networks = []
            current_network = {}

            for line in output.split('\n'):
                line = line.strip()

                if line.startswith('BSS '):
                    if current_network:
                        networks.append(current_network)
                    bssid = line.split('BSS ')[1].split('(')[0].strip()
                    current_network = {'bssid': bssid, 'method': 'iw'}
                elif 'SSID:' in line:
                    ssid = line.split('SSID: ')[-1].strip()
                    current_network['ssid'] = ssid if ssid else '<Hidden>'
                elif 'freq:' in line:
                    freq = line.split('freq: ')[-1].strip()
                    current_network['frequency_mhz'] = freq
                    # Calculate channel from frequency
                    if freq:
                        try:
                            freq_int = int(freq)
                            if 2412 <= freq_int <= 2484:
                                current_network['channel'] = str((freq_int - 2407) // 5)
                            elif freq_int >= 5000:
                                current_network['channel'] = str((freq_int - 5000) // 5)
                        except:
                            pass
                elif 'signal:' in line:
                    signal = line.split('signal: ')[-1].split()[0]
                    try:
                        current_network['signal_dbm'] = float(signal)
                    except:
                        pass
                elif 'WPA:' in line:
                    current_network['security'] = 'WPA'
                elif 'RSN:' in line:
                    current_network['security'] = 'WPA2'

            if current_network:
                networks.append(current_network)

            return networks
        except Exception as e:
            print(f"iw scan failed: {e}")
            return []

    def assess_security(self, ssid: str, bssid: str) -> Dict[str, Any]:
        """
        Assess WiFi network security

        Args:
            ssid: Network SSID
            bssid: Network BSSID (MAC address)

        Returns:
            Security assessment report
        """
        assessment = {
            'ssid': ssid,
            'bssid': bssid,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'recommendations': [],
            'security_score': 100  # Start at 100, deduct for issues
        }

        # Check for weak security
        network_info = self._get_network_details(bssid)

        if not network_info:
            assessment['error'] = 'Network not found'
            return assessment

        security = network_info.get('security', 'UNKNOWN')

        # Open network
        if 'OPEN' in security or security == '':
            assessment['vulnerabilities'].append({
                'type': 'No Encryption',
                'severity': 'CRITICAL',
                'description': 'Network has no encryption - all traffic visible',
                'cvss_score': 10.0
            })
            assessment['security_score'] -= 70
            assessment['recommendations'].append('Enable WPA2 or WPA3 encryption immediately')

        # WEP encryption
        elif 'WEP' in security:
            assessment['vulnerabilities'].append({
                'type': 'WEP Encryption',
                'severity': 'CRITICAL',
                'description': 'WEP is broken and can be cracked in minutes',
                'cvss_score': 9.5
            })
            assessment['security_score'] -= 60
            assessment['recommendations'].append('Upgrade to WPA2 or WPA3 immediately')

        # WPA (no 2)
        elif 'WPA' in security and 'WPA2' not in security and 'WPA3' not in security:
            assessment['vulnerabilities'].append({
                'type': 'WPA1 Encryption',
                'severity': 'HIGH',
                'description': 'WPA1 has known vulnerabilities (TKIP weakness)',
                'cvss_score': 7.5
            })
            assessment['security_score'] -= 30
            assessment['recommendations'].append('Upgrade to WPA2 or WPA3')

        # WPS enabled check
        wps_status = self._check_wps(bssid)
        if wps_status.get('enabled'):
            assessment['vulnerabilities'].append({
                'type': 'WPS Enabled',
                'severity': 'HIGH',
                'description': 'WPS is vulnerable to brute force attacks',
                'cvss_score': 8.0
            })
            assessment['security_score'] -= 25
            assessment['recommendations'].append('Disable WPS to prevent brute force attacks')

        # Hidden SSID check
        if ssid == '<Hidden>' or ssid == '':
            assessment['vulnerabilities'].append({
                'type': 'Hidden SSID',
                'severity': 'LOW',
                'description': 'Hidden SSID provides minimal security and can be detected',
                'cvss_score': 2.0
            })
            assessment['security_score'] -= 5
            assessment['recommendations'].append('Hidden SSID provides false sense of security')

        # Weak signal (potential for rogue AP)
        signal = network_info.get('signal_dbm', -100)
        if signal > -30:
            assessment['vulnerabilities'].append({
                'type': 'Unusually Strong Signal',
                'severity': 'MEDIUM',
                'description': 'Signal too strong - possible rogue AP or very close attacker',
                'cvss_score': 5.0
            })
            assessment['recommendations'].append('Verify AP is legitimate and not a rogue device')

        # Ensure score doesn't go below 0
        assessment['security_score'] = max(0, assessment['security_score'])

        return assessment

    def _get_network_details(self, bssid: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific network"""
        # This would typically be from a cached scan
        return self.cache.get(bssid)

    def _check_wps(self, bssid: str) -> Dict[str, Any]:
        """Check if WPS is enabled on network"""
        try:
            # This would use tools like wash or reaver
            # Placeholder for now
            return {
                'enabled': False,
                'method': 'Not implemented - requires wash/reaver'
            }
        except:
            return {'enabled': False}

    def track_clients(self, bssid: str, duration: int = 60) -> Dict[str, Any]:
        """
        Track client devices connected to WiFi network

        Args:
            bssid: Target network BSSID
            duration: Monitoring duration in seconds

        Returns:
            Client tracking results
        """
        results = {
            'bssid': bssid,
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': duration,
            'clients': [],
            'total_clients': 0,
            'method': 'Passive monitoring'
        }

        # This would typically use airodump-ng or similar
        # Placeholder implementation
        results['note'] = 'Requires monitor mode and airodump-ng for live tracking'

        return results

    def channel_analysis(self, interface: str = 'wlan0') -> Dict[str, Any]:
        """
        Analyze WiFi channel utilization

        Returns:
            Channel usage analysis
        """
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'channels': {},
            'recommendations': []
        }

        # Scan all networks
        scan_results = self.discover_networks(interface, duration=10)

        # Analyze channel usage
        channel_counts = {}
        for network in scan_results['networks']:
            channel = network.get('channel', 'Unknown')
            if channel != 'Unknown':
                channel_counts[channel] = channel_counts.get(channel, 0) + 1

        # Build analysis
        for channel, count in sorted(channel_counts.items()):
            analysis['channels'][channel] = {
                'network_count': count,
                'congestion': 'High' if count >= 5 else 'Medium' if count >= 3 else 'Low'
            }

        # Recommendations
        if channel_counts:
            least_used = min(channel_counts, key=channel_counts.get)
            analysis['recommendations'].append(f"Consider using channel {least_used} (least congested)")

        return analysis

    def detect_rogue_aps(self, known_networks: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Detect potential rogue access points

        Args:
            known_networks: List of known legitimate networks
                           [{"ssid": "MyNetwork", "bssid": "AA:BB:CC:DD:EE:FF"}, ...]

        Returns:
            Rogue AP detection results
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'suspicious_aps': [],
            'total_suspicious': 0
        }

        # Create lookup dict
        known_dict = {net['bssid']: net['ssid'] for net in known_networks}

        # Scan networks
        scan = self.discover_networks(duration=20)

        for network in scan['networks']:
            bssid = network.get('bssid', '')
            ssid = network.get('ssid', '')

            # Check for SSID spoofing (same SSID, different BSSID)
            for known_net in known_networks:
                if ssid == known_net['ssid'] and bssid != known_net['bssid']:
                    results['suspicious_aps'].append({
                        'type': 'SSID Spoofing',
                        'ssid': ssid,
                        'rogue_bssid': bssid,
                        'legitimate_bssid': known_net['bssid'],
                        'severity': 'HIGH',
                        'signal_dbm': network.get('signal_dbm', -100)
                    })

        results['total_suspicious'] = len(results['suspicious_aps'])

        return results


if __name__ == '__main__':
    wi = WiFiIntelligence()

    print("\n📡 WiFi Intelligence Module")
    print("1. Discover Networks")
    print("2. Assess Security")
    print("3. Channel Analysis")
    print("4. Detect Rogue APs")

    choice = input("\nSelect: ").strip()

    if choice == '1':
        result = wi.discover_networks()
        print(json.dumps(result, indent=2))
    elif choice == '2':
        ssid = input("SSID: ").strip()
        bssid = input("BSSID: ").strip()
        result = wi.assess_security(ssid, bssid)
        print(json.dumps(result, indent=2))
    elif choice == '3':
        result = wi.channel_analysis()
        print(json.dumps(result, indent=2))
