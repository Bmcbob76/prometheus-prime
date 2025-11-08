#!/usr/bin/env python3
"""
🌐 NETWORK SECURITY MODULE
Port scanning, service enumeration, vulnerability detection
Authority Level: 11.0
"""

import socket
import concurrent.futures
from datetime import datetime
from typing import Dict, Any, List, Tuple
import subprocess
import json
import re

class NetworkSecurity:
    """Network reconnaissance and security scanning"""
    
    def __init__(self):
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        print("🌐 Network Security Module initialized")
    
    def port_scan(self, target: str, ports: List[int] = None, timeout: float = 1.0) -> Dict[str, Any]:
        """
        Fast multi-threaded port scanner
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan (default: common ports)
            timeout: Socket timeout in seconds
        """
        if ports is None:
            ports = list(self.common_ports.keys())
        
        print(f"🔍 Scanning {target} ({len(ports)} ports)...")
        
        open_ports = []
        
        def scan_port(port: int) -> Tuple[int, bool, str]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self.common_ports.get(port, 'Unknown')
                    return (port, True, service)
            except:
                pass
            return (port, False, '')
        
        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(scan_port, ports)
        
        for port, is_open, service in results:
            if is_open:
                open_ports.append({
                    'port': port,
                    'service': service,
                    'state': 'open'
                })
        
        print(f"✅ Scan complete: {len(open_ports)} ports open")
        
        return {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': open_ports,
            'total_open': len(open_ports)
        }
    
    def service_banner_grab(self, target: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """Grab service banner for fingerprinting"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send probe
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {
                'target': target,
                'port': port,
                'banner': banner,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'target': target,
                'port': port,
                'error': str(e)
            }
    
    def nmap_scan(self, target: str, scan_type: str = 'basic') -> Dict[str, Any]:
        """
        Execute Nmap scan (requires Nmap installed)
        
        Scan types:
        - basic: Fast port scan
        - full: Comprehensive scan with service detection
        - vuln: Vulnerability scanning
        - aggressive: OS detection + service versions + scripts
        """
        scan_commands = {
            'basic': ['nmap', '-F', target],
            'full': ['nmap', '-p-', '-sV', target],
            'vuln': ['nmap', '--script', 'vuln', target],
            'aggressive': ['nmap', '-A', '-T4', target]
        }
        
        if scan_type not in scan_commands:
            return {'error': f'Invalid scan type: {scan_type}'}
        
        try:
            print(f"🔍 Running Nmap {scan_type} scan on {target}...")
            result = subprocess.run(
                scan_commands[scan_type],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                'target': target,
                'scan_type': scan_type,
                'output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Scan timeout'}
        except FileNotFoundError:
            return {'error': 'Nmap not installed'}
        except Exception as e:
            return {'error': str(e)}
    
    def subnet_scan(self, subnet: str) -> Dict[str, Any]:
        """
        Scan entire subnet for live hosts
        
        Args:
            subnet: CIDR notation (e.g., 192.168.1.0/24)
        """
        try:
            print(f"🌐 Scanning subnet {subnet}...")
            result = subprocess.run(
                ['nmap', '-sn', subnet],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Parse live hosts
            lines = result.stdout.split('\n')
            live_hosts = []
            
            for line in lines:
                if 'Nmap scan report for' in line:
                    host = line.split('for ')[-1].strip()
                    live_hosts.append(host)
            
            return {
                'subnet': subnet,
                'live_hosts': live_hosts,
                'total_hosts': len(live_hosts),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Quick vulnerability assessment"""
        vulns = []
        
        # Check for common vulnerabilities
        checks = {
            21: self._check_ftp_anon,
            22: self._check_ssh_weak,
            80: self._check_http_vulns,
            443: self._check_https_vulns,
            3306: self._check_mysql_anon,
            3389: self._check_rdp_vulns
        }
        
        # Port scan first
        scan_result = self.port_scan(target, list(checks.keys()))
        
        for port_info in scan_result['open_ports']:
            port = port_info['port']
            if port in checks:
                vuln_check = checks[port](target, port)
                if vuln_check:
                    vulns.extend(vuln_check)
        
        return {
            'target': target,
            'vulnerabilities': vulns,
            'total_vulns': len(vulns),
            'timestamp': datetime.now().isoformat()
        }
    
    def _check_ftp_anon(self, target: str, port: int) -> List[Dict]:
        """Check for anonymous FTP"""
        try:
            import ftplib
            ftp = ftplib.FTP(timeout=3)
            ftp.connect(target, port)
            ftp.login('anonymous', 'anonymous@')
            ftp.quit()
            return [{'port': port, 'type': 'FTP Anonymous Login', 'severity': 'high'}]
        except:
            return []
    
    def _check_ssh_weak(self, target: str, port: int) -> List[Dict]:
        """Check SSH configuration"""
        vulns = []
        banner = self.service_banner_grab(target, port)
        if 'banner' in banner:
            if 'OpenSSH' in banner['banner']:
                # Check for old versions
                if any(v in banner['banner'] for v in ['5.3', '6.6', '7.2']):
                    vulns.append({
                        'port': port,
                        'type': 'Outdated SSH Version',
                        'severity': 'medium'
                    })
        return vulns
    
    def _check_http_vulns(self, target: str, port: int) -> List[Dict]:
        """Check HTTP vulnerabilities"""
        vulns = []
        try:
            import requests
            response = requests.get(f'http://{target}:{port}', timeout=3, verify=False)
            
            # Check headers
            if 'Server' in response.headers:
                vulns.append({
                    'port': port,
                    'type': 'Server Version Disclosure',
                    'severity': 'low',
                    'details': response.headers['Server']
                })
            
            if 'X-Powered-By' in response.headers:
                vulns.append({
                    'port': port,
                    'type': 'Technology Disclosure',
                    'severity': 'low',
                    'details': response.headers['X-Powered-By']
                })
        except:
            pass
        return vulns
    
    def _check_https_vulns(self, target: str, port: int) -> List[Dict]:
        """Check HTTPS/TLS vulnerabilities"""
        return self._check_http_vulns(target, port)
    
    def _check_mysql_anon(self, target: str, port: int) -> List[Dict]:
        """Check MySQL anonymous access"""
        try:
            import pymysql
            conn = pymysql.connect(host=target, port=port, user='root', password='', connect_timeout=3)
            conn.close()
            return [{'port': port, 'type': 'MySQL No Password', 'severity': 'critical'}]
        except:
            return []
    
    def _check_rdp_vulns(self, target: str, port: int) -> List[Dict]:
        """Check RDP vulnerabilities"""
        return [{'port': port, 'type': 'RDP Exposed', 'severity': 'medium'}]
    
    def traceroute(self, target: str) -> Dict[str, Any]:
        """Network path tracing"""
        try:
            result = subprocess.run(
                ['tracert', target] if os.name == 'nt' else ['traceroute', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'target': target,
                'path': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}


def main():
    """Test network security tools"""
    ns = NetworkSecurity()
    
    target = input("Enter target IP/hostname: ").strip()
    
    if not target:
        print("❌ Target required")
        return
    
    print("\n1. Port Scan")
    print("2. Nmap Scan")
    print("3. Vulnerability Scan")
    print("4. Service Banner Grab")
    
    choice = input("\nSelect scan type: ").strip()
    
    if choice == '1':
        result = ns.port_scan(target)
        print(json.dumps(result, indent=2))
    elif choice == '2':
        result = ns.nmap_scan(target, 'basic')
        print(result['output'])
    elif choice == '3':
        result = ns.vulnerability_scan(target)
        print(json.dumps(result, indent=2))
    elif choice == '4':
        port = int(input("Port: "))
        result = ns.service_banner_grab(target, port)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    import os
    main()
