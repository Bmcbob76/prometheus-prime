#!/usr/bin/env python3
"""
NETWORK RECON - Network Reconnaissance & Mapping
Authority Level: 9.9
"""

import subprocess
import socket
import ipaddress
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class NetworkRecon:
    """Network reconnaissance operations"""
    
    def __init__(self):
        self.nmap_available = self._check_nmap()
        
    def _check_nmap(self) -> bool:
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def ping_sweep(self, network: str) -> Dict:
        """Perform ping sweep of network"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            alive_hosts = []
            
            for ip in list(net.hosts())[:254]:  # Limit to class C
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((str(ip), 80))
                    if result == 0:
                        alive_hosts.append(str(ip))
                    sock.close()
                except:
                    pass
            
            return {
                'status': 'success',
                'network': network,
                'alive_hosts': alive_hosts,
                'count': len(alive_hosts)
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def port_scan(self, target: str, ports: List[int] = None) -> Dict:
        """Scan target for open ports"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return {
            'status': 'success',
            'target': target,
            'open_ports': open_ports,
            'count': len(open_ports)
        }
    
    def nmap_scan(self, target: str, scan_type: str = 'quick') -> Dict:
        """Execute nmap scan"""
        if not self.nmap_available:
            return {'status': 'error', 'error': 'nmap not installed'}
        
        scan_commands = {
            'quick': f'nmap -T4 -F {target}',
            'full': f'nmap -T4 -A -p- {target}',
            'stealth': f'nmap -sS -T2 {target}',
            'udp': f'nmap -sU {target}',
            'os': f'nmap -O {target}'
        }
        
        cmd = scan_commands.get(scan_type, scan_commands['quick'])
        
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': scan_type,
                'output': result.stdout
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'message': 'Scan exceeded time limit'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def service_detection(self, target: str, port: int) -> Dict:
        """Detect service running on port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Send HTTP request to probe service
            sock.send(b'GET / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {
                'status': 'success',
                'target': target,
                'port': port,
                'banner': banner[:200]  # First 200 chars
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def dns_enum(self, domain: str) -> Dict:
        """Enumerate DNS records"""
        try:
            import dns.resolver
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            records = {}
            
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(rdata) for rdata in answers]
                except:
                    records[rtype] = []
            
            return {
                'status': 'success',
                'domain': domain,
                'records': records
            }
        except ImportError:
            return {'status': 'error', 'error': 'dnspython not installed'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Network Reconnaissance")
    parser.add_argument('--target', help='Target host/network')
    parser.add_argument('--ping-sweep', action='store_true')
    parser.add_argument('--port-scan', action='store_true')
    parser.add_argument('--nmap', choices=['quick', 'full', 'stealth', 'udp', 'os'])
    parser.add_argument('--service', type=int, help='Detect service on port')
    
    args = parser.parse_args()
    
    recon = NetworkRecon()
    
    if args.ping_sweep and args.target:
        result = recon.ping_sweep(args.target)
        print(f"Ping Sweep: {result['status']}")
        print(f"Alive hosts: {result.get('count', 0)}")
        for host in result.get('alive_hosts', []):
            print(f"  {host}")
    
    if args.port_scan and args.target:
        result = recon.port_scan(args.target)
        print(f"Port Scan: {result['status']}")
        print(f"Open ports on {args.target}:")
        for port in result.get('open_ports', []):
            print(f"  Port {port}")
    
    if args.nmap and args.target:
        result = recon.nmap_scan(args.target, args.nmap)
        print(f"Nmap Scan: {result['status']}")
        print(result.get('output', ''))
