#!/usr/bin/env python3
"""
🌐 TRAFFIC ANALYSIS MODULE
Network traffic monitoring, packet analysis, protocol detection
Authority Level: 11.0

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️

SIGINT PHASE 2 - Traffic Analysis Operations
"""

import subprocess
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import time

class TrafficAnalysis:
    """
    Comprehensive network traffic analysis

    Features:
    - Real-time packet capture and analysis
    - Protocol distribution analysis
    - Top talkers identification
    - Bandwidth monitoring
    - Anomaly detection
    - Deep packet inspection
    - Session tracking
    - DNS query analysis
    - HTTP/HTTPS traffic analysis
    - Suspicious activity detection
    """

    def __init__(self):
        self.capture_file = None
        self.stats = defaultdict(int)
        print("🌐 Traffic Analysis Module initialized")

    def capture_traffic(self, interface: str = 'eth0', duration: int = 60,
                       filter_expr: str = None) -> Dict[str, Any]:
        """
        Capture network traffic for analysis

        Args:
            interface: Network interface to capture on
            duration: Capture duration in seconds
            filter_expr: BPF filter expression (e.g., "tcp port 80")

        Returns:
            Capture results and statistics
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'interface': interface,
            'duration_seconds': duration,
            'filter': filter_expr or 'all',
            'capture_file': None,
            'packets_captured': 0,
            'bytes_captured': 0
        }

        # Generate capture filename
        capture_file = f"/tmp/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

        try:
            # Build tcpdump command
            cmd = ['sudo', 'tcpdump', '-i', interface, '-w', capture_file, '-G', str(duration)]

            if filter_expr:
                cmd.extend(filter_expr.split())

            # Run capture
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=duration + 5)

            # Parse capture statistics from stderr
            stats_output = stderr.decode('utf-8')
            packet_match = re.search(r'(\d+) packets captured', stats_output)
            if packet_match:
                results['packets_captured'] = int(packet_match.group(1))

            results['capture_file'] = capture_file
            self.capture_file = capture_file

        except Exception as e:
            results['error'] = str(e)

        return results

    def analyze_protocols(self, pcap_file: str = None) -> Dict[str, Any]:
        """
        Analyze protocol distribution in captured traffic

        Args:
            pcap_file: PCAP file to analyze (uses last capture if None)

        Returns:
            Protocol distribution analysis
        """
        if not pcap_file:
            pcap_file = self.capture_file

        if not pcap_file:
            return {'error': 'No capture file available'}

        analysis = {
            'pcap_file': pcap_file,
            'timestamp': datetime.now().isoformat(),
            'protocols': {},
            'total_packets': 0,
            'total_bytes': 0
        }

        try:
            # Use tshark for protocol analysis
            cmd = f"tshark -r {pcap_file} -q -z io,phs"
            output = subprocess.check_output(cmd, shell=True, timeout=30).decode('utf-8')

            # Parse protocol hierarchy
            for line in output.split('\n'):
                if 'frames' in line.lower() or 'bytes' in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        protocol = parts[0]
                        frames = int(parts[1]) if parts[1].isdigit() else 0
                        bytes_val = int(parts[2]) if parts[2].isdigit() else 0

                        analysis['protocols'][protocol] = {
                            'packets': frames,
                            'bytes': bytes_val
                        }
                        analysis['total_packets'] += frames
                        analysis['total_bytes'] += bytes_val

            # Calculate percentages
            if analysis['total_packets'] > 0:
                for protocol in analysis['protocols']:
                    packets = analysis['protocols'][protocol]['packets']
                    analysis['protocols'][protocol]['percentage'] = round(
                        (packets / analysis['total_packets']) * 100, 2
                    )

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    def identify_top_talkers(self, pcap_file: str = None, limit: int = 10) -> Dict[str, Any]:
        """
        Identify top communicating hosts

        Args:
            pcap_file: PCAP file to analyze
            limit: Number of top talkers to return

        Returns:
            Top talkers analysis
        """
        if not pcap_file:
            pcap_file = self.capture_file

        if not pcap_file:
            return {'error': 'No capture file available'}

        results = {
            'pcap_file': pcap_file,
            'timestamp': datetime.now().isoformat(),
            'top_sources': [],
            'top_destinations': [],
            'top_conversations': []
        }

        try:
            # Top source IPs
            cmd = f"tshark -r {pcap_file} -q -z ip_hosts,tree | head -n {limit+10}"
            output = subprocess.check_output(cmd, shell=True, timeout=30).decode('utf-8')

            # Parse output
            sources = {}
            for line in output.split('\n'):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    count = int(ip_match.group(2))
                    sources[ip] = count

            # Sort and limit
            sorted_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:limit]
            results['top_sources'] = [
                {'ip': ip, 'packet_count': count} for ip, count in sorted_sources
            ]

        except Exception as e:
            results['error'] = str(e)

        return results

    def monitor_bandwidth(self, interface: str = 'eth0', duration: int = 10) -> Dict[str, Any]:
        """
        Monitor bandwidth usage

        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds

        Returns:
            Bandwidth statistics
        """
        results = {
            'interface': interface,
            'duration_seconds': duration,
            'timestamp': datetime.now().isoformat(),
            'samples': [],
            'avg_rx_mbps': 0,
            'avg_tx_mbps': 0,
            'peak_rx_mbps': 0,
            'peak_tx_mbps': 0
        }

        try:
            # Read initial stats
            rx_bytes_start, tx_bytes_start = self._get_interface_stats(interface)

            # Sample every second
            samples = []
            for i in range(duration):
                time.sleep(1)
                rx_bytes, tx_bytes = self._get_interface_stats(interface)

                # Calculate rates in Mbps
                rx_mbps = ((rx_bytes - rx_bytes_start) * 8) / (1000000 * (i + 1))
                tx_mbps = ((tx_bytes - tx_bytes_start) * 8) / (1000000 * (i + 1))

                sample = {
                    'second': i + 1,
                    'rx_mbps': round(rx_mbps, 2),
                    'tx_mbps': round(tx_mbps, 2)
                }
                samples.append(sample)

            results['samples'] = samples

            # Calculate statistics
            if samples:
                rx_rates = [s['rx_mbps'] for s in samples]
                tx_rates = [s['tx_mbps'] for s in samples]

                results['avg_rx_mbps'] = round(sum(rx_rates) / len(rx_rates), 2)
                results['avg_tx_mbps'] = round(sum(tx_rates) / len(tx_rates), 2)
                results['peak_rx_mbps'] = round(max(rx_rates), 2)
                results['peak_tx_mbps'] = round(max(tx_rates), 2)

        except Exception as e:
            results['error'] = str(e)

        return results

    def _get_interface_stats(self, interface: str) -> Tuple[int, int]:
        """Get RX/TX bytes for interface"""
        try:
            with open(f'/sys/class/net/{interface}/statistics/rx_bytes', 'r') as f:
                rx_bytes = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/tx_bytes', 'r') as f:
                tx_bytes = int(f.read().strip())
            return rx_bytes, tx_bytes
        except:
            return 0, 0

    def detect_anomalies(self, pcap_file: str = None) -> Dict[str, Any]:
        """
        Detect suspicious or anomalous network traffic

        Args:
            pcap_file: PCAP file to analyze

        Returns:
            Anomaly detection results
        """
        if not pcap_file:
            pcap_file = self.capture_file

        if not pcap_file:
            return {'error': 'No capture file available'}

        results = {
            'pcap_file': pcap_file,
            'timestamp': datetime.now().isoformat(),
            'anomalies': [],
            'total_anomalies': 0,
            'severity_breakdown': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }

        # Placeholder for anomaly detection logic
        # In production, this would use ML models, baseline comparisons, etc.

        anomaly_checks = [
            self._check_port_scanning,
            self._check_dns_tunneling,
            self._check_data_exfiltration,
            self._check_suspicious_protocols,
            self._check_unusual_traffic_patterns
        ]

        for check in anomaly_checks:
            try:
                anomalies = check(pcap_file)
                results['anomalies'].extend(anomalies)
            except Exception as e:
                pass

        # Calculate severity breakdown
        for anomaly in results['anomalies']:
            severity = anomaly.get('severity', 'LOW')
            results['severity_breakdown'][severity] += 1

        results['total_anomalies'] = len(results['anomalies'])

        return results

    def _check_port_scanning(self, pcap_file: str) -> List[Dict[str, Any]]:
        """Detect port scanning activity"""
        anomalies = []

        try:
            # Count unique destination ports per source IP
            cmd = f"tshark -r {pcap_file} -T fields -e ip.src -e tcp.dstport 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True, timeout=30).decode('utf-8')

            # Parse and analyze
            port_counts = defaultdict(set)
            for line in output.split('\n'):
                if '\t' in line:
                    src_ip, dst_port = line.strip().split('\t')
                    if dst_port:
                        port_counts[src_ip].add(dst_port)

            # Flag IPs accessing many different ports
            for src_ip, ports in port_counts.items():
                if len(ports) > 20:
                    anomalies.append({
                        'type': 'Port Scanning',
                        'source_ip': src_ip,
                        'unique_ports_accessed': len(ports),
                        'severity': 'HIGH',
                        'description': f'Source IP accessed {len(ports)} different ports'
                    })

        except:
            pass

        return anomalies

    def _check_dns_tunneling(self, pcap_file: str) -> List[Dict[str, Any]]:
        """Detect potential DNS tunneling"""
        anomalies = []

        try:
            # Look for unusually long DNS queries
            cmd = f"tshark -r {pcap_file} -Y 'dns.qry.name' -T fields -e dns.qry.name 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True, timeout=30).decode('utf-8')

            for line in output.split('\n'):
                query = line.strip()
                if len(query) > 50:  # Unusually long DNS query
                    anomalies.append({
                        'type': 'DNS Tunneling',
                        'dns_query': query[:100],  # Truncate for display
                        'query_length': len(query),
                        'severity': 'HIGH',
                        'description': 'Unusually long DNS query may indicate tunneling'
                    })

        except:
            pass

        return anomalies

    def _check_data_exfiltration(self, pcap_file: str) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration"""
        anomalies = []

        # This would analyze upload/download ratios, destination IPs, etc.
        # Placeholder for now

        return anomalies

    def _check_suspicious_protocols(self, pcap_file: str) -> List[Dict[str, Any]]:
        """Detect use of suspicious protocols"""
        anomalies = []

        try:
            # Look for protocols that might be suspicious
            suspicious_ports = {
                4444: 'Metasploit default',
                5555: 'Common backdoor',
                6666: 'IRC/Backdoor',
                31337: 'Elite/Backdoor',
                12345: 'NetBus trojan'
            }

            cmd = f"tshark -r {pcap_file} -T fields -e tcp.dstport -e tcp.srcport 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True, timeout=30).decode('utf-8')

            for line in output.split('\n'):
                if '\t' in line:
                    dst_port, src_port = line.strip().split('\t')
                    for port in [dst_port, src_port]:
                        if port.isdigit() and int(port) in suspicious_ports:
                            anomalies.append({
                                'type': 'Suspicious Protocol',
                                'port': int(port),
                                'description': suspicious_ports[int(port)],
                                'severity': 'CRITICAL'
                            })

        except:
            pass

        return anomalies

    def _check_unusual_traffic_patterns(self, pcap_file: str) -> List[Dict[str, Any]]:
        """Detect unusual traffic patterns"""
        anomalies = []

        # This would use baseline comparisons, time-series analysis, etc.
        # Placeholder for now

        return anomalies

    def analyze_dns_queries(self, pcap_file: str = None, limit: int = 20) -> Dict[str, Any]:
        """
        Analyze DNS queries

        Args:
            pcap_file: PCAP file to analyze
            limit: Number of top queries to return

        Returns:
            DNS query analysis
        """
        if not pcap_file:
            pcap_file = self.capture_file

        if not pcap_file:
            return {'error': 'No capture file available'}

        results = {
            'pcap_file': pcap_file,
            'timestamp': datetime.now().isoformat(),
            'top_queries': [],
            'total_queries': 0,
            'unique_domains': 0
        }

        try:
            cmd = f"tshark -r {pcap_file} -Y 'dns.qry.name' -T fields -e dns.qry.name 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True, timeout=30).decode('utf-8')

            # Count queries
            query_counts = defaultdict(int)
            for line in output.split('\n'):
                query = line.strip()
                if query:
                    query_counts[query] += 1

            results['total_queries'] = sum(query_counts.values())
            results['unique_domains'] = len(query_counts)

            # Top queries
            sorted_queries = sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
            results['top_queries'] = [
                {'domain': domain, 'query_count': count} for domain, count in sorted_queries
            ]

        except Exception as e:
            results['error'] = str(e)

        return results

    def analyze_http_traffic(self, pcap_file: str = None) -> Dict[str, Any]:
        """
        Analyze HTTP/HTTPS traffic

        Args:
            pcap_file: PCAP file to analyze

        Returns:
            HTTP traffic analysis
        """
        if not pcap_file:
            pcap_file = self.capture_file

        if not pcap_file:
            return {'error': 'No capture file available'}

        results = {
            'pcap_file': pcap_file,
            'timestamp': datetime.now().isoformat(),
            'http_requests': [],
            'top_hosts': [],
            'user_agents': set(),
            'total_requests': 0
        }

        try:
            # Extract HTTP requests
            cmd = f"tshark -r {pcap_file} -Y 'http.request' -T fields -e http.host -e http.request.uri -e http.user_agent 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True, timeout=30).decode('utf-8')

            host_counts = defaultdict(int)

            for line in output.split('\n'):
                if '\t' in line:
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        host = parts[0]
                        uri = parts[1]
                        user_agent = parts[2] if len(parts) > 2 else 'Unknown'

                        results['http_requests'].append({
                            'host': host,
                            'uri': uri,
                            'user_agent': user_agent
                        })

                        host_counts[host] += 1
                        if user_agent:
                            results['user_agents'].add(user_agent)

            results['total_requests'] = len(results['http_requests'])

            # Top hosts
            sorted_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            results['top_hosts'] = [
                {'host': host, 'request_count': count} for host, count in sorted_hosts
            ]

            # Convert set to list for JSON serialization
            results['user_agents'] = list(results['user_agents'])

        except Exception as e:
            results['error'] = str(e)

        return results


if __name__ == '__main__':
    ta = TrafficAnalysis()

    print("\n🌐 Traffic Analysis Module")
    print("1. Capture Traffic")
    print("2. Analyze Protocols")
    print("3. Monitor Bandwidth")
    print("4. Detect Anomalies")
    print("5. Analyze DNS")

    choice = input("\nSelect: ").strip()

    if choice == '1':
        interface = input("Interface (eth0): ").strip() or 'eth0'
        duration = int(input("Duration (seconds): ") or "10")
        result = ta.capture_traffic(interface, duration)
        print(json.dumps(result, indent=2))
    elif choice == '3':
        interface = input("Interface (eth0): ").strip() or 'eth0'
        duration = int(input("Duration (seconds): ") or "10")
        result = ta.monitor_bandwidth(interface, duration)
        print(json.dumps(result, indent=2))
