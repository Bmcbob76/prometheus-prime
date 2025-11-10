"""
PROMETHEUS PRIME - NETWORK DIAGNOSTICS MODULE

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️

Network connectivity, latency, bandwidth, DNS resolution diagnostics.
Comprehensive network health monitoring and performance analysis.
"""

import asyncio
import socket
import time
import subprocess
import platform
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None


class NetworkDiagnostics:
    """
    Comprehensive network diagnostics system.

    Features:
    - Connectivity testing (ping, HTTP, TCP)
    - Latency measurements (RTT, jitter)
    - Bandwidth testing
    - DNS resolution testing
    - Route tracing
    - Port connectivity
    - Network interface status
    """

    def __init__(self):
        self.logger = logging.getLogger("NetworkDiagnostics")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "connectivity": {},
            "latency": {},
            "bandwidth": {},
            "dns": {},
            "routes": {},
            "interfaces": {},
            "ports": {},
            "health_score": 0
        }

    def run_full_diagnostics(self) -> Dict:
        """Run complete network diagnostics suite."""
        self.logger.info("Starting network diagnostics...")

        # Connectivity tests
        self.test_internet_connectivity()
        self.test_dns_connectivity()
        self.test_gateway_connectivity()

        # Latency measurements
        self.measure_latency()
        self.measure_jitter()

        # Bandwidth testing
        self.test_bandwidth()

        # DNS diagnostics
        self.test_dns_resolution()
        self.test_dns_servers()

        # Network infrastructure
        self.check_network_interfaces()
        self.test_common_ports()
        self.trace_routes()

        # Calculate overall health
        self.calculate_network_health()

        self.logger.info("Network diagnostics complete")
        return self.results

    def test_internet_connectivity(self) -> Dict:
        """Test internet connectivity to multiple endpoints."""
        self.logger.info("Testing internet connectivity...")

        test_endpoints = [
            ("google.com", 80),
            ("cloudflare.com", 443),
            ("amazon.com", 443),
            ("github.com", 443)
        ]

        results = {
            "reachable": [],
            "unreachable": [],
            "success_rate": 0
        }

        for host, port in test_endpoints:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    results["reachable"].append(f"{host}:{port}")
                else:
                    results["unreachable"].append(f"{host}:{port}")
            except Exception as e:
                results["unreachable"].append(f"{host}:{port} (Error: {str(e)})")

        total = len(test_endpoints)
        reachable = len(results["reachable"])
        results["success_rate"] = (reachable / total * 100) if total > 0 else 0

        self.results["connectivity"]["internet"] = results
        return results

    def test_dns_connectivity(self) -> Dict:
        """Test DNS server connectivity."""
        self.logger.info("Testing DNS connectivity...")

        dns_servers = [
            ("8.8.8.8", "Google DNS"),
            ("1.1.1.1", "Cloudflare DNS"),
            ("208.67.222.222", "OpenDNS")
        ]

        results = {
            "reachable": [],
            "unreachable": []
        }

        for dns_ip, dns_name in dns_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.connect((dns_ip, 53))
                sock.close()
                results["reachable"].append(dns_name)
            except Exception as e:
                results["unreachable"].append(f"{dns_name} ({str(e)})")

        self.results["connectivity"]["dns_servers"] = results
        return results

    def test_gateway_connectivity(self) -> Dict:
        """Test default gateway connectivity."""
        self.logger.info("Testing gateway connectivity...")

        results = {
            "gateway": None,
            "reachable": False,
            "latency_ms": None
        }

        try:
            # Get default gateway
            if platform.system() == "Windows":
                output = subprocess.check_output("route print", shell=True).decode()
                # Parse for default gateway
                for line in output.split('\n'):
                    if "0.0.0.0" in line and "0.0.0.0" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            results["gateway"] = parts[2]
                            break
            else:
                output = subprocess.check_output("ip route show default", shell=True).decode()
                if "via" in output:
                    results["gateway"] = output.split("via")[1].split()[0]

            # Test gateway reachability
            if results["gateway"]:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((results["gateway"], 80))
                elapsed = (time.time() - start_time) * 1000
                sock.close()

                if result == 0 or result == 111:  # Connected or connection refused (but reachable)
                    results["reachable"] = True
                    results["latency_ms"] = round(elapsed, 2)

        except Exception as e:
            self.logger.warning(f"Gateway test failed: {e}")
            results["error"] = str(e)

        self.results["connectivity"]["gateway"] = results
        return results

    def measure_latency(self, hosts: Optional[List[str]] = None) -> Dict:
        """Measure latency (RTT) to various hosts."""
        self.logger.info("Measuring latency...")

        if hosts is None:
            hosts = ["8.8.8.8", "1.1.1.1", "google.com", "github.com"]

        results = {}

        for host in hosts:
            try:
                # TCP connection time measurement
                times = []
                for _ in range(5):
                    start = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)

                    try:
                        sock.connect((host, 80))
                        elapsed = (time.time() - start) * 1000
                        times.append(elapsed)
                    except:
                        pass
                    finally:
                        sock.close()

                    time.sleep(0.2)

                if times:
                    results[host] = {
                        "min_ms": round(min(times), 2),
                        "max_ms": round(max(times), 2),
                        "avg_ms": round(sum(times) / len(times), 2),
                        "samples": len(times)
                    }
                else:
                    results[host] = {"error": "No successful connections"}

            except Exception as e:
                results[host] = {"error": str(e)}

        self.results["latency"]["measurements"] = results
        return results

    def measure_jitter(self, host: str = "8.8.8.8", samples: int = 10) -> Dict:
        """Measure network jitter (latency variation)."""
        self.logger.info(f"Measuring jitter to {host}...")

        times = []

        for _ in range(samples):
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, 80))
                elapsed = (time.time() - start) * 1000
                times.append(elapsed)
                sock.close()
                time.sleep(0.1)
            except:
                pass

        results = {
            "host": host,
            "samples": len(times),
            "jitter_ms": 0
        }

        if len(times) >= 2:
            # Calculate jitter as average absolute difference between consecutive measurements
            differences = [abs(times[i] - times[i-1]) for i in range(1, len(times))]
            results["jitter_ms"] = round(sum(differences) / len(differences), 2)
            results["avg_latency_ms"] = round(sum(times) / len(times), 2)

        self.results["latency"]["jitter"] = results
        return results

    def test_bandwidth(self) -> Dict:
        """Estimate bandwidth (simplified test)."""
        self.logger.info("Testing bandwidth...")

        results = {
            "download_mbps": None,
            "test_method": "HTTP download test"
        }

        if requests is None:
            results["error"] = "requests library not available"
            self.results["bandwidth"] = results
            return results

        try:
            # Download a test file (1MB from Cloudflare)
            test_url = "https://speed.cloudflare.com/__down?bytes=1000000"

            start_time = time.time()
            response = requests.get(test_url, timeout=10, stream=True)

            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)

            elapsed_seconds = time.time() - start_time

            # Calculate Mbps
            bits_downloaded = total_size * 8
            mbps = (bits_downloaded / elapsed_seconds) / 1_000_000

            results["download_mbps"] = round(mbps, 2)
            results["bytes_downloaded"] = total_size
            results["time_seconds"] = round(elapsed_seconds, 2)

        except Exception as e:
            results["error"] = str(e)

        self.results["bandwidth"] = results
        return results

    def test_dns_resolution(self) -> Dict:
        """Test DNS resolution performance."""
        self.logger.info("Testing DNS resolution...")

        test_domains = [
            "google.com",
            "github.com",
            "amazon.com",
            "cloudflare.com"
        ]

        results = {
            "successful": [],
            "failed": [],
            "avg_resolution_time_ms": 0
        }

        times = []

        for domain in test_domains:
            try:
                start = time.time()
                ip = socket.gethostbyname(domain)
                elapsed = (time.time() - start) * 1000

                results["successful"].append({
                    "domain": domain,
                    "ip": ip,
                    "time_ms": round(elapsed, 2)
                })
                times.append(elapsed)

            except Exception as e:
                results["failed"].append({
                    "domain": domain,
                    "error": str(e)
                })

        if times:
            results["avg_resolution_time_ms"] = round(sum(times) / len(times), 2)

        self.results["dns"]["resolution"] = results
        return results

    def test_dns_servers(self) -> Dict:
        """Test configured DNS servers."""
        self.logger.info("Testing DNS servers...")

        results = {
            "configured_servers": [],
            "working_servers": []
        }

        if dns is None:
            results["error"] = "dnspython library not available"
            self.results["dns"]["servers"] = results
            return results

        try:
            resolver = dns.resolver.Resolver()
            results["configured_servers"] = [str(ns) for ns in resolver.nameservers]

            # Test each DNS server
            for ns in resolver.nameservers:
                try:
                    custom_resolver = dns.resolver.Resolver()
                    custom_resolver.nameservers = [ns]
                    custom_resolver.timeout = 2
                    custom_resolver.lifetime = 2

                    start = time.time()
                    custom_resolver.resolve("google.com", "A")
                    elapsed = (time.time() - start) * 1000

                    results["working_servers"].append({
                        "server": ns,
                        "response_time_ms": round(elapsed, 2)
                    })
                except:
                    pass

        except Exception as e:
            results["error"] = str(e)

        self.results["dns"]["servers"] = results
        return results

    def check_network_interfaces(self) -> Dict:
        """Check network interface status."""
        self.logger.info("Checking network interfaces...")

        results = {
            "interfaces": [],
            "active_count": 0
        }

        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig", shell=True).decode()
                # Parse ipconfig output
                current_interface = None
                for line in output.split('\n'):
                    if "adapter" in line.lower():
                        if current_interface:
                            results["interfaces"].append(current_interface)
                        current_interface = {"name": line.strip(), "addresses": []}
                    elif "IPv4" in line or "IPv6" in line:
                        if current_interface:
                            current_interface["addresses"].append(line.strip())
                if current_interface:
                    results["interfaces"].append(current_interface)
            else:
                output = subprocess.check_output("ip addr show", shell=True).decode()
                # Parse ip addr output
                for line in output.split('\n'):
                    if "inet " in line or "inet6 " in line:
                        results["active_count"] += 1

        except Exception as e:
            results["error"] = str(e)

        self.results["interfaces"] = results
        return results

    def test_common_ports(self) -> Dict:
        """Test connectivity to common ports."""
        self.logger.info("Testing common ports...")

        test_ports = [
            (80, "HTTP"),
            (443, "HTTPS"),
            (53, "DNS"),
            (22, "SSH"),
            (21, "FTP"),
            (25, "SMTP"),
            (3389, "RDP"),
            (3306, "MySQL")
        ]

        results = {
            "open": [],
            "closed": [],
            "filtered": []
        }

        for port, service in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()

                if result == 0:
                    results["open"].append(f"{port}/{service}")
                elif result == 111:  # Connection refused
                    results["closed"].append(f"{port}/{service}")
                else:
                    results["filtered"].append(f"{port}/{service}")
            except:
                results["filtered"].append(f"{port}/{service}")

        self.results["ports"] = results
        return results

    def trace_routes(self, targets: Optional[List[str]] = None) -> Dict:
        """Trace network routes to targets."""
        self.logger.info("Tracing routes...")

        if targets is None:
            targets = ["8.8.8.8", "1.1.1.1"]

        results = {}

        for target in targets:
            try:
                if platform.system() == "Windows":
                    cmd = f"tracert -h 10 -w 1000 {target}"
                else:
                    cmd = f"traceroute -m 10 -w 1 {target}"

                output = subprocess.check_output(cmd, shell=True, timeout=15, stderr=subprocess.STDOUT).decode()
                results[target] = {
                    "hops": output.count('\n'),
                    "completed": "reached" in output.lower() or target in output
                }
            except subprocess.TimeoutExpired:
                results[target] = {"error": "Timeout"}
            except Exception as e:
                results[target] = {"error": str(e)}

        self.results["routes"] = results
        return results

    def calculate_network_health(self) -> int:
        """Calculate overall network health score (0-100)."""
        score = 0

        # Connectivity (40 points)
        if "internet" in self.results["connectivity"]:
            success_rate = self.results["connectivity"]["internet"].get("success_rate", 0)
            score += (success_rate / 100) * 40

        # Latency (30 points)
        if "measurements" in self.results["latency"]:
            avg_latencies = [
                m.get("avg_ms", 1000)
                for m in self.results["latency"]["measurements"].values()
                if isinstance(m, dict) and "avg_ms" in m
            ]
            if avg_latencies:
                avg_latency = sum(avg_latencies) / len(avg_latencies)
                # Score: <50ms=30pts, <100ms=25pts, <200ms=20pts, <500ms=10pts, >500ms=5pts
                if avg_latency < 50:
                    score += 30
                elif avg_latency < 100:
                    score += 25
                elif avg_latency < 200:
                    score += 20
                elif avg_latency < 500:
                    score += 10
                else:
                    score += 5

        # DNS (20 points)
        if "resolution" in self.results["dns"]:
            dns_results = self.results["dns"]["resolution"]
            total_tests = len(dns_results.get("successful", [])) + len(dns_results.get("failed", []))
            if total_tests > 0:
                success_rate = len(dns_results.get("successful", [])) / total_tests
                score += success_rate * 20

        # Bandwidth (10 points)
        if "download_mbps" in self.results.get("bandwidth", {}):
            mbps = self.results["bandwidth"]["download_mbps"]
            if mbps:
                # Score: >100Mbps=10pts, >50Mbps=8pts, >10Mbps=6pts, >1Mbps=4pts
                if mbps > 100:
                    score += 10
                elif mbps > 50:
                    score += 8
                elif mbps > 10:
                    score += 6
                elif mbps > 1:
                    score += 4
                else:
                    score += 2

        self.results["health_score"] = int(score)
        return int(score)

    def get_summary(self) -> Dict:
        """Get network diagnostics summary."""
        return {
            "timestamp": self.results["timestamp"],
            "health_score": self.results["health_score"],
            "connectivity": {
                "internet_reachable": len(self.results.get("connectivity", {}).get("internet", {}).get("reachable", [])),
                "dns_servers_reachable": len(self.results.get("connectivity", {}).get("dns_servers", {}).get("reachable", [])),
                "gateway_reachable": self.results.get("connectivity", {}).get("gateway", {}).get("reachable", False)
            },
            "performance": {
                "avg_latency_ms": self.results.get("latency", {}).get("measurements", {}).get("google.com", {}).get("avg_ms", "N/A"),
                "jitter_ms": self.results.get("latency", {}).get("jitter", {}).get("jitter_ms", "N/A"),
                "bandwidth_mbps": self.results.get("bandwidth", {}).get("download_mbps", "N/A")
            },
            "recommendations": self._generate_recommendations()
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate network improvement recommendations."""
        recommendations = []

        score = self.results.get("health_score", 0)

        if score < 50:
            recommendations.append("CRITICAL: Network health is poor. Check internet connectivity and gateway.")
        elif score < 70:
            recommendations.append("WARNING: Network performance is below optimal. Investigate latency issues.")

        # Check connectivity
        if "internet" in self.results.get("connectivity", {}):
            success_rate = self.results["connectivity"]["internet"].get("success_rate", 0)
            if success_rate < 75:
                recommendations.append("Multiple internet endpoints unreachable. Check firewall and ISP connection.")

        # Check latency
        if "measurements" in self.results.get("latency", {}):
            for host, data in self.results["latency"]["measurements"].items():
                if isinstance(data, dict) and "avg_ms" in data:
                    if data["avg_ms"] > 200:
                        recommendations.append(f"High latency to {host} ({data['avg_ms']}ms). Network congestion possible.")

        # Check DNS
        if "resolution" in self.results.get("dns", {}):
            failed = len(self.results["dns"]["resolution"].get("failed", []))
            if failed > 0:
                recommendations.append(f"DNS resolution failures detected ({failed} domains). Check DNS servers.")

        if not recommendations:
            recommendations.append("Network health is optimal. No issues detected.")

        return recommendations


if __name__ == "__main__":
    # Test network diagnostics
    diagnostics = NetworkDiagnostics()
    results = diagnostics.run_full_diagnostics()
    summary = diagnostics.get_summary()

    print("\n" + "="*60)
    print("PROMETHEUS PRIME - NETWORK DIAGNOSTICS")
    print("="*60)
    print(json.dumps(summary, indent=2))
