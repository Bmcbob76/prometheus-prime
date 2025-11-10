#!/usr/bin/env python3
"""
PROMETHEUS PRIME - NMAP SCANNER MODULE
Authority: 11.0 | Commander Bobby Don McWilliams II
Real port scanning with nmap integration
"""

import asyncio
import nmap
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime

class ScanType(Enum):
    """Scan type enumeration"""
    QUICK = "quick"
    FULL = "full"
    INTENSE = "intense"

@dataclass
class PortScanResult:
    """Port scan result structure"""
    target: str
    scan_type: str
    ports_found: List[Dict]
    total_ports: int
    duration: float
    os_info: Optional[Dict] = None
    success: bool = True
    error: Optional[str] = None
    scan_timestamp: str = None

class PrometheusNmapScanner:
    """Real nmap-based port scanner"""
    
    def __init__(self):
        self.scanner = nmap.PortScanner()
    
    async def quick_port_scan(self, target: str, timeout: int = 60) -> PortScanResult:
        """Quick scan - top 1000 ports, ~15-30 seconds"""
        start_time = datetime.now()
        
        try:
            # Run in thread pool (nmap is blocking)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.scanner.scan(
                    target,
                    arguments='-sS -T4 --top-ports 1000'
                )
            )
            
            ports_found = []
            
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in ports:
                        port_info = self.scanner[host][proto][port]
                        ports_found.append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', '')
                        })
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return PortScanResult(
                target=target,
                scan_type="quick",
                ports_found=ports_found,
                total_ports=len(ports_found),
                duration=duration,
                scan_timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return PortScanResult(
                target=target,
                scan_type="quick",
                ports_found=[],
                total_ports=0,
                duration=duration,
                success=False,
                error=str(e),
                scan_timestamp=datetime.now().isoformat()
            )
    
    async def full_port_scan(self, target: str) -> PortScanResult:
        """Full scan - all 65535 ports, ~5-10 minutes"""
        start_time = datetime.now()
        
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.scanner.scan(
                    target,
                    arguments='-p- -T4'
                )
            )
            
            ports_found = []
            
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in ports:
                        port_info = self.scanner[host][proto][port]
                        ports_found.append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown')
                        })
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return PortScanResult(
                target=target,
                scan_type="full",
                ports_found=ports_found,
                total_ports=len(ports_found),
                duration=duration,
                scan_timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return PortScanResult(
                target=target,
                scan_type="full",
                ports_found=[],
                total_ports=0,
                duration=duration,
                success=False,
                error=str(e),
                scan_timestamp=datetime.now().isoformat()
            )

# Test
if __name__ == "__main__":
    async def test():
        scanner = PrometheusNmapScanner()
        result = await scanner.quick_port_scan("127.0.0.1")
        print(f"Scanned {result.target}")
        print(f"Found {result.total_ports} open ports")
        print(f"Duration: {result.duration:.2f}s")
        
    asyncio.run(test())
