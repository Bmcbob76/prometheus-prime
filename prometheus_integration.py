#!/usr/bin/env python3
"""
PROMETHEUS PRIME - COMPREHENSIVE INTEGRATION
Authority: 11.0 | Commander Bobby Don McWilliams II
Unified security assessment combining all scanners
"""

import asyncio
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

from prometheus_nmap_scanner import PrometheusNmapScanner
from prometheus_smb_analyzer import PrometheusSMBAnalyzer
from prometheus_vulnerability_scanner import PrometheusVulnerabilityScanner

@dataclass
class ComprehensiveReport:
    """Complete security assessment report"""
    target: str
    threat_level: str  # CRITICAL/HIGH/MEDIUM/LOW
    risk_score: int  # 0-100
    
    # Port scan results
    total_ports: int
    critical_ports: List[int]
    
    # SMB results
    smb_shares: int
    administrative_shares_exposed: bool
    
    # Vulnerability results
    total_vulnerabilities: int
    critical_vulns: int
    high_vulns: int
    
    # Analysis
    attack_vectors: List[str]
    recommendations: List[str]
    
    scan_duration: float
    success: bool = True
    error: Optional[str] = None

class PrometheusIntegration:
    """Comprehensive security scanner"""
    
    def __init__(self):
        self.nmap_scanner = PrometheusNmapScanner()
        self.smb_analyzer = PrometheusSMBAnalyzer()
        self.vuln_scanner = PrometheusVulnerabilityScanner()
    
    async def comprehensive_scan(self, target: str) -> ComprehensiveReport:
        """Complete security assessment"""
        start_time = datetime.now()
        
        try:
            print(f"[*] Starting comprehensive scan of {target}")
            
            # Step 1: Port scan
            print("[*] Phase 1: Port scanning...")
            port_result = await self.nmap_scanner.quick_port_scan(target)
            
            if not port_result.success:
                raise Exception(f"Port scan failed: {port_result.error}")
            
            print(f"[+] Found {port_result.total_ports} open ports")
            
            # Step 2: SMB analysis (if port 445 open)
            smb_result = None
            if any(p['port'] == 445 for p in port_result.ports_found):
                print("[*] Phase 2: SMB analysis...")
                smb_result = await self.smb_analyzer.quick_smb_scan(target)
                print(f"[+] Found {smb_result.total_shares} SMB shares")
            
            # Step 3: Vulnerability matching
            print("[*] Phase 3: Vulnerability scanning...")
            services = {str(p['port']): p['service'] for p in port_result.ports_found}
            vuln_result = await self.vuln_scanner.scan_target(target, services)
            print(f"[+] Found {vuln_result.total_vulnerabilities} vulnerabilities")
            
            # Step 4: Risk assessment
            print("[*] Phase 4: Risk assessment...")
            threat_level, risk_score = self._calculate_threat_level(
                port_result, smb_result, vuln_result
            )
            
            # Step 5: Attack vectors
            attack_vectors = self._identify_attack_vectors(
                port_result, smb_result, vuln_result
            )
            
            # Step 6: Recommendations
            recommendations = self._generate_recommendations(
                port_result, smb_result, vuln_result
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            print(f"[+] Scan complete in {duration:.2f}s")
            
            return ComprehensiveReport(
                target=target,
                threat_level=threat_level,
                risk_score=risk_score,
                total_ports=port_result.total_ports,
                critical_ports=[p['port'] for p in port_result.ports_found if p['port'] in [445, 5985, 3389]],
                smb_shares=smb_result.total_shares if smb_result else 0,
                administrative_shares_exposed=bool(smb_result and smb_result.administrative_shares) if smb_result else False,
                total_vulnerabilities=vuln_result.total_vulnerabilities,
                critical_vulns=vuln_result.critical_count,
                high_vulns=vuln_result.high_count,
                attack_vectors=attack_vectors,
                recommendations=recommendations,
                scan_duration=duration
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return ComprehensiveReport(
                target=target,
                threat_level="UNKNOWN",
                risk_score=0,
                total_ports=0,
                critical_ports=[],
                smb_shares=0,
                administrative_shares_exposed=False,
                total_vulnerabilities=0,
                critical_vulns=0,
                high_vulns=0,
                attack_vectors=[],
                recommendations=[],
                scan_duration=duration,
                success=False,
                error=str(e)
            )
    
    def _calculate_threat_level(self, port_result, smb_result, vuln_result) -> tuple:
        """Calculate overall threat level and risk score"""
        risk_score = 0
        
        # Critical ports
        risk_score += len([p for p in port_result.ports_found if p['port'] in [445, 5985, 3389]]) * 15
        
        # Admin shares
        if smb_result and smb_result.administrative_shares:
            risk_score += 25
        
        # Vulnerabilities
        risk_score += vuln_result.critical_count * 20
        risk_score += vuln_result.high_count * 10
        
        risk_score = min(100, risk_score)
        
        if risk_score >= 80:
            threat_level = "CRITICAL"
        elif risk_score >= 60:
            threat_level = "HIGH"
        elif risk_score >= 40:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        return threat_level, risk_score
    
    def _identify_attack_vectors(self, port_result, smb_result, vuln_result) -> List[str]:
        """Identify potential attack vectors"""
        vectors = []
        
        # SMB attacks
        if any(p['port'] == 445 for p in port_result.ports_found):
            vectors.append("SMB exploitation (EternalBlue, administrative shares)")
        
        # WinRM
        if any(p['port'] == 5985 for p in port_result.ports_found):
            vectors.append("WinRM remote PowerShell execution")
        
        # RDP
        if any(p['port'] == 3389 for p in port_result.ports_found):
            vectors.append("RDP brute-force and BlueKeep exploitation")
        
        # Admin shares
        if smb_result and smb_result.administrative_shares:
            vectors.append("Administrative share access (C$, ADMIN$)")
        
        return vectors
    
    def _generate_recommendations(self, port_result, smb_result, vuln_result) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Critical vulnerabilities
        if vuln_result.critical_count > 0:
            recommendations.append("URGENT: Patch critical vulnerabilities immediately")
        
        # Admin shares
        if smb_result and smb_result.administrative_shares:
            recommendations.append("Disable administrative shares (C$, ADMIN$)")
        
        # SMB
        if any(p['port'] == 445 for p in port_result.ports_found):
            recommendations.append("Disable SMBv1 protocol")
            recommendations.append("Block SMB port 445 at firewall")
        
        # WinRM
        if any(p['port'] == 5985 for p in port_result.ports_found):
            recommendations.append("Restrict WinRM access to specific IPs")
        
        # RDP
        if any(p['port'] == 3389 for p in port_result.ports_found):
            recommendations.append("Enable Network Level Authentication for RDP")
            recommendations.append("Change default RDP port")
        
        return recommendations

# Test
if __name__ == "__main__":
    async def test():
        integration = PrometheusIntegration()
        result = await integration.comprehensive_scan("127.0.0.1")
        
        print(f"\n=== COMPREHENSIVE SCAN RESULTS ===")
        print(f"Target: {result.target}")
        print(f"Threat Level: {result.threat_level}")
        print(f"Risk Score: {result.risk_score}/100")
        print(f"Duration: {result.scan_duration:.2f}s")
        
    asyncio.run(test())
