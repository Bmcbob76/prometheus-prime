#!/usr/bin/env python3
"""
PROMETHEUS PRIME - TEST SUITE
Authority: 11.0 | Commander Bobby Don McWilliams II
Comprehensive testing of all security modules
"""

import asyncio
import sys
from datetime import datetime

from prometheus_nmap_scanner import PrometheusNmapScanner
from prometheus_smb_analyzer import PrometheusSMBAnalyzer
from prometheus_vulnerability_scanner import PrometheusVulnerabilityScanner
from prometheus_integration import PrometheusIntegration

def header(title: str):
    """Print section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

async def test_nmap(target: str):
    """Test nmap scanner"""
    header("🔱 TEST 1: NMAP PORT SCANNER")
    
    scanner = PrometheusNmapScanner()
    print(f"📡 Scanning {target}...")
    
    result = await scanner.quick_port_scan(target)
    
    print(f"  Success: {result.success}")
    print(f"  Ports Found: {result.total_ports}")
    print(f"  Duration: {result.duration:.2f}s")
    
    if result.ports_found:
        print(f"\n  Top 5 Open Ports:")
        for port in result.ports_found[:5]:
            print(f"    • {port['port']}/{port['protocol']} - {port['service']}")
    
    return result.success

async def test_smb(target: str):
    """Test SMB analyzer"""
    header("🔱 TEST 2: SMB ANALYZER")
    
    analyzer = PrometheusSMBAnalyzer()
    print(f"🔍 Analyzing {target}...")
    
    result = await analyzer.quick_smb_scan(target)
    
    print(f"  Success: {result.success}")
    print(f"  Shares: {result.total_shares}")
    print(f"  Admin Shares: {len(result.administrative_shares)}")
    print(f"  Duration: {result.duration:.2f}s")
    
    if result.administrative_shares:
        print(f"\n  ⚠️ Administrative Shares:")
        for share in result.administrative_shares:
            print(f"    • {share}")
    
    return result.success

async def test_vuln():
    """Test vulnerability scanner"""
    header("🔱 TEST 3: VULNERABILITY SCANNER")
    
    scanner = PrometheusVulnerabilityScanner()
    print("🔎 Checking CVE database...")
    
    # Test CVE lookup
    eternalblue = await scanner.check_cve("CVE-2017-0143")
    
    if eternalblue:
        print(f"  ✅ EternalBlue: {eternalblue.title}")
        print(f"     CVSS: {eternalblue.cvss_score}")
        print(f"     Severity: {eternalblue.severity}")
    
    # Test scan
    services = {"445": "SMB", "3389": "RDP"}
    result = await scanner.scan_target("192.168.1.200", services)
    
    print(f"\n  Success: {result.success}")
    print(f"  Vulnerabilities: {result.total_vulnerabilities}")
    print(f"  Critical: {result.critical_count}")
    print(f"  Risk Score: {result.risk_score}/100")
    
    return result.success

async def test_integration(target: str):
    """Test comprehensive integration"""
    header("🔱 TEST 4: COMPREHENSIVE INTEGRATION")
    
    integration = PrometheusIntegration()
    print(f"🎯 Comprehensive scan of {target}...")
    print("   (This may take 30-60 seconds...)")
    
    result = await integration.comprehensive_scan(target)
    
    print(f"\n  Success: {result.success}")
    print(f"  Threat Level: {result.threat_level}")
    print(f"  Risk Score: {result.risk_score}/100")
    print(f"  Duration: {result.scan_duration:.2f}s")
    
    if result.attack_vectors:
        print(f"\n  🚨 Attack Vectors:")
        for vec in result.attack_vectors:
            print(f"    • {vec}")
    
    return result.success

async def run_all_tests(target: str):
    """Run complete test suite"""
    print("\n" + "╔" + "="*68 + "╗")
    print("║  🔱 PROMETHEUS PRIME - TEST SUITE                                  ║")
    print("║  Authority: 11.0 | Commander Bobby Don McWilliams II              ║")
    print("╚" + "="*68 + "╝")
    
    start_time = datetime.now()
    print(f"\n📍 Target: {target}")
    print(f"⏰ Start: {start_time.strftime('%H:%M:%S')}")
    
    results = {}
    
    try:
        results["nmap"] = await test_nmap(target)
        results["smb"] = await test_smb(target)
        results["vuln"] = await test_vuln()
        results["integration"] = await test_integration(target)
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted")
        return
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        return
    
    duration = (datetime.now() - start_time).total_seconds()
    
    header("📊 TEST SUMMARY")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    print(f"\n  Tests Passed: {passed}/{total}")
    print(f"  Duration: {duration:.2f}s")
    
    for test, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"    {status} - {test.upper()}")
    
    if passed == total:
        print(f"\n  🎉 ALL TESTS PASSED")
    else:
        print(f"\n  ⚠️ SOME TESTS FAILED")
    
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    asyncio.run(run_all_tests(target))
