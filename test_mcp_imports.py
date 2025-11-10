#!/usr/bin/env python3
"""
Test script to verify all MCP server imports work correctly
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

print("Testing Prometheus Prime MCP Server Imports...")
print("=" * 70)

# Test capability imports
print("\n📦 Testing Security Domain Imports...")
try:
    from capabilities.network_recon import NetworkRecon
    from capabilities.web_exploitation import WebExploitation
    from capabilities.wireless_ops import WirelessOps
    from capabilities.social_engineering import SocialEngineering
    from capabilities.physical_security import PhysicalSecurity
    from capabilities.crypto_analysis import CryptoAnalysis
    from capabilities.malware_dev import MalwareDev
    from capabilities.forensics import Forensics
    from capabilities.cloud_security import CloudSecurity
    from capabilities.mobile_security import MobileSecurity
    from capabilities.iot_security import IoTSecurity
    from capabilities.scada_ics import ScadaICS
    from capabilities.threat_intel import ThreatIntel
    from capabilities.red_team import RedTeam
    from capabilities.blue_team import BlueTeam
    from capabilities.purple_team import PurpleTeam
    from capabilities.osint import OSINT
    from capabilities.exploit_dev import ExploitDev
    from capabilities.post_exploitation import PostExploitation
    from capabilities.persistence import Persistence
    print("✅ All 20 security domains imported successfully")
except Exception as e:
    print(f"❌ Security domain import failed: {e}")
    sys.exit(1)

# Test diagnostic imports
print("\n🔬 Testing Diagnostic System Imports...")
try:
    from src.diagnostics.system_diagnostics import SystemDiagnostics
    from src.diagnostics.network_diagnostics import NetworkDiagnostics
    from src.diagnostics.security_diagnostics import SecurityDiagnostics
    from src.diagnostics.ai_ml_diagnostics import AIMLDiagnostics
    from src.diagnostics.database_diagnostics import DatabaseDiagnostics
    print("✅ All 5 diagnostic systems imported successfully")
except Exception as e:
    print(f"❌ Diagnostic import failed: {e}")
    sys.exit(1)

# Test tool imports
print("\n🛠️  Testing Basic Tool Imports...")
try:
    from tools.scanner import PortScanner, VulnScanner, OSFingerprinter
    from tools.evasion import EvasionTechniques
    from tools.exploits import ExploitFramework
    from tools.payloads import PayloadGenerator
    from tools.password_cracking import PasswordCracker
    from tools.mobile_exploitation import MobileExploitation
    from tools.advanced_wireless import AdvancedWireless
    from tools.network_device_penetration import NetworkDevicePenetration
    from tools.physical_attacks import PhysicalAttacks
    from tools.advanced_persistence import AdvancedPersistence
    print("✅ All basic tools imported successfully")
except Exception as e:
    print(f"❌ Basic tool import failed: {e}")
    sys.exit(1)

# Test advanced attack imports (Set 1)
print("\n⚔️  Testing Advanced Attack Imports (Set 1)...")
try:
    from tools.advanced_attacks import (
        AIModelPoisoning, QuantumCryptoAttacks, SupplyChainAttacks,
        SideChannelAttacks, DNSTunnelingExfiltration, ContainerEscape,
        FirmwareBackdoors, MemoryForensicsEvasion, APIAuthBypass, BlockchainExploits
    )
    print("✅ All 10 advanced attacks (Set 1) imported successfully")
except Exception as e:
    print(f"❌ Advanced attacks (Set 1) import failed: {e}")
    sys.exit(1)

# Test advanced attack imports (Set 2)
print("\n⚔️  Testing Advanced Attack Imports (Set 2)...")
try:
    from tools.advanced_attacks_set2 import (
        LivingOffTheLand, CredentialHarvesting, CloudInfrastructureAttacks,
        ActiveDirectoryAttacks, RadioFrequencyAttacks, ICSScadaAttacks,
        VoiceAudioAttacks, HardwareImplantsEvilMaid, MLModelExtraction,
        PrivacyAnonymityBreaking
    )
    print("✅ All 10 advanced attacks (Set 2) imported successfully")
except Exception as e:
    print(f"❌ Advanced attacks (Set 2) import failed: {e}")
    sys.exit(1)

# Test advanced defense imports (Set 1)
print("\n🛡️  Testing Advanced Defense Imports (Set 1)...")
try:
    from tools.advanced_defenses import (
        AIPoweredThreatDetection, DeceptionTechnology, ZeroTrustArchitecture,
        AutomatedIncidentResponse, ThreatIntelFusion, BehavioralAnalytics,
        CryptographicAgility, SupplyChainSecurity, ContainerSecurity,
        QuantumSafeCryptography
    )
    print("✅ All 10 advanced defenses (Set 1) imported successfully")
except Exception as e:
    print(f"❌ Advanced defenses (Set 1) import failed: {e}")
    sys.exit(1)

# Test advanced defense imports (Set 2)
print("\n🛡️  Testing Advanced Defense Imports (Set 2)...")
try:
    from tools.advanced_defenses_set2 import (
        EndpointDetectionResponse, NetworkTrafficAnalysis, ThreatHuntingPlatform,
        DataLossPrevention, PrivilegedAccessManagement, SIEM,
        CloudSecurityPostureManagement, ApplicationSecurityTesting,
        MobileDeviceManagement, ThreatIntelligencePlatform
    )
    print("✅ All 10 advanced defenses (Set 2) imported successfully")
except Exception as e:
    print(f"❌ Advanced defenses (Set 2) import failed: {e}")
    sys.exit(1)

# Summary
print("\n" + "=" * 70)
print("✅ ALL IMPORTS SUCCESSFUL")
print("=" * 70)
print("\n📊 Total Capabilities Verified:")
print(f"   • Security Domains: 20")
print(f"   • Diagnostic Systems: 5")
print(f"   • Basic Tools: 12")
print(f"   • Advanced Attacks (Set 1): 10")
print(f"   • Advanced Attacks (Set 2): 10")
print(f"   • Advanced Defenses (Set 1): 10")
print(f"   • Advanced Defenses (Set 2): 10")
print(f"   • TOTAL: 77 capabilities")
print()
print("🔥 MCP Server is ready for integration!")
print()
print("Next steps:")
print("  1. Install MCP SDK: pip install mcp")
print("  2. Run setup: ./setup_mcp.sh")
print("  3. Configure Claude Desktop")
print("=" * 70)
