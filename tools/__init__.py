"""
PROMETHEUS PRIME - ADVANCED SECURITY TOOLS
Complete Offensive & Defensive Penetration Testing Toolkit

AUTHORIZED TESTING ONLY - CONTROLLED LAB ENVIRONMENT

Complete Arsenal:
- Password Cracking (Hashcat, John, Rainbow Tables)
- Mobile Exploitation (Android/iOS)
- Network Device Penetration (Routers, Switches, IoT, ICS)
- Wireless Attacks (WiFi, Bluetooth, RFID, NFC, Zigbee)
- Physical Attacks (USB, HID, DMA, Cold Boot)
- Advanced Persistence (Rootkits, Bootkits, Fileless)
- Credential Dumping (LSASS, SAM, Keychain)
- Exploit Frameworks
- Evasion Techniques
"""

# Basic Tools
from .scanner import PortScanner, VulnScanner
from .exploits import ExploitFramework
from .payloads import PayloadGenerator
from .evasion import EvasionTechniques

# Advanced Password Cracking
from .password_cracking import (
    PasswordCracker,
    CredentialDumper
)

# Mobile Device Exploitation
from .mobile_exploitation import (
    AndroidExploit,
    IOSExploit,
    PhoneInterception
)

# Network Device Penetration
from .network_device_penetration import (
    RouterExploit,
    SwitchExploit,
    IoTExploit,
    IndustrialControlExploit
)

# Advanced Wireless Attacks
from .advanced_wireless import (
    AdvancedWiFiAttacks,
    BluetoothAttacks,
    RFIDAttacks,
    ZigbeeAttacks
)

# Physical Attacks
from .physical_attacks import (
    USBAttacks,
    DMAAttacks,
    ColdBootAttacks,
    HardwareImplants,
    EvilMaidAttacks
)

# Advanced Persistence
from .advanced_persistence import (
    RootkitPersistence,
    FilelessPersistence,
    AdvancedPersistence
)

__all__ = [
    # Basic Tools
    'PortScanner',
    'VulnScanner',
    'ExploitFramework',
    'PayloadGenerator',
    'EvasionTechniques',

    # Password Cracking
    'PasswordCracker',
    'CredentialDumper',

    # Mobile Exploitation
    'AndroidExploit',
    'IOSExploit',
    'PhoneInterception',

    # Network Device Penetration
    'RouterExploit',
    'SwitchExploit',
    'IoTExploit',
    'IndustrialControlExploit',

    # Wireless Attacks
    'AdvancedWiFiAttacks',
    'BluetoothAttacks',
    'RFIDAttacks',
    'ZigbeeAttacks',

    # Physical Attacks
    'USBAttacks',
    'DMAAttacks',
    'ColdBootAttacks',
    'HardwareImplants',
    'EvilMaidAttacks',

    # Advanced Persistence
    'RootkitPersistence',
    'FilelessPersistence',
    'AdvancedPersistence',
]

# Module Information
__version__ = '2.0.0'
__author__ = 'Commander Bobby Don McWilliams II'
__authority_level__ = 11.0
__classification__ = 'PROMETHEUS PRIME - AUTHORIZED TESTING ONLY'
