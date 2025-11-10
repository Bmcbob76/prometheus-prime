#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║    OMEGA SOVEREIGN TRUST SYSTEM - DEVICE & NETWORK AUTHORITY    ║
║         Complete Device Management and Trust Verification        ║
╚══════════════════════════════════════════════════════════════════╝

CAPABILITIES:
✅ Device Registration and Verification
✅ Bloodline Authority Enforcement
✅ Network Trust Management
✅ Device Health Monitoring
✅ Access Control and Permissions
"""

import os
import json
import time
import hashlib
import socket
import platform
import psutil
import uuid
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

# ══════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════

class TrustLevel(Enum):
    """Device trust levels"""
    UNTRUSTED = 0
    PENDING = 1
    BASIC = 2
    ELEVATED = 3
    TRUSTED = 4
    SOVEREIGN = 5  # Bloodline authority

class DeviceType(Enum):
    """Device types"""
    WORKSTATION = "workstation"
    SERVER = "server"
    LAPTOP = "laptop"
    MOBILE = "mobile"
    IOT = "iot"
    UNKNOWN = "unknown"

# ══════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════

@dataclass
class DeviceIdentity:
    """Device identity information"""
    device_id: str
    hostname: str
    mac_address: str
    ip_address: str
    os_type: str
    os_version: str
    device_type: DeviceType
    registered_timestamp: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

@dataclass
class DeviceTrust:
    """Device trust record"""
    device_id: str
    trust_level: TrustLevel
    bloodline_verified: bool = False
    authority_level: float = 0.0
    granted_by: str = "SYSTEM"
    granted_timestamp: float = field(default_factory=time.time)
    expires_timestamp: Optional[float] = None
    permissions: List[str] = field(default_factory=list)

@dataclass
class NetworkTrustZone:
    """Network trust zone"""
    zone_id: str
    zone_name: str
    ip_ranges: List[str]
    trust_level: TrustLevel
    allowed_devices: List[str] = field(default_factory=list)

# ══════════════════════════════════════════════════════════════════
# SOVEREIGN TRUST SYSTEM
# ══════════════════════════════════════════════════════════════════

class SovereignTrustSystem:
    """Complete sovereign trust system for device and network management"""
    
    def __init__(self, storage_path: str = "P:/ECHO_PRIME/OMEGA_SWARM_BRAIN/trust_db"):
        self.storage_path = storage_path
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Trust databases
        self.devices: Dict[str, DeviceIdentity] = {}
        self.trust_records: Dict[str, DeviceTrust] = {}
        self.network_zones: Dict[str, NetworkTrustZone] = {}
        
        # Bloodline authority
        self.bloodline_devices: List[str] = []
        self.commander_authority = "COMMANDER_BOBBY_DON_MCWILLIAMS_II"
        
        # Statistics
        self.stats = {
            "total_devices": 0,
            "trusted_devices": 0,
            "sovereign_devices": 0,
            "trust_checks": 0,
            "trust_violations": 0
        }
        
        # Load existing data
        self._load_trust_database()
        
        # Register this device
        self._register_self()
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║        SOVEREIGN TRUST SYSTEM INITIALIZED                    ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
        logging.info(f"📊 Registered devices: {len(self.devices)}")
        logging.info(f"🔐 Trusted devices: {self.stats['trusted_devices']}")
        logging.info(f"👑 Sovereign devices: {self.stats['sovereign_devices']}")
    
    def _get_device_id(self) -> str:
        """Generate unique device ID"""
        # Use MAC address and hostname
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                       for elements in range(0,2*6,2)][::-1])
        hostname = socket.gethostname()
        return hashlib.sha256(f"{mac}_{hostname}".encode()).hexdigest()[:16]
    
    def _get_device_info(self) -> DeviceIdentity:
        """Get current device information"""
        device_id = self._get_device_id()
        hostname = socket.gethostname()
        
        # Get MAC address
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                       for elements in range(0,2*6,2)][::-1])
        
        # Get IP address
        try:
            ip = socket.gethostbyname(hostname)
        except:
            ip = "127.0.0.1"
        
        # Determine device type
        system = platform.system().lower()
        if "server" in hostname.lower():
            device_type = DeviceType.SERVER
        elif system == "windows":
            device_type = DeviceType.WORKSTATION
        elif system == "linux":
            device_type = DeviceType.SERVER
        else:
            device_type = DeviceType.UNKNOWN
        
        return DeviceIdentity(
            device_id=device_id,
            hostname=hostname,
            mac_address=mac,
            ip_address=ip,
            os_type=platform.system(),
            os_version=platform.version(),
            device_type=device_type
        )
    
    def _register_self(self):
        """Register current device with SOVEREIGN authority"""
        device_info = self._get_device_info()
        
        if device_info.device_id not in self.devices:
            self.devices[device_info.device_id] = device_info
            
            # Grant SOVEREIGN trust to this device
            self.trust_records[device_info.device_id] = DeviceTrust(
                device_id=device_info.device_id,
                trust_level=TrustLevel.SOVEREIGN,
                bloodline_verified=True,
                authority_level=11.0,
                granted_by=self.commander_authority,
                permissions=["ALL"]
            )
            
            self.bloodline_devices.append(device_info.device_id)
            self.stats["total_devices"] += 1
            self.stats["trusted_devices"] += 1
            self.stats["sovereign_devices"] += 1
            
            logging.info(f"🔐 Self-registered as SOVEREIGN device: {device_info.hostname}")
            self._save_trust_database()
    
    def register_device(self, device_info: DeviceIdentity, 
                       trust_level: TrustLevel = TrustLevel.PENDING) -> bool:
        """Register a new device"""
        if device_info.device_id in self.devices:
            logging.warning(f"⚠️ Device already registered: {device_info.device_id}")
            return False
        
        self.devices[device_info.device_id] = device_info
        self.trust_records[device_info.device_id] = DeviceTrust(
            device_id=device_info.device_id,
            trust_level=trust_level,
            permissions=[]
        )
        
        self.stats["total_devices"] += 1
        
        logging.info(f"✅ Device registered: {device_info.hostname} ({trust_level.name})")
        self._save_trust_database()
        return True
    
    def grant_trust(self, device_id: str, trust_level: TrustLevel, 
                   granted_by: str = "SYSTEM", permissions: List[str] = None) -> bool:
        """Grant trust to a device"""
        if device_id not in self.devices:
            logging.error(f"❌ Device not found: {device_id}")
            return False
        
        if device_id not in self.trust_records:
            self.trust_records[device_id] = DeviceTrust(
                device_id=device_id,
                trust_level=trust_level,
                granted_by=granted_by,
                permissions=permissions or []
            )
        else:
            trust_record = self.trust_records[device_id]
            trust_record.trust_level = trust_level
            trust_record.granted_by = granted_by
            trust_record.granted_timestamp = time.time()
            if permissions:
                trust_record.permissions = permissions
        
        if trust_level.value >= TrustLevel.TRUSTED.value:
            self.stats["trusted_devices"] += 1
        
        logging.info(f"🔐 Trust granted to {self.devices[device_id].hostname}: {trust_level.name}")
        self._save_trust_database()
        return True
    
    def verify_trust(self, device_id: str, required_level: TrustLevel = TrustLevel.BASIC) -> bool:
        """Verify device trust level"""
        self.stats["trust_checks"] += 1
        
        if device_id not in self.trust_records:
            self.stats["trust_violations"] += 1
            logging.warning(f"⚠️ Trust verification failed: Device not registered")
            return False
        
        trust_record = self.trust_records[device_id]
        
        # Check expiration
        if trust_record.expires_timestamp and time.time() > trust_record.expires_timestamp:
            self.stats["trust_violations"] += 1
            logging.warning(f"⚠️ Trust verification failed: Trust expired")
            return False
        
        # Check trust level
        if trust_record.trust_level.value < required_level.value:
            self.stats["trust_violations"] += 1
            logging.warning(f"⚠️ Trust verification failed: Insufficient trust level")
            return False
        
        # Update last seen
        if device_id in self.devices:
            self.devices[device_id].last_seen = time.time()
        
        return True
    
    def verify_bloodline(self, device_id: str) -> bool:
        """Verify bloodline sovereignty"""
        if device_id not in self.trust_records:
            return False
        
        trust_record = self.trust_records[device_id]
        return trust_record.bloodline_verified and device_id in self.bloodline_devices
    
    def create_network_zone(self, zone_name: str, ip_ranges: List[str], 
                           trust_level: TrustLevel) -> str:
        """Create a network trust zone"""
        zone_id = hashlib.sha256(zone_name.encode()).hexdigest()[:16]
        
        self.network_zones[zone_id] = NetworkTrustZone(
            zone_id=zone_id,
            zone_name=zone_name,
            ip_ranges=ip_ranges,
            trust_level=trust_level
        )
        
        logging.info(f"✅ Network zone created: {zone_name} ({trust_level.name})")
        self._save_trust_database()
        return zone_id
    
    def get_device_health(self, device_id: str) -> Dict[str, Any]:
        """Get device health metrics"""
        if device_id not in self.devices:
            return {"error": "Device not found"}
        
        device_info = self.devices[device_id]
        trust_record = self.trust_records.get(device_id)
        
        # Get system health if this is the current device
        if device_id == self._get_device_id():
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "device_id": device_id,
                "hostname": device_info.hostname,
                "trust_level": trust_record.trust_level.name if trust_record else "UNKNOWN",
                "health": {
                    "cpu_usage": cpu_percent,
                    "memory_usage": memory.percent,
                    "disk_usage": disk.percent,
                    "uptime_hours": (time.time() - psutil.boot_time()) / 3600
                },
                "last_seen": datetime.fromtimestamp(device_info.last_seen).isoformat()
            }
        else:
            return {
                "device_id": device_id,
                "hostname": device_info.hostname,
                "trust_level": trust_record.trust_level.name if trust_record else "UNKNOWN",
                "last_seen": datetime.fromtimestamp(device_info.last_seen).isoformat()
            }
    
    def get_trust_summary(self) -> Dict[str, Any]:
        """Get trust system summary"""
        return {
            "statistics": self.stats,
            "devices_by_trust_level": {
                level.name: sum(1 for t in self.trust_records.values() if t.trust_level == level)
                for level in TrustLevel
            },
            "bloodline_devices": len(self.bloodline_devices),
            "network_zones": len(self.network_zones)
        }
    
    def _save_trust_database(self):
        """Save trust database to disk"""
        try:
            # Save devices
            devices_data = {
                device_id: {
                    "device_id": d.device_id,
                    "hostname": d.hostname,
                    "mac_address": d.mac_address,
                    "ip_address": d.ip_address,
                    "os_type": d.os_type,
                    "os_version": d.os_version,
                    "device_type": d.device_type.value,
                    "registered_timestamp": d.registered_timestamp,
                    "last_seen": d.last_seen
                }
                for device_id, d in self.devices.items()
            }
            
            with open(f"{self.storage_path}/devices.json", "w") as f:
                json.dump(devices_data, f, indent=2)
            
            # Save trust records
            trust_data = {
                device_id: {
                    "device_id": t.device_id,
                    "trust_level": t.trust_level.value,
                    "bloodline_verified": t.bloodline_verified,
                    "authority_level": t.authority_level,
                    "granted_by": t.granted_by,
                    "granted_timestamp": t.granted_timestamp,
                    "expires_timestamp": t.expires_timestamp,
                    "permissions": t.permissions
                }
                for device_id, t in self.trust_records.items()
            }
            
            with open(f"{self.storage_path}/trust_records.json", "w") as f:
                json.dump(trust_data, f, indent=2)
            
        except Exception as e:
            logging.error(f"❌ Failed to save trust database: {e}")
    
    def _load_trust_database(self):
        """Load trust database from disk"""
        try:
            # Load devices
            devices_path = f"{self.storage_path}/devices.json"
            if os.path.exists(devices_path):
                with open(devices_path, "r") as f:
                    devices_data = json.load(f)
                
                for device_id, data in devices_data.items():
                    self.devices[device_id] = DeviceIdentity(
                        device_id=data["device_id"],
                        hostname=data["hostname"],
                        mac_address=data["mac_address"],
                        ip_address=data["ip_address"],
                        os_type=data["os_type"],
                        os_version=data["os_version"],
                        device_type=DeviceType(data["device_type"]),
                        registered_timestamp=data["registered_timestamp"],
                        last_seen=data["last_seen"]
                    )
            
            # Load trust records
            trust_path = f"{self.storage_path}/trust_records.json"
            if os.path.exists(trust_path):
                with open(trust_path, "r") as f:
                    trust_data = json.load(f)
                
                for device_id, data in trust_data.items():
                    self.trust_records[device_id] = DeviceTrust(
                        device_id=data["device_id"],
                        trust_level=TrustLevel(data["trust_level"]),
                        bloodline_verified=data["bloodline_verified"],
                        authority_level=data["authority_level"],
                        granted_by=data["granted_by"],
                        granted_timestamp=data["granted_timestamp"],
                        expires_timestamp=data.get("expires_timestamp"),
                        permissions=data["permissions"]
                    )
                    
                    if data["bloodline_verified"]:
                        self.bloodline_devices.append(device_id)
            
            # Update stats
            self.stats["total_devices"] = len(self.devices)
            self.stats["trusted_devices"] = sum(1 for t in self.trust_records.values() 
                                               if t.trust_level.value >= TrustLevel.TRUSTED.value)
            self.stats["sovereign_devices"] = len(self.bloodline_devices)
            
        except Exception as e:
            logging.error(f"❌ Failed to load trust database: {e}")

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize trust system
    trust_system = SovereignTrustSystem()
    
    # Show summary
    summary = trust_system.get_trust_summary()
    print("\n" + "="*70)
    print("SOVEREIGN TRUST SYSTEM SUMMARY")
    print("="*70)
    print(json.dumps(summary, indent=2))
    
    # Show device health
    device_id = trust_system._get_device_id()
    health = trust_system.get_device_health(device_id)
    print("\n" + "="*70)
    print("DEVICE HEALTH")
    print("="*70)
    print(json.dumps(health, indent=2))
