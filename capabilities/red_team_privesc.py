"""RED TEAM - Privilege Escalation
AUTHORIZED USE ONLY - For penetration testing in controlled lab environments
"""
import logging
import subprocess
import os
from typing import Dict, List, Optional, Any

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.PrivEsc")

class PrivilegeEscalation:
    """Privilege escalation techniques for authorized penetration testing"""

    def __init__(self, scope_validator=None, authorization_required=True):
        self.logger = logger
        self.authorization_required = authorization_required
        self.scope_validator = scope_validator
        self.logger.info("PrivilegeEscalation module initialized - AUTHORIZED PENTESTING ONLY")

    def _check_authorization(self, target: str, method: str) -> bool:
        if not self.authorization_required:
            return True
        if self.scope_validator:
            authorized = self.scope_validator.validate(target, method)
            if not authorized:
                raise PermissionError(f"Target not in authorized scope")
            return True
        self.logger.warning("No scope validator - assuming authorized")
        return True

    def check_suid_files(self) -> Dict[str, Any]:
        """Find SUID binaries on Linux"""
        self._check_authorization("localhost", "suid_check")
        try:
            cmd = ["find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null"]
            proc = subprocess.run(" ".join(cmd), shell=True, capture_output=True, text=True, timeout=60)

            suid_files = [line.strip() for line in proc.stdout.split('\n') if line.strip()]

            return {
                "method": "suid_check",
                "status": "complete",
                "suid_files_found": len(suid_files),
                "files": suid_files[:50]  # Limit output
            }
        except Exception as e:
            return {"method": "suid_check", "status": "failed", "error": str(e)}

    def check_sudo_permissions(self) -> Dict[str, Any]:
        """Check sudo permissions"""
        self._check_authorization("localhost", "sudo_check")
        try:
            proc = subprocess.run(["sudo", "-l"], capture_output=True, text=True, timeout=10)

            return {
                "method": "sudo_check",
                "status": "complete",
                "output": proc.stdout[:1000]
            }
        except Exception as e:
            return {"method": "sudo_check", "status": "failed", "error": str(e)}

    def check_capabilities(self) -> Dict[str, Any]:
        """Check Linux capabilities"""
        self._check_authorization("localhost", "capabilities_check")
        try:
            cmd = ["getcap", "-r", "/", "2>/dev/null"]
            proc = subprocess.run(" ".join(cmd), shell=True, capture_output=True, text=True, timeout=60)

            capabilities = [line.strip() for line in proc.stdout.split('\n') if line.strip()]

            return {
                "method": "capabilities_check",
                "status": "complete",
                "capabilities_found": len(capabilities),
                "capabilities": capabilities[:50]
            }
        except Exception as e:
            return {"method": "capabilities", "status": "failed", "error": str(e)}

    def check_writable_paths(self) -> Dict[str, Any]:
        """Check writable paths in PATH environment"""
        self._check_authorization("localhost", "writable_paths")
        try:
            path_dirs = os.environ.get("PATH", "").split(":")
            writable = []

            for directory in path_dirs:
                if os.path.exists(directory) and os.access(directory, os.W_OK):
                    writable.append(directory)

            return {
                "method": "writable_paths_check",
                "status": "complete",
                "writable_directories": len(writable),
                "directories": writable,
                "note": "Writable PATH directories can be exploited for hijacking"
            }
        except Exception as e:
            return {"method": "writable_paths", "status": "failed", "error": str(e)}

    def check_cron_jobs(self) -> Dict[str, Any]:
        """Check for vulnerable cron jobs"""
        self._check_authorization("localhost", "cron_check")
        try:
            cron_locations = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/"]
            findings = []

            for location in cron_locations:
                if os.path.exists(location):
                    if os.path.isfile(location):
                        with open(location, 'r') as f:
                            findings.append({"file": location, "content": f.read()[:500]})
                    elif os.path.isdir(location):
                        files = os.listdir(location)
                        findings.append({"directory": location, "files": files})

            return {
                "method": "cron_check",
                "status": "complete",
                "findings_count": len(findings),
                "findings": findings
            }
        except Exception as e:
            return {"method": "cron_check", "status": "failed", "error": str(e)}

    def check_kernel_version(self) -> Dict[str, Any]:
        """Check kernel version for known exploits"""
        self._check_authorization("localhost", "kernel_check")
        try:
            proc = subprocess.run(["uname", "-r"], capture_output=True, text=True)
            kernel_version = proc.stdout.strip()

            return {
                "method": "kernel_version_check",
                "status": "complete",
                "kernel_version": kernel_version,
                "note": "Check kernel version against known exploit databases"
            }
        except Exception as e:
            return {"method": "kernel_check", "status": "failed", "error": str(e)}

    def run_linpeas(self) -> Dict[str, Any]:
        """Run LinPEAS privilege escalation scanner"""
        self._check_authorization("localhost", "linpeas")
        try:
            # Check if linpeas.sh exists
            if not os.path.exists("/tmp/linpeas.sh"):
                return {
                    "method": "linpeas",
                    "status": "not_found",
                    "note": "Download from https://github.com/carlospolop/PEASS-ng/releases"
                }

            proc = subprocess.run(["bash", "/tmp/linpeas.sh"], capture_output=True, text=True, timeout=300)

            return {
                "method": "linpeas",
                "status": "complete",
                "output": proc.stdout[:2000]  # Limit output
            }
        except Exception as e:
            return {"method": "linpeas", "status": "failed", "error": str(e)}

    def get_capabilities(self) -> List[str]:
        return ["check_suid_files", "check_sudo_permissions", "check_capabilities",
                "check_writable_paths", "check_cron_jobs", "check_kernel_version", "run_linpeas"]

__all__ = ["PrivilegeEscalation"]
