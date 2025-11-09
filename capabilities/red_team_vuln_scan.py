"""RED TEAM - Vulnerability Scanning
AUTHORIZED USE ONLY - For penetration testing in controlled lab environments
"""
import logging
import subprocess
import requests
from typing import Dict, List, Optional, Any

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.VulnScan")

class VulnerabilityScanner:
    """Vulnerability scanning for authorized penetration testing"""

    def __init__(self, scope_validator=None, authorization_required=True):
        self.logger = logger
        self.authorization_required = authorization_required
        self.scope_validator = scope_validator
        self.logger.info("VulnerabilityScanner module initialized - AUTHORIZED PENTESTING ONLY")

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

    def nmap_vuln_scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Run Nmap vulnerability scripts"""
        self._check_authorization(target, "nmap_vuln")
        try:
            cmd = ["nmap", "-sV", "--script", "vuln", "-p", ports, target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return {
                "method": "nmap_vuln_scan",
                "status": "complete",
                "target": target,
                "output": proc.stdout[:2000]
            }
        except Exception as e:
            return {"method": "nmap_vuln", "status": "failed", "error": str(e)}

    def nikto_scan(self, target: str) -> Dict[str, Any]:
        """Run Nikto web vulnerability scanner"""
        self._check_authorization(target, "nikto")
        try:
            cmd = ["nikto", "-h", target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return {
                "method": "nikto_scan",
                "status": "complete",
                "target": target,
                "output": proc.stdout[:2000]
            }
        except Exception as e:
            return {"method": "nikto", "status": "failed", "error": str(e)}

    def check_cve(self, service: str, version: str) -> Dict[str, Any]:
        """Check CVE database for known vulnerabilities"""
        self._check_authorization("cve_database", "cve_check")
        try:
            # Query CVE database API (example using NVD)
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}+{version}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                cve_count = data.get("totalResults", 0)

                return {
                    "method": "cve_check",
                    "status": "complete",
                    "service": service,
                    "version": version,
                    "cve_count": cve_count,
                    "results": data.get("result", {}).get("CVE_Items", [])[:5]
                }
            else:
                return {"method": "cve_check", "status": "api_error", "code": response.status_code}

        except Exception as e:
            return {"method": "cve_check", "status": "failed", "error": str(e)}

    def service_version_check(self, target: str, port: int) -> Dict[str, Any]:
        """Detect service version and check for known vulnerabilities"""
        self._check_authorization(target, "version_detection")
        try:
            cmd = ["nmap", "-sV", "-p", str(port), target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            return {
                "method": "service_version_check",
                "status": "complete",
                "target": target,
                "port": port,
                "output": proc.stdout
            }
        except Exception as e:
            return {"method": "version_check", "status": "failed", "error": str(e)}

    def ssl_tls_scan(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Scan SSL/TLS configuration"""
        self._check_authorization(target, "ssl_scan")
        try:
            cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            return {
                "method": "ssl_tls_scan",
                "status": "complete",
                "target": target,
                "port": port,
                "output": proc.stdout[:1500]
            }
        except Exception as e:
            return {"method": "ssl_scan", "status": "failed", "error": str(e)}

    def exploit_check(self, cve_id: str) -> Dict[str, Any]:
        """Check if exploit is available for CVE"""
        self._check_authorization("exploit_db", "exploit_check")
        try:
            # Use searchsploit to find exploits
            cmd = ["searchsploit", cve_id]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            exploits_found = len([l for l in proc.stdout.split('\n') if l.strip() and not l.startswith('-')])

            return {
                "method": "exploit_check",
                "status": "complete",
                "cve_id": cve_id,
                "exploits_found": exploits_found,
                "output": proc.stdout[:1000]
            }
        except Exception as e:
            return {"method": "exploit_check", "status": "failed", "error": str(e)}

    def get_capabilities(self) -> List[str]:
        return ["nmap_vuln_scan", "nikto_scan", "check_cve", "service_version_check",
                "ssl_tls_scan", "exploit_check"]

__all__ = ["VulnerabilityScanner"]
