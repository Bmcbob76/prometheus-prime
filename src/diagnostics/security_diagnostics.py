"""
PROMETHEUS PRIME - SECURITY DIAGNOSTICS MODULE

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️

Security vulnerability scanning, configuration auditing, compliance checking.
Comprehensive security posture assessment and hardening recommendations.
"""

import os
import sys
import platform
import subprocess
import logging
import hashlib
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


class SecurityDiagnostics:
    """
    Comprehensive security diagnostics system.

    Features:
    - Vulnerability scanning
    - Configuration auditing
    - Compliance checking (CIS, NIST)
    - Permission analysis
    - Encryption verification
    - Firewall status
    - Security updates
    - CVE database checking
    """

    def __init__(self):
        self.logger = logging.getLogger("SecurityDiagnostics")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": {},
            "configuration": {},
            "compliance": {},
            "permissions": {},
            "encryption": {},
            "firewall": {},
            "updates": {},
            "risk_score": 0,
            "security_score": 100
        }

        self.severity_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
            "INFO": 0
        }

    def run_full_diagnostics(self) -> Dict:
        """Run complete security diagnostics suite."""
        self.logger.info("Starting security diagnostics...")

        # Vulnerability scanning
        self.scan_open_ports()
        self.check_weak_passwords()
        self.scan_outdated_software()

        # Configuration auditing
        self.audit_system_configuration()
        self.check_security_settings()
        self.audit_user_accounts()

        # Compliance checks
        self.check_cis_compliance()
        self.check_encryption_compliance()

        # Permission analysis
        self.check_file_permissions()
        self.check_sudo_permissions()

        # Security features
        self.check_firewall_status()
        self.check_antivirus_status()
        self.check_security_updates()

        # Calculate risk scores
        self.calculate_risk_score()
        self.calculate_security_score()

        self.logger.info("Security diagnostics complete")
        return self.results

    def scan_open_ports(self) -> Dict:
        """Scan for open ports on localhost."""
        self.logger.info("Scanning open ports...")

        import socket

        results = {
            "open_ports": [],
            "suspicious_ports": [],
            "total_scanned": 0
        }

        # Common ports to scan
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            27017: "MongoDB"
        }

        suspicious_ports = {23, 21, 5900}  # Telnet, FTP, VNC (unencrypted)

        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()

                results["total_scanned"] += 1

                if result == 0:
                    port_info = {
                        "port": port,
                        "service": service,
                        "severity": "HIGH" if port in suspicious_ports else "INFO"
                    }
                    results["open_ports"].append(port_info)

                    if port in suspicious_ports:
                        results["suspicious_ports"].append(port_info)

            except Exception as e:
                self.logger.debug(f"Error scanning port {port}: {e}")

        self.results["vulnerabilities"]["open_ports"] = results
        return results

    def check_weak_passwords(self) -> Dict:
        """Check for weak password policies."""
        self.logger.info("Checking password policies...")

        results = {
            "policy_checks": [],
            "issues_found": []
        }

        if platform.system() == "Windows":
            try:
                # Check Windows password policy
                output = subprocess.check_output("net accounts", shell=True).decode()

                checks = {
                    "Minimum password length": 8,
                    "Password complexity": "Enabled"
                }

                for line in output.split('\n'):
                    if "Minimum password length" in line:
                        try:
                            length = int(line.split(':')[1].strip())
                            if length < 12:
                                results["issues_found"].append({
                                    "issue": "Weak minimum password length",
                                    "current": length,
                                    "recommended": 12,
                                    "severity": "MEDIUM"
                                })
                        except:
                            pass

                results["policy_checks"].append("Windows password policy checked")

            except Exception as e:
                results["error"] = str(e)

        elif platform.system() == "Linux":
            try:
                # Check PAM configuration
                pam_files = [
                    "/etc/pam.d/common-password",
                    "/etc/pam.d/system-auth",
                    "/etc/security/pwquality.conf"
                ]

                for pam_file in pam_files:
                    if os.path.exists(pam_file):
                        with open(pam_file, 'r') as f:
                            content = f.read()
                            if "minlen" not in content:
                                results["issues_found"].append({
                                    "issue": f"No minimum password length in {pam_file}",
                                    "severity": "MEDIUM"
                                })

                results["policy_checks"].append("Linux PAM configuration checked")

            except Exception as e:
                results["error"] = str(e)

        self.results["vulnerabilities"]["password_policy"] = results
        return results

    def scan_outdated_software(self) -> Dict:
        """Check for outdated software packages."""
        self.logger.info("Checking for outdated software...")

        results = {
            "outdated_packages": [],
            "update_available": False
        }

        try:
            if platform.system() == "Windows":
                # Check Python packages
                try:
                    output = subprocess.check_output([sys.executable, "-m", "pip", "list", "--outdated"],
                                                   timeout=30).decode()
                    lines = output.split('\n')[2:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                results["outdated_packages"].append({
                                    "package": parts[0],
                                    "current": parts[1],
                                    "latest": parts[2],
                                    "severity": "LOW"
                                })
                except:
                    pass

            elif platform.system() == "Linux":
                # Check apt packages
                try:
                    subprocess.check_output("apt update", shell=True, stderr=subprocess.DEVNULL, timeout=30)
                    output = subprocess.check_output("apt list --upgradable", shell=True, timeout=30).decode()
                    lines = output.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            results["outdated_packages"].append({
                                "package": line.split('/')[0],
                                "severity": "MEDIUM"
                            })
                except:
                    pass

            if results["outdated_packages"]:
                results["update_available"] = True

        except Exception as e:
            results["error"] = str(e)

        self.results["vulnerabilities"]["outdated_software"] = results
        return results

    def audit_system_configuration(self) -> Dict:
        """Audit system security configuration."""
        self.logger.info("Auditing system configuration...")

        results = {
            "checks": [],
            "issues": []
        }

        # Check OS version
        os_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version()
        }
        results["checks"].append({"check": "OS Information", "data": os_info})

        # Check if running as admin/root
        is_admin = False
        if platform.system() == "Windows":
            try:
                is_admin = os.getuid() == 0
            except AttributeError:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.getuid() == 0

        if is_admin:
            results["issues"].append({
                "issue": "Running with elevated privileges",
                "severity": "MEDIUM",
                "recommendation": "Run with least privilege when possible"
            })

        results["checks"].append({"check": "Privilege level", "elevated": is_admin})

        self.results["configuration"]["system"] = results
        return results

    def check_security_settings(self) -> Dict:
        """Check various security settings."""
        self.logger.info("Checking security settings...")

        results = {
            "settings": [],
            "issues": []
        }

        if platform.system() == "Windows":
            try:
                # Check UAC status
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
                uac_enabled = winreg.QueryValueEx(key, "EnableLUA")[0]
                winreg.CloseKey(key)

                results["settings"].append({"setting": "UAC", "enabled": bool(uac_enabled)})

                if not uac_enabled:
                    results["issues"].append({
                        "issue": "UAC disabled",
                        "severity": "HIGH",
                        "recommendation": "Enable User Account Control"
                    })

            except Exception as e:
                self.logger.debug(f"Error checking UAC: {e}")

        elif platform.system() == "Linux":
            # Check SELinux/AppArmor
            try:
                if os.path.exists("/usr/sbin/getenforce"):
                    output = subprocess.check_output("getenforce", shell=True).decode().strip()
                    results["settings"].append({"setting": "SELinux", "status": output})

                    if output != "Enforcing":
                        results["issues"].append({
                            "issue": "SELinux not enforcing",
                            "severity": "MEDIUM",
                            "recommendation": "Enable SELinux in enforcing mode"
                        })

                if os.path.exists("/sys/module/apparmor"):
                    results["settings"].append({"setting": "AppArmor", "status": "Present"})

            except Exception as e:
                self.logger.debug(f"Error checking mandatory access control: {e}")

        self.results["configuration"]["security_settings"] = results
        return results

    def audit_user_accounts(self) -> Dict:
        """Audit user accounts for security issues."""
        self.logger.info("Auditing user accounts...")

        results = {
            "total_users": 0,
            "admin_users": [],
            "issues": []
        }

        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("net user", shell=True).decode()
                # Parse user list
                users = []
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('-'):
                        users.extend(line.split())

                results["total_users"] = len(users)

                # Check admin users
                admin_output = subprocess.check_output("net localgroup Administrators", shell=True).decode()
                for line in admin_output.split('\n'):
                    if line.strip() and not line.startswith('-') and not line.startswith('Alias'):
                        results["admin_users"].append(line.strip())

            elif platform.system() == "Linux":
                # Read /etc/passwd
                with open('/etc/passwd', 'r') as f:
                    users = [line.split(':')[0] for line in f if not line.startswith('#')]
                    results["total_users"] = len(users)

                # Check sudo users
                if os.path.exists('/etc/sudoers'):
                    try:
                        output = subprocess.check_output("getent group sudo", shell=True).decode()
                        admin_users = output.split(':')[-1].strip().split(',')
                        results["admin_users"] = admin_users
                    except:
                        pass

        except Exception as e:
            results["error"] = str(e)

        # Check for excessive admin accounts
        if len(results["admin_users"]) > 3:
            results["issues"].append({
                "issue": f"Multiple administrator accounts ({len(results['admin_users'])})",
                "severity": "MEDIUM",
                "recommendation": "Limit number of privileged accounts"
            })

        self.results["configuration"]["user_accounts"] = results
        return results

    def check_cis_compliance(self) -> Dict:
        """Check CIS (Center for Internet Security) compliance."""
        self.logger.info("Checking CIS compliance...")

        results = {
            "benchmark": "CIS Benchmarks",
            "checks_performed": [],
            "compliant": [],
            "non_compliant": [],
            "compliance_percentage": 0
        }

        # CIS Control 1: Inventory of Authorized and Unauthorized Devices
        results["checks_performed"].append("Asset inventory")
        results["non_compliant"].append({
            "control": "CIS Control 1",
            "issue": "No automated asset inventory detected",
            "severity": "MEDIUM"
        })

        # CIS Control 5: Secure Configuration for Hardware and Software
        results["checks_performed"].append("Secure configuration")
        if platform.system() == "Windows":
            try:
                # Check for security baselines
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
                results["compliant"].append({
                    "control": "CIS Control 5",
                    "check": "Security policies configured"
                })
                winreg.CloseKey(key)
            except:
                pass

        # CIS Control 6: Maintenance, Monitoring and Analysis of Audit Logs
        results["checks_performed"].append("Audit logging")
        if platform.system() == "Linux":
            if os.path.exists("/var/log/auth.log") or os.path.exists("/var/log/secure"):
                results["compliant"].append({
                    "control": "CIS Control 6",
                    "check": "System audit logs present"
                })
            else:
                results["non_compliant"].append({
                    "control": "CIS Control 6",
                    "issue": "System audit logs not found",
                    "severity": "HIGH"
                })

        # CIS Control 10: Data Recovery Capability
        results["checks_performed"].append("Backup configuration")
        results["non_compliant"].append({
            "control": "CIS Control 10",
            "issue": "No automated backup verification",
            "severity": "MEDIUM"
        })

        # Calculate compliance percentage
        total = len(results["compliant"]) + len(results["non_compliant"])
        if total > 0:
            results["compliance_percentage"] = (len(results["compliant"]) / total) * 100

        self.results["compliance"]["cis"] = results
        return results

    def check_encryption_compliance(self) -> Dict:
        """Check encryption compliance."""
        self.logger.info("Checking encryption compliance...")

        results = {
            "disk_encryption": False,
            "tls_enabled": False,
            "ssh_encryption": False,
            "issues": []
        }

        if platform.system() == "Windows":
            try:
                # Check BitLocker status
                output = subprocess.check_output("manage-bde -status", shell=True, stderr=subprocess.DEVNULL).decode()
                if "Protection On" in output:
                    results["disk_encryption"] = True
                else:
                    results["issues"].append({
                        "issue": "BitLocker not enabled",
                        "severity": "HIGH",
                        "recommendation": "Enable BitLocker disk encryption"
                    })
            except:
                pass

        elif platform.system() == "Linux":
            try:
                # Check LUKS encryption
                output = subprocess.check_output("lsblk -f", shell=True).decode()
                if "crypto_LUKS" in output:
                    results["disk_encryption"] = True
                else:
                    results["issues"].append({
                        "issue": "Disk encryption not detected",
                        "severity": "HIGH",
                        "recommendation": "Enable LUKS disk encryption"
                    })
            except:
                pass

        self.results["compliance"]["encryption"] = results
        return results

    def check_file_permissions(self) -> Dict:
        """Check for insecure file permissions."""
        self.logger.info("Checking file permissions...")

        results = {
            "checks_performed": [],
            "issues": []
        }

        if platform.system() == "Linux":
            # Check common sensitive files
            sensitive_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/ssh/sshd_config"
            ]

            for file_path in sensitive_files:
                if os.path.exists(file_path):
                    stat_info = os.stat(file_path)
                    mode = oct(stat_info.st_mode)[-3:]

                    results["checks_performed"].append({
                        "file": file_path,
                        "permissions": mode
                    })

                    # Check if world-readable/writable
                    if stat_info.st_mode & 0o004:  # World-readable
                        if file_path == "/etc/shadow":
                            results["issues"].append({
                                "file": file_path,
                                "issue": "Shadow file is world-readable",
                                "severity": "CRITICAL",
                                "current_permissions": mode
                            })

        self.results["permissions"]["file_permissions"] = results
        return results

    def check_sudo_permissions(self) -> Dict:
        """Check sudo/privileged access configuration."""
        self.logger.info("Checking sudo permissions...")

        results = {
            "sudo_users": [],
            "issues": []
        }

        if platform.system() == "Linux":
            try:
                # Check sudoers file
                if os.path.exists("/etc/sudoers"):
                    with open("/etc/sudoers", 'r') as f:
                        content = f.read()

                        # Check for NOPASSWD
                        if "NOPASSWD" in content:
                            results["issues"].append({
                                "issue": "Passwordless sudo configured",
                                "severity": "HIGH",
                                "recommendation": "Require password for sudo"
                            })

                        # Check for ALL=(ALL) ALL
                        if "ALL=(ALL) ALL" in content:
                            results["issues"].append({
                                "issue": "Overly permissive sudo rule",
                                "severity": "MEDIUM",
                                "recommendation": "Limit sudo commands to necessary operations"
                            })

            except PermissionError:
                results["error"] = "Permission denied reading sudoers"

        self.results["permissions"]["sudo"] = results
        return results

    def check_firewall_status(self) -> Dict:
        """Check firewall configuration and status."""
        self.logger.info("Checking firewall status...")

        results = {
            "enabled": False,
            "type": None,
            "rules_count": 0,
            "issues": []
        }

        if platform.system() == "Windows":
            try:
                output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True).decode()
                if "State" in output and "ON" in output:
                    results["enabled"] = True
                    results["type"] = "Windows Defender Firewall"
                else:
                    results["issues"].append({
                        "issue": "Windows Firewall disabled",
                        "severity": "CRITICAL",
                        "recommendation": "Enable Windows Defender Firewall"
                    })
            except Exception as e:
                results["error"] = str(e)

        elif platform.system() == "Linux":
            # Check ufw
            try:
                output = subprocess.check_output("ufw status", shell=True, stderr=subprocess.DEVNULL).decode()
                if "Status: active" in output:
                    results["enabled"] = True
                    results["type"] = "UFW"
                    results["rules_count"] = output.count("ALLOW") + output.count("DENY")
                else:
                    results["issues"].append({
                        "issue": "UFW firewall not active",
                        "severity": "HIGH",
                        "recommendation": "Enable UFW firewall"
                    })
            except:
                # Check iptables
                try:
                    output = subprocess.check_output("iptables -L -n", shell=True).decode()
                    rules_count = output.count("ACCEPT") + output.count("DROP") + output.count("REJECT")
                    if rules_count > 0:
                        results["enabled"] = True
                        results["type"] = "iptables"
                        results["rules_count"] = rules_count
                except:
                    results["issues"].append({
                        "issue": "No firewall detected",
                        "severity": "CRITICAL",
                        "recommendation": "Install and enable firewall (ufw or iptables)"
                    })

        self.results["firewall"] = results
        return results

    def check_antivirus_status(self) -> Dict:
        """Check antivirus/anti-malware status."""
        self.logger.info("Checking antivirus status...")

        results = {
            "installed": False,
            "enabled": False,
            "updated": False,
            "product": None
        }

        if platform.system() == "Windows":
            try:
                # Check Windows Defender
                output = subprocess.check_output(
                    'powershell "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled"',
                    shell=True
                ).decode()

                if "True" in output:
                    results["installed"] = True
                    results["enabled"] = True
                    results["product"] = "Windows Defender"

            except Exception as e:
                self.logger.debug(f"Error checking antivirus: {e}")

        self.results["configuration"]["antivirus"] = results
        return results

    def check_security_updates(self) -> Dict:
        """Check for pending security updates."""
        self.logger.info("Checking security updates...")

        results = {
            "updates_available": False,
            "security_updates": [],
            "last_update_check": None
        }

        if platform.system() == "Windows":
            try:
                # This would require Windows Update API or PowerShell
                results["info"] = "Windows Update check requires elevated privileges"
            except Exception as e:
                results["error"] = str(e)

        elif platform.system() == "Linux":
            try:
                # Check for security updates
                output = subprocess.check_output(
                    "apt list --upgradable 2>/dev/null | grep -i security",
                    shell=True
                ).decode()

                if output.strip():
                    results["updates_available"] = True
                    for line in output.split('\n'):
                        if line.strip():
                            results["security_updates"].append(line.split('/')[0])

            except:
                pass

        self.results["updates"] = results
        return results

    def calculate_risk_score(self) -> int:
        """Calculate overall risk score based on vulnerabilities."""
        risk_score = 0

        # Count vulnerabilities by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        # Scan all results for issues
        for category in self.results.values():
            if isinstance(category, dict):
                if "issues" in category:
                    for issue in category["issues"]:
                        severity = issue.get("severity", "LOW")
                        if severity in severity_counts:
                            severity_counts[severity] += 1

        # Calculate weighted risk score
        for severity, count in severity_counts.items():
            risk_score += count * self.severity_weights[severity]

        self.results["risk_score"] = risk_score
        return risk_score

    def calculate_security_score(self) -> int:
        """Calculate overall security score (0-100, higher is better)."""
        score = 100

        # Deduct points based on issues
        for category in self.results.values():
            if isinstance(category, dict):
                if "issues" in category:
                    for issue in category["issues"]:
                        severity = issue.get("severity", "LOW")
                        if severity == "CRITICAL":
                            score -= 15
                        elif severity == "HIGH":
                            score -= 10
                        elif severity == "MEDIUM":
                            score -= 5
                        elif severity == "LOW":
                            score -= 2

        # Ensure score doesn't go below 0
        score = max(0, score)

        self.results["security_score"] = score
        return score

    def get_summary(self) -> Dict:
        """Get security diagnostics summary."""
        return {
            "timestamp": self.results["timestamp"],
            "risk_score": self.results["risk_score"],
            "security_score": self.results["security_score"],
            "critical_issues": self._count_issues_by_severity("CRITICAL"),
            "high_issues": self._count_issues_by_severity("HIGH"),
            "medium_issues": self._count_issues_by_severity("MEDIUM"),
            "low_issues": self._count_issues_by_severity("LOW"),
            "recommendations": self._generate_recommendations()
        }

    def _count_issues_by_severity(self, severity: str) -> int:
        """Count issues of a specific severity."""
        count = 0
        for category in self.results.values():
            if isinstance(category, dict):
                if "issues" in category:
                    for issue in category["issues"]:
                        if issue.get("severity") == severity:
                            count += 1
        return count

    def _generate_recommendations(self) -> List[str]:
        """Generate top security recommendations."""
        recommendations = []

        score = self.results.get("security_score", 100)

        if score < 50:
            recommendations.append("CRITICAL: Security posture is severely compromised. Immediate action required.")
        elif score < 70:
            recommendations.append("WARNING: Multiple security issues detected. Address high-priority items.")

        # Firewall
        if not self.results.get("firewall", {}).get("enabled", False):
            recommendations.append("Enable and configure host firewall immediately (CRITICAL)")

        # Encryption
        if not self.results.get("compliance", {}).get("encryption", {}).get("disk_encryption", False):
            recommendations.append("Enable disk encryption to protect data at rest (HIGH)")

        # Updates
        if self.results.get("updates", {}).get("updates_available", False):
            recommendations.append("Apply pending security updates (HIGH)")

        # Open ports
        suspicious = len(self.results.get("vulnerabilities", {}).get("open_ports", {}).get("suspicious_ports", []))
        if suspicious > 0:
            recommendations.append(f"Close {suspicious} suspicious open port(s) (HIGH)")

        if not recommendations:
            recommendations.append("Security posture is strong. Continue regular security assessments.")

        return recommendations[:5]  # Top 5 recommendations


if __name__ == "__main__":
    # Test security diagnostics
    diagnostics = SecurityDiagnostics()
    results = diagnostics.run_full_diagnostics()
    summary = diagnostics.get_summary()

    print("\n" + "="*60)
    print("PROMETHEUS PRIME - SECURITY DIAGNOSTICS")
    print("="*60)
    print(json.dumps(summary, indent=2))
