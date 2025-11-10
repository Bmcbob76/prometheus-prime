"""
PROMETHEUS PRIME - PASSWORD CRACKING & HASH ANALYSIS TOOLKIT
Authority Level: 11.0
Status: OPERATIONAL

Comprehensive password cracking, hash analysis, and credential testing tools.
"""

import subprocess
import hashlib
import os
import json
from typing import Dict, List, Optional, Any
import base64
import itertools
import string


class PasswordCrackingToolkit:
    """Complete password cracking and hash analysis toolkit."""

    def __init__(self):
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384
        }

    def hash_identify(self, hash_string: str) -> Dict[str, Any]:
        """
        Identify hash type based on length and format.

        Args:
            hash_string: The hash to identify

        Returns:
            Dictionary with possible hash types
        """
        hash_len = len(hash_string)
        results = {
            "hash": hash_string,
            "length": hash_len,
            "possible_types": []
        }

        # Identify based on length
        hash_types = {
            32: ["MD5", "NTLM", "MD4"],
            40: ["SHA1", "RIPEMD-160", "MySQL5 (old)"],
            56: ["SHA224", "Haval-224"],
            64: ["SHA256", "RIPEMD-256", "BLAKE2s"],
            96: ["SHA384"],
            128: ["SHA512", "Whirlpool", "BLAKE2b"]
        }

        if hash_len in hash_types:
            results["possible_types"] = hash_types[hash_len]

        # Check for specific patterns
        if hash_string.startswith("$1$"):
            results["possible_types"].append("MD5 (Unix)")
        elif hash_string.startswith("$2a$") or hash_string.startswith("$2b$"):
            results["possible_types"].append("bcrypt")
        elif hash_string.startswith("$5$"):
            results["possible_types"].append("SHA256 (Unix)")
        elif hash_string.startswith("$6$"):
            results["possible_types"].append("SHA512 (Unix)")
        elif hash_string.startswith("$apr1$"):
            results["possible_types"].append("Apache MD5")

        return results

    def hash_generate(self, plaintext: str, algorithm: str = 'all') -> Dict[str, str]:
        """
        Generate hashes from plaintext.

        Args:
            plaintext: The text to hash
            algorithm: Hash algorithm or 'all' for all types

        Returns:
            Dictionary of algorithm: hash pairs
        """
        results = {}

        if algorithm == 'all':
            for name, func in self.hash_algorithms.items():
                results[name] = func(plaintext.encode()).hexdigest()
        elif algorithm in self.hash_algorithms:
            results[algorithm] = self.hash_algorithms[algorithm](plaintext.encode()).hexdigest()
        else:
            return {"error": f"Unknown algorithm: {algorithm}"}

        return results

    def john_crack(self, hash_file: str, wordlist: Optional[str] = None,
                   format: Optional[str] = None) -> Dict[str, Any]:
        """
        Use John the Ripper to crack passwords.

        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format: Hash format (md5, sha1, etc.)

        Returns:
            Cracking results
        """
        if not os.path.exists(hash_file):
            return {"error": "Hash file not found"}

        cmd = ["john"]

        if format:
            cmd.extend(["--format=" + format])

        if wordlist:
            if os.path.exists(wordlist):
                cmd.extend(["--wordlist=" + wordlist])
            else:
                return {"error": "Wordlist not found"}

        cmd.append(hash_file)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Get cracked passwords
            show_cmd = ["john", "--show", hash_file]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True)

            return {
                "status": "completed",
                "output": result.stdout,
                "cracked": show_result.stdout,
                "errors": result.stderr
            }
        except FileNotFoundError:
            return {"error": "John the Ripper not installed. Install with: apt-get install john"}
        except subprocess.TimeoutExpired:
            return {"error": "Cracking timeout (5 minutes)"}

    def hashcat_crack(self, hash_string: str, attack_mode: int = 0,
                     hash_type: int = 0, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Use Hashcat for GPU-accelerated cracking.

        Args:
            hash_string: Hash to crack
            attack_mode: 0=straight, 1=combination, 3=brute-force, 6=hybrid
            hash_type: Hashcat hash type number
            wordlist: Path to wordlist

        Returns:
            Cracking results
        """
        cmd = ["hashcat", "-m", str(hash_type), "-a", str(attack_mode)]

        # Create temp file for hash
        temp_hash = "/tmp/prometheus_hash.txt"
        with open(temp_hash, 'w') as f:
            f.write(hash_string)

        cmd.append(temp_hash)

        if attack_mode == 0 and wordlist:
            if os.path.exists(wordlist):
                cmd.append(wordlist)
            else:
                return {"error": "Wordlist not found"}

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return {
                "status": "completed",
                "output": result.stdout,
                "errors": result.stderr,
                "hash": hash_string
            }
        except FileNotFoundError:
            return {"error": "Hashcat not installed. Install from https://hashcat.net/hashcat/"}
        except subprocess.TimeoutExpired:
            return {"error": "Cracking timeout (5 minutes)"}
        finally:
            if os.path.exists(temp_hash):
                os.remove(temp_hash)

    def brute_force_generate(self, charset: str = "lowercase",
                            min_length: int = 1, max_length: int = 4) -> List[str]:
        """
        Generate brute force password combinations.

        Args:
            charset: Character set (lowercase, uppercase, digits, special, all)
            min_length: Minimum password length
            max_length: Maximum password length

        Returns:
            List of generated passwords
        """
        charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': string.punctuation,
            'all': string.ascii_letters + string.digits + string.punctuation
        }

        if charset not in charsets:
            return []

        chars = charsets[charset]
        passwords = []

        # Limit to prevent memory issues
        total_combinations = sum(len(chars) ** i for i in range(min_length, max_length + 1))
        if total_combinations > 100000:
            return ["ERROR: Too many combinations. Reduce length or use wordlist attack."]

        for length in range(min_length, max_length + 1):
            for combo in itertools.product(chars, repeat=length):
                passwords.append(''.join(combo))

        return passwords[:10000]  # Limit to 10k

    def password_strength(self, password: str) -> Dict[str, Any]:
        """
        Analyze password strength.

        Args:
            password: Password to analyze

        Returns:
            Strength analysis
        """
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        # Calculate entropy
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32

        import math
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        # Strength rating
        if entropy < 28:
            strength = "Very Weak"
        elif entropy < 36:
            strength = "Weak"
        elif entropy < 60:
            strength = "Moderate"
        elif entropy < 128:
            strength = "Strong"
        else:
            strength = "Very Strong"

        return {
            "password": "*" * length,
            "length": length,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_special": has_special,
            "entropy_bits": round(entropy, 2),
            "strength": strength,
            "recommendations": self._get_recommendations(password, entropy)
        }

    def _get_recommendations(self, password: str, entropy: float) -> List[str]:
        """Generate password improvement recommendations."""
        recommendations = []

        if len(password) < 12:
            recommendations.append("Increase length to at least 12 characters")
        if not any(c.isupper() for c in password):
            recommendations.append("Add uppercase letters")
        if not any(c.islower() for c in password):
            recommendations.append("Add lowercase letters")
        if not any(c.isdigit() for c in password):
            recommendations.append("Add numbers")
        if not any(c in string.punctuation for c in password):
            recommendations.append("Add special characters")
        if entropy < 60:
            recommendations.append("Use a longer password with mixed character types")

        return recommendations if recommendations else ["Password meets strong criteria"]

    def rainbow_table_generate(self, wordlist: str, output_file: str,
                               hash_type: str = 'md5') -> Dict[str, Any]:
        """
        Generate rainbow table from wordlist.

        Args:
            wordlist: Path to wordlist
            output_file: Output file for rainbow table
            hash_type: Hash algorithm to use

        Returns:
            Generation results
        """
        if not os.path.exists(wordlist):
            return {"error": "Wordlist not found"}

        if hash_type not in self.hash_algorithms:
            return {"error": f"Unsupported hash type: {hash_type}"}

        hash_func = self.hash_algorithms[hash_type]
        rainbow_table = {}

        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        hash_value = hash_func(word.encode()).hexdigest()
                        rainbow_table[hash_value] = word

            # Save rainbow table
            with open(output_file, 'w') as f:
                json.dump(rainbow_table, f, indent=2)

            return {
                "status": "success",
                "entries": len(rainbow_table),
                "output_file": output_file,
                "hash_type": hash_type
            }
        except Exception as e:
            return {"error": str(e)}

    def rainbow_table_lookup(self, hash_value: str, rainbow_file: str) -> Dict[str, Any]:
        """
        Lookup hash in rainbow table.

        Args:
            hash_value: Hash to lookup
            rainbow_file: Rainbow table file

        Returns:
            Lookup results
        """
        if not os.path.exists(rainbow_file):
            return {"error": "Rainbow table not found"}

        try:
            with open(rainbow_file, 'r') as f:
                rainbow_table = json.load(f)

            if hash_value in rainbow_table:
                return {
                    "found": True,
                    "hash": hash_value,
                    "plaintext": rainbow_table[hash_value]
                }
            else:
                return {
                    "found": False,
                    "hash": hash_value,
                    "message": "Hash not found in rainbow table"
                }
        except Exception as e:
            return {"error": str(e)}

    def hydra_attack(self, target: str, service: str, username: str,
                    wordlist: str, port: Optional[int] = None) -> Dict[str, Any]:
        """
        Use Hydra for online password attacks.

        Args:
            target: Target IP or hostname
            service: Service (ssh, ftp, http, etc.)
            username: Username to test
            wordlist: Password wordlist
            port: Custom port (optional)

        Returns:
            Attack results
        """
        if not os.path.exists(wordlist):
            return {"error": "Wordlist not found"}

        cmd = ["hydra", "-l", username, "-P", wordlist]

        if port:
            cmd.extend(["-s", str(port)])

        cmd.extend([target, service])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return {
                "status": "completed",
                "target": target,
                "service": service,
                "username": username,
                "output": result.stdout,
                "errors": result.stderr
            }
        except FileNotFoundError:
            return {"error": "Hydra not installed. Install with: apt-get install hydra"}
        except subprocess.TimeoutExpired:
            return {"error": "Attack timeout (5 minutes)"}


# Example usage and testing
if __name__ == "__main__":
    toolkit = PasswordCrackingToolkit()

    # Test hash identification
    print("=== Hash Identification ===")
    result = toolkit.hash_identify("5f4dcc3b5aa765d61d8327deb882cf99")
    print(json.dumps(result, indent=2))

    # Test hash generation
    print("\n=== Hash Generation ===")
    result = toolkit.hash_generate("password123")
    print(json.dumps(result, indent=2))

    # Test password strength
    print("\n=== Password Strength ===")
    result = toolkit.password_strength("MyP@ssw0rd2024!")
    print(json.dumps(result, indent=2))
