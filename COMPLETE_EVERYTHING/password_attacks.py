#!/usr/bin/env python3
"""
PASSWORD ATTACKS - Hash Cracking & Password Security
Authority Level: 9.9
"""

import subprocess
import hashlib
from typing import Dict, List
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class PasswordAttacks:
    """Password cracking and hash analysis"""
    
    def __init__(self):
        self.hashcat_available = self._check_hashcat()
        self.john_available = self._check_john()
        
    def _check_hashcat(self) -> bool:
        try:
            result = subprocess.run(['hashcat', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _check_john(self) -> bool:
        try:
            result = subprocess.run(['john', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def identify_hash(self, hash_value: str) -> Dict:
        """Identify hash type by length and pattern"""
        hash_len = len(hash_value)
        
        hash_types = {
            32: 'MD5',
            40: 'SHA1',
            56: 'SHA224',
            64: 'SHA256',
            96: 'SHA384',
            128: 'SHA512'
        }
        
        likely_type = hash_types.get(hash_len, 'Unknown')
        
        return {
            'hash': hash_value,
            'length': hash_len,
            'likely_type': likely_type,
            'suggestions': self._get_hash_suggestions(likely_type)
        }
    
    def _get_hash_suggestions(self, hash_type: str) -> List[str]:
        """Get cracking suggestions for hash type"""
        suggestions = []
        if hash_type == 'MD5':
            suggestions = ['Dictionary attack', 'Rainbow tables', 'Online MD5 databases']
        elif hash_type in ['SHA256', 'SHA512']:
            suggestions = ['Dictionary attack with rules', 'Mask attack', 'Combination attack']
        return suggestions
    
    def dictionary_attack(self, hash_file: str, wordlist: str, hash_type: str = 'md5') -> Dict:
        """Perform dictionary attack using hashcat"""
        if not self.hashcat_available:
            return {'status': 'error', 'error': 'Hashcat not installed'}
        
        # Map hash type to hashcat mode
        hash_modes = {
            'md5': '0',
            'sha1': '100',
            'sha256': '1400',
            'sha512': '1700',
            'ntlm': '1000'
        }
        
        mode = hash_modes.get(hash_type.lower(), '0')
        
        try:
            cmd = [
                'hashcat',
                '-m', mode,
                '-a', '0',
                hash_file,
                wordlist,
                '--force'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                'status': 'complete',
                'output': result.stdout,
                'mode': hash_type
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'message': 'Attack exceeded time limit'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def brute_force_attack(self, hash_file: str, hash_type: str = 'md5', 
                          mask: str = '?a?a?a?a?a?a') -> Dict:
        """Perform brute force attack"""
        if not self.hashcat_available:
            return {'status': 'error', 'error': 'Hashcat not installed'}
        
        hash_modes = {
            'md5': '0',
            'sha1': '100',
            'sha256': '1400'
        }
        
        mode = hash_modes.get(hash_type.lower(), '0')
        
        try:
            cmd = [
                'hashcat',
                '-m', mode,
                '-a', '3',
                hash_file,
                mask,
                '--force'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            return {
                'status': 'complete',
                'output': result.stdout
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def generate_hashes(self, plaintext: str) -> Dict:
        """Generate common hashes for plaintext"""
        hashes = {
            'md5': hashlib.md5(plaintext.encode()).hexdigest(),
            'sha1': hashlib.sha1(plaintext.encode()).hexdigest(),
            'sha256': hashlib.sha256(plaintext.encode()).hexdigest(),
            'sha512': hashlib.sha512(plaintext.encode()).hexdigest()
        }
        
        return {
            'plaintext': plaintext,
            'hashes': hashes
        }
    
    def check_status(self) -> Dict:
        """Check available password cracking tools"""
        return {
            'hashcat': self.hashcat_available,
            'john': self.john_available,
            'status': 'ready' if (self.hashcat_available or self.john_available) else 'tools_missing'
        }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Password Attack Framework")
    parser.add_argument('--identify', help='Identify hash type')
    parser.add_argument('--generate', help='Generate hashes for plaintext')
    parser.add_argument('--dictionary', nargs=3, metavar=('HASH_FILE', 'WORDLIST', 'TYPE'))
    parser.add_argument('--brute', nargs=2, metavar=('HASH_FILE', 'TYPE'))
    parser.add_argument('--check-tools', action='store_true')
    
    args = parser.parse_args()
    
    pa = PasswordAttacks()
    
    if args.check_tools:
        status = pa.check_status()
        print("Password Cracking Tools:")
        print(f"  Hashcat: {'✅' if status['hashcat'] else '❌'}")
        print(f"  John: {'✅' if status['john'] else '❌'}")
        print(f"  Status: {status['status']}")
    
    if args.identify:
        result = pa.identify_hash(args.identify)
        print(f"Hash: {result['hash']}")
        print(f"Length: {result['length']}")
        print(f"Type: {result['likely_type']}")
        print("Suggestions:")
        for suggestion in result['suggestions']:
            print(f"  - {suggestion}")
    
    if args.generate:
        result = pa.generate_hashes(args.generate)
        print(f"Plaintext: {result['plaintext']}")
        for hash_type, hash_value in result['hashes'].items():
            print(f"{hash_type.upper()}: {hash_value}")
