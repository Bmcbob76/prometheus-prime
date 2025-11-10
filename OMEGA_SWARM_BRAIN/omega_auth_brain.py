"""
🧠 OMEGA AUTHENTICATION BRAIN - Multi-Modal Security System
Commander Bobby Don McWilliams II - Authority Level 11.0
"""

import json
import hashlib
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import secrets

@dataclass
class AuthenticationAttempt:
    method: str  # 'token', 'voice', 'auth11'
    success: bool
    timestamp: str
    ip_address: Optional[str]
    user_agent: Optional[str]

@dataclass
class BloodlineToken:
    token_hash: str
    user_id: str
    authority_level: float
    issued_at: str
    expires_at: str
    permissions: List[str]

class OmegaAuthBrain:
    """Advanced multi-modal authentication system"""
    
    def __init__(self):
        self.valid_tokens: Dict[str, BloodlineToken] = {}
        self.auth_attempts: List[AuthenticationAttempt] = []
        self.locked_ips: Dict[str, datetime] = {}
        
        # Voice recognition patterns
        self.voice_patterns = {
            'commander': ['commander', 'bobby don', 'brother'],
            'echo prime': ['echo prime', 'echo x', 'x1200'],
            'authority': ['authority eleven', 'authority 11', 'level 11']
        }
        
        # AUTH11 keyboard sequence
        self.auth11_sequence = ['Control', 'Alt', 'Digit1', 'Digit1']
        
        print("🧠 OMEGA AUTH BRAIN INITIALIZED - AUTHORITY 11.0")
    
    def generate_bloodline_token(self, user_id: str, authority_level: float = 11.0) -> str:
        """Generate secure bloodline authentication token"""
        token_data = f"{user_id}:{authority_level}:{secrets.token_hex(32)}:{time.time()}"
        token = hashlib.sha256(token_data.encode()).hexdigest()
        
        bloodline = BloodlineToken(
            token_hash=token,
            user_id=user_id,
            authority_level=authority_level,
            issued_at=datetime.now().isoformat(),
            expires_at=(datetime.now() + timedelta(days=30)).isoformat(),
            permissions=['master_gui', 'server_control', 'neural_access', 'full_system']
        )
        
        self.valid_tokens[token] = bloodline
        print(f"✅ Bloodline token generated for {user_id} - Authority {authority_level}")
        return token
    
    def validate_token(self, token: str, ip_address: str = None) -> bool:
        """Validate bloodline token"""
        if self._is_ip_locked(ip_address):
            return False
        
        if token in self.valid_tokens:
            bloodline = self.valid_tokens[token]
            expires = datetime.fromisoformat(bloodline.expires_at)
            
            if datetime.now() < expires:
                self._log_attempt('token', True, ip_address)
                return True
            else:
                print("❌ Token expired")
                del self.valid_tokens[token]
        
        self._log_attempt('token', False, ip_address)
        return False
    
    def validate_voice_pattern(self, transcript: str, ip_address: str = None) -> bool:
        """Validate voice recognition authentication"""
        if self._is_ip_locked(ip_address):
            return False
        
        transcript_lower = transcript.lower()
        
        # Check for commander identity
        commander_match = any(pattern in transcript_lower for pattern in self.voice_patterns['commander'])
        
        # Check for echo prime activation
        echo_match = any(pattern in transcript_lower for pattern in self.voice_patterns['echo prime'])
        
        # Check for authority level
        authority_match = any(pattern in transcript_lower for pattern in self.voice_patterns['authority'])
        
        success = commander_match and (echo_match or authority_match)
        self._log_attempt('voice', success, ip_address)
        
        if success:
            print("✅ Voice authentication successful")
        else:
            print("❌ Voice authentication failed")
        
        return success
    
    def validate_auth11_sequence(self, key_sequence: List[str], ip_address: str = None) -> bool:
        """Validate AUTH11 keyboard sequence (Ctrl+Alt+1+1)"""
        if self._is_ip_locked(ip_address):
            return False
        
        success = key_sequence == self.auth11_sequence
        self._log_attempt('auth11', success, ip_address)
        
        if success:
            print("✅ AUTH11 sequence validated")
        else:
            print("❌ AUTH11 sequence invalid")
        
        return success
    
    def check_multi_modal_auth(self, token: str = None, voice: str = None, 
                               auth11: List[str] = None, ip_address: str = None) -> Dict:
        """Check multi-modal authentication status"""
        results = {
            'authenticated': False,
            'methods': {
                'token': False,
                'voice': False,
                'auth11': False
            },
            'authority_level': 0.0,
            'access_granted': False
        }
        
        # Check each method
        if token:
            results['methods']['token'] = self.validate_token(token, ip_address)
        
        if voice:
            results['methods']['voice'] = self.validate_voice_pattern(voice, ip_address)
        
        if auth11:
            results['methods']['auth11'] = self.validate_auth11_sequence(auth11, ip_address)
        
        # Determine overall authentication
        successful_methods = sum(results['methods'].values())
        
        if successful_methods >= 2:
            results['authenticated'] = True
            results['authority_level'] = 11.0
            results['access_granted'] = True
            print("🎖️ FULL AUTHENTICATION GRANTED - AUTHORITY 11.0")
        elif successful_methods == 1:
            results['authenticated'] = True
            results['authority_level'] = 5.0
            print("⚠️ PARTIAL AUTHENTICATION - LIMITED ACCESS")
        else:
            print("❌ AUTHENTICATION FAILED")
        
        return results
    
    def _is_ip_locked(self, ip_address: str) -> bool:
        """Check if IP is locked due to failed attempts"""
        if not ip_address or ip_address not in self.locked_ips:
            return False
        
        lock_until = self.locked_ips[ip_address]
        if datetime.now() < lock_until:
            return True
        else:
            del self.locked_ips[ip_address]
            return False
    
    def _log_attempt(self, method: str, success: bool, ip_address: str = None, user_agent: str = None):
        """Log authentication attempt"""
        attempt = AuthenticationAttempt(
            method=method,
            success=success,
            timestamp=datetime.now().isoformat(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.auth_attempts.append(attempt)
        
        # Lock IP after 5 failed attempts
        if not success and ip_address:
            recent_failures = sum(
                1 for a in self.auth_attempts[-10:]
                if a.ip_address == ip_address and not a.success
            )
            
            if recent_failures >= 5:
                self.locked_ips[ip_address] = datetime.now() + timedelta(minutes=15)
                print(f"🔒 IP locked for 15 minutes: {ip_address}")
    
    def get_auth_stats(self) -> Dict:
        """Get authentication statistics"""
        total = len(self.auth_attempts)
        successful = sum(1 for a in self.auth_attempts if a.success)
        
        return {
            'total_attempts': total,
            'successful': successful,
            'failed': total - successful,
            'success_rate': (successful / total * 100) if total > 0 else 0,
            'active_tokens': len(self.valid_tokens),
            'locked_ips': len(self.locked_ips)
        }
    
    def export_config(self) -> Dict:
        """Export authentication configuration for GUI"""
        return {
            'voice_patterns': self.voice_patterns,
            'auth11_sequence': self.auth11_sequence,
            'token_validity_days': 30,
            'max_failed_attempts': 5,
            'lockout_duration_minutes': 15
        }


# CLI Interface
if __name__ == '__main__':
    import sys
    
    brain = OmegaAuthBrain()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'generate':
            token = brain.generate_bloodline_token('Commander', 11.0)
            print(f"Token: {token}")
        elif sys.argv[1] == 'stats':
            print(json.dumps(brain.get_auth_stats(), indent=2))
        else:
            print("Usage: python omega_auth_brain.py [generate|stats]")
    else:
        print(json.dumps(brain.export_config(), indent=2))
