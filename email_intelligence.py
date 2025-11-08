#!/usr/bin/env python3
"""
📧 EMAIL INTELLIGENCE MODULE
Email validation, breach checking, reputation analysis
Authority Level: 11.0

Uses HIBP (Have I Been Pwned), email validation APIs, and advanced analysis
"""

import os
import re
import requests
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Load master keychain
load_dotenv(r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env")


class EmailIntelligence:
    """Email OSINT with breach detection, validation, and reputation"""
    
    def __init__(self):
        self.hibp_key = os.getenv('HIBP_API_KEY')
        self.hunter_key = os.getenv('HUNTER_IO_API_KEY')
        self.clearbit_key = os.getenv('CLEARBIT_API_KEY')
        
        # Base URLs
        self.hibp_breach_url = "https://haveibeenpwned.com/api/v3/breachedaccount"
        self.hibp_paste_url = "https://haveibeenpwned.com/api/v3/pasteaccount"
        self.hunter_verify_url = "https://api.hunter.io/v2/email-verifier"
        
        # API status
        self.apis_available = {
            'hibp': bool(self.hibp_key),
            'hunter': bool(self.hunter_key),
            'clearbit': bool(self.clearbit_key)
        }
        
        if not self.hibp_key:
            print("⚠️ HIBP_API_KEY not found - breach checking will be limited")
    
    def analyze(self, email: str) -> Dict[str, Any]:
        """
        Complete email intelligence analysis
        
        Args:
            email: Email address to analyze
            
        Returns:
            Comprehensive email intelligence report
        """
        print(f"📧 Email Intelligence: {email}")
        
        result = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'apis_used': [],
            'valid': False,
            'validation': None,
            'breaches': None,
            'pastes': None,
            'reputation': None,
            'domain_info': None,
            'errors': []
        }
        
        # Validation
        try:
            result['validation'] = self._validate_email(email)
            result['valid'] = result['validation'].get('valid', False)
            result['apis_used'].append('validation')
        except Exception as e:
            result['errors'].append(f'Validation error: {str(e)}')
            print(f"❌ Validation failed: {e}")
        
        # Breach check via HIBP
        if self.hibp_key and result['valid']:
            try:
                result['breaches'] = self._check_breaches(email)
                result['apis_used'].append('hibp_breaches')
            except Exception as e:
                result['errors'].append(f'Breach check error: {str(e)}')
                print(f"❌ Breach check failed: {e}")
            
            try:
                result['pastes'] = self._check_pastes(email)
                result['apis_used'].append('hibp_pastes')
            except Exception as e:
                result['errors'].append(f'Paste check error: {str(e)}')
        
        # Hunter.io verification
        if self.hunter_key and result['valid']:
            try:
                result['hunter_verification'] = self._hunter_verify(email)
                result['apis_used'].append('hunter')
            except Exception as e:
                result['errors'].append(f'Hunter verification error: {str(e)}')
        
        # Domain analysis
        if result['valid']:
            domain = email.split('@')[1]
            result['domain_info'] = self._analyze_domain(domain)
        
        # Generate summary
        result['summary'] = self._generate_summary(result)
        
        print(f"✅ Email intelligence complete: {len(result['apis_used'])} APIs used")
        return result
    
    def _validate_email(self, email: str) -> Dict[str, Any]:
        """Validate email format and structure"""
        
        validation = {
            'valid': False,
            'format_valid': False,
            'domain_valid': False,
            'disposable': False,
            'catch_all': None,
            'deliverable': None
        }
        
        # Regex validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        validation['format_valid'] = bool(re.match(email_pattern, email))
        
        if not validation['format_valid']:
            return validation
        
        # Extract domain
        try:
            domain = email.split('@')[1]
            
            # Check if domain has valid DNS records
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                validation['domain_valid'] = len(list(mx_records)) > 0
            except:
                # Fallback to basic check
                validation['domain_valid'] = self._check_domain_exists(domain)
            
            # Check for disposable email domains
            validation['disposable'] = self._is_disposable_domain(domain)
            
            validation['valid'] = validation['format_valid'] and validation['domain_valid'] and not validation['disposable']
            
        except Exception as e:
            print(f"Domain validation error: {e}")
        
        return validation
    
    def _check_breaches(self, email: str) -> Dict[str, Any]:
        """Check if email appears in data breaches (HIBP)"""
        
        headers = {
            'hibp-api-key': self.hibp_key,
            'user-agent': 'Prometheus-Prime-OSINT'
        }
        
        try:
            response = requests.get(
                f"{self.hibp_breach_url}/{email}",
                headers=headers,
                params={'truncateResponse': 'false'},
                timeout=10
            )
            
            if response.status_code == 404:
                return {
                    'found': False,
                    'breach_count': 0,
                    'breaches': []
                }
            
            response.raise_for_status()
            breaches = response.json()
            
            # Process breach data
            breach_summary = []
            for breach in breaches:
                breach_summary.append({
                    'name': breach.get('Name'),
                    'domain': breach.get('Domain'),
                    'breach_date': breach.get('BreachDate'),
                    'added_date': breach.get('AddedDate'),
                    'pwn_count': breach.get('PwnCount'),
                    'description': breach.get('Description', '')[:200],
                    'data_classes': breach.get('DataClasses', []),
                    'verified': breach.get('IsVerified'),
                    'sensitive': breach.get('IsSensitive')
                })
            
            return {
                'found': True,
                'breach_count': len(breaches),
                'breaches': breach_summary,
                'total_pwn_count': sum(b.get('pwn_count', 0) for b in breach_summary)
            }
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                return {'error': 'Invalid HIBP API key'}
            elif e.response.status_code == 429:
                return {'error': 'Rate limit exceeded'}
            raise
    
    def _check_pastes(self, email: str) -> Dict[str, Any]:
        """Check if email appears in pastes (HIBP)"""
        
        headers = {
            'hibp-api-key': self.hibp_key,
            'user-agent': 'Prometheus-Prime-OSINT'
        }
        
        try:
            response = requests.get(
                f"{self.hibp_paste_url}/{email}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 404:
                return {
                    'found': False,
                    'paste_count': 0,
                    'pastes': []
                }
            
            response.raise_for_status()
            pastes = response.json()
            
            # Process paste data
            paste_summary = []
            for paste in pastes[:10]:  # Limit to 10 most recent
                paste_summary.append({
                    'source': paste.get('Source'),
                    'id': paste.get('Id'),
                    'title': paste.get('Title'),
                    'date': paste.get('Date'),
                    'email_count': paste.get('EmailCount')
                })
            
            return {
                'found': True,
                'paste_count': len(pastes),
                'pastes': paste_summary
            }
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {'found': False, 'paste_count': 0, 'pastes': []}
            raise
    
    def _hunter_verify(self, email: str) -> Dict[str, Any]:
        """Verify email deliverability with Hunter.io"""
        
        try:
            response = requests.get(
                self.hunter_verify_url,
                params={
                    'email': email,
                    'api_key': self.hunter_key
                },
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            
            if 'data' in data:
                verification = data['data']
                return {
                    'status': verification.get('status'),
                    'result': verification.get('result'),
                    'score': verification.get('score'),
                    'regexp': verification.get('regexp'),
                    'gibberish': verification.get('gibberish'),
                    'disposable': verification.get('disposable'),
                    'webmail': verification.get('webmail'),
                    'mx_records': verification.get('mx_records'),
                    'smtp_server': verification.get('smtp_server'),
                    'smtp_check': verification.get('smtp_check'),
                    'accept_all': verification.get('accept_all'),
                    'block': verification.get('block')
                }
            
            return {'error': 'No verification data returned'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze email domain"""
        
        analysis = {
            'domain': domain,
            'is_freemail': self._is_freemail_domain(domain),
            'is_disposable': self._is_disposable_domain(domain),
            'mx_records_exist': False
        }
        
        # Check MX records
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            analysis['mx_records_exist'] = True
            analysis['mx_records'] = [str(mx.exchange) for mx in mx_records]
        except:
            analysis['mx_records_exist'] = False
        
        return analysis
    
    def _check_domain_exists(self, domain: str) -> bool:
        """Simple domain existence check"""
        try:
            import socket
            socket.gethostbyname(domain)
            return True
        except:
            return False
    
    def _is_freemail_domain(self, domain: str) -> bool:
        """Check if domain is a free email provider"""
        freemail_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
            'tutanota.com', 'zoho.com', 'yandex.com', 'gmx.com'
        }
        return domain.lower() in freemail_domains
    
    def _is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is a disposable email provider"""
        disposable_domains = {
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'throwaway.email', 'mailinator.com', 'maildrop.cc',
            'temp-mail.org', 'fakeinbox.com', 'getnada.com'
        }
        return domain.lower() in disposable_domains
    
    def _generate_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence summary"""
        
        summary = {
            'email_valid': result.get('valid', False),
            'risk_level': 'unknown',
            'compromised': False,
            'key_findings': [],
            'recommendations': []
        }
        
        # Check for breaches
        breaches = result.get('breaches', {})
        if breaches and breaches.get('found'):
            summary['compromised'] = True
            summary['risk_level'] = 'high'
            count = breaches.get('breach_count', 0)
            summary['key_findings'].append(f"⚠️ Found in {count} data breach(es)")
            summary['recommendations'].append('Change password immediately')
            summary['recommendations'].append('Enable 2FA on all accounts')
        
        # Check for pastes
        pastes = result.get('pastes', {})
        if pastes and pastes.get('found'):
            count = pastes.get('paste_count', 0)
            summary['key_findings'].append(f"Found in {count} paste(s)")
            if not summary['compromised']:
                summary['risk_level'] = 'medium'
        
        # Domain analysis
        domain_info = result.get('domain_info', {})
        if domain_info:
            if domain_info.get('is_disposable'):
                summary['key_findings'].append('Disposable email domain')
                summary['risk_level'] = 'medium'
            if domain_info.get('is_freemail'):
                summary['key_findings'].append('Free email provider')
        
        # Hunter verification
        hunter = result.get('hunter_verification', {})
        if hunter and not hunter.get('error'):
            score = hunter.get('score', 0)
            if score < 50:
                summary['key_findings'].append(f'Low deliverability score: {score}')
            if hunter.get('disposable'):
                summary['key_findings'].append('Identified as disposable')
        
        # Set risk level if not already set
        if summary['risk_level'] == 'unknown':
            if summary['email_valid']:
                summary['risk_level'] = 'low'
            else:
                summary['risk_level'] = 'invalid'
        
        return summary
    
    def batch_analyze(self, emails: List[str]) -> Dict[str, Any]:
        """Analyze multiple emails"""
        results = {}
        
        for email in emails:
            try:
                results[email] = self.analyze(email)
            except Exception as e:
                results[email] = {
                    'email': email,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
        
        return results
    
    def check_password_breach(self, password: str) -> Dict[str, Any]:
        """
        Check if password has been compromised using k-anonymity
        (Doesn't send full password to HIBP, only first 5 chars of hash)
        """
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )
            response.raise_for_status()
            
            # Parse response
            hashes = response.text.splitlines()
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    return {
                        'compromised': True,
                        'count': int(count),
                        'message': f'This password has been seen {count} times in breaches'
                    }
            
            return {
                'compromised': False,
                'count': 0,
                'message': 'Password not found in breach databases'
            }
            
        except Exception as e:
            return {'error': str(e)}


def main():
    """Test email intelligence"""
    ei = EmailIntelligence()
    
    # Test with an email
    test_email = input("Enter email to analyze: ").strip()
    
    if test_email:
        result = ei.analyze(test_email)
        
        print("\n" + "="*60)
        print(f"📧 EMAIL INTELLIGENCE REPORT: {test_email}")
        print("="*60)
        
        # Validation
        validation = result.get('validation', {})
        print(f"\n✉️ Validation:")
        print(f"   Valid: {result.get('valid')}")
        print(f"   Format: {validation.get('format_valid')}")
        print(f"   Domain: {validation.get('domain_valid')}")
        print(f"   Disposable: {validation.get('disposable')}")
        
        # Breaches
        breaches = result.get('breaches', {})
        if breaches and breaches.get('found'):
            print(f"\n⚠️ BREACH ALERT:")
            print(f"   Breaches Found: {breaches.get('breach_count')}")
            print(f"   Total Accounts Affected: {breaches.get('total_pwn_count'):,}")
            for breach in breaches.get('breaches', [])[:5]:
                print(f"   • {breach['name']} ({breach['breach_date']})")
        elif breaches:
            print(f"\n✅ No breaches found")
        
        # Pastes
        pastes = result.get('pastes', {})
        if pastes and pastes.get('found'):
            print(f"\n📋 Paste Alert:")
            print(f"   Found in {pastes.get('paste_count')} paste(s)")
        
        # Summary
        summary = result.get('summary', {})
        print(f"\n📊 Summary:")
        print(f"   Risk Level: {summary['risk_level'].upper()}")
        print(f"   Compromised: {summary['compromised']}")
        if summary['key_findings']:
            print(f"   Findings:")
            for finding in summary['key_findings']:
                print(f"     • {finding}")
        if summary['recommendations']:
            print(f"   Recommendations:")
            for rec in summary['recommendations']:
                print(f"     • {rec}")
        
        print("\n" + "="*60)
        print(f"APIs Used: {', '.join(result['apis_used'])}")


if __name__ == '__main__':
    main()
