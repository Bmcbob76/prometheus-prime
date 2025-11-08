#!/usr/bin/env python3
"""
🌐 DOMAIN INTELLIGENCE MODULE
WHOIS lookups, DNS records, domain reputation
Authority Level: 11.0

Uses WhoisXML API for comprehensive domain intelligence
"""

import os
import requests
from datetime import datetime
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load master keychain
load_dotenv(r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env")


class DomainIntelligence:
    """Domain OSINT with WHOIS, DNS, and reputation checks"""
    
    def __init__(self):
        self.whoisxml_key = os.getenv('WHOISXML_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        # Base URLs
        self.whois_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        self.dns_url = "https://www.whoisxmlapi.com/whoisserver/DNSService"
        self.reputation_url = "https://domain-reputation.whoisxmlapi.com/api/v2"
        
        # API status
        self.apis_available = {
            'whoisxml': bool(self.whoisxml_key),
            'virustotal': bool(self.virustotal_key)
        }
        
        if not self.whoisxml_key:
            print("⚠️ WHOISXML_API_KEY not found - domain lookups will be limited")
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        """
        Complete domain intelligence lookup
        
        Args:
            domain: Domain name (e.g., 'example.com')
            
        Returns:
            Comprehensive domain intelligence report
        """
        print(f"🔍 Domain Intelligence: {domain}")
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'apis_used': [],
            'whois': None,
            'dns': None,
            'reputation': None,
            'errors': []
        }
        
        # WHOIS lookup
        if self.whoisxml_key:
            try:
                result['whois'] = self._whois_lookup(domain)
                result['apis_used'].append('whoisxml')
            except Exception as e:
                result['errors'].append(f'WHOIS error: {str(e)}')
                print(f"❌ WHOIS lookup failed: {e}")
        
        # DNS records
        if self.whoisxml_key:
            try:
                result['dns'] = self._dns_lookup(domain)
                result['apis_used'].append('whoisxml_dns')
            except Exception as e:
                result['errors'].append(f'DNS error: {str(e)}')
                print(f"❌ DNS lookup failed: {e}")
        
        # Domain reputation
        if self.whoisxml_key:
            try:
                result['reputation'] = self._reputation_check(domain)
                result['apis_used'].append('domain_reputation')
            except Exception as e:
                result['errors'].append(f'Reputation error: {str(e)}')
                print(f"❌ Reputation check failed: {e}")
        
        # VirusTotal domain check
        if self.virustotal_key:
            try:
                result['virustotal'] = self._virustotal_check(domain)
                result['apis_used'].append('virustotal')
            except Exception as e:
                result['errors'].append(f'VirusTotal error: {str(e)}')
        
        # Generate summary
        result['summary'] = self._generate_summary(result)
        
        print(f"✅ Domain intelligence complete: {len(result['apis_used'])} APIs used")
        return result
    
    def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """WHOIS domain registration data"""
        
        params = {
            'apiKey': self.whoisxml_key,
            'domainName': domain,
            'outputFormat': 'JSON'
        }
        
        response = requests.get(self.whois_url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        whois_record = data.get('WhoisRecord', {})
        
        # Extract key information
        registrar = whois_record.get('registrarName', 'Unknown')
        created = whois_record.get('createdDate', 'Unknown')
        expires = whois_record.get('expiresDate', 'Unknown')
        updated = whois_record.get('updatedDate', 'Unknown')
        
        # Registrant information
        registrant = whois_record.get('registrant', {})
        
        return {
            'registrar': registrar,
            'created_date': created,
            'expiration_date': expires,
            'updated_date': updated,
            'registrant': {
                'name': registrant.get('name', 'REDACTED'),
                'organization': registrant.get('organization', 'REDACTED'),
                'country': registrant.get('country', 'Unknown')
            },
            'name_servers': whois_record.get('nameServers', {}).get('hostNames', []),
            'status': whois_record.get('status', 'Unknown'),
            'raw_whois': whois_record.get('registryData', {}).get('rawText', '')[:500]  # First 500 chars
        }
    
    def _dns_lookup(self, domain: str) -> Dict[str, Any]:
        """DNS record lookup (A, AAAA, MX, TXT, NS)"""
        
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        for record_type in record_types:
            try:
                params = {
                    'apiKey': self.whoisxml_key,
                    'domainName': domain,
                    'type': record_type,
                    'outputFormat': 'JSON'
                }
                
                response = requests.get(self.dns_url, params=params, timeout=10)
                response.raise_for_status()
                
                data = response.json()
                dns_data = data.get('DNSData', {})
                
                # Extract records
                records = dns_data.get('dnsRecords', [])
                if records:
                    dns_results[record_type] = [
                        {
                            'value': r.get('dnsType', '') + ' ' + r.get('address', r.get('target', r.get('strings', [''])[0] if r.get('strings') else '')),
                            'ttl': r.get('ttl', 0)
                        }
                        for r in records
                    ]
            
            except Exception as e:
                dns_results[record_type] = f'Error: {str(e)}'
        
        return dns_results
    
    def _reputation_check(self, domain: str) -> Dict[str, Any]:
        """Domain reputation and risk assessment"""
        
        params = {
            'apiKey': self.whoisxml_key,
            'domainName': domain
        }
        
        try:
            response = requests.get(self.reputation_url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract reputation score
            reputation_score = data.get('reputationScore', 0)
            test_results = data.get('testResults', {})
            
            return {
                'reputation_score': reputation_score,  # 0-100, higher is better
                'risk_level': self._calculate_risk_level(reputation_score),
                'tests': {
                    'malware': test_results.get('malwareMatch', 'unknown'),
                    'phishing': test_results.get('phishingMatch', 'unknown'),
                    'spam': test_results.get('spamMatch', 'unknown'),
                    'suspicious': test_results.get('suspiciousMatch', 'unknown')
                },
                'mode': data.get('mode', 'unknown')
            }
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                # API key issue or quota exceeded
                return {
                    'reputation_score': None,
                    'risk_level': 'unknown',
                    'error': 'API quota exceeded or invalid key',
                    'tests': {}
                }
            raise
    
    def _virustotal_check(self, domain: str) -> Dict[str, Any]:
        """VirusTotal domain reputation check"""
        
        headers = {
            'x-apikey': self.virustotal_key
        }
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'reputation': attributes.get('reputation', 0),
                'total_votes': attributes.get('total_votes', {}),
                'analysis_stats': stats,
                'malicious_count': stats.get('malicious', 0),
                'suspicious_count': stats.get('suspicious', 0),
                'harmless_count': stats.get('harmless', 0),
                'undetected_count': stats.get('undetected', 0)
            }
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {'error': 'Domain not found in VirusTotal database'}
            raise
    
    def _calculate_risk_level(self, score: Optional[float]) -> str:
        """Calculate risk level from reputation score"""
        if score is None:
            return 'unknown'
        if score >= 80:
            return 'low'
        elif score >= 60:
            return 'medium'
        elif score >= 40:
            return 'high'
        else:
            return 'critical'
    
    def _generate_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence summary"""
        
        summary = {
            'domain_active': bool(result.get('whois')),
            'risk_assessment': 'unknown',
            'key_findings': [],
            'recommendations': []
        }
        
        # Risk assessment
        reputation = result.get('reputation', {})
        if reputation and reputation.get('reputation_score') is not None:
            summary['risk_assessment'] = reputation.get('risk_level', 'unknown')
        
        # Key findings
        whois = result.get('whois', {})
        if whois:
            age_text = f"Registered: {whois.get('created_date', 'Unknown')}"
            summary['key_findings'].append(age_text)
            
            registrar = whois.get('registrar', 'Unknown')
            summary['key_findings'].append(f"Registrar: {registrar}")
        
        # DNS findings
        dns = result.get('dns', {})
        if dns:
            a_records = dns.get('A', [])
            if a_records:
                summary['key_findings'].append(f"{len(a_records)} A record(s) found")
        
        # VirusTotal findings
        vt = result.get('virustotal', {})
        if vt and not vt.get('error'):
            malicious = vt.get('malicious_count', 0)
            if malicious > 0:
                summary['key_findings'].append(f"⚠️ {malicious} malicious detections on VirusTotal")
                summary['recommendations'].append('Further investigation recommended')
        
        return summary
    
    def batch_lookup(self, domains: list) -> Dict[str, Any]:
        """Lookup multiple domains"""
        results = {}
        
        for domain in domains:
            try:
                results[domain] = self.lookup(domain)
            except Exception as e:
                results[domain] = {
                    'domain': domain,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
        
        return results


def main():
    """Test domain intelligence"""
    di = DomainIntelligence()
    
    # Test with a domain
    test_domain = input("Enter domain to analyze (e.g., example.com): ").strip()
    
    if test_domain:
        result = di.lookup(test_domain)
        
        print("\n" + "="*60)
        print(f"🌐 DOMAIN INTELLIGENCE REPORT: {test_domain}")
        print("="*60)
        
        # WHOIS Info
        if result.get('whois'):
            whois = result['whois']
            print(f"\n📋 WHOIS Information:")
            print(f"   Registrar: {whois.get('registrar')}")
            print(f"   Created: {whois.get('created_date')}")
            print(f"   Expires: {whois.get('expiration_date')}")
            print(f"   Country: {whois.get('registrant', {}).get('country')}")
        
        # DNS Records
        if result.get('dns'):
            print(f"\n🔗 DNS Records:")
            for record_type, records in result['dns'].items():
                if isinstance(records, list) and records:
                    print(f"   {record_type}: {len(records)} record(s)")
        
        # Reputation
        if result.get('reputation'):
            rep = result['reputation']
            score = rep.get('reputation_score')
            if score is not None:
                print(f"\n⚠️ Reputation Score: {score}/100")
                print(f"   Risk Level: {rep.get('risk_level', 'unknown').upper()}")
        
        # Summary
        if result.get('summary'):
            summary = result['summary']
            print(f"\n📊 Summary:")
            print(f"   Risk: {summary['risk_assessment'].upper()}")
            if summary['key_findings']:
                print(f"   Findings:")
                for finding in summary['key_findings']:
                    print(f"     • {finding}")
        
        print("\n" + "="*60)
        print(f"APIs Used: {', '.join(result['apis_used'])}")
        if result.get('errors'):
            print(f"Errors: {len(result['errors'])}")


if __name__ == '__main__':
    main()
