#!/usr/bin/env python3
"""
🌐 IP INTELLIGENCE MODULE
IP geolocation, reputation, ASN lookup, threat intelligence
Authority Level: 11.0

Multi-source IP intelligence with abuse detection and reputation scoring
"""

import os
import requests
from datetime import datetime
from typing import Dict, Any, List
from dotenv import load_dotenv
from gs343_gateway import with_phoenix_retry, gs343

# Load master keychain
load_dotenv(r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env")


class IPIntelligence:
    """IP OSINT with geolocation, reputation, and threat intelligence"""
    
    def __init__(self):
        self.ipapi_key = os.getenv('IPGEOLOCATION_API_KEY')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.shodan_key = os.getenv('SHODAN_API_KEY')
        
        print(f"🌐 IP Intelligence initialized")
        print(f"   APIs: IPGeolocation={bool(self.ipapi_key)}, AbuseIPDB={bool(self.abuseipdb_key)}, VirusTotal={bool(self.virustotal_key)}, Shodan={bool(self.shodan_key)}")
    
    @with_phoenix_retry(max_retries=3)
    def analyze(self, ip: str) -> Dict[str, Any]:
        """
        Complete IP intelligence analysis
        
        Args:
            ip: IP address to analyze
            
        Returns:
            Comprehensive IP intelligence report
        """
        print(f"🔍 IP Intelligence: {ip}")
        
        result = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'apis_used': [],
            'geolocation': None,
            'reputation': None,
            'abuse_reports': None,
            'threat_intel': None,
            'shodan': None,
            'errors': []
        }
        
        # Geolocation (Free fallback: ipapi.co)
        try:
            result['geolocation'] = self._geolocate_ip(ip)
            result['apis_used'].append('geolocation')
        except Exception as e:
            result['errors'].append(f'Geolocation error: {str(e)}')
            print(f"❌ Geolocation failed: {e}")
        
        # Abuse reports
        if self.abuseipdb_key:
            try:
                result['abuse_reports'] = self._check_abuse(ip)
                result['apis_used'].append('abuseipdb')
            except Exception as e:
                result['errors'].append(f'Abuse check error: {str(e)}')
        
        # VirusTotal reputation
        if self.virustotal_key:
            try:
                result['reputation'] = self._check_virustotal(ip)
                result['apis_used'].append('virustotal')
            except Exception as e:
                result['errors'].append(f'VirusTotal error: {str(e)}')
        
        # Shodan intelligence
        if self.shodan_key:
            try:
                result['shodan'] = self._shodan_lookup(ip)
                result['apis_used'].append('shodan')
            except Exception as e:
                result['errors'].append(f'Shodan error: {str(e)}')
        
        # Generate summary
        result['summary'] = self._generate_summary(result)
        
        print(f"✅ IP intelligence complete: {len(result['apis_used'])} APIs used")
        return result
    
    def _geolocate_ip(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation data"""
        
        # Try ipapi.co (free, no key required)
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
            response.raise_for_status()
            data = response.json()
            
            return {
                'ip': data.get('ip'),
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'continent': data.get('continent_code'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone'),
                'postal': data.get('postal'),
                'isp': data.get('org'),
                'asn': data.get('asn'),
                'currency': data.get('currency')
            }
        
        except Exception as e:
            # Fallback to ipgeolocation.io if available
            if self.ipapi_key:
                response = requests.get(
                    "https://api.ipgeolocation.io/ipgeo",
                    params={'apiKey': self.ipapi_key, 'ip': ip},
                    timeout=10
                )
                response.raise_for_status()
                return response.json()
            raise
    
    def _check_abuse(self, ip: str) -> Dict[str, Any]:
        """Check IP abuse reports (AbuseIPDB)"""
        
        headers = {
            'Key': self.abuseipdb_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        ip_data = data.get('data', {})
        
        return {
            'abuse_score': ip_data.get('abuseConfidenceScore', 0),
            'total_reports': ip_data.get('totalReports', 0),
            'num_distinct_users': ip_data.get('numDistinctUsers', 0),
            'last_reported': ip_data.get('lastReportedAt'),
            'is_whitelisted': ip_data.get('isWhitelisted', False),
            'country_code': ip_data.get('countryCode'),
            'usage_type': ip_data.get('usageType'),
            'isp': ip_data.get('isp'),
            'domain': ip_data.get('domain')
        }
    
    def _check_virustotal(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation on VirusTotal"""
        
        headers = {'x-apikey': self.virustotal_key}
        
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        return {
            'reputation': attributes.get('reputation', 0),
            'malicious_count': stats.get('malicious', 0),
            'suspicious_count': stats.get('suspicious', 0),
            'harmless_count': stats.get('harmless', 0),
            'undetected_count': stats.get('undetected', 0),
            'network': attributes.get('network'),
            'asn': attributes.get('asn'),
            'as_owner': attributes.get('as_owner'),
            'country': attributes.get('country')
        }
    
    def _shodan_lookup(self, ip: str) -> Dict[str, Any]:
        """Shodan IP intelligence"""
        
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={'key': self.shodan_key},
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        
        return {
            'open_ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'os': data.get('os'),
            'organization': data.get('org'),
            'isp': data.get('isp'),
            'asn': data.get('asn'),
            'country_code': data.get('country_code'),
            'city': data.get('city'),
            'vulnerabilities': data.get('vulns', []),
            'tags': data.get('tags', []),
            'services': [
                {
                    'port': s.get('port'),
                    'product': s.get('product'),
                    'version': s.get('version')
                }
                for s in data.get('data', [])[:10]
            ]
        }
    
    def _generate_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence summary"""
        
        summary = {
            'risk_level': 'unknown',
            'malicious': False,
            'key_findings': [],
            'recommendations': []
        }
        
        # Abuse score
        abuse = result.get('abuse_reports', {})
        if abuse:
            score = abuse.get('abuse_score', 0)
            if score > 75:
                summary['risk_level'] = 'critical'
                summary['malicious'] = True
                summary['key_findings'].append(f"⚠️ High abuse score: {score}/100")
                summary['recommendations'].append('Block this IP immediately')
            elif score > 50:
                summary['risk_level'] = 'high'
                summary['key_findings'].append(f"Moderate abuse score: {score}/100")
            elif score > 25:
                summary['risk_level'] = 'medium'
        
        # VirusTotal malicious detections
        vt = result.get('reputation', {})
        if vt:
            malicious = vt.get('malicious_count', 0)
            if malicious > 5:
                summary['malicious'] = True
                summary['risk_level'] = 'critical'
                summary['key_findings'].append(f"⚠️ {malicious} malicious detections")
        
        # Geolocation
        geo = result.get('geolocation', {})
        if geo:
            country = geo.get('country', 'Unknown')
            city = geo.get('city', 'Unknown')
            summary['key_findings'].append(f"Location: {city}, {country}")
            summary['key_findings'].append(f"ISP: {geo.get('isp', 'Unknown')}")
        
        # Shodan vulnerabilities
        shodan = result.get('shodan', {})
        if shodan and shodan.get('vulnerabilities'):
            vuln_count = len(shodan['vulnerabilities'])
            summary['key_findings'].append(f"⚠️ {vuln_count} known vulnerabilities")
            summary['recommendations'].append('Patch vulnerabilities immediately')
        
        if summary['risk_level'] == 'unknown':
            summary['risk_level'] = 'low'
        
        return summary
    
    def batch_analyze(self, ips: List[str]) -> Dict[str, Any]:
        """Analyze multiple IPs"""
        results = {}
        
        for ip in ips:
            try:
                results[ip] = self.analyze(ip)
            except Exception as e:
                # Apply Phoenix healing
                healing = gs343.heal_phoenix(
                    error=str(e),
                    context={'module': 'ip_intelligence', 'ip': ip}
                )
                results[ip] = {
                    'ip': ip,
                    'error': str(e),
                    'healing': healing,
                    'timestamp': datetime.now().isoformat()
                }
        
        return results


def main():
    """Test IP intelligence"""
    ip_intel = IPIntelligence()
    
    test_ip = input("Enter IP to analyze (e.g., 8.8.8.8): ").strip()
    
    if test_ip:
        result = ip_intel.analyze(test_ip)
        
        print("\n" + "="*60)
        print(f"🌐 IP INTELLIGENCE REPORT: {test_ip}")
        print("="*60)
        
        # Geolocation
        geo = result.get('geolocation', {})
        if geo:
            print(f"\n📍 Geolocation:")
            print(f"   Location: {geo.get('city')}, {geo.get('country')}")
            print(f"   Coordinates: {geo.get('latitude')}, {geo.get('longitude')}")
            print(f"   ISP: {geo.get('isp')}")
            print(f"   ASN: {geo.get('asn')}")
        
        # Abuse reports
        abuse = result.get('abuse_reports', {})
        if abuse:
            print(f"\n⚠️ Abuse Reports:")
            print(f"   Abuse Score: {abuse.get('abuse_score')}/100")
            print(f"   Total Reports: {abuse.get('total_reports')}")
            print(f"   Usage Type: {abuse.get('usage_type')}")
        
        # VirusTotal
        vt = result.get('reputation', {})
        if vt and not vt.get('error'):
            print(f"\n🛡️ VirusTotal:")
            print(f"   Malicious: {vt.get('malicious_count')}")
            print(f"   Suspicious: {vt.get('suspicious_count')}")
            print(f"   Harmless: {vt.get('harmless_count')}")
        
        # Shodan
        shodan = result.get('shodan', {})
        if shodan and not shodan.get('error'):
            print(f"\n🔍 Shodan:")
            print(f"   Open Ports: {shodan.get('open_ports')}")
            print(f"   Organization: {shodan.get('organization')}")
            print(f"   Vulnerabilities: {len(shodan.get('vulnerabilities', []))}")
        
        # Summary
        summary = result.get('summary', {})
        print(f"\n📊 Summary:")
        print(f"   Risk Level: {summary['risk_level'].upper()}")
        print(f"   Malicious: {summary['malicious']}")
        if summary['key_findings']:
            print(f"   Findings:")
            for finding in summary['key_findings']:
                print(f"     • {finding}")
        
        print("\n" + "="*60)
        print(f"APIs Used: {', '.join(result['apis_used'])}")


if __name__ == '__main__':
    main()
