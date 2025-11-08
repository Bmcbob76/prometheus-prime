#!/usr/bin/env python3
"""
OSINT OPERATIONS - Open Source Intelligence Gathering
Authority Level: 9.9
"""

import requests
import subprocess
from typing import Dict, List
import logging
import json

logger = logging.getLogger(__name__)

class OSINTOperations:
    """Open source intelligence gathering"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def whois_lookup(self, domain: str) -> Dict:
        """WHOIS domain lookup"""
        try:
            result = subprocess.run(
                ['nslookup', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'status': 'success',
                'domain': domain,
                'output': result.stdout
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def email_format_guess(self, first_name: str, last_name: str, domain: str) -> Dict:
        """Guess common email formats"""
        formats = [
            f"{first_name.lower()}.{last_name.lower()}@{domain}",
            f"{first_name[0].lower()}{last_name.lower()}@{domain}",
            f"{first_name.lower()}@{domain}",
            f"{first_name.lower()}{last_name.lower()}@{domain}",
            f"{first_name[0].lower()}.{last_name.lower()}@{domain}"
        ]
        
        return {
            'status': 'success',
            'possible_emails': formats
        }
    
    def social_media_search(self, username: str) -> Dict:
        """Search for username across social media"""
        platforms = {
            'github': f'https://github.com/{username}',
            'twitter': f'https://twitter.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
            'instagram': f'https://instagram.com/{username}'
        }
        
        found = {}
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=10, allow_redirects=True)
                found[platform] = {
                    'exists': response.status_code == 200,
                    'url': url
                }
            except:
                found[platform] = {'exists': False, 'url': url}
        
        return {
            'status': 'success',
            'username': username,
            'platforms': found
        }
    
    def subdomain_enum(self, domain: str) -> Dict:
        """Enumerate subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'remote'
        ]
        
        found_subdomains = []
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                result = subprocess.run(
                    ['nslookup', full_domain],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if 'Name:' in result.stdout or 'Address:' in result.stdout:
                    found_subdomains.append(full_domain)
            except:
                pass
        
        return {
            'status': 'success',
            'domain': domain,
            'subdomains': found_subdomains,
            'count': len(found_subdomains)
        }
    
    def ip_geolocation(self, ip_address: str) -> Dict:
        """Get geolocation for IP address"""
        try:
            response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=10)
            data = response.json()
            
            return {
                'status': 'success',
                'ip': ip_address,
                'location': {
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country_name'),
                    'org': data.get('org')
                }
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def breach_check(self, email: str) -> Dict:
        """Check if email appears in known breaches (ethical use only)"""
        # Placeholder - would integrate with HaveIBeenPwned API
        return {
            'status': 'not_implemented',
            'message': 'Requires HIBP API key',
            'email': email
        }
    
    def metadata_extract(self, file_path: str) -> Dict:
        """Extract metadata from file"""
        try:
            import exiftool
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata(file_path)
            
            return {
                'status': 'success',
                'file': file_path,
                'metadata': metadata
            }
        except ImportError:
            return {'status': 'error', 'error': 'exiftool not installed'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OSINT Operations")
    parser.add_argument('--whois', help='Domain WHOIS lookup')
    parser.add_argument('--email', nargs=3, metavar=('FIRST', 'LAST', 'DOMAIN'))
    parser.add_argument('--username', help='Search username across platforms')
    parser.add_argument('--subdomains', help='Enumerate subdomains')
    parser.add_argument('--geoip', help='IP geolocation lookup')
    
    args = parser.parse_args()
    
    osint = OSINTOperations()
    
    if args.whois:
        result = osint.whois_lookup(args.whois)
        print(f"WHOIS Lookup: {result['status']}")
        print(result.get('output', ''))
    
    if args.email:
        result = osint.email_format_guess(args.email[0], args.email[1], args.email[2])
        print("Possible email formats:")
        for email in result['possible_emails']:
            print(f"  {email}")
    
    if args.username:
        result = osint.social_media_search(args.username)
        print(f"Social Media Search: {result['status']}")
        for platform, data in result['platforms'].items():
            status = '✅ Found' if data['exists'] else '❌ Not found'
            print(f"  {platform}: {status} - {data['url']}")
    
    if args.subdomains:
        result = osint.subdomain_enum(args.subdomains)
        print(f"Subdomain Enumeration: {result['status']}")
        print(f"Found {result['count']} subdomains:")
        for subdomain in result['subdomains']:
            print(f"  {subdomain}")
    
    if args.geoip:
        result = osint.ip_geolocation(args.geoip)
        print(f"IP Geolocation: {result['status']}")
        if 'location' in result:
            loc = result['location']
            print(f"  City: {loc['city']}")
            print(f"  Region: {loc['region']}")
            print(f"  Country: {loc['country']}")
            print(f"  ISP: {loc['org']}")
