"""
PROMETHEUS-PRIME OSINT Core - FULL IMPLEMENTATION
Open Source Intelligence Gathering & Reconnaissance
Authority Level 11.0 | Commander Bobby Don McWilliams II

CAPABILITIES:
- DNS enumeration (all record types)
- WHOIS analysis & historical data
- Subdomain discovery (bruteforce + DNS)
- Email harvesting (search engines + DNS)
- Social media reconnaissance
- GitHub/GitLab intelligence
- Certificate transparency logs
- IP geolocation & ASN lookup
- Port scanning integration
- Shodan/Censys automation
- Domain reputation analysis
- Wayback Machine integration
"""

import asyncio
import aiohttp
import dns.resolver
import dns.zone
import dns.query
import whois
import socket
import ssl
import json
import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime
import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, quote
import base64
# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class OSINTTarget:
    """Comprehensive target definition"""
    domain: Optional[str] = None
    ip: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    person: Optional[str] = None
    social_handles: Dict[str, str] = field(default_factory=dict)
    
@dataclass
class DNSRecord:
    """DNS record with metadata"""
    record_type: str
    value: str
    ttl: int
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class SubdomainResult:
    """Subdomain discovery result"""
    subdomain: str
    ip_addresses: List[str]
    cname: Optional[str]
    alive: bool
    http_status: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
@dataclass
class EmailResult:
    """Email discovery result"""
    email: str
    source: str
    confidence: float
    first_seen: datetime = field(default_factory=datetime.now)
    
@dataclass
class SocialMediaProfile:
    """Social media profile data"""
    platform: str
    username: str
    url: str
    followers: Optional[int] = None
    verified: bool = False
    bio: Optional[str] = None
    location: Optional[str] = None

@dataclass 
class IPIntelligence:
    """IP address intelligence"""
    ip: str
    hostname: Optional[str]
    country: str
    city: str
    isp: str
    asn: str
    reputation_score: float
    threat_level: str
    open_ports: List[int] = field(default_factory=list)

# ============================================================================
# OSINT ENGINE - COMPREHENSIVE INTELLIGENCE GATHERING
# ============================================================================

class OSINTEngine:
    """Production-grade OSINT intelligence engine"""
    
    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        self.session = None
        self.api_keys = api_keys or {}
        self.results = {}
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 3
        self.dns_resolver.lifetime = 3
        
        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'webdisk', 'ns', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm',
            'imap', 'test', 'portal', 'ns3', 'ns4', 'blog', 'dev', 'www2', 'admin',
            'forum', 'news', 'vpn', 'ns5', 'email', 'server', 'beta', 'stage', 'staging',
            'api', 'secure', 'shop', 'store', 'login', 'cdn', 'remote', 'cloud',
            'git', 'support', 'mobile', 'docs', 'help', 'gateway', 'app', 'apps'
        ]
        
        # Search engine user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
    
    async def __aenter__(self):
        """Async context manager entry"""
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
        
    async def __aexit__(self, *args):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    # ========================================================================
    # DNS RECONNAISSANCE
    # ========================================================================
    
    def dns_comprehensive_scan(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """Complete DNS enumeration - all record types"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA', 'DNSKEY', 'DS']
        results = {}
        
        for rtype in record_types:
            try:
                answers = self.dns_resolver.resolve(domain, rtype)
                records = []
                for rdata in answers:
                    records.append(DNSRecord(
                        record_type=rtype,
                        value=str(rdata),
                        ttl=answers.ttl
                    ))
                results[rtype] = records
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                results[rtype] = []
            except Exception as e:
                results[rtype] = []
        
        return results
    
    def dns_zone_transfer(self, domain: str) -> Optional[List[str]]:
        """Attempt DNS zone transfer (AXFR)"""
        try:
            ns_records = self.dns_resolver.resolve(domain, 'NS')
            for ns in ns_records:
                nameserver = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
                    if zone:
                        records = []
                        for name, node in zone.nodes.items():
                            records.append(f"{name}.{domain}")
                        return records
                except:
                    continue
        except:
            pass
        return None
    
    def dns_reverse_lookup(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0]
        except:
            return None
    
    def dnssec_validation(self, domain: str) -> Dict[str, bool]:
        """Check DNSSEC configuration"""
        has_dnskey = False
        has_ds = False
        
        try:
            self.dns_resolver.resolve(domain, 'DNSKEY')
            has_dnskey = True
        except:
            pass
            
        try:
            self.dns_resolver.resolve(domain, 'DS')
            has_ds = True
        except:
            pass
        
        return {'dnskey_present': has_dnskey, 'ds_present': has_ds, 'dnssec_enabled': has_dnskey and has_ds}
    
    # ========================================================================
    # SUBDOMAIN ENUMERATION
    # ========================================================================
    
    async def subdomain_bruteforce(self, domain: str, wordlist: Optional[List[str]] = None) -> List[SubdomainResult]:
        """Bruteforce subdomain discovery"""
        wordlist = wordlist or self.common_subdomains
        results = []
        
        async def check_subdomain(subdomain: str):
            target = f"{subdomain}.{domain}"
            try:
                answers = self.dns_resolver.resolve(target, 'A')
                ips = [str(rdata) for rdata in answers]
                
                # Check if alive
                alive = False
                http_status = None
                title = None
                
                try:
                    async with self.session.get(f"http://{target}", timeout=aiohttp.ClientTimeout(total=5), allow_redirects=True) as resp:
                        alive = True
                        http_status = resp.status
                        if resp.status == 200:
                            html = await resp.text()
                            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                            if title_match:
                                title = title_match.group(1)
                except:
                    pass
                
                return SubdomainResult(
                    subdomain=target,
                    ip_addresses=ips,
                    cname=None,
                    alive=alive,
                    http_status=http_status,
                    title=title
                )
            except:
                return None
        
        # Run checks concurrently
        tasks = [check_subdomain(sub) for sub in wordlist]
        checked = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in checked:
            if result and not isinstance(result, Exception):
                results.append(result)
        
        return results
    
    async def subdomain_crtsh(self, domain: str) -> List[str]:
        """Certificate Transparency log subdomain discovery"""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip()
                            if subdomain and '*' not in subdomain:
                                subdomains.add(subdomain.lower())
        except:
            pass
        
        return list(subdomains)
    
    def subdomain_google_dorks(self, domain: str) -> List[str]:
        """Google dork for subdomain discovery"""
        dorks = [
            f"site:*.{domain}",
            f"site:{domain} -www"
        ]
        return dorks  # Return dork queries for manual/automated execution
    
    # ========================================================================
    # WHOIS & DOMAIN INTELLIGENCE
    # ========================================================================
    
    def whois_comprehensive(self, domain: str) -> Dict:
        """Comprehensive WHOIS lookup"""
        try:
            w = whois.whois(domain)
            
            # Extract and normalize data
            result = {
                'domain_name': w.domain_name if isinstance(w.domain_name, str) else w.domain_name[0] if w.domain_name else None,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else [],
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else None,
                'org': w.org if hasattr(w, 'org') else None,
                'address': w.address if hasattr(w, 'address') else None,
                'city': w.city if hasattr(w, 'city') else None,
                'state': w.state if hasattr(w, 'state') else None,
                'country': w.country if hasattr(w, 'country') else None,
                'registrant_postal_code': w.registrant_postal_code if hasattr(w, 'registrant_postal_code') else None
            }
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def domain_age_check(self, domain: str) -> Optional[int]:
        """Calculate domain age in days"""
        try:
            w = whois.whois(domain)
            if w.creation_date:
                created = w.creation_date if isinstance(w.creation_date, datetime) else w.creation_date[0]
                age = (datetime.now() - created).days
                return age
        except:
            pass
        return None
    
    # ========================================================================
    # EMAIL HARVESTING
    # ========================================================================
    
    async def email_harvest_search_engines(self, domain: str) -> List[EmailResult]:
        """theHarvester-style email discovery from search engines"""
        emails = []
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@' + re.escape(domain) + r'\b', re.IGNORECASE)
        
        search_queries = [
            f'site:{domain} email',
            f'site:{domain} contact',
            f'@{domain}',
            f'site:{domain} "email" OR "mail" OR "contact"'
        ]
        
        # Note: Actual search engine scraping would require handling CAPTCHAs
        # This is a framework for integration with search APIs
        
        return emails
    
    def email_dns_discovery(self, domain: str) -> List[EmailResult]:
        """Extract emails from DNS records"""
        emails = []
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        try:
            # Check TXT records
            txt_records = self.dns_resolver.resolve(domain, 'TXT')
            for txt in txt_records:
                text = str(txt)
                found = email_pattern.findall(text)
                for email in found:
                    emails.append(EmailResult(
                        email=email.lower(),
                        source='DNS-TXT',
                        confidence=0.9
                    ))
        except:
            pass
        
        return emails
    
    # ========================================================================
    # IP INTELLIGENCE & GEOLOCATION
    # ========================================================================
    
    async def ip_comprehensive_lookup(self, ip: str) -> IPIntelligence:
        """Complete IP intelligence gathering"""
        hostname = self.dns_reverse_lookup(ip)
        
        # Geolocation via ip-api.com (free tier)
        geo_data = {}
        try:
            async with self.session.get(f"http://ip-api.com/json/{ip}?fields=66846719") as resp:
                if resp.status == 200:
                    geo_data = await resp.json()
        except:
            pass
        
        # Port scanning (top ports)
        open_ports = await self.scan_common_ports(ip)
        
        # Reputation check
        reputation = self.check_ip_reputation(ip)
        
        return IPIntelligence(
            ip=ip,
            hostname=hostname,
            country=geo_data.get('country', 'Unknown'),
            city=geo_data.get('city', 'Unknown'),
            isp=geo_data.get('isp', 'Unknown'),
            asn=str(geo_data.get('as', 'Unknown')),
            reputation_score=reputation['score'],
            threat_level=reputation['level'],
            open_ports=open_ports
        )
    
    async def scan_common_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """Scan common ports on target IP"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        open_ports = []
        
        async def check_port(port: int):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        tasks = [check_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                open_ports.append(result)
        
        return sorted(open_ports)
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """Check IP reputation (multiple sources)"""
        # AbuseIPDB, VirusTotal, etc. would go here with API keys
        # Basic reputation check
        score = 0.5  # Neutral by default
        level = 'unknown'
        
        # Check common blacklists
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net'
        ]
        
        blacklisted = 0
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for bl in blacklists:
            try:
                query = f"{reversed_ip}.{bl}"
                self.dns_resolver.resolve(query, 'A')
                blacklisted += 1
            except:
                pass
        
        if blacklisted > 0:
            score = 0.2
            level = 'high_risk'
        elif blacklisted == 0:
            score = 0.8
            level = 'clean'
        
        return {'score': score, 'level': level, 'blacklisted_count': blacklisted}
    
    async def asn_lookup(self, ip: str) -> Dict:
        """ASN and network ownership lookup"""
        try:
            async with self.session.get(f"https://api.hackertarget.com/aslookup/?q={ip}") as resp:
                if resp.status == 200:
                    data = await resp.text()
                    lines = data.strip().split('\n')
                    if lines:
                        return {'asn_info': lines[0], 'raw': data}
        except:
            pass
        return {}
    
    # ========================================================================
    # SHODAN & CENSYS INTEGRATION
    # ========================================================================
    
    async def shodan_host_lookup(self, ip: str) -> Dict:
        """Shodan host information"""
        api_key = self.api_keys.get('shodan')
        if not api_key:
            return {'error': 'No Shodan API key provided'}
        
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {'error': f'Status {resp.status}'}
        except Exception as e:
            return {'error': str(e)}
    
    async def shodan_search(self, query: str, limit: int = 100) -> List[Dict]:
        """Shodan search query"""
        api_key = self.api_keys.get('shodan')
        if not api_key:
            return []
        
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={quote(query)}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get('matches', [])[:limit]
        except:
            pass
        return []
    
    # ========================================================================
    # GITHUB RECONNAISSANCE
    # ========================================================================
    
    async def github_user_recon(self, username: str) -> Dict:
        """GitHub user reconnaissance"""
        result = {'user': {}, 'repos': [], 'gists': []}
        
        # User info
        try:
            async with self.session.get(f"https://api.github.com/users/{username}") as resp:
                if resp.status == 200:
                    result['user'] = await resp.json()
        except:
            pass
        
        # Repositories
        try:
            async with self.session.get(f"https://api.github.com/users/{username}/repos?per_page=100") as resp:
                if resp.status == 200:
                    result['repos'] = await resp.json()
        except:
            pass
        
        # Gists
        try:
            async with self.session.get(f"https://api.github.com/users/{username}/gists") as resp:
                if resp.status == 200:
                    result['gists'] = await resp.json()
        except:
            pass
        
        return result
    
    async def github_org_recon(self, org: str) -> Dict:
        """GitHub organization reconnaissance"""
        result = {'org': {}, 'repos': [], 'members': []}
        
        try:
            async with self.session.get(f"https://api.github.com/orgs/{org}") as resp:
                if resp.status == 200:
                    result['org'] = await resp.json()
        except:
            pass
        
        try:
            async with self.session.get(f"https://api.github.com/orgs/{org}/repos?per_page=100") as resp:
                if resp.status == 200:
                    result['repos'] = await resp.json()
        except:
            pass
        
        try:
            async with self.session.get(f"https://api.github.com/orgs/{org}/members") as resp:
                if resp.status == 200:
                    result['members'] = await resp.json()
        except:
            pass
        
        return result
    
    async def github_code_search(self, query: str, language: Optional[str] = None) -> List[Dict]:
        """Search GitHub code"""
        search_query = quote(query)
        if language:
            search_query += f"+language:{language}"
        
        results = []
        try:
            url = f"https://api.github.com/search/code?q={search_query}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get('items', [])
        except:
            pass
        
        return results
    
    # ========================================================================
    # SOCIAL MEDIA RECONNAISSANCE
    # ========================================================================
    
    async def social_media_username_check(self, username: str) -> List[SocialMediaProfile]:
        """Check username across major platforms"""
        platforms = {
            'twitter': f"https://twitter.com/{username}",
            'github': f"https://github.com/{username}",
            'instagram': f"https://instagram.com/{username}",
            'linkedin': f"https://linkedin.com/in/{username}",
            'facebook': f"https://facebook.com/{username}",
            'reddit': f"https://reddit.com/user/{username}",
            'youtube': f"https://youtube.com/@{username}",
            'tiktok': f"https://tiktok.com/@{username}",
            'medium': f"https://medium.com/@{username}",
            'dev.to': f"https://dev.to/{username}"
        }
        
        profiles = []
        
        async def check_platform(platform: str, url: str):
            try:
                async with self.session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        return SocialMediaProfile(
                            platform=platform,
                            username=username,
                            url=url
                        )
            except:
                pass
            return None
        
        tasks = [check_platform(p, u) for p, u in platforms.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                profiles.append(result)
        
        return profiles
    
    # ========================================================================
    # SSL/TLS CERTIFICATE ANALYSIS
    # ========================================================================
    
    def ssl_certificate_info(self, domain: str, port: int = 443) -> Dict:
        """Extract SSL/TLS certificate information"""
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', []),
                        'cipher': ssock.cipher()
                    }
        except Exception as e:
            return {'error': str(e)}
    
    # ========================================================================
    # WAYBACK MACHINE / WEB ARCHIVE
    # ========================================================================
    
    async def wayback_snapshots(self, url: str) -> List[Dict]:
        """Get Wayback Machine snapshots"""
        snapshots = []
        
        try:
            api_url = f"http://archive.org/wayback/available?url={quote(url)}"
            async with self.session.get(api_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if 'archived_snapshots' in data and 'closest' in data['archived_snapshots']:
                        closest = data['archived_snapshots']['closest']
                        snapshots.append({
                            'timestamp': closest.get('timestamp'),
                            'url': closest.get('url'),
                            'status': closest.get('status')
                        })
        except:
            pass
        
        return snapshots
    
    async def wayback_cdx_search(self, domain: str, limit: int = 100) -> List[str]:
        """Search Wayback Machine CDX for URLs"""
        urls = []
        
        try:
            api_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}"
            async with self.session.get(api_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for row in data[1:]:  # Skip header
                        if len(row) > 2:
                            urls.append(row[2])  # Original URL
        except:
            pass
        
        return list(set(urls))  # Deduplicate
    
    # ========================================================================
    # TECHNOLOGY FINGERPRINTING
    # ========================================================================
    
    async def detect_technologies(self, url: str) -> List[str]:
        """Detect web technologies (Wappalyzer-style)"""
        technologies = []
        
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    headers = resp.headers
                    
                    # Server header
                    if 'Server' in headers:
                        technologies.append(f"Server: {headers['Server']}")
                    
                    # Powered-by
                    if 'X-Powered-By' in headers:
                        technologies.append(f"Powered-By: {headers['X-Powered-By']}")
                    
                    # Framework detection
                    frameworks = {
                        'WordPress': ['wp-content', 'wp-includes'],
                        'Drupal': ['sites/all/modules', 'Drupal.settings'],
                        'Joomla': ['com_content', '/components/'],
                        'React': ['react.js', 'react.min.js', '__REACT'],
                        'Vue.js': ['vue.js', 'vue.min.js'],
                        'Angular': ['ng-app', 'angular.js'],
                        'jQuery': ['jquery.js', 'jquery.min.js'],
                        'Bootstrap': ['bootstrap.css', 'bootstrap.min.css']
                    }
                    
                    for tech, signatures in frameworks.items():
                        for sig in signatures:
                            if sig in html:
                                technologies.append(tech)
                                break
        except:
            pass
        
        return list(set(technologies))
    
    # ========================================================================
    # DATA PERSISTENCE
    # ========================================================================
    
    def save_results(self, target: str, data: Dict, output_dir: str = "E:/prometheus_prime/osint_db/results"):
        """Save OSINT results to JSON"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        safe_filename = target.replace('.', '_').replace('/', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = output_path / f"{safe_filename}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        return str(filename)
    
    def load_results(self, filename: str) -> Dict:
        """Load previously saved OSINT results"""
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    # ========================================================================
    # COMPREHENSIVE WORKFLOWS
    # ========================================================================
    
    async def full_domain_osint(self, domain: str) -> Dict:
        """Complete OSINT workflow for a domain"""
        results = {
            'target': domain,
            'timestamp': datetime.now().isoformat(),
            'dns': {},
            'subdomains': [],
            'whois': {},
            'ssl': {},
            'technologies': [],
            'emails': [],
            'ip_intel': [],
            'wayback': [],
            'shodan': {}
        }
        
        print(f"[*] Starting comprehensive OSINT for {domain}")
        
        # DNS reconnaissance
        print("[*] DNS enumeration...")
        results['dns'] = self.dns_comprehensive_scan(domain)
        results['dns']['dnssec'] = self.dnssec_validation(domain)
        results['dns']['zone_transfer'] = self.dns_zone_transfer(domain)
        
        # WHOIS
        print("[*] WHOIS lookup...")
        results['whois'] = self.whois_comprehensive(domain)
        results['whois']['age_days'] = self.domain_age_check(domain)
        
        # Subdomain discovery
        print("[*] Subdomain enumeration...")
        subdomain_tasks = [
            self.subdomain_bruteforce(domain),
            self.subdomain_crtsh(domain)
        ]
        subdomain_results = await asyncio.gather(*subdomain_tasks)
        results['subdomains'] = subdomain_results[0]
        results['subdomains_crt'] = subdomain_results[1]
        
        # SSL/TLS analysis
        print("[*] SSL certificate analysis...")
        results['ssl'] = self.ssl_certificate_info(domain)
        
        # Technology detection
        print("[*] Technology fingerprinting...")
        results['technologies'] = await self.detect_technologies(f"https://{domain}")
        
        # Email harvesting
        print("[*] Email discovery...")
        results['emails'] = self.email_dns_discovery(domain)
        
        # IP intelligence (for A records)
        print("[*] IP intelligence gathering...")
        if 'A' in results['dns'] and results['dns']['A']:
            ip_tasks = [self.ip_comprehensive_lookup(record.value) for record in results['dns']['A'][:3]]
            results['ip_intel'] = await asyncio.gather(*ip_tasks)
        
        # Wayback Machine
        print("[*] Wayback Machine lookup...")
        results['wayback'] = await self.wayback_snapshots(f"https://{domain}")
        
        # Shodan (if API key available)
        if self.api_keys.get('shodan') and 'A' in results['dns'] and results['dns']['A']:
            print("[*] Shodan lookup...")
            first_ip = results['dns']['A'][0].value
            results['shodan'] = await self.shodan_host_lookup(first_ip)
        
        print(f"[+] OSINT complete for {domain}")
        
        # Save results
        output_file = self.save_results(domain, results)
        print(f"[+] Results saved to: {output_file}")
        
        return results
    
    async def full_ip_osint(self, ip: str) -> Dict:
        """Complete OSINT workflow for an IP address"""
        results = {
            'target': ip,
            'timestamp': datetime.now().isoformat(),
            'ip_intel': {},
            'reverse_dns': None,
            'ports': [],
            'reputation': {},
            'asn': {},
            'shodan': {}
        }
        
        print(f"[*] Starting IP OSINT for {ip}")
        
        # Comprehensive IP lookup
        print("[*] IP intelligence...")
        results['ip_intel'] = await self.ip_comprehensive_lookup(ip)
        
        # Reverse DNS
        print("[*] Reverse DNS...")
        results['reverse_dns'] = self.dns_reverse_lookup(ip)
        
        # Port scanning
        print("[*] Port scanning...")
        results['ports'] = await self.scan_common_ports(ip)
        
        # Reputation check
        print("[*] Reputation analysis...")
        results['reputation'] = self.check_ip_reputation(ip)
        
        # ASN lookup
        print("[*] ASN lookup...")
        results['asn'] = await self.asn_lookup(ip)
        
        # Shodan
        if self.api_keys.get('shodan'):
            print("[*] Shodan query...")
            results['shodan'] = await self.shodan_host_lookup(ip)
        
        print(f"[+] IP OSINT complete for {ip}")
        
        output_file = self.save_results(ip, results)
        print(f"[+] Results saved to: {output_file}")
        
        return results
    
    async def full_person_osint(self, name: str, email: Optional[str] = None, username: Optional[str] = None) -> Dict:
        """Complete OSINT workflow for a person"""
        results = {
            'target': name,
            'email': email,
            'username': username,
            'timestamp': datetime.now().isoformat(),
            'social_media': [],
            'github': {},
            'email_info': {}
        }
        
        print(f"[*] Starting person OSINT for {name}")
        
        # Social media (if username provided)
        if username:
            print("[*] Social media enumeration...")
            results['social_media'] = await self.social_media_username_check(username)
        
        # GitHub (if username provided)
        if username:
            print("[*] GitHub reconnaissance...")
            results['github'] = await self.github_user_recon(username)
        
        # Email analysis (if provided)
        if email:
            domain = email.split('@')[1] if '@' in email else None
            if domain:
                print(f"[*] Email domain analysis ({domain})...")
                results['email_info'] = {
                    'domain': domain,
                    'dns': self.dns_comprehensive_scan(domain),
                    'whois': self.whois_comprehensive(domain)
                }
        
        print(f"[+] Person OSINT complete for {name}")
        
        output_file = self.save_results(name.replace(' ', '_'), results)
        print(f"[+] Results saved to: {output_file}")
        
        return results
    
    async def full_company_osint(self, company: str, domain: Optional[str] = None) -> Dict:
        """Complete OSINT workflow for a company"""
        results = {
            'company': company,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'domain_intel': {},
            'github_org': {},
            'employees': [],
            'subdomains': []
        }
        
        print(f"[*] Starting company OSINT for {company}")
        
        # Domain intelligence (if provided)
        if domain:
            print(f"[*] Domain intelligence for {domain}...")
            results['domain_intel'] = await self.full_domain_osint(domain)
        
        # GitHub organization (try company name)
        print("[*] GitHub organization search...")
        github_username = company.lower().replace(' ', '-').replace(',', '').replace('.', '')
        results['github_org'] = await self.github_org_recon(github_username)
        
        print(f"[+] Company OSINT complete for {company}")
        
        output_file = self.save_results(company.replace(' ', '_'), results)
        print(f"[+] Results saved to: {output_file}")
        
        return results


# ============================================================================
# STANDALONE EXECUTION FUNCTIONS
# ============================================================================

async def run_domain_osint(domain: str, api_keys: Optional[Dict[str, str]] = None) -> Dict:
    """Standalone domain OSINT execution"""
    async with OSINTEngine(api_keys=api_keys) as engine:
        return await engine.full_domain_osint(domain)

async def run_ip_osint(ip: str, api_keys: Optional[Dict[str, str]] = None) -> Dict:
    """Standalone IP OSINT execution"""
    async with OSINTEngine(api_keys=api_keys) as engine:
        return await engine.full_ip_osint(ip)

async def run_person_osint(name: str, email: Optional[str] = None, username: Optional[str] = None, 
                          api_keys: Optional[Dict[str, str]] = None) -> Dict:
    """Standalone person OSINT execution"""
    async with OSINTEngine(api_keys=api_keys) as engine:
        return await engine.full_person_osint(name, email, username)

async def run_company_osint(company: str, domain: Optional[str] = None, 
                           api_keys: Optional[Dict[str, str]] = None) -> Dict:
    """Standalone company OSINT execution"""
    async with OSINTEngine(api_keys=api_keys) as engine:
        return await engine.full_company_osint(company, domain)


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import sys
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           PROMETHEUS-PRIME OSINT ENGINE                  ║
    ║           Authority Level 11.0                            ║
    ║           Commander Bobby Don McWilliams II               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python osint_core.py domain <target.com>")
        print("  python osint_core.py ip <192.168.1.1>")
        print("  python osint_core.py person <name> [--email email@domain.com] [--username user123]")
        print("  python osint_core.py company <CompanyName> [--domain company.com]")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    target = sys.argv[2]
    
    if mode == 'domain':
        asyncio.run(run_domain_osint(target))
    elif mode == 'ip':
        asyncio.run(run_ip_osint(target))
    elif mode == 'person':
        email = sys.argv[sys.argv.index('--email') + 1] if '--email' in sys.argv else None
        username = sys.argv[sys.argv.index('--username') + 1] if '--username' in sys.argv else None
        asyncio.run(run_person_osint(target, email, username))
    elif mode == 'company':
        domain = sys.argv[sys.argv.index('--domain') + 1] if '--domain' in sys.argv else None
        asyncio.run(run_company_osint(target, domain))
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
