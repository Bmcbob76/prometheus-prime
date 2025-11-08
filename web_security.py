#!/usr/bin/env python3
"""
🌐 WEB SECURITY MODULE  
Web application security testing and vulnerability scanning
Authority Level: 11.0
"""

import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Dict, Any, List
import re
import json

class WebSecurity:
    """Web application security scanner"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Prometheus-Prime-Scanner/2.0'
        })
        print("🌐 Web Security Module initialized")
    
    def security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'Referrer-Policy': response.headers.get('Referrer-Policy'),
                'Permissions-Policy': response.headers.get('Permissions-Policy')
            }
            
            missing = [k for k, v in security_headers.items() if v is None]
            
            return {
                'url': url,
                'headers': security_headers,
                'missing_headers': missing,
                'security_score': int((7 - len(missing)) / 7 * 100),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def sql_injection_test(self, url: str, param: str = 'id') -> Dict[str, Any]:
        """Basic SQL injection detection"""
        payloads = [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "admin'--", "admin' #", "admin'/*",
            "' or 1=1--", "' or 1=1#", "' or 1=1/*"
        ]
        
        vulnerable = []
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Check for SQL error messages
                sql_errors = [
                    'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                    'SQLServer', 'Microsoft SQL', 'ODBC', 'sqlite'
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        vulnerable.append({
                            'payload': payload,
                            'error_found': error,
                            'vulnerable': True
                        })
                        break
            except:
                pass
        
        return {
            'url': url,
            'parameter': param,
            'vulnerable': len(vulnerable) > 0,
            'findings': vulnerable,
            'timestamp': datetime.now().isoformat()
        }
    
    def xss_test(self, url: str, param: str = 'search') -> Dict[str, Any]:
        """Cross-site scripting detection"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'>"
        ]
        
        vulnerable = []
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Check if payload is reflected without encoding
                if payload in response.text or payload.replace("'", '"') in response.text:
                    vulnerable.append({
                        'payload': payload,
                        'reflected': True,
                        'vulnerable': True
                    })
            except:
                pass
        
        return {
            'url': url,
            'parameter': param,
            'vulnerable': len(vulnerable) > 0,
            'findings': vulnerable,
            'timestamp': datetime.now().isoformat()
        }
    
    def directory_bruteforce(self, base_url: str, wordlist: List[str] = None) -> Dict[str, Any]:
        """Directory and file enumeration"""
        if wordlist is None:
            wordlist = [
                'admin', 'login', 'wp-admin', 'phpmyadmin',
                'backup', 'config', 'test', 'api', 'uploads',
                '.git', '.env', '.htaccess', 'robots.txt', 'sitemap.xml'
            ]
        
        found = []
        
        for path in wordlist:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=3, verify=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    found.append({
                        'path': path,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
            except:
                pass
        
        return {
            'base_url': base_url,
            'paths_tested': len(wordlist),
            'found': found,
            'count': len(found),
            'timestamp': datetime.now().isoformat()
        }
    
    def subdomain_enum(self, domain: str, wordlist: List[str] = None) -> Dict[str, Any]:
        """Subdomain enumeration"""
        if wordlist is None:
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test',
                'staging', 'blog', 'shop', 'portal', 'vpn', 'remote'
            ]
        
        found = []
        
        for sub in wordlist:
            try:
                test_domain = f"{sub}.{domain}"
                response = self.session.get(f"http://{test_domain}", timeout=3, verify=False)
                
                if response.status_code < 400:
                    found.append({
                        'subdomain': test_domain,
                        'status': response.status_code,
                        'title': self._extract_title(response.text)
                    })
            except:
                pass
        
        return {
            'domain': domain,
            'subdomains_tested': len(wordlist),
            'found': found,
            'count': len(found),
            'timestamp': datetime.now().isoformat()
        }
    
    def crawl_links(self, url: str, max_depth: int = 2) -> Dict[str, Any]:
        """Web crawler to discover links"""
        visited = set()
        to_visit = [(url, 0)]
        links = []
        
        while to_visit and len(visited) < 100:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            visited.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=5, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = urljoin(current_url, link['href'])
                    
                    if urlparse(href).netloc == urlparse(url).netloc:
                        links.append(href)
                        if href not in visited:
                            to_visit.append((href, depth + 1))
            except:
                pass
        
        return {
            'start_url': url,
            'links_found': list(set(links)),
            'count': len(set(links)),
            'pages_crawled': len(visited),
            'timestamp': datetime.now().isoformat()
        }
    
    def ssl_scan(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """SSL/TLS security analysis"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        'hostname': hostname,
                        'port': port,
                        'cipher': cipher,
                        'protocol': version,
                        'certificate': {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'notBefore': cert['notBefore'],
                            'notAfter': cert['notAfter']
                        },
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def technology_detection(self, url: str) -> Dict[str, Any]:
        """Detect web technologies used"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            technologies = {
                'server': response.headers.get('Server'),
                'x_powered_by': response.headers.get('X-Powered-By'),
                'frameworks': [],
                'cms': [],
                'javascript_libs': []
            }
            
            content = response.text.lower()
            
            # Framework detection
            framework_patterns = {
                'Django': 'django',
                'Rails': 'rails',
                'Laravel': 'laravel',
                'Express': 'express',
                'Flask': 'flask',
                'ASP.NET': 'asp.net'
            }
            
            for name, pattern in framework_patterns.items():
                if pattern in content:
                    technologies['frameworks'].append(name)
            
            # CMS detection
            cms_patterns = {
                'WordPress': 'wp-content',
                'Joomla': 'joomla',
                'Drupal': 'drupal',
                'Magento': 'magento',
                'Shopify': 'shopify'
            }
            
            for name, pattern in cms_patterns.items():
                if pattern in content:
                    technologies['cms'].append(name)
            
            # JavaScript library detection
            js_patterns = {
                'jQuery': 'jquery',
                'React': 'react',
                'Angular': 'angular',
                'Vue': 'vue.js',
                'Bootstrap': 'bootstrap'
            }
            
            for name, pattern in js_patterns.items():
                if pattern in content:
                    technologies['javascript_libs'].append(name)
            
            return {
                'url': url,
                'technologies': technologies,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.string if title else 'No title'
        except:
            return 'Unknown'
    
    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        """Complete web security assessment"""
        print(f"🔍 Comprehensive web security scan: {url}")
        
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'scans': {}
        }
        
        # Security headers
        print("   📋 Checking security headers...")
        results['scans']['security_headers'] = self.security_headers(url)
        
        # Technology detection
        print("   🔧 Detecting technologies...")
        results['scans']['technologies'] = self.technology_detection(url)
        
        # Directory enumeration
        print("   📁 Enumerating directories...")
        results['scans']['directories'] = self.directory_bruteforce(url)
        
        # Crawl links
        print("   🕸️ Crawling site...")
        results['scans']['links'] = self.crawl_links(url, max_depth=1)
        
        # SSL scan
        if url.startswith('https://'):
            print("   🔒 Analyzing SSL/TLS...")
            hostname = urlparse(url).netloc
            results['scans']['ssl'] = self.ssl_scan(hostname)
        
        print("✅ Comprehensive scan complete")
        return results


def main():
    """Test web security tools"""
    ws = WebSecurity()
    
    url = input("Enter target URL: ").strip()
    
    if not url:
        print("❌ URL required")
        return
    
    print("\n1. Security Headers")
    print("2. SQL Injection Test")
    print("3. XSS Test")
    print("4. Directory Bruteforce")
    print("5. Technology Detection")
    print("6. Comprehensive Scan")
    
    choice = input("\nSelect scan type: ").strip()
    
    if choice == '1':
        result = ws.security_headers(url)
        print(json.dumps(result, indent=2))
    elif choice == '2':
        result = ws.sql_injection_test(url)
        print(json.dumps(result, indent=2))
    elif choice == '3':
        result = ws.xss_test(url)
        print(json.dumps(result, indent=2))
    elif choice == '4':
        result = ws.directory_bruteforce(url)
        print(json.dumps(result, indent=2))
    elif choice == '5':
        result = ws.technology_detection(url)
        print(json.dumps(result, indent=2))
    elif choice == '6':
        result = ws.comprehensive_scan(url)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
