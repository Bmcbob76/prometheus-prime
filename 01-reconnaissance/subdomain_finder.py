#!/usr/bin/env python3
"""
Subdomain Finder - Multi-source subdomain enumeration
For authorized penetration testing only
"""

import requests
import dns.resolver
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
import sys

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()

    def crt_sh(self):
        """Query crt.sh certificate transparency logs"""
        print(f"[*] Querying crt.sh for {self.domain}")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry['name_value']
                    if '\n' in name:
                        for subdomain in name.split('\n'):
                            self.subdomains.add(subdomain.strip())
                    else:
                        self.subdomains.add(name.strip())
                print(f"[+] Found {len(self.subdomains)} subdomains from crt.sh")
        except Exception as e:
            print(f"[-] Error querying crt.sh: {e}")

    def dns_bruteforce(self, wordlist_path):
        """Brute force subdomains using wordlist"""
        print(f"[*] Starting DNS brute force attack...")
        try:
            with open(wordlist_path, 'r') as f:
                subdomains_to_test = [line.strip() for line in f]

            def check_subdomain(sub):
                try:
                    full_domain = f"{sub}.{self.domain}"
                    dns.resolver.resolve(full_domain, 'A')
                    return full_domain
                except:
                    return None

            with ThreadPoolExecutor(max_workers=10) as executor:
                results = executor.map(check_subdomain, subdomains_to_test)
                for result in results:
                    if result:
                        self.subdomains.add(result)
                        print(f"[+] Found: {result}")
        except Exception as e:
            print(f"[-] Error in DNS brute force: {e}")

    def hackertarget_api(self):
        """Query HackerTarget API"""
        print(f"[*] Querying HackerTarget API...")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line and ',' in line:
                        subdomain = line.split(',')[0]
                        self.subdomains.add(subdomain)
        except Exception as e:
            print(f"[-] Error querying HackerTarget: {e}")

    def get_results(self):
        """Return unique subdomains"""
        return sorted(list(self.subdomains))

def main():
    parser = argparse.ArgumentParser(description='Multi-source subdomain enumeration')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Wordlist for brute force')
    parser.add_argument('-o', '--output', help='Output file')

    args = parser.parse_args()

    print(f"""
    ╔═══════════════════════════════════════╗
    ║   Subdomain Finder v1.0               ║
    ║   For Authorized Testing Only         ║
    ╚═══════════════════════════════════════╝
    """)

    finder = SubdomainFinder(args.domain)

    # Run all enumeration methods
    finder.crt_sh()
    finder.hackertarget_api()

    if args.wordlist:
        finder.dns_bruteforce(args.wordlist)

    results = finder.get_results()

    print(f"\n[+] Total unique subdomains found: {len(results)}")
    print("\n[+] Results:")
    for subdomain in results:
        print(f"  - {subdomain}")

    if args.output:
        with open(args.output, 'w') as f:
            for subdomain in results:
                f.write(f"{subdomain}\n")
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
