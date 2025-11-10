#!/usr/bin/env python3
"""
Multi-threaded Port Scanner with Service Detection
For authorized penetration testing only
"""

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import sys

# Common service banners
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT",
    27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle", 161: "SNMP"
}

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, timeout=1):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []

    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = COMMON_PORTS.get(port, "UNKNOWN")
                banner = self.grab_banner(sock, port)
                self.open_ports.append((port, service, banner))
                print(f"[+] Port {port:5d} OPEN - {service:15s} {banner}")

            sock.close()
        except socket.gaierror:
            print("[-] Hostname could not be resolved")
            sys.exit()
        except socket.error:
            pass
        except KeyboardInterrupt:
            print("\n[-] Scan cancelled by user")
            sys.exit()

    def grab_banner(self, sock, port):
        """Attempt to grab service banner"""
        try:
            if port in [80, 8080, 443, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: target\r\n\r\n')
            else:
                sock.send(b'\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:50] if banner else ""
        except:
            return ""

    def scan(self):
        """Execute the port scan"""
        print(f"""
╔═══════════════════════════════════════════════════════╗
║            Multi-Threaded Port Scanner                ║
║          For Authorized Testing Only                  ║
╚═══════════════════════════════════════════════════════╝

[*] Target: {self.target}
[*] Port Range: {self.start_port}-{self.end_port}
[*] Threads: {self.threads}
[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """)

        try:
            # Resolve hostname
            ip = socket.gethostbyname(self.target)
            print(f"[*] Resolved {self.target} to {ip}\n")

            # Scan ports
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                ports = range(self.start_port, self.end_port + 1)
                executor.map(self.scan_port, ports)

            print(f"\n[*] Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"[+] Found {len(self.open_ports)} open ports\n")

            if self.open_ports:
                print("=" * 70)
                print(f"{'PORT':<10} {'SERVICE':<20} {'BANNER'}")
                print("=" * 70)
                for port, service, banner in sorted(self.open_ports):
                    print(f"{port:<10} {service:<20} {banner[:40]}")

        except KeyboardInterrupt:
            print("\n[-] Scan cancelled by user")
            sys.exit()
        except Exception as e:
            print(f"[-] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Multi-threaded port scanner with service detection')
    parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    parser.add_argument('-s', '--start', type=int, default=1, help='Start port (default: 1)')
    parser.add_argument('-e', '--end', type=int, default=1024, help='End port (default: 1024)')
    parser.add_argument('-T', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Socket timeout in seconds (default: 1)')

    args = parser.parse_args()

    scanner = PortScanner(
        target=args.target,
        start_port=args.start,
        end_port=args.end,
        threads=args.threads,
        timeout=args.timeout
    )
    scanner.scan()

if __name__ == "__main__":
    main()
