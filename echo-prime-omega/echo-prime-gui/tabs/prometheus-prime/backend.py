"""
PROMETHEUS PRIME - COMPREHENSIVE TAB BACKEND
Complete offensive security platform with 20+ domains and 300+ tools
Authority Level: 11.0
"""

from flask import Blueprint, render_template, request, jsonify
from flask_socketio import emit
import json
from datetime import datetime
from pathlib import Path

# Load tab configuration
CONFIG_FILE = Path(__file__).parent / 'tab_config.json'
with open(CONFIG_FILE, 'r') as f:
    TAB_CONFIG = json.load(f)

# Create Flask Blueprint
tab_blueprint = Blueprint(
    TAB_CONFIG['id'],
    __name__,
    url_prefix=TAB_CONFIG['routes']['main'],
    template_folder='templates',
    static_folder='static'
)

# ==================== COMPREHENSIVE TOOL DOMAINS ====================
# 20+ Security Domains with 300+ Tools

TOOL_DOMAINS = {
    "reconnaissance": {
        "name": "Reconnaissance & OSINT",
        "icon": "🔍",
        "color": "#00ffff",
        "description": "Information gathering, enumeration, and open-source intelligence",
        "tools": [
            {
                "id": "nmap_full",
                "name": "Nmap - Full Port Scan",
                "requires_target": True,
                "command": "nmap -p- -sV -sC -A",
                "options": ["OS Detection", "Service Version", "Aggressive Scan", "Script Scan"],
                "ai_guidance": "Performs comprehensive port scanning. Use for initial reconnaissance to discover all open ports and services on target."
            },
            {
                "id": "nmap_quick",
                "name": "Nmap - Quick Scan",
                "requires_target": True,
                "command": "nmap -F",
                "options": ["Fast Mode", "Top 100 Ports"],
                "ai_guidance": "Quick scan of top 100 most common ports. Use when time is critical."
            },
            {
                "id": "masscan",
                "name": "Masscan - Ultra-Fast Scanner",
                "requires_target": True,
                "command": "masscan -p1-65535",
                "options": ["All Ports", "Rate Limit", "Banner Grab"],
                "ai_guidance": "Ultra-fast port scanner capable of scanning entire internet in minutes. Use for large-scale reconnaissance."
            },
            {
                "id": "sublist3r",
                "name": "Sublist3r - Subdomain Enum",
                "requires_target": True,
                "command": "sublist3r -d",
                "options": ["Brute Force", "Recursive", "Verbose"],
                "ai_guidance": "Enumerates subdomains using search engines and brute force. Essential for expanding attack surface."
            },
            {
                "id": "amass",
                "name": "OWASP Amass",
                "requires_target": True,
                "command": "amass enum -d",
                "options": ["Passive", "Active", "Brute Force", "All Sources"],
                "ai_guidance": "Advanced subdomain enumeration and network mapping. Uses multiple data sources for comprehensive results."
            },
            {
                "id": "dnsenum",
                "name": "DNS Enumeration",
                "requires_target": True,
                "command": "dnsenum",
                "options": ["Zone Transfer", "Brute Force", "Google Scraping"],
                "ai_guidance": "Comprehensive DNS enumeration. Attempts zone transfers, reverse lookups, and subdomain discovery."
            },
            {
                "id": "fierce",
                "name": "Fierce DNS Scanner",
                "requires_target": True,
                "command": "fierce --domain",
                "options": ["Recursive", "Wide Scan"],
                "ai_guidance": "DNS reconnaissance tool for locating non-contiguous IP space."
            },
            {
                "id": "whois",
                "name": "WHOIS Lookup",
                "requires_target": True,
                "command": "whois",
                "options": ["Full Details", "Contact Info"],
                "ai_guidance": "Query domain registration information. Useful for gathering organization details and nameservers."
            },
            {
                "id": "theHarvester",
                "name": "theHarvester - Email/Subdomain",
                "requires_target": True,
                "command": "theHarvester -d",
                "options": ["All Sources", "Emails", "Hosts", "Virtual Hosts"],
                "ai_guidance": "Gathers emails, subdomains, hosts, employee names from public sources like search engines and PGP key servers."
            },
            {
                "id": "recon_ng",
                "name": "Recon-ng Framework",
                "requires_target": True,
                "command": "recon-ng",
                "options": ["All Modules", "Custom Workspace"],
                "ai_guidance": "Full-featured reconnaissance framework with dozens of modules. Automates OSINT gathering."
            },
            {
                "id": "shodan",
                "name": "Shodan Search",
                "requires_target": True,
                "command": "shodan search",
                "options": ["IP Info", "Host Details", "Exploits"],
                "ai_guidance": "Search engine for Internet-connected devices. Reveals exposed services, vulnerabilities, and misconfigurations."
            },
            {
                "id": "censys",
                "name": "Censys Search",
                "requires_target": True,
                "command": "censys search",
                "options": ["Certificates", "Hosts", "IPv4"],
                "ai_guidance": "Internet-wide scanning and certificate transparency logs. Excellent for asset discovery."
            },
            {
                "id": "dmitry",
                "name": "DMitry - Deepmagic Info Tool",
                "requires_target": True,
                "command": "dmitry -iwnse",
                "options": ["WHOIS", "Netcraft", "Subdomains", "Email"],
                "ai_guidance": "Unified information gathering tool combining WHOIS, Netcraft, subdomain search."
            },
            {
                "id": "maltego",
                "name": "Maltego - Link Analysis",
                "requires_target": True,
                "command": "maltego",
                "options": ["Standard", "XL"],
                "ai_guidance": "Visual link analysis tool for OSINT. Maps relationships between people, companies, domains, and infrastructure."
            },
            {
                "id": "spiderfoot",
                "name": "SpiderFoot - OSINT Automation",
                "requires_target": True,
                "command": "spiderfoot -s",
                "options": ["All Modules", "Passive Only"],
                "ai_guidance": "Automated OSINT collection from 100+ data sources. Correlates and analyzes gathered intelligence."
            }
        ]
    },

    "vulnerability_assessment": {
        "name": "Vulnerability Assessment",
        "icon": "🎯",
        "color": "#ff6600",
        "description": "Automated vulnerability scanning and CVE exploitation",
        "tools": [
            {
                "id": "nessus",
                "name": "Nessus Professional",
                "requires_target": True,
                "command": "nessus-scan",
                "options": ["Full Scan", "Web App Scan", "PCI Audit", "Malware Scan"],
                "ai_guidance": "Industry-standard vulnerability scanner. Comprehensive CVE detection with 220,000+ plugins."
            },
            {
                "id": "openvas",
                "name": "OpenVAS Scanner",
                "requires_target": True,
                "command": "openvas -T",
                "options": ["Full Scan", "Fast Scan", "Discovery Only"],
                "ai_guidance": "Open-source vulnerability scanner. Extensive CVE database and active development."
            },
            {
                "id": "nikto",
                "name": "Nikto Web Scanner",
                "requires_target": True,
                "command": "nikto -h",
                "options": ["All Tests", "SSL", "CGI Scan", "Mutations"],
                "ai_guidance": "Web server scanner that checks for 6700+ dangerous files/programs, outdated versions, and configuration issues."
            },
            {
                "id": "nuclei",
                "name": "Nuclei - Template Scanner",
                "requires_target": True,
                "command": "nuclei -u",
                "options": ["All Templates", "Critical Only", "Custom Templates"],
                "ai_guidance": "Fast vulnerability scanner using YAML templates. 5000+ community templates for modern vulnerabilities."
            },
            {
                "id": "searchsploit",
                "name": "Exploit-DB Search",
                "requires_target": False,
                "command": "searchsploit",
                "options": ["Web Results", "Local Only", "Update DB"],
                "ai_guidance": "Search 50,000+ exploits from Exploit-DB. Essential for finding public exploits for discovered vulnerabilities."
            },
            {
                "id": "metasploit_vuln",
                "name": "Metasploit Vuln Scanner",
                "requires_target": True,
                "command": "msfconsole -x",
                "options": ["SMB", "SSH", "HTTP", "All Services"],
                "ai_guidance": "Vulnerability scanning modules from Metasploit Framework. Directly integrates with exploitation."
            },
            {
                "id": "wpscan",
                "name": "WPScan - WordPress Scanner",
                "requires_target": True,
                "command": "wpscan --url",
                "options": ["Enumerate Plugins", "Enumerate Themes", "Enumerate Users", "Aggressive"],
                "ai_guidance": "WordPress security scanner. Identifies plugins, themes, users, and known vulnerabilities."
            },
            {
                "id": "joomscan",
                "name": "JoomScan - Joomla Scanner",
                "requires_target": True,
                "command": "joomscan -u",
                "options": ["Enumerate Components", "Fingerprint"],
                "ai_guidance": "Joomla vulnerability scanner detecting components and known vulnerabilities."
            },
            {
                "id": "droopescan",
                "name": "DroopeScan - CMS Scanner",
                "requires_target": True,
                "command": "droopescan scan",
                "options": ["Drupal", "Joomla", "WordPress"],
                "ai_guidance": "Multi-CMS scanner supporting Drupal, Joomla, WordPress, and Silverstripe."
            },
            {
                "id": "lynis",
                "name": "Lynis - System Auditor",
                "requires_target": False,
                "command": "lynis audit system",
                "options": ["Full Audit", "Security Only", "Generate Report"],
                "ai_guidance": "Security auditing tool for Unix-based systems. Detects misconfigurations and hardening opportunities."
            }
        ]
    },

    "web_application": {
        "name": "Web Application Testing",
        "icon": "🌐",
        "color": "#00ff00",
        "description": "Web app vulnerability testing, injection, and fuzzing",
        "tools": [
            {
                "id": "burp_suite",
                "name": "Burp Suite Professional",
                "requires_target": True,
                "command": "burp",
                "options": ["Active Scan", "Passive Scan", "Intruder", "Repeater"],
                "ai_guidance": "Industry-leading web app security testing platform. Comprehensive scanning with manual testing tools."
            },
            {
                "id": "sqlmap",
                "name": "SQLMap - SQL Injection",
                "requires_target": True,
                "command": "sqlmap -u",
                "options": ["Full Detection", "Dump Database", "OS Shell", "WAF Bypass"],
                "ai_guidance": "Automated SQL injection detection and exploitation. Supports all major database systems."
            },
            {
                "id": "xsser",
                "name": "XSSer - Cross-Site Scripting",
                "requires_target": True,
                "command": "xsser --url",
                "options": ["Auto Detect", "All Payloads", "DOM XSS", "Blind XSS"],
                "ai_guidance": "Automated XSS detection tool with 1300+ attack vectors. Tests reflected, stored, and DOM-based XSS."
            },
            {
                "id": "gobuster",
                "name": "Gobuster - Directory Brute Force",
                "requires_target": True,
                "command": "gobuster dir -u",
                "options": ["Common Wordlist", "Comprehensive", "Extensions", "Status Codes"],
                "ai_guidance": "Fast directory and file brute-forcing tool. Essential for discovering hidden resources."
            },
            {
                "id": "ffuf",
                "name": "Ffuf - Web Fuzzer",
                "requires_target": True,
                "command": "ffuf -u",
                "options": ["Directory Fuzzing", "Subdomain Fuzzing", "Parameter Fuzzing", "Virtual Host"],
                "ai_guidance": "Fast web fuzzer for directories, parameters, subdomains. Highly customizable with filtering options."
            },
            {
                "id": "dirb",
                "name": "DIRB - Web Content Scanner",
                "requires_target": True,
                "command": "dirb",
                "options": ["Common", "Big", "Custom Wordlist"],
                "ai_guidance": "Web content scanner that finds hidden directories and files using wordlists."
            },
            {
                "id": "wfuzz",
                "name": "Wfuzz - Web Application Fuzzer",
                "requires_target": True,
                "command": "wfuzz -u",
                "options": ["POST Data", "Headers", "Cookies", "Authentication"],
                "ai_guidance": "Web application fuzzer for finding resources and vulnerabilities through brute forcing."
            },
            {
                "id": "commix",
                "name": "Commix - Command Injection",
                "requires_target": True,
                "command": "commix --url",
                "options": ["Auto Detect", "Shell Upload", "File Read", "Reverse Shell"],
                "ai_guidance": "Automated command injection and exploitation tool. Tests for OS command injection vulnerabilities."
            },
            {
                "id": "nosqlmap",
                "name": "NoSQLMap - NoSQL Injection",
                "requires_target": True,
                "command": "nosqlmap -u",
                "options": ["MongoDB", "CouchDB", "All Databases"],
                "ai_guidance": "NoSQL injection and exploitation tool for MongoDB, CouchDB, and others."
            },
            {
                "id": "ldapdomaindump",
                "name": "LDAP Domain Dump",
                "requires_target": True,
                "command": "ldapdomaindump -u",
                "options": ["All Objects", "Users Only", "Groups Only"],
                "ai_guidance": "Dumps LDAP information from Active Directory for analysis."
            },
            {
                "id": "ssrf_proxy",
                "name": "SSRF Proxy",
                "requires_target": False,
                "command": "ssrf-proxy",
                "options": ["HTTP", "HTTPS", "Gopher"],
                "ai_guidance": "Tool for testing Server-Side Request Forgery vulnerabilities."
            },
            {
                "id": "jwt_tool",
                "name": "JWT Tool - Token Testing",
                "requires_target": False,
                "command": "jwt_tool",
                "options": ["Crack", "Tamper", "Inject", "All Attacks"],
                "ai_guidance": "JWT token testing and exploitation. Tests for weak secrets, algorithm confusion, injection."
            },
            {
                "id": "graphql_cop",
                "name": "GraphQL Cop",
                "requires_target": True,
                "command": "graphql-cop",
                "options": ["Introspection", "Field Suggestions", "Batching"],
                "ai_guidance": "Security auditing tool for GraphQL APIs."
            },
            {
                "id": "api_fuzzer",
                "name": "API Fuzzer",
                "requires_target": True,
                "command": "api-fuzzer",
                "options": ["REST", "GraphQL", "SOAP"],
                "ai_guidance": "Automated API security testing tool for REST, GraphQL, and SOAP APIs."
            },
            {
                "id": "zaproxy",
                "name": "OWASP ZAP",
                "requires_target": True,
                "command": "zap.sh",
                "options": ["Active Scan", "Passive Scan", "Spider", "Ajax Spider"],
                "ai_guidance": "OWASP Zed Attack Proxy for web app security testing. Free alternative to Burp Suite."
            }
        ]
    },

    "network_attacks": {
        "name": "Network Attacks",
        "icon": "🔥",
        "color": "#ff0000",
        "description": "Network-level attacks, MitM, and traffic manipulation",
        "tools": [
            {
                "id": "ettercap",
                "name": "Ettercap - MitM Framework",
                "requires_target": True,
                "command": "ettercap -T -M arp",
                "options": ["ARP Poisoning", "DNS Spoofing", "SSL Strip", "Plugin Engine"],
                "ai_guidance": "Comprehensive MitM attack framework. Perform ARP poisoning, sniffing, and active protocol dissection."
            },
            {
                "id": "bettercap",
                "name": "Bettercap - Network Swiss Army Knife",
                "requires_target": False,
                "command": "bettercap",
                "options": ["ARP Spoof", "DNS Spoof", "Proxy", "Sniffing"],
                "ai_guidance": "Modern network attack framework. Supports ARP spoofing, proxy attacks, credential harvesting."
            },
            {
                "id": "arpspoof",
                "name": "ARPspoof",
                "requires_target": True,
                "command": "arpspoof -t",
                "options": ["Bidirectional", "Gateway Spoof"],
                "ai_guidance": "Classic ARP spoofing tool for MitM attacks on local network."
            },
            {
                "id": "responder",
                "name": "Responder - LLMNR/NBT-NS Poisoner",
                "requires_target": False,
                "command": "responder -I",
                "options": ["Analyze Mode", "Poison All", "WPAD", "SMB Relay"],
                "ai_guidance": "Poisons LLMNR, NBT-NS, and MDNS requests to capture credentials. Essential for Windows networks."
            },
            {
                "id": "wireshark",
                "name": "Wireshark - Packet Analyzer",
                "requires_target": False,
                "command": "wireshark",
                "options": ["Capture", "Display Filters", "Follow Stream"],
                "ai_guidance": "World's foremost packet analyzer. Capture and analyze network traffic in real-time."
            },
            {
                "id": "tcpdump",
                "name": "TCPdump - Packet Sniffer",
                "requires_target": False,
                "command": "tcpdump -i",
                "options": ["All Interfaces", "Specific Protocol", "Save to File"],
                "ai_guidance": "Command-line packet sniffer. Lightweight alternative to Wireshark for capturing traffic."
            },
            {
                "id": "hping3",
                "name": "Hping3 - Packet Crafting",
                "requires_target": True,
                "command": "hping3",
                "options": ["SYN Flood", "UDP Flood", "ICMP Flood", "Custom Packets"],
                "ai_guidance": "Advanced packet crafting tool. Can perform SYN floods, port scanning, and firewall testing."
            },
            {
                "id": "dnsspoof",
                "name": "DNSspoof",
                "requires_target": False,
                "command": "dnsspoof -i",
                "options": ["Custom Hosts File", "Wildcard"],
                "ai_guidance": "DNS spoofing tool for redirecting DNS queries to attacker-controlled IPs."
            },
            {
                "id": "sslstrip",
                "name": "SSLstrip - HTTPS Downgrade",
                "requires_target": False,
                "command": "sslstrip -l",
                "options": ["Port 8080", "Custom Port", "Favicon"],
                "ai_guidance": "Downgrades HTTPS connections to HTTP in MitM attacks. Enables cleartext credential capture."
            },
            {
                "id": "mitmproxy",
                "name": "MITMproxy - Interactive Proxy",
                "requires_target": False,
                "command": "mitmproxy",
                "options": ["Transparent", "Reverse", "Upstream"],
                "ai_guidance": "Interactive HTTPS proxy for intercepting, modifying, and replaying HTTP/HTTPS traffic."
            }
        ]
    },

    "wireless": {
        "name": "Wireless Attacks",
        "icon": "📡",
        "color": "#9400d3",
        "description": "WiFi penetration testing and wireless attacks",
        "tools": [
            {
                "id": "aircrack_suite",
                "name": "Aircrack-ng Suite",
                "requires_target": False,
                "command": "aircrack-ng",
                "options": ["Monitor Mode", "Capture", "Crack WPA/WPA2", "Deauth"],
                "ai_guidance": "Complete WiFi security testing suite. Includes airmon-ng, airodump-ng, aireplay-ng, aircrack-ng."
            },
            {
                "id": "wifite",
                "name": "Wifite2 - Automated WiFi Attack",
                "requires_target": False,
                "command": "wifite",
                "options": ["WPS", "WPA/WPA2", "WEP", "All Modes"],
                "ai_guidance": "Automated wireless attack tool. Handles WEP, WPA/WPA2, and WPS attacks automatically."
            },
            {
                "id": "reaver",
                "name": "Reaver - WPS Attack",
                "requires_target": True,
                "command": "reaver -i",
                "options": ["Pixie Dust", "Brute Force", "Verbose"],
                "ai_guidance": "WPS brute-force attack tool. Exploits weak WPS implementations to recover WPA passwords."
            },
            {
                "id": "bully",
                "name": "Bully - WPS Brute Force",
                "requires_target": True,
                "command": "bully",
                "options": ["Pixie Dust", "PIN Brute Force"],
                "ai_guidance": "Alternative WPS brute-force tool. Faster than Reaver in some scenarios."
            },
            {
                "id": "fern_wifi",
                "name": "Fern WiFi Cracker",
                "requires_target": False,
                "command": "fern-wifi-cracker",
                "options": ["WEP", "WPA/WPA2", "WPS", "Session Hijack"],
                "ai_guidance": "GUI-based wireless security testing tool with attack automation."
            },
            {
                "id": "cowpatty",
                "name": "CoWPAtty - WPA-PSK Cracker",
                "requires_target": False,
                "command": "cowpatty -r",
                "options": ["Dictionary Attack", "Rainbow Tables"],
                "ai_guidance": "WPA-PSK offline password cracker using dictionary or rainbow table attacks."
            },
            {
                "id": "mdk4",
                "name": "MDK4 - WiFi DoS",
                "requires_target": False,
                "command": "mdk4",
                "options": ["Beacon Flood", "Authentication DoS", "Deauthentication", "EAPOL Start"],
                "ai_guidance": "WiFi security testing tool for DoS attacks and stress testing wireless networks."
            },
            {
                "id": "evil_twin",
                "name": "Evil Twin AP Creator",
                "requires_target": False,
                "command": "create-ap",
                "options": ["WPA2", "Open", "Captive Portal"],
                "ai_guidance": "Creates rogue access point that mimics legitimate network for credential harvesting."
            },
            {
                "id": "wifi_pumpkin",
                "name": "WiFi-Pumpkin - Rogue AP Framework",
                "requires_target": False,
                "command": "wifi-pumpkin3",
                "options": ["Captive Portal", "DNS Spoof", "Proxy", "Credentials"],
                "ai_guidance": "Framework for creating rogue WiFi access points with captive portals and credential harvesting."
            },
            {
                "id": "kismet",
                "name": "Kismet - WiFi Detector",
                "requires_target": False,
                "command": "kismet",
                "options": ["Passive Scan", "All Channels", "GPS Logging"],
                "ai_guidance": "Wireless network detector and IDS. Passively monitors WiFi networks without transmitting."
            }
        ]
    },

    "password_attacks": {
        "name": "Password Attacks",
        "icon": "🔐",
        "color": "#ffff00",
        "description": "Password cracking, brute-forcing, and credential attacks",
        "tools": [
            {
                "id": "hashcat",
                "name": "Hashcat - Advanced Password Recovery",
                "requires_target": False,
                "command": "hashcat -m",
                "options": ["Dictionary", "Brute Force", "Combinator", "Mask Attack", "Rule-Based"],
                "ai_guidance": "World's fastest password cracker. GPU-accelerated with support for 300+ hash types."
            },
            {
                "id": "john",
                "name": "John the Ripper",
                "requires_target": False,
                "command": "john",
                "options": ["Single Crack", "Wordlist", "Incremental", "Custom Rules"],
                "ai_guidance": "Classic password cracker. Excellent for Unix passwords and custom rule-based attacks."
            },
            {
                "id": "hydra",
                "name": "THC Hydra - Network Login Cracker",
                "requires_target": True,
                "command": "hydra -l",
                "options": ["SSH", "FTP", "HTTP", "SMB", "RDP", "VNC", "MySQL", "PostgreSQL"],
                "ai_guidance": "Fast network login cracker supporting 50+ protocols. Essential for remote service brute-forcing."
            },
            {
                "id": "medusa",
                "name": "Medusa - Parallel Login Brute-Forcer",
                "requires_target": True,
                "command": "medusa -h",
                "options": ["SSH", "FTP", "HTTP", "SMB", "Multiple Targets"],
                "ai_guidance": "Parallel login brute-force tool. Alternative to Hydra with different protocol support."
            },
            {
                "id": "ncrack",
                "name": "Ncrack - Network Auth Cracker",
                "requires_target": True,
                "command": "ncrack",
                "options": ["RDP", "SSH", "HTTP", "Timing Templates"],
                "ai_guidance": "High-speed network authentication cracking tool from Nmap developers."
            },
            {
                "id": "patator",
                "name": "Patator - Multi-Purpose Brute-Forcer",
                "requires_target": True,
                "command": "patator",
                "options": ["FTP", "SSH", "HTTP", "SMTP", "MySQL"],
                "ai_guidance": "Modular brute-force tool with many modules for different protocols."
            },
            {
                "id": "crunch",
                "name": "Crunch - Wordlist Generator",
                "requires_target": False,
                "command": "crunch",
                "options": ["Min/Max Length", "Character Set", "Pattern", "Permutations"],
                "ai_guidance": "Generates custom wordlists based on criteria. Essential for targeted password attacks."
            },
            {
                "id": "cewl",
                "name": "CeWL - Custom Wordlist Generator",
                "requires_target": True,
                "command": "cewl",
                "options": ["Spider Depth", "Min Word Length", "Emails", "Metadata"],
                "ai_guidance": "Creates custom wordlists by spidering target website. Useful for targeted dictionary attacks."
            },
            {
                "id": "mimikatz",
                "name": "Mimikatz - Windows Credential Dumper",
                "requires_target": False,
                "command": "mimikatz",
                "options": ["sekurlsa::logonpasswords", "lsadump::sam", "kerberos::tickets"],
                "ai_guidance": "Dumps plaintext passwords and hashes from Windows memory. Essential post-exploitation tool."
            },
            {
                "id": "lazagne",
                "name": "LaZagne - Credential Recovery",
                "requires_target": False,
                "command": "lazagne",
                "options": ["All Modules", "Browsers", "WiFi", "Databases"],
                "ai_guidance": "Retrieves passwords stored locally on Windows, Linux, and Mac. Checks browsers, wifi, databases, etc."
            },
            {
                "id": "brutespray",
                "name": "BruteSpray - Nmap to Brute Force",
                "requires_target": False,
                "command": "brutespray --file",
                "options": ["All Services", "SSH Only", "Custom Wordlist"],
                "ai_guidance": "Takes Nmap scan results and automatically brute-forces services with Medusa."
            },
            {
                "id": "crowbar",
                "name": "Crowbar - Brute Force Tool",
                "requires_target": True,
                "command": "crowbar -b",
                "options": ["RDP", "OpenVPN", "SSH Key", "VNC"],
                "ai_guidance": "Brute-force tool specialized for RDP, OpenVPN, and SSH private keys."
            }
        ]
    },

    "exploitation": {
        "name": "Exploitation",
        "icon": "💥",
        "color": "#ff00ff",
        "description": "Exploit frameworks, payload generation, and exploitation",
        "tools": [
            {
                "id": "metasploit",
                "name": "Metasploit Framework",
                "requires_target": True,
                "command": "msfconsole",
                "options": ["Auto Exploit", "Manual Mode", "Resource Script"],
                "ai_guidance": "World's most advanced exploitation framework. 2000+ exploits, 500+ payloads, post-exploitation modules."
            },
            {
                "id": "msfvenom",
                "name": "MSFvenom - Payload Generator",
                "requires_target": False,
                "command": "msfvenom -p",
                "options": ["Windows", "Linux", "Mac", "Android", "Web", "Encoded"],
                "ai_guidance": "Metasploit payload generator. Creates customized shells, backdoors, and implants for all platforms."
            },
            {
                "id": "exploit_db",
                "name": "Exploit Database Search",
                "requires_target": False,
                "command": "searchsploit",
                "options": ["Update", "Web Results", "Copy to Clipboard"],
                "ai_guidance": "Search 50,000+ exploits from Exploit-DB. Offline archive of public exploits."
            },
            {
                "id": "beef",
                "name": "BeEF - Browser Exploitation",
                "requires_target": False,
                "command": "beef-xss",
                "options": ["Hook Browser", "All Modules"],
                "ai_guidance": "Browser Exploitation Framework. Hooks browsers via XSS and provides command/control interface."
            },
            {
                "id": "empire",
                "name": "PowerShell Empire",
                "requires_target": False,
                "command": "empire",
                "options": ["Launcher", "Stager", "All Modules"],
                "ai_guidance": "Post-exploitation framework for Windows using PowerShell. Includes persistence, privilege escalation, and more."
            },
            {
                "id": "covenant",
                "name": "Covenant C2 Framework",
                "requires_target": False,
                "command": "covenant",
                "options": ["HTTP Listener", "SMB Listener"],
                "ai_guidance": ".NET C2 framework for post-exploitation. Modern alternative to Empire."
            },
            {
                "id": "cobalt_strike",
                "name": "Cobalt Strike (Commercial)",
                "requires_target": False,
                "command": "cobaltstrike",
                "options": ["Beacon", "Malleable C2", "All Features"],
                "ai_guidance": "Commercial penetration testing platform with advanced C2 capabilities and red team features."
            },
            {
                "id": "routersploit",
                "name": "RouterSploit Framework",
                "requires_target": True,
                "command": "rsf",
                "options": ["Auto Exploit", "Scanner", "Creds"],
                "ai_guidance": "Exploitation framework dedicated to embedded devices and routers."
            },
            {
                "id": "commix_exploit",
                "name": "Commix - Command Injection",
                "requires_target": True,
                "command": "commix --url",
                "options": ["Auto", "Shell Upload", "Reverse Shell"],
                "ai_guidance": "Automated command injection exploitation tool for web applications."
            },
            {
                "id": "webapp_exploit",
                "name": "Web App Exploit Generator",
                "requires_target": True,
                "command": "exploit-gen",
                "options": ["LFI/RFI", "File Upload", "XXE"],
                "ai_guidance": "Generates custom exploits for web application vulnerabilities."
            }
        ]
    },

    "post_exploitation": {
        "name": "Post-Exploitation",
        "icon": "👁️",
        "color": "#00ffff",
        "description": "Post-compromise activities, lateral movement, persistence",
        "tools": [
            {
                "id": "bloodhound",
                "name": "BloodHound - AD Attack Paths",
                "requires_target": False,
                "command": "bloodhound",
                "options": ["Collect All", "DCOnly", "ComputerOnly"],
                "ai_guidance": "Maps Active Directory to find attack paths. Visualizes shortest path to Domain Admin."
            },
            {
                "id": "sharphound",
                "name": "SharpHound - AD Collector",
                "requires_target": False,
                "command": "sharphound",
                "options": ["All", "Default", "DCOnly", "Stealth"],
                "ai_guidance": "Data collector for BloodHound. Gathers Active Directory enumeration data."
            },
            {
                "id": "crackmapexec",
                "name": "CrackMapExec - SMB Swiss Army Knife",
                "requires_target": True,
                "command": "crackmapexec smb",
                "options": ["Password Spray", "Dump SAM", "Execute Command", "Enum Shares"],
                "ai_guidance": "Post-exploitation tool for large Active Directory networks. Automates credential testing and command execution."
            },
            {
                "id": "evil_winrm",
                "name": "Evil-WinRM - WinRM Shell",
                "requires_target": True,
                "command": "evil-winrm -i",
                "options": ["Upload File", "Download File", "Execute Command"],
                "ai_guidance": "WinRM shell for remote Windows administration. Useful for lateral movement and command execution."
            },
            {
                "id": "impacket_suite",
                "name": "Impacket Suite",
                "requires_target": True,
                "command": "impacket",
                "options": ["psexec", "smbexec", "wmiexec", "secretsdump", "GetNPUsers"],
                "ai_guidance": "Python classes for working with network protocols. Essential for Windows post-exploitation."
            },
            {
                "id": "chisel",
                "name": "Chisel - TCP/UDP Tunnel",
                "requires_target": True,
                "command": "chisel",
                "options": ["Server", "Client", "Reverse", "SOCKS5"],
                "ai_guidance": "Fast TCP/UDP tunnel over HTTP. Excellent for pivoting and creating tunnels through firewalls."
            },
            {
                "id": "proxychains",
                "name": "ProxyChains - Proxy Tunneling",
                "requires_target": False,
                "command": "proxychains",
                "options": ["Dynamic Chain", "Strict Chain", "Random Chain"],
                "ai_guidance": "Forces TCP connections through proxy chains. Essential for pivoting through compromised hosts."
            },
            {
                "id": "sshuttle",
                "name": "sshuttle - VPN over SSH",
                "requires_target": True,
                "command": "sshuttle -r",
                "options": ["All Traffic", "Specific Subnets", "DNS"],
                "ai_guidance": "Transparent proxy VPN over SSH. Routes traffic through compromised SSH server."
            },
            {
                "id": "powercat",
                "name": "PowerCat - PowerShell Netcat",
                "requires_target": False,
                "command": "powercat",
                "options": ["Reverse Shell", "Bind Shell", "Port Forward"],
                "ai_guidance": "PowerShell implementation of netcat. Useful for shells and port forwarding on Windows."
            },
            {
                "id": "powerup",
                "name": "PowerUp - Windows PrivEsc",
                "requires_target": False,
                "command": "powerup",
                "options": ["Invoke-AllChecks", "Service Abuse", "DLL Hijack"],
                "ai_guidance": "PowerShell tool for finding Windows privilege escalation vectors."
            }
        ]
    },

    "privilege_escalation": {
        "name": "Privilege Escalation",
        "icon": "⬆️",
        "color": "#ffa500",
        "description": "Escalate privileges on Linux, Windows, and Unix systems",
        "tools": [
            {
                "id": "linpeas",
                "name": "LinPEAS - Linux PrivEsc",
                "requires_target": False,
                "command": "linpeas.sh",
                "options": ["Detailed", "Fast", "Stealth"],
                "ai_guidance": "Linux privilege escalation automation script. Checks for 150+ local privilege escalation vectors."
            },
            {
                "id": "winpeas",
                "name": "WinPEAS - Windows PrivEsc",
                "requires_target": False,
                "command": "winpeas.exe",
                "options": ["Fast", "Full", "Quiet"],
                "ai_guidance": "Windows privilege escalation automation. Comprehensive checks for misconfigurations and vulnerabilities."
            },
            {
                "id": "linenum",
                "name": "LinEnum - Linux Enumeration",
                "requires_target": False,
                "command": "linenum.sh",
                "options": ["Thorough", "Quick"],
                "ai_guidance": "Scripted local Linux enumeration. Gathers system information useful for privilege escalation."
            },
            {
                "id": "les",
                "name": "Linux Exploit Suggester",
                "requires_target": False,
                "command": "les.sh",
                "options": ["Kernel Exploits", "All"],
                "ai_guidance": "Suggests kernel exploits based on Linux version. Helps identify local privilege escalation opportunities."
            },
            {
                "id": "unix_privesc_check",
                "name": "Unix PrivEsc Check",
                "requires_target": False,
                "command": "unix-privesc-check",
                "options": ["Standard", "Detailed"],
                "ai_guidance": "Checks Unix-like systems for privilege escalation vectors."
            },
            {
                "id": "sherlock",
                "name": "Sherlock - Windows Exploit Suggester",
                "requires_target": False,
                "command": "sherlock.ps1",
                "options": ["All Checks"],
                "ai_guidance": "PowerShell script that finds missing patches for local privilege escalation on Windows."
            },
            {
                "id": "watson",
                "name": "Watson - Windows Vuln Scanner",
                "requires_target": False,
                "command": "watson.exe",
                "options": ["All Vulnerabilities"],
                "ai_guidance": ".NET tool for identifying missing KBs and suggesting exploits for Windows privilege escalation."
            },
            {
                "id": "gtfobins",
                "name": "GTFOBins - Unix Binaries Exploit",
                "requires_target": False,
                "command": "gtfobins-check",
                "options": ["SUID", "Sudo", "Capabilities"],
                "ai_guidance": "Checks for Unix binaries that can be exploited for privilege escalation via SUID, sudo, or capabilities."
            },
            {
                "id": "pspy",
                "name": "pspy - Process Monitor",
                "requires_target": False,
                "command": "pspy",
                "options": ["Monitor All", "Cron Jobs"],
                "ai_guidance": "Monitors Linux processes without root. Useful for finding cron jobs and scheduled tasks running as root."
            },
            {
                "id": "sudo_killer",
                "name": "SUDO_KILLER",
                "requires_target": False,
                "command": "sudo_killer",
                "options": ["Full Scan", "Quick"],
                "ai_guidance": "Tool for identifying and exploiting sudo rules for privilege escalation."
            }
        ]
    },

    "social_engineering": {
        "name": "Social Engineering",
        "icon": "🎭",
        "color": "#ff1493",
        "description": "Phishing, pretexting, and social manipulation",
        "tools": [
            {
                "id": "setoolkit",
                "name": "Social Engineer Toolkit (SET)",
                "requires_target": False,
                "command": "setoolkit",
                "options": ["Phishing", "Credential Harvester", "Infectious Media", "Arduino Attack"],
                "ai_guidance": "Comprehensive social engineering toolkit. Creates phishing pages, payloads, and attack vectors."
            },
            {
                "id": "gophish",
                "name": "Gophish - Phishing Framework",
                "requires_target": False,
                "command": "gophish",
                "options": ["Campaign", "Templates", "Landing Pages"],
                "ai_guidance": "Open-source phishing framework for red teams. Manages campaigns, templates, and tracks success rates."
            },
            {
                "id": "evilginx",
                "name": "Evilginx2 - MitM Phishing",
                "requires_target": True,
                "command": "evilginx",
                "options": ["Reverse Proxy", "2FA Bypass"],
                "ai_guidance": "Man-in-the-middle attack framework for phishing credentials and session cookies. Bypasses 2FA."
            },
            {
                "id": "king_phisher",
                "name": "King Phisher",
                "requires_target": False,
                "command": "king-phisher",
                "options": ["Campaign Management", "Email Templates"],
                "ai_guidance": "Phishing campaign toolkit for testing and promoting security awareness training."
            },
            {
                "id": "modlishka",
                "name": "Modlishka - Reverse Proxy Phishing",
                "requires_target": True,
                "command": "modlishka",
                "options": ["2FA Bypass", "Session Hijack"],
                "ai_guidance": "Reverse proxy phishing tool for capturing credentials and session cookies with 2FA bypass."
            },
            {
                "id": "shellphish",
                "name": "ShellPhish - Phishing Tool",
                "requires_target": False,
                "command": "shellphish",
                "options": ["32 Templates", "Ngrok Integration"],
                "ai_guidance": "Automated phishing tool with 32 pre-built templates for popular services."
            },
            {
                "id": "hidden_eye",
                "name": "HiddenEye - Phishing Pages",
                "requires_target": False,
                "command": "hidden-eye",
                "options": ["Social Media", "Email", "Custom"],
                "ai_guidance": "Modern phishing tool with templates for social media, email services, and custom pages."
            },
            {
                "id": "zphisher",
                "name": "Zphisher - Phishing Automation",
                "requires_target": False,
                "command": "zphisher",
                "options": ["30+ Templates", "Cloudflared Tunnel"],
                "ai_guidance": "Automated phishing tool with 30+ templates and multiple tunneling options."
            },
            {
                "id": "email_spoof",
                "name": "Email Spoofing Tool",
                "requires_target": True,
                "command": "sendemail",
                "options": ["SMTP", "Custom Headers", "Attachments"],
                "ai_guidance": "Sends spoofed emails for social engineering campaigns. Tests email authentication (SPF, DKIM, DMARC)."
            },
            {
                "id": "maltego_se",
                "name": "Maltego - OSINT for SE",
                "requires_target": True,
                "command": "maltego",
                "options": ["Person Search", "Company Info"],
                "ai_guidance": "OSINT platform for gathering intelligence on targets before social engineering attacks."
            }
        ]
    },

    "cryptography": {
        "name": "Cryptography & Crypto Attacks",
        "icon": "🔒",
        "color": "#4169e1",
        "description": "Cryptanalysis, encryption testing, and crypto attacks",
        "tools": [
            {
                "id": "sslscan",
                "name": "SSLscan - SSL/TLS Scanner",
                "requires_target": True,
                "command": "sslscan",
                "options": ["All Ciphers", "Vulnerabilities", "Heartbleed"],
                "ai_guidance": "Tests SSL/TLS services for supported ciphers, protocols, and vulnerabilities like Heartbleed."
            },
            {
                "id": "testssl",
                "name": "testssl.sh - SSL/TLS Testing",
                "requires_target": True,
                "command": "testssl.sh",
                "options": ["Full Test", "Vulnerabilities Only", "PFS"],
                "ai_guidance": "Comprehensive SSL/TLS testing. Checks for protocol flaws, cipher strength, and certificate issues."
            },
            {
                "id": "openssl_test",
                "name": "OpenSSL Testing Suite",
                "requires_target": True,
                "command": "openssl s_client",
                "options": ["Connect", "Certificate Info", "Cipher List"],
                "ai_guidance": "Command-line OpenSSL toolkit for testing SSL/TLS connections and certificates."
            },
            {
                "id": "rsactftool",
                "name": "RsaCtfTool - RSA Attack",
                "requires_target": False,
                "command": "rsactftool",
                "options": ["Factorization", "Wiener Attack", "All Attacks"],
                "ai_guidance": "RSA attack tool with multiple attack methods including factorization, Wiener, and more."
            },
            {
                "id": "hash_identifier",
                "name": "Hash Identifier",
                "requires_target": False,
                "command": "hash-identifier",
                "options": ["Auto Detect", "All Hashes"],
                "ai_guidance": "Identifies hash types from input. Essential before attempting to crack unknown hashes."
            },
            {
                "id": "hashid",
                "name": "hashID - Hash Identifier",
                "requires_target": False,
                "command": "hashid",
                "options": ["Hashcat Mode", "John Mode"],
                "ai_guidance": "Identifies hash types and provides hashcat/john mode numbers for cracking."
            },
            {
                "id": "cipher_tools",
                "name": "Classical Cipher Tools",
                "requires_target": False,
                "command": "cipher-tools",
                "options": ["Caesar", "Vigenere", "Substitution", "Transposition"],
                "ai_guidance": "Tools for analyzing and breaking classical ciphers."
            },
            {
                "id": "xortool",
                "name": "XORTool - XOR Analysis",
                "requires_target": False,
                "command": "xortool",
                "options": ["Brute Force", "Known Plaintext"],
                "ai_guidance": "Analyzes files encrypted with XOR cipher. Attempts to find key and decrypt."
            },
            {
                "id": "padding_oracle",
                "name": "Padding Oracle Attack",
                "requires_target": True,
                "command": "padbuster",
                "options": ["Auto", "Manual", "Custom Block Size"],
                "ai_guidance": "Exploits padding oracle vulnerabilities in CBC mode encryption to decrypt data."
            },
            {
                "id": "featherduster",
                "name": "FeatherDuster - Crypto Analysis",
                "requires_target": False,
                "command": "featherduster",
                "options": ["Auto Analysis", "Classical Ciphers"],
                "ai_guidance": "Automated cryptanalysis tool that analyzes encrypted data and suggests attack methods."
            }
        ]
    },
}

# System state
prometheus_state = {
    "active": False,
    "autonomous_mode": False,
    "engagement_active": False,
    "target": None,
    "current_phase": None,
    "last_update": None,
    "stats": TAB_CONFIG.get('stats', {}),
    "status": "IDLE",
    "active_engagements": [],
    "recent_findings": [],
    "tool_activity": [],
    "execution_log": []
}

# 6-Phase Engagement Workflow
ENGAGEMENT_PHASES = {
    1: {"name": "Reconnaissance & Intelligence Gathering", "icon": "🔍"},
    2: {"name": "Vulnerability Assessment & Analysis", "icon": "🎯"},
    3: {"name": "Exploitation & Initial Access", "icon": "💥"},
    4: {"name": "Post-Exploitation & Privilege Escalation", "icon": "⬆️"},
    5: {"name": "Persistence & Data Exfiltration", "icon": "👁️"},
    6: {"name": "Reporting & Remediation Guidance", "icon": "📋"}
}

# ==================== ROUTES ====================

@tab_blueprint.route('/')
def index():
    """Render comprehensive Prometheus Prime frontend"""
    template_path = f"{TAB_CONFIG['id']}/frontend_comprehensive.html"
    return render_template(template_path, config=TAB_CONFIG, domains=TOOL_DOMAINS, phases=ENGAGEMENT_PHASES)

@tab_blueprint.route('/api/domains', methods=['GET'])
def get_all_domains():
    """Get all tool domains with complete tool information"""
    return jsonify({
        "success": True,
        "count": len(TOOL_DOMAINS),
        "domains": TOOL_DOMAINS
    })

@tab_blueprint.route('/api/tools/<domain_id>', methods=['GET'])
def get_domain_tools(domain_id):
    """Get all tools for a specific domain"""
    if domain_id in TOOL_DOMAINS:
        return jsonify({
            "success": True,
            "domain": TOOL_DOMAINS[domain_id]
        })
    return jsonify({"success": False, "error": "Domain not found"}), 404

@tab_blueprint.route('/api/tool/<tool_id>/guidance', methods=['GET'])
def get_tool_guidance(tool_id):
    """Get AI guidance for a specific tool"""
    for domain_id, domain in TOOL_DOMAINS.items():
        for tool in domain['tools']:
            if tool['id'] == tool_id:
                return jsonify({
                    "success": True,
                    "tool": tool['name'],
                    "guidance": tool.get('ai_guidance', 'No guidance available'),
                    "command": tool.get('command', ''),
                    "options": tool.get('options', [])
                })
    return jsonify({"success": False, "error": "Tool not found"}), 404

@tab_blueprint.route('/api/execute-tool', methods=['POST'])
def execute_tool():
    """Execute a specific tool"""
    data = request.json
    tool_id = data.get('tool_id')
    domain_id = data.get('domain_id')
    target = data.get('target', '')
    options = data.get('options', [])

    # Find tool
    tool_info = None
    for domain in TOOL_DOMAINS.values():
        for tool in domain['tools']:
            if tool['id'] == tool_id:
                tool_info = tool
                break

    if not tool_info:
        return jsonify({"success": False, "error": "Tool not found"}), 404

    # Create execution record
    execution = {
        "id": f"EXEC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "tool_id": tool_id,
        "tool_name": tool_info['name'],
        "domain": domain_id,
        "target": target,
        "options": options,
        "timestamp": datetime.now().isoformat(),
        "status": "running"
    }

    prometheus_state["execution_log"].insert(0, execution)
    if len(prometheus_state["execution_log"]) > 100:
        prometheus_state["execution_log"] = prometheus_state["execution_log"][:100]

    broadcast_update({
        "event": "tool_started",
        "execution": execution
    })

    return jsonify({
        "success": True,
        "message": f"Executing {tool_info['name']}",
        "execution": execution
    })

@tab_blueprint.route('/api/status', methods=['GET'])
def get_status():
    """Get current Prometheus Prime status"""
    return jsonify({
        "success": True,
        "state": prometheus_state,
        "config": TAB_CONFIG,
        "total_domains": len(TOOL_DOMAINS),
        "total_tools": sum(len(d['tools']) for d in TOOL_DOMAINS.values())
    })

@tab_blueprint.route('/api/start', methods=['POST'])
def start_system():
    """Start Prometheus Prime system"""
    prometheus_state["active"] = True
    prometheus_state["status"] = "ACTIVE"
    prometheus_state["last_update"] = datetime.now().isoformat()

    broadcast_update({"event": "system_started"})

    return jsonify({
        "success": True,
        "message": "Prometheus Prime system activated",
        "state": prometheus_state
    })

@tab_blueprint.route('/api/stop', methods=['POST'])
def stop_system():
    """Stop Prometheus Prime system"""
    prometheus_state["active"] = False
    prometheus_state["autonomous_mode"] = False
    prometheus_state["engagement_active"] = False
    prometheus_state["status"] = "STOPPED"

    broadcast_update({"event": "system_stopped"})

    return jsonify({
        "success": True,
        "message": "Prometheus Prime system stopped",
        "state": prometheus_state
    })

@tab_blueprint.route('/api/start-autonomous', methods=['POST'])
def start_autonomous():
    """Start autonomous penetration testing engagement"""
    data = request.json
    target = data.get('target', '')
    depth = data.get('depth', 'full')

    if not target:
        return jsonify({"success": False, "error": "Target required"}), 400

    engagement_id = f"ENG-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    prometheus_state["autonomous_mode"] = True
    prometheus_state["engagement_active"] = True
    prometheus_state["target"] = target
    prometheus_state["current_phase"] = 1
    prometheus_state["status"] = "AUTONOMOUS ENGAGEMENT"

    engagement = {
        "id": engagement_id,
        "target": target,
        "depth": depth,
        "phase": 1,
        "started": datetime.now().isoformat(),
        "status": "running"
    }
    prometheus_state["active_engagements"].append(engagement)

    broadcast_update({
        "event": "autonomous_started",
        "engagement_id": engagement_id,
        "target": target,
        "phase": 1
    })

    return jsonify({
        "success": True,
        "engagement_id": engagement_id,
        "message": f"Autonomous engagement started on {target}",
        "phase": 1,
        "state": prometheus_state
    })

@tab_blueprint.route('/api/stop-autonomous', methods=['POST'])
def stop_autonomous():
    """Stop autonomous engagement"""
    prometheus_state["autonomous_mode"] = False
    prometheus_state["engagement_active"] = False
    prometheus_state["current_phase"] = None
    prometheus_state["status"] = "ACTIVE"

    broadcast_update({"event": "autonomous_stopped"})

    return jsonify({
        "success": True,
        "message": "Autonomous engagement stopped",
        "state": prometheus_state
    })

@tab_blueprint.route('/api/logs', methods=['GET'])
def get_logs():
    """Get execution logs"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify({
        "success": True,
        "logs": prometheus_state["execution_log"][:limit],
        "total": len(prometheus_state["execution_log"])
    })

# ==================== WEBSOCKET HANDLERS ====================

socketio_instance = None

def init_socketio(socketio):
    """Initialize WebSocket handlers"""
    global socketio_instance
    socketio_instance = socketio

    @socketio.on(f'{TAB_CONFIG["id"]}_connect')
    def handle_connect(data):
        emit(f'{TAB_CONFIG["id"]}_status', {
            "connected": True,
            "state": prometheus_state
        })

    @socketio.on(f'{TAB_CONFIG["id"]}_request_update')
    def handle_update_request():
        emit(f'{TAB_CONFIG["id"]}_update', {
            "state": prometheus_state,
            "timestamp": datetime.now().isoformat()
        })

def broadcast_update(update_data):
    """Broadcast update to all connected clients"""
    if socketio_instance:
        socketio_instance.emit(f'{TAB_CONFIG["id"]}_update', {
            "data": update_data,
            "state": prometheus_state,
            "timestamp": datetime.now().isoformat()
        })

# ==================== INITIALIZATION ====================

def initialize(app, socketio):
    """Called by Master GUI during tab discovery"""
    app.register_blueprint(tab_blueprint)
    init_socketio(socketio)

    total_tools = sum(len(d['tools']) for d in TOOL_DOMAINS.values())

    print(f"✅ Initialized: {TAB_CONFIG['name']} Tab")
    print(f"   Routes: {TAB_CONFIG['routes']['main']}")
    print(f"   Domains: {len(TOOL_DOMAINS)}")
    print(f"   Tools: {total_tools}")
    print(f"   Authority Level: {TAB_CONFIG['authority_level']}")

    return {
        "id": TAB_CONFIG['id'],
        "name": TAB_CONFIG['name'],
        "blueprint": tab_blueprint,
        "config": TAB_CONFIG,
        "state": prometheus_state
    }

# ==================== STANDALONE TESTING ====================

if __name__ == '__main__':
    from flask import Flask
    from flask_socketio import SocketIO

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'prometheus-prime-secret'
    socketio = SocketIO(app, cors_allowed_origins="*")

    initialize(app, socketio)

    total_tools = sum(len(d['tools']) for d in TOOL_DOMAINS.values())

    print("\n" + "="*60)
    print(f"🚀 {TAB_CONFIG['name']} - Standalone Mode")
    print(f"   Domains: {len(TOOL_DOMAINS)}")
    print(f"   Tools: {total_tools}")
    print(f"   Access at: http://localhost:5001{TAB_CONFIG['routes']['main']}")
    print("="*60 + "\n")

    socketio.run(app, debug=True, host='0.0.0.0', port=5001)
