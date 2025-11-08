# Reconnaissance & OSINT

## Overview

Reconnaissance is the first phase of penetration testing, involving gathering information about the target system, network, or organization.

## Types of Reconnaissance

### 1. Passive Reconnaissance
Information gathering without directly interacting with the target.

### 2. Active Reconnaissance
Direct interaction with target systems to gather information.

---

## Passive Reconnaissance Techniques

### OSINT (Open Source Intelligence)

#### Search Engines
```bash
# Google Dorks
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql OR ext:conf
site:target.com intext:"password" OR intext:"username"

# Shodan
shodan search "hostname:target.com"
shodan search "org:Target Corp"
shodan search "ssl:target.com"

# Censys
censys search "target.com"
```

#### WHOIS Lookup
```bash
whois target.com
whois -h whois.arin.net target.com
```

#### DNS Reconnaissance
```bash
# DNS enumeration
dig target.com ANY
dig @8.8.8.8 target.com
dig target.com mx
dig target.com ns
dig target.com txt
dig -x <IP_ADDRESS>  # Reverse DNS

# Zone transfer attempt
dig axfr @ns1.target.com target.com

# Subdomain enumeration
dnsrecon -d target.com
fierce --domain target.com
```

#### Email Harvesting
```bash
# theHarvester
theharvester -d target.com -b all

# Hunter.io (API)
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY"

# Manually
# Check LinkedIn, company websites, GitHub, pastebin
```

#### Social Media OSINT
```
# Tools
- Maltego
- SpiderFoot
- Recon-ng
- sherlock (username search across platforms)

# Manual
- LinkedIn (employees, job postings)
- Twitter (company accounts, employee tweets)
- Facebook (company pages)
- Instagram (geo-tags, employee posts)
```

#### Subdomain Enumeration
```bash
# Sublist3r
sublist3r -d target.com

# Amass
amass enum -d target.com

# Assetfinder
assetfinder --subs-only target.com

# Subfinder
subfinder -d target.com

# Certificate transparency logs
curl "https://crt.sh/?q=%.target.com&output=json" | jq .

# GitHub subdomain discovery
python3 github-subdomains.py -t TOKEN -d target.com
```

#### Website Reconnaissance
```bash
# Wayback Machine
curl "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=json"

# BuiltWith
builtwith target.com

# WhatWeb
whatweb target.com

# Wappalyzer (browser extension)
```

#### Metadata Extraction
```bash
# ExifTool
exiftool document.pdf
exiftool image.jpg

# FOCA (Windows)
# Extracts metadata from documents

# Metagoofil
metagoofil -d target.com -t pdf,doc,xls,ppt,docx,xlsx,pptx -l 100
```

---

## Active Reconnaissance

### Port Scanning
```bash
# Nmap - Basic scans
nmap target.com
nmap -p- target.com                    # All ports
nmap -p 1-65535 target.com
nmap -sV target.com                    # Service version detection
nmap -O target.com                     # OS detection
nmap -A target.com                     # Aggressive scan

# Nmap - Stealth scans
nmap -sS target.com                    # SYN scan
nmap -sN target.com                    # NULL scan
nmap -sF target.com                    # FIN scan
nmap -sX target.com                    # Xmas scan

# Nmap - Timing and performance
nmap -T4 target.com                    # Faster scan
nmap -T0 target.com                    # Paranoid (IDS evasion)

# Nmap - Output
nmap -oA scan_results target.com       # All formats
nmap -oN normal.txt target.com         # Normal output
nmap -oX xml.xml target.com            # XML output
nmap -oG greppable.txt target.com      # Greppable

# Masscan
masscan -p1-65535 target.com --rate=1000

# Unicornscan
unicornscan -mU target.com:1-65535
```

### Service Enumeration
```bash
# Banner grabbing
nc -v target.com 80
telnet target.com 80
curl -I target.com

# Nmap scripts
nmap --script=banner target.com
nmap --script=default target.com
nmap --script=vuln target.com
nmap --script=http-enum target.com
```

### Web Application Discovery
```bash
# Directory brute forcing
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
dirb http://target.com
dirsearch -u http://target.com -e php,html,js
ffuf -u http://target.com/FUZZ -w wordlist.txt

# Nikto
nikto -h http://target.com

# WPScan (WordPress)
wpscan --url http://target.com --enumerate ap,at,u

# Joomscan (Joomla)
joomscan -u http://target.com
```

### Network Mapping
```bash
# Traceroute
traceroute target.com
traceroute -I target.com  # ICMP
traceroute -T target.com  # TCP

# Network topology discovery
nmap -sn 192.168.1.0/24   # Ping scan

# ARP scanning (local network)
arp-scan -l
netdiscover -r 192.168.1.0/24
```

---

## OSINT Tools

### Automated Frameworks
```bash
# Recon-ng
recon-ng
marketplace search
marketplace install all
workspaces create target_company
db insert domains
modules search

# theHarvester
theharvester -d target.com -b google,bing,yahoo,linkedin

# SpiderFoot
spiderfoot -s target.com

# Maltego
# GUI-based OSINT tool

# OSINT Framework
https://osintframework.com/
```

### Email & Credential Search
```bash
# Have I Been Pwned
curl https://haveibeenpwned.com/api/v3/breachedaccount/email@target.com

# DeHashed
# Search for leaked credentials

# Pastebin monitoring
# Check for leaked data
```

### GitHub Reconnaissance
```bash
# GitDorker
python3 GitDorker.py -tf TOKENSFILE -d target.com

# Gitrob
gitrob analyze target_org

# TruffleHog
trufflehog --regex --entropy=False https://github.com/target/repo

# Search for secrets
git-secrets --scan
gitleaks detect
```

---

## Cloud Asset Discovery

### AWS
```bash
# S3 bucket enumeration
aws s3 ls s3://target-bucket --no-sign-request
s3scanner scan --bucket target

# CloudFront
dig target.com
# Look for cloudfront.net in CNAME
```

### Azure
```bash
# Azure blob enumeration
az storage blob list --account-name targetaccount

# MicroBurst (PowerShell)
Invoke-EnumerateAzureBlobs -Base target
```

### GCP
```bash
# Google Cloud Storage
gsutil ls gs://target-bucket

# GCP bucket finder
python3 cloud_enum.py -k target
```

---

## Wireless Reconnaissance

```bash
# WiFi scanning
airodump-ng wlan0mon

# Bluetooth discovery
hcitool scan
bluetoothctl scan on

# RFID/NFC
proxmark3
```

---

## Physical Reconnaissance

- Building layout observation
- Security camera locations
- Entry/exit points
- Badge types
- Security guard schedules
- Dumpster diving
- Tailgating opportunities

---

## Reconnaissance Scripts

See `scripts/recon/` directory for automation scripts:
- `auto_recon.sh` - Automated reconnaissance pipeline
- `subdomain_enum.sh` - Comprehensive subdomain enumeration
- `osint_gather.py` - OSINT data aggregator
- `port_scan_parse.py` - Parse and analyze nmap results

---

## Tips & Best Practices

1. **Document Everything** - Keep detailed notes of all findings
2. **Use Multiple Sources** - Cross-reference information
3. **Respect Rate Limits** - Don't overwhelm targets or services
4. **Legal Boundaries** - Stay within scope of authorization
5. **Operational Security** - Use VPNs, proxies when appropriate
6. **Automate** - Use scripts for repetitive tasks
7. **Stay Updated** - Tools and techniques evolve constantly

---

## Common Reconnaissance Workflow

1. **Passive Information Gathering**
   - WHOIS lookups
   - DNS enumeration
   - Search engine reconnaissance
   - Social media OSINT

2. **Active Information Gathering**
   - Port scanning
   - Service enumeration
   - Network mapping
   - Web application discovery

3. **Analysis & Documentation**
   - Organize findings
   - Identify attack surface
   - Prioritize targets
   - Create attack plan

---

## Further Reading

- OWASP Testing Guide - Information Gathering
- PTES Technical Guidelines - Intelligence Gathering
- NIST SP 800-115 - Technical Guide to Information Security Testing
