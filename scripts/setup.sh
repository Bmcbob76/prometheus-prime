#!/bin/bash

# Prometheus Prime - Setup Script
# For authorized penetration testing lab environments only

echo "╔═══════════════════════════════════════════════════════╗"
echo "║       Prometheus Prime - Setup Script                ║"
echo "║       For Authorized Lab Environments Only            ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script should be run as root for full installation"
   echo "[!] Some tools may not install correctly"
   echo ""
fi

# Update system
echo "[*] Updating system packages..."
apt-get update -y > /dev/null 2>&1

# Essential tools
echo "[*] Installing essential penetration testing tools..."

# Network tools
apt-get install -y nmap masscan netcat-traditional socat dnsutils whois curl wget \
    tcpdump wireshark tshark arp-scan netdiscover > /dev/null 2>&1

# Web application tools
apt-get install -y nikto dirb gobuster wfuzz sqlmap burpsuite ffuf \
    wpscan whatweb wafw00f > /dev/null 2>&1

# Password attacks
apt-get install -y john hydra medusa hashcat hashid crunch cewl \
    wordlists > /dev/null 2>&1

# Exploitation
apt-get install -y metasploit-framework exploitdb searchsploit > /dev/null 2>&1

# Wireless
apt-get install -y aircrack-ng reaver wifite hostapd dnsmasq \
    kismet > /dev/null 2>&1

# Post-exploitation
apt-get install -y mimikatz impacket-scripts evil-winrm bloodhound > /dev/null 2>&1

# Programming languages
apt-get install -y python3 python3-pip golang ruby ruby-dev perl php > /dev/null 2>&1

# Misc tools
apt-get install -y git vim tmux screen proxychains tor steghide exiftool \
    binwalk foremost > /dev/null 2>&1

echo "[+] Essential tools installed"

# Python tools
echo "[*] Installing Python-based tools..."
pip3 install --upgrade pip > /dev/null 2>&1
pip3 install pwntools requests beautifulsoup4 scapy impacket > /dev/null 2>&1

echo "[+] Python tools installed"

# Create workspace directories
echo "[*] Creating workspace directories..."
mkdir -p ~/workspace/{recon,exploits,loot,notes,screenshots}
mkdir -p ~/tools
echo "[+] Workspace created at ~/workspace"

# Download common wordlists
echo "[*] Downloading wordlists..."
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "    - Extracting rockyou.txt..."
    gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || echo "    [!] rockyou.txt not found"
fi

# Install additional tools
echo "[*] Cloning additional tools..."

# SecLists
if [ ! -d ~/tools/SecLists ]; then
    echo "    - SecLists..."
    git clone https://github.com/danielmiessler/SecLists.git ~/tools/SecLists > /dev/null 2>&1
fi

# LinPEAS & WinPEAS
if [ ! -d ~/tools/PEASS-ng ]; then
    echo "    - PEASS (LinPEAS/WinPEAS)..."
    git clone https://github.com/carlospolop/PEASS-ng.git ~/tools/PEASS-ng > /dev/null 2>&1
fi

# PayloadsAllTheThings
if [ ! -d ~/tools/PayloadsAllTheThings ]; then
    echo "    - PayloadsAllTheThings..."
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git ~/tools/PayloadsAllTheThings > /dev/null 2>&1
fi

# AutoRecon
if [ ! -d ~/tools/AutoRecon ]; then
    echo "    - AutoRecon..."
    git clone https://github.com/Tib3rius/AutoRecon.git ~/tools/AutoRecon > /dev/null 2>&1
    cd ~/tools/AutoRecon && pip3 install -r requirements.txt > /dev/null 2>&1
    cd -
fi

echo "[+] Additional tools installed"

# Make scripts executable
echo "[*] Making Prometheus Prime scripts executable..."
find ./01-reconnaissance -name "*.py" -exec chmod +x {} \;
find ./03-web-application -name "*.py" -exec chmod +x {} \;

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║            Setup Complete!                            ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "[+] Tools installed successfully"
echo "[+] Workspace created at ~/workspace"
echo "[+] Additional tools in ~/tools"
echo ""
echo "[!] Remember: Only use these tools in authorized environments"
echo "[!] Always obtain written permission before testing"
echo ""
echo "Quick start:"
echo "  - Read the main README.md for documentation"
echo "  - Check cheatsheets/ for quick reference guides"
echo "  - Browse categories (01-reconnaissance, 03-web-application, etc.)"
echo ""
echo "Happy (ethical) hacking!"
