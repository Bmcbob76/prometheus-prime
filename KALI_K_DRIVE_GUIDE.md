# 🔱 KALI LINUX K: DRIVE CREATION GUIDE

**Authority:** 11.0 | **Commander:** Bobby Don McWilliams II  
**Mission:** Create 100GB K: drive for Kali Linux

---

## 📊 CURRENT DISK STATUS

**X: Drive (ECHO_PRIME_XV3):**
- Total: 781 GB
- Free: 713 GB
- Will shrink by: 100 GB
- Remaining after: 681 GB

**New K: Drive:**
- Size: 100 GB
- Label: KALI_LINUX
- Purpose: Full Kali Linux installation

---

## 💾 KALI LINUX SPACE BREAKDOWN

**100 GB Allocation:**
```
Kali Base Install:     20 GB
Tool Packages:         30 GB
Updates & Cache:       20 GB
Work Files/Exploits:   20 GB
Growth Buffer:         10 GB
─────────────────────────────
TOTAL:                100 GB
```

**Why 100GB?**
- ✅ Full Kali installation with all tools
- ✅ Room for Metasploit framework
- ✅ Custom exploit development
- ✅ Multiple Python environments
- ✅ Docker containers
- ✅ Updates for 1-2 years

---

## ⚡ EXECUTION STEPS

### Option 1: Automated Script (RECOMMENDED)

**Run as Administrator:**
```cmd
Right-click: C:\Temp\CREATE_KALI_DRIVE.bat
Select: "Run as administrator"
```

**What it does:**
1. Shrinks X: drive by 100 GB
2. Creates new partition
3. Formats as NTFS
4. Assigns K: drive letter
5. Labels as "KALI_LINUX"

---

### Option 2: Manual Diskpart

**Open Command Prompt as Administrator:**

```cmd
diskpart

# View current volumes
list volume

# Select X: drive
select volume X

# Shrink by 100 GB (102400 MB)
shrink desired=102400

# Create new partition
create partition primary

# Format with label
format fs=ntfs quick label="KALI_LINUX"

# Assign K: letter
assign letter=K

# Exit
exit
```

---

### Option 3: Disk Management GUI

1. **Open Disk Management:**
   - Press `Win + X`
   - Select "Disk Management"

2. **Shrink X: drive:**
   - Right-click X: drive
   - Select "Shrink Volume"
   - Enter: 102400 MB (100 GB)
   - Click "Shrink"

3. **Create K: drive:**
   - Right-click unallocated space
   - Select "New Simple Volume"
   - Assign letter: K
   - Format: NTFS
   - Label: KALI_LINUX

---

## 🔧 VERIFICATION

**After creation, verify:**

```powershell
# Check K: drive
Get-Volume K

# Expected output:
DriveLetter: K
FileSystemLabel: KALI_LINUX
Size: ~107374182400 (100 GB)
```

---

## 🐧 KALI LINUX INSTALLATION

### WSL2 Installation (Recommended)

**After K: drive creation:**

```powershell
# Install WSL2 if not already
wsl --install

# Install Kali from Microsoft Store
# Or command line:
wsl --install -d kali-linux

# Move installation to K: drive
wsl --export kali-linux K:\kali-backup.tar
wsl --unregister kali-linux
wsl --import kali-linux K:\kali-wsl K:\kali-backup.tar --version 2
```

### Dual Boot Installation

**If installing as dual boot:**
1. Create K: drive with this script
2. Download Kali ISO
3. Use Rufus to create bootable USB
4. Install Kali to K: drive partition
5. Update GRUB bootloader

---

## 📦 POST-INSTALLATION

**After Kali install on K:, run:**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Kali meta-packages
sudo apt install kali-linux-large -y

# Essential tools
sudo apt install metasploit-framework nmap burpsuite sqlmap -y

# Development tools
sudo apt install python3-pip docker.io -y

# Exploitation frameworks
sudo apt install exploitdb armitage -y
```

---

## 🎯 INTEGRATION WITH PROMETHEUS

**Link K: Kali with Prometheus Prime:**

```bash
# On Kali (K: drive)
mkdir -p /mnt/prometheus
sudo mount /dev/sda10 /mnt/prometheus  # Adjust device

# Or in WSL2
ln -s /mnt/p/ECHO_PRIME/prometheus_prime ~/prometheus
```

**Shared tools directory:**
```
K:\kali-tools\ ←→ P:\ECHO_PRIME\prometheus_prime\tools\
```

---

## 📁 RECOMMENDED K: STRUCTURE

```
K:\
├── kali-wsl\              # WSL2 installation
├── kali-tools\            # Custom tools
├── exploits\              # Exploit database
├── payloads\              # Custom payloads
├── wordlists\             # Password lists
├── captures\              # Packet captures
├── reports\               # Pentest reports
└── backups\               # System backups
```

---

## ⚠️ TROUBLESHOOTING

**"Access Denied" error:**
- Run script as Administrator
- Disable UAC temporarily
- Check X: drive isn't system drive

**"Not enough space" error:**
- Check X: has 100GB+ free
- Close all files on X:
- Disable page file on X: temporarily

**K: letter already in use:**
- Change to different letter (L:, M:, etc.)
- Edit script: `assign letter=L`

---

## 🔗 INTEGRATION PATHS

**Prometheus → Kali:**
```
P:\ECHO_PRIME\prometheus_prime\tools\  →  K:\kali-tools\
P:\ECHO_PRIME\prometheus_prime\exploits\  →  K:\exploits\
```

**Kali → Prometheus:**
```
K:\results\  →  P:\ECHO_PRIME\prometheus_prime\reports\
```

---

## ✅ EXECUTION CHECKLIST

- [ ] Verify 100GB+ free on X:
- [ ] Close all X: drive files
- [ ] Run CREATE_KALI_DRIVE.bat as Admin
- [ ] Verify K: drive created (100GB)
- [ ] Install Kali Linux (WSL2 or dual boot)
- [ ] Update Kali packages
- [ ] Install meta-packages
- [ ] Link with Prometheus Prime
- [ ] Configure shared directories
- [ ] Test integration

---

## 🎖️ READY TO EXECUTE

**Files Created:**
1. `C:\Temp\create_kali_drive.txt` - Diskpart commands
2. `C:\Temp\CREATE_KALI_DRIVE.bat` - Automated script

**To Create K: Drive:**
```cmd
Right-click: C:\Temp\CREATE_KALI_DRIVE.bat
Run as Administrator
```

**After K: creation:**
- Install Kali Linux via WSL2 or dual boot
- 100GB provides full arsenal + room for growth
- Integration with Prometheus Prime ready

---

**🔱 K: DRIVE READY FOR KALI LINUX DEPLOYMENT**

**Commander Bobby Don McWilliams II - Authority 11.0**
