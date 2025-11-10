# 🏗️ ECHO PRIME INSTALLER - BUILD IMPLEMENTATION PLAN

**Goal:** Create single-file installer matching Adobe/Microsoft production standards
**Timeline:** 2-3 weeks
**Result:** `ECHO_PRIME_Setup.exe` - One-click installation of complete system

---

## 📋 PHASE 1: REPOSITORY CONSOLIDATION (Week 1)

### **Step 1.1: Create Main ECHO_PRIME Repository**

```bash
# Create new repository structure
mkdir ECHO_PRIME
cd ECHO_PRIME
git init

# Create directory structure
mkdir -p {core,agents,mcp-servers,memory,ekm,voice,security,runtime,docs,tools}
```

### **Step 1.2: Integrate Existing Repositories**

```bash
# Add Prometheus Prime as submodule
git submodule add https://github.com/Bmcbob76/prometheus-prime agents/prometheus-prime

# Or merge directly into monorepo
cp -r P:\ECHO_PRIME\prometheus_prime\prometheus-prime agents/prometheus-prime

# Copy MLS Launcher
cp -r P:\ECHO_PRIME\MLS_CLEAN\PRODUCTION core/mls

# Copy ECHO PRIME GUI
cp -r P:\ECHO_PRIME\ECHO_PRIMEGUI core/gui

# Copy all MCP servers
cp -r P:\ECHO_PRIME\MCP_SERVERS mcp-servers/

# Copy memory system
cp -r M:\MEMORY_ORCHESTRATION memory/orchestrator
cp -r M:\MEMORY_ORCHESTRATION\schema memory/schema
# Copy only samples, not all crystals
cp -r M:\MEMORY_ORCHESTRATION\samples memory/samples

# Copy EKM system
cp -r [EKM_PATH]\generator ekm/generator
cp -r [EKM_PATH]\schema ekm/schema
cp -r [EKM_PATH]\samples ekm/samples

# Copy voice systems
cp -r P:\ECHO_PRIME\voice voice/
```

### **Step 1.3: Create .gitignore**

```gitignore
# User data (not in installer)
**/CRYSTALS_TIER_*/
**/CRYSTALS_NEW/
**/EKMS/storage/
**/vault_data/
**/.env

# Large external datasets
L:/exploitdb/
**/BEEF/modules/
**/Orange-cyberdefense/

# Build artifacts
dist/
build/
node_modules/
*.pyc
__pycache__/

# OS files
.DS_Store
Thumbs.db
```

---

## 📦 PHASE 2: INSTALLER FRAMEWORK SETUP (Week 1)

### **Step 2.1: Initialize Electron Project**

Create `package.json`:

```json
{
  "name": "echo-prime",
  "version": "4.0.0",
  "description": "ECHO PRIME - Complete AI Intelligence Platform",
  "main": "core/gui/main.js",
  "author": "Commander Bob",
  "license": "Proprietary",
  "homepage": "https://echo-prime.ai",

  "scripts": {
    "start": "electron .",
    "dev": "electron . --dev",
    "build": "electron-builder",
    "build:win": "electron-builder --win",
    "build:mac": "electron-builder --mac",
    "build:linux": "electron-builder --linux",
    "build:all": "electron-builder -wml",
    "postinstall": "electron-builder install-app-deps",
    "pack": "electron-builder --dir",
    "dist": "electron-builder"
  },

  "dependencies": {
    "electron-updater": "^6.1.7",
    "better-sqlite3": "^9.2.2",
    "axios": "^1.6.0"
  },

  "devDependencies": {
    "electron": "^28.0.0",
    "electron-builder": "^24.9.1",
    "electron-windows-sign": "^1.0.0"
  },

  "build": {
    "appId": "ai.echo-prime.desktop",
    "productName": "ECHO PRIME",
    "copyright": "Copyright © 2025 Commander Bob",
    "compression": "maximum",
    "asar": true,

    "directories": {
      "output": "dist",
      "buildResources": "build"
    },

    "files": [
      "core/**/*",
      "agents/**/*",
      "mcp-servers/**/*",
      "memory/**/*",
      "ekm/**/*",
      "voice/**/*",
      "security/**/*",
      "docs/**/*",
      "tools/**/*",
      "!**/*.md",
      "!**/samples/**"
    ],

    "extraResources": [
      {
        "from": "runtime/python",
        "to": "runtime/python",
        "filter": ["**/*"]
      },
      {
        "from": "runtime/node",
        "to": "runtime/node",
        "filter": ["**/*"]
      },
      {
        "from": "docs",
        "to": "docs"
      }
    ],

    "win": {
      "target": [
        {
          "target": "nsis",
          "arch": ["x64"]
        }
      ],
      "icon": "build/icon.ico",
      "requestedExecutionLevel": "asInvoker",
      "sign": "./build/sign-windows.js",
      "publisherName": "ECHO PRIME AI",
      "verifyUpdateCodeSignature": false
    },

    "nsis": {
      "oneClick": false,
      "perMachine": false,
      "allowElevation": true,
      "allowToChangeInstallationDirectory": true,
      "installerIcon": "build/installer-icon.ico",
      "uninstallerIcon": "build/uninstaller-icon.ico",
      "installerHeaderIcon": "build/header-icon.ico",
      "createDesktopShortcut": true,
      "createStartMenuShortcut": true,
      "shortcutName": "ECHO PRIME",
      "runAfterFinish": true,
      "deleteAppDataOnUninstall": false,
      "license": "LICENSE.txt",
      "artifactName": "ECHO_PRIME_Setup_${version}.${ext}",

      "include": "build/installer-script.nsh",

      "warningsAsErrors": false
    },

    "mac": {
      "target": ["dmg"],
      "icon": "build/icon.icns",
      "category": "public.app-category.developer-tools",
      "hardenedRuntime": true,
      "gatekeeperAssess": false,
      "entitlements": "build/entitlements.mac.plist",
      "entitlementsInherit": "build/entitlements.mac.plist"
    },

    "dmg": {
      "title": "ECHO PRIME ${version}",
      "icon": "build/volume-icon.icns",
      "background": "build/dmg-background.png",
      "window": {
        "width": 600,
        "height": 400
      },
      "contents": [
        {
          "x": 150,
          "y": 200,
          "type": "file"
        },
        {
          "x": 450,
          "y": 200,
          "type": "link",
          "path": "/Applications"
        }
      ]
    },

    "linux": {
      "target": ["AppImage", "deb"],
      "icon": "build/icon.png",
      "category": "Development",
      "maintainer": "Commander Bob <bob@echo-prime.ai>",
      "vendor": "ECHO PRIME AI",
      "synopsis": "Complete AI Intelligence Platform",
      "description": "ECHO PRIME provides a complete AI-powered cybersecurity and intelligence platform with 506,000+ integrated tools."
    },

    "publish": {
      "provider": "generic",
      "url": "https://updates.echo-prime.ai/"
    }
  }
}
```

### **Step 2.2: Create Custom NSIS Installer Script**

Create `build/installer-script.nsh`:

```nsis
!macro customInit
  ; Check Windows version
  ${If} ${AtLeastWin10}
    ; OK
  ${Else}
    MessageBox MB_OK|MB_ICONSTOP "ECHO PRIME requires Windows 10 or later."
    Quit
  ${EndIf}

  ; Check disk space (5GB required)
  ${GetRoot} "$INSTDIR" $0
  ${DriveSpace} "$0\" "/D=F /S=M" $1
  ${If} $1 < 5000
    MessageBox MB_OK|MB_ICONSTOP "Insufficient disk space. 5GB required."
    Quit
  ${EndIf}

  ; Check for existing installation
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app-id}" "InstallLocation"
  ${If} $0 != ""
    MessageBox MB_YESNO "ECHO PRIME is already installed. Uninstall first?" IDYES uninstall IDNO abort
    uninstall:
      ExecWait '"$0\uninstall.exe" /S'
      Goto done
    abort:
      Quit
    done:
  ${EndIf}
!macroend

!macro customInstall
  ; Install embedded Python
  DetailPrint "Installing Python runtime..."
  CopyFiles /SILENT "$INSTDIR\runtime\python" "$INSTDIR\runtime\python"

  ; Install Python dependencies
  DetailPrint "Installing Python dependencies..."
  nsExec::ExecToLog '"$INSTDIR\runtime\python\python.exe" -m pip install -r "$INSTDIR\requirements.txt"'

  ; Install embedded Node.js
  DetailPrint "Installing Node.js runtime..."
  CopyFiles /SILENT "$INSTDIR\runtime\node" "$INSTDIR\runtime\node"

  ; Initialize databases
  DetailPrint "Initializing databases..."
  nsExec::ExecToLog '"$INSTDIR\runtime\python\python.exe" "$INSTDIR\tools\init_databases.py"'

  ; Create data directories
  CreateDirectory "$APPDATA\ECHO_PRIME\memory\storage"
  CreateDirectory "$APPDATA\ECHO_PRIME\ekm\storage"
  CreateDirectory "$APPDATA\ECHO_PRIME\logs"
  CreateDirectory "$APPDATA\ECHO_PRIME\cache"

  ; Register Windows services (optional)
  DetailPrint "Registering services..."
  nsExec::ExecToLog '"$INSTDIR\tools\register_services.bat"'

  ; Create desktop shortcut
  CreateShortCut "$DESKTOP\ECHO PRIME.lnk" "$INSTDIR\ECHO PRIME.exe" "" "$INSTDIR\icon.ico"

  ; Create Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\ECHO PRIME"
  CreateShortCut "$SMPROGRAMS\ECHO PRIME\ECHO PRIME.lnk" "$INSTDIR\ECHO PRIME.exe"
  CreateShortCut "$SMPROGRAMS\ECHO PRIME\Uninstall.lnk" "$INSTDIR\uninstall.exe"
  CreateShortCut "$SMPROGRAMS\ECHO PRIME\User Manual.lnk" "$INSTDIR\docs\User_Manual.pdf"

  ; Register file associations
  WriteRegStr HKCR ".epml" "" "ECHO.PRIME.Memory"
  WriteRegStr HKCR "ECHO.PRIME.Memory" "" "ECHO PRIME Memory Crystal"
  WriteRegStr HKCR "ECHO.PRIME.Memory\DefaultIcon" "" "$INSTDIR\icon.ico"
  WriteRegStr HKCR "ECHO.PRIME.Memory\shell\open\command" "" '"$INSTDIR\ECHO PRIME.exe" "%1"'

  ; Set up auto-updater
  WriteRegStr HKLM "Software\ECHO PRIME" "UpdateURL" "https://updates.echo-prime.ai/"
  WriteRegStr HKLM "Software\ECHO PRIME" "Version" "${version}"

  DetailPrint "Installation complete!"
!macroend

!macro customUnInstall
  ; Ask about user data
  MessageBox MB_YESNO "Keep user data (memory crystals, EKMs, settings)?" IDYES keep IDNO delete
  delete:
    RMDir /r "$APPDATA\ECHO_PRIME"
    Goto done
  keep:
    ; Keep user data
  done:

  ; Stop services
  nsExec::ExecToLog '"$INSTDIR\tools\stop_services.bat"'

  ; Remove shortcuts
  Delete "$DESKTOP\ECHO PRIME.lnk"
  RMDir /r "$SMPROGRAMS\ECHO PRIME"

  ; Remove file associations
  DeleteRegKey HKCR ".epml"
  DeleteRegKey HKCR "ECHO.PRIME.Memory"

  ; Remove registry entries
  DeleteRegKey HKLM "Software\ECHO PRIME"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app-id}"

  DetailPrint "Uninstallation complete!"
!macroend
```

---

## 🐍 PHASE 3: EMBED PYTHON RUNTIME (Week 1-2)

### **Step 3.1: Download Embedded Python**

```bash
# Download Python 3.11 embedded for Windows
wget https://www.python.org/ftp/python/3.11.7/python-3.11.7-embed-amd64.zip

# Extract to runtime/python
unzip python-3.11.7-embed-amd64.zip -d runtime/python

# Get pip
cd runtime/python
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```

### **Step 3.2: Install Python Dependencies**

Create `requirements.txt`:

```txt
# Core dependencies
requests==2.31.0
flask==3.0.0
fastapi==0.108.0
uvicorn==0.25.0
websockets==12.0
pyjwt==2.8.0
cryptography==41.0.7
beautifulsoup4==4.12.2

# Database
sqlalchemy==2.0.23
better-sqlite3==0.4.3

# Security tools
pycryptodome==3.19.0
paramiko==3.4.0

# OSINT
phonenumbers==8.13.26
validators==0.22.0

# Voice
elevenlabs==0.2.26

# Utilities
python-dotenv==1.0.0
pyyaml==6.0.1
colorama==0.4.6
rich==13.7.0
```

```bash
# Install all dependencies into embedded Python
runtime/python/python.exe -m pip install -r requirements.txt --target runtime/python/Lib/site-packages
```

---

## 📦 PHASE 4: PACKAGE ALL COMPONENTS (Week 2)

### **Step 4.1: Organize All Systems**

```
ECHO_PRIME/
├── core/
│   ├── mls/                    # MLS Launcher
│   │   ├── launcher.py
│   │   ├── service_registry.json
│   │   └── orchestrator.py
│   │
│   └── gui/                    # Electron GUI
│       ├── main.js
│       ├── preload.js
│       ├── renderer/
│       │   ├── index.html
│       │   ├── dashboard.html
│       │   ├── agents.html
│       │   └── settings.html
│       └── assets/
│
├── agents/
│   └── prometheus-prime/       # All prometheus prime files
│
├── mcp-servers/                # All MCP servers
│   ├── epcp3o-agent/
│   ├── developer-gateway/
│   └── [others]/
│
├── memory/
│   ├── orchestrator/
│   ├── schema/
│   └── samples/
│
├── ekm/
│   ├── generator/
│   ├── schema/
│   └── samples/
│
├── voice/
│   └── [voice systems]
│
├── security/
│   └── vault/
│
├── runtime/
│   ├── python/                 # Embedded Python 3.11
│   └── node/                   # Embedded Node.js
│
├── docs/
│   ├── User_Manual.pdf
│   ├── Quick_Start.pdf
│   └── API_Reference.pdf
│
└── tools/
    ├── init_databases.py
    ├── register_services.bat
    └── first_run_wizard.py
```

### **Step 4.2: Create First-Run Wizard**

Create `tools/first_run_wizard.py`:

```python
import tkinter as tk
from tkinter import ttk
import json
import os

class FirstRunWizard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ECHO PRIME - First Run Setup")
        self.root.geometry("600x400")

        self.pages = [
            self.welcome_page,
            self.user_profile_page,
            self.api_config_page,
            self.memory_config_page,
            self.complete_page
        ]
        self.current_page = 0

        self.config = {}
        self.show_current_page()

    def show_current_page(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.pages[self.current_page]()

    def welcome_page(self):
        ttk.Label(self.root, text="Welcome to ECHO PRIME!",
                 font=("Arial", 18, "bold")).pack(pady=20)

        text = """
        ECHO PRIME is your complete AI-powered
        cybersecurity and intelligence platform.

        This wizard will help you:
        • Set up your user profile
        • Configure authority level
        • Initialize memory system
        • Connect API services (optional)
        """

        ttk.Label(self.root, text=text, justify="left").pack(pady=20)

        ttk.Button(self.root, text="Next", command=self.next_page).pack(pady=20)

    def user_profile_page(self):
        ttk.Label(self.root, text="User Profile Setup",
                 font=("Arial", 16, "bold")).pack(pady=20)

        frame = ttk.Frame(self.root)
        frame.pack(pady=20)

        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky="w")
        username = ttk.Entry(frame, width=30)
        username.grid(row=0, column=1, padx=10)
        username.insert(0, os.environ.get("USERNAME", "User"))

        ttk.Label(frame, text="Authority Level:").grid(row=1, column=0, sticky="w")
        authority = ttk.Combobox(frame, values=["11.0 - Full System Access",
                                                 "10.0 - System Administrator",
                                                 "5.0 - Analyst/Operator",
                                                 "1.0 - Read-Only Access"])
        authority.grid(row=1, column=1, padx=10)
        authority.current(0)

        ttk.Label(frame, text="Master Password:").grid(row=2, column=0, sticky="w")
        password = ttk.Entry(frame, width=30, show="•")
        password.grid(row=2, column=1, padx=10)

        self.config["username"] = username
        self.config["authority"] = authority
        self.config["password"] = password

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Back", command=self.prev_page).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Next", command=self.next_page).pack(side="left", padx=5)

    def api_config_page(self):
        # API configuration page
        pass

    def memory_config_page(self):
        # Memory system configuration
        pass

    def complete_page(self):
        ttk.Label(self.root, text="Setup Complete!",
                 font=("Arial", 18, "bold")).pack(pady=20)

        ttk.Label(self.root, text="ECHO PRIME is ready to use.").pack(pady=10)

        ttk.Button(self.root, text="Launch ECHO PRIME",
                  command=self.launch).pack(pady=20)

    def next_page(self):
        self.current_page += 1
        self.show_current_page()

    def prev_page(self):
        self.current_page -= 1
        self.show_current_page()

    def launch(self):
        # Save configuration
        config_path = os.path.join(os.getenv("APPDATA"), "ECHO_PRIME", "config.json")
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        config_data = {
            "username": self.config["username"].get(),
            "authority_level": float(self.config["authority"].get().split(" ")[0]),
            # ... other config
        }

        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=2)

        self.root.destroy()

        # Launch main GUI
        import subprocess
        subprocess.Popen([os.path.join(os.path.dirname(__file__), "..", "ECHO PRIME.exe")])

if __name__ == "__main__":
    wizard = FirstRunWizard()
    wizard.root.mainloop()
```

---

## 🔨 PHASE 5: BUILD & TEST (Week 2-3)

### **Step 5.1: Build Installer**

```bash
# Install dependencies
npm install

# Build for Windows
npm run build:win

# Output: dist/ECHO_PRIME_Setup_4.0.0.exe
```

### **Step 5.2: Test Installation**

```
Test Checklist:
├── [  ] Fresh install on Windows 10
├── [  ] Fresh install on Windows 11
├── [  ] Upgrade from previous version
├── [  ] Custom installation path
├── [  ] Component selection
├── [  ] Services start correctly
├── [  ] GUI launches without errors
├── [  ] All agents accessible
├── [  ] Memory system functional
├── [  ] Voice integration works
├── [  ] Auto-updater functional
├── [  ] Uninstaller works correctly
└── [  ] No leftover files after uninstall
```

---

## 🚀 PHASE 6: DISTRIBUTION (Week 3)

### **Step 6.1: Code Signing**

```bash
# Get code signing certificate (from DigiCert, Sectigo, etc.)
# Cost: ~$200-500/year

# Sign the installer
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com /d "ECHO PRIME" dist/ECHO_PRIME_Setup_4.0.0.exe
```

### **Step 6.2: Create Download Page**

```bash
# Upload to hosting
aws s3 cp dist/ECHO_PRIME_Setup_4.0.0.exe s3://downloads.echo-prime.ai/

# Create download page at https://echo-prime.ai/download
```

### **Step 6.3: Set Up Auto-Update Server**

```bash
# Upload update manifest
cat > latest.yml <<EOF
version: 4.0.0
files:
  - url: ECHO_PRIME_Setup_4.0.0.exe
    sha512: [hash]
    size: 1500000000
path: ECHO_PRIME_Setup_4.0.0.exe
sha512: [hash]
releaseDate: '2025-11-10'
EOF

aws s3 cp latest.yml s3://updates.echo-prime.ai/
```

---

## 📊 TIMELINE SUMMARY

```
Week 1:
├── Day 1-2: Repository consolidation
├── Day 3-4: Installer framework setup
├── Day 5-6: Embed Python runtime
└── Day 7:   Package all components

Week 2:
├── Day 1-2: Create first-run wizard
├── Day 3-4: Build and test installer
├── Day 5-6: Fix bugs and refine
└── Day 7:   Code signing preparation

Week 3:
├── Day 1-2: Final testing on all platforms
├── Day 3-4: Create documentation
├── Day 5:   Set up distribution infrastructure
├── Day 6:   Release preparation
└── Day 7:   PUBLIC RELEASE
```

---

## ✅ DELIVERABLES

**End Result:**
1. ✅ `ECHO_PRIME_Setup_4.0.0.exe` (Windows installer)
2. ✅ `ECHO_PRIME_4.0.0.dmg` (Mac installer)
3. ✅ `ECHO_PRIME_4.0.0.AppImage` (Linux installer)
4. ✅ Auto-update server configured
5. ✅ Download page live
6. ✅ User documentation complete
7. ✅ Code-signed and production-ready

**User Experience:**
- Download single file (~1.5GB)
- Double-click to install
- 5-minute installation
- Launch ECHO PRIME
- Complete AI system ready to use

---

**MATCHES:** Adobe Creative Cloud, Visual Studio, Docker Desktop quality standards.

**READY FOR:** Mass production and public distribution.

**END OF BUILD PLAN**
