# PyManager - Universal Python Version Manager

**System-Wide PATH Hijack for Automatic Python Version Routing**

PyManager is a transparent Python version router that hijacks ALL `python` calls system-wide and automatically routes them to the correct Python version based on file context, directory settings, or global configuration.

## 🎯 Mission

**Make PyManager the ONLY Python in PATH. Auto-route to correct version per file/directory. Zero user intervention.**

## ⚡ Key Features

- **Total PATH Dominance**: Single entry point for ALL Python calls
- **Zero Configuration**: Works without modifying existing scripts
- **Intelligent Routing**: Automatic version detection from multiple sources
- **Per-Directory Locking**: Set Python version once, applies to entire project
- **Version Aliases**: Use semantic names like `ml`, `latest`, `legacy`
- **Transparent Execution**: <50ms routing overhead
- **Pip Integration**: Version-aware package installation
- **Backwards Compatible**: No script changes required

## 🏗️ Architecture

```
H:\Tools\PyManager\              # (or any install location)
├── python.exe                   # THE MANAGER (your only PATH Python)
├── python3.exe                  # Alias to python.exe
├── pip.exe                      # Version-aware pip wrapper
├── pymanager.json               # Configuration
├── core/
│   ├── dispatcher.py            # Core routing logic
│   └── pip_wrapper.py           # Pip version router
└── pythons/                     # Managed Python installations
    ├── py311/                   # Python 3.11
    ├── py39/                    # Python 3.9
    └── py38/                    # Python 3.8
```

## 🚀 Installation

### Quick Start

```bash
# Clone repository
git clone https://github.com/Bmcbob76/python-manager.git
cd python-manager

# Run installer (adds to PATH, detects Pythons)
python install.py

# RESTART terminal

# Verify
python --pm-info
```

### Manual Installation

1. **Clone/Download** to desired location (e.g., `H:\Tools\PyManager`)

2. **Run Installer**:
   ```bash
   python install.py
   ```
   This will:
   - Detect existing Python installations
   - Create default configuration
   - Add PyManager to PATH (first position)
   - Build standalone executable (if PyInstaller available)

3. **Restart Terminal** for PATH changes to take effect

4. **Verify**:
   ```bash
   python --pm-info
   where python  # Should show PyManager first
   ```

## 📋 Configuration

### pymanager.json

```json
{
  "default_version": "3.11",
  "versions": {
    "3.11": "pythons/py311/python.exe",
    "3.10": "pythons/py310/python.exe",
    "3.9": "pythons/py39/python.exe",
    "3.8": "pythons/py38/python.exe",
    "ml": "pythons/py311/python.exe",
    "latest": "pythons/py311/python.exe",
    "legacy": "pythons/py38/python.exe"
  },
  "directory_overrides": {
    "E:\\ECHO_XV4": "3.11",
    "D:\\LegacyProjects": "3.8",
    "C:\\ML_Projects": "ml"
  },
  "verbose": false,
  "auto_detect": true
}
```

### Version Detection Priority

PyManager uses the following hierarchy to determine Python version:

1. **File Shebang**: `#!pymanager:3.11`
2. **Directory `.pyversion` File**: Recursive search up directory tree
3. **Directory Overrides**: Path-based rules in config
4. **Global Default**: `default_version` in config
5. **Fallback**: Highest installed version

## 💡 Usage Examples

### Scenario 1: Existing Script (No Changes)

```bash
# Old way
C:\Python311\python.exe script.py

# New way (automatic routing)
python script.py
```

PyManager detects version and routes automatically.

### Scenario 2: Version-Specific Project

```bash
cd E:\MyProject

# Lock entire directory to Python 3.11
echo 3.11 > .pyversion

# All scripts now use Python 3.11
python train_model.py
python test_suite.py
python deploy.py
```

### Scenario 3: Per-File Version Control

```python
# script_a.py
#!pymanager:3.11
import torch  # Uses Python 3.11

# script_b.py
#!pymanager:3.9
import legacy_lib  # Uses Python 3.9
```

Both scripts in same directory, different Python versions!

### Scenario 4: Version Aliases

```python
# ml_project.py
#!pymanager:ml
import tensorflow  # Uses 'ml' alias (Python 3.11)

# legacy_code.py
#!pymanager:legacy
import old_package  # Uses 'legacy' alias (Python 3.8)
```

### Scenario 5: Pip Version Management

```bash
# Install to current/default Python
pip install numpy

# Install to specific Python version
cd my_311_project
echo 3.11 > .pyversion
pip install torch  # Installs to Python 3.11

# Explicit version targeting
pip3.9 install pandas  # Force install to Python 3.9
```

## 🔧 Advanced Usage

### Enable Verbose Mode

See routing decisions in real-time:

```json
{
  "verbose": true
}
```

Output:
```
[PyManager] Routing to Python 3.11: H:\Tools\PyManager\pythons\py311\python.exe
```

### Directory Overrides

Force specific versions for entire directory trees:

```json
{
  "directory_overrides": {
    "E:\\ECHO_XV4": "3.11",
    "D:\\OldProjects": "3.8",
    "C:\\ML": "ml"
  }
}
```

### Custom Version Aliases

Create semantic version names:

```json
{
  "versions": {
    "3.11": "pythons/py311/python.exe",
    "ml": "pythons/py311/python.exe",
    "data-science": "pythons/py311/python.exe",
    "web": "pythons/py310/python.exe",
    "legacy": "pythons/py38/python.exe"
  }
}
```

Use in scripts:
```python
#!pymanager:data-science
import pandas, numpy, sklearn
```

## 🛠️ Building Standalone Executable

For production deployment, build standalone `python.exe`:

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
python build.py

# Output in dist/python.exe
```

Then deploy `dist/` folder with executable and config.

## 📦 Version Control Integration

### Git Integration

Add to `.gitignore`:
```
# PyManager
.pyversion
```

Add to `.gitattributes` for team consistency:
```
.pyversion text eol=lf
```

### Project Setup

```bash
# Set project Python version
echo 3.11 > .pyversion
git add .pyversion
git commit -m "Lock project to Python 3.11"
```

Now all team members automatically use Python 3.11 for this project!

## 🔍 Troubleshooting

### Python Not Routing Correctly

Check detection:
```bash
python --pm-info
```

Enable verbose mode in config:
```json
{"verbose": true}
```

### PATH Not Updated

Windows:
```powershell
# Check PATH
$env:Path -split ';' | Select-String PyManager

# Restart terminal or refresh:
refreshenv  # (if using chocolatey)
```

Linux/Mac:
```bash
# Check PATH
echo $PATH | grep -o "[^:]*PyManager[^:]*"

# Reload shell:
source ~/.bashrc
```

### Version Not Found

Check available versions:
```bash
python --pymanager-versions
```

Add missing version to `pymanager.json`:
```json
{
  "versions": {
    "3.12": "C:\\Python312\\python.exe"
  }
}
```

## 🗑️ Uninstallation

```bash
python uninstall.py
```

This will:
- Remove PyManager from PATH
- Clean build artifacts
- Backup configuration
- Leave source files (manual delete if desired)

## 🔐 Security Considerations

- **No Elevation Required**: Uses `HKEY_CURRENT_USER` on Windows
- **Transparent Execution**: No code injection or modification
- **Sandboxed**: Each Python version isolated
- **Auditable**: All routing logged in verbose mode

## 📊 Performance

- **Routing Overhead**: <50ms
- **Memory**: ~5MB (standalone executable)
- **Disk**: ~10MB (with all dependencies)

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- [ ] Linux/Mac full support and testing
- [ ] Virtual environment detection
- [ ] Conda integration
- [ ] GUI configuration tool
- [ ] Auto-update mechanism
- [ ] Version auto-download

## 📄 License

MIT License - See LICENSE file

## 🙏 Credits

Created by Commander Bobby Don McWilliams II for ECHO PRIME XV4

**FULL SYSTEM HIJACK. NO PYTHON ESCAPES THE MANAGER.**

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `python script.py` | Run with auto-detected version |
| `python --pm-info` | Show PyManager configuration |
| `python --pymanager-versions` | List available Python versions |
| `echo 3.11 > .pyversion` | Lock directory to Python 3.11 |
| `pip install package` | Install to current/default version |
| `pip3.11 install package` | Install to Python 3.11 explicitly |
| `python install.py` | Install/reinstall PyManager |
| `python uninstall.py` | Remove PyManager from system |
| `python build.py` | Build standalone executable |

## Example Scripts

See `examples/` directory for:
- Multi-version project setup
- Directory-based routing
- Shebang-based routing
- Pip version management
- CI/CD integration
