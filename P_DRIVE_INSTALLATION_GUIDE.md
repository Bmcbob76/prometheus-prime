# 🔥 PROMETHEUS PRIME - P DRIVE INSTALLATION GUIDE

**Authority Level:** 11.0
**Target Location:** `P:\ECHO_PRIME\prometheus_prime_new`
**Memory Location:** `P:\MEMORY_ORCHESTRATION`

---

## 📋 PREREQUISITES

### System Requirements

- ✅ Windows 10/11 (64-bit)
- ✅ Python 3.8+ installed
- ✅ P: Drive accessible and mounted
- ✅ At least 10GB free space on P: drive
- ✅ Administrator privileges (for some tools)

### Python Installation

If Python is not installed:

1. Download Python from https://www.python.org/downloads/
2. Run installer
3. **IMPORTANT:** Check "Add Python to PATH"
4. Choose "Install Now"
5. Verify: Open CMD and type `python --version`

---

## 🚀 INSTALLATION STEPS

### Step 1: Run Installation Script

**From your current Prometheus location:**

```batch
INSTALL_P_DRIVE.bat
```

This will:
- ✅ Create directory structure on P: drive
- ✅ Copy all Python files
- ✅ Copy documentation
- ✅ Create memory directories
- ✅ Generate .env configuration
- ✅ Create launch scripts

### Step 2: Configure API Keys

Edit `P:\ECHO_PRIME\prometheus_prime_new\.env`:

```env
# Replace these with your actual API keys
OPENAI_API_KEY=sk-your-actual-openai-key
ANTHROPIC_API_KEY=sk-ant-your-actual-anthropic-key
ELEVENLABS_API_KEY=your-actual-elevenlabs-key
```

**How to get API keys:**

- **OpenAI:** https://platform.openai.com/api-keys
- **Anthropic:** https://console.anthropic.com/settings/keys
- **ElevenLabs:** https://elevenlabs.io/app/settings/api-keys

### Step 3: Install Dependencies

Run from P: drive:

```batch
cd /d P:\ECHO_PRIME\prometheus_prime_new
INSTALL_DEPENDENCIES.bat
```

This installs all required Python packages:
- anthropic, openai, elevenlabs
- pyaudio, SpeechRecognition
- opencv-python, face-recognition
- And 15+ more packages

**Installation time:** 5-10 minutes

### Step 4: Verify Installation

Run test to verify everything works:

```batch
cd /d P:\ECHO_PRIME\prometheus_prime_new
TEST_EXPERT_KNOWLEDGE.bat
```

You should see:
```
🎓 PROMETHEUS EXPERT KNOWLEDGE SYSTEM TEST
===========================================================
📊 Total tools mastered: 209
```

---

## 📁 DIRECTORY STRUCTURE

After installation, your P: drive will have:

```
P:\
├── ECHO_PRIME\
│   └── prometheus_prime_new\
│       ├── capabilities\                # All capability modules
│       │   ├── network_recon.py
│       │   ├── web_exploitation.py
│       │   ├── wireless_ops.py
│       │   └── ... (20 total)
│       │
│       ├── src\                         # Source code
│       │   ├── autonomous\
│       │   │   └── prometheus_autonomous.py
│       │   ├── ai_brain\
│       │   ├── voice\
│       │   ├── memory\
│       │   └── ...
│       │
│       ├── logs\                        # Operation logs
│       ├── config\                      # Configuration files
│       ├── models\                      # AI models
│       │
│       ├── prometheus_prime_ultimate_gui.py    # Main GUI
│       ├── prometheus_expert_knowledge.py      # Expert system
│       ├── mcp_server_complete.py             # MCP server
│       ├── prometheus_complete.py             # Core system
│       │
│       ├── LAUNCH_GUI.bat               # GUI launcher
│       ├── LAUNCH_MCP_SERVER.bat        # MCP launcher
│       ├── LAUNCH_AUTONOMOUS.bat        # Autonomous mode
│       ├── TEST_EXPERT_KNOWLEDGE.bat    # System test
│       ├── INSTALL_DEPENDENCIES.bat     # Dependency installer
│       │
│       ├── .env                         # Configuration
│       ├── requirements.txt             # Python packages
│       │
│       └── Documentation\
│           ├── PROMETHEUS_COGNITIVE_INTEGRATION_MISSION.md
│           ├── PROMETHEUS_AUTONOMY_STATUS.md
│           ├── GUI_USAGE_GUIDE.md
│           ├── PROMETHEUS_209_TOOLS.md
│           └── ...
│
└── MEMORY_ORCHESTRATION\                # Prometheus memory
    ├── prometheus_crystals\             # Crystal memory
    │   ├── TIER_S\                      # Supreme tier
    │   ├── TIER_A\                      # Alpha tier
    │   ├── TIER_B\                      # Beta tier
    │   └── ... (9 tiers total)
    │
    └── prometheus_operations\           # Operations DB
        └── prometheus_operations.db
```

---

## 🚀 LAUNCHING PROMETHEUS

### Method 1: GUI Interface (Recommended)

```batch
cd /d P:\ECHO_PRIME\prometheus_prime_new
LAUNCH_GUI.bat
```

**Features:**
- 27 tabs with all security domains
- 209 MCP tools accessible
- Real-time monitoring
- Professional interface

### Method 2: MCP Server (For Claude Desktop)

```batch
cd /d P:\ECHO_PRIME\prometheus_prime_new
LAUNCH_MCP_SERVER.bat
```

Then configure Claude Desktop to use the server.

### Method 3: Autonomous Mode

```batch
cd /d P:\ECHO_PRIME\prometheus_prime_new
LAUNCH_AUTONOMOUS.bat
```

**Warning:** Autonomous mode requires careful configuration and monitoring.

### Method 4: Python API

Create `test_prometheus.py`:

```python
import asyncio
from prometheus_expert_knowledge import PrometheusExpertise

async def main():
    # Initialize expert system
    expertise = PrometheusExpertise()

    # Get tool count
    total_tools = expertise.count_total_tools()
    print(f"Total tools mastered: {total_tools}")

    # Get recommendations
    recommendations = await expertise.recommend_tool("Scan network")
    for rec in recommendations:
        print(f"- {rec['name']}: {rec['reason']}")

asyncio.run(main())
```

Run:
```batch
python test_prometheus.py
```

---

## ⚙️ CONFIGURATION

### Environment Variables (.env)

Located at: `P:\ECHO_PRIME\prometheus_prime_new\.env`

```env
# API Keys
OPENAI_API_KEY=sk-your-key
ANTHROPIC_API_KEY=sk-ant-your-key
ELEVENLABS_API_KEY=your-key

# Prometheus Configuration
PROMETHEUS_AUTHORITY_LEVEL=11.0
PROMETHEUS_COMMANDER=Bobby Don McWilliams II
PROMETHEUS_MEMORY_PATH=P:\MEMORY_ORCHESTRATION

# Operational Settings
PROMETHEUS_STEALTH_MODE=false
PROMETHEUS_DEFENSE_MODE=true
PROMETHEUS_AUTO_CRYSTALLIZE=true

# Voice Settings
PROMETHEUS_VOICE_ENABLED=true
PROMETHEUS_VOICE_PROFILE=tactical
```

### Memory Configuration

Crystal memory will be stored at:
- `P:\MEMORY_ORCHESTRATION\prometheus_crystals\`

Database will be at:
- `P:\MEMORY_ORCHESTRATION\prometheus_operations\prometheus_operations.db`

---

## 🔧 TROUBLESHOOTING

### Issue 1: "P: drive not found"

**Solution:**
1. Check if P: drive is mounted in File Explorer
2. Verify you can access `P:\` in CMD: `dir P:\`
3. If network drive, ensure connection is active

### Issue 2: "Python not found"

**Solution:**
```batch
# Check Python installation
python --version

# If not found, add to PATH or reinstall Python
# Make sure to check "Add Python to PATH" during install
```

### Issue 3: "Module not found" errors

**Solution:**
```batch
cd /d P:\ECHO_PRIME\prometheus_prime_new
pip install -r requirements.txt --force-reinstall
```

### Issue 4: "Access denied" errors

**Solution:**
- Run CMD as Administrator
- Check folder permissions on P: drive
- Ensure you have write access to P:\ECHO_PRIME

### Issue 5: GUI won't launch

**Solution:**
```batch
# Install tkinter (usually included with Python)
# If missing, reinstall Python with "tcl/tk" option checked

# Test if tkinter works:
python -c "import tkinter; print('Tkinter OK')"
```

### Issue 6: Voice system errors

**Solution:**
```batch
# Install audio dependencies
pip install pyaudio elevenlabs

# If pyaudio fails on Windows:
pip install pipwin
pipwin install pyaudio
```

---

## 📊 VERIFICATION CHECKLIST

After installation, verify:

- [ ] P: drive installation completed successfully
- [ ] .env file configured with API keys
- [ ] Dependencies installed without errors
- [ ] Test script shows "209 tools mastered"
- [ ] GUI launches without errors
- [ ] Memory directories created
- [ ] Can access P:\ECHO_PRIME\prometheus_prime_new
- [ ] Can access P:\MEMORY_ORCHESTRATION

---

## 🎯 NEXT STEPS

### 1. Configure Your Environment

Edit `.env` file with your actual API keys and preferences.

### 2. Run System Diagnostics

```batch
cd /d P:\ECHO_PRIME\prometheus_prime_new
python -c "from prometheus_expert_knowledge import PrometheusExpertise; expertise = PrometheusExpertise(); print(expertise.get_capability_summary())"
```

### 3. Launch GUI and Explore

```batch
LAUNCH_GUI.bat
```

Navigate through all 27 tabs to familiarize yourself with capabilities.

### 4. Review Documentation

Read the comprehensive guides:
- `PROMETHEUS_COGNITIVE_INTEGRATION_MISSION.md` - Complete system architecture
- `PROMETHEUS_AUTONOMY_STATUS.md` - Autonomy capabilities
- `GUI_USAGE_GUIDE.md` - GUI interface documentation
- `PROMETHEUS_209_TOOLS.md` - Complete tool reference

### 5. Start Using Prometheus

Begin with simple operations:
1. Network scanning
2. WiFi discovery
3. Web enumeration
4. System diagnostics

Then progress to advanced features:
- RED TEAM operations
- Autonomous mode
- Voice interface
- Full missions

---

## 🔐 SECURITY NOTES

### Authorization

**CRITICAL:** Prometheus Prime must only be used for:
- ✅ Authorized penetration testing
- ✅ Controlled lab environments
- ✅ CTF competitions
- ✅ Educational purposes with consent

### Data Protection

- Memory crystals contain sensitive operation data
- Keep `P:\MEMORY_ORCHESTRATION` secure
- API keys in `.env` should be protected
- Consider encrypting P: drive if it contains sensitive data

### Operational Security

- Review operations before execution
- Monitor autonomous mode carefully
- Use stealth mode when appropriate
- Keep logs for documentation

---

## 📞 SUPPORT

### Getting Help

1. **Documentation First**
   - Check `PROMETHEUS_AUTONOMY_STATUS.md`
   - Review `GUI_USAGE_GUIDE.md`
   - Read tool reference: `PROMETHEUS_209_TOOLS.md`

2. **Common Issues**
   - See troubleshooting section above
   - Check Python version (must be 3.8+)
   - Verify P: drive access
   - Ensure dependencies installed

3. **Testing**
   - Run `TEST_EXPERT_KNOWLEDGE.bat`
   - Check system diagnostics
   - Verify API keys

---

## 🔥 QUICK REFERENCE

### Launch Commands

```batch
# Change to Prometheus directory
cd /d P:\ECHO_PRIME\prometheus_prime_new

# Launch GUI
LAUNCH_GUI.bat

# Launch MCP Server
LAUNCH_MCP_SERVER.bat

# Test system
TEST_EXPERT_KNOWLEDGE.bat

# Install/update dependencies
INSTALL_DEPENDENCIES.bat

# Launch autonomous mode (careful!)
LAUNCH_AUTONOMOUS.bat
```

### File Locations

- **Installation:** `P:\ECHO_PRIME\prometheus_prime_new\`
- **Memory:** `P:\MEMORY_ORCHESTRATION\`
- **Configuration:** `P:\ECHO_PRIME\prometheus_prime_new\.env`
- **Logs:** `P:\ECHO_PRIME\prometheus_prime_new\logs\`
- **Documentation:** `P:\ECHO_PRIME\prometheus_prime_new\*.md`

---

## 📋 SUMMARY

**Installation Path:** `P:\ECHO_PRIME\prometheus_prime_new`
**Memory Path:** `P:\MEMORY_ORCHESTRATION`
**Authority Level:** 11.0
**Total Tools:** 209 MCP Tools
**Security Domains:** 25+

**Status:** Ready for deployment on P: drive

---

## 🎯 POST-INSTALLATION

After successful installation, Prometheus Prime on P: drive will have:

✅ **Complete Autonomy** - 100% autonomous operation capability
✅ **All Senses** - Vision, hearing, voice, network, system awareness
✅ **Expert Knowledge** - 209 MCP tools completely mastered
✅ **Echo Prime Memory** - 9-tier crystal system with 565+ crystals
✅ **Professional GUI** - 27 tabs with all capabilities
✅ **Complete Documentation** - Full user guides and references

**Prometheus Prime is ready to serve at Authority Level 11.0!**

---

*Installation Guide Version: 1.0*
*Date: 2025-11-08*
*Authority Level: 11.0*
*Operator: Commander Bobby Don McWilliams II*
