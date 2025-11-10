# PROMETHEUS PRIME - DEPLOYMENT GUIDE

**Authority Level**: 11.0
**Operator**: Commander Bobby Don McWilliams II
**Total MCP Tools**: 282 across 6 categories

---

## 📦 DEPLOYMENT OPTIONS

### Option 1: Windows PowerShell Installation (Recommended for P: Drive)

**Prerequisites:**
- Windows system with PowerShell
- P: drive mounted and accessible
- Python 3.8+ installed
- Git (optional, for cloning repository)

**Steps:**

1. **Transfer files to Windows machine**
   ```bash
   # On Linux/source machine, create deployment archive:
   git archive --format=tar.gz -o prometheus-prime-deployment.tar.gz HEAD

   # Transfer to Windows machine via network/USB
   ```

2. **Extract and run PowerShell installer**
   ```powershell
   # On Windows machine:
   cd path\to\prometheus-prime
   .\install_to_windows.ps1

   # Or specify custom target:
   .\install_to_windows.ps1 -TargetDrive "P:" -TargetPath "ECHO_PRIME\prometheus_prime_new"
   ```

3. **Configure environment**
   - Edit `P:\ECHO_PRIME\prometheus_prime_new\.env`
   - Add API keys for Claude, OpenAI, Google, Cohere, ElevenLabs
   - Update database connection strings if needed

4. **Install dependencies**
   ```powershell
   cd P:\ECHO_PRIME\prometheus_prime_new
   pip install -r requirements.txt
   ```

5. **Verify installation**
   ```powershell
   python test_mcp_tool.py
   ```

---

### Option 2: Direct Git Clone

**On target system:**

```bash
# Clone repository
git clone https://github.com/Bmcbob76/prometheus-prime.git P:\ECHO_PRIME\prometheus_prime_new

# Checkout the latest feature branch
cd P:\ECHO_PRIME\prometheus_prime_new
git checkout claude/prometheus-autonomous-ai-agent-011CUv5AA2qn3VNNZHELe8qj

# Install dependencies
pip install -r requirements.txt

# Configure .env
copy .env.example .env
# Edit .env with your API keys
```

---

## 🚀 POST-DEPLOYMENT CONFIGURATION

### 1. Environment Variables (.env file)

```env
# REQUIRED API Keys
ANTHROPIC_API_KEY=sk-ant-xxxxx
OPENAI_API_KEY=sk-xxxxx
GOOGLE_API_KEY=xxxxx
COHERE_API_KEY=xxxxx
ELEVENLABS_API_KEY=xxxxx

# Database Configuration (if using)
REDIS_HOST=localhost
REDIS_PORT=6379
MYSQL_HOST=localhost
MYSQL_PORT=3306

# Memory System
MEMORY_ROOT=M:\MEMORY_ORCHESTRATION

# Authority
AUTHORITY_LEVEL=11.0
OPERATOR=Commander Bobby Don McWilliams II
```

### 2. MCP Server Configuration for Claude Desktop

**Location**: `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "prometheus-prime": {
      "command": "python",
      "args": ["P:\\ECHO_PRIME\\prometheus_prime_new\\mcp_server.py"],
      "env": {}
    }
  }
}
```

**Restart Claude Desktop** after configuration.

### 3. Test MCP Tools

```bash
# Run comprehensive test
python test_mcp_tool.py

# Expected output:
# ✅ PASS: Registry Load (282 tools)
# ✅ PASS: Payload Generator
# ✅ PASS: Physical Attacks
# 🎉 3/3 tests passed
```

### 4. View All Available Tools

```bash
# Generate complete tool documentation
python list_all_tools.py > MY_TOOLS.txt

# Or view pre-generated list:
type PROMETHEUS_MCP_TOOLS_COMPLETE.txt
```

---

## 🤖 AUTONOMOUS OPERATION

### Launch Demo Mode

```bash
# Safe demonstration mode (read-only)
python demo_autonomous.py
```

**Output**: Complete OODA loop demonstration showing all 4 phases.

### Launch Full Autonomous Mode

**⚠️ REQUIRES:**
- Signed Rules of Engagement (ROE)
- Target authorization
- All API keys configured
- All dependencies installed

```bash
# Full autonomous deployment
python src/autonomous/prometheus_autonomous.py
```

---

## 📊 SYSTEM ARCHITECTURE

### 282 MCP Tools Breakdown:

| Category | Count | Description |
|----------|-------|-------------|
| **Security Domain** | 81 | Network scanning, exploitation, privilege escalation |
| **Specialized** | 85 | OSINT, web attacks, wireless, physical security |
| **Diagnostic** | 66 | System monitoring, error detection, health checks |
| **SIGINT** | 27 | Signals intelligence, traffic analysis |
| **Ultimate** | 13 | GRANDMASTER level - BGP hijacking, biometric bypass |
| **Basic Tool** | 10 | File operations, command execution, utilities |

### 6 Sensory Systems:

1. **Vision**: OpenCV, face-recognition, pytesseract, EasyOCR
2. **Hearing**: Whisper, Vosk, pyannote.audio
3. **Voice**: ElevenLabs synthesis
4. **Touch**: Network/system interaction
5. **Proprioception**: Self-monitoring
6. **Memory**: 9-tier crystal memory system

### Autonomous OODA Loop:

1. **OBSERVE**: Intelligence gathering from target environment
2. **ORIENT**: Analyze data, understand situation
3. **DECIDE**: AI consensus (5 models) determines optimal action
4. **ACT**: Execute operation via security domains

---

## 🛡️ SAFETY & COMPLIANCE

### Built-in Safety Protocols:

- ✅ Ethical guardrails enforced
- ✅ ROE (Rules of Engagement) compliance required
- ✅ Authorization verification before destructive actions
- ✅ Audit logging of all operations
- ✅ Emergency stop capability

### Authority Levels:

- **1.0-5.0**: Low - Basic reconnaissance, information gathering
- **5.1-8.0**: Medium - Active scanning, vulnerability assessment
- **8.1-10.0**: High - Exploitation, lateral movement
- **10.1+**: Maximum - Ultimate capabilities (BGP, cloud, biometric)

**Current Authority Level**: 11.0 (Full access to all 282 tools)

---

## 🐛 TROUBLESHOOTING

### Common Issues:

**1. ImportError when loading registry**
```bash
# Solution: Ensure all dependencies installed
pip install -r requirements.txt --upgrade
```

**2. MCP server not appearing in Claude Desktop**
```bash
# Solution: Check configuration file syntax
python -m json.tool %APPDATA%\Claude\claude_desktop_config.json
# Restart Claude Desktop
```

**3. API key errors**
```bash
# Solution: Verify .env file
python -c "from dotenv import load_dotenv; import os; load_dotenv(); print('Keys loaded:', bool(os.getenv('ANTHROPIC_API_KEY')))"
```

**4. Permission denied on file operations**
```bash
# Solution: Run with appropriate privileges
# Windows: Run PowerShell as Administrator
```

---

## 📈 MONITORING & LOGS

### Log Locations:

- Autonomous operations: `./logs/autonomous_*.log`
- MCP server: `./logs/mcp_server.log`
- Tool execution: `./logs/prometheus_*.log`

### Monitor Autonomous Status:

```python
from src.autonomous.prometheus_autonomous import PrometheusAutonomous
autonomous = PrometheusAutonomous()
status = autonomous.get_status()
print(f"Cycles: {status['cycles_completed']}")
print(f"Operations: {status['operations_completed']}")
```

---

## 🔄 UPDATES & MAINTENANCE

### Pull Latest Changes:

```bash
cd P:\ECHO_PRIME\prometheus_prime_new
git fetch origin
git pull origin claude/prometheus-autonomous-ai-agent-011CUv5AA2qn3VNNZHELe8qj
pip install -r requirements.txt --upgrade
```

### Backup Configuration:

```bash
# Backup .env and custom configs
copy .env .env.backup
copy .claude\mcp.json .claude\mcp.json.backup
```

---

## 📞 SUPPORT & DOCUMENTATION

### Files:

- **Complete Tool List**: `PROMETHEUS_MCP_TOOLS_COMPLETE.txt` (2,033 lines)
- **Capability Registry**: `PROMETHEUS_CAPABILITY_REGISTRY.py` (1,733 lines)
- **Test Suite**: `test_mcp_tool.py`
- **Demo Script**: `demo_autonomous.py`

### Repository:

- **GitHub**: https://github.com/Bmcbob76/prometheus-prime
- **Branch**: `claude/prometheus-autonomous-ai-agent-011CUv5AA2qn3VNNZHELe8qj`

---

## ✅ DEPLOYMENT CHECKLIST

- [ ] Transfer files to target system
- [ ] Run installation script (PowerShell on Windows)
- [ ] Configure .env file with API keys
- [ ] Install Python dependencies (`pip install -r requirements.txt`)
- [ ] Run test suite (`python test_mcp_tool.py`)
- [ ] Configure Claude Desktop MCP settings
- [ ] Restart Claude Desktop
- [ ] Verify tools appear in Claude interface
- [ ] Run autonomous demo (`python demo_autonomous.py`)
- [ ] Review security and ROE documentation
- [ ] Enable audit logging
- [ ] Test emergency stop procedures

---

**🔥 PROMETHEUS PRIME IS READY FOR DEPLOYMENT**

Authority Level: 11.0
All 282 MCP tools operational
Autonomous mode ready
Safety protocols enforced
