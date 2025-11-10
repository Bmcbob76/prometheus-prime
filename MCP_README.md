# 🔥 Prometheus Prime - MCP Integration

**Quick setup guide for exposing ALL Prometheus Prime capabilities to Claude Desktop**

---

## ⚡ QUICK START (3 Steps)

### 1. Run Setup Script
```bash
cd /home/user/prometheus-prime
./setup_mcp.sh
```

### 2. Restart Claude Desktop

### 3. Test Tools
In Claude Desktop, try:
```
Use prom_health to check Prometheus Prime status
```

---

## 📊 WHAT YOU GET

| Capability | Tools | Description |
|------------|-------|-------------|
| **Security Domains** | 20 | Network recon, web exploitation, wireless, social engineering, etc. |
| **Diagnostics** | 5 | System, network, security, AI/ML, database health monitoring |
| **Basic Tools** | 12+ | Port scanning, exploits, payloads, password cracking, evasion |
| **Advanced Attacks** | 20 | AI poisoning, quantum crypto, LOTL, credential harvest, AD attacks |
| **Advanced Defenses** | 20 | EDR, SIEM, threat hunting, zero trust, behavioral analytics |
| **TOTAL** | **77+** | Complete offensive/defensive security operations |

---

## 📖 FULL DOCUMENTATION

See [MCP_INTEGRATION_GUIDE.md](./MCP_INTEGRATION_GUIDE.md) for:
- Complete tool reference
- Usage examples
- Troubleshooting
- Advanced configuration

---

## 🎯 EXAMPLE COMMANDS

### Security Operations
```
Use prom_network_recon to scan 192.168.1.1
Use prom_web_exploitation to test SQL injection on https://example.com
Use prom_osint to gather intelligence on target.com
```

### Diagnostics
```
Use prom_diag_system to run full system diagnostics
Use prom_diag_security to audit security posture
Use prom_diag_aiml to check GPU and AI framework health
```

### Advanced Operations
```
Use prom_attack_active_directory to show Golden Ticket attack
Use prom_defense_edr to enable behavioral monitoring
Use prom_defense_siem to configure log aggregation
```

---

## ⚠️ REQUIREMENTS

- Python 3.8+
- MCP SDK: `pip install mcp`
- Claude Desktop (latest version)
- All Prometheus Prime dependencies installed

---

## 🔧 MANUAL SETUP

If the automated script doesn't work:

1. **Install MCP SDK:**
   ```bash
   pip install mcp
   ```

2. **Add to Claude Desktop config** (`~/.config/Claude/claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "prometheus-prime": {
         "command": "/usr/bin/python3",
         "args": ["/home/user/prometheus-prime/mcp_server.py"],
         "env": {
           "PYTHONPATH": "/home/user/prometheus-prime"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop**

---

## ✅ VERIFICATION

Test that everything works:

```bash
# Test MCP server standalone
python3 mcp_server.py

# Should see:
# 🔥 PROMETHEUS PRIME ULTIMATE - MCP SERVER
# 📡 Total MCP Tools: 77+
```

In Claude Desktop:
```
Use prom_health
```

Should return complete system status.

---

## 🐛 TROUBLESHOOTING

| Issue | Solution |
|-------|----------|
| Tools not showing | Check Claude Desktop config syntax, restart Claude |
| Import errors | Run `pip install -r requirements.txt` |
| Server not starting | Check Python path in config, verify dependencies |
| Permission denied | Make setup script executable: `chmod +x setup_mcp.sh` |

---

## 📞 SUPPORT

1. Read [MCP_INTEGRATION_GUIDE.md](./MCP_INTEGRATION_GUIDE.md)
2. Check Claude Desktop console (Ctrl+Shift+I) for errors
3. Verify all dependencies: `pip list | grep mcp`

---

**Authority Level:** 11.0
**Status:** FULL OPERATIONAL CAPABILITY
**Total Tools:** 77+

🔥 **PROMETHEUS PRIME ULTIMATE** 🔥
