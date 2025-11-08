# 🎯 MISSION BRIEF: PROMETHEUS PRIME SIGINT EXPANSION
**Authority Level:** 11.0  
**Commander:** Bobby Don McWilliams II  
**Target Repo:** https://github.com/Bmcbob76/prometheus-prime  
**Mission Status:** ACTIVE

---

## 📋 MISSION OBJECTIVES

Build **8 new SIGINT modules** with **full MCP tool integration** for Prometheus Prime offensive/defensive platform. All capabilities must be production-ready, fully functional, and integrated into the existing MCP server architecture.

---

## 🎖️ COMMANDER'S RULES - READ FIRST

**CRITICAL EXECUTION STANDARDS:**
- ✅ **NO PLACEHOLDERS** - Every function must be complete, working code
- ✅ **NO STUBS/MOCKS** - Real implementations only
- ✅ **FULL ERROR HANDLING** - Phoenix healing patterns (GS343)
- ✅ **MCP INTEGRATION** - All tools must register in prometheus_prime_mcp.py
- ✅ **PRODUCTION QUALITY** - This is Authority Level 11.0 operational code
- ✅ **WINDOWS COMPATIBILITY** - All external tools must work on Windows
- ✅ **ASYNC OPERATIONS** - Use threading/async for performance-critical ops

**FORBIDDEN ACTIONS:**
- ❌ NO mock/stub implementations
- ❌ NO "TODO" comments without implementation
- ❌ NO incomplete error handling
- ❌ NO Linux-only dependencies (must work on Windows)

---

## 🏗️ EXISTING ARCHITECTURE REFERENCE

**Current File Structure:**
```
PROMETHEUS_PRIME/
├── prometheus_prime_mcp.py         # Main MCP server (ADD NEW TOOLS HERE)
├── phone_intelligence.py           # Example: OSINT module
├── network_security.py             # Example: Network scanning
├── mobile_control.py              # Example: Device control
├── web_security.py                # Example: Web testing
├── exploitation_framework.py      # Example: Exploit integration
├── gs343_gateway.py               # Phoenix healing (USE THIS)
├── requirements.txt               # Add new dependencies here
└── mls_config.json                # MLS registration
```

**MCP Tool Registration Pattern (from prometheus_prime_mcp.py):**
```python
@self.mcp.tool()
def tool_name(param1: str, param2: int = 5000) -> Dict[str, Any]:
    """
    Tool description for Claude
    
    Args:
        param1: Parameter description
        param2: Parameter description with default
    
    Returns:
        Dict with results
    """
    try:
        # Use Phoenix healing
        result = self.gs343.heal_with_retry(
            operation=lambda: module.function(param1, param2),
            operation_name="tool_name",
            max_retries=3
        )
        return result
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "tool": "tool_name"
        }
```

**Phoenix Healing Pattern (from gs343_gateway.py):**
```python
def heal_with_retry(self, operation, operation_name, max_retries=3):
    """Auto-retry with exponential backoff"""
    for attempt in range(max_retries):
        try:
            return operation()
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return {"success": False, "error": str(e)}
```

---

## 🔥 MODULE 1: WIFI INTELLIGENCE (wifi_intelligence.py)

**Priority:** HIGH  
**Dependencies:** `scapy`, `netaddr`, `wifi` (Python WiFi), `pywifi`

**Required Capabilities:**
1. **WiFi Network Scanner**
   - Scan all WiFi networks in range
   - Extract SSID, BSSID, channel, signal strength, encryption
   - Detect hidden networks
   - Channel utilization analysis

2. **WiFi Monitor Mode**
   - Enable/disable monitor mode on adapter
   - Channel hopping (1-14, auto or manual)
   - Packet capture (beacon frames, probe requests, data)
   - Real-time packet statistics

3. **WiFi Deauthentication**
   - Send deauth packets to specific client/AP
   - Broadcast deauth (all clients)
   - Configurable packet count and delay
   - Target validation

4. **Rogue AP Detection**
   - Detect Evil Twin APs
   - MAC address spoofing detection
   - Signal strength anomalies
   - SSID cloning detection

5. **WPA Handshake Capture**
   - Auto-capture 4-way handshake
   - Save to PCAP format
   - Handshake validation
   - Support for multiple targets

6. **WiFi Credential Harvesting**
   - Extract WiFi credentials from Windows (netsh wlan show profiles)
   - Parse PSK from network profiles
   - Export to JSON/CSV format

**MCP Tools to Create:**
- `prom_wifi_scan` - Scan WiFi networks
- `prom_wifi_monitor_start` - Enable monitor mode
- `prom_wifi_monitor_stop` - Disable monitor mode
- `prom_wifi_deauth` - Deauth attack
- `prom_wifi_rogue_detect` - Detect rogue APs
- `prom_wifi_handshake_capture` - Capture WPA handshake
- `prom_wifi_creds_extract` - Extract saved WiFi credentials (Windows)

**Windows Implementation Notes:**
- Use `pywifi` for WiFi scanning (Windows compatible)
- Use `scapy` for packet crafting
- For monitor mode: Check if adapter supports (many Windows adapters don't - provide fallback using native scanning)
- For credential extraction: Use `subprocess` with `netsh wlan show profiles` and `netsh wlan show profile name="SSID" key=clear`

---

## 🔥 MODULE 2: TRAFFIC ANALYSIS (traffic_analysis.py)

**Priority:** HIGH  
**Dependencies:** `scapy`, `mitmproxy`, `pcapy-ng`, `dpkt`

**Required Capabilities:**
1. **PCAP Capture**
   - Live packet capture on interface
   - Filter by protocol, port, IP
   - Save to PCAP file
   - Statistics (packet count, bytes, protocols)

2. **Deep Packet Inspection**
   - Parse HTTP/HTTPS headers
   - Extract URLs, User-Agents, cookies
   - Protocol distribution analysis
   - Top talkers identification

3. **MITM Framework**
   - ARP spoofing (poison target + gateway)
   - DNS spoofing (redirect domains)
   - SSL strip (downgrade HTTPS to HTTP)
   - Transparent proxy setup

4. **Traffic Pattern Analysis**
   - Identify protocols (HTTP, DNS, SSH, etc.)
   - Connection tracking (src -> dst)
   - Bandwidth usage per IP
   - Suspicious pattern detection

5. **Metadata Extraction**
   - Extract file transfers (HTTP)
   - DNS query logging
   - Email metadata (SMTP/POP3/IMAP)
   - FTP credentials

**MCP Tools to Create:**
- `prom_pcap_capture` - Start PCAP capture
- `prom_pcap_analyze` - Analyze existing PCAP file
- `prom_dpi_inspect` - Deep packet inspection
- `prom_mitm_arp_poison` - ARP spoofing attack
- `prom_mitm_dns_spoof` - DNS spoofing
- `prom_mitm_ssl_strip` - SSL stripping
- `prom_traffic_baseline` - Analyze traffic patterns
- `prom_metadata_extract` - Extract metadata from traffic

**Windows Implementation Notes:**
- Use `npcap` (Windows packet capture driver) - check if installed
- Provide installation instructions if missing
- Use `scapy` with npcap backend
- For MITM: Windows requires elevated privileges - check and warn

---

## ⚡ MODULE 3: BLUETOOTH INTELLIGENCE (bluetooth_intelligence.py)

**Priority:** HIGH  
**Dependencies:** `pybluez`, `bleak` (BLE), `bluetooth` (Linux), Windows Bluetooth API via ctypes

**Required Capabilities:**
1. **BLE Scanner**
   - Scan for BLE devices
   - Extract device name, MAC, RSSI, services
   - Manufacturer data parsing
   - iBeacon detection

2. **Classic Bluetooth Scanner**
   - Scan for classic Bluetooth devices
   - Device name, class, services
   - SDP (Service Discovery Protocol)
   - Device fingerprinting

3. **Bluetooth Tracking**
   - Track device movement by RSSI
   - Proximity estimation
   - Device presence logging
   - Multi-device tracking

4. **Device Fingerprinting**
   - Identify device type (phone, laptop, IoT)
   - Manufacturer identification
   - Service profiling
   - Vulnerability assessment

**MCP Tools to Create:**
- `prom_ble_scan` - Scan BLE devices
- `prom_bt_classic_scan` - Scan classic Bluetooth
- `prom_bt_track_device` - Track specific device
- `prom_bt_fingerprint` - Device fingerprinting
- `prom_bt_proximity` - Proximity estimation

**Windows Implementation Notes:**
- Use `bleak` for BLE (Windows compatible)
- For classic Bluetooth: Use Windows Bluetooth API via `ctypes` or `pybluez` if available
- Provide fallback if Bluetooth adapter not found
- RSSI tracking may be limited on Windows - use available APIs

---

## 📡 MODULE 4: RF/SDR MODULE (rf_intelligence.py)

**Priority:** MEDIUM  
**Dependencies:** `pyrtlsdr`, `scipy`, `numpy`, `matplotlib` (for spectrum analysis)

**Required Capabilities:**
1. **SDR Signal Detection**
   - Scan frequency range
   - Detect active signals
   - Signal strength measurement
   - Bandwidth estimation

2. **Spectrum Analysis**
   - FFT spectrum visualization (data only, no GUI)
   - Peak detection
   - Signal classification
   - Frequency hopping detection

3. **Signal Decoding**
   - Decode 433MHz/315MHz signals (OOK, ASK)
   - Decode LoRa packets
   - Decode POCSAG (pagers)
   - Save raw IQ data

4. **RF Monitoring**
   - Long-term frequency monitoring
   - Signal logging
   - Anomaly detection
   - Pattern recognition

**MCP Tools to Create:**
- `prom_sdr_scan_freq` - Scan frequency range
- `prom_sdr_detect_signals` - Detect active signals
- `prom_sdr_spectrum_analyze` - Spectrum analysis
- `prom_sdr_decode_signal` - Decode specific protocol
- `prom_sdr_monitor` - Long-term monitoring

**Windows Implementation Notes:**
- Requires RTL-SDR dongle (check if present)
- Use `pyrtlsdr` with `rtl-sdr.dll` on Windows
- Provide installation guide for RTL-SDR drivers
- Return data only (no plots), let Claude analyze

---

## 📞 MODULE 5: VOIP INTELLIGENCE (voip_intelligence.py)

**Priority:** MEDIUM  
**Dependencies:** `scapy`, `dpkt`, `pcapy-ng`

**Required Capabilities:**
1. **SIP Scanner**
   - Enumerate SIP servers
   - Extension enumeration
   - Version fingerprinting
   - Vulnerability detection

2. **VoIP Call Monitoring**
   - Capture SIP signaling
   - Extract call metadata (caller, callee, duration)
   - RTP stream detection
   - Codec identification

3. **RTP Stream Capture**
   - Capture RTP packets
   - Extract audio payload
   - Save to WAV (if possible)
   - Stream statistics

4. **Credential Extraction**
   - Extract SIP credentials from traffic
   - Digest authentication parsing
   - Password cracking (weak digests)

**MCP Tools to Create:**
- `prom_voip_sip_scan` - Scan for SIP servers
- `prom_voip_call_monitor` - Monitor VoIP calls
- `prom_voip_rtp_capture` - Capture RTP stream
- `prom_voip_creds_extract` - Extract VoIP credentials
- `prom_voip_extension_enum` - Enumerate extensions

**Windows Implementation Notes:**
- Use `scapy` for packet capture
- Parse SIP/RTP using `dpkt`
- Audio reconstruction optional (complex) - focus on metadata extraction
- Provide PCAP saving for external analysis

---

## 🗺️ MODULE 6: NETWORK MAPPER (network_mapper.py)

**Priority:** MEDIUM  
**Dependencies:** `scapy`, `netifaces`, `manuf` (MAC vendor lookup)

**Required Capabilities:**
1. **Device Discovery**
   - ARP scan (Layer 2)
   - ICMP sweep (Layer 3)
   - Active host enumeration
   - MAC address collection

2. **Device Fingerprinting**
   - Passive OS fingerprinting (TTL, window size)
   - Active OS detection
   - MAC vendor lookup
   - Service identification

3. **Topology Mapping**
   - Gateway identification
   - Router discovery
   - VLAN detection
   - Network diagram data (JSON)

4. **Network Baselining**
   - Track devices over time
   - New device alerts
   - Device change tracking
   - Historical data

**MCP Tools to Create:**
- `prom_net_discover_devices` - Discover all devices
- `prom_net_fingerprint_device` - Fingerprint specific device
- `prom_net_map_topology` - Map network topology
- `prom_net_baseline` - Create network baseline
- `prom_net_mac_lookup` - MAC vendor lookup

**Windows Implementation Notes:**
- Use `scapy` for ARP/ICMP
- Use `netifaces` for local interface info
- Use `manuf` for MAC vendor database
- Store baselines in JSON files

---

## 📶 MODULE 7: CELLULAR INTELLIGENCE (cellular_intelligence.py)

**Priority:** LOW  
**Dependencies:** `pyserial`, `at-commands` (for modems)

**Required Capabilities:**
1. **Cell Tower Detection**
   - Detect nearby cell towers
   - Extract Cell ID, LAC, MCC, MNC
   - Signal strength measurement
   - Tower geolocation (via databases)

2. **IMSI Catcher Detection**
   - Detect fake cell towers
   - LAC/Cell ID anomaly detection
   - Encryption downgrade detection
   - Location tracking

3. **Carrier Information**
   - Identify carrier by MCC/MNC
   - Network type (2G, 3G, 4G, 5G)
   - Roaming detection

4. **SMS/Call Metadata**
   - Monitor SMS metadata (not content)
   - Call duration tracking
   - Frequency analysis

**MCP Tools to Create:**
- `prom_cell_detect_towers` - Detect cell towers
- `prom_cell_imsi_catcher_detect` - Detect IMSI catchers
- `prom_cell_carrier_info` - Get carrier information
- `prom_cell_monitor_metadata` - Monitor SMS/call metadata

**Windows Implementation Notes:**
- Requires USB modem or phone with AT command support
- Use `pyserial` for serial communication
- Many features require special hardware (SDR or modem)
- Provide graceful degradation if hardware not available

---

## 🔇 MODULE 8: PASSIVE MONITOR (passive_monitor.py)

**Priority:** LOW  
**Dependencies:** `scapy`, `sqlite3` (for storage)

**Required Capabilities:**
1. **Traffic Baselining**
   - Long-term traffic capture
   - Protocol distribution over time
   - Bandwidth usage trends
   - Connection patterns

2. **Anomaly Detection**
   - Detect unusual traffic patterns
   - Port scan detection
   - DDoS indicators
   - Exfiltration detection

3. **Protocol Analysis**
   - Parse non-HTTP protocols
   - Extract protocol-specific data
   - Protocol fingerprinting
   - Version detection

4. **Metadata Database**
   - Store all metadata in SQLite
   - Query interface
   - Export to CSV/JSON
   - Data retention policies

**MCP Tools to Create:**
- `prom_passive_start_monitor` - Start passive monitoring
- `prom_passive_stop_monitor` - Stop monitoring
- `prom_passive_get_baseline` - Get traffic baseline
- `prom_passive_detect_anomalies` - Detect anomalies
- `prom_passive_query_db` - Query metadata database

**Windows Implementation Notes:**
- Use `scapy` with npcap
- Store data in SQLite database
- Run as background thread
- Provide stop mechanism to avoid resource exhaustion

---

## 🔧 INTEGRATION REQUIREMENTS

### 1. Update prometheus_prime_mcp.py

**Add imports:**
```python
from wifi_intelligence import WiFiIntelligence
from traffic_analysis import TrafficAnalysis
from bluetooth_intelligence import BluetoothIntelligence
from rf_intelligence import RFIntelligence
from voip_intelligence import VoIPIntelligence
from network_mapper import NetworkMapper
from cellular_intelligence import CellularIntelligence
from passive_monitor import PassiveMonitor
```

**Initialize modules in __init__:**
```python
self.wifi = WiFiIntelligence()
self.traffic = TrafficAnalysis()
self.bluetooth = BluetoothIntelligence()
self.rf = RFIntelligence()
self.voip = VoIPIntelligence()
self.netmap = NetworkMapper()
self.cellular = CellularIntelligence()
self.passive = PassiveMonitor()
```

**Register all MCP tools** using the pattern shown above

### 2. Update requirements.txt

Add all new dependencies:
```
scapy>=2.5.0
pywifi>=1.1.12
netaddr>=0.8.0
mitmproxy>=10.0.0
pcapy-ng>=1.0.9
dpkt>=1.9.8
pybluez>=0.23
bleak>=0.21.0
pyrtlsdr>=0.2.92
scipy>=1.11.0
numpy>=1.24.0
matplotlib>=3.7.0
netifaces>=0.11.0
manuf>=1.1.5
pyserial>=3.5
```

### 3. Update mls_config.json

Add new tool registrations:
```json
{
  "tools": [
    {
      "name": "prom_wifi_scan",
      "category": "wifi_intelligence"
    },
    // ... add all 40+ new tools
  ]
}
```

### 4. Create SIGINT_README.md

Document all new capabilities, usage examples, dependencies, and security warnings.

---

## ✅ ACCEPTANCE CRITERIA

**Each module must have:**
- ✅ Complete class with all functions implemented
- ✅ Proper error handling (Phoenix healing patterns)
- ✅ Type hints on all functions
- ✅ Docstrings with Args/Returns
- ✅ MCP tools registered in prometheus_prime_mcp.py
- ✅ Windows compatibility verified
- ✅ External dependencies documented
- ✅ Security warnings for offensive capabilities

**Each MCP tool must:**
- ✅ Accept proper parameters with defaults
- ✅ Return Dict[str, Any] with "success" boolean
- ✅ Use Phoenix healing (gs343.heal_with_retry)
- ✅ Have clear docstring for Claude
- ✅ Handle missing dependencies gracefully

**Testing requirements:**
- ✅ Each module must have test functions
- ✅ Verify external tools (npcap, RTL-SDR, etc.)
- ✅ Provide installation guides for missing tools
- ✅ Graceful degradation if hardware unavailable

---

## 🎯 EXECUTION CHECKLIST

**Phase 1: Infrastructure (Do First)**
- [ ] Update requirements.txt with all dependencies
- [ ] Create base classes for each module
- [ ] Set up Phoenix healing integration
- [ ] Verify Windows compatibility

**Phase 2: High Priority Modules**
- [ ] wifi_intelligence.py (7 tools)
- [ ] traffic_analysis.py (8 tools)
- [ ] bluetooth_intelligence.py (5 tools)

**Phase 3: Medium Priority Modules**
- [ ] rf_intelligence.py (5 tools)
- [ ] voip_intelligence.py (5 tools)
- [ ] network_mapper.py (5 tools)

**Phase 4: Low Priority Modules**
- [ ] cellular_intelligence.py (4 tools)
- [ ] passive_monitor.py (5 tools)

**Phase 5: Integration**
- [ ] Update prometheus_prime_mcp.py with all tools
- [ ] Update mls_config.json
- [ ] Create SIGINT_README.md
- [ ] Test all tools end-to-end

---

## 🚨 SECURITY & LEGAL

**ALL OFFENSIVE CAPABILITIES REQUIRE:**
- Written authorization from system owner
- Defined scope and rules of engagement
- Compliance with local/international laws
- Ethical guidelines and responsible disclosure

**Add this warning to every offensive tool:**
```python
# ⚠️ OFFENSIVE TOOL - AUTHORIZED USE ONLY
# Unauthorized access is illegal under CFAA and international law
# Commander Bob (Authority 11.0) authorization required
```

---

## 📊 DELIVERABLES

**Files to create:**
1. `wifi_intelligence.py` - WiFi SIGINT module
2. `traffic_analysis.py` - Traffic analysis module
3. `bluetooth_intelligence.py` - Bluetooth SIGINT module
4. `rf_intelligence.py` - RF/SDR module
5. `voip_intelligence.py` - VoIP intelligence module
6. `network_mapper.py` - Network mapping module
7. `cellular_intelligence.py` - Cellular intelligence module
8. `passive_monitor.py` - Passive monitoring module
9. `SIGINT_README.md` - Complete SIGINT documentation

**Files to update:**
1. `prometheus_prime_mcp.py` - Add all 40+ new MCP tools
2. `requirements.txt` - Add all dependencies
3. `mls_config.json` - Register new tools
4. `README.md` - Update with SIGINT capabilities

**Total new MCP tools:** ~44 tools across 8 modules

---

## 🎖️ COMMANDER'S FINAL ORDERS

**Authority Level 11.0 standards:**
- Every function must be production-ready
- No placeholders, no TODOs without implementation
- Complete error handling with Phoenix healing
- Windows compatibility is mandatory
- Performance-critical operations must be async/threaded
- All offensive capabilities require proper warnings

**This is operational code for ECHO_XV4 system.**
**Failure is not acceptable.**
**Execute with precision.**

---

**MISSION START: EXPAND PROMETHEUS PRIME SIGINT CAPABILITIES**  
**COMMANDER: Bobby Don McWilliams II**  
**AUTHORITY: 11.0**  
**STATUS: ACTIVE** 🎖️

---

**When complete, commit to repo with:**
```bash
git add .
git commit -m "SIGINT expansion: 8 modules, 44+ MCP tools, full Windows support"
git push origin master:main
```
