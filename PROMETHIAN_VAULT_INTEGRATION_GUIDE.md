# PROMETHEUS PRIME - CODEBASE ARCHITECTURE & ORGANIZATION SUMMARY

## Project Overview
**Prometheus Prime** is a comprehensive offensive/defensive security operations platform with:
- Authority Level: 11.0 (Maximum)
- 43 MCP Tools + 13 HTTP API Endpoints
- Full-spectrum security capabilities: OSINT, Network Security, Mobile Control, Web Security, Exploitation Framework
- M Drive Memory Integration
- GS343 Phoenix Healing (auto-recovery system)

---

## 1. DIRECTORY STRUCTURE

### Top-Level Organization
```
/home/user/prometheus-prime/
├── prometheus_prime_mcp.py              # Main MCP Server (608 lines)
├── prometheus_memory.py                 # M Drive Memory Integration (355 lines)
├── gs343_gateway.py                     # Phoenix Healing System (371 lines)
├── gs343_comprehensive_scanner_*.py     # Advanced scanning (768 lines)
├── osint_api_server.py                  # HTTP API Server (364 lines)
├── scope_gate.py                        # Lab Scope Validation
├── config_loader.py                     # Configuration Management
├── logging_setup.py                     # Logging System
│
├── OSINT Modules (6 core files):
│   ├── phone_intelligence.py            # Twilio CNAM lookups (318 lines)
│   ├── social_osint.py                  # Reddit/social media (293 lines)
│   ├── domain_intelligence.py           # WHOIS/DNS (379 lines)
│   ├── email_intelligence.py            # HIBP/breach checks (511 lines)
│   ├── ip_intelligence.py               # Geolocation/Shodan (369 lines)
│   └── network_security.py              # Port scanning (339 lines)
│
├── Security & Control Modules (3 core files):
│   ├── mobile_control.py                # iOS/Android control (479 lines)
│   ├── web_security.py                  # Web testing (408 lines)
│   └── exploitation_framework.py        # Metasploit integration (421 lines)
│
├── CORE INFRASTRUCTURE DIRECTORIES:
│   ├── crypto/                          # Cryptographic operations
│   │   └── crypto_exploits.py          # Hash cracking, RSA attacks
│   │
│   ├── capabilities/                    # Advanced red team capabilities (28 Python files)
│   │   ├── red_team_core.py
│   │   ├── red_team_recon.py
│   │   ├── red_team_ad_attacks.py
│   │   ├── red_team_c2.py
│   │   ├── red_team_exploits.py
│   │   ├── red_team_evasion.py
│   │   ├── red_team_mimikatz.py
│   │   ├── red_team_post_exploit.py
│   │   ├── red_team_persistence.py
│   │   ├── red_team_metasploit.py
│   │   ├── red_team_reporting.py
│   │   ├── biometric_bypass.py
│   │   ├── cloud_exploits.py
│   │   ├── lateral_movement.py
│   │   ├── mobile_exploits.py
│   │   ├── password_attacks.py
│   │   └── [17 more modules...]
│   │
│   ├── tools/                           # Arsenal toolkit
│   │   ├── arsenal/                     # Community pentest toolkit
│   │   │   ├── modules/
│   │   │   ├── app.py
│   │   │   └── __main__.py
│   │   └── jamming_scripts/
│   │
│   ├── configs/                         # Configuration files
│   │   ├── default.yaml                 # Main configuration
│   │   └── example_scope.yaml           # Lab scope definition
│   │
│   ├── osint_db/                        # OSINT databases
│   │
│   ├── ai_models/                       # AI/ML exploitation modules
│   │
│   ├── automotive/                      # CAN bus exploitation
│   │
│   ├── ics_scada/                       # Industrial control systems
│   │
│   ├── quantum/                         # Quantum computing modules
│   │
│   ├── BEEF/                            # Empty (reserved)
│   │
│   ├── EGB/                             # Specialized exploits
│   │
│   ├── POC/                             # Proof of concepts
│   │
│   ├── Orange-cyberdefense/             # Orange CD framework
│   │
│   ├── KNOWLEDGE_INDEX/                 # Indexed knowledge database
│   │   ├── language_index.json
│   │   ├── category_index.json
│   │   ├── technique_index.json
│   │   └── file_index.json
│   │
│   └── ULTIMATE_CAPABILITIES/           # Advanced capability definitions
│
├── DOCUMENTATION:
│   ├── README.md                        # Main documentation
│   ├── COMPLETE_STATUS.md
│   ├── PROMETHEUS_PRIME_STATUS.md
│   ├── PROMETHEUS_COGNITIVE_INTEGRATION_MISSION.md
│   ├── CLAUDE_CODE_INTEGRATION.md
│   ├── MCP_SERVER_SETUP_PROMPT.md
│   └── [Many other documentation files...]
│
└── CONFIGURATION & ENVIRONMENT:
    ├── .env                             # API keys & credentials
    ├── mls_config.json                  # MLS registration
    ├── .gitignore
    └── prometheus_prime_mcp_config.yaml (if present)
```

---

## 2. SECURITY & CRYPTO MODULES LOCATION

### Cryptographic Operations
**Location:** `/home/user/prometheus-prime/crypto/`

**File:** `crypto_exploits.py` (100+ lines)
```
CryptoExploiter class with:
- MD5/SHA256 hash cracking
- Brute force PIN attacks
- Weak RSA key factorization (Fermat's method)
- CBC padding oracle attacks
- Entropy analysis
- Rainbow table generation
- Blockchain address analysis
```

### Encryption in Data Handling
Files using encryption/security:
- `phone_intelligence.py` - SQLite cache with phone data
- `prometheus_memory.py` - Credentials vault with encryption-capable storage
- `scope_gate.py` - Validates scope to prevent unauthorized operations
- Various modules use `cryptography.hazmat.primitives` for:
  - Asymmetric encryption (RSA)
  - Symmetric encryption (AES)
  - Hash functions
  - Serialization (PEM format)

---

## 3. MCP SERVERS & TOOLS IMPLEMENTATION

### Main MCP Server
**File:** `/home/user/prometheus-prime/prometheus_prime_mcp.py` (608 lines)

**Architecture:**
```python
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

app = Server("prometheus-prime")

@app.list_tools()
async def list_tools() -> List[Tool]:
    # Returns 43 tools organized in categories
    
@app.call_tool()
async def call_tool(name: str, arguments: Dict) -> List[TextContent]:
    # Executes requested tool
```

### MCP Tool Categories (43 Total)

#### 1. OSINT Tools (6)
- `prom_health` - System health
- `prom_phone_lookup` - Phone intelligence
- `prom_social_search` - Social OSINT
- `prom_domain_lookup` - Domain intelligence
- `prom_email_analyze` - Email intelligence
- `prom_ip_analyze` - IP intelligence

#### 2. Network Security Tools (5)
- `prom_port_scan` - Port scanner
- `prom_nmap_scan` - Nmap wrapper
- `prom_vulnerability_scan` - Vuln detection
- `prom_subnet_scan` - Host discovery
- `prom_service_banner` - Fingerprinting

#### 3. Mobile Control Tools (8)
- `prom_android_devices` - List devices
- `prom_android_info` - Device info
- `prom_android_shell` - Command execution
- `prom_android_screenshot` - Screen capture
- `prom_android_apps` - App listing
- `prom_ios_devices` - iOS enumeration
- `prom_ios_info` - iOS device info
- `prom_ios_screenshot` - iOS screenshot

#### 4. Web Security Tools (8)
- `prom_web_headers` - Security header analysis
- `prom_sql_injection` - SQL injection testing
- `prom_xss_test` - XSS vulnerability testing
- `prom_dir_bruteforce` - Directory enumeration
- `prom_web_crawl` - Web crawler
- `prom_ssl_scan` - SSL/TLS analysis
- `prom_tech_detect` - Technology detection
- `prom_web_comprehensive` - Full scan

#### 5. Exploitation Tools (5)
- `prom_search_exploits` - Search Exploit-DB
- `prom_generate_payload` - msfvenom wrapper
- `prom_list_payloads` - List available payloads
- `prom_pattern_create` - Cyclic pattern generation
- `prom_msf_search` - Metasploit search

#### 6. Utility Tools (2)
- `prom_osint_full` - Complete OSINT report
- `prom_healing_stats` - Phoenix healing stats

### HTTP API Server
**File:** `/home/user/prometheus-prime/osint_api_server.py` (364 lines)

**Endpoints (13 total):**
- `/api/health` - Health check
- `/api/phone` - Phone lookup
- `/api/social` - Social OSINT
- `/api/domain` - Domain intelligence
- `/api/email` - Email intelligence
- `/api/ip` - IP intelligence
- `/api/port_scan` - Port scanning
- `/api/nmap` - Nmap wrapper
- `/api/web_headers` - Security headers
- `/api/sql_injection` - SQL testing
- `/api/xss_test` - XSS testing
- `/api/exploits` - Exploit search
- `/api/full_osint` - Complete OSINT

---

## 4. MODULE ORGANIZATION PATTERNS

### OSINT Module Template
```python
class PhoneIntelligence:
    def __init__(self):
        # Load .env credentials
        # Initialize cache/database
        # Initialize external clients
    
    def _init_cache_db(self):
        # Create SQLite cache
    
    def lookup(self, target):
        # Main operation
        # Error handling via GS343
        # Cache storage
```

### Security Module Integration
```python
from gs343_gateway import gs343, with_phoenix_retry

@with_phoenix_retry
def operation():
    try:
        # Core logic
    except Exception as e:
        # Phoenix healing via GS343
```

### Capabilities Module Structure
```
capabilities/
├── __init__.py              # Package definition with scope enforcement notes
├── red_team_*.py            # 25+ specialized modules
│   ├── Reconnaissance
│   ├── Active Directory attacks
│   ├── C2 & Persistence
│   ├── Post-exploitation
│   ├── Lateral movement
│   ├── Privilege escalation
│   ├── Evasion techniques
│   ├── Reporting & exfiltration
│   └── Metasploit integration
└── biometric_bypass.py
└── cloud_exploits.py
└── mobile_exploits.py
└── password_attacks.py
```

---

## 5. CONFIGURATION & ENVIRONMENT PATTERNS

### Environment Variables (.env)
**Location:** `/home/user/prometheus-prime/.env`

**Configured Keys:**
```
# API Credentials
REDDIT_CLIENT_ID=qs18EYiz8vVGgaxptMhi7Q
REDDIT_CLIENT_SECRET=95woJCHY46KcNGGPv7UgG3xO7L6bXw
REDDIT_USERNAME=Federal_Mousse_6763
REDDIT_PASSWORD=Bmc4ever
WHOISXML_API_KEY=at_dJJtIIyviPnZTsfCnZHxHf2vUdqou

# Optional APIs
GOOGLE_API_KEY=
GOOGLE_CX_ID=
TWITTER_BEARER_TOKEN=
```

### Configuration Files
**Location:** `/home/user/prometheus-prime/configs/`

#### 1. `default.yaml` - Main Configuration
```yaml
agent:
  name: PROMETHEUS-PRIME
  authority_level: 9.9
  voice_character: BREE
  commander_name: Commander Bobby Don McWilliams II

lab:
  scope_file: configs/example_scope.yaml
  require_scope_confirmation: true
  hard_block_out_of_scope: true

features:
  enable_recon: true
  enable_vuln_scan: true
  enable_ad_attacks: false
  enable_reporting: true
  enable_payload_dev: false
  enable_c2: false
  [... 10+ feature flags ...]

paths:
  base_dir: .
  logs_dir: logs
  reports_dir: reports
  sessions_dir: sessions
  payloads_dir: payloads
  osint_db_path: osint_db/prime.sqlite

logging:
  level: INFO
  file: logs/prometheus_prime.log
  rotate: false

tools:
  nmap_path: ""
  msfconsole_path: ""
  hashcat_path: ""
  
recon:
  nmap:
    default_args: ["-sS", "-sV", "-T4"]
    host_timeout: "30m"
  http:
    user_agent: "PrometheusPrime/1.0 (Lab-Only)"
    request_timeout_seconds: 10
```

#### 2. `example_scope.yaml` - Lab Scope
```yaml
scope:
  cidrs: [lab CIDRs]
  domains: [lab domains]
  hosts: [specific hosts]
  allowed_ports: ["1-65535"]
  protocols: ["tcp", "udp"]
  egress:
    allow_to_cidrs: [outbound CIDRs]
    allow_to_domains: [outbound domains]

policy:
  require_confirmation: true
  banner: "LAB-ONLY"
  hard_block_out_of_scope: true
```

### Configuration Loader
**File:** `/home/user/prometheus-prime/config_loader.py`

**Functions:**
```python
def load_config(config_path: str = "configs/default.yaml") -> Dict:
    # Loads YAML configuration
    # Applies .env overrides (PP_LOG_LEVEL, PP_FEATURE_*, PP_SCOPE_FILE)
    # Ensures required directories exist
    # Returns merged config

def load_scope(cfg: Dict) -> Dict:
    # Loads lab scope from scope_file
    # Validates CIDRS, domains, ports
    # Returns scope and policy dictionaries

def dump_effective_config(cfg: Dict, out_path: Optional[str] = None) -> str:
    # Exports current effective configuration as JSON
    # For troubleshooting
```

### Environment Override Patterns
```bash
# Override log level
PP_LOG_LEVEL=DEBUG

# Enable/disable features
PP_FEATURE_ENABLE_RECON=true
PP_FEATURE_ENABLE_VULN_SCAN=true
PP_FEATURE_ENABLE_AD_ATTACKS=false

# Override scope file
PP_SCOPE_FILE=/path/to/scope.yaml
```

---

## 6. EXISTING SECURITY & ENCRYPTION IMPLEMENTATIONS

### A. Phoenix Healing System (GS343)
**File:** `/home/user/prometheus-prime/gs343_gateway.py` (371 lines)

**Features:**
```python
class GS343Gateway:
    def heal_phoenix(error: str, context: Dict) -> Dict:
        # Error analysis
        # Healing suggestions
        # Fallback API chains
        # Auto-recovery actions
        
    Retry Configuration:
    - max_retries: 3
    - backoff_base: 2
    - backoff_max: 30 seconds
    
    Fallback Chains:
    - phone_lookup: [twilio, numverify, opencnam]
    - domain_whois: [whoisxml, whois_api, dns_lookup]
    - email_breach: [hibp, dehashed, leakcheck]
    - ip_geolocation: [ipapi, ipgeolocation, ipinfo]
```

### B. M Drive Memory System
**File:** `/home/user/prometheus-prime/prometheus_memory.py` (355 lines)

**Persistent Storage:**
```python
class PrometheusMemory:
    SQLite Tables:
    1. operations - Operation tracking
       - timestamp, capability, command, target, success, output
       
    2. targets - Target database
       - ip_address, hostname, authorized flag, operations count
       
    3. credentials - Encrypted credential vault
       - source, target, username, credential_type, credential_value
       
    4. intelligence - Intelligence reports
       - category, target, title, severity, tags
       
    Environment Variables:
    - PROMETHEUS_MEMORY_PATH (default: M:\MEMORY_ORCHESTRATION)
    - PROMETHEUS_COMMANDER
    - PROMETHEUS_AUTHORITY_LEVEL
```

### C. Scope Gate Validation
**File:** `/home/user/prometheus-prime/scope_gate.py`

**Security Functions:**
```python
class ScopeViolation(PermissionError):
    # Raised when target is out of scope

def enforce_scope(target: str, port: int = None, protocol: str = None):
    # Validates CIDR ranges
    # Validates domain names
    # Validates port ranges
    # Blocks unauthorized operations
    # Hard-block mode prevents all out-of-scope activities
```

### D. Cryptographic Operations
**File:** `/home/user/prometheus-prime/crypto/crypto_exploits.py`

**Capabilities:**
- Hash cracking (MD5, SHA256)
- RSA key factorization
- Padding oracle attacks
- Entropy analysis
- Rainbow table generation
- Cryptocurrency analysis

**Libraries Used:**
```python
from Crypto.Cipher import AES, DES, DES3
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
```

### E. Data Caching & Storage
Multiple modules use SQLite for:
- Phone number caching (30-day TTL)
- OSINT database storage
- Operation tracking
- Credential vault

---

## 7. KEY ARCHITECTURAL PATTERNS

### Pattern 1: Module Initialization
All OSINT modules follow pattern:
```python
class ModuleClass:
    def __init__(self):
        load_dotenv()                    # Load .env
        initialize_client()              # Init external client
        setup_database()                 # SQLite cache
        print("✅ Module initialized")
```

### Pattern 2: Error Handling & Recovery
```python
from gs343_gateway import with_phoenix_retry

@with_phoenix_retry
def operation():
    try:
        result = external_api_call()
    except Exception as e:
        healing = gs343.heal_phoenix(error, context)
        if 'try_fallback_api' in healing['auto_actions']:
            result = fallback_api_call()
```

### Pattern 3: Scope Validation
```python
from scope_gate import enforce_scope, ScopeViolation

def sensitive_operation(target: str):
    try:
        enforce_scope(target)
    except ScopeViolation:
        return {"error": "Target out of scope"}
    
    # Proceed with operation
```

### Pattern 4: MCP Tool Definition
```python
Tool(
    name="tool_name",
    description="What it does",
    inputSchema={
        "type": "object",
        "properties": {
            "param1": {"type": "string", "description": "..."},
            "param2": {"type": "boolean", "default": True}
        },
        "required": ["param1"]
    }
)
```

---

## 8. DEPENDENCIES & IMPORTS

### Core Libraries Used
```
mcp                      # Model Context Protocol
requests                 # HTTP requests
flask, fastapi          # HTTP servers
python-dotenv           # Environment loading
twilio                  # Phone API
beautifulsoup4          # HTML parsing
dnspython               # DNS queries
pymysql                 # MySQL connections
cryptography            # Encryption primitives
Crypto (pycryptodome)   # Cryptographic operations
```

### External Tools Integration
- Nmap - Network scanning
- Metasploit - Exploitation framework
- Hashcat - Password cracking
- Impacket - Network protocols
- Shodan/VirusTotal - Threat intelligence

---

## 9. DOCUMENTATION STRUCTURE

Key documentation files:
- `README.md` - Main overview
- `COMPLETE_STATUS.md` - Full capabilities list
- `PROMETHEUS_PRIME_STATUS.md` - Status report
- `MCP_SERVER_SETUP_PROMPT.md` - MCP configuration guide
- `CLAUDE_CODE_INTEGRATION.md` - Claude integration guide
- `PROMETHEUS_COGNITIVE_INTEGRATION_MISSION.md` - Advanced integration details
- `PROMETHEUS_PRIME_SKILL_MANIFEST.md` - Skill definitions

---

## 10. INTEGRATION POINTS FOR PROMETHIAN VAULT ADDON

### Recommended Integration Points:

1. **Crypto Module Enhancement**
   - Location: `/home/user/prometheus-prime/crypto/`
   - Add vault encryption/decryption operations
   - Integrate with existing CryptoExploiter class

2. **Memory System Integration**
   - Location: `/home/user/prometheus-prime/prometheus_memory.py`
   - Add vault credentials table
   - Integrate with credentials vault schema

3. **Scope Gate Enhancement**
   - Location: `/home/user/prometheus-prime/scope_gate.py`
   - Add vault access control validation
   - Ensure vault operations respect scope

4. **MCP Tools Addition**
   - Location: `/home/user/prometheus-prime/prometheus_prime_mcp.py`
   - Add vault management tools
   - Register 5-10 new tools for vault operations

5. **Configuration Extension**
   - Location: `/home/user/prometheus-prime/configs/default.yaml`
   - Add vault configuration section
   - Add feature flags for vault operations

6. **API Server Enhancement**
   - Location: `/home/user/prometheus-prime/osint_api_server.py`
   - Add /api/vault endpoints for HTTP access
   - Integrate with Flask API framework

---

## SUMMARY

The Prometheus Prime codebase is a highly modular, professionally organized security operations platform with:

- **29 Python core modules** + **28 capability modules** = **57 total Python files**
- **Clear separation of concerns** (OSINT, Network, Mobile, Web, Exploitation)
- **Robust configuration system** (YAML + .env + environment overrides)
- **Built-in security features** (Scope validation, Phoenix healing, M Drive memory)
- **Encryption capabilities** (AES, RSA, Hash cracking)
- **MCP server architecture** with standardized tool definitions
- **Comprehensive documentation** and multiple integration guides

For integrating the Promethian Vault addon:
- Follow the modular patterns established in existing modules
- Use the same configuration/logging patterns
- Leverage GS343 for error handling
- Implement scope validation for vault access
- Add new MCP tools following the standard Tool schema
- Integrate with prometheus_memory.py for persistent storage
