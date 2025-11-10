# PROMETHEUS PRIME - CODEBASE QUICK REFERENCE

## Architecture Overview Diagram

```
PROMETHEUS PRIME ECOSYSTEM
=================================

┌─────────────────────────────────────────────────────────────────┐
│                      MCP INTERFACE LAYER                        │
│  prometheus_prime_mcp.py (608 lines) + 43 Tools + HTTP API    │
└────────────┬────────────────────────────────────────────────────┘
             │
        ┌────┴────────────────────────────────────────────────────┐
        │                                                          │
┌───────▼─────────────┐  ┌──────────────────────┐  ┌────────────┐│
│ OSINT LAYER         │  │ SECURITY LAYER       │  │ CONTROL    ││
│ (6 modules)         │  │ (3 modules)          │  │ LAYER      ││
├─────────────────────┤  ├──────────────────────┤  ├────────────┤│
│ Phone Intelligence  │  │ Network Security     │  │ Mobile     ││
│ Social OSINT        │  │ Web Security         │  │ Control    ││
│ Domain Intel        │  │ Exploitation FW      │  │            ││
│ Email Intel         │  │                      │  │ iOS/Android││
│ IP Intel            │  │                      │  │ Control    ││
│ Network Security    │  │                      │  │            ││
└─────────────────────┘  └──────────────────────┘  └────────────┘│
        │                        │                        │        │
        └────────────┬───────────┴────────────┬──────────┘        │
                     │                        │                    │
        ┌────────────▼────────────┐  ┌────────▼─────────────────┐ │
        │ INFRASTRUCTURE LAYER     │  │ CAPABILITIES LAYER       │ │
        ├──────────────────────────┤  ├──────────────────────────┤ │
        │ Memory (M Drive)         │  │ Red Team Arsenal (28 mod)│ │
        │ Config Management        │  │ ├─ Recon                │ │
        │ Scope Validation         │  │ ├─ AD Attacks           │ │
        │ Phoenix Healing (GS343)  │  │ ├─ Exploitation         │ │
        │ Crypto Operations        │  │ ├─ Evasion              │ │
        │ Logging & Audit          │  │ ├─ Persistence          │ │
        │ HTTP API Server          │  │ ├─ Lateral Movement     │ │
        └──────────────────────────┘  │ ├─ Post-Exploitation    │ │
                                       │ └─ Reporting            │ │
                                       └──────────────────────────┘ │
        ┌────────────────────────────────────────────────────────┐ │
        │ SPECIALIZED MODULES                                    │ │
        ├──────────────────┬──────────────────┬──────────────────┤ │
        │ AI/ML Exploits   │ Automotive (CAN) │ ICS/SCADA        │ │
        │ Quantum Ops      │ Arsenal Toolkit  │ Orange CD Tools  │ │
        └──────────────────┴──────────────────┴──────────────────┘ │
└──────────────────────────────────────────────────────────────────┘

        ┌─────────────────────────────────────┐
        │ CONFIGURATION & SECURITY            │
        ├─────────────────────────────────────┤
        │ .env (API Keys)                     │
        │ default.yaml (Features/Paths)       │
        │ example_scope.yaml (Lab Scope)      │
        │ SQLite Databases (caches + memory)  │
        └─────────────────────────────────────┘
```

## Core Modules by Category

### OSINT Modules (Intelligence Gathering)
```
Location: /home/user/prometheus-prime/*.py
Total: 6 modules (1,971 lines)

phone_intelligence.py (318 lines)
  ├── PhoneIntelligence class
  ├── Twilio CNAM lookup
  ├── Caller name caching (30-day TTL)
  ├── Carrier identification
  └── SQLite cache database

social_osint.py (293 lines)
  ├── SocialOSINT class
  ├── Reddit API integration
  ├── Username enumeration
  ├── Cross-platform correlation
  └── Google dork generation

domain_intelligence.py (379 lines)
  ├── DomainIntelligence class
  ├── WHOIS registration data
  ├── DNS record enumeration
  ├── Domain reputation scoring
  └── VirusTotal integration

email_intelligence.py (511 lines)
  ├── EmailIntelligence class
  ├── HIBP breach detection
  ├── Password compromise checking
  ├── Email validation & deliverability
  └── Disposable email detection

ip_intelligence.py (369 lines)
  ├── IPIntelligence class
  ├── Geolocation (city-level)
  ├── Shodan integration
  ├── Abuse report scoring
  └── Vulnerability detection

network_security.py (339 lines)
  ├── NetworkSecurity class
  ├── Multi-threaded port scanning
  ├── Service banner grabbing
  ├── Vulnerability detection
  └── Subnet discovery
```

### Security & Control Modules
```
Location: /home/user/prometheus-prime/*.py
Total: 3 modules (1,308 lines)

mobile_control.py (479 lines)
  ├── MobileControl class
  ├── Android (ADB) control
  │  ├── Device enumeration
  │  ├── Shell execution
  │  ├── Screenshot capture
  │  ├── App management
  │  └── File transfer
  └── iOS (libimobiledevice) control
     ├── Device enumeration
     ├── Screenshot capture
     ├── System log streaming
     └── App installation

web_security.py (408 lines)
  ├── WebSecurity class
  ├── Security header analysis
  ├── SQL injection testing (9 payloads)
  ├── XSS testing (5 payloads)
  ├── Directory bruteforce
  ├── Web crawler
  ├── SSL/TLS analysis
  └── Technology detection

exploitation_framework.py (421 lines)
  ├── ExploitationFramework class
  ├── Exploit-DB search
  ├── Payload generation (msfvenom)
  ├── Metasploit integration
  ├── Buffer overflow tools
  └── Pattern generation
```

### Infrastructure & Support Modules
```
Location: /home/user/prometheus-prime/*.py
Total: Core infrastructure modules

prometheus_prime_mcp.py (608 lines)
  ├── Main MCP Server
  ├── Tool registration
  ├── Tool execution handlers
  ├── 43 MCP tools definition
  └── Stdio communication

prometheus_memory.py (355 lines)
  ├── M Drive memory system
  ├── SQLite operations database
  ├── Target database
  ├── Credentials vault
  ├── Intelligence reports
  └── Operation tracking

gs343_gateway.py (371 lines)
  ├── Phoenix healing system
  ├── Error analysis
  ├── Healing suggestions
  ├── Fallback API chains
  ├── Retry logic (3 retries, 2x backoff)
  └── Auto-recovery actions

config_loader.py (160 lines)
  ├── YAML config loading
  ├── .env override handling
  ├── Path resolution
  ├── Feature flags
  ├── Lab scope loading
  └── Configuration validation

scope_gate.py (150+ lines)
  ├── Scope validation
  ├── CIDR validation
  ├── Domain validation
  ├── Port range checking
  ├── Protocol validation
  └── ScopeViolation exception

osint_api_server.py (364 lines)
  ├── Flask HTTP API server
  ├── 13 API endpoints
  ├── CORS support
  ├── JSON responses
  └── Error handling

logging_setup.py
  ├── Logging configuration
  ├── Log rotation
  ├── Module logging
  └── Audit logging
```

## Configuration Files

```
Location: /home/user/prometheus-prime/configs/

default.yaml (85 lines)
  ├── Agent configuration
  │  ├── name: PROMETHEUS-PRIME
  │  ├── authority_level: 9.9
  │  └── voice_character: BREE
  ├── Lab settings
  │  ├── scope_file reference
  │  ├── scope confirmation required
  │  └── hard_block_out_of_scope
  ├── Feature flags (15 total)
  │  ├── enable_recon
  │  ├── enable_vuln_scan
  │  ├── enable_ad_attacks
  │  ├── enable_reporting
  │  └── [11 more...]
  ├── Paths
  │  ├── logs_dir
  │  ├── reports_dir
  │  ├── sessions_dir
  │  ├── payloads_dir
  │  └── osint_db_path
  ├── Logging
  │  ├── level: INFO
  │  ├── file: logs/prometheus_prime.log
  │  └── rotate: false
  ├── Tools (external path configuration)
  │  ├── nmap_path
  │  ├── msfconsole_path
  │  └── hashcat_path
  └── Recon settings
     ├── Nmap defaults
     ├── DNS settings
     └── HTTP user agent

example_scope.yaml (30+ lines)
  ├── scope
  │  ├── cidrs: [lab CIDRs]
  │  ├── domains: [lab domains]
  │  ├── hosts: [specific hosts]
  │  ├── allowed_ports: [port ranges]
  │  ├── protocols: [tcp/udp]
  │  └── egress controls
  └── policy
     ├── require_confirmation
     ├── banner: LAB-ONLY
     └── hard_block_out_of_scope
```

## Environment Variables (.env)

```
Location: /home/user/prometheus-prime/.env

API CREDENTIALS:
REDDIT_CLIENT_ID=<key>
REDDIT_CLIENT_SECRET=<secret>
REDDIT_USERNAME=<username>
REDDIT_PASSWORD=<password>
WHOISXML_API_KEY=<key>
GOOGLE_API_KEY=<key>
GOOGLE_CX_ID=<id>
TWITTER_BEARER_TOKEN=<token>

[Plus 8+ more API keys for specialized services]
```

## Module Class Structure Pattern

```python
# All OSINT modules follow this pattern:

class ModuleName:
    def __init__(self):
        load_dotenv()                    # Load .env
        self.client = initialize_api()   # Init external client
        self.cache_db = setup_cache()    # SQLite cache
        print("✅ Module initialized")
    
    def _init_cache_db(self):
        """Create SQLite schema"""
        # CREATE TABLE operations
    
    def main_operation(self, target):
        """Primary operation"""
        try:
            result = external_api_call(target)
            self._cache_result(result)
            return result
        except Exception as e:
            healing = gs343.heal_phoenix(error)
            if fallback_available():
                return fallback_operation(target)
            raise
```

## MCP Tool Categories (43 Total)

```
┌─────────────────────────────────────────────────────────┐
│ OSINT (6)      │ Network (5)    │ Mobile (8)           │
├────────────────┼────────────────┼──────────────────────┤
│ prom_health    │ prom_port_scan │ prom_android_*       │
│ prom_phone_*   │ prom_nmap_scan │ prom_ios_*           │
│ prom_social_*  │ prom_vuln_scan │                      │
│ prom_domain_*  │ prom_subnet_*  │ (8 tools total)      │
│ prom_email_*   │ prom_service_* │                      │
│ prom_ip_*      │                │                      │
└────────────────┴────────────────┴──────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ Web (8)            │ Exploit (5)      │ Utility (2)     │
├────────────────────┼──────────────────┼─────────────────┤
│ prom_web_headers   │ prom_search_*    │ prom_osint_full │
│ prom_sql_inject    │ prom_generate_*  │ prom_healing_*  │
│ prom_xss_test      │ prom_list_*      │                 │
│ prom_dir_brute     │ prom_pattern_*   │                 │
│ prom_web_crawl     │ prom_msf_search  │                 │
│ prom_ssl_scan      │                  │                 │
│ prom_tech_detect   │                  │                 │
│ prom_web_comp      │                  │                 │
└────────────────────┴──────────────────┴─────────────────┘
```

## Capabilities Module (28 Python Files)

```
/home/user/prometheus-prime/capabilities/

Reconnaissance (5 modules)
  ├── red_team_core.py
  ├── red_team_recon.py
  ├── recon_nmap.py
  └── ...

Offensive Operations (8 modules)
  ├── red_team_exploits.py
  ├── red_team_ad_attacks.py
  ├── red_team_c2.py
  ├── red_team_persistence.py
  └── ...

Defensive Operations (6 modules)
  ├── red_team_evasion.py
  ├── red_team_mimikatz.py
  ├── red_team_obfuscation.py
  └── ...

Post-Exploitation (5 modules)
  ├── red_team_post_exploit.py
  ├── red_team_metasploit.py
  ├── lateral_movement.py
  └── ...

Specialized Exploits (4 modules)
  ├── biometric_bypass.py
  ├── cloud_exploits.py
  ├── mobile_exploits.py
  └── password_attacks.py
```

## Key Design Patterns

### Pattern 1: Module Initialization
```python
# Standard init in all OSINT modules
self.cache_db = Path(db_path)
self.cache_db.parent.mkdir(parents=True, exist_ok=True)
self._init_cache_db()
```

### Pattern 2: Error Recovery
```python
from gs343_gateway import with_phoenix_retry

@with_phoenix_retry
def operation():
    # Auto-retry with exponential backoff
    # Fallback chains if available
```

### Pattern 3: Scope Validation
```python
from scope_gate import enforce_scope, ScopeViolation

enforce_scope(target)  # Raises if out of scope
```

### Pattern 4: SQLite Caching
```python
# All modules use local SQLite for:
- API response caching (with TTL)
- Credential storage
- Operation history
- Intelligence records
```

## Dependencies Summary

### Core Python Libraries
- `mcp` - Model Context Protocol
- `flask` - HTTP server
- `requests` - HTTP requests
- `python-dotenv` - Environment loading
- `cryptography` - Encryption
- `pycryptodome` - Crypto operations
- `beautifulsoup4` - HTML parsing
- `dnspython` - DNS queries
- `twilio` - Phone API
- `pymysql` - Database

### External Tools
- Nmap - Network scanning
- Metasploit - Exploitation
- Hashcat - Password cracking
- Impacket - Protocol handling
- Shodan/VirusTotal APIs - Threat intel

## File Size Reference

| File | Lines | Size |
|------|-------|------|
| gs343_comprehensive_scanner_*.py | 768 | 22KB |
| PROMETHEUS_PRIME_ULTIMATE_ENHANCED.py | 715 | 19KB |
| prometheus_voice_bridge.py | 648 | 18KB |
| prometheus_prime_mcp.py | 608 | 17KB |
| email_intelligence.py | 511 | 14KB |
| mobile_control.py | 479 | 13KB |
| exploitation_framework.py | 421 | 12KB |
| web_security.py | 408 | 11KB |
| domain_intelligence.py | 379 | 11KB |
| gs343_gateway.py | 371 | 10KB |

## Quick Navigation

Find implementation for:
| Functionality | File | Class |
|--------------|------|-------|
| Phone lookup | phone_intelligence.py | PhoneIntelligence |
| Domain WHOIS | domain_intelligence.py | DomainIntelligence |
| Email breach | email_intelligence.py | EmailIntelligence |
| IP geolocation | ip_intelligence.py | IPIntelligence |
| Port scanning | network_security.py | NetworkSecurity |
| Mobile control | mobile_control.py | MobileControl |
| Web security | web_security.py | WebSecurity |
| Exploitation | exploitation_framework.py | ExploitationFramework |
| MCP tools | prometheus_prime_mcp.py | Server/Tools |
| Memory/DB | prometheus_memory.py | PrometheusMemory |
| Error healing | gs343_gateway.py | GS343Gateway |
| Scope validation | scope_gate.py | ScopeViolation |
| Configuration | config_loader.py | load_config() |

---

**Total Codebase: 57 Python files, 9,236 lines of code, highly modular architecture**
