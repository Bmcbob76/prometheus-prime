# PROMETHIAN VAULT - TECHNICAL INTEGRATION SPECIFICATION

## Quick Reference for Integration

### 1. Module Class Template (Follow This Pattern)

All security modules in Prometheus Prime follow this pattern:

```python
#!/usr/bin/env python3
"""
VAULT_ADDON - Module Description
Authority Level: 11.0
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Get logger for this module
log = logging.getLogger("PROMETHEUS-PRIME.VaultAddon")

class VaultAddon:
    """Main vault addon class"""
    
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Initialize configuration
        self.vault_enabled = os.getenv('VAULT_ENABLED', 'true').lower() == 'true'
        self.vault_path = os.getenv('VAULT_PATH', os.path.join(Path.home(), '.vault'))
        
        # Create vault directory
        Path(self.vault_path).mkdir(parents=True, exist_ok=True)
        
        # Initialize database/storage
        self._init_storage()
        
        log.info("✅ Vault Addon initialized")
        print("✅ Vault Addon initialized")
    
    def _init_storage(self):
        """Initialize vault storage (SQLite, filesystem, etc)"""
        pass
    
    def vault_operation(self, target: str) -> Dict[str, Any]:
        """
        Main vault operation
        
        Args:
            target: Target for operation
            
        Returns:
            Operation result
        """
        try:
            # Validate scope
            from scope_gate import enforce_scope, ScopeViolation
            try:
                enforce_scope(target)
            except ScopeViolation:
                return {"error": "Target out of scope", "code": 403}
            
            # Core operation
            result = self._execute_operation(target)
            
            return {
                "success": True,
                "target": target,
                "data": result
            }
        
        except Exception as e:
            # Use Phoenix healing for error recovery
            from gs343_gateway import gs343
            healing = gs343.heal_phoenix(str(e), {"module": "VaultAddon"})
            
            return {
                "success": False,
                "error": str(e),
                "healing_suggestions": healing['suggestions']
            }
    
    def _execute_operation(self, target: str) -> Dict:
        """Core operation implementation"""
        pass
```

### 2. MCP Tool Registration Template

Add to `prometheus_prime_mcp.py`:

```python
# ========== VAULT TOOLS ==========
Tool(
    name="prom_vault_status",
    description="Check Promethian Vault status and health",
    inputSchema={
        "type": "object",
        "properties": {},
        "required": []
    }
),
Tool(
    name="prom_vault_store",
    description="Store credential/secret in vault",
    inputSchema={
        "type": "object",
        "properties": {
            "secret_name": {"type": "string", "description": "Name of secret"},
            "secret_value": {"type": "string", "description": "Secret value"},
            "secret_type": {"type": "string", "enum": ["credential", "api_key", "token"]}
        },
        "required": ["secret_name", "secret_value", "secret_type"]
    }
),
Tool(
    name="prom_vault_retrieve",
    description="Retrieve secret from vault",
    inputSchema={
        "type": "object",
        "properties": {
            "secret_name": {"type": "string", "description": "Name of secret"}
        },
        "required": ["secret_name"]
    }
),
Tool(
    name="prom_vault_list",
    description="List all secrets in vault",
    inputSchema={
        "type": "object",
        "properties": {},
        "required": []
    }
),
Tool(
    name="prom_vault_delete",
    description="Delete secret from vault",
    inputSchema={
        "type": "object",
        "properties": {
            "secret_name": {"type": "string", "description": "Name of secret"}
        },
        "required": ["secret_name"]
    }
),
```

Then add handler in `@app.call_tool()`:

```python
elif name == "prom_vault_status":
    result = vault_addon.vault_status()
    return [TextContent(type="text", text=json.dumps(result, indent=2))]

elif name == "prom_vault_store":
    result = vault_addon.vault_store(
        arguments['secret_name'],
        arguments['secret_value'],
        arguments['secret_type']
    )
    return [TextContent(type="text", text=json.dumps(result, indent=2))]

elif name == "prom_vault_retrieve":
    result = vault_addon.vault_retrieve(arguments['secret_name'])
    return [TextContent(type="text", text=json.dumps(result, indent=2))]

elif name == "prom_vault_list":
    result = vault_addon.vault_list()
    return [TextContent(type="text", text=json.dumps(result, indent=2))]

elif name == "prom_vault_delete":
    result = vault_addon.vault_delete(arguments['secret_name'])
    return [TextContent(type="text", text=json.dumps(result, indent=2))]
```

### 3. Configuration Extension

Add to `configs/default.yaml`:

```yaml
vault:
  enabled: true
  path: ~/.vault
  database_path: ~/.vault/vault.db
  encryption_method: AES-256
  features:
    enable_credential_storage: true
    enable_api_key_management: true
    enable_secret_rotation: false
    enable_audit_logging: true
  
  # Vault access control
  access_control:
    require_scope_check: true
    require_authentication: true
    require_confirmation: false
  
  # Encryption settings
  encryption:
    algorithm: AES-256-CBC
    key_derivation: PBKDF2
    iterations: 100000
```

### 4. Memory Integration

Add to `prometheus_memory.py`:

```python
# In PrometheusMemory.__init__():
def _init_vault_schema(self):
    """Initialize vault-related tables"""
    cursor = self.conn.cursor()
    
    # Vault credentials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_name TEXT UNIQUE NOT NULL,
            secret_type TEXT NOT NULL,
            encrypted_value TEXT NOT NULL,
            encryption_key_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            accessed_at TIMESTAMP,
            access_count INTEGER DEFAULT 0,
            created_by TEXT,
            authorized_users TEXT,
            tags TEXT,
            metadata TEXT
        )
    ''')
    
    # Vault audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            secret_name TEXT,
            user TEXT,
            status TEXT,
            details TEXT
        )
    ''')
    
    self.conn.commit()
```

### 5. Encryption Integration

Extend `/home/user/prometheus-prime/crypto/crypto_exploits.py`:

```python
class VaultEncryption:
    """Vault encryption operations"""
    
    def __init__(self):
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        from cryptography.hazmat.primitives import hashes
        import base64
        import os
        
        self.Fernet = Fernet
        self.PBKDF2 = PBKDF2
        self.hashes = hashes
        self.base64 = base64
        self.os = os
    
    def encrypt_secret(self, secret: str, password: str) -> str:
        """Encrypt secret with password-derived key"""
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
        
        # Derive key from password
        salt = self.os.urandom(16)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Encrypt
        cipher = Fernet(key)
        encrypted = cipher.encrypt(secret.encode())
        
        return base64.b64encode(salt + encrypted).decode()
    
    def decrypt_secret(self, encrypted: str, password: str) -> str:
        """Decrypt secret with password"""
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
        
        data = base64.b64decode(encrypted)
        salt = data[:16]
        encrypted_data = data[16:]
        
        # Derive key from password
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Decrypt
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_data).decode()
```

### 6. Scope Gate Integration

Extend `/home/user/prometheus-prime/scope_gate.py`:

```python
def enforce_vault_scope(secret_name: str, action: str = "read") -> bool:
    """
    Enforce scope on vault operations
    
    Args:
        secret_name: Name of secret being accessed
        action: Type of action (read, write, delete)
        
    Returns:
        True if allowed, raises ScopeViolation if not
    """
    # Implement vault-specific scope rules
    vault_scope = {
        'allowed_secret_types': ['credential', 'api_key'],
        'allowed_actions': ['read', 'write', 'delete'],
        'protected_secrets': []  # Secrets that require special access
    }
    
    if action not in vault_scope['allowed_actions']:
        raise ScopeViolation(f"Action '{action}' not allowed on vault")
    
    if secret_name in vault_scope['protected_secrets']:
        # Require additional authorization
        pass
    
    return True
```

### 7. API Server Integration

Add to `osint_api_server.py`:

```python
@app.route('/api/vault/status', methods=['GET'])
def vault_status():
    """Check vault status"""
    try:
        result = vault_addon.vault_status()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault/store', methods=['POST'])
def vault_store():
    """Store secret in vault"""
    try:
        data = request.json
        result = vault_addon.vault_store(
            data['secret_name'],
            data['secret_value'],
            data.get('secret_type', 'credential')
        )
        return jsonify(result), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault/retrieve/<secret_name>', methods=['GET'])
def vault_retrieve(secret_name):
    """Retrieve secret from vault"""
    try:
        result = vault_addon.vault_retrieve(secret_name)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault/list', methods=['GET'])
def vault_list():
    """List all secrets"""
    try:
        result = vault_addon.vault_list()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault/delete/<secret_name>', methods=['DELETE'])
def vault_delete(secret_name):
    """Delete secret from vault"""
    try:
        result = vault_addon.vault_delete(secret_name)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

### 8. Logging Pattern

```python
import logging

log = logging.getLogger("PROMETHEUS-PRIME.VaultAddon")

# In operations:
log.info(f"Vault operation: {action} on {secret_name}")
log.debug(f"Vault result: {result}")
log.warning(f"Vault access denied: {reason}")
log.error(f"Vault operation failed: {error}")
```

### 9. Error Handling Pattern

```python
from gs343_gateway import gs343

try:
    # Vault operation
    result = encrypt_and_store(secret)
except ConnectionError as e:
    healing = gs343.heal_phoenix(str(e), {
        "module": "VaultAddon",
        "operation": "store",
        "error_type": "connection"
    })
    log.error(f"Vault connection error: {healing['suggestions']}")
except Exception as e:
    log.error(f"Vault operation failed: {e}")
    raise
```

### 10. Directory Structure for Vault Addon

```
/home/user/prometheus-prime/
├── vault_addon.py                    # Main vault addon module
├── vault_encryption.py               # Encryption operations
├── vault_storage.py                  # Storage operations
├── vault_config.py                   # Configuration
├── vault_api.py                      # API operations
└── configs/
    └── vault_config.yaml             # Vault configuration
```

## Implementation Checklist

- [ ] Create main vault addon module (`vault_addon.py`)
- [ ] Create encryption module (`vault_encryption.py`)
- [ ] Create storage module (`vault_storage.py`)
- [ ] Add MCP tools to `prometheus_prime_mcp.py`
- [ ] Update `configs/default.yaml` with vault config
- [ ] Add vault tables to `prometheus_memory.py`
- [ ] Add vault scope validation to `scope_gate.py`
- [ ] Add API endpoints to `osint_api_server.py`
- [ ] Add feature flag to `default.yaml`
- [ ] Update documentation
- [ ] Add tests
- [ ] Update .gitignore for vault files

## File Locations Quick Reference

| Component | Location |
|-----------|----------|
| Main MCP Server | `/home/user/prometheus-prime/prometheus_prime_mcp.py` |
| Memory System | `/home/user/prometheus-prime/prometheus_memory.py` |
| Config Loader | `/home/user/prometheus-prime/config_loader.py` |
| Phoenix Healing | `/home/user/prometheus-prime/gs343_gateway.py` |
| Scope Gate | `/home/user/prometheus-prime/scope_gate.py` |
| Crypto Ops | `/home/user/prometheus-prime/crypto/crypto_exploits.py` |
| HTTP API | `/home/user/prometheus-prime/osint_api_server.py` |
| Configuration | `/home/user/prometheus-prime/configs/default.yaml` |
| Environment | `/home/user/prometheus-prime/.env` |
| Capabilities | `/home/user/prometheus-prime/capabilities/` |

## Key Import Statements for Vault Addon

```python
# Core
from pathlib import Path
from typing import Dict, Any, Optional, List
import json, os, logging
from datetime import datetime

# Prometheus Prime
from config_loader import load_config
from scope_gate import enforce_scope, ScopeViolation
from gs343_gateway import gs343, with_phoenix_retry
from prometheus_memory import PrometheusMemory

# Cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PrivateFormat, NoEncryption
)

# Database
import sqlite3

# Environment
from dotenv import load_dotenv
```

---

This specification provides everything needed to integrate the Promethian Vault addon following Prometheus Prime's established patterns and architecture.
