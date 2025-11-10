# 🔐 PROMETHIAN VAULT - COMPREHENSIVE USER MANUAL

**Version 1.0**
**For Human Users and AI Assistants**
**Authority Level: 11.0**

---

## TABLE OF CONTENTS

1. [Introduction](#introduction)
2. [Installation & Setup](#installation--setup)
3. [Basic Operations](#basic-operations)
4. [Advanced Operations](#advanced-operations)
5. [Security Operations](#security-operations)
6. [Integration Guide](#integration-guide)
7. [Command Reference](#command-reference)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)
10. [Maintenance](#maintenance)
11. [Appendices](#appendices)

---

## INTRODUCTION

### What is Promethian Vault?

The Promethian Vault is a Pentagon-level security system designed to protect sensitive data including API keys, passwords, cryptocurrency wallets, SSH keys, and certificates. It uses military-grade encryption (AES-256-GCM) with active defensive countermeasures.

### Who Should Use This Manual?

- **Human Users**: System administrators, developers, security engineers
- **AI Assistants**: Claude, ChatGPT, or other AI systems integrating with Prometheus Prime
- **Applications**: Echo Prime, custom Python programs, automated systems

### Prerequisites

- Python 3.8 or higher
- Basic understanding of command-line operations
- Access to Prometheus Prime repository
- Administrator privileges (for installation)

### Quick Start (3 Steps)

```bash
# 1. Set master password
echo "VAULT_MASTER_PASSWORD=your_super_strong_password_here" >> .env

# 2. Store a secret
python3 -c "
from vault_addon import get_vault
vault = get_vault()
vault.store_api_key('openai', 'sk-proj-YOUR_KEY_HERE', ['ai', 'production'])
print('✅ Stored')
"

# 3. Retrieve the secret
python3 -c "
from vault_addon import get_vault
vault = get_vault()
result = vault.retrieve('openai_api_key')
print(result['secret_value'])
"
```

---

## INSTALLATION & SETUP

### Step 1: Verify Installation

Check if vault modules are present:

```bash
cd /home/user/prometheus-prime
ls -la vault_*.py
```

Expected output:
```
vault_addon.py
vault_encryption.py
vault_storage.py
```

### Step 2: Install Dependencies

```bash
# Install required Python packages
pip3 install cryptography python-dotenv --break-system-packages

# Verify installation
python3 -c "import cryptography; print('✅ cryptography installed')"
python3 -c "from dotenv import load_dotenv; print('✅ python-dotenv installed')"
```

### Step 3: Create Master Password

**CRITICAL**: This is the most important step. Your master password protects everything.

**Password Requirements**:
- ✅ Minimum 20 characters
- ✅ Mix of uppercase and lowercase letters
- ✅ Include numbers
- ✅ Include special characters (!@#$%^&*)
- ✅ NOT a dictionary word
- ✅ NOT used anywhere else
- ✅ NOT written on paper

**Good Examples**:
```
Pr0m3th3us!V4ult#2024@Secure
MyS3cur3V4u1t!P4ssw0rd@2024
Th1s-Is-My-Sup3r-S3cur3-V4ult!2024
```

**Bad Examples** (DON'T USE):
```
password123          ❌ Too simple
mypassword          ❌ No numbers/symbols
Password1!          ❌ Too short
admin123            ❌ Common password
```

**Set Master Password**:

```bash
# Method 1: Add to .env file (recommended)
cd /home/user/prometheus-prime
echo "VAULT_MASTER_PASSWORD=your_super_strong_password_here" >> .env

# Verify (should show your password)
grep VAULT_MASTER_PASSWORD .env

# Method 2: Set environment variable (temporary, only for current session)
export VAULT_MASTER_PASSWORD="your_super_strong_password_here"
```

**IMPORTANT**: Add `.env` to `.gitignore` if not already:

```bash
echo ".env" >> .gitignore
```

### Step 4: Initialize Vault

```python
# test_init.py
from vault_addon import PromethianVault

# Initialize vault (creates database and honeypots)
vault = PromethianVault()

# Check status
status = vault.status()
print(f"✅ Vault initialized")
print(f"Status: {status['status']}")
print(f"Honeypots: {status['honeypots_count']}")
```

Run:
```bash
python3 test_init.py
```

Expected output:
```
🔐 Pentagon-level encryption engine initialized
✅ Database initialized with all tables
🍯 4 honeypot secrets deployed
🗄️  Vault storage initialized

============================================================
🔐 PROMETHIAN VAULT - PENTAGON-LEVEL SECURITY ACTIVE
============================================================
✅ AES-256-GCM Encryption
✅ RSA-4096 Key Protection
✅ Intrusion Detection Active
✅ Honeypot Defenses Deployed
✅ Auto-Lockdown Enabled
============================================================

✅ Vault initialized
Status: ACTIVE
Honeypots: 4
```

### Step 5: Verify Encryption Works

```python
# test_encryption.py
from vault_addon import get_vault

vault = get_vault()

# Store test secret
print("Storing test secret...")
result = vault.store(
    name="test_secret",
    value="This is my test secret!",
    secret_type="credential",
    tags=["test"]
)
print(f"Store result: {result['success']}")

# Retrieve test secret
print("\nRetrieving test secret...")
result = vault.retrieve("test_secret")
print(f"Retrieved: {result['secret_value']}")
print(f"Match: {result['secret_value'] == 'This is my test secret!'}")

# Clean up
vault.delete("test_secret")
print("\n✅ Encryption verified!")
```

### Step 6: Configure Vault (Optional)

Edit `configs/default.yaml`:

```yaml
vault:
  enabled: true
  vault_path: ~/.promethian_vault  # Change if desired

  access_control:
    max_failed_attempts: 5  # Adjust lockdown threshold
    lockdown_duration_hours: 1  # Adjust lockdown duration

  features:
    enable_honeypot_secrets: true  # Disable if not needed
    enable_auto_lockdown: true     # Disable for testing
    enable_audit_logging: true     # Always keep enabled
```

---

## BASIC OPERATIONS

### Operation 1: Store an API Key

**Syntax**:
```python
vault.store_api_key(service, api_key, tags=None)
```

**Example 1 - Store OpenAI Key**:
```python
from vault_addon import get_vault

vault = get_vault()

result = vault.store_api_key(
    service="openai",
    api_key="sk-proj-1234567890abcdefghijklmnop",
    tags=["ai", "production", "echo-prime"]
)

print(result)
# Output: {
#   'success': True,
#   'action': 'STORED',
#   'secret_name': 'openai_api_key',
#   'algorithm': 'AES-256-GCM',
#   'key_id': '9b040b3e'
# }
```

**Example 2 - Store Anthropic Key**:
```python
vault.store_api_key(
    "anthropic",
    "sk-ant-api03-1234567890abcdef",
    ["ai", "production"]
)
```

**Example 3 - Store GitHub Token**:
```python
vault.store_api_key(
    "github",
    "ghp_1234567890abcdefghijklmnop",
    ["github", "automation"]
)
```

**What Happens**:
1. Service name "openai" → stored as "openai_api_key"
2. API key encrypted with AES-256-GCM
3. Tags stored for organization
4. Audit log entry created
5. Access counter initialized to 0

### Operation 2: Store a Password

**Syntax**:
```python
vault.store_password(service, username, password)
```

**Example 1 - Store Database Password**:
```python
vault.store_password(
    service="postgresql",
    username="admin",
    password="MyS3cur3DB!P@ssw0rd"
)

# Stored as: postgresql_admin_password
```

**Example 2 - Store GitHub Password**:
```python
vault.store_password(
    service="github",
    username="user@example.com",
    password="MyGitHub!P@ss123"
)

# Stored as: github_user@example.com_password
```

**Example 3 - Store Email Password**:
```python
vault.store_password(
    service="gmail",
    username="myemail@gmail.com",
    password="AppSpecific!Password123"
)
```

### Operation 3: Store Cryptocurrency Wallet

**Syntax**:
```python
vault.store_crypto_wallet(wallet_name, seed_phrase=None, private_key=None, blockchain="ethereum")
```

**Example 1 - Store Ethereum Wallet (Seed Phrase)**:
```python
vault.store_crypto_wallet(
    wallet_name="main_ethereum_wallet",
    seed_phrase="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
    blockchain="ethereum"
)

# Stored as: crypto_main_ethereum_wallet_seed
```

**Example 2 - Store Bitcoin Wallet (Private Key)**:
```python
vault.store_crypto_wallet(
    wallet_name="bitcoin_cold_storage",
    private_key="5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss",
    blockchain="bitcoin"
)

# Stored as: crypto_bitcoin_cold_storage_privkey
```

**Example 3 - Store Multi-Chain Wallet**:
```python
# Store same wallet for different chains
vault.store_crypto_wallet("metamask", seed_phrase="...", blockchain="ethereum")
vault.store_crypto_wallet("metamask", seed_phrase="...", blockchain="polygon")
vault.store_crypto_wallet("metamask", seed_phrase="...", blockchain="arbitrum")
```

### Operation 4: Store Custom Secret

**Syntax**:
```python
vault.store(name, value, secret_type="credential", tags=None, user="system")
```

**Example 1 - Store SSH Private Key**:
```python
vault.store(
    name="production_server_ssh",
    value="""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----""",
    secret_type="ssh_private_key",
    tags=["ssh", "production", "server"]
)
```

**Example 2 - Store SSL Certificate**:
```python
vault.store(
    name="website_ssl_cert",
    value="""-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh...
-----END CERTIFICATE-----""",
    secret_type="certificate",
    tags=["ssl", "website", "production"]
)
```

**Example 3 - Store OAuth Token**:
```python
vault.store(
    name="google_oauth_token",
    value="ya29.a0AfH6SMBxyz...",
    secret_type="token",
    tags=["oauth", "google", "calendar"]
)
```

**Example 4 - Store JWT Secret**:
```python
vault.store(
    name="jwt_signing_secret",
    value="ThisIsMyJWTSecretKey!VerySecure123",
    secret_type="token",
    tags=["jwt", "authentication", "backend"]
)
```

### Operation 5: Retrieve a Secret

**Syntax**:
```python
vault.retrieve(secret_name, user="system")
```

**Example 1 - Retrieve API Key**:
```python
result = vault.retrieve("openai_api_key")

if result["success"]:
    api_key = result["secret_value"]
    print(f"API Key: {api_key}")
    print(f"Accessed {result['access_count']} times")
else:
    print(f"Error: {result['error']}")
```

**Example 2 - Retrieve Password**:
```python
result = vault.retrieve("postgresql_admin_password")

if result["success"]:
    password = result["secret_value"]
    # Use password to connect to database
    import psycopg2
    conn = psycopg2.connect(
        host="localhost",
        database="mydb",
        user="admin",
        password=password
    )
else:
    print(f"Failed to get password: {result['error']}")
```

**Example 3 - Retrieve Crypto Wallet**:
```python
result = vault.retrieve("crypto_main_ethereum_wallet_seed")

if result["success"]:
    seed_phrase = result["secret_value"]
    # NEVER log or print seed phrases!
    # Use it to restore wallet
    from eth_account import Account
    Account.enable_unaudited_hdwallet_features()
    account = Account.from_mnemonic(seed_phrase)
```

**Error Handling**:
```python
result = vault.retrieve("secret_name")

if not result["success"]:
    error = result.get("error", "Unknown error")

    if "locked" in error.lower():
        print("🚨 Vault is locked! Check intrusion log.")
    elif "not found" in error.lower():
        print("Secret doesn't exist")
    elif "authentication failed" in error.lower():
        print("Wrong master password or data corrupted")
    else:
        print(f"Error: {error}")
```

### Operation 6: List All Secrets

**Syntax**:
```python
vault.list(user="system", show_honeypots=False)
```

**Example 1 - List All Secrets**:
```python
result = vault.list()

print(f"Total secrets: {result['count']}\n")

for secret in result['secrets']:
    print(f"Name: {secret['secret_name']}")
    print(f"Type: {secret['secret_type']}")
    print(f"Created: {secret['created_at']}")
    print(f"Accessed: {secret['access_count']} times")
    print(f"Tags: {', '.join(secret['tags'])}")
    print()
```

**Example 2 - Filter by Type**:
```python
result = vault.list()

# Show only API keys
api_keys = [s for s in result['secrets'] if s['secret_type'] == 'api_key']
print("API Keys:")
for key in api_keys:
    print(f"  - {key['secret_name']}")

# Show only crypto wallets
crypto = [s for s in result['secrets'] if 'crypto' in s['secret_type']]
print("\nCrypto Wallets:")
for wallet in crypto:
    print(f"  - {wallet['secret_name']}")
```

**Example 3 - Check Last Access**:
```python
result = vault.list()

# Find unused secrets
import datetime
for secret in result['secrets']:
    if secret['access_count'] == 0:
        print(f"Never accessed: {secret['secret_name']}")

    # Check if accessed recently
    if secret['accessed_at']:
        last_access = datetime.datetime.fromisoformat(secret['accessed_at'])
        days_ago = (datetime.datetime.now() - last_access).days
        if days_ago > 90:
            print(f"Not accessed in 90+ days: {secret['secret_name']}")
```

### Operation 7: Delete a Secret

**Syntax**:
```python
vault.delete(secret_name, user="system")
```

**Example 1 - Delete Secret**:
```python
result = vault.delete("old_api_key")

if result["success"]:
    print(f"✅ Deleted: {result['secret_name']}")
else:
    print(f"❌ Failed: {result['error']}")
```

**Example 2 - Delete with Confirmation**:
```python
secret_name = "important_password"

# Confirm before deleting
confirm = input(f"Delete '{secret_name}'? (yes/no): ")
if confirm.lower() == "yes":
    result = vault.delete(secret_name)
    print(f"{'✅' if result['success'] else '❌'} {result}")
else:
    print("Deletion cancelled")
```

**What Happens During Delete**:
1. Data overwritten with random bytes (7 passes)
2. Database record updated with random data
3. Record deleted from database
4. Audit log entry created
5. Operation logged with timestamp

**⚠️ WARNING**: Deletion is permanent! Always create backup first.

### Operation 8: Check Vault Status

**Syntax**:
```python
vault.status()
```

**Example**:
```python
status = vault.status()

print(f"Vault Status: {status['status']}")
print(f"Secrets: {status['secrets_count']}")
print(f"Honeypots: {status['honeypots_count']}")
print(f"Recent Events: {status['recent_events_24h']}")
print(f"Intrusions: {status['intrusions_detected']}")
print(f"Database Size: {status['database_size']:,} bytes")
print()
print("Encryption:")
print(f"  Algorithm: {status['encryption']['algorithm']}")
print(f"  Key Derivation: {status['encryption']['key_derivation']}")
print(f"  Asymmetric: {status['encryption']['asymmetric']}")
print(f"  Integrity: {status['encryption']['integrity']}")
```

---

## ADVANCED OPERATIONS

### Advanced 1: Batch Store Multiple Secrets

```python
from vault_addon import get_vault

vault = get_vault()

# Define all secrets
secrets = {
    "api_keys": [
        {"service": "openai", "key": "sk-proj-...", "tags": ["ai"]},
        {"service": "anthropic", "key": "sk-ant-...", "tags": ["ai"]},
        {"service": "elevenlabs", "key": "...", "tags": ["voice"]},
    ],
    "passwords": [
        {"service": "github", "user": "admin", "pass": "..."},
        {"service": "database", "user": "postgres", "pass": "..."},
    ],
    "custom": [
        {"name": "jwt_secret", "value": "...", "type": "token"},
        {"name": "encryption_key", "value": "...", "type": "credential"},
    ]
}

# Store all API keys
for item in secrets["api_keys"]:
    result = vault.store_api_key(
        item["service"],
        item["key"],
        item["tags"]
    )
    print(f"✅ Stored {item['service']}")

# Store all passwords
for item in secrets["passwords"]:
    result = vault.store_password(
        item["service"],
        item["user"],
        item["pass"]
    )
    print(f"✅ Stored {item['service']} password")

# Store custom secrets
for item in secrets["custom"]:
    result = vault.store(
        item["name"],
        item["value"],
        item["type"]
    )
    print(f"✅ Stored {item['name']}")

print(f"\n✅ Stored {len(secrets['api_keys']) + len(secrets['passwords']) + len(secrets['custom'])} secrets")
```

### Advanced 2: Bulk Retrieve with Caching

```python
class VaultCache:
    """Cache for frequently accessed secrets"""

    def __init__(self, ttl_seconds=3600):
        import time
        self.cache = {}
        self.ttl = ttl_seconds
        self.vault = get_vault()
        self.time = time

    def get(self, secret_name):
        """Get secret from cache or vault"""
        now = self.time.time()

        # Check cache
        if secret_name in self.cache:
            value, timestamp = self.cache[secret_name]
            if now - timestamp < self.ttl:
                return value  # Cache hit

        # Cache miss - retrieve from vault
        result = self.vault.retrieve(secret_name)
        if result["success"]:
            self.cache[secret_name] = (result["secret_value"], now)
            return result["secret_value"]

        return None

    def invalidate(self, secret_name=None):
        """Clear cache"""
        if secret_name:
            self.cache.pop(secret_name, None)
        else:
            self.cache.clear()

# Usage
cache = VaultCache(ttl_seconds=3600)  # 1 hour cache

# First call: ~500ms (vault retrieval)
openai_key = cache.get("openai_api_key")

# Subsequent calls: <1ms (from cache)
openai_key = cache.get("openai_api_key")
openai_key = cache.get("openai_api_key")

# Invalidate when key is rotated
vault.store_api_key("openai", "new_key", ["ai"])
cache.invalidate("openai_api_key")
```

### Advanced 3: Secret Rotation Automation

```python
import datetime
from vault_addon import get_vault

class SecretRotation:
    """Automate secret rotation"""

    def __init__(self):
        self.vault = get_vault()

    def rotate_api_key(self, service, new_key, notify=True):
        """Rotate an API key"""
        old_result = self.vault.retrieve(f"{service}_api_key")

        if old_result["success"]:
            old_key = old_result["secret_value"]
            old_accessed = old_result["access_count"]

            # Store new key
            self.vault.store_api_key(
                service,
                new_key,
                tags=["rotated", f"rotation_date_{datetime.date.today()}"]
            )

            if notify:
                print(f"🔄 Rotated {service} API key")
                print(f"   Old key was accessed {old_accessed} times")
                print(f"   New key stored successfully")

            return True
        else:
            print(f"❌ Failed to retrieve old key: {old_result['error']}")
            return False

    def get_rotation_candidates(self, days_threshold=90):
        """Find secrets that should be rotated"""
        result = self.vault.list()
        candidates = []

        for secret in result['secrets']:
            if secret['created_at']:
                created = datetime.datetime.fromisoformat(secret['created_at'])
                age_days = (datetime.datetime.now() - created).days

                if age_days > days_threshold:
                    candidates.append({
                        "name": secret['secret_name'],
                        "age_days": age_days,
                        "type": secret['secret_type']
                    })

        return candidates

# Usage
rotator = SecretRotation()

# Find old secrets
candidates = rotator.get_rotation_candidates(days_threshold=90)
print(f"Secrets older than 90 days: {len(candidates)}")
for candidate in candidates:
    print(f"  - {candidate['name']} ({candidate['age_days']} days old)")

# Rotate a key
rotator.rotate_api_key("openai", "sk-proj-NEW_KEY_HERE")
```

### Advanced 4: Conditional Access with Scope

```python
from vault_addon import get_vault

class ScopedVaultAccess:
    """Restrict vault access by scope/environment"""

    def __init__(self, environment="development"):
        self.vault = get_vault()
        self.environment = environment

    def get_secret(self, secret_name):
        """Get secret only if it matches current environment"""
        result = self.vault.list()

        # Find the secret
        secret = next(
            (s for s in result['secrets'] if s['secret_name'] == secret_name),
            None
        )

        if not secret:
            return None

        # Check if tags match environment
        tags = secret.get('tags', [])
        if self.environment not in tags and 'all' not in tags:
            print(f"❌ Secret '{secret_name}' not available in {self.environment}")
            return None

        # Retrieve if allowed
        result = self.vault.retrieve(secret_name)
        return result.get('secret_value') if result['success'] else None

# Usage
# Development environment - only gets dev secrets
dev_vault = ScopedVaultAccess(environment="development")
dev_key = dev_vault.get_secret("openai_api_key_dev")  # ✅ Works
prod_key = dev_vault.get_secret("openai_api_key_prod")  # ❌ Blocked

# Production environment - only gets prod secrets
prod_vault = ScopedVaultAccess(environment="production")
prod_key = prod_vault.get_secret("openai_api_key_prod")  # ✅ Works
```

### Advanced 5: Multi-Vault Management

```python
from vault_addon import PromethianVault

class MultiVaultManager:
    """Manage multiple vaults for different purposes"""

    def __init__(self):
        self.vaults = {
            "production": PromethianVault(
                vault_path="/secure/vault_prod",
                master_password="PRODUCTION_PASSWORD"
            ),
            "staging": PromethianVault(
                vault_path="/secure/vault_staging",
                master_password="STAGING_PASSWORD"
            ),
            "development": PromethianVault(
                vault_path="/secure/vault_dev",
                master_password="DEV_PASSWORD"
            )
        }

    def get_secret(self, environment, secret_name):
        """Get secret from specific vault"""
        if environment not in self.vaults:
            raise ValueError(f"Unknown environment: {environment}")

        vault = self.vaults[environment]
        result = vault.retrieve(secret_name)

        if result["success"]:
            return result["secret_value"]
        else:
            raise ValueError(f"Failed to retrieve: {result['error']}")

    def sync_secret(self, secret_name, from_env, to_env):
        """Copy secret between vaults"""
        # Get from source
        source_vault = self.vaults[from_env]
        result = source_vault.retrieve(secret_name)

        if not result["success"]:
            return False

        # Store in destination
        dest_vault = self.vaults[to_env]
        dest_vault.store(
            secret_name,
            result["secret_value"],
            "credential",
            tags=[f"synced_from_{from_env}"]
        )

        return True

# Usage
manager = MultiVaultManager()

# Get production API key
prod_key = manager.get_secret("production", "openai_api_key")

# Copy from staging to development
manager.sync_secret("test_api_key", "staging", "development")
```

---

## SECURITY OPERATIONS

### Security Op 1: View Audit Log

```python
from vault_addon import get_vault

vault = get_vault()

# Get last 100 operations
result = vault.get_audit_log(limit=100)

print(f"Audit Log ({result['count']} entries):\n")

for entry in result['entries']:
    status_icon = "✅" if entry['status'] == "SUCCESS" else "❌"
    print(f"{status_icon} {entry['timestamp']}")
    print(f"   Action: {entry['action']}")
    print(f"   Secret: {entry['secret_name']}")
    print(f"   User: {entry['user']}")
    print(f"   Status: {entry['status']}")
    if entry['details']:
        print(f"   Details: {entry['details']}")
    print()
```

### Security Op 2: Detect Suspicious Activity

```python
def detect_suspicious_activity(vault):
    """Analyze audit log for suspicious patterns"""
    audit = vault.get_audit_log(limit=1000)

    # Pattern 1: Multiple failed attempts
    failed_attempts = {}
    for entry in audit['entries']:
        if entry['status'] == 'ERROR':
            user = entry['user']
            failed_attempts[user] = failed_attempts.get(user, 0) + 1

    for user, count in failed_attempts.items():
        if count >= 3:
            print(f"⚠️  ALERT: {user} has {count} failed attempts")

    # Pattern 2: Access at unusual times
    import datetime
    night_access = []
    for entry in audit['entries']:
        timestamp = datetime.datetime.fromisoformat(entry['timestamp'])
        hour = timestamp.hour
        if hour < 6 or hour > 22:  # Outside 6am-10pm
            night_access.append(entry)

    if night_access:
        print(f"⚠️  ALERT: {len(night_access)} access attempts outside normal hours")

    # Pattern 3: Rapid access (potential automated attack)
    if len(audit['entries']) > 100:
        first = datetime.datetime.fromisoformat(audit['entries'][-1]['timestamp'])
        last = datetime.datetime.fromisoformat(audit['entries'][0]['timestamp'])
        duration = (last - first).total_seconds()

        if duration < 60:  # 100+ operations in under 1 minute
            print(f"⚠️  ALERT: Rapid access detected ({len(audit['entries'])} ops in {duration}s)")

    # Pattern 4: Access to multiple secrets in short time
    recent_secrets = set()
    recent_time = datetime.datetime.now() - datetime.timedelta(minutes=5)

    for entry in audit['entries']:
        timestamp = datetime.datetime.fromisoformat(entry['timestamp'])
        if timestamp > recent_time:
            recent_secrets.add(entry['secret_name'])

    if len(recent_secrets) > 10:
        print(f"⚠️  ALERT: {len(recent_secrets)} different secrets accessed in 5 minutes")

# Usage
vault = get_vault()
detect_suspicious_activity(vault)
```

### Security Op 3: Check Intrusion Log

```python
vault = get_vault()

# Get intrusion events
result = vault.get_intrusion_log()

print(f"🚨 Intrusion Log ({result['intrusions_detected']} events)\n")

if result['intrusions_detected'] > 0:
    for event in result['entries']:
        severity_icon = "🔴" if event['severity'] == "CRITICAL" else "🟡"

        print(f"{severity_icon} {event['timestamp']}")
        print(f"   Type: {event['event_type']}")
        print(f"   Severity: {event['severity']}")
        print(f"   Details: {event['details']}")
        print(f"   Action: {event['action_taken']}")
        print()

    # Take action
    print("\n⚠️  RECOMMENDED ACTIONS:")
    print("1. Review all intrusion events above")
    print("2. Identify source of suspicious activity")
    print("3. Rotate all potentially compromised secrets")
    print("4. Update master password if necessary")
    print("5. Review and strengthen access controls")
else:
    print("✅ No intrusions detected")
```

### Security Op 4: Create Encrypted Backup

```python
vault = get_vault()

# Create backup
result = vault.backup()

if result["success"]:
    print(f"✅ Backup created successfully")
    print(f"   Path: {result['backup_path']}")
    print(f"   Timestamp: {result['timestamp']}")
    print()

    # Copy to secure location
    import shutil
    secure_location = "/mnt/backup/vault_backups/"

    try:
        shutil.copy2(
            result['backup_path'],
            secure_location
        )
        print(f"✅ Backup copied to {secure_location}")
    except Exception as e:
        print(f"❌ Failed to copy: {e}")
        print(f"   Manual copy: cp {result['backup_path']} {secure_location}")
else:
    print(f"❌ Backup failed: {result['error']}")
```

### Security Op 5: Unlock Vault After Lockdown

```python
vault = get_vault()

# Check if locked
status = vault.status()

if status['status'] == 'LOCKED':
    print("🔒 Vault is currently locked")
    print(f"   Locked until: {status.get('lockdown_until', 'Unknown')}")
    print()

    # Review why it's locked
    intrusions = vault.get_intrusion_log()
    if intrusions['intrusions_detected'] > 0:
        latest = intrusions['entries'][0]
        print(f"🚨 Lockdown reason: {latest['event_type']}")
        print(f"   Details: {latest['details']}")
        print()

    # Decide whether to unlock
    print("⚠️  Before unlocking:")
    print("1. Investigate the intrusion event")
    print("2. Ensure it's not an ongoing attack")
    print("3. Rotate any potentially compromised secrets")
    print()

    confirm = input("Unlock vault? (yes/no): ")
    if confirm.lower() == "yes":
        vault.unlock()
        print("✅ Vault unlocked")
    else:
        print("Vault remains locked")
else:
    print(f"✅ Vault is {status['status']}")
```

### Security Op 6: Rotate Master Password

```python
def rotate_master_password(old_password, new_password):
    """
    Rotate master password (requires re-encrypting all secrets)

    WARNING: This is a destructive operation. Create backup first!
    """
    from vault_addon import PromethianVault

    # Create backup with old password
    print("📥 Creating backup with old password...")
    old_vault = PromethianVault(master_password=old_password)
    backup_result = old_vault.backup()
    print(f"✅ Backup: {backup_result['backup_path']}")

    # Get all secrets
    print("\n📤 Retrieving all secrets...")
    list_result = old_vault.list()
    secrets_to_migrate = []

    for secret in list_result['secrets']:
        if not secret['is_honeypot']:  # Skip honeypots
            result = old_vault.retrieve(secret['secret_name'])
            if result['success']:
                secrets_to_migrate.append({
                    'name': secret['secret_name'],
                    'value': result['secret_value'],
                    'type': secret['secret_type'],
                    'tags': secret['tags']
                })
                print(f"   Retrieved: {secret['secret_name']}")

    print(f"\n✅ Retrieved {len(secrets_to_migrate)} secrets")

    # Create new vault with new password
    print("\n🔐 Creating new vault with new password...")
    import os
    os.environ['VAULT_MASTER_PASSWORD'] = new_password

    # Delete old vault database
    import shutil
    vault_path = old_vault.storage.vault_path
    shutil.rmtree(vault_path)
    print("   Old vault deleted")

    # Initialize with new password
    new_vault = PromethianVault(master_password=new_password)
    print("   New vault initialized")

    # Re-store all secrets
    print("\n📥 Re-storing all secrets with new password...")
    for secret in secrets_to_migrate:
        new_vault.store(
            secret['name'],
            secret['value'],
            secret['type'],
            secret['tags']
        )
        print(f"   Stored: {secret['name']}")

    print(f"\n✅ Master password rotated successfully")
    print(f"✅ {len(secrets_to_migrate)} secrets re-encrypted")
    print(f"\n⚠️  Update .env with new password:")
    print(f"   VAULT_MASTER_PASSWORD={new_password}")

# Usage (BE VERY CAREFUL!)
# rotate_master_password("old_password", "new_super_strong_password")
```

---

## INTEGRATION GUIDE

### Integration 1: Echo Prime

**File**: `echo_prime_vault.py`

```python
#!/usr/bin/env python3
"""
Echo Prime with Promethian Vault Integration
"""

from vault_addon import get_vault
from openai import OpenAI
from anthropic import Anthropic

class EchoPrimeSecure:
    """Echo Prime with secure credential management"""

    def __init__(self):
        self.vault = get_vault()
        self.load_credentials()
        self.init_clients()

    def load_credentials(self):
        """Load all required credentials from vault"""
        print("🔐 Loading credentials from Promethian Vault...")

        # Define required credentials
        self.credentials = {}
        required = ["openai_api_key", "anthropic_api_key", "elevenlabs_api_key"]

        for secret_name in required:
            result = self.vault.retrieve(secret_name)
            if result["success"]:
                self.credentials[secret_name] = result["secret_value"]
                print(f"   ✅ {secret_name}")
            else:
                print(f"   ❌ {secret_name}: {result['error']}")

        print(f"✅ Loaded {len(self.credentials)}/{len(required)} credentials\n")

    def init_clients(self):
        """Initialize AI service clients"""
        if "openai_api_key" in self.credentials:
            self.openai = OpenAI(api_key=self.credentials["openai_api_key"])
            print("✅ OpenAI client initialized")

        if "anthropic_api_key" in self.credentials:
            self.anthropic = Anthropic(api_key=self.credentials["anthropic_api_key"])
            print("✅ Anthropic client initialized")

    def run(self):
        """Main Echo Prime execution"""
        print("\n🤖 Echo Prime Running...\n")

        # Your Echo Prime logic here
        # Use self.openai and self.anthropic

if __name__ == "__main__":
    echo = EchoPrimeSecure()
    echo.run()
```

### Integration 2: Environment Variables

```python
#!/usr/bin/env python3
"""
Load vault secrets into environment variables
"""

import os
from vault_addon import get_vault

def load_vault_to_env():
    """Load all vault secrets into environment"""
    vault = get_vault()

    # Map vault secrets to environment variables
    mapping = {
        "openai_api_key": "OPENAI_API_KEY",
        "anthropic_api_key": "ANTHROPIC_API_KEY",
        "elevenlabs_api_key": "ELEVENLABS_API_KEY",
        "postgresql_admin_password": "DATABASE_PASSWORD"
    }

    for vault_key, env_key in mapping.items():
        result = vault.retrieve(vault_key)
        if result["success"]:
            os.environ[env_key] = result["secret_value"]
            print(f"✅ Loaded {env_key}")
        else:
            print(f"❌ Failed to load {vault_key}")

if __name__ == "__main__":
    load_vault_to_env()

    # Now run your application
    # os.system("python your_app.py")
```

### Integration 3: Configuration Files

```python
#!/usr/bin/env python3
"""
Replace vault:// references in config files
"""

import yaml
from vault_addon import get_vault

def load_config_with_vault(config_file):
    """Load config and replace vault references"""
    with open(config_file) as f:
        config = yaml.safe_load(f)

    vault = get_vault()

    # Recursively replace vault:// references
    def replace_vault_refs(obj):
        if isinstance(obj, dict):
            return {k: replace_vault_refs(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [replace_vault_refs(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith("vault://"):
            secret_name = obj.replace("vault://", "")
            result = vault.retrieve(secret_name)
            return result["secret_value"] if result["success"] else obj
        else:
            return obj

    return replace_vault_refs(config)

# Usage
# config.yaml:
# api:
#   openai_key: vault://openai_api_key
#   anthropic_key: vault://anthropic_api_key

config = load_config_with_vault("config.yaml")
print(config)
# Output: {'api': {'openai_key': 'sk-proj-...', 'anthropic_key': 'sk-ant-...'}}
```

---

## COMMAND REFERENCE

### Python API

**Initialize**:
```python
from vault_addon import PromethianVault, get_vault

# Method 1: New instance
vault = PromethianVault()

# Method 2: Get singleton (recommended)
vault = get_vault()
```

**Store Operations**:
```python
vault.store(name, value, secret_type, tags, user)
vault.store_api_key(service, api_key, tags)
vault.store_password(service, username, password)
vault.store_crypto_wallet(wallet_name, seed_phrase, private_key, blockchain)
```

**Retrieve Operations**:
```python
vault.retrieve(secret_name, user)
vault.list(user, show_honeypots)
vault.exists(secret_name)
```

**Delete Operations**:
```python
vault.delete(secret_name, user)
```

**Management**:
```python
vault.status()
vault.backup(backup_path, encrypt)
vault.unlock()
```

**Security**:
```python
vault.get_audit_log(limit)
vault.get_intrusion_log()
```

### MCP Tools

**Available via Claude Desktop**:
```
prom_vault_status()
prom_vault_store(name, value, secret_type, tags)
prom_vault_retrieve(name)
prom_vault_list()
prom_vault_delete(name)
prom_vault_store_api_key(service, api_key, tags)
prom_vault_store_password(service, username, password)
prom_vault_store_crypto(wallet_name, seed_phrase, private_key, blockchain)
prom_vault_backup(backup_path)
prom_vault_audit_log(limit)
prom_vault_intrusion_log()
```

### Command Line

**Quick test**:
```bash
# Check vault status
python3 -c "from vault_addon import get_vault; import json; print(json.dumps(get_vault().status(), indent=2, default=str))"

# Store secret
python3 -c "from vault_addon import get_vault; print(get_vault().store('test', 'value', 'credential'))"

# Retrieve secret
python3 -c "from vault_addon import get_vault; print(get_vault().retrieve('test')['secret_value'])"

# List secrets
python3 -c "from vault_addon import get_vault; print(get_vault().list())"
```

---

## TROUBLESHOOTING

### Problem 1: "Vault not initialized"

**Symptoms**:
```
AttributeError: 'NoneType' object has no attribute 'retrieve'
```

**Cause**: Master password not set

**Solution**:
```bash
# Check if password is set
grep VAULT_MASTER_PASSWORD .env

# If not found, set it
echo "VAULT_MASTER_PASSWORD=your_strong_password" >> .env

# Verify
python3 -c "from vault_addon import get_vault; print('✅ Vault OK')"
```

### Problem 2: "Authentication failed"

**Symptoms**:
```
❌ Authentication failed for secret_name - wrong password or tampered data
```

**Causes**:
1. Wrong master password
2. Database from different password
3. Data corruption

**Solutions**:

**Check 1 - Verify password**:
```python
from vault_addon import PromethianVault

# Try with your password
vault = PromethianVault(master_password="your_password")
status = vault.status()
print(status)  # If this works, password is correct
```

**Check 2 - Restore from backup**:
```bash
# List backups
ls -lh ~/.promethian_vault/backups/

# Restore latest
cp ~/.promethian_vault/backups/vault_backup_latest.db ~/.promethian_vault/vault.db
```

**Check 3 - Create new vault**:
```bash
# Backup old database
mv ~/.promethian_vault ~/promethian_vault_old

# Initialize new vault
python3 -c "from vault_addon import PromethianVault; PromethianVault()"

# Re-store secrets manually
```

### Problem 3: "Vault is locked"

**Symptoms**:
```
{"success": false, "error": "Vault is locked"}
```

**Cause**: Auto-lockdown triggered

**Solution**:
```python
from vault_addon import get_vault

vault = get_vault()

# Check why locked
intrusions = vault.get_intrusion_log()
print(f"Intrusions: {intrusions['intrusions_detected']}")
for event in intrusions['entries']:
    print(f"  - {event['event_type']}: {event['details']}")

# Unlock (after investigating!)
vault.unlock()
```

### Problem 4: "CHECKSUM VERIFICATION FAILED"

**Symptoms**:
```
🚨 VAULT LOCKDOWN TRIGGERED: CHECKSUM VERIFICATION FAILED
```

**Cause**: Database tampered with or corrupted

**CRITICAL** - This is a serious security event!

**Solution**:
```bash
# 1. DO NOT ignore this - data may be compromised

# 2. Check intrusion log
python3 -c "from vault_addon import get_vault; print(get_vault().get_intrusion_log())"

# 3. Restore from backup immediately
cp /backup/vault_backup.db ~/.promethian_vault/vault.db

# 4. Rotate ALL secrets
# (Manually rotate all API keys, passwords, etc.)

# 5. Investigate breach
# - Review system logs
# - Check for unauthorized access
# - Scan for malware
```

### Problem 5: Slow performance

**Symptoms**:
- Each retrieve takes ~500ms

**Cause**: PBKDF2 iterations (this is intentional for security)

**Solutions**:

**Option 1 - Cache frequently used secrets**:
```python
# See "Advanced 2: Bulk Retrieve with Caching"
```

**Option 2 - Reduce iterations (NOT RECOMMENDED)**:
```python
# This weakens security!
# Only do this in development/testing

# Edit vault_encryption.py
self.PBKDF2_ITERATIONS = 100000  # Instead of 600000
```

### Problem 6: Import errors

**Symptoms**:
```
ModuleNotFoundError: No module named 'cryptography'
ModuleNotFoundError: No module named 'dotenv'
```

**Solution**:
```bash
pip3 install cryptography python-dotenv --break-system-packages

# Verify
python3 -c "import cryptography; from dotenv import load_dotenv; print('✅ OK')"
```

### Problem 7: Database locked

**Symptoms**:
```
sqlite3.OperationalError: database is locked
```

**Cause**: Another process is using the database

**Solution**:
```bash
# Find processes using database
lsof ~/.promethian_vault/vault.db

# Kill if needed
kill -9 <PID>

# Or wait for other process to finish
```

---

## BEST PRACTICES

### Practice 1: Master Password Security

**✅ DO**:
- Use 20+ characters
- Mix uppercase, lowercase, numbers, symbols
- Use passphrase: "correct-horse-battery-staple-2024-prometheus!"
- Store in password manager (1Password, Bitwarden, LastPass)
- Never share with anyone
- Rotate every 6-12 months

**❌ DON'T**:
- Use dictionary words
- Reuse from other services
- Write on paper
- Store in plaintext files
- Commit to git
- Share via email/chat

### Practice 2: Secret Organization

**Use descriptive names**:
```python
# Good
vault.store_api_key("openai_production", "sk-proj-...", ["production", "ai"])
vault.store_api_key("openai_development", "sk-proj-...", ["development", "ai"])

# Bad
vault.store_api_key("key1", "sk-proj-...", [])
vault.store_api_key("key2", "sk-proj-...", [])
```

**Use tags for organization**:
```python
# Organize by environment
vault.store("secret", "value", "credential", tags=["production"])
vault.store("secret", "value", "credential", tags=["development"])

# Organize by purpose
vault.store("secret", "value", "credential", tags=["ai", "openai"])
vault.store("secret", "value", "credential", tags=["database", "postgresql"])

# Organize by rotation schedule
vault.store("secret", "value", "credential", tags=["rotate_monthly"])
vault.store("secret", "value", "credential", tags=["rotate_quarterly"])
```

### Practice 3: Regular Backups

**Automated backup script**:
```python
#!/usr/bin/env python3
"""
Daily vault backup
Run via cron: 0 2 * * * /path/to/backup_vault.py
"""

import datetime
from vault_addon import get_vault
import shutil

vault = get_vault()

# Create backup
result = vault.backup()

if result["success"]:
    # Copy to secure location
    date_str = datetime.date.today().isoformat()
    secure_path = f"/mnt/backup/vault/vault_{date_str}.db"

    shutil.copy2(result['backup_path'], secure_path)
    print(f"✅ Backup: {secure_path}")

    # Cleanup old backups (keep last 30 days)
    import os
    import glob

    backup_dir = "/mnt/backup/vault/"
    backups = sorted(glob.glob(f"{backup_dir}/vault_*.db"))

    if len(backups) > 30:
        for old_backup in backups[:-30]:
            os.remove(old_backup)
            print(f"🗑️  Deleted old backup: {old_backup}")
```

### Practice 4: Secret Rotation Schedule

**Quarterly rotation**:
```python
# Every 90 days, rotate all API keys

import datetime

def should_rotate(secret):
    """Check if secret needs rotation"""
    created = datetime.datetime.fromisoformat(secret['created_at'])
    age_days = (datetime.datetime.now() - created).days
    return age_days > 90

vault = get_vault()
result = vault.list()

print("Secrets due for rotation:\n")
for secret in result['secrets']:
    if should_rotate(secret):
        print(f"- {secret['secret_name']} ({(datetime.datetime.now() - datetime.datetime.fromisoformat(secret['created_at'])).days} days old)")
```

### Practice 5: Audit Log Review

**Weekly security review**:
```python
#!/usr/bin/env python3
"""
Weekly security audit
"""

from vault_addon import get_vault
import datetime

vault = get_vault()

print("🔍 WEEKLY SECURITY AUDIT\n")
print("="*60)

# Check for failures
audit = vault.get_audit_log(limit=500)
failures = [e for e in audit['entries'] if e['status'] == 'ERROR']

if failures:
    print(f"\n⚠️  {len(failures)} failed operations in last 500 events")
    for fail in failures[:10]:
        print(f"   - {fail['timestamp']}: {fail['action']} on {fail['secret_name']}")

# Check for intrusions
intrusions = vault.get_intrusion_log()
if intrusions['intrusions_detected'] > 0:
    print(f"\n🚨 {intrusions['intrusions_detected']} INTRUSIONS DETECTED")
    for event in intrusions['entries']:
        print(f"   - {event['timestamp']}: {event['event_type']}")

# Check vault health
status = vault.status()
print(f"\n📊 Vault Health:")
print(f"   Status: {status['status']}")
print(f"   Secrets: {status['secrets_count']}")
print(f"   Events (24h): {status['recent_events_24h']}")

print("\n" + "="*60)
```

### Practice 6: Never Log Secrets

**✅ CORRECT**:
```python
api_key = vault.retrieve("openai_api_key")["secret_value"]

# Log that we got it, not what it is
logger.info("Retrieved OpenAI API key successfully")
logger.info(f"API key for: openai (length: {len(api_key)})")

# Use the key
client = OpenAI(api_key=api_key)
```

**❌ WRONG**:
```python
api_key = vault.retrieve("openai_api_key")["secret_value"]

# DON'T DO THIS!
print(f"API Key: {api_key}")  # ❌ Printed to console
logger.info(f"Using key: {api_key}")  # ❌ Written to log file
logging.debug(f"OpenAI key: {api_key}")  # ❌ In debug logs
```

---

## MAINTENANCE

### Monthly Tasks

**1. Create backup**:
```python
vault = get_vault()
vault.backup()
```

**2. Review audit log**:
```python
vault.get_audit_log(limit=1000)
# Check for suspicious patterns
```

**3. Check for old secrets**:
```python
result = vault.list()
for secret in result['secrets']:
    created = datetime.datetime.fromisoformat(secret['created_at'])
    age = (datetime.datetime.now() - created).days
    if age > 90:
        print(f"Consider rotating: {secret['secret_name']} ({age} days old)")
```

### Quarterly Tasks

**1. Rotate API keys**:
```python
# Get new keys from providers
# Store in vault
vault.store_api_key("openai", "new_key", ["rotated"])
```

**2. Review and cleanup**:
```python
# Delete unused secrets
result = vault.list()
for secret in result['secrets']:
    if secret['access_count'] == 0:
        print(f"Never used: {secret['secret_name']}")
        # Decide whether to keep or delete
```

**3. Test backup restoration**:
```bash
# In test environment
cp ~/.promethian_vault/vault.db /tmp/vault_original.db
cp ~/.promethian_vault/backups/latest.db ~/.promethian_vault/vault.db
# Test retrieval
# Restore original
cp /tmp/vault_original.db ~/.promethian_vault/vault.db
```

### Annual Tasks

**1. Rotate master password**:
```python
# See "Security Op 6: Rotate Master Password"
```

**2. Security audit**:
```python
# Full review of all secrets
# Check for:
# - Unused secrets
# - Old secrets (>1 year)
# - Deprecated services
# - Security incidents in audit log
```

**3. Update dependencies**:
```bash
pip3 install --upgrade cryptography python-dotenv
```

---

## APPENDICES

### Appendix A: Error Codes

| Error Message | Cause | Solution |
|---------------|-------|----------|
| "Vault not initialized" | Master password not set | Set VAULT_MASTER_PASSWORD in .env |
| "Vault is locked" | Auto-lockdown triggered | Check intrusion log, unlock if safe |
| "Authentication failed" | Wrong password or corruption | Verify password, restore from backup |
| "Secret not found" | Secret doesn't exist | Check name spelling, list all secrets |
| "Checksum verification failed" | Database tampered | CRITICAL - restore from backup, rotate all |
| "Wrong password" | Incorrect master password | Verify VAULT_MASTER_PASSWORD |
| "Database is locked" | Another process using DB | Wait or kill other process |

### Appendix B: File Locations

| File | Location | Purpose |
|------|----------|---------|
| Vault database | `~/.promethian_vault/vault.db` | Main encrypted database |
| Backups | `~/.promethian_vault/backups/` | Backup files |
| Master password | `.env` file | VAULT_MASTER_PASSWORD variable |
| Module files | `/home/user/prometheus-prime/` | vault_*.py files |
| Configuration | `configs/default.yaml` | Vault settings |

### Appendix C: Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| VAULT_MASTER_PASSWORD | Master encryption password | "MyStrong!Password123" |
| VAULT_PATH | Custom vault location | "/secure/vault" |

### Appendix D: Security Specifications

| Component | Specification |
|-----------|---------------|
| Symmetric Encryption | AES-256-GCM |
| Asymmetric Encryption | RSA-4096 |
| Key Derivation | PBKDF2-HMAC-SHA512 |
| KDF Iterations | 600,000 |
| Integrity Check | HMAC-SHA512 |
| Checksum | SHA-512 |
| Salt Size | 32 bytes (256 bits) |
| Nonce Size | 12 bytes (96 bits) |

### Appendix E: Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│              PROMETHIAN VAULT QUICK REFERENCE               │
├─────────────────────────────────────────────────────────────┤
│ SETUP                                                       │
│ $ echo "VAULT_MASTER_PASSWORD=pass" >> .env               │
│                                                             │
│ STORE                                                       │
│ vault.store_api_key("service", "key", ["tags"])           │
│ vault.store_password("service", "user", "pass")           │
│ vault.store_crypto_wallet("name", seed_phrase="...")      │
│                                                             │
│ RETRIEVE                                                    │
│ result = vault.retrieve("secret_name")                    │
│ value = result["secret_value"]                            │
│                                                             │
│ MANAGE                                                      │
│ vault.list()          # List all secrets                  │
│ vault.delete("name")  # Delete secret                     │
│ vault.status()        # Check vault status                │
│ vault.backup()        # Create backup                     │
│                                                             │
│ SECURITY                                                    │
│ vault.get_audit_log(100)     # View operations           │
│ vault.get_intrusion_log()    # View intrusions           │
│ vault.unlock()               # Unlock after lockdown     │
└─────────────────────────────────────────────────────────────┘
```

---

**END OF USER MANUAL**

**Version**: 1.0
**Last Updated**: 2024-11-09
**Authority Level**: 11.0
**Support**: Review PROMETHIAN_VAULT_BRIEF.md for technical details

---

*For additional help, see:*
- *VAULT_INTEGRATION_FOR_ECHO_PRIME.md - Echo Prime integration guide*
- *VAULT_QUICK_REFERENCE.md - One-page cheat sheet*
- *PROMETHIAN_VAULT_README.md - Feature overview*
- *examples/vault_echo_prime_example.py - Working examples*
