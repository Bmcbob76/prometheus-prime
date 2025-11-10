#!/usr/bin/env python3
"""
PROMETHIAN VAULT - MAIN ADDON MODULE
Pentagon-Level Security for Sensitive Data
Authority Level: 11.0

Commander: Bobby Don McWilliams II

FEATURES:
🔐 AES-256-GCM + RSA-4096 encryption
🛡️  Multi-layer defense with intrusion detection
🍯 Honeypot secrets to trap attackers
🔒 Auto-lockdown on suspicious activity
📊 Complete audit trail
💾 Encrypted backups
🚨 Counter-defense mechanisms

PROTECTED DATA TYPES:
- API Keys (OpenAI, Anthropic, etc.)
- Crypto Wallet Seeds & Private Keys
- Passwords & Credentials
- Certificates & SSH Keys
- Tokens & Session Data
- Any sensitive information
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from dotenv import load_dotenv

# Prometheus Prime imports
try:
    from gs343_gateway import gs343, with_phoenix_retry
except ImportError:
    # Fallback if GS343 not available
    def with_phoenix_retry(func):
        return func
    class GS343Fallback:
        def heal_phoenix(self, error, context):
            return {"suggestions": [], "auto_actions": []}
    gs343 = GS343Fallback()

# Vault imports
from vault_encryption import VaultEncryption
from vault_storage import VaultStorage

log = logging.getLogger("PROMETHEUS-PRIME.VaultAddon")


class PromethianVault:
    """
    Main Promethian Vault System

    Pentagon-level security for all sensitive data including:
    - API keys
    - Cryptocurrency wallets
    - Passwords
    - Certificates
    - Tokens
    - Any secret data

    Security Architecture:
    1. AES-256-GCM authenticated encryption
    2. PBKDF2-HMAC-SHA512 key derivation (600k iterations)
    3. RSA-4096 for key exchange
    4. HMAC-SHA512 integrity verification
    5. Tamper detection
    6. Intrusion detection with honeypots
    7. Auto-lockdown on attacks
    8. Complete audit trail
    """

    def __init__(
        self,
        vault_path: Optional[str] = None,
        master_password: Optional[str] = None,
        config: Optional[Dict] = None
    ):
        """
        Initialize Promethian Vault

        Args:
            vault_path: Path to vault directory
            master_password: Master password
            config: Configuration dictionary
        """
        load_dotenv()

        # Load configuration
        self.config = config or self._load_config()

        # Initialize storage
        self.storage = VaultStorage(
            vault_path=vault_path or self.config.get('vault_path'),
            master_password=master_password or os.getenv('VAULT_MASTER_PASSWORD')
        )

        # Statistics
        self.stats = {
            "operations_total": 0,
            "operations_successful": 0,
            "operations_failed": 0,
            "intrusions_detected": 0,
            "lockdowns_triggered": 0
        }

        log.info("🔐 PROMETHIAN VAULT INITIALIZED")
        print("\n" + "="*60)
        print("🔐 PROMETHIAN VAULT - PENTAGON-LEVEL SECURITY ACTIVE")
        print("="*60)
        print("✅ AES-256-GCM Encryption")
        print("✅ RSA-4096 Key Protection")
        print("✅ Intrusion Detection Active")
        print("✅ Honeypot Defenses Deployed")
        print("✅ Auto-Lockdown Enabled")
        print("="*60 + "\n")

    def _load_config(self) -> Dict:
        """Load vault configuration"""
        try:
            from config_loader import load_config
            cfg = load_config()
            return cfg.get('vault', {
                'enabled': True,
                'vault_path': os.path.expanduser('~/.promethian_vault'),
                'max_failed_attempts': 5,
                'lockdown_duration_hours': 1
            })
        except ImportError:
            return {
                'enabled': True,
                'vault_path': os.path.expanduser('~/.promethian_vault'),
                'max_failed_attempts': 5,
                'lockdown_duration_hours': 1
            }

    # =================================================================
    # CORE VAULT OPERATIONS
    # =================================================================

    def store(
        self,
        name: str,
        value: str,
        secret_type: str = "credential",
        tags: Optional[List[str]] = None,
        user: str = "system"
    ) -> Dict[str, Any]:
        """
        Store encrypted secret in vault

        Args:
            name: Secret name (unique identifier)
            value: Secret value to encrypt
            secret_type: Type (api_key, password, crypto_wallet, certificate, token)
            tags: Optional tags for organization
            user: User storing the secret

        Returns:
            Result dictionary with success status

        Example:
            >>> vault.store("openai_key", "sk-...", "api_key", ["ai", "production"])
        """
        self.stats["operations_total"] += 1

        try:
            log.info(f"📥 Storing secret: {name} ({secret_type})")

            result = self.storage.store_secret(
                secret_name=name,
                secret_value=value,
                secret_type=secret_type,
                tags=tags,
                user=user
            )

            if result["success"]:
                self.stats["operations_successful"] += 1
                print(f"✅ Secret stored: {name}")
            else:
                self.stats["operations_failed"] += 1

            return result

        except Exception as e:
            self.stats["operations_failed"] += 1
            log.error(f"❌ Store failed: {e}")

            # Phoenix healing
            healing = gs343.heal_phoenix(str(e), {
                "module": "VaultAddon",
                "operation": "store",
                "secret_name": name
            })

            return {
                "success": False,
                "error": str(e),
                "healing_suggestions": healing.get("suggestions", [])
            }

    def retrieve(self, name: str, user: str = "system") -> Dict[str, Any]:
        """
        Retrieve and decrypt secret from vault

        Args:
            name: Secret name
            user: User retrieving the secret

        Returns:
            Decrypted secret value

        Example:
            >>> result = vault.retrieve("openai_key")
            >>> api_key = result["secret_value"]
        """
        self.stats["operations_total"] += 1

        try:
            log.info(f"📤 Retrieving secret: {name}")

            result = self.storage.retrieve_secret(secret_name=name, user=user)

            if result["success"]:
                self.stats["operations_successful"] += 1
                print(f"✅ Secret retrieved: {name}")
            else:
                self.stats["operations_failed"] += 1

            return result

        except Exception as e:
            self.stats["operations_failed"] += 1
            log.error(f"❌ Retrieve failed: {e}")

            healing = gs343.heal_phoenix(str(e), {
                "module": "VaultAddon",
                "operation": "retrieve",
                "secret_name": name
            })

            return {
                "success": False,
                "error": str(e),
                "healing_suggestions": healing.get("suggestions", [])
            }

    def list(self, user: str = "system", show_honeypots: bool = False) -> Dict[str, Any]:
        """
        List all secrets in vault

        Args:
            user: User requesting list
            show_honeypots: Include honeypot secrets

        Returns:
            List of secret metadata
        """
        return self.storage.list_secrets(user=user, include_honeypots=show_honeypots)

    def delete(self, name: str, user: str = "system") -> Dict[str, Any]:
        """
        Securely delete secret from vault

        Args:
            name: Secret name
            user: User deleting

        Returns:
            Result dictionary
        """
        self.stats["operations_total"] += 1

        try:
            result = self.storage.delete_secret(secret_name=name, user=user)

            if result["success"]:
                self.stats["operations_successful"] += 1
                print(f"🗑️  Secret deleted: {name}")
            else:
                self.stats["operations_failed"] += 1

            return result

        except Exception as e:
            self.stats["operations_failed"] += 1
            return {"success": False, "error": str(e)}

    def exists(self, name: str) -> bool:
        """Check if secret exists"""
        return self.storage.secret_exists(name)

    # =================================================================
    # SPECIALIZED OPERATIONS
    # =================================================================

    def store_api_key(self, service: str, api_key: str, tags: Optional[List[str]] = None) -> Dict:
        """
        Store API key with automatic naming

        Args:
            service: Service name (e.g., "openai", "anthropic")
            api_key: API key value
            tags: Optional tags

        Example:
            >>> vault.store_api_key("openai", "sk-...", ["ai", "production"])
        """
        name = f"{service}_api_key"
        return self.store(name, api_key, "api_key", tags or [service, "api"])

    def store_password(self, service: str, username: str, password: str) -> Dict:
        """
        Store password with service and username

        Args:
            service: Service name
            username: Username/email
            password: Password

        Example:
            >>> vault.store_password("github", "user@email.com", "password123")
        """
        name = f"{service}_{username}_password"
        return self.store(name, password, "password", [service, "password", username])

    def store_crypto_wallet(
        self,
        wallet_name: str,
        seed_phrase: Optional[str] = None,
        private_key: Optional[str] = None,
        blockchain: str = "ethereum"
    ) -> Dict:
        """
        Store cryptocurrency wallet credentials

        Args:
            wallet_name: Wallet identifier
            seed_phrase: 12/24 word seed phrase
            private_key: Private key (if not using seed)
            blockchain: Blockchain type

        Example:
            >>> vault.store_crypto_wallet(
            ...     "main_wallet",
            ...     seed_phrase="word1 word2 ... word12",
            ...     blockchain="ethereum"
            ... )
        """
        if seed_phrase:
            name = f"crypto_{wallet_name}_seed"
            value = seed_phrase
            secret_type = "crypto_seed"
        elif private_key:
            name = f"crypto_{wallet_name}_privkey"
            value = private_key
            secret_type = "crypto_private_key"
        else:
            return {"success": False, "error": "Must provide seed_phrase or private_key"}

        return self.store(name, value, secret_type, [blockchain, "crypto", wallet_name])

    def store_ssh_key(self, key_name: str, private_key: str, public_key: Optional[str] = None) -> Dict:
        """
        Store SSH private key (and optionally public key)

        Args:
            key_name: Key identifier
            private_key: Private key content
            public_key: Optional public key content

        Returns:
            Result dictionary
        """
        results = []

        # Store private key
        result = self.store(
            f"ssh_{key_name}_private",
            private_key,
            "ssh_private_key",
            ["ssh", key_name, "private"]
        )
        results.append(result)

        # Store public key if provided
        if public_key:
            result = self.store(
                f"ssh_{key_name}_public",
                public_key,
                "ssh_public_key",
                ["ssh", key_name, "public"]
            )
            results.append(result)

        return {
            "success": all(r["success"] for r in results),
            "results": results
        }

    # =================================================================
    # VAULT MANAGEMENT
    # =================================================================

    def status(self) -> Dict[str, Any]:
        """
        Get vault status and statistics

        Returns:
            Complete vault status
        """
        storage_status = self.storage.get_vault_status()

        return {
            **storage_status,
            "operations": self.stats,
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA512",
                "asymmetric": "RSA-4096",
                "integrity": "HMAC-SHA512"
            }
        }

    def backup(self, backup_path: Optional[str] = None, encrypt: bool = True) -> Dict[str, Any]:
        """
        Create encrypted backup of vault

        Args:
            backup_path: Path for backup file
            encrypt: Whether to encrypt backup

        Returns:
            Backup result
        """
        try:
            import shutil
            from datetime import datetime

            if not backup_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = str(self.storage.backup_path / f"vault_backup_{timestamp}.db")

            # Copy database
            shutil.copy2(self.storage.db_path, backup_path)

            # TODO: Encrypt backup file with separate password

            log.info(f"💾 Backup created: {backup_path}")
            print(f"💾 Vault backup: {backup_path}")

            return {
                "success": True,
                "backup_path": backup_path,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            log.error(f"❌ Backup failed: {e}")
            return {"success": False, "error": str(e)}

    def unlock(self) -> Dict[str, Any]:
        """Unlock vault after lockdown"""
        if self.storage.locked:
            self.storage.locked = False
            self.storage.lockdown_until = None
            self.storage.failed_access_attempts = 0
            log.info("🔓 Vault unlocked")
            return {"success": True, "message": "Vault unlocked"}
        else:
            return {"success": True, "message": "Vault already unlocked"}

    def get_audit_log(self, limit: int = 100) -> Dict[str, Any]:
        """
        Get audit log entries

        Args:
            limit: Maximum number of entries

        Returns:
            Audit log entries
        """
        try:
            import sqlite3

            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT timestamp, action, secret_name, user, status, details
                FROM vault_audit
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

            entries = []
            for row in cursor.fetchall():
                entries.append({
                    "timestamp": row[0],
                    "action": row[1],
                    "secret_name": row[2],
                    "user": row[3],
                    "status": row[4],
                    "details": row[5]
                })

            conn.close()

            return {
                "success": True,
                "count": len(entries),
                "entries": entries
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_intrusion_log(self) -> Dict[str, Any]:
        """Get intrusion detection log"""
        try:
            import sqlite3

            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT timestamp, event_type, severity, details, action_taken
                FROM vault_intrusion_log
                ORDER BY timestamp DESC
            ''')

            entries = []
            for row in cursor.fetchall():
                entries.append({
                    "timestamp": row[0],
                    "event_type": row[1],
                    "severity": row[2],
                    "details": row[3],
                    "action_taken": row[4]
                })

            conn.close()

            self.stats["intrusions_detected"] = len(entries)

            return {
                "success": True,
                "intrusions_detected": len(entries),
                "entries": entries
            }

        except Exception as e:
            return {"success": False, "error": str(e)}


# =================================================================
# CONVENIENCE FUNCTIONS
# =================================================================

# Global vault instance
_vault_instance = None

def get_vault(master_password: Optional[str] = None) -> PromethianVault:
    """Get or create global vault instance"""
    global _vault_instance
    if _vault_instance is None:
        _vault_instance = PromethianVault(master_password=master_password)
    return _vault_instance


if __name__ == "__main__":
    # CLI interface for vault
    logging.basicConfig(level=logging.INFO)

    print("\n🔐 PROMETHIAN VAULT - Command Line Interface\n")

    vault = PromethianVault(master_password="test_password_123")

    # Demo operations
    print("\n📋 DEMO OPERATIONS:\n")

    # Store API key
    vault.store_api_key("openai", "sk-test-key-12345", ["ai", "test"])

    # Store password
    vault.store_password("github", "testuser", "password123")

    # Store crypto wallet
    vault.store_crypto_wallet(
        "main_wallet",
        seed_phrase="test seed phrase with twelve words here for testing purposes only",
        blockchain="ethereum"
    )

    # List all secrets
    print("\n📦 SECRETS IN VAULT:\n")
    result = vault.list()
    for secret in result.get("secrets", []):
        print(f"  • {secret['secret_name']} ({secret['secret_type']}) - accessed {secret['access_count']} times")

    # Get status
    print("\n📊 VAULT STATUS:\n")
    status = vault.status()
    print(json.dumps(status, indent=2, default=str))

    print("\n✅ Vault demo complete!")
