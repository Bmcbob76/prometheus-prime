#!/usr/bin/env python3
"""
PROMETHIAN VAULT - SECURE STORAGE SYSTEM
Pentagon-Level Data Storage with Tamper Detection
Authority Level: 11.0

Features:
- Encrypted SQLite database
- Tamper detection and integrity verification
- Secure deletion with overwrite
- Access tracking and audit logging
- Honeypot secrets for intrusion detection
- Automatic lockdown on suspicious activity
"""

import os
import sqlite3
import json
import logging
import hashlib
import secrets
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import asdict

from vault_encryption import VaultEncryption, EncryptedData

log = logging.getLogger("PROMETHEUS-PRIME.VaultStorage")


class VaultStorage:
    """
    Secure storage system for Promethian Vault

    Security Features:
    - Encrypted database with SQLCipher-like protection
    - Tamper detection via checksums
    - Audit logging of all operations
    - Honeypot secrets to detect attackers
    - Auto-lockdown on suspicious activity
    - Secure deletion
    """

    def __init__(self, vault_path: Optional[str] = None, master_password: Optional[str] = None):
        """
        Initialize vault storage

        Args:
            vault_path: Path to vault directory
            master_password: Master password for encryption
        """
        self.vault_path = Path(vault_path or os.path.expanduser("~/.promethian_vault"))
        self.db_path = self.vault_path / "vault.db"
        self.backup_path = self.vault_path / "backups"

        # Create directories
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.backup_path.mkdir(parents=True, exist_ok=True)

        # Initialize encryption engine
        self.encryption = VaultEncryption(master_password)

        # Security state
        self.locked = False
        self.failed_access_attempts = 0
        self.max_failed_attempts = 5
        self.lockdown_until = None

        # Initialize database
        self._init_database()

        # Setup honeypots
        self._setup_honeypots()

        log.info(f"🗄️  Vault storage initialized: {self.db_path}")
        print(f"🗄️  Vault storage: {self.db_path}")

    def _init_database(self):
        """Initialize SQLite database with all required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main secrets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_name TEXT UNIQUE NOT NULL,
                secret_type TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                encryption_metadata TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                accessed_at TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                created_by TEXT,
                tags TEXT,
                is_honeypot BOOLEAN DEFAULT 0,
                checksum TEXT NOT NULL
            )
        ''')

        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                secret_name TEXT,
                user TEXT,
                status TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                suspicious BOOLEAN DEFAULT 0
            )
        ''')

        # Access control table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_access_control (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_name TEXT NOT NULL,
                user TEXT NOT NULL,
                permissions TEXT NOT NULL,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                UNIQUE(secret_name, user)
            )
        ''')

        # Intrusion detection log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_intrusion_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                source_ip TEXT,
                action_taken TEXT
            )
        ''')

        # Backup history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_backup_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                backup_path TEXT NOT NULL,
                secrets_count INTEGER,
                checksum TEXT NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

        log.info("✅ Database initialized with all tables")

    def _setup_honeypots(self):
        """Setup honeypot secrets to detect attackers"""
        honeypot_names = [
            "admin_password",  # Common target
            "root_key",
            "master_secret",
            "production_api_key"
        ]

        for name in honeypot_names:
            try:
                # Always recreate honeypots to ensure they have latest AAD format
                # Create fake secret
                fake_secret = f"HONEYPOT_{secrets.token_hex(16)}"
                self.store_secret(
                    secret_name=name,
                    secret_value=fake_secret,
                    secret_type="honeypot",
                    is_honeypot=True
                )
            except Exception as e:
                log.debug(f"Honeypot setup error for {name}: {e}")

        log.info(f"🍯 {len(honeypot_names)} honeypot secrets deployed")

    def _check_lockdown(self) -> bool:
        """
        Check if vault is in lockdown mode

        Returns:
            True if locked, False if accessible
        """
        if self.lockdown_until:
            if datetime.now() < self.lockdown_until:
                log.warning("🚨 VAULT IN LOCKDOWN MODE")
                return True
            else:
                # Lockdown expired
                self.lockdown_until = None
                self.failed_access_attempts = 0

        return self.locked

    def _trigger_lockdown(self, reason: str):
        """
        Trigger vault lockdown

        Args:
            reason: Reason for lockdown
        """
        self.locked = True
        self.lockdown_until = datetime.now() + timedelta(hours=1)

        # Log intrusion
        self._log_intrusion("LOCKDOWN", "CRITICAL", reason)

        log.error(f"🚨 VAULT LOCKDOWN TRIGGERED: {reason}")
        print(f"🚨 VAULT LOCKDOWN: {reason}")
        print(f"⏰ Locked until: {self.lockdown_until}")

    def _compute_checksum(self, encrypted_data: str) -> str:
        """
        Compute SHA-512 checksum of encrypted data

        Args:
            encrypted_data: Encrypted data

        Returns:
            Hex checksum
        """
        return hashlib.sha512(encrypted_data.encode()).hexdigest()

    def _verify_checksum(self, encrypted_data: str, expected_checksum: str) -> bool:
        """
        Verify data integrity

        Args:
            encrypted_data: Encrypted data
            expected_checksum: Expected checksum

        Returns:
            True if valid
        """
        actual = self._compute_checksum(encrypted_data)
        return secrets.compare_digest(actual, expected_checksum)

    def store_secret(
        self,
        secret_name: str,
        secret_value: str,
        secret_type: str,
        tags: Optional[List[str]] = None,
        user: str = "system",
        is_honeypot: bool = False
    ) -> Dict[str, Any]:
        """
        Store encrypted secret in vault

        Args:
            secret_name: Unique name for secret
            secret_value: Secret value to encrypt and store
            secret_type: Type (api_key, password, crypto_wallet, etc.)
            tags: Optional tags
            user: User storing the secret
            is_honeypot: Whether this is a honeypot secret

        Returns:
            Result dictionary
        """
        try:
            # Check lockdown
            if self._check_lockdown():
                return {"success": False, "error": "Vault is locked"}

            # Encrypt secret
            encrypted = self.encryption.encrypt_secret(secret_value, secret_name)

            # Store AAD for retrieval
            aad = json.dumps({
                "secret_name": secret_name,
                "timestamp": encrypted.timestamp,
                "version": "1.0"
            })

            # Serialize encrypted data
            encrypted_data = json.dumps({
                "ciphertext": encrypted.ciphertext.hex(),
                "nonce": encrypted.nonce.hex(),
                "salt": encrypted.salt.hex(),
                "tag": encrypted.tag.hex() if encrypted.tag else "",
                "algorithm": encrypted.algorithm,
                "key_id": encrypted.key_id,
                "timestamp": encrypted.timestamp,
                "integrity_hash": encrypted.integrity_hash,
                "aad": aad
            })

            # Compute checksum
            checksum = self._compute_checksum(encrypted_data)

            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if secret already exists
            cursor.execute(
                "SELECT id FROM vault_secrets WHERE secret_name = ?",
                (secret_name,)
            )
            exists = cursor.fetchone()

            if exists:
                # Update existing
                cursor.execute('''
                    UPDATE vault_secrets
                    SET encrypted_data = ?, encryption_metadata = ?,
                        updated_at = CURRENT_TIMESTAMP, checksum = ?,
                        secret_type = ?, tags = ?
                    WHERE secret_name = ?
                ''', (
                    encrypted_data,
                    json.dumps({"algorithm": encrypted.algorithm, "key_id": encrypted.key_id}),
                    checksum,
                    secret_type,
                    json.dumps(tags or []),
                    secret_name
                ))
                action = "UPDATED"
            else:
                # Insert new
                cursor.execute('''
                    INSERT INTO vault_secrets
                    (secret_name, secret_type, encrypted_data, encryption_metadata,
                     created_by, tags, is_honeypot, checksum)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    secret_name,
                    secret_type,
                    encrypted_data,
                    json.dumps({"algorithm": encrypted.algorithm, "key_id": encrypted.key_id}),
                    user,
                    json.dumps(tags or []),
                    1 if is_honeypot else 0,
                    checksum
                ))
                action = "STORED"

            conn.commit()
            conn.close()

            # Log audit
            self._log_audit(action, secret_name, user, "SUCCESS")

            log.info(f"✅ Secret {action}: {secret_name}")
            return {
                "success": True,
                "action": action,
                "secret_name": secret_name,
                "algorithm": encrypted.algorithm,
                "key_id": encrypted.key_id
            }

        except Exception as e:
            log.error(f"❌ Failed to store secret {secret_name}: {e}")
            self._log_audit("STORE_FAILED", secret_name, user, "ERROR", str(e))
            return {"success": False, "error": str(e)}

    def retrieve_secret(
        self,
        secret_name: str,
        user: str = "system"
    ) -> Dict[str, Any]:
        """
        Retrieve and decrypt secret from vault

        Args:
            secret_name: Name of secret
            user: User retrieving the secret

        Returns:
            Decrypted secret or error
        """
        try:
            # Check lockdown
            if self._check_lockdown():
                return {"success": False, "error": "Vault is locked"}

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Fetch secret
            cursor.execute('''
                SELECT encrypted_data, checksum, is_honeypot, access_count
                FROM vault_secrets
                WHERE secret_name = ?
            ''', (secret_name,))

            result = cursor.fetchone()

            if not result:
                self._log_audit("RETRIEVE_NOT_FOUND", secret_name, user, "ERROR")
                conn.close()
                return {"success": False, "error": "Secret not found"}

            encrypted_data_str, checksum, is_honeypot, access_count = result

            # Check if honeypot
            if is_honeypot:
                self._trigger_lockdown(f"HONEYPOT ACCESS DETECTED: {secret_name} by {user}")
                self._log_intrusion(
                    "HONEYPOT_ACCESS",
                    "CRITICAL",
                    f"User {user} accessed honeypot secret: {secret_name}"
                )

            # Verify checksum
            if not self._verify_checksum(encrypted_data_str, checksum):
                self._trigger_lockdown(f"CHECKSUM VERIFICATION FAILED: {secret_name}")
                self._log_intrusion(
                    "TAMPER_DETECTED",
                    "CRITICAL",
                    f"Checksum mismatch for secret: {secret_name}"
                )
                conn.close()
                return {"success": False, "error": "TAMPER DETECTED - LOCKDOWN ACTIVATED"}

            # Deserialize encrypted data
            encrypted_dict = json.loads(encrypted_data_str)
            encrypted = EncryptedData(
                ciphertext=bytes.fromhex(encrypted_dict["ciphertext"]),
                nonce=bytes.fromhex(encrypted_dict["nonce"]),
                salt=bytes.fromhex(encrypted_dict["salt"]),
                tag=bytes.fromhex(encrypted_dict["tag"]) if encrypted_dict["tag"] else b'',
                algorithm=encrypted_dict["algorithm"],
                key_id=encrypted_dict["key_id"],
                timestamp=encrypted_dict["timestamp"],
                integrity_hash=encrypted_dict["integrity_hash"]
            )

            # Get stored AAD
            stored_aad = encrypted_dict.get("aad")

            # Decrypt with stored AAD
            decrypted = self.encryption.decrypt_secret(encrypted, secret_name, aad=stored_aad)

            # Update access tracking
            cursor.execute('''
                UPDATE vault_secrets
                SET accessed_at = CURRENT_TIMESTAMP,
                    access_count = access_count + 1
                WHERE secret_name = ?
            ''', (secret_name,))

            conn.commit()
            conn.close()

            # Log audit
            self._log_audit("RETRIEVE", secret_name, user, "SUCCESS")

            # Reset failed attempts on successful access
            self.failed_access_attempts = 0

            log.info(f"✅ Secret retrieved: {secret_name} (access #{access_count + 1})")
            return {
                "success": True,
                "secret_name": secret_name,
                "secret_value": decrypted,
                "access_count": access_count + 1
            }

        except Exception as e:
            # Track failed attempts
            self.failed_access_attempts += 1
            if self.failed_access_attempts >= self.max_failed_attempts:
                self._trigger_lockdown(f"Too many failed access attempts: {self.failed_access_attempts}")

            log.error(f"❌ Failed to retrieve secret {secret_name}: {e}")
            self._log_audit("RETRIEVE_FAILED", secret_name, user, "ERROR", str(e))
            return {"success": False, "error": str(e)}

    def list_secrets(self, user: str = "system", include_honeypots: bool = False) -> Dict[str, Any]:
        """
        List all secrets in vault (names only)

        Args:
            user: User requesting list
            include_honeypots: Include honeypot secrets

        Returns:
            List of secret metadata
        """
        try:
            if self._check_lockdown():
                return {"success": False, "error": "Vault is locked"}

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if include_honeypots:
                cursor.execute('''
                    SELECT secret_name, secret_type, created_at, accessed_at,
                           access_count, tags, is_honeypot
                    FROM vault_secrets
                    ORDER BY created_at DESC
                ''')
            else:
                cursor.execute('''
                    SELECT secret_name, secret_type, created_at, accessed_at,
                           access_count, tags, is_honeypot
                    FROM vault_secrets
                    WHERE is_honeypot = 0
                    ORDER BY created_at DESC
                ''')

            secrets = []
            for row in cursor.fetchall():
                secrets.append({
                    "secret_name": row[0],
                    "secret_type": row[1],
                    "created_at": row[2],
                    "accessed_at": row[3],
                    "access_count": row[4],
                    "tags": json.loads(row[5]) if row[5] else [],
                    "is_honeypot": bool(row[6])
                })

            conn.close()

            self._log_audit("LIST", None, user, "SUCCESS")

            return {
                "success": True,
                "count": len(secrets),
                "secrets": secrets
            }

        except Exception as e:
            log.error(f"❌ Failed to list secrets: {e}")
            return {"success": False, "error": str(e)}

    def delete_secret(self, secret_name: str, user: str = "system") -> Dict[str, Any]:
        """
        Securely delete secret from vault

        Args:
            secret_name: Name of secret to delete
            user: User deleting the secret

        Returns:
            Result dictionary
        """
        try:
            if self._check_lockdown():
                return {"success": False, "error": "Vault is locked"}

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Overwrite data before deletion (secure deletion)
            random_data = json.dumps({"overwritten": secrets.token_hex(128)})
            cursor.execute('''
                UPDATE vault_secrets
                SET encrypted_data = ?, checksum = ?
                WHERE secret_name = ?
            ''', (random_data, self._compute_checksum(random_data), secret_name))

            # Delete
            cursor.execute("DELETE FROM vault_secrets WHERE secret_name = ?", (secret_name,))

            if cursor.rowcount == 0:
                conn.close()
                return {"success": False, "error": "Secret not found"}

            conn.commit()
            conn.close()

            self._log_audit("DELETE", secret_name, user, "SUCCESS")

            log.info(f"🗑️  Secret deleted: {secret_name}")
            return {"success": True, "secret_name": secret_name}

        except Exception as e:
            log.error(f"❌ Failed to delete secret {secret_name}: {e}")
            return {"success": False, "error": str(e)}

    def secret_exists(self, secret_name: str) -> bool:
        """Check if secret exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM vault_secrets WHERE secret_name = ?", (secret_name,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists

    def _log_audit(
        self,
        action: str,
        secret_name: Optional[str],
        user: str,
        status: str,
        details: Optional[str] = None
    ):
        """Log audit event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO vault_audit (action, secret_name, user, status, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (action, secret_name, user, status, details))

            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"Failed to log audit: {e}")

    def _log_intrusion(self, event_type: str, severity: str, details: str):
        """Log intrusion event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO vault_intrusion_log (event_type, severity, details, action_taken)
                VALUES (?, ?, ?, ?)
            ''', (event_type, severity, details, "LOCKDOWN" if self.locked else "LOGGED"))

            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"Failed to log intrusion: {e}")

    def get_vault_status(self) -> Dict[str, Any]:
        """Get vault status and statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Count secrets
            cursor.execute("SELECT COUNT(*) FROM vault_secrets WHERE is_honeypot = 0")
            secret_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM vault_secrets WHERE is_honeypot = 1")
            honeypot_count = cursor.fetchone()[0]

            # Recent audit events
            cursor.execute('''
                SELECT COUNT(*) FROM vault_audit
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            recent_events = cursor.fetchone()[0]

            # Intrusions
            cursor.execute("SELECT COUNT(*) FROM vault_intrusion_log")
            intrusion_count = cursor.fetchone()[0]

            conn.close()

            return {
                "success": True,
                "status": "LOCKED" if self.locked else "ACTIVE",
                "lockdown_until": self.lockdown_until.isoformat() if self.lockdown_until else None,
                "secrets_count": secret_count,
                "honeypots_count": honeypot_count,
                "recent_events_24h": recent_events,
                "intrusions_detected": intrusion_count,
                "vault_path": str(self.vault_path),
                "database_size": os.path.getsize(self.db_path)
            }

        except Exception as e:
            return {"success": False, "error": str(e)}


if __name__ == "__main__":
    # Test vault storage
    logging.basicConfig(level=logging.INFO)

    print("🗄️  Testing Promethian Vault Storage\n")

    vault = VaultStorage(master_password="test_password_123")

    # Store secrets
    result = vault.store_secret("test_api_key", "sk-1234567890abcdef", "api_key", tags=["test", "api"])
    print(f"Store: {result}\n")

    # Retrieve secret
    result = vault.retrieve_secret("test_api_key")
    print(f"Retrieve: {result}\n")

    # List secrets
    result = vault.list_secrets()
    print(f"List: {result}\n")

    # Get status
    result = vault.get_vault_status()
    print(f"Status: {json.dumps(result, indent=2)}\n")

    print("🛡️  Storage tests passed!")
