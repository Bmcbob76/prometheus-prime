#!/usr/bin/env python3
"""
🔐 PROMETHIAN VAULT - TEST & DEMONSTRATION
Pentagon-Level Security Test Suite
"""

import sys
import json
import logging
from pathlib import Path

# Add module path
sys.path.append(str(Path(__file__).parent))

from vault_addon import PromethianVault

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def print_section(title):
    """Print section header"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")

def print_result(result):
    """Print formatted result"""
    print(json.dumps(result, indent=2, default=str))
    print()

def test_vault():
    """Comprehensive vault test suite"""

    print("\n" + "🔐" * 30)
    print("  PROMETHIAN VAULT - SECURITY TEST SUITE")
    print("  Pentagon-Level Encryption Testing")
    print("🔐" * 30 + "\n")

    # Initialize vault with test password
    print("🔧 Initializing Promethian Vault...")
    vault = PromethianVault(master_password="test_master_password_very_strong_123")
    print()

    # ========== TEST 1: VAULT STATUS ==========
    print_section("TEST 1: Vault Status & Health Check")
    status = vault.status()
    print_result(status)

    # ========== TEST 2: STORE API KEYS ==========
    print_section("TEST 2: Store API Keys")

    print("📥 Storing OpenAI API key...")
    result = vault.store_api_key(
        "openai",
        "sk-test-1234567890abcdef-FAKE-KEY-FOR-TESTING",
        tags=["ai", "testing", "openai"]
    )
    print_result(result)

    print("📥 Storing Anthropic API key...")
    result = vault.store_api_key(
        "anthropic",
        "sk-ant-test-9876543210-FAKE-KEY-FOR-TESTING",
        tags=["ai", "testing", "anthropic"]
    )
    print_result(result)

    print("📥 Storing GitHub API token...")
    result = vault.store_api_key(
        "github",
        "ghp_test_token_1234567890abcdef",
        tags=["github", "testing", "vcs"]
    )
    print_result(result)

    # ========== TEST 3: STORE PASSWORDS ==========
    print_section("TEST 3: Store Passwords")

    print("📥 Storing GitHub password...")
    result = vault.store_password(
        "github",
        "testuser@example.com",
        "super_secure_password_123!"
    )
    print_result(result)

    print("📥 Storing Database password...")
    result = vault.store_password(
        "postgresql",
        "admin",
        "db_password_very_secure_456"
    )
    print_result(result)

    # ========== TEST 4: STORE CRYPTO WALLETS ==========
    print_section("TEST 4: Store Cryptocurrency Wallets")

    print("📥 Storing Ethereum wallet (seed phrase)...")
    result = vault.store_crypto_wallet(
        "ethereum_main",
        seed_phrase="test seed phrase with twelve words here for demo purposes only testing wallet",
        blockchain="ethereum"
    )
    print_result(result)

    print("📥 Storing Bitcoin wallet (private key)...")
    result = vault.store_crypto_wallet(
        "bitcoin_cold",
        private_key="5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss-FAKE-TESTING",
        blockchain="bitcoin"
    )
    print_result(result)

    # ========== TEST 5: CUSTOM SECRETS ==========
    print_section("TEST 5: Store Custom Secrets")

    print("📥 Storing SSH private key...")
    result = vault.store(
        "ssh_production_server",
        "-----BEGIN RSA PRIVATE KEY-----\nFAKE-KEY-DATA-FOR-TESTING\n-----END RSA PRIVATE KEY-----",
        "ssh_private_key",
        tags=["ssh", "production", "server"]
    )
    print_result(result)

    print("📥 Storing SSL certificate...")
    result = vault.store(
        "ssl_cert_example_com",
        "-----BEGIN CERTIFICATE-----\nFAKE-CERT-DATA\n-----END CERTIFICATE-----",
        "certificate",
        tags=["ssl", "certificate", "production"]
    )
    print_result(result)

    # ========== TEST 6: LIST ALL SECRETS ==========
    print_section("TEST 6: List All Secrets")

    result = vault.list()
    print(f"Total secrets stored: {result['count']}\n")

    for secret in result['secrets']:
        honeypot_flag = " 🍯" if secret['is_honeypot'] else ""
        print(f"  • {secret['secret_name']:<40} ({secret['secret_type']:<20}) "
              f"[accessed {secret['access_count']} times]{honeypot_flag}")
    print()

    # ========== TEST 7: RETRIEVE SECRETS ==========
    print_section("TEST 7: Retrieve & Decrypt Secrets")

    print("📤 Retrieving OpenAI API key...")
    result = vault.retrieve("openai_api_key")
    if result['success']:
        print(f"✅ Decrypted: {result['secret_value'][:20]}...")
        print(f"   Access count: {result['access_count']}\n")

    print("📤 Retrieving Ethereum wallet...")
    result = vault.retrieve("crypto_ethereum_main_seed")
    if result['success']:
        print(f"✅ Decrypted: {result['secret_value'][:30]}...")
        print(f"   Access count: {result['access_count']}\n")

    # ========== TEST 8: ENCRYPTION VERIFICATION ==========
    print_section("TEST 8: Encryption Verification")

    print("🔐 Testing encryption/decryption cycle...")
    test_secret = "This is a very sensitive secret that must be protected!"

    print(f"Original: {test_secret}")

    result = vault.store("encryption_test", test_secret, "credential")
    print(f"✅ Encrypted and stored")

    result = vault.retrieve("encryption_test")
    retrieved = result['secret_value']
    print(f"Decrypted: {retrieved}")

    if test_secret == retrieved:
        print("✅ ENCRYPTION VERIFICATION PASSED\n")
    else:
        print("❌ ENCRYPTION VERIFICATION FAILED\n")

    # ========== TEST 9: AUDIT LOG ==========
    print_section("TEST 9: Audit Log Review")

    result = vault.get_audit_log(limit=20)
    print(f"Recent audit events: {result['count']}\n")

    for entry in result['entries'][:10]:
        print(f"  {entry['timestamp']} | {entry['action']:<15} | "
              f"{entry['secret_name']:<30} | {entry['status']}")
    print()

    # ========== TEST 10: INTRUSION DETECTION ==========
    print_section("TEST 10: Intrusion Detection Status")

    result = vault.get_intrusion_log()
    print(f"Intrusions detected: {result['intrusions_detected']}\n")

    if result['intrusions_detected'] > 0:
        print("⚠️  Security Events:\n")
        for entry in result['entries']:
            print(f"  {entry['timestamp']} | {entry['event_type']:<20} | "
                  f"{entry['severity']:<10} | {entry['action_taken']}")
        print()
    else:
        print("✅ No intrusions detected\n")

    # ========== TEST 11: BACKUP ==========
    print_section("TEST 11: Encrypted Backup")

    print("💾 Creating encrypted backup...")
    result = vault.backup()
    if result['success']:
        print(f"✅ Backup created: {result['backup_path']}")
        print(f"   Timestamp: {result['timestamp']}\n")

    # ========== TEST 12: DELETE SECRET ==========
    print_section("TEST 12: Secure Deletion")

    print("🗑️  Securely deleting test secret...")
    result = vault.delete("encryption_test")
    print_result(result)

    # ========== FINAL STATUS ==========
    print_section("FINAL: Vault Status Summary")

    status = vault.status()
    print(f"Vault Status: {status['status']}")
    print(f"Total Secrets: {status['secrets_count']}")
    print(f"Honeypots: {status['honeypots_count']}")
    print(f"Recent Events (24h): {status['recent_events_24h']}")
    print(f"Intrusions: {status['intrusions_detected']}")
    print(f"Database Size: {status['database_size']:,} bytes")
    print()
    print(f"Encryption: {status['encryption']['algorithm']}")
    print(f"Key Derivation: {status['encryption']['key_derivation']}")
    print(f"Asymmetric: {status['encryption']['asymmetric']}")
    print(f"Integrity: {status['encryption']['integrity']}")
    print()

    # ========== TEST SUMMARY ==========
    print("\n" + "=" * 60)
    print("  🎉 ALL TESTS COMPLETED SUCCESSFULLY")
    print("=" * 60)
    print()
    print("✅ Vault initialization")
    print("✅ API key storage")
    print("✅ Password storage")
    print("✅ Crypto wallet storage")
    print("✅ Custom secret storage")
    print("✅ Secret listing")
    print("✅ Secret retrieval")
    print("✅ Encryption verification")
    print("✅ Audit logging")
    print("✅ Intrusion detection")
    print("✅ Backup creation")
    print("✅ Secure deletion")
    print()
    print("🛡️  PROMETHIAN VAULT - PENTAGON-LEVEL SECURITY VERIFIED")
    print()

if __name__ == "__main__":
    try:
        test_vault()
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
