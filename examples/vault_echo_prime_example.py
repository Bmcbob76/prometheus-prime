#!/usr/bin/env python3
"""
ECHO PRIME VAULT INTEGRATION EXAMPLE
Demonstrates secure API key management with Promethian Vault
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from vault_addon import PromethianVault, get_vault


def setup_vault_first_time():
    """
    Run this ONCE to store all your API keys in the vault
    """
    print("\n" + "="*60)
    print("  🔐 FIRST TIME SETUP - STORING API KEYS IN VAULT")
    print("="*60 + "\n")

    # Initialize vault (will use VAULT_MASTER_PASSWORD from .env)
    vault = PromethianVault()

    # Store OpenAI API key
    print("📥 Storing OpenAI API key...")
    result = vault.store_api_key(
        service="openai",
        api_key="sk-proj-YOUR_OPENAI_KEY_HERE",  # Replace with your actual key
        tags=["ai", "echo-prime", "production"]
    )
    print(f"   {result}\n")

    # Store Anthropic API key
    print("📥 Storing Anthropic API key...")
    result = vault.store_api_key(
        service="anthropic",
        api_key="sk-ant-YOUR_ANTHROPIC_KEY_HERE",  # Replace with your actual key
        tags=["ai", "echo-prime", "production"]
    )
    print(f"   {result}\n")

    # Store ElevenLabs API key
    print("📥 Storing ElevenLabs API key...")
    result = vault.store_api_key(
        service="elevenlabs",
        api_key="your_elevenlabs_key_here",  # Replace with your actual key
        tags=["voice", "echo-prime"]
    )
    print(f"   {result}\n")

    # Store any database credentials
    print("📥 Storing database password...")
    result = vault.store_password(
        service="postgresql",
        username="echo_prime_user",
        password="your_db_password_here"  # Replace with your actual password
    )
    print(f"   {result}\n")

    print("✅ All credentials stored securely in vault!\n")


def use_vault_in_echo_prime():
    """
    Example of how to use the vault in your Echo Prime application
    """
    print("\n" + "="*60)
    print("  🤖 ECHO PRIME - LOADING CREDENTIALS FROM VAULT")
    print("="*60 + "\n")

    # Get vault instance (reuses same instance)
    vault = get_vault()

    # Check vault status
    print("🔐 Vault Status:")
    status = vault.status()
    print(f"   Status: {status['status']}")
    print(f"   Secrets: {status['secrets_count']}")
    print(f"   Intrusions: {status['intrusions_detected']}")
    print()

    # Retrieve OpenAI API key
    print("📤 Retrieving OpenAI API key...")
    result = vault.retrieve("openai_api_key")

    if result["success"]:
        openai_key = result["secret_value"]
        print(f"   ✅ Retrieved successfully")
        print(f"   ✅ Key: {openai_key[:10]}... (masked)")
        print(f"   ✅ Access count: {result['access_count']}")
        print()

        # Now use the key with OpenAI
        # from openai import OpenAI
        # client = OpenAI(api_key=openai_key)
        print("   💡 You can now use: OpenAI(api_key=openai_key)")
        print()
    else:
        print(f"   ❌ Failed: {result.get('error')}")
        print()

    # Retrieve Anthropic API key
    print("📤 Retrieving Anthropic API key...")
    result = vault.retrieve("anthropic_api_key")

    if result["success"]:
        anthropic_key = result["secret_value"]
        print(f"   ✅ Retrieved successfully")
        print(f"   ✅ Key: {anthropic_key[:10]}... (masked)")
        print()

        # Now use the key with Anthropic
        # from anthropic import Anthropic
        # client = Anthropic(api_key=anthropic_key)
        print("   💡 You can now use: Anthropic(api_key=anthropic_key)")
        print()
    else:
        print(f"   ❌ Failed: {result.get('error')}")
        print()

    # List all secrets (for debugging)
    print("📋 All secrets in vault:")
    secrets_list = vault.list()
    for secret in secrets_list.get("secrets", []):
        honeypot = "🍯" if secret.get("is_honeypot") else ""
        print(f"   • {secret['secret_name']:<30} ({secret['secret_type']:<20}) {honeypot}")
    print()


def complete_echo_prime_example():
    """
    Complete example showing full Echo Prime integration
    """
    print("\n" + "="*60)
    print("  🚀 COMPLETE ECHO PRIME EXAMPLE")
    print("="*60 + "\n")

    vault = get_vault()

    # Load all required keys
    credentials = {}
    required_keys = ["openai_api_key", "anthropic_api_key", "elevenlabs_api_key"]

    for key_name in required_keys:
        result = vault.retrieve(key_name)
        if result["success"]:
            credentials[key_name] = result["secret_value"]
            print(f"✅ Loaded {key_name}")
        else:
            print(f"⚠️  Failed to load {key_name}: {result.get('error')}")

    print()

    # Simulate Echo Prime initialization
    if "openai_api_key" in credentials:
        print("🤖 Initializing Echo Prime AI systems...")
        # from openai import OpenAI
        # openai_client = OpenAI(api_key=credentials["openai_api_key"])
        print("   ✅ OpenAI client ready")

    if "anthropic_api_key" in credentials:
        # from anthropic import Anthropic
        # anthropic_client = Anthropic(api_key=credentials["anthropic_api_key"])
        print("   ✅ Anthropic client ready")

    if "elevenlabs_api_key" in credentials:
        # ElevenLabs initialization
        print("   ✅ ElevenLabs client ready")

    print()
    print("🎉 Echo Prime fully initialized with secure vault credentials!")
    print()


def check_vault_security():
    """
    Check vault security and audit logs
    """
    print("\n" + "="*60)
    print("  🛡️  VAULT SECURITY CHECK")
    print("="*60 + "\n")

    vault = get_vault()

    # Get detailed status
    status = vault.status()

    print("📊 Vault Statistics:")
    print(f"   Status: {status['status']}")
    print(f"   Secrets stored: {status['secrets_count']}")
    print(f"   Honeypots deployed: {status['honeypots_count']}")
    print(f"   Recent events (24h): {status['recent_events_24h']}")
    print(f"   Intrusions detected: {status['intrusions_detected']}")
    print(f"   Database size: {status['database_size']:,} bytes")
    print()

    print("🔐 Encryption:")
    print(f"   Algorithm: {status['encryption']['algorithm']}")
    print(f"   Key Derivation: {status['encryption']['key_derivation']}")
    print(f"   Asymmetric: {status['encryption']['asymmetric']}")
    print(f"   Integrity: {status['encryption']['integrity']}")
    print()

    # Check audit log
    print("📋 Recent Audit Log (last 10 entries):")
    audit = vault.get_audit_log(limit=10)
    for entry in audit['entries']:
        print(f"   {entry['timestamp']} | {entry['action']:<15} | {entry['status']:<10} | {entry['secret_name']}")
    print()

    # Check intrusions
    intrusions = vault.get_intrusion_log()
    if intrusions['intrusions_detected'] > 0:
        print("⚠️  SECURITY ALERT: Intrusions detected!")
        for event in intrusions['entries']:
            print(f"   {event['timestamp']} | {event['event_type']} | {event['severity']} | {event['action_taken']}")
        print()
    else:
        print("✅ No intrusions detected")
        print()


def backup_vault():
    """
    Create encrypted backup of vault
    """
    print("\n" + "="*60)
    print("  💾 VAULT BACKUP")
    print("="*60 + "\n")

    vault = get_vault()

    result = vault.backup()

    if result["success"]:
        print(f"✅ Backup created successfully")
        print(f"   Path: {result['backup_path']}")
        print(f"   Timestamp: {result['timestamp']}")
        print()
        print("💡 Store this backup in a secure location!")
        print()
    else:
        print(f"❌ Backup failed: {result.get('error')}")
        print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Echo Prime Vault Integration Example")
    parser.add_argument(
        "action",
        choices=["setup", "use", "complete", "security", "backup"],
        help="Action to perform"
    )

    args = parser.parse_args()

    try:
        if args.action == "setup":
            setup_vault_first_time()
        elif args.action == "use":
            use_vault_in_echo_prime()
        elif args.action == "complete":
            complete_echo_prime_example()
        elif args.action == "security":
            check_vault_security()
        elif args.action == "backup":
            backup_vault()

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
