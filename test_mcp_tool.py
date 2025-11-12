#!/usr/bin/env python3
"""
Quick test to verify MCP tools are working
Tests the payload generator capability that was just restored
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_registry_load():
    """Test that the capability registry loads successfully"""
    print("=" * 60)
    print("TEST 1: Loading PROMETHEUS_CAPABILITY_REGISTRY")
    print("=" * 60)

    try:
        from PROMETHEUS_CAPABILITY_REGISTRY import PrometheusCapabilityRegistry

        registry = PrometheusCapabilityRegistry()
        all_caps = registry.get_all_capabilities()

        print(f"✅ Registry loaded successfully")
        print(f"✅ Total capabilities: {len(all_caps)}")

        # Count by category
        categories = {}
        for cap in all_caps:
            cat = cap.category.value
            categories[cat] = categories.get(cat, 0) + 1

        print(f"\n📊 Breakdown by category:")
        for cat, count in sorted(categories.items()):
            print(f"   - {cat}: {count} tools")

        return True

    except Exception as e:
        print(f"❌ Registry load failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_payload_tool():
    """Test the restored payload generator tool"""
    print("\n" + "=" * 60)
    print("TEST 2: Testing Payload Generator (Restored Capability)")
    print("=" * 60)

    try:
        from tools.payloads import PayloadGenerator

        print("✅ PayloadGenerator imported successfully")

        # Create instance
        pg = PayloadGenerator()
        print("✅ PayloadGenerator instantiated")

        # Test listing available payloads
        if hasattr(pg, 'list_payloads'):
            payloads = pg.list_payloads()
            print(f"✅ Available payload types: {len(payloads)}")
            print(f"   Examples: {list(payloads.keys())[:5]}")

        # Test generating a simple payload (if method exists)
        if hasattr(pg, 'generate'):
            print("\n🧪 Testing payload generation...")
            result = pg.generate('reverse_shell', {
                'lhost': '127.0.0.1',
                'lport': 4444,
                'platform': 'linux',
                'arch': 'x64'
            })

            if result and 'payload' in result:
                print(f"✅ Payload generated successfully")
                print(f"   Platform: {result.get('platform', 'N/A')}")
                print(f"   Size: {len(result['payload'])} bytes")
            else:
                print("⚠️  Payload generation returned unexpected format")

        return True

    except Exception as e:
        print(f"❌ Payload tool test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_physical_attacks():
    """Test the restored physical attacks tool"""
    print("\n" + "=" * 60)
    print("TEST 3: Testing Physical Attacks (Restored Capability)")
    print("=" * 60)

    try:
        from tools.physical_attacks import PhysicalAttacks

        print("✅ PhysicalAttacks imported successfully")

        # Create instance
        pa = PhysicalAttacks()
        print("✅ PhysicalAttacks instantiated")

        # Test listing available attacks
        if hasattr(pa, 'list_attacks'):
            attacks = pa.list_attacks()
            print(f"✅ Available attack types: {len(attacks)}")
            print(f"   Examples: {list(attacks)[:5]}")

        return True

    except Exception as e:
        print(f"❌ Physical attacks test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("\n🚀 PROMETHEUS PRIME MCP TOOL TESTING")
    print("Testing restored capabilities and registry expansion\n")

    results = []

    # Test 1: Registry load
    results.append(("Registry Load", test_registry_load()))

    # Test 2: Payload generator
    results.append(("Payload Generator", test_payload_tool()))

    # Test 3: Physical attacks
    results.append(("Physical Attacks", test_physical_attacks()))

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")

    print(f"\n{'🎉' if passed == total else '⚠️'}  {passed}/{total} tests passed")

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
