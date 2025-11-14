#!/usr/bin/env python3
"""
Claude CLI Subprocess Fix - Test Script
Tests the stdin=DEVNULL fix for Claude CLI hanging issue
"""

import subprocess
import os
import time
import sys

def test_claude_version():
    """Test 1: Verify Claude CLI is accessible"""
    print("\n" + "="*60)
    print("TEST 1: Claude CLI Version Check")
    print("="*60)

    try:
        result = subprocess.run(
            ['claude', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        print(f"✅ Claude CLI found: {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        print("❌ Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_without_fix():
    """Test 2: Original method (will likely hang)"""
    print("\n" + "="*60)
    print("TEST 2: Without Fix (stdin not set to DEVNULL)")
    print("="*60)
    print("WARNING: This test may hang for 30 seconds...")

    try:
        start = time.time()
        result = subprocess.run(
            ['claude', '-p', '--dangerously-skip-permissions', 'what is 2+2'],
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"✅ Completed in {elapsed:.2f}s")
            print(f"Response: {result.stdout.strip()[:100]}")
            return True
        else:
            print(f"❌ Failed with return code {result.returncode}")
            print(f"Error: {result.stderr.strip()[:200]}")
            return False

    except subprocess.TimeoutExpired:
        print(f"❌ HUNG - Timed out after 30 seconds (as expected)")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_with_fix():
    """Test 3: With stdin=DEVNULL fix (should work)"""
    print("\n" + "="*60)
    print("TEST 3: With Fix (stdin=subprocess.DEVNULL)")
    print("="*60)

    try:
        start = time.time()
        result = subprocess.run(
            ['claude', '-p', '--dangerously-skip-permissions', 'what is 2+2'],
            stdin=subprocess.DEVNULL,  # ⭐ THE FIX
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.expanduser("~")
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"✅ SUCCESS! Completed in {elapsed:.2f}s")
            print(f"Response: {result.stdout.strip()}")
            return True
        else:
            print(f"⚠️ Completed but with error (return code {result.returncode})")
            print(f"Stdout: {result.stdout.strip()}")
            print(f"Stderr: {result.stderr.strip()}")
            return False

    except subprocess.TimeoutExpired:
        print(f"❌ Still hanging - Fix didn't work")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_advanced_query():
    """Test 4: More complex query with fix"""
    print("\n" + "="*60)
    print("TEST 4: Complex Query Test")
    print("="*60)

    query = "List 5 programming languages and rate them 1-10"

    try:
        start = time.time()
        result = subprocess.run(
            ['claude', '-p', '--dangerously-skip-permissions', query],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.expanduser("~")
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"✅ SUCCESS! Completed in {elapsed:.2f}s")
            print(f"Response preview: {result.stdout.strip()[:200]}...")
            return True
        else:
            print(f"⚠️ Completed but with error")
            print(f"Stderr: {result.stderr.strip()[:200]}")
            return False

    except subprocess.TimeoutExpired:
        print(f"❌ Timeout")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_http_bridge_function():
    """Test 5: HTTP Bridge Integration Function"""
    print("\n" + "="*60)
    print("TEST 5: HTTP Bridge Function Test")
    print("="*60)

    def query_claude(query, timeout=60):
        """Production-ready function for HTTP bridge"""
        try:
            result = subprocess.run(
                ['claude', '-p', '--dangerously-skip-permissions', query],
                stdin=subprocess.DEVNULL,  # ⭐ THE FIX
                capture_output=True,
                text=True,
                timeout=timeout,
                env=os.environ.copy(),
                cwd=os.path.expanduser("~")
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "response": result.stdout.strip(),
                    "error": None
                }
            else:
                return {
                    "success": False,
                    "response": None,
                    "error": result.stderr.strip() or "Unknown error"
                }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "response": None,
                "error": f"Timeout after {timeout}s"
            }
        except Exception as e:
            return {
                "success": False,
                "response": None,
                "error": str(e)
            }

    # Test the function
    start = time.time()
    result = query_claude("what is the capital of France")
    elapsed = time.time() - start

    if result["success"]:
        print(f"✅ SUCCESS! Function works correctly ({elapsed:.2f}s)")
        print(f"Response: {result['response'][:150]}")
        return True
    else:
        print(f"❌ Function failed: {result['error']}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("CLAUDE CLI SUBPROCESS FIX - COMPREHENSIVE TEST")
    print("="*60)
    print("\nThis script will test the stdin=DEVNULL fix for Claude CLI hanging.")
    print("Some tests may take 30-60 seconds if they hang (expected behavior).\n")

    input("Press ENTER to start tests...")

    # Track results
    results = {}

    # Test 1: Version check
    results['version'] = test_claude_version()
    if not results['version']:
        print("\n❌ Claude CLI not found. Cannot proceed with tests.")
        print("Install with: npm install -g @anthropic-ai/claude-code")
        return

    # Test 2: Without fix (may hang)
    print("\n⚠️  Test 2 may hang for 30 seconds. This is expected.")
    user_input = input("Run test WITHOUT fix? (y/n): ")
    if user_input.lower() == 'y':
        results['without_fix'] = test_without_fix()
    else:
        print("Skipping Test 2")
        results['without_fix'] = None

    # Test 3: With fix (should work)
    results['with_fix'] = test_with_fix()

    # Test 4: Complex query
    if results['with_fix']:
        results['complex'] = test_advanced_query()
    else:
        print("\nSkipping Test 4 (basic fix didn't work)")
        results['complex'] = None

    # Test 5: HTTP bridge function
    if results['with_fix']:
        results['http_bridge'] = test_http_bridge_function()
    else:
        print("\nSkipping Test 5 (basic fix didn't work)")
        results['http_bridge'] = None

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"1. Version Check:        {'✅ PASS' if results['version'] else '❌ FAIL'}")
    print(f"2. Without Fix:          {'✅ PASS' if results['without_fix'] else '❌ FAIL/HANG' if results['without_fix'] is False else '⊘ SKIPPED'}")
    print(f"3. With Fix:             {'✅ PASS' if results['with_fix'] else '❌ FAIL'}")
    print(f"4. Complex Query:        {'✅ PASS' if results['complex'] else '❌ FAIL' if results['complex'] is False else '⊘ SKIPPED'}")
    print(f"5. HTTP Bridge Function: {'✅ PASS' if results['http_bridge'] else '❌ FAIL' if results['http_bridge'] is False else '⊘ SKIPPED'}")

    print("\n" + "="*60)
    if results['with_fix']:
        print("✅ FIX VERIFIED - stdin=subprocess.DEVNULL works!")
        print("\nYou can now use this in your HTTP bridge:")
        print("\nsubprocess.run(")
        print("    ['claude', '-p', '--dangerously-skip-permissions', query],")
        print("    stdin=subprocess.DEVNULL,  # ⭐ THE FIX")
        print("    capture_output=True,")
        print("    text=True,")
        print("    timeout=60")
        print(")")
    else:
        print("❌ FIX DID NOT WORK")
        print("\nPossible issues:")
        print("1. Claude CLI authentication problem - try: claude auth login")
        print("2. Claude CLI version issue - try: npm update -g @anthropic-ai/claude-code")
        print("3. Windows permissions issue - try running as administrator")
        print("4. Network/proxy issue blocking Claude CLI")
        print("\nSee CLAUDE_CLI_SUBPROCESS_FIX.md for alternative solutions.")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user.")
        sys.exit(1)
