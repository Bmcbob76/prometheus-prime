#!/usr/bin/env python3
"""
Claude CLI Stdin Solutions - Comprehensive Test Script
Tests all 5 methods to find which one works on your system
"""

import subprocess
import threading
import tempfile
import os
import time
import sys

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*70)
    print(text)
    print("="*70)

def test_solution_1_prewrite():
    """
    Solution 1: Pre-write to stdin using threading
    Writes to stdin immediately after process starts
    """
    print_header("TEST 1: Pre-write to stdin (threading)")
    print("Theory: Write data before Node.js checks stdin availability")

    try:
        process = subprocess.Popen(
            ['claude', '-p', '--dangerously-skip-permissions'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0  # Unbuffered
        )

        def write_stdin():
            try:
                process.stdin.write("what is 2+2\n")
                process.stdin.flush()
                process.stdin.close()
            except Exception as e:
                print(f"Write error: {e}")

        # Start writing immediately
        writer = threading.Thread(target=write_stdin)
        writer.start()

        # Wait for result
        stdout, stderr = process.communicate(timeout=30)
        writer.join(timeout=1)

        if process.returncode == 0:
            print(f"✅ SUCCESS!")
            print(f"Response: {stdout.strip()[:200]}")
            return True
        else:
            print(f"❌ FAILED")
            print(f"Error: {stderr.strip()[:300]}")
            return False

    except subprocess.TimeoutExpired:
        process.kill()
        print("❌ TIMEOUT (30s)")
        return False
    except FileNotFoundError:
        print("❌ Claude CLI not found")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def test_solution_2_powershell_inline():
    """
    Solution 2: PowerShell inline command
    Uses PowerShell's native pipe handling
    """
    print_header("TEST 2: PowerShell inline command")
    print("Theory: Let PowerShell handle the pipe natively")

    try:
        start = time.time()
        result = subprocess.run(
            ['powershell', '-Command', 'echo "what is 2+2" | claude -p --dangerously-skip-permissions'],
            capture_output=True,
            text=True,
            timeout=30
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"✅ SUCCESS! ({elapsed:.2f}s)")
            print(f"Response: {result.stdout.strip()[:200]}")
            return True
        else:
            print(f"❌ FAILED ({elapsed:.2f}s)")
            print(f"Error: {result.stderr.strip()[:300]}")
            return False

    except subprocess.TimeoutExpired:
        print("❌ TIMEOUT (30s)")
        return False
    except FileNotFoundError:
        print("❌ PowerShell not found")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def test_solution_3_file_stdin():
    """
    Solution 3: File handle as stdin
    Creates temp file and uses as stdin (data ready immediately)
    """
    print_header("TEST 3: File handle as stdin")
    print("Theory: File handle is readable immediately (no timing issue)")

    temp_file = None
    try:
        # Create temp file with query
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("what is 2+2")
            temp_file = f.name

        print(f"Temp file: {temp_file}")

        # Use file as stdin
        start = time.time()
        with open(temp_file, 'r') as stdin_file:
            result = subprocess.run(
                ['claude', '-p', '--dangerously-skip-permissions'],
                stdin=stdin_file,
                capture_output=True,
                text=True,
                timeout=30
            )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"✅ SUCCESS! ({elapsed:.2f}s)")
            print(f"Response: {result.stdout.strip()[:200]}")
            return True
        else:
            print(f"❌ FAILED ({elapsed:.2f}s)")
            print(f"Error: {result.stderr.strip()[:300]}")
            return False

    except subprocess.TimeoutExpired:
        print("❌ TIMEOUT (30s)")
        return False
    except FileNotFoundError:
        print("❌ Claude CLI not found")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False
    finally:
        # Cleanup temp file
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)
            print(f"Cleaned up temp file")

def test_solution_4_shell_true():
    """
    Solution 4: shell=True with PowerShell
    Uses shell to set up pipe before process starts
    """
    print_header("TEST 4: shell=True with PowerShell executable")
    print("Theory: Let shell set up pipe before Node.js starts")

    try:
        start = time.time()
        result = subprocess.run(
            'echo "what is 2+2" | claude -p --dangerously-skip-permissions',
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            executable='powershell.exe'
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"✅ SUCCESS! ({elapsed:.2f}s)")
            print(f"Response: {result.stdout.strip()[:200]}")
            return True
        else:
            print(f"❌ FAILED ({elapsed:.2f}s)")
            print(f"Error: {result.stderr.strip()[:300]}")
            return False

    except subprocess.TimeoutExpired:
        print("❌ TIMEOUT (30s)")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def test_solution_5_communicate():
    """
    Solution 5: Popen.communicate(input=query)
    Standard approach that should work but might have timing issues
    """
    print_header("TEST 5: Popen.communicate(input=query)")
    print("Theory: Standard approach with communicate()")

    try:
        start = time.time()
        process = subprocess.Popen(
            ['claude', '-p', '--dangerously-skip-permissions'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = process.communicate(input="what is 2+2", timeout=30)
        elapsed = time.time() - start

        if process.returncode == 0:
            print(f"✅ SUCCESS! ({elapsed:.2f}s)")
            print(f"Response: {stdout.strip()[:200]}")
            return True
        else:
            print(f"❌ FAILED ({elapsed:.2f}s)")
            print(f"Error: {stderr.strip()[:300]}")
            return False

    except subprocess.TimeoutExpired:
        process.kill()
        print("❌ TIMEOUT (30s)")
        return False
    except FileNotFoundError:
        print("❌ Claude CLI not found")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def test_solution_6_prompt_argument():
    """
    Solution 6: Pass query as positional argument (not stdin)
    Tests if -p flag accepts prompt as argument
    """
    print_header("TEST 6: Query as positional argument (no stdin)")
    print("Theory: Maybe -p flag accepts prompt as argument?")

    try:
        start = time.time()
        result = subprocess.run(
            ['claude', '-p', '--dangerously-skip-permissions', 'what is 2+2'],
            stdin=subprocess.DEVNULL,  # Explicitly close stdin
            capture_output=True,
            text=True,
            timeout=30
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"✅ SUCCESS! ({elapsed:.2f}s)")
            print(f"Response: {result.stdout.strip()[:200]}")
            return True
        else:
            print(f"❌ FAILED ({elapsed:.2f}s)")
            print(f"Error: {result.stderr.strip()[:300]}")
            return False

    except subprocess.TimeoutExpired:
        print("❌ TIMEOUT (30s)")
        return False
    except FileNotFoundError:
        print("❌ Claude CLI not found")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def verify_prerequisites():
    """Check if Claude CLI is available"""
    print_header("PREREQUISITES CHECK")

    # Check Claude CLI
    try:
        result = subprocess.run(
            ['claude', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        print(f"✅ Claude CLI found: {result.stdout.strip()}")
        cli_ok = True
    except FileNotFoundError:
        print("❌ Claude CLI not found")
        print("   Install: npm install -g @anthropic-ai/claude-code")
        cli_ok = False
    except Exception as e:
        print(f"❌ Claude CLI error: {e}")
        cli_ok = False

    # Check PowerShell
    try:
        result = subprocess.run(
            ['powershell', '-Command', 'echo test'],
            capture_output=True,
            text=True,
            timeout=5
        )
        print(f"✅ PowerShell found")
        ps_ok = True
    except FileNotFoundError:
        print("❌ PowerShell not found")
        ps_ok = False
    except Exception as e:
        print(f"❌ PowerShell error: {e}")
        ps_ok = False

    # Check auth
    creds_path = os.path.expanduser("~/.claude/.credentials.json")
    if os.path.exists(creds_path):
        print(f"✅ Claude credentials found")
        auth_ok = True
    else:
        print(f"⚠️  Claude credentials not found at {creds_path}")
        print("   You may need to run: claude auth login")
        auth_ok = False

    return cli_ok and ps_ok

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("CLAUDE CLI STDIN SOLUTIONS - COMPREHENSIVE TEST SUITE")
    print("="*70)
    print("\nThis script will test 6 different methods to call Claude CLI")
    print("from Python subprocess and determine which one works.\n")
    print("Each test may take up to 30 seconds if it hangs.")
    print("="*70)

    # Check prerequisites
    if not verify_prerequisites():
        print("\n❌ Prerequisites not met. Cannot proceed with tests.")
        return 1

    input("\nPress ENTER to start tests...")

    # Run all tests
    results = {}

    print("\n" + "="*70)
    print("RUNNING TESTS (6 total)")
    print("="*70)

    results['prewrite'] = test_solution_1_prewrite()
    time.sleep(2)

    results['powershell_inline'] = test_solution_2_powershell_inline()
    time.sleep(2)

    results['file_stdin'] = test_solution_3_file_stdin()
    time.sleep(2)

    results['shell_true'] = test_solution_4_shell_true()
    time.sleep(2)

    results['communicate'] = test_solution_5_communicate()
    time.sleep(2)

    results['prompt_arg'] = test_solution_6_prompt_argument()

    # Print summary
    print("\n" + "="*70)
    print("TEST RESULTS SUMMARY")
    print("="*70)
    print(f"1. Pre-write (threading):        {'✅ PASS' if results['prewrite'] else '❌ FAIL'}")
    print(f"2. PowerShell inline:            {'✅ PASS' if results['powershell_inline'] else '❌ FAIL'}")
    print(f"3. File handle stdin:            {'✅ PASS' if results['file_stdin'] else '❌ FAIL'}")
    print(f"4. shell=True PowerShell:        {'✅ PASS' if results['shell_true'] else '❌ FAIL'}")
    print(f"5. communicate(input=):          {'✅ PASS' if results['communicate'] else '❌ FAIL'}")
    print(f"6. Prompt as argument:           {'✅ PASS' if results['prompt_arg'] else '❌ FAIL'}")
    print("="*70)

    # Find working solutions
    working = [name for name, passed in results.items() if passed]

    if working:
        print(f"\n✅ {len(working)} WORKING SOLUTION(S) FOUND!")
        print("\nWorking methods:")
        method_names = {
            'prewrite': 'Pre-write with threading',
            'powershell_inline': 'PowerShell inline command',
            'file_stdin': 'File handle as stdin',
            'shell_true': 'shell=True with PowerShell',
            'communicate': 'Popen.communicate(input=)',
            'prompt_arg': 'Prompt as positional argument'
        }
        for method in working:
            print(f"  • {method_names.get(method, method)}")

        print("\n" + "="*70)
        print("RECOMMENDATION FOR HTTP BRIDGE")
        print("="*70)

        # Recommend best method
        if 'file_stdin' in working:
            print("✅ Use: File handle as stdin (most reliable)")
            print("\nCode:")
            print("""
import tempfile
import subprocess
import os

def query_claude(query, timeout=60):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(query)
        temp_file = f.name

    try:
        with open(temp_file, 'r') as stdin_file:
            result = subprocess.run(
                ['claude', '-p', '--dangerously-skip-permissions'],
                stdin=stdin_file,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        return result.stdout.strip()
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
            """)
        elif 'powershell_inline' in working:
            print("✅ Use: PowerShell inline command")
            print("\nCode:")
            print("""
import subprocess

def query_claude(query, timeout=60):
    result = subprocess.run(
        ['powershell', '-Command', f'echo "{query}" | claude -p --dangerously-skip-permissions'],
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return result.stdout.strip()
            """)
        elif 'prompt_arg' in working:
            print("✅ Use: Prompt as argument (simplest)")
            print("\nCode:")
            print("""
import subprocess

def query_claude(query, timeout=60):
    result = subprocess.run(
        ['claude', '-p', '--dangerously-skip-permissions', query],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return result.stdout.strip()
            """)
        else:
            print(f"✅ Use: {working[0]}")
            print("\nSee CLAUDE_CLI_STDIN_INVESTIGATION.md for implementation")

    else:
        print("\n❌ NO SOLUTIONS WORKED")
        print("\nPossible issues:")
        print("  1. Claude CLI authentication - try: claude auth login")
        print("  2. Claude CLI version - try: npm update -g @anthropic-ai/claude-code")
        print("  3. Windows permissions - try running as administrator")
        print("  4. Network/proxy issues")
        print("\n" + "="*70)
        print("ALTERNATIVE: Use Claude API directly")
        print("="*70)
        print("""
import anthropic

client = anthropic.Anthropic(api_key="your-api-key")
message = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=4096,
    messages=[{"role": "user", "content": query}]
)
print(message.content[0].text)
        """)

    print("\n" + "="*70)
    print("Tests complete. See CLAUDE_CLI_STDIN_INVESTIGATION.md for details.")
    print("="*70 + "\n")

    return 0 if working else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        sys.exit(1)
