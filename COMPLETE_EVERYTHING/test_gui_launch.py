#!/usr/bin/env python3
"""
PROMETHEUS PRIME - GUI TEST LAUNCHER
Quick verification that GUI shows honest status

Run: H:\Tools\python.exe E:\prometheus_prime\COMPLETE_EVERYTHING\test_gui_launch.py
"""

import sys
import subprocess

print("="*80)
print("PROMETHEUS PRIME - GUI LAUNCH TEST")
print("="*80)
print()

print("[1/3] Checking capability status...")
result1 = subprocess.run(
    [r"H:\Tools\python.exe", 
     r"E:\prometheus_prime\COMPLETE_EVERYTHING\prometheus_capability_checker.py"],
    capture_output=True,
    text=True
)
print(result1.stdout)
print()

print("[2/3] Launching GUI with honest status...")
print("Opening PROMETHEUS_TABBED_GUI.py...")
print("Check that GUI header shows HONEST status, not fake success rates!")
print()

try:
    subprocess.Popen(
        [r"H:\Tools\python.exe",
         r"E:\prometheus_prime\COMPLETE_EVERYTHING\PROMETHEUS_TABBED_GUI.py"]
    )
    print("✅ GUI launched! Check window for honest status display.")
except Exception as e:
    print(f"❌ GUI launch failed: {e}")

print()
print("[3/3] Verification checklist:")
print("  ✓ Does header say 'HONEST CAPABILITY STATUS'?")
print("  ✓ Does it show '1 dependencies missing'?")
print("  ✓ Do capabilities show 'NOT_READY' or 'NEEDS_X'?")
print("  ✓ NO fake 97-99.3% success rates?")
print()
print("="*80)
