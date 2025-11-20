#!/usr/bin/env python3
#!pymanager:3.11
"""
Test script for port conflict auto-fix
If port 9410 is in use, PyManager should find alternative
"""

import sys
import os

print(f"Python version: {sys.version}")

# PyManager will inject PORT environment variable if conflict detected
original_port = 9410
actual_port = int(os.environ.get('PYMANAGER_PORT_OVERRIDE', original_port))

print(f"Original port: {original_port}")
print(f"Actual port:   {actual_port}")

if actual_port != original_port:
    print(f"✅ PyManager detected port conflict and switched to {actual_port}")
else:
    print(f"✅ Port {original_port} is free")

# Simulate starting a server (don't actually start it)
print(f"\nWould start HTTP server on port {actual_port}")
