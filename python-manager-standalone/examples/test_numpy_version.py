#!/usr/bin/env python3
#!pymanager:3.14
"""
Test script for dependency compatibility auto-fix
This script requests Python 3.14 but imports numpy
PyManager should auto-downgrade to Python 3.11 for compatibility
"""

import sys

print(f"Requested Python 3.14, running: {sys.version}")

try:
    import numpy as np
    print(f"NumPy version: {np.__version__}")
    print("✅ NumPy imported successfully!")
    print("PyManager auto-switched to compatible Python version")
except ImportError as e:
    print(f"❌ NumPy import failed: {e}")
    print("PyManager dependency check may need adjustment")
