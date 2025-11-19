#!/usr/bin/env python3
"""
Example Directory Routing - Uses .pyversion file
This script automatically uses Python 3.11 because
the .pyversion file in this directory specifies it
"""

import sys

print(f"Running with Python {sys.version}")
print("Version detected from .pyversion file in examples/ directory")
print("All scripts in this directory will use Python 3.11")
