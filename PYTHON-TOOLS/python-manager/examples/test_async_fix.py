#!/usr/bin/env python3
#!pymanager:3.11
"""
Test script for async event loop auto-fix
PyManager should inject event loop wrapper automatically
"""

import asyncio
import sys

print(f"Python version: {sys.version}")
print("Testing async event loop fix...")

async def test_task():
    print("Async task running!")
    await asyncio.sleep(0.1)
    print("Async task complete!")

# This would normally cause RuntimeError: no running event loop
# But PyManager auto-fix should inject event loop wrapper
task = asyncio.create_task(test_task())
print("Task created (PyManager auto-fix should prevent RuntimeError)")
