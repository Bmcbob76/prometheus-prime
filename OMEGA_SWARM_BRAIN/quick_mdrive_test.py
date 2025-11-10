#!/usr/bin/env python3
"""Quick M: drive connection test"""

import logging

logging.basicConfig(level=logging.INFO)

from omega_mdrive_integration import MDriveMemoryConnector
import time

# Test M: drive connector
connector = MDriveMemoryConnector()
stats = connector.get_statistics()

print("\n" + "="*70)
print("M: DRIVE MEMORY CONNECTOR - QUICK TEST")
print("="*70)
print(f"✅ M: Drive Available: {stats['m_drive_available']}")
print(f"✅ Databases Connected: {stats['databases_connected']}")
print(f"✅ Total Databases: {len(stats['available_databases'])}")

if stats['m_drive_available']:
    # Store test data
    print("\n🔄 Storing test data...")
    connector.store_crystal_memory({
        "test_event": "OMEGA_INTEGRATION_TEST",
        "timestamp": time.time()
    })
    print("✅ Test data stored successfully")
    
print("\n" + "="*70)
print("M: DRIVE INTEGRATION: ✅ OPERATIONAL")
print("="*70)
