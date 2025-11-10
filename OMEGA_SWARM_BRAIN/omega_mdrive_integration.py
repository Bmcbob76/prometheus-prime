#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║    OMEGA M-DRIVE INTEGRATION - 9-PILLAR MEMORY CONNECTION       ║
║         Integration with Existing M: Drive Memory System         ║
╚══════════════════════════════════════════════════════════════════╝

INTEGRATES WITH M: DRIVE 9-PILLAR MEMORY:
- L9_EKM (Layer 9 Enterprise Knowledge Management)
- MASTER_EKM (Master Intelligence Layers)
- CONSCIOUSNESS_EKM
- KNOWLEDGE_EKM
- MEMORY_EKM
- NETWORK_EKM
- SOVEREIGN_EKM
- SYSTEM_EKM
- CRYSTAL_MEMORIES (Immutable records)
"""

import logging
import sqlite3
import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# ══════════════════════════════════════════════════════════════════
# M: DRIVE MEMORY PILLARS
# ══════════════════════════════════════════════════════════════════

class MDrivePillar(Enum):
    """9 memory pillars on M: drive"""
    CONSCIOUSNESS = "CONSCIOUSNESS_EKM"    # Emergence, Trinity, GS343
    KNOWLEDGE = "KNOWLEDGE_EKM"            # Code, Document, Learning
    MEMORY = "MEMORY_EKM"                  # Crystal, Persistent, Session
    NETWORK = "NETWORK_EKM"                # Communication, Expansion, Scan
    SOVEREIGN = "SOVEREIGN_EKM"            # Decision, Goal, Personal
    SYSTEM = "SYSTEM_EKM"                  # Performance, Phoenix, Security
    L9_SOVEREIGN = "L9_EKM/SOVEREIGN_EKM"  # Layer 9 Sovereign
    L9_SYSTEM = "L9_EKM/SYSTEM_EKM"        # Layer 9 System
    CRYSTALS = "CRYSTAL_MEMORIES"          # Immutable crystal storage

# ══════════════════════════════════════════════════════════════════
# M: DRIVE DATABASE PATHS
# ══════════════════════════════════════════════════════════════════

M_DRIVE_PATHS = {
    # MASTER EKM databases
    MDrivePillar.CONSCIOUSNESS: {
        "emergence_events": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/CONSCIOUSNESS_EKM/emergence_events.db",
        "gs343_consciousness": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/CONSCIOUSNESS_EKM/gs343_consciousness.db",
        "trinity_consciousness": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/CONSCIOUSNESS_EKM/trinity_consciousness.db"
    },
    MDrivePillar.KNOWLEDGE: {
        "code_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/KNOWLEDGE_EKM/code_intelligence.db",
        "document_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/KNOWLEDGE_EKM/document_intelligence.db",
        "learning_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/KNOWLEDGE_EKM/learning_intelligence.db"
    },
    MDrivePillar.MEMORY: {
        "crystal_memories": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/MEMORY_EKM/crystal_memories.db",
        "persistent_memories": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/MEMORY_EKM/persistent_memories.db",
        "session_memories": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/MEMORY_EKM/session_memories.db"
    },
    MDrivePillar.NETWORK: {
        "communication_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/NETWORK_EKM/communication_intelligence.db",
        "expansion_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/NETWORK_EKM/expansion_intelligence.db",
        "scan_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/NETWORK_EKM/scan_intelligence.db"
    },
    MDrivePillar.SOVEREIGN: {
        "decision_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/SOVEREIGN_EKM/decision_intelligence.db",
        "goal_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/SOVEREIGN_EKM/goal_intelligence.db",
        "personal_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/SOVEREIGN_EKM/personal_intelligence.db"
    },
    MDrivePillar.SYSTEM: {
        "performance_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/SYSTEM_EKM/performance_intelligence.db",
        "phoenix_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/SYSTEM_EKM/phoenix_intelligence.db",
        "security_intelligence": "M:/MEMORY_ORCHESTRATION/MASTER_EKM/SYSTEM_EKM/security_intelligence.db"
    },
    # L9 EKM databases
    MDrivePillar.L9_SOVEREIGN: {
        "authority_matrix": "M:/MEMORY_ORCHESTRATION/L9_EKM/SOVEREIGN_EKM/authority_matrix/authority_matrix.db",
        "bloodline_verification": "M:/MEMORY_ORCHESTRATION/L9_EKM/SOVEREIGN_EKM/bloodline_verification/bloodline_verification.db",
        "command_authority": "M:/MEMORY_ORCHESTRATION/L9_EKM/SOVEREIGN_EKM/command_authority/command_authority.db"
    },
    MDrivePillar.L9_SYSTEM: {
        "configuration_state": "M:/MEMORY_ORCHESTRATION/L9_EKM/SYSTEM_EKM/configuration_state/configuration_state.db",
        "performance_metrics": "M:/MEMORY_ORCHESTRATION/L9_EKM/SYSTEM_EKM/performance_metrics/performance_metrics.db",
        "system_evolution": "M:/MEMORY_ORCHESTRATION/L9_EKM/SYSTEM_EKM/system_evolution/system_evolution.db"
    }
}

# ══════════════════════════════════════════════════════════════════
# M: DRIVE MEMORY ENTRY
# ══════════════════════════════════════════════════════════════════

@dataclass
class MDrivermoryEntry:
    """Memory entry for M: drive storage"""
    pillar: MDrivePillar
    database: str
    content: Any
    timestamp: float = None
    importance: float = 1.0
    tags: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}

# ══════════════════════════════════════════════════════════════════
# M: DRIVE MEMORY CONNECTOR
# ══════════════════════════════════════════════════════════════════

class MDriveMemoryConnector:
    """
    Connector to existing M: drive 9-pillar memory system
    Provides unified interface to all memory databases
    """
    
    def __init__(self):
        self.m_drive_available = Path("M:/").exists()
        
        if not self.m_drive_available:
            logging.warning("⚠️ M: drive not available - using local fallback")
            self.fallback_mode = True
        else:
            self.fallback_mode = False
            logging.info("✅ M: drive detected - connecting to 9-pillar memory")
        
        # Test connections
        self.available_databases = self._test_connections()
        
        # Statistics
        self.stats = {
            "reads": 0,
            "writes": 0,
            "errors": 0,
            "pillars_connected": len(self.available_databases)
        }
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║        M: DRIVE MEMORY CONNECTOR INITIALIZED                 ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
        logging.info(f"📊 Connected to {len(self.available_databases)} databases")
    
    def _test_connections(self) -> Dict[str, bool]:
        """Test connections to all M: drive databases"""
        available = {}
        
        if self.fallback_mode:
            return available
        
        for pillar, databases in M_DRIVE_PATHS.items():
            for db_name, db_path in databases.items():
                try:
                    path = Path(db_path)
                    if path.exists():
                        # Try to connect
                        conn = sqlite3.connect(db_path)
                        conn.close()
                        available[db_name] = True
                        logging.info(f"  ✅ {db_name}")
                    else:
                        available[db_name] = False
                        logging.debug(f"  ⚠️ {db_name} - not found")
                except Exception as e:
                    available[db_name] = False
                    logging.debug(f"  ❌ {db_name} - {e}")
        
        return available
    
    def store(self, pillar: MDrivePillar, database: str, 
             content: Any, importance: float = 1.0,
             tags: List[str] = None, metadata: Dict[str, Any] = None) -> bool:
        """Store data in M: drive memory"""
        if self.fallback_mode:
            logging.warning("M: drive not available - store operation skipped")
            return False
        
        if database not in self.available_databases or not self.available_databases[database]:
            logging.warning(f"Database {database} not available")
            return False
        
        try:
            # Get database path
            db_path = None
            for p, dbs in M_DRIVE_PATHS.items():
                if database in dbs:
                    db_path = dbs[database]
                    break
            
            if not db_path:
                logging.error(f"Database path not found for {database}")
                return False
            
            # Connect and store
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create table if not exists (generic structure)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS omega_memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT,
                    importance REAL,
                    tags TEXT,
                    metadata TEXT,
                    timestamp REAL
                )
            ''')
            
            # Insert data
            cursor.execute('''
                INSERT INTO omega_memories (content, importance, tags, metadata, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                json.dumps(content) if not isinstance(content, str) else content,
                importance,
                json.dumps(tags or []),
                json.dumps(metadata or {}),
                time.time()
            ))
            
            conn.commit()
            conn.close()
            
            self.stats['writes'] += 1
            logging.debug(f"💾 Stored to {database}")
            return True
            
        except Exception as e:
            self.stats['errors'] += 1
            logging.error(f"❌ Failed to store in {database}: {e}")
            return False
    
    def retrieve(self, pillar: MDrivePillar, database: str, 
                limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve data from M: drive memory"""
        if self.fallback_mode:
            logging.warning("M: drive not available - retrieve operation skipped")
            return []
        
        if database not in self.available_databases or not self.available_databases[database]:
            logging.warning(f"Database {database} not available")
            return []
        
        try:
            # Get database path
            db_path = None
            for p, dbs in M_DRIVE_PATHS.items():
                if database in dbs:
                    db_path = dbs[database]
                    break
            
            if not db_path:
                return []
            
            # Connect and retrieve
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if omega_memories table exists
            cursor.execute('''
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='omega_memories'
            ''')
            
            if not cursor.fetchone():
                conn.close()
                return []
            
            # Retrieve data
            cursor.execute(f'''
                SELECT content, importance, tags, metadata, timestamp
                FROM omega_memories
                ORDER BY timestamp DESC
                LIMIT {limit}
            ''')
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "content": json.loads(row[0]) if row[0] else None,
                    "importance": row[1],
                    "tags": json.loads(row[2]) if row[2] else [],
                    "metadata": json.loads(row[3]) if row[3] else {},
                    "timestamp": row[4]
                })
            
            conn.close()
            
            self.stats['reads'] += 1
            return results
            
        except Exception as e:
            self.stats['errors'] += 1
            logging.error(f"❌ Failed to retrieve from {database}: {e}")
            return []
    
    def store_consciousness(self, content: Any, consciousness_type: str = "trinity"):
        """Store consciousness-related memory"""
        if consciousness_type == "trinity":
            db = "trinity_consciousness"
        elif consciousness_type == "gs343":
            db = "gs343_consciousness"
        else:
            db = "emergence_events"
        
        return self.store(MDrivePillar.CONSCIOUSNESS, db, content, importance=2.5)
    
    def store_decision(self, content: Any):
        """Store decision intelligence"""
        return self.store(MDrivePillar.SOVEREIGN, "decision_intelligence", content, importance=2.0)
    
    def store_performance_metric(self, content: Any):
        """Store performance metric"""
        return self.store(MDrivePillar.SYSTEM, "performance_intelligence", content, importance=1.5)
    
    def store_crystal_memory(self, content: Any):
        """Store immutable crystal memory"""
        return self.store(MDrivePillar.MEMORY, "crystal_memories", content, importance=3.0)
    
    def store_bloodline_event(self, content: Any):
        """Store bloodline sovereignty event"""
        return self.store(MDrivePillar.L9_SOVEREIGN, "bloodline_verification", content, importance=3.0)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connector statistics"""
        return {
            "m_drive_available": not self.fallback_mode,
            "databases_connected": len([v for v in self.available_databases.values() if v]),
            "stats": self.stats,
            "available_databases": list(self.available_databases.keys())
        }

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - M:DRIVE - %(levelname)s - %(message)s')
    
    # Initialize M: drive connector
    connector = MDriveMemoryConnector()
    
    # Test storage
    if not connector.fallback_mode:
        # Store consciousness event
        connector.store_consciousness({
            "event": "OMEGA_BRAIN_ONLINE",
            "timestamp": time.time(),
            "agents": 1200
        }, consciousness_type="trinity")
        
        # Store decision
        connector.store_decision({
            "decision": "spawn_agent",
            "agent_name": "Alpha",
            "approved": True
        })
        
        # Store performance metric
        connector.store_performance_metric({
            "metric": "agent_success_rate",
            "value": 0.95,
            "timestamp": time.time()
        })
        
        # Store crystal memory
        connector.store_crystal_memory({
            "type": "SOVEREIGN_COMMAND",
            "commander": "COMMANDER_BOBBY_DON_MCWILLIAMS_II",
            "command": "INITIALIZE_OMEGA_BRAIN",
            "timestamp": time.time()
        })
    
    # Show statistics
    stats = connector.get_statistics()
    print("\n" + "="*70)
    print("M: DRIVE MEMORY CONNECTOR STATISTICS")
    print("="*70)
    print(f"M: Drive Available: {stats['m_drive_available']}")
    print(f"Databases Connected: {stats['databases_connected']}")
    print(f"Reads: {stats['stats']['reads']}")
    print(f"Writes: {stats['stats']['writes']}")
    print(f"Errors: {stats['stats']['errors']}")
    print("\nAvailable Databases:")
    for db in stats['available_databases'][:10]:
        print(f"  • {db}")
