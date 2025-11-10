#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         OMEGA MEMORY - 8-PILLAR MEMORY ARCHITECTURE              ║
║              Complete Memory System & Crystal Storage             ║
╚══════════════════════════════════════════════════════════════════╝

8 MEMORY PILLARS:
1. SHORT_TERM - Immediate working memory
2. LONG_TERM - Persistent knowledge storage
3. EPISODIC - Event and experience memory
4. SEMANTIC - Factual knowledge base
5. PROCEDURAL - Skills and procedures
6. EMOTIONAL - Emotional context and sentiment
7. CRYSTAL - Immutable sovereign records
8. QUANTUM - Probabilistic future states

Each pillar has:
- Capacity limits
- Retention policies
- Access patterns
- Compression strategies
"""

import logging
import sqlite3
import json
import time
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
from pathlib import Path
import gzip
import pickle

# ══════════════════════════════════════════════════════════════════
# MEMORY PILLAR TYPES
# ══════════════════════════════════════════════════════════════════

class MemoryPillar(Enum):
    """8-Pillar memory architecture"""
    SHORT_TERM = "short_term"          # Immediate working memory (minutes)
    LONG_TERM = "long_term"            # Persistent storage (years)
    EPISODIC = "episodic"              # Events and experiences
    SEMANTIC = "semantic"              # Facts and knowledge
    PROCEDURAL = "procedural"          # Skills and how-to
    EMOTIONAL = "emotional"            # Emotional context
    CRYSTAL = "crystal"                # Immutable sovereign records
    QUANTUM = "quantum"                # Probabilistic futures

# ══════════════════════════════════════════════════════════════════
# MEMORY ENTRY
# ══════════════════════════════════════════════════════════════════

@dataclass
class MemoryEntry:
    """Individual memory entry"""
    id: str
    pillar: MemoryPillar
    content: Any
    timestamp: float = field(default_factory=time.time)
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    importance: float = 1.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    compressed: bool = False
    immutable: bool = False
    
    def access(self):
        """Record memory access"""
        self.access_count += 1
        self.last_accessed = time.time()
    
    def calculate_relevance(self, current_time: float) -> float:
        """Calculate memory relevance based on recency and importance"""
        time_decay = 1.0 / (1 + (current_time - self.timestamp) / 86400)  # Decay over days
        access_boost = min(self.access_count / 10.0, 2.0)  # Max 2x boost
        return self.importance * time_decay * access_boost

# ══════════════════════════════════════════════════════════════════
# PILLAR CONFIGURATION
# ══════════════════════════════════════════════════════════════════

@dataclass
class PillarConfig:
    """Configuration for each memory pillar"""
    pillar: MemoryPillar
    max_capacity: int
    retention_days: Optional[int]
    compression_enabled: bool
    immutable: bool
    priority: float
    
    def __post_init__(self):
        if self.retention_days is None and self.pillar != MemoryPillar.CRYSTAL:
            # Default retention based on pillar type
            retention_map = {
                MemoryPillar.SHORT_TERM: 1,
                MemoryPillar.LONG_TERM: 3650,
                MemoryPillar.EPISODIC: 365,
                MemoryPillar.SEMANTIC: 3650,
                MemoryPillar.PROCEDURAL: 3650,
                MemoryPillar.EMOTIONAL: 180,
                MemoryPillar.QUANTUM: 30
            }
            self.retention_days = retention_map.get(self.pillar, 365)

PILLAR_CONFIGS = {
    MemoryPillar.SHORT_TERM: PillarConfig(
        pillar=MemoryPillar.SHORT_TERM,
        max_capacity=1000,
        retention_days=1,
        compression_enabled=False,
        immutable=False,
        priority=1.0
    ),
    MemoryPillar.LONG_TERM: PillarConfig(
        pillar=MemoryPillar.LONG_TERM,
        max_capacity=100000,
        retention_days=3650,
        compression_enabled=True,
        immutable=False,
        priority=0.8
    ),
    MemoryPillar.EPISODIC: PillarConfig(
        pillar=MemoryPillar.EPISODIC,
        max_capacity=50000,
        retention_days=365,
        compression_enabled=True,
        immutable=False,
        priority=0.7
    ),
    MemoryPillar.SEMANTIC: PillarConfig(
        pillar=MemoryPillar.SEMANTIC,
        max_capacity=200000,
        retention_days=3650,
        compression_enabled=True,
        immutable=False,
        priority=0.9
    ),
    MemoryPillar.PROCEDURAL: PillarConfig(
        pillar=MemoryPillar.PROCEDURAL,
        max_capacity=10000,
        retention_days=3650,
        compression_enabled=False,
        immutable=False,
        priority=1.0
    ),
    MemoryPillar.EMOTIONAL: PillarConfig(
        pillar=MemoryPillar.EMOTIONAL,
        max_capacity=25000,
        retention_days=180,
        compression_enabled=True,
        immutable=False,
        priority=0.6
    ),
    MemoryPillar.CRYSTAL: PillarConfig(
        pillar=MemoryPillar.CRYSTAL,
        max_capacity=float('inf'),
        retention_days=None,  # Permanent
        compression_enabled=False,
        immutable=True,
        priority=2.0
    ),
    MemoryPillar.QUANTUM: PillarConfig(
        pillar=MemoryPillar.QUANTUM,
        max_capacity=5000,
        retention_days=30,
        compression_enabled=False,
        immutable=False,
        priority=0.5
    )
}

# ══════════════════════════════════════════════════════════════════
# OMEGA MEMORY SYSTEM
# ══════════════════════════════════════════════════════════════════

class OmegaMemorySystem:
    """
    Complete 8-pillar memory architecture for Omega Swarm Brain
    Handles storage, retrieval, compression, and retention
    """
    
    def __init__(self, db_path: str = "P:/ECHO_PRIME/OMEGA_SWARM_BRAIN/memory/omega_memory.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # In-memory caches for each pillar
        self.pillars: Dict[MemoryPillar, List[MemoryEntry]] = {
            pillar: [] for pillar in MemoryPillar
        }
        
        # Pillar configurations
        self.configs = PILLAR_CONFIGS
        
        # Statistics
        self.stats = {
            "total_writes": 0,
            "total_reads": 0,
            "compressions": 0,
            "evictions": 0
        }
        
        # Initialize database
        self._init_database()
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║          OMEGA MEMORY SYSTEM INITIALIZED                     ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
        
        for pillar in MemoryPillar:
            config = self.configs[pillar]
            logging.info(f"💾 {pillar.name}: Capacity {config.max_capacity}, "
                        f"Retention {config.retention_days} days")
    
    def _init_database(self):
        """Initialize SQLite database for persistent storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                pillar TEXT NOT NULL,
                content BLOB,
                timestamp REAL,
                access_count INTEGER,
                last_accessed REAL,
                importance REAL,
                tags TEXT,
                metadata TEXT,
                compressed INTEGER,
                immutable INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_pillar ON memories(pillar)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON memories(timestamp)
        ''')
        
        conn.commit()
        conn.close()
    
    def store(self, pillar: MemoryPillar, content: Any, 
              importance: float = 1.0, tags: List[str] = None,
              metadata: Dict = None) -> MemoryEntry:
        """Store a new memory in specified pillar"""
        memory_id = self._generate_memory_id(pillar, content)
        
        entry = MemoryEntry(
            id=memory_id,
            pillar=pillar,
            content=content,
            importance=importance,
            tags=tags or [],
            metadata=metadata or {},
            immutable=self.configs[pillar].immutable
        )
        
        # Add to in-memory cache
        self.pillars[pillar].append(entry)
        
        # Check capacity and evict if necessary
        self._check_capacity(pillar)
        
        # Persist to database
        self._persist_memory(entry)
        
        self.stats['total_writes'] += 1
        
        logging.debug(f"💾 Stored memory in {pillar.name}: {memory_id[:8]}...")
        return entry
    
    def retrieve(self, pillar: MemoryPillar, memory_id: str) -> Optional[MemoryEntry]:
        """Retrieve a specific memory by ID"""
        # Check in-memory cache first
        for entry in self.pillars[pillar]:
            if entry.id == memory_id:
                entry.access()
                self.stats['total_reads'] += 1
                return entry
        
        # Check database
        entry = self._load_from_database(memory_id)
        if entry:
            entry.access()
            self.stats['total_reads'] += 1
            # Add to cache
            self.pillars[pillar].append(entry)
        
        return entry
    
    def search(self, pillar: Optional[MemoryPillar] = None,
               tags: List[str] = None, 
               min_importance: float = 0.0,
               limit: int = 100) -> List[MemoryEntry]:
        """Search memories by criteria"""
        results = []
        
        # Determine which pillars to search
        pillars_to_search = [pillar] if pillar else list(MemoryPillar)
        
        for p in pillars_to_search:
            for entry in self.pillars[p]:
                # Filter by importance
                if entry.importance < min_importance:
                    continue
                
                # Filter by tags
                if tags and not any(tag in entry.tags for tag in tags):
                    continue
                
                results.append(entry)
                
                if len(results) >= limit:
                    break
        
        # Sort by relevance
        current_time = time.time()
        results.sort(key=lambda e: e.calculate_relevance(current_time), reverse=True)
        
        return results[:limit]
    
    def consolidate(self):
        """
        Consolidate memories across pillars
        Move short-term to long-term, compress old memories
        """
        logging.info("🔄 Starting memory consolidation...")
        
        consolidated_count = 0
        compressed_count = 0
        
        # Move important short-term memories to long-term
        short_term = self.pillars[MemoryPillar.SHORT_TERM]
        for entry in short_term[:]:
            if entry.importance > 1.5 and entry.access_count > 3:
                # Transfer to long-term
                long_term_entry = MemoryEntry(
                    id=entry.id,
                    pillar=MemoryPillar.LONG_TERM,
                    content=entry.content,
                    timestamp=entry.timestamp,
                    access_count=entry.access_count,
                    last_accessed=entry.last_accessed,
                    importance=entry.importance,
                    tags=entry.tags,
                    metadata=entry.metadata
                )
                self.pillars[MemoryPillar.LONG_TERM].append(long_term_entry)
                short_term.remove(entry)
                consolidated_count += 1
        
        # Compress old memories
        for pillar in [MemoryPillar.LONG_TERM, MemoryPillar.EPISODIC]:
            config = self.configs[pillar]
            if config.compression_enabled:
                for entry in self.pillars[pillar]:
                    if not entry.compressed and time.time() - entry.timestamp > 86400 * 7:
                        entry.content = self._compress(entry.content)
                        entry.compressed = True
                        compressed_count += 1
        
        logging.info(f"✅ Consolidated {consolidated_count} memories, compressed {compressed_count}")
        self.stats['compressions'] += compressed_count
    
    def clean_expired(self):
        """Remove expired memories based on retention policies"""
        current_time = time.time()
        removed_count = 0
        
        for pillar, entries in self.pillars.items():
            config = self.configs[pillar]
            
            # Skip crystal pillar (permanent)
            if pillar == MemoryPillar.CRYSTAL:
                continue
            
            if config.retention_days:
                retention_seconds = config.retention_days * 86400
                
                # Remove expired entries
                expired = [e for e in entries if current_time - e.timestamp > retention_seconds]
                for entry in expired:
                    if not entry.immutable:
                        entries.remove(entry)
                        self._delete_from_database(entry.id)
                        removed_count += 1
        
        if removed_count > 0:
            logging.info(f"🗑️ Removed {removed_count} expired memories")
            self.stats['evictions'] += removed_count
    
    def _check_capacity(self, pillar: MemoryPillar):
        """Check pillar capacity and evict if necessary"""
        config = self.configs[pillar]
        entries = self.pillars[pillar]
        
        if len(entries) <= config.max_capacity:
            return
        
        # Evict least relevant memories
        current_time = time.time()
        entries.sort(key=lambda e: e.calculate_relevance(current_time))
        
        # Remove 10% of capacity
        evict_count = int(config.max_capacity * 0.1)
        for _ in range(evict_count):
            if entries and not entries[0].immutable:
                evicted = entries.pop(0)
                self._delete_from_database(evicted.id)
                self.stats['evictions'] += 1
    
    def _compress(self, content: Any) -> bytes:
        """Compress memory content"""
        serialized = pickle.dumps(content)
        compressed = gzip.compress(serialized)
        return compressed
    
    def _decompress(self, compressed: bytes) -> Any:
        """Decompress memory content"""
        decompressed = gzip.decompress(compressed)
        return pickle.loads(decompressed)
    
    def _generate_memory_id(self, pillar: MemoryPillar, content: Any) -> str:
        """Generate unique memory ID"""
        content_str = str(content) + str(time.time())
        return hashlib.sha256(content_str.encode()).hexdigest()
    
    def _persist_memory(self, entry: MemoryEntry):
        """Persist memory to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        content = entry.content if not entry.compressed else entry.content
        if not isinstance(content, bytes):
            content = pickle.dumps(content)
        
        cursor.execute('''
            INSERT OR REPLACE INTO memories 
            (id, pillar, content, timestamp, access_count, last_accessed, 
             importance, tags, metadata, compressed, immutable)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.id,
            entry.pillar.value,
            content,
            entry.timestamp,
            entry.access_count,
            entry.last_accessed,
            entry.importance,
            json.dumps(entry.tags),
            json.dumps(entry.metadata),
            1 if entry.compressed else 0,
            1 if entry.immutable else 0
        ))
        
        conn.commit()
        conn.close()
    
    def _load_from_database(self, memory_id: str) -> Optional[MemoryEntry]:
        """Load memory from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM memories WHERE id = ?', (memory_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        content = pickle.loads(row[2]) if row[2] else None
        
        return MemoryEntry(
            id=row[0],
            pillar=MemoryPillar(row[1]),
            content=content,
            timestamp=row[3],
            access_count=row[4],
            last_accessed=row[5],
            importance=row[6],
            tags=json.loads(row[7]) if row[7] else [],
            metadata=json.loads(row[8]) if row[8] else {},
            compressed=bool(row[9]),
            immutable=bool(row[10])
        )
    
    def _delete_from_database(self, memory_id: str):
        """Delete memory from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM memories WHERE id = ?', (memory_id,))
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get memory system statistics"""
        pillar_stats = {}
        for pillar, entries in self.pillars.items():
            config = self.configs[pillar]
            pillar_stats[pillar.name] = {
                "count": len(entries),
                "capacity": config.max_capacity,
                "utilization": (len(entries) / config.max_capacity * 100) if config.max_capacity != float('inf') else 0,
                "compressed": sum(1 for e in entries if e.compressed)
            }
        
        return {
            "pillars": pillar_stats,
            "total_memories": sum(len(e) for e in self.pillars.values()),
            "stats": self.stats
        }

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - MEMORY - %(levelname)s - %(message)s')
    
    # Initialize memory system
    memory = OmegaMemorySystem()
    
    # Store test memories
    memory.store(MemoryPillar.SHORT_TERM, "Quick thought about task X", importance=1.0)
    memory.store(MemoryPillar.LONG_TERM, "Important knowledge: System architecture", importance=2.0)
    memory.store(MemoryPillar.EPISODIC, "Event: System startup at 10:00 AM", importance=1.5)
    memory.store(MemoryPillar.SEMANTIC, "Fact: Python is a programming language", importance=1.8)
    memory.store(MemoryPillar.PROCEDURAL, "How to: Deploy new agent", importance=2.0)
    memory.store(MemoryPillar.CRYSTAL, "SOVEREIGN_COMMAND: Commander authority verified", importance=3.0)
    
    # Consolidate
    memory.consolidate()
    
    # Show statistics
    stats = memory.get_statistics()
    print("\n" + "="*70)
    print("MEMORY SYSTEM STATISTICS")
    print("="*70)
    print(f"Total Memories: {stats['total_memories']}")
    print("\nPillar Status:")
    for pillar_name, pillar_stats in stats['pillars'].items():
        print(f"{pillar_name}: {pillar_stats['count']}/{pillar_stats['capacity']} "
              f"({pillar_stats['utilization']:.1f}% utilized)")
    
    print(f"\nOperations:")
    print(f"Writes: {stats['stats']['total_writes']}")
    print(f"Reads: {stats['stats']['total_reads']}")
    print(f"Compressions: {stats['stats']['compressions']}")
    print(f"Evictions: {stats['stats']['evictions']}")
