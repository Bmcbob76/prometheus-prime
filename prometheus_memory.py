#!/usr/bin/env python3
"""
PROMETHEUS PRIME - M DRIVE MEMORY INTEGRATION
==============================================
Authority Level: 11.0 - Maximum
Commander: Bobby Don McWilliams II

Integrates Prometheus Prime with M Drive Memory Orchestration System
"""

import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

class PrometheusMemory:
    """M Drive memory integration for Prometheus Prime"""
    
    def __init__(self):
        self.memory_path = os.getenv('PROMETHEUS_MEMORY_PATH', r'M:\MEMORY_ORCHESTRATION')
        self.operations_db = os.path.join(self.memory_path, 'prometheus_operations.db')
        self.commander = os.getenv('PROMETHEUS_COMMANDER', 'Bobby Don McWilliams II')
        self.authority_level = float(os.getenv('PROMETHEUS_AUTHORITY_LEVEL', '11.0'))
        
        # Ensure directories exist
        os.makedirs(self.memory_path, exist_ok=True)
        os.makedirs(os.path.join(self.memory_path, 'prometheus_operations'), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for operation tracking"""
        conn = sqlite3.connect(self.operations_db)
        cursor = conn.cursor()
        
        # Operations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                capability TEXT NOT NULL,
                command TEXT NOT NULL,
                parameters TEXT,
                target TEXT,
                success INTEGER,
                output TEXT,
                execution_time REAL,
                commander TEXT,
                authority_level REAL,
                memory_file TEXT
            )
        ''')
        
        # Targets database
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT,
                authorized INTEGER DEFAULT 0,
                notes TEXT,
                operations_count INTEGER DEFAULT 0
            )
        ''')
        
        # Credentials vault
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT,
                target TEXT,
                username TEXT,
                credential_type TEXT,
                credential_value TEXT,
                domain TEXT,
                notes TEXT
            )
        ''')
        
        # Intelligence reports
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                category TEXT,
                target TEXT,
                title TEXT,
                content TEXT,
                severity TEXT,
                tags TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def log_operation(self, capability: str, command: str, params: Dict = None,
                      target: str = None, success: bool = True, output: str = "",
                      execution_time: float = 0) -> int:
        """Log an operation to M Drive memory"""
        conn = sqlite3.connect(self.operations_db)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        params_json = json.dumps(params) if params else None
        
        # Create memory file
        memory_file = os.path.join(
            self.memory_path, 
            'prometheus_operations',
            f"{capability}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        memory_data = {
            'timestamp': timestamp,
            'capability': capability,
            'command': command,
            'parameters': params,
            'target': target,
            'success': success,
            'output': output,
            'execution_time': execution_time,
            'commander': self.commander,
            'authority_level': self.authority_level
        }
        
        with open(memory_file, 'w') as f:
            json.dump(memory_data, f, indent=2)
        
        # Insert into database
        cursor.execute('''
            INSERT INTO operations 
            (timestamp, capability, command, parameters, target, success, output, 
             execution_time, commander, authority_level, memory_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, capability, command, params_json, target, int(success),
              output[:5000], execution_time, self.commander, self.authority_level, memory_file))
        
        operation_id = cursor.lastrowid
        
        # Update target if provided
        if target:
            self._update_target(cursor, target)
        
        conn.commit()
        conn.close()
        
        return operation_id
        
    def _update_target(self, cursor, target: str):
        """Update or create target entry"""
        timestamp = datetime.now().isoformat()
        
        cursor.execute('SELECT id, operations_count FROM targets WHERE ip_address = ?', (target,))
        result = cursor.fetchone()
        
        if result:
            target_id, ops_count = result
            cursor.execute('''
                UPDATE targets 
                SET last_seen = ?, operations_count = ?
                WHERE id = ?
            ''', (timestamp, ops_count + 1, target_id))
        else:
            cursor.execute('''
                INSERT INTO targets (ip_address, first_seen, last_seen, operations_count)
                VALUES (?, ?, ?, 1)
            ''', (target, timestamp, timestamp))
    
    def store_credential(self, source: str, target: str, username: str,
                        credential_type: str, credential_value: str,
                        domain: str = None, notes: str = None):
        """Store harvested credentials"""
        conn = sqlite3.connect(self.operations_db)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO credentials
            (timestamp, source, target, username, credential_type, credential_value, domain, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, source, target, username, credential_type, credential_value, domain, notes))
        
        conn.commit()
        conn.close()
        
    def store_intelligence(self, category: str, target: str, title: str,
                          content: str, severity: str = 'INFO', tags: List[str] = None):
        """Store intelligence report"""
        conn = sqlite3.connect(self.operations_db)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        tags_json = json.dumps(tags) if tags else None
        
        cursor.execute('''
            INSERT INTO intelligence
            (timestamp, category, target, title, content, severity, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, category, target, title, content, severity, tags_json))
        
        conn.commit()
        conn.close()
        
    def get_recent_operations(self, limit: int = 50) -> List[Dict]:
        """Retrieve recent operations"""
        conn = sqlite3.connect(self.operations_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM operations
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        operations = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return operations
        
    def get_target_history(self, target: str) -> Dict:
        """Get complete history for a target"""
        conn = sqlite3.connect(self.operations_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get target info
        cursor.execute('SELECT * FROM targets WHERE ip_address = ?', (target,))
        target_info = dict(cursor.fetchone()) if cursor.fetchone() else None
        
        # Get operations
        cursor.execute('''
            SELECT * FROM operations
            WHERE target = ?
            ORDER BY timestamp DESC
        ''', (target,))
        operations = [dict(row) for row in cursor.fetchall()]
        
        # Get credentials
        cursor.execute('''
            SELECT * FROM credentials
            WHERE target = ?
            ORDER BY timestamp DESC
        ''', (target,))
        credentials = [dict(row) for row in cursor.fetchall()]
        
        # Get intelligence
        cursor.execute('''
            SELECT * FROM intelligence
            WHERE target = ?
            ORDER BY timestamp DESC
        ''', (target,))
        intelligence = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'target_info': target_info,
            'operations': operations,
            'credentials': credentials,
            'intelligence': intelligence
        }
        
    def search_operations(self, capability: str = None, target: str = None,
                         success_only: bool = False, limit: int = 100) -> List[Dict]:
        """Search operations by criteria"""
        conn = sqlite3.connect(self.operations_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = 'SELECT * FROM operations WHERE 1=1'
        params = []
        
        if capability:
            query += ' AND capability = ?'
            params.append(capability)
            
        if target:
            query += ' AND target = ?'
            params.append(target)
            
        if success_only:
            query += ' AND success = 1'
            
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        operations = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return operations
        
    def get_statistics(self) -> Dict:
        """Get operation statistics"""
        conn = sqlite3.connect(self.operations_db)
        cursor = conn.cursor()
        
        # Total operations
        cursor.execute('SELECT COUNT(*) FROM operations')
        total_ops = cursor.fetchone()[0]
        
        # Success rate
        cursor.execute('SELECT COUNT(*) FROM operations WHERE success = 1')
        successful_ops = cursor.fetchone()[0]
        
        # Capabilities usage
        cursor.execute('''
            SELECT capability, COUNT(*) as count
            FROM operations
            GROUP BY capability
            ORDER BY count DESC
        ''')
        capabilities = dict(cursor.fetchall())
        
        # Target count
        cursor.execute('SELECT COUNT(*) FROM targets')
        target_count = cursor.fetchone()[0]
        
        # Credential count
        cursor.execute('SELECT COUNT(*) FROM credentials')
        credential_count = cursor.fetchone()[0]
        
        conn.close()
        
        success_rate = (successful_ops / total_ops * 100) if total_ops > 0 else 0
        
        return {
            'total_operations': total_ops,
            'successful_operations': successful_ops,
            'success_rate': round(success_rate, 2),
            'capabilities_usage': capabilities,
            'targets_tracked': target_count,
            'credentials_stored': credential_count,
            'commander': self.commander,
            'authority_level': self.authority_level
        }

# Global instance
_prometheus_memory = None

def get_memory() -> PrometheusMemory:
    """Get or create Prometheus memory instance"""
    global _prometheus_memory
    if _prometheus_memory is None:
        _prometheus_memory = PrometheusMemory()
    return _prometheus_memory
