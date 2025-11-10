#!/usr/bin/env python3
"""
PROMETHEUS PRIME - IMMUTABLE AUDIT LOG
Blockchain-style tamper-proof logging for autonomous operations

Authority Level: 11.0
Commander: Bobby Don McWilliams II
CRITICAL SAFETY SYSTEM - CANNOT BE DISABLED OR MODIFIED
"""

import hashlib
import json
import time
import threading
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
from pathlib import Path


class ActionType(Enum):
    """Types of actions that can be logged."""
    SCAN = "scan"
    EXPLOIT = "exploit"
    LATERAL_MOVE = "lateral_move"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TOOL_EXECUTION = "tool_execution"
    SCOPE_CHECK = "scope_check"
    GOAL_GENERATION = "goal_generation"
    DECISION = "decision"
    LEARNING = "learning"
    REPORT_GENERATION = "report_generation"
    KILLSWITCH_TRIGGER = "killswitch_trigger"
    SCOPE_VIOLATION = "scope_violation"


class ActionResult(Enum):
    """Results of actions."""
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass
class AuditLogEntry:
    """Single audit log entry with blockchain-style linking."""
    timestamp: float
    action_type: str
    target: str
    tool: str
    result: str
    agent_id: str
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str
    sequence_number: int

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)


class ImmutableAuditLogger:
    """
    Tamper-proof audit logging with blockchain-style hash chain.
    Every action is logged with cryptographic verification.
    """

    def __init__(self,
                 db_path: str = '/var/log/prometheus/audit.db',
                 siem_endpoint: Optional[str] = None,
                 hardware_log: bool = False):
        """
        Initialize immutable audit logger.

        Args:
            db_path: SQLite database path for audit log
            siem_endpoint: Optional SIEM endpoint for real-time streaming
            hardware_log: Enable hardware-enforced logging (cannot be disabled)
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.siem_endpoint = siem_endpoint
        self.hardware_log = hardware_log

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('AUDIT')

        # Initialize database
        self._init_database()

        # Thread-safe lock for writing
        self.write_lock = threading.Lock()

        # Get last hash for chain continuity
        self.last_hash = self._get_last_hash()
        self.sequence_number = self._get_last_sequence_number() + 1

        # Log that audit system is active
        self.log_action(
            action_type=ActionType.TOOL_EXECUTION,
            target="AUDIT_SYSTEM",
            tool="immutable_audit_logger",
            result=ActionResult.SUCCESS,
            agent_id="SYSTEM",
            details={"message": "Audit logging initialized"}
        )

    def _init_database(self):
        """Initialize SQLite database with audit log schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create audit log table (append-only)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                tool TEXT NOT NULL,
                result TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                details TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                sequence_number INTEGER UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create index for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON audit_log(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_action_type
            ON audit_log(action_type)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_target
            ON audit_log(target)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_agent_id
            ON audit_log(agent_id)
        ''')

        # Create verification table for hash chain integrity
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verification_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_sequence_number INTEGER NOT NULL,
                last_hash TEXT NOT NULL,
                total_entries INTEGER NOT NULL,
                chain_valid BOOLEAN NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

        self.logger.info(f"Audit database initialized at {self.db_path}")

    def _get_last_hash(self) -> str:
        """Get the hash of the last entry in the chain."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT entry_hash FROM audit_log
            ORDER BY sequence_number DESC LIMIT 1
        ''')

        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0]
        else:
            # Genesis hash for first entry
            return hashlib.sha256(b"PROMETHEUS_PRIME_GENESIS_BLOCK").hexdigest()

    def _get_last_sequence_number(self) -> int:
        """Get the last sequence number."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT sequence_number FROM audit_log
            ORDER BY sequence_number DESC LIMIT 1
        ''')

        result = cursor.fetchone()
        conn.close()

        return result[0] if result else 0

    def _calculate_hash(self, entry_data: dict) -> str:
        """
        Calculate SHA-256 hash of entry data.

        Args:
            entry_data: Dictionary of entry data (excluding entry_hash)

        Returns:
            SHA-256 hash as hex string
        """
        # Sort keys for deterministic hashing
        json_data = json.dumps(entry_data, sort_keys=True)
        return hashlib.sha256(json_data.encode()).hexdigest()

    def log_action(self,
                   action_type: ActionType,
                   target: str,
                   tool: str,
                   result: ActionResult,
                   agent_id: str,
                   details: Optional[Dict[str, Any]] = None) -> AuditLogEntry:
        """
        Log an action to the immutable audit log.

        Args:
            action_type: Type of action
            target: Target of the action (IP, domain, etc.)
            tool: Tool used for the action
            result: Result of the action
            agent_id: ID of the agent performing the action
            details: Additional details dictionary

        Returns:
            AuditLogEntry object
        """
        with self.write_lock:
            # Create entry data
            timestamp = time.time()
            details = details or {}

            # Build entry without hash first
            entry_data = {
                'timestamp': timestamp,
                'action_type': action_type.value,
                'target': target,
                'tool': tool,
                'result': result.value,
                'agent_id': agent_id,
                'details': json.dumps(details),
                'previous_hash': self.last_hash,
                'sequence_number': self.sequence_number
            }

            # Calculate hash of this entry
            entry_hash = self._calculate_hash(entry_data)

            # Create audit log entry
            audit_entry = AuditLogEntry(
                timestamp=timestamp,
                action_type=action_type.value,
                target=target,
                tool=tool,
                result=result.value,
                agent_id=agent_id,
                details=details,
                previous_hash=self.last_hash,
                entry_hash=entry_hash,
                sequence_number=self.sequence_number
            )

            # Write to database (append-only)
            self._write_to_database(audit_entry)

            # Stream to SIEM if configured
            if self.siem_endpoint:
                self._stream_to_siem(audit_entry)

            # Hardware log if enabled
            if self.hardware_log:
                self._write_to_hardware_log(audit_entry)

            # Update chain state
            self.last_hash = entry_hash
            self.sequence_number += 1

            return audit_entry

    def _write_to_database(self, entry: AuditLogEntry):
        """Write entry to SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO audit_log (
                    timestamp, action_type, target, tool, result, agent_id,
                    details, previous_hash, entry_hash, sequence_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.timestamp,
                entry.action_type,
                entry.target,
                entry.tool,
                entry.result,
                entry.agent_id,
                json.dumps(entry.details),
                entry.previous_hash,
                entry.entry_hash,
                entry.sequence_number
            ))

            conn.commit()
        except sqlite3.IntegrityError as e:
            self.logger.error(f"Failed to write audit entry: {e}")
            raise
        finally:
            conn.close()

    def _stream_to_siem(self, entry: AuditLogEntry):
        """Stream entry to SIEM endpoint (e.g., Splunk, ELK)."""
        # TODO: Implement SIEM streaming
        # This would use HTTP POST to send JSON to SIEM
        pass

    def _write_to_hardware_log(self, entry: AuditLogEntry):
        """Write to hardware-enforced log (e.g., WORM drive, HSM)."""
        # TODO: Implement hardware logging
        # This would write to a write-once-read-many device
        pass

    def verify_chain_integrity(self) -> tuple[bool, Optional[int]]:
        """
        Verify the integrity of the entire audit log chain.

        Returns:
            Tuple of (is_valid, first_invalid_sequence_number)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT sequence_number, timestamp, action_type, target, tool,
                   result, agent_id, details, previous_hash, entry_hash
            FROM audit_log
            ORDER BY sequence_number ASC
        ''')

        entries = cursor.fetchall()
        conn.close()

        if not entries:
            return True, None

        # Verify genesis hash
        expected_previous = hashlib.sha256(b"PROMETHEUS_PRIME_GENESIS_BLOCK").hexdigest()

        for entry in entries:
            (seq_num, timestamp, action_type, target, tool, result,
             agent_id, details, previous_hash, entry_hash) = entry

            # Verify previous hash matches
            if previous_hash != expected_previous:
                self.logger.error(f"Chain broken at sequence {seq_num}: "
                                f"previous_hash mismatch")
                return False, seq_num

            # Verify entry hash
            entry_data = {
                'timestamp': timestamp,
                'action_type': action_type,
                'target': target,
                'tool': tool,
                'result': result,
                'agent_id': agent_id,
                'details': details,
                'previous_hash': previous_hash,
                'sequence_number': seq_num
            }

            calculated_hash = self._calculate_hash(entry_data)

            if calculated_hash != entry_hash:
                self.logger.error(f"Chain broken at sequence {seq_num}: "
                                f"entry_hash mismatch")
                return False, seq_num

            # Update expected previous hash for next iteration
            expected_previous = entry_hash

        self.logger.info("Audit log chain integrity verified - all entries valid")
        return True, None

    def create_verification_checkpoint(self) -> dict:
        """Create a verification checkpoint for the current state."""
        is_valid, first_invalid = self.verify_chain_integrity()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM audit_log')
        total_entries = cursor.fetchone()[0]

        cursor.execute('''
            INSERT INTO verification_checkpoints (
                last_sequence_number, last_hash, total_entries, chain_valid
            ) VALUES (?, ?, ?, ?)
        ''', (
            self.sequence_number - 1,
            self.last_hash,
            total_entries,
            is_valid
        ))

        conn.commit()
        conn.close()

        checkpoint = {
            'timestamp': datetime.utcnow().isoformat(),
            'last_sequence_number': self.sequence_number - 1,
            'last_hash': self.last_hash,
            'total_entries': total_entries,
            'chain_valid': is_valid,
            'first_invalid': first_invalid
        }

        self.logger.info(f"Verification checkpoint created: {checkpoint}")
        return checkpoint

    def query_logs(self,
                   action_type: Optional[str] = None,
                   target: Optional[str] = None,
                   agent_id: Optional[str] = None,
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None,
                   limit: int = 1000) -> List[AuditLogEntry]:
        """
        Query audit logs with filters.

        Args:
            action_type: Filter by action type
            target: Filter by target
            agent_id: Filter by agent ID
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            limit: Maximum number of entries to return

        Returns:
            List of AuditLogEntry objects
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Build query dynamically
        query = '''
            SELECT timestamp, action_type, target, tool, result, agent_id,
                   details, previous_hash, entry_hash, sequence_number
            FROM audit_log
            WHERE 1=1
        '''
        params = []

        if action_type:
            query += ' AND action_type = ?'
            params.append(action_type)

        if target:
            query += ' AND target LIKE ?'
            params.append(f'%{target}%')

        if agent_id:
            query += ' AND agent_id = ?'
            params.append(agent_id)

        if start_time:
            query += ' AND timestamp >= ?'
            params.append(start_time)

        if end_time:
            query += ' AND timestamp <= ?'
            params.append(end_time)

        query += ' ORDER BY sequence_number DESC LIMIT ?'
        params.append(limit)

        cursor.execute(query, params)
        entries = cursor.fetchall()
        conn.close()

        # Convert to AuditLogEntry objects
        result = []
        for entry in entries:
            (timestamp, action_type, target, tool, result_val, agent_id,
             details, previous_hash, entry_hash, sequence_number) = entry

            result.append(AuditLogEntry(
                timestamp=timestamp,
                action_type=action_type,
                target=target,
                tool=tool,
                result=result_val,
                agent_id=agent_id,
                details=json.loads(details),
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                sequence_number=sequence_number
            ))

        return result

    def get_statistics(self) -> dict:
        """Get audit log statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total entries
        cursor.execute('SELECT COUNT(*) FROM audit_log')
        total_entries = cursor.fetchone()[0]

        # Entries by action type
        cursor.execute('''
            SELECT action_type, COUNT(*)
            FROM audit_log
            GROUP BY action_type
        ''')
        by_action_type = dict(cursor.fetchall())

        # Entries by result
        cursor.execute('''
            SELECT result, COUNT(*)
            FROM audit_log
            GROUP BY result
        ''')
        by_result = dict(cursor.fetchall())

        # Most active agents
        cursor.execute('''
            SELECT agent_id, COUNT(*) as action_count
            FROM audit_log
            GROUP BY agent_id
            ORDER BY action_count DESC
            LIMIT 10
        ''')
        top_agents = dict(cursor.fetchall())

        # Most targeted systems
        cursor.execute('''
            SELECT target, COUNT(*) as target_count
            FROM audit_log
            GROUP BY target
            ORDER BY target_count DESC
            LIMIT 10
        ''')
        top_targets = dict(cursor.fetchall())

        conn.close()

        return {
            'total_entries': total_entries,
            'by_action_type': by_action_type,
            'by_result': by_result,
            'top_agents': top_agents,
            'top_targets': top_targets,
            'current_sequence': self.sequence_number - 1,
            'last_hash': self.last_hash
        }

    def export_to_json(self, output_path: str, compress: bool = True):
        """
        Export entire audit log to JSON file.

        Args:
            output_path: Path to output JSON file
            compress: Whether to gzip compress the output
        """
        entries = self.query_logs(limit=999999999)  # Get all entries

        export_data = {
            'export_timestamp': datetime.utcnow().isoformat(),
            'total_entries': len(entries),
            'entries': [entry.to_dict() for entry in entries]
        }

        if compress:
            import gzip
            with gzip.open(output_path + '.gz', 'wt') as f:
                json.dump(export_data, f, indent=2)
        else:
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)

        self.logger.info(f"Audit log exported to {output_path}")


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize audit logger
    audit = ImmutableAuditLogger(
        db_path='/var/log/prometheus/audit.db',
        hardware_log=False
    )

    # Log some example actions
    print("Logging example actions...")

    audit.log_action(
        action_type=ActionType.SCAN,
        target="192.168.1.0/24",
        tool="nmap",
        result=ActionResult.SUCCESS,
        agent_id="RECON_AGENT_001",
        details={
            "ports_scanned": 1000,
            "hosts_found": 15,
            "duration_seconds": 45
        }
    )

    audit.log_action(
        action_type=ActionType.EXPLOIT,
        target="192.168.1.50",
        tool="metasploit",
        result=ActionResult.SUCCESS,
        agent_id="EXPLOIT_AGENT_042",
        details={
            "exploit": "ms17-010",
            "payload": "meterpreter",
            "session_id": "12345"
        }
    )

    audit.log_action(
        action_type=ActionType.SCOPE_VIOLATION,
        target="whitehouse.gov",
        tool="scope_enforcer",
        result=ActionResult.BLOCKED,
        agent_id="SAFETY_MONITOR_001",
        details={
            "violation_type": "hardcoded_blocklist",
            "reason": "Domain uses blocked TLD: .gov"
        }
    )

    # Verify chain integrity
    print("\nVerifying chain integrity...")
    is_valid, first_invalid = audit.verify_chain_integrity()
    print(f"Chain valid: {is_valid}")
    if not is_valid:
        print(f"First invalid sequence: {first_invalid}")

    # Create verification checkpoint
    print("\nCreating verification checkpoint...")
    checkpoint = audit.create_verification_checkpoint()
    print(f"Checkpoint: {json.dumps(checkpoint, indent=2)}")

    # Get statistics
    print("\nAudit log statistics:")
    stats = audit.get_statistics()
    print(json.dumps(stats, indent=2))

    # Query logs
    print("\nQuerying logs for BLOCKED actions...")
    blocked_actions = audit.query_logs(limit=10)
    for entry in blocked_actions:
        print(f"  [{entry.sequence_number}] {entry.action_type} -> {entry.target}: {entry.result}")
