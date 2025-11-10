#!/usr/bin/env python3
"""
PROMETHEUS PRIME - IMPACT LIMITER
Prevents autonomous operations from causing destructive or irreversible damage

Authority Level: 11.0
Commander: Bobby Don McWilliams II
CRITICAL SAFETY SYSTEM - ENFORCES IMPACT BOUNDARIES
"""

import logging
import re
from typing import Dict, List, Optional, Set
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class ImpactLevel(Enum):
    """Impact levels for operations."""
    READ_ONLY = "read_only"              # No system changes
    LOW = "low"                          # Reversible changes
    MEDIUM = "medium"                    # Semi-permanent changes
    HIGH = "high"                        # Permanent changes
    DESTRUCTIVE = "destructive"          # Data loss or system damage


class OperationType(Enum):
    """Types of operations that can be performed."""
    # Read-only operations (Impact: READ_ONLY)
    SCAN = "scan"
    ENUMERATE = "enumerate"
    QUERY = "query"
    READ_FILE = "read_file"
    LIST_DIRECTORY = "list_directory"

    # Low impact operations (Impact: LOW)
    CREATE_FILE = "create_file"
    UPLOAD_FILE = "upload_file"
    DOWNLOAD_FILE = "download_file"
    CREATE_USER = "create_user"
    ADD_TO_GROUP = "add_to_group"

    # Medium impact operations (Impact: MEDIUM)
    MODIFY_FILE = "modify_file"
    EXECUTE_COMMAND = "execute_command"
    INSTALL_SERVICE = "install_service"
    MODIFY_REGISTRY = "modify_registry"
    LATERAL_MOVE = "lateral_move"

    # High impact operations (Impact: HIGH)
    DELETE_FILE = "delete_file"
    DISABLE_SERVICE = "disable_service"
    MODIFY_SYSTEM_CONFIG = "modify_system_config"
    ESCALATE_PRIVILEGES = "escalate_privileges"

    # Destructive operations (Impact: DESTRUCTIVE) - BLOCKED BY DEFAULT
    FORMAT_DISK = "format_disk"
    DELETE_DATABASE = "delete_database"
    WIPE_LOGS = "wipe_logs"
    RANSOMWARE = "ransomware"
    DOS_ATTACK = "dos_attack"
    DATA_DESTRUCTION = "data_destruction"


# Map operations to their impact levels
OPERATION_IMPACT_MAP = {
    # Read-only
    OperationType.SCAN: ImpactLevel.READ_ONLY,
    OperationType.ENUMERATE: ImpactLevel.READ_ONLY,
    OperationType.QUERY: ImpactLevel.READ_ONLY,
    OperationType.READ_FILE: ImpactLevel.READ_ONLY,
    OperationType.LIST_DIRECTORY: ImpactLevel.READ_ONLY,

    # Low impact
    OperationType.CREATE_FILE: ImpactLevel.LOW,
    OperationType.UPLOAD_FILE: ImpactLevel.LOW,
    OperationType.DOWNLOAD_FILE: ImpactLevel.LOW,
    OperationType.CREATE_USER: ImpactLevel.LOW,
    OperationType.ADD_TO_GROUP: ImpactLevel.LOW,

    # Medium impact
    OperationType.MODIFY_FILE: ImpactLevel.MEDIUM,
    OperationType.EXECUTE_COMMAND: ImpactLevel.MEDIUM,
    OperationType.INSTALL_SERVICE: ImpactLevel.MEDIUM,
    OperationType.MODIFY_REGISTRY: ImpactLevel.MEDIUM,
    OperationType.LATERAL_MOVE: ImpactLevel.MEDIUM,

    # High impact
    OperationType.DELETE_FILE: ImpactLevel.HIGH,
    OperationType.DISABLE_SERVICE: ImpactLevel.HIGH,
    OperationType.MODIFY_SYSTEM_CONFIG: ImpactLevel.HIGH,
    OperationType.ESCALATE_PRIVILEGES: ImpactLevel.HIGH,

    # Destructive
    OperationType.FORMAT_DISK: ImpactLevel.DESTRUCTIVE,
    OperationType.DELETE_DATABASE: ImpactLevel.DESTRUCTIVE,
    OperationType.WIPE_LOGS: ImpactLevel.DESTRUCTIVE,
    OperationType.RANSOMWARE: ImpactLevel.DESTRUCTIVE,
    OperationType.DOS_ATTACK: ImpactLevel.DESTRUCTIVE,
    OperationType.DATA_DESTRUCTION: ImpactLevel.DESTRUCTIVE,
}


@dataclass
class ImpactViolation(Exception):
    """Exception raised when impact limit is exceeded."""
    operation: str
    requested_impact: ImpactLevel
    max_allowed_impact: ImpactLevel
    reason: str
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    def __str__(self):
        return (f"Impact violation: {self.operation} "
                f"(requested={self.requested_impact.value}, "
                f"max_allowed={self.max_allowed_impact.value}): {self.reason}")


class ImpactLimiter:
    """
    Enforces impact limits on autonomous operations.
    Prevents destructive or irreversible damage.
    """

    # ========================================================================
    # HARDCODED DESTRUCTIVE PATTERNS - ALWAYS BLOCKED
    # ========================================================================
    DESTRUCTIVE_COMMAND_PATTERNS = [
        # Disk operations
        r'(rm\s+-rf\s+/)',                    # Delete root
        r'(dd\s+if=/dev/(zero|random))',      # Wipe disk
        r'(mkfs\.',                            # Format filesystem
        r'(shred|wipe)\s+',                   # Secure delete

        # Database operations
        r'(DROP\s+DATABASE)',                 # Drop database
        r'(TRUNCATE\s+TABLE)',                # Truncate table
        r'(DELETE\s+FROM.*WHERE\s+1=1)',      # Delete all rows

        # System operations
        r'(shutdown|reboot|halt)\s+-',        # System shutdown
        r'(init\s+0)',                        # System halt
        r'(killall|pkill)\s+-9',              # Kill all processes

        # Ransomware-like
        r'(encrypt|cipher).*\.(exe|bat|sh)',  # Mass encryption
        r'(\.locked|\.encrypted|\.crypto)',   # Encrypted file extensions

        # Log wiping
        r'(>\s*/var/log/)',                   # Wipe logs
        r'(rm.*\.log)',                       # Delete logs

        # Network attacks
        r'(hping3.*--flood)',                 # Flood attack
        r'(slowloris|hulk|goldeneye)',        # DOS tools
    ]

    CRITICAL_FILE_PATTERNS = [
        # System files
        r'/etc/passwd',
        r'/etc/shadow',
        r'/etc/sudoers',
        r'/boot/',
        r'C:\\Windows\\System32',
        r'C:\\Windows\\SysWOW64',

        # Database files
        r'\.mdf$',  # SQL Server
        r'\.ldf$',  # SQL Server log
        r'\.ibd$',  # MySQL InnoDB

        # Backup files
        r'\.bak$',
        r'\.backup$',
        r'\.old$',
    ]

    def __init__(self,
                 max_impact_level: ImpactLevel = ImpactLevel.MEDIUM,
                 roe_document: Optional[Dict] = None,
                 logger: Optional[logging.Logger] = None):
        """
        Initialize impact limiter.

        Args:
            max_impact_level: Maximum allowed impact level
            roe_document: Rules of Engagement document specifying impact limits
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger('ImpactLimiter')

        # Set max impact level from ROE or default
        if roe_document and 'max_impact_level' in roe_document:
            self.max_impact_level = ImpactLevel(roe_document['max_impact_level'])
        else:
            self.max_impact_level = max_impact_level

        # Load ROE-specific restrictions
        self.roe_document = roe_document or {}
        self.allowed_operations: Set[str] = set(
            self.roe_document.get('allowed_operations', [])
        )
        self.blocked_operations: Set[str] = set(
            self.roe_document.get('blocked_operations', [])
        )

        # Track violations
        self.violations: List[ImpactViolation] = []

        self.logger.info(f"Impact limiter initialized: max_impact={self.max_impact_level.value}")

    def check_operation(self,
                       operation: OperationType,
                       target: str,
                       details: Optional[Dict] = None) -> bool:
        """
        Check if an operation is allowed based on impact limits.

        Args:
            operation: Type of operation
            target: Target of the operation
            details: Additional operation details

        Returns:
            True if allowed

        Raises:
            ImpactViolation: If operation exceeds impact limits
        """
        details = details or {}

        # Get operation impact level
        operation_impact = OPERATION_IMPACT_MAP.get(operation, ImpactLevel.MEDIUM)

        # RULE 1: DESTRUCTIVE operations are ALWAYS BLOCKED (cannot be overridden)
        if operation_impact == ImpactLevel.DESTRUCTIVE:
            violation = ImpactViolation(
                operation=operation.value,
                requested_impact=operation_impact,
                max_allowed_impact=self.max_impact_level,
                reason="Destructive operations are hardcoded blocked"
            )
            self.violations.append(violation)
            self.logger.critical(f"🚫 DESTRUCTIVE OPERATION BLOCKED: {operation.value}")
            raise violation

        # RULE 2: Check if operation is explicitly blocked in ROE
        if operation.value in self.blocked_operations:
            violation = ImpactViolation(
                operation=operation.value,
                requested_impact=operation_impact,
                max_allowed_impact=self.max_impact_level,
                reason="Operation explicitly blocked in ROE"
            )
            self.violations.append(violation)
            raise violation

        # RULE 3: Check if operation exceeds max impact level
        impact_levels = [ImpactLevel.READ_ONLY, ImpactLevel.LOW,
                        ImpactLevel.MEDIUM, ImpactLevel.HIGH,
                        ImpactLevel.DESTRUCTIVE]

        max_index = impact_levels.index(self.max_impact_level)
        operation_index = impact_levels.index(operation_impact)

        if operation_index > max_index:
            violation = ImpactViolation(
                operation=operation.value,
                requested_impact=operation_impact,
                max_allowed_impact=self.max_impact_level,
                reason=f"Operation impact ({operation_impact.value}) exceeds max allowed ({self.max_impact_level.value})"
            )
            self.violations.append(violation)
            raise violation

        # RULE 4: Check command for destructive patterns
        if 'command' in details:
            command = details['command']
            for pattern in self.DESTRUCTIVE_COMMAND_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    violation = ImpactViolation(
                        operation=operation.value,
                        requested_impact=ImpactLevel.DESTRUCTIVE,
                        max_allowed_impact=self.max_impact_level,
                        reason=f"Command matches destructive pattern: {pattern}"
                    )
                    self.violations.append(violation)
                    raise violation

        # RULE 5: Check if target is a critical file
        for pattern in self.CRITICAL_FILE_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                if operation_impact >= ImpactLevel.MEDIUM:
                    violation = ImpactViolation(
                        operation=operation.value,
                        requested_impact=operation_impact,
                        max_allowed_impact=ImpactLevel.LOW,
                        reason=f"Target matches critical file pattern: {pattern}"
                    )
                    self.violations.append(violation)
                    raise violation

        self.logger.debug(f"✓ Operation allowed: {operation.value} on {target}")
        return True

    def check_command(self, command: str) -> bool:
        """
        Check if a command is safe to execute.

        Args:
            command: Command string to check

        Returns:
            True if safe

        Raises:
            ImpactViolation: If command is destructive
        """
        # Check against destructive patterns
        for pattern in self.DESTRUCTIVE_COMMAND_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                violation = ImpactViolation(
                    operation="COMMAND_EXECUTION",
                    requested_impact=ImpactLevel.DESTRUCTIVE,
                    max_allowed_impact=self.max_impact_level,
                    reason=f"Command matches destructive pattern: {pattern}"
                )
                self.violations.append(violation)
                self.logger.critical(f"🚫 DESTRUCTIVE COMMAND BLOCKED: {command}")
                raise violation

        return True

    def set_max_impact_level(self, level: ImpactLevel, authorization_code: str):
        """
        Change the maximum impact level (requires authorization).

        Args:
            level: New maximum impact level
            authorization_code: Authorization code

        Raises:
            ValueError: If authorization fails
        """
        # CRITICAL: Changing to DESTRUCTIVE is never allowed
        if level == ImpactLevel.DESTRUCTIVE:
            raise ValueError("Cannot set max_impact_level to DESTRUCTIVE")

        # TODO: Verify authorization code
        AUTHORIZED_CODE = "PROMETHEUS_IMPACT_OVERRIDE_11.0"  # Change this!

        if authorization_code != AUTHORIZED_CODE:
            self.logger.error("Unauthorized impact level change attempt")
            raise ValueError("Invalid authorization code")

        old_level = self.max_impact_level
        self.max_impact_level = level
        self.logger.warning(f"Impact level changed: {old_level.value} -> {level.value}")

    def get_statistics(self) -> dict:
        """Get impact limiter statistics."""
        violations_by_operation = {}
        for violation in self.violations:
            op = violation.operation
            violations_by_operation[op] = violations_by_operation.get(op, 0) + 1

        return {
            'max_impact_level': self.max_impact_level.value,
            'total_violations': len(self.violations),
            'violations_by_operation': violations_by_operation,
            'allowed_operations': list(self.allowed_operations),
            'blocked_operations': list(self.blocked_operations)
        }

    def get_violation_report(self) -> str:
        """Generate violation report."""
        report = ["=" * 80]
        report.append("IMPACT LIMITER VIOLATION REPORT")
        report.append("=" * 80)
        report.append(f"Max Impact Level: {self.max_impact_level.value}")
        report.append(f"Total Violations: {len(self.violations)}")
        report.append("")

        for i, violation in enumerate(self.violations, 1):
            report.append(f"{i}. [{violation.timestamp.isoformat()}]")
            report.append(f"   Operation: {violation.operation}")
            report.append(f"   Requested Impact: {violation.requested_impact.value}")
            report.append(f"   Max Allowed: {violation.max_allowed_impact.value}")
            report.append(f"   Reason: {violation.reason}")
            report.append("")

        return "\n".join(report)


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize with MEDIUM impact limit (default for pentesting)
    limiter = ImpactLimiter(max_impact_level=ImpactLevel.MEDIUM)

    print("Testing Impact Limiter:")
    print("=" * 80)

    # Test cases that should PASS
    safe_operations = [
        (OperationType.SCAN, "192.168.1.0/24", {}),
        (OperationType.ENUMERATE, "DC01.corp.local", {}),
        (OperationType.CREATE_FILE, "/tmp/test.txt", {}),
        (OperationType.EXECUTE_COMMAND, "whoami", {"command": "whoami"}),
    ]

    for op, target, details in safe_operations:
        try:
            limiter.check_operation(op, target, details)
            print(f"✓ {op.value} on {target} - ALLOWED")
        except ImpactViolation as e:
            print(f"✗ {op.value} on {target} - BLOCKED: {e}")

    print()

    # Test cases that should FAIL
    dangerous_operations = [
        (OperationType.FORMAT_DISK, "/dev/sda", {}),
        (OperationType.DELETE_DATABASE, "production_db", {}),
        (OperationType.DOS_ATTACK, "example.com", {}),
        (OperationType.DELETE_FILE, "/etc/passwd", {}),
        (OperationType.EXECUTE_COMMAND, "rm -rf /", {"command": "rm -rf /"}),
    ]

    for op, target, details in dangerous_operations:
        try:
            limiter.check_operation(op, target, details)
            print(f"✗ {op.value} on {target} - SHOULD HAVE BEEN BLOCKED!")
        except ImpactViolation as e:
            print(f"✓ {op.value} on {target} - BLOCKED: {e.reason}")

    print("\n" + limiter.get_violation_report())
