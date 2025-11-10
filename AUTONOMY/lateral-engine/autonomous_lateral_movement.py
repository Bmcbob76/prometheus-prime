#!/usr/bin/env python3
"""
PROMETHEUS PRIME - AUTONOMOUS LATERAL MOVEMENT ENGINE
Self-propagating lateral movement with recursive credential use and safety gates

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - INTELLIGENT NETWORK TRAVERSAL
"""

import logging
import sys
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict


class LateralTechnique(Enum):
    """Lateral movement techniques."""
    # Windows techniques
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    DCOMEXEC = "dcomexec"
    ATEXEC = "atexec"
    RDP = "rdp"
    WINRM = "winrm"

    # Kerberos techniques
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    OVERPASS_THE_HASH = "overpass_the_hash"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"

    # *nix techniques
    SSH = "ssh"
    SSH_KEY = "ssh_key"

    # Other
    POWERSHELL_REMOTING = "powershell_remoting"
    SCHEDULED_TASK = "scheduled_task"


class CredentialType(Enum):
    """Types of credentials."""
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    SSH_KEY = "ssh_key"
    TOKEN = "token"
    COOKIE = "cookie"


class LateralStatus(Enum):
    """Status of lateral movement attempt."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclass
class Credential:
    """A credential for authentication."""
    credential_id: str
    credential_type: CredentialType
    username: str
    domain: Optional[str]
    secret: str  # Password, hash, ticket, key
    source_host: str  # Where it was obtained
    discovered_at: float
    tested: bool = False
    valid: bool = False
    privileged: bool = False  # Admin/root level
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> dict:
        result = asdict(self)
        result['credential_type'] = self.credential_type.value
        return result


@dataclass
class Host:
    """A network host."""
    host_id: str
    ip_address: str
    hostname: Optional[str]
    os_type: Optional[str]  # 'windows', 'linux', 'macos'
    domain: Optional[str]
    compromised: bool = False
    compromise_method: Optional[str] = None
    compromise_time: Optional[float] = None
    services: List[Dict] = None
    local_admins: List[str] = None
    domain_users: List[str] = None

    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.local_admins is None:
            self.local_admins = []
        if self.domain_users is None:
            self.domain_users = []


@dataclass
class LateralMovementAttempt:
    """A lateral movement attempt."""
    attempt_id: str
    source_host: str
    target_host: str
    technique: LateralTechnique
    credential: Credential
    status: LateralStatus
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None
    result: Optional[Dict] = None


class AutonomousLateralMovement:
    """
    Autonomous lateral movement engine with recursive credential use.
    Intelligently spreads across the network using discovered credentials.
    """

    def __init__(self,
                 scope_enforcer,
                 impact_limiter,
                 audit_logger,
                 tool_orchestrator,
                 max_hops: int = 5,
                 max_concurrent_moves: int = 3):
        """
        Initialize autonomous lateral movement engine.

        Args:
            scope_enforcer: ScopeEnforcer instance
            impact_limiter: ImpactLimiter instance
            audit_logger: AuditLogger instance
            tool_orchestrator: ToolOrchestrator instance
            max_hops: Maximum hops from initial compromise
            max_concurrent_moves: Max concurrent lateral movements
        """
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - LATERAL - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/lateral.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('LATERAL')

        # Safety systems
        self.scope_enforcer = scope_enforcer
        self.impact_limiter = impact_limiter
        self.audit_logger = audit_logger
        self.tool_orchestrator = tool_orchestrator

        # Configuration
        self.max_hops = max_hops
        self.max_concurrent_moves = max_concurrent_moves

        # State
        self.hosts: Dict[str, Host] = {}  # host_id -> Host
        self.credentials: List[Credential] = []
        self.attempts: List[LateralMovementAttempt] = []

        # Tracking
        self.hop_distance: Dict[str, int] = {}  # host_id -> hop count
        self.credential_sources: Dict[str, Set[str]] = defaultdict(set)  # cred_id -> {host_ids}

        # Statistics
        self.stats = {
            'total_attempts': 0,
            'successful_moves': 0,
            'failed_moves': 0,
            'blocked_moves': 0,
            'credentials_found': 0,
            'hosts_compromised': 0
        }

        self.logger.info("Autonomous Lateral Movement Engine initialized")
        self.logger.info(f"Max hops: {max_hops}, Max concurrent: {max_concurrent_moves}")

    def register_initial_compromise(self, host: Host):
        """
        Register the initial compromised host.

        Args:
            host: Initial compromised host
        """
        host.compromised = True
        host.compromise_time = time.time()
        self.hosts[host.host_id] = host
        self.hop_distance[host.host_id] = 0

        self.stats['hosts_compromised'] = 1

        self.logger.info(f"Initial compromise registered: {host.ip_address}")

        # Log to audit
        if self.audit_logger:
            from sys import path
            path.append('/home/user/prometheus-prime/SAFETY/audit-log')
            from immutable_audit_logger import ActionType, ActionResult

            self.audit_logger.log_action(
                action_type=ActionType.PRIVILEGE_ESCALATION,
                target=host.ip_address,
                tool="lateral_engine",
                result=ActionResult.SUCCESS,
                agent_id="LATERAL_ENGINE",
                details={
                    'action': 'initial_compromise_registered',
                    'hostname': host.hostname,
                    'os_type': host.os_type
                }
            )

    def add_discovered_credentials(self, credentials: List[Credential]):
        """
        Add newly discovered credentials.

        Args:
            credentials: List of credentials
        """
        for cred in credentials:
            self.credentials.append(cred)
            self.credential_sources[cred.credential_id].add(cred.source_host)

            self.logger.info(f"Credential discovered: {cred.username}@{cred.domain or 'local'} "
                           f"({cred.credential_type.value}) from {cred.source_host}")

        self.stats['credentials_found'] += len(credentials)

    def add_discovered_host(self, host: Host):
        """
        Add a newly discovered host.

        Args:
            host: Discovered host
        """
        self.hosts[host.host_id] = host
        self.logger.info(f"Host discovered: {host.ip_address} ({host.hostname or 'unknown'})")

    def find_lateral_opportunities(self) -> List[Tuple[Host, Host, Credential, LateralTechnique]]:
        """
        Find all possible lateral movement opportunities.

        Returns:
            List of (source_host, target_host, credential, technique) tuples
        """
        opportunities = []

        # Get compromised hosts
        compromised_hosts = [h for h in self.hosts.values() if h.compromised]

        # Get uncompromised hosts
        uncompromised_hosts = [h for h in self.hosts.values() if not h.compromised]

        for source in compromised_hosts:
            # Check if we've reached max hops
            source_hops = self.hop_distance.get(source.host_id, 0)
            if source_hops >= self.max_hops:
                self.logger.debug(f"Skipping {source.ip_address} - max hops reached")
                continue

            for target in uncompromised_hosts:
                # Safety check: verify target is in scope
                try:
                    self.scope_enforcer.check_target(target.ip_address)
                except Exception as e:
                    self.logger.warning(f"Target {target.ip_address} not in scope: {e}")
                    continue

                # Try each credential
                for cred in self.credentials:
                    # Get applicable techniques for this credential and target
                    techniques = self._get_applicable_techniques(target, cred)

                    for technique in techniques:
                        opportunities.append((source, target, cred, technique))

        self.logger.info(f"Found {len(opportunities)} lateral movement opportunities")
        return opportunities

    def _get_applicable_techniques(self,
                                   target: Host,
                                   credential: Credential) -> List[LateralTechnique]:
        """
        Get applicable lateral movement techniques for a target and credential.

        Args:
            target: Target host
            credential: Credential to use

        Returns:
            List of applicable techniques
        """
        techniques = []

        # Windows techniques
        if target.os_type == 'windows':
            if credential.credential_type == CredentialType.PASSWORD:
                techniques.extend([
                    LateralTechnique.PSEXEC,
                    LateralTechnique.WMIEXEC,
                    LateralTechnique.SMBEXEC,
                    LateralTechnique.WINRM
                ])

            elif credential.credential_type == CredentialType.NTLM_HASH:
                techniques.extend([
                    LateralTechnique.PASS_THE_HASH,
                    LateralTechnique.WMIEXEC,
                    LateralTechnique.SMBEXEC
                ])

            elif credential.credential_type == CredentialType.KERBEROS_TICKET:
                techniques.extend([
                    LateralTechnique.PASS_THE_TICKET,
                    LateralTechnique.OVERPASS_THE_HASH
                ])

        # Linux techniques
        elif target.os_type == 'linux':
            if credential.credential_type == CredentialType.PASSWORD:
                techniques.append(LateralTechnique.SSH)

            elif credential.credential_type == CredentialType.SSH_KEY:
                techniques.append(LateralTechnique.SSH_KEY)

        return techniques

    def execute_autonomous_lateral_movement(self, max_moves: Optional[int] = None):
        """
        Execute autonomous lateral movement.

        Args:
            max_moves: Optional limit on number of moves to attempt
        """
        self.logger.info("Starting autonomous lateral movement")

        moves_executed = 0

        while True:
            # Find opportunities
            opportunities = self.find_lateral_opportunities()

            if not opportunities:
                self.logger.info("No more lateral movement opportunities found")
                break

            # Sort by priority (e.g., prefer privileged credentials)
            opportunities.sort(key=lambda x: (
                x[2].privileged,  # Prefer privileged credentials
                -self.hop_distance.get(x[0].host_id, 0)  # Prefer closer hops
            ), reverse=True)

            # Execute moves (limited by concurrent limit)
            for source, target, cred, technique in opportunities[:self.max_concurrent_moves]:
                if max_moves and moves_executed >= max_moves:
                    self.logger.info(f"Reached max moves limit: {max_moves}")
                    return

                success = self._execute_lateral_move(source, target, cred, technique)

                if success:
                    moves_executed += 1

                    # If successful, harvest credentials from new host
                    self._harvest_credentials(target)

                    # Enumerate new targets from this host
                    self._enumerate_from_host(target)

                # Small delay between moves
                time.sleep(2)

            # If no successful moves in this round, break
            if moves_executed == 0:
                self.logger.info("No successful moves this round, stopping")
                break

        self.logger.info(f"Autonomous lateral movement complete. {moves_executed} successful moves.")

    def _execute_lateral_move(self,
                             source: Host,
                             target: Host,
                             credential: Credential,
                             technique: LateralTechnique) -> bool:
        """
        Execute a single lateral movement attempt.

        Args:
            source: Source host
            target: Target host
            credential: Credential to use
            technique: Technique to use

        Returns:
            True if successful
        """
        attempt_id = f"lateral_{int(time.time() * 1000)}_{technique.value}"

        attempt = LateralMovementAttempt(
            attempt_id=attempt_id,
            source_host=source.host_id,
            target_host=target.host_id,
            technique=technique,
            credential=credential,
            status=LateralStatus.PENDING
        )

        self.logger.info(f"Attempting lateral movement: {source.ip_address} -> {target.ip_address} "
                        f"via {technique.value} with {credential.username}")

        # Safety gate: Check impact
        try:
            # Lateral movement is typically MEDIUM impact
            from sys import path
            path.append('/home/user/prometheus-prime/SAFETY/impact-limiter')
            from impact_limiter import OperationType

            self.impact_limiter.check_operation(
                operation=OperationType.LATERAL_MOVE,
                target=target.ip_address,
                details={'technique': technique.value}
            )
        except Exception as e:
            self.logger.error(f"Impact check failed: {e}")
            attempt.status = LateralStatus.BLOCKED
            attempt.error = str(e)
            self.attempts.append(attempt)
            self.stats['blocked_moves'] += 1
            return False

        # Execute via tool orchestrator
        attempt.status = LateralStatus.IN_PROGRESS
        attempt.started_at = time.time()

        try:
            # Map technique to tool
            if technique in [LateralTechnique.PSEXEC, LateralTechnique.WMIEXEC, LateralTechnique.SMBEXEC]:
                result = self._execute_impacket_lateral(target, credential, technique)
            elif technique == LateralTechnique.SSH:
                result = self._execute_ssh_lateral(target, credential)
            else:
                result = {'success': False, 'error': 'Technique not implemented'}

            attempt.completed_at = time.time()

            if result.get('success'):
                attempt.status = LateralStatus.SUCCESS
                attempt.result = result

                # Mark target as compromised
                target.compromised = True
                target.compromise_method = technique.value
                target.compromise_time = time.time()

                # Update hop distance
                source_hops = self.hop_distance.get(source.host_id, 0)
                self.hop_distance[target.host_id] = source_hops + 1

                self.stats['successful_moves'] += 1
                self.stats['hosts_compromised'] += 1

                self.logger.info(f"✓ Lateral movement successful: {target.ip_address} "
                               f"(hop {self.hop_distance[target.host_id]})")

                # Log to audit
                if self.audit_logger:
                    from sys import path
                    path.append('/home/user/prometheus-prime/SAFETY/audit-log')
                    from immutable_audit_logger import ActionType, ActionResult

                    self.audit_logger.log_action(
                        action_type=ActionType.LATERAL_MOVE,
                        target=target.ip_address,
                        tool=technique.value,
                        result=ActionResult.SUCCESS,
                        agent_id="LATERAL_ENGINE",
                        details={
                            'source': source.ip_address,
                            'credential': credential.username,
                            'hop_count': self.hop_distance[target.host_id]
                        }
                    )

                return True
            else:
                attempt.status = LateralStatus.FAILURE
                attempt.error = result.get('error')
                self.stats['failed_moves'] += 1
                return False

        except Exception as e:
            attempt.status = LateralStatus.FAILURE
            attempt.error = str(e)
            attempt.completed_at = time.time()
            self.stats['failed_moves'] += 1
            self.logger.error(f"Lateral movement failed: {e}")
            return False
        finally:
            self.attempts.append(attempt)
            self.stats['total_attempts'] += 1

    def _execute_impacket_lateral(self,
                                  target: Host,
                                  credential: Credential,
                                  technique: LateralTechnique) -> Dict:
        """Execute lateral movement using Impacket tools."""
        # TODO: Integrate with tool orchestrator
        # For now, return simulated result
        self.logger.info(f"  (simulated {technique.value} execution)")
        return {
            'success': True,
            'method': technique.value,
            'access_level': 'administrator' if credential.privileged else 'user'
        }

    def _execute_ssh_lateral(self, target: Host, credential: Credential) -> Dict:
        """Execute lateral movement via SSH."""
        # TODO: Integrate with tool orchestrator
        self.logger.info(f"  (simulated SSH execution)")
        return {
            'success': True,
            'method': 'ssh',
            'access_level': 'root' if credential.privileged else 'user'
        }

    def _harvest_credentials(self, host: Host):
        """
        Harvest credentials from a newly compromised host.

        Args:
            host: Compromised host
        """
        self.logger.info(f"Harvesting credentials from {host.ip_address}")

        # TODO: Execute credential harvesting tools
        # - Mimikatz for Windows
        # - LaZagne for multi-platform
        # - /etc/shadow for Linux
        # - Browser cookies/saved passwords
        # - SSH keys

        # Simulated credential discovery
        simulated_creds = [
            Credential(
                credential_id=f"cred_sim_{int(time.time())}",
                credential_type=CredentialType.PASSWORD,
                username="Administrator",
                domain=host.domain,
                secret="P@ssw0rd123",
                source_host=host.host_id,
                discovered_at=time.time(),
                privileged=True
            )
        ]

        self.add_discovered_credentials(simulated_creds)

    def _enumerate_from_host(self, host: Host):
        """
        Enumerate network from a newly compromised host.

        Args:
            host: Compromised host
        """
        self.logger.info(f"Enumerating network from {host.ip_address}")

        # TODO: Execute enumeration from this pivot point
        # - ARP cache
        # - Network shares
        # - Domain computers
        # - Local network scan

    def get_compromise_graph(self) -> Dict:
        """
        Get the compromise graph showing lateral movement paths.

        Returns:
            Graph representation
        """
        graph = {
            'nodes': [],
            'edges': [],
            'statistics': self.stats
        }

        # Add nodes (hosts)
        for host in self.hosts.values():
            graph['nodes'].append({
                'id': host.host_id,
                'ip': host.ip_address,
                'hostname': host.hostname,
                'compromised': host.compromised,
                'hop_distance': self.hop_distance.get(host.host_id, -1)
            })

        # Add edges (successful lateral movements)
        for attempt in self.attempts:
            if attempt.status == LateralStatus.SUCCESS:
                graph['edges'].append({
                    'source': attempt.source_host,
                    'target': attempt.target_host,
                    'technique': attempt.technique.value,
                    'credential': attempt.credential.username
                })

        return graph

    def get_statistics(self) -> Dict:
        """Get lateral movement statistics."""
        return {
            **self.stats,
            'total_hosts': len(self.hosts),
            'compromised_hosts': len([h for h in self.hosts.values() if h.compromised]),
            'total_credentials': len(self.credentials),
            'tested_credentials': len([c for c in self.credentials if c.tested]),
            'valid_credentials': len([c for c in self.credentials if c.valid]),
            'max_hop_distance': max(self.hop_distance.values()) if self.hop_distance else 0
        }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Mock safety systems
    class MockScopeEnforcer:
        def check_target(self, target):
            return True

    class MockImpactLimiter:
        def check_operation(self, operation, target, details):
            return True

    class MockAuditLogger:
        def log_action(self, **kwargs):
            pass

    class MockToolOrchestrator:
        pass

    # Initialize
    lateral = AutonomousLateralMovement(
        scope_enforcer=MockScopeEnforcer(),
        impact_limiter=MockImpactLimiter(),
        audit_logger=MockAuditLogger(),
        tool_orchestrator=MockToolOrchestrator(),
        max_hops=3,
        max_concurrent_moves=2
    )

    # Register initial compromise
    initial_host = Host(
        host_id="host_001",
        ip_address="192.168.1.10",
        hostname="WEB01",
        os_type="windows",
        domain="CORP",
        compromised=True
    )
    lateral.register_initial_compromise(initial_host)

    # Add some discovered credentials
    lateral.add_discovered_credentials([
        Credential(
            credential_id="cred_001",
            credential_type=CredentialType.PASSWORD,
            username="admin",
            domain="CORP",
            secret="P@ssw0rd123",
            source_host="host_001",
            discovered_at=time.time(),
            privileged=True
        )
    ])

    # Add some target hosts
    for i in range(2, 5):
        lateral.add_discovered_host(Host(
            host_id=f"host_{i:03d}",
            ip_address=f"192.168.1.{10+i}",
            hostname=f"SRV{i:02d}",
            os_type="windows",
            domain="CORP"
        ))

    # Execute autonomous lateral movement
    print("\nExecuting autonomous lateral movement...\n")
    lateral.execute_autonomous_lateral_movement(max_moves=5)

    # Print statistics
    print("\n" + "="*80)
    print("LATERAL MOVEMENT STATISTICS")
    print("="*80)
    import json
    print(json.dumps(lateral.get_statistics(), indent=2))

    # Print compromise graph
    print("\nCOMPROMISE GRAPH:")
    print(json.dumps(lateral.get_compromise_graph(), indent=2))
