#!/usr/bin/env python3
"""
PROMETHEUS PRIME - OODA LOOP ENGINE
Continuous Observe-Orient-Decide-Act cycle for autonomous operations

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - NO HUMAN INTERVENTION REQUIRED
"""

import time
import logging
import json
import threading
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import sys


class OperationPhase(Enum):
    """Phases of penetration testing operation."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DATA_COLLECTION = "data_collection"
    REPORTING = "reporting"
    COMPLETE = "complete"


class ActionStatus(Enum):
    """Status of an action."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclass
class ObservationData:
    """Data collected during observation phase."""
    timestamp: float
    source: str  # Tool/agent that provided data
    data_type: str  # Type of data (scan_result, exploit_result, etc.)
    target: str
    data: Dict[str, Any]
    confidence: float  # 0.0 to 1.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OrientationState:
    """Current understanding of the environment."""
    discovered_hosts: Set[str]
    discovered_services: Dict[str, List[Dict]]  # IP -> [services]
    discovered_vulnerabilities: Dict[str, List[Dict]]  # IP -> [vulns]
    compromised_hosts: Set[str]
    credentials: List[Dict[str, str]]
    attack_paths: List[List[str]]  # Possible attack paths
    current_phase: OperationPhase
    current_goals: List[str]
    blockers: List[str]  # Things preventing progress


@dataclass
class Decision:
    """A decision to take an action."""
    timestamp: float
    action_type: str
    target: str
    tool: str
    parameters: Dict[str, Any]
    rationale: str
    priority: int  # 1-10, higher = more important
    estimated_impact: str  # read_only, low, medium, high
    prerequisites: List[str]  # What must be true before executing
    expected_outcome: str


@dataclass
class Action:
    """An action to be executed."""
    action_id: str
    decision: Decision
    status: ActionStatus
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class OODALoop:
    """
    Continuous Observe-Orient-Decide-Act loop for autonomous operations.

    This is the core autonomous decision-making engine.
    """

    def __init__(self,
                 roe_document: Dict,
                 goals: List[str],
                 cycle_interval: float = 10.0,  # 10 seconds per cycle
                 max_concurrent_actions: int = 5):
        """
        Initialize OODA loop.

        Args:
            roe_document: Rules of Engagement document
            goals: Initial list of high-level goals
            cycle_interval: Seconds between cycles
            max_concurrent_actions: Max actions to run simultaneously
        """
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - OODA - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/ooda.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('OODA')

        # Configuration
        self.roe_document = roe_document
        self.cycle_interval = cycle_interval
        self.max_concurrent_actions = max_concurrent_actions

        # State
        self.running = False
        self.cycle_count = 0

        # Orientation state - our understanding of the environment
        self.state = OrientationState(
            discovered_hosts=set(),
            discovered_services={},
            discovered_vulnerabilities={},
            compromised_hosts=set(),
            credentials=[],
            attack_paths=[],
            current_phase=OperationPhase.RECONNAISSANCE,
            current_goals=goals,
            blockers=[]
        )

        # Observation buffer
        self.observations: List[ObservationData] = []
        self.observation_lock = threading.Lock()

        # Decision and action queues
        self.decisions: List[Decision] = []
        self.pending_actions: List[Action] = []
        self.active_actions: List[Action] = []
        self.completed_actions: List[Action] = []

        # Integration points
        self.scope_enforcer = None
        self.impact_limiter = None
        self.audit_logger = None
        self.tool_orchestrator = None

        self.logger.info("OODA Loop initialized")
        self.logger.info(f"Goals: {goals}")
        self.logger.info(f"Cycle interval: {cycle_interval}s")

    def integrate_safety_systems(self,
                                 scope_enforcer,
                                 impact_limiter,
                                 audit_logger):
        """
        Integrate with safety systems.

        Args:
            scope_enforcer: ScopeEnforcer instance
            impact_limiter: ImpactLimiter instance
            audit_logger: ImmutableAuditLogger instance
        """
        self.scope_enforcer = scope_enforcer
        self.impact_limiter = impact_limiter
        self.audit_logger = audit_logger
        self.logger.info("Safety systems integrated")

    def integrate_tool_orchestrator(self, tool_orchestrator):
        """
        Integrate with tool orchestrator.

        Args:
            tool_orchestrator: ToolOrchestrator instance
        """
        self.tool_orchestrator = tool_orchestrator
        self.logger.info("Tool orchestrator integrated")

    def add_observation(self, observation: ObservationData):
        """
        Add an observation to the buffer.

        Args:
            observation: ObservationData object
        """
        with self.observation_lock:
            self.observations.append(observation)
            self.logger.debug(f"Observation added: {observation.data_type} from {observation.source}")

    def start(self):
        """Start the OODA loop."""
        if self.running:
            self.logger.warning("OODA loop already running")
            return

        self.running = True
        self.loop_thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="OODALoop"
        )
        self.loop_thread.start()
        self.logger.info("🔄 OODA Loop started - Autonomous operations active")

    def stop(self):
        """Stop the OODA loop."""
        self.running = False
        self.logger.info("OODA Loop stopped")

    def _loop(self):
        """Main OODA loop."""
        while self.running:
            cycle_start = time.time()
            self.cycle_count += 1

            self.logger.info(f"\n{'='*80}")
            self.logger.info(f"OODA CYCLE #{self.cycle_count}")
            self.logger.info(f"{'='*80}")

            try:
                # 1. OBSERVE
                self.logger.info("📡 OBSERVE: Collecting data...")
                observations = self._observe()

                # 2. ORIENT
                self.logger.info("🧭 ORIENT: Analyzing situation...")
                self._orient(observations)

                # 3. DECIDE
                self.logger.info("🎯 DECIDE: Planning next actions...")
                decisions = self._decide()

                # 4. ACT
                self.logger.info("⚡ ACT: Executing actions...")
                self._act(decisions)

                # Log cycle summary
                self._log_cycle_summary()

            except Exception as e:
                self.logger.error(f"Error in OODA cycle: {e}", exc_info=True)

            # Sleep until next cycle
            cycle_duration = time.time() - cycle_start
            sleep_time = max(0, self.cycle_interval - cycle_duration)

            if sleep_time > 0:
                self.logger.debug(f"Cycle completed in {cycle_duration:.2f}s, sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
            else:
                self.logger.warning(f"Cycle took {cycle_duration:.2f}s (longer than {self.cycle_interval}s interval)")

    def _observe(self) -> List[ObservationData]:
        """
        OBSERVE phase: Collect all available data.

        Returns:
            List of new observations
        """
        with self.observation_lock:
            new_observations = self.observations.copy()
            self.observations.clear()

        self.logger.info(f"Collected {len(new_observations)} new observations")

        # Log observations
        for obs in new_observations:
            self.logger.debug(f"  - {obs.data_type} from {obs.source}: {obs.target}")

        return new_observations

    def _orient(self, observations: List[ObservationData]):
        """
        ORIENT phase: Update our understanding of the environment.

        Args:
            observations: New observations to process
        """
        # Process each observation and update state
        for obs in observations:
            if obs.data_type == "host_discovered":
                self.state.discovered_hosts.add(obs.target)
                self.logger.info(f"  + Host discovered: {obs.target}")

            elif obs.data_type == "service_discovered":
                if obs.target not in self.state.discovered_services:
                    self.state.discovered_services[obs.target] = []
                self.state.discovered_services[obs.target].append(obs.data)
                self.logger.info(f"  + Service discovered on {obs.target}: {obs.data.get('port')}/{obs.data.get('service')}")

            elif obs.data_type == "vulnerability_found":
                if obs.target not in self.state.discovered_vulnerabilities:
                    self.state.discovered_vulnerabilities[obs.target] = []
                self.state.discovered_vulnerabilities[obs.target].append(obs.data)
                self.logger.info(f"  + Vulnerability found on {obs.target}: {obs.data.get('cve_id', 'UNKNOWN')}")

            elif obs.data_type == "host_compromised":
                self.state.compromised_hosts.add(obs.target)
                self.logger.info(f"  🎯 Host compromised: {obs.target}")

            elif obs.data_type == "credentials_found":
                self.state.credentials.append(obs.data)
                self.logger.info(f"  🔑 Credentials found: {obs.data.get('username')}@{obs.target}")

        # Update phase based on current state
        self._update_phase()

        # Identify attack paths
        self._identify_attack_paths()

        # Identify blockers
        self._identify_blockers()

        # Log current state
        self.logger.info(f"State: {len(self.state.discovered_hosts)} hosts, "
                        f"{len(self.state.compromised_hosts)} compromised, "
                        f"{len(self.state.credentials)} credentials")

    def _update_phase(self):
        """Update the current operation phase based on state."""
        old_phase = self.state.current_phase

        # Determine phase based on state
        if len(self.state.compromised_hosts) == 0:
            if len(self.state.discovered_vulnerabilities) > 0:
                self.state.current_phase = OperationPhase.EXPLOITATION
            elif len(self.state.discovered_services) > 0:
                self.state.current_phase = OperationPhase.VULNERABILITY_ANALYSIS
            elif len(self.state.discovered_hosts) > 0:
                self.state.current_phase = OperationPhase.ENUMERATION
            else:
                self.state.current_phase = OperationPhase.RECONNAISSANCE
        else:
            # We have compromised hosts
            if self._goals_achieved():
                self.state.current_phase = OperationPhase.REPORTING
            else:
                # Check if we should do lateral movement or privilege escalation
                self.state.current_phase = OperationPhase.POST_EXPLOITATION

        if self.state.current_phase != old_phase:
            self.logger.info(f"Phase transition: {old_phase.value} -> {self.state.current_phase.value}")

    def _identify_attack_paths(self):
        """Identify possible attack paths to achieve goals."""
        # TODO: Implement attack graph analysis
        # This would use BloodHound-style analysis to find paths
        pass

    def _identify_blockers(self):
        """Identify what's blocking progress toward goals."""
        self.state.blockers.clear()

        # Check if we're stuck
        if self.cycle_count > 10:
            if len(self.state.discovered_hosts) == 0:
                self.state.blockers.append("No hosts discovered - check scope configuration")

            if len(self.state.discovered_services) == 0 and len(self.state.discovered_hosts) > 0:
                self.state.blockers.append("No services discovered on known hosts")

            if len(self.state.compromised_hosts) == 0 and len(self.state.discovered_vulnerabilities) > 5:
                self.state.blockers.append("Vulnerabilities found but no successful exploitation")

    def _decide(self) -> List[Decision]:
        """
        DECIDE phase: Determine what actions to take next.

        Returns:
            List of decisions
        """
        decisions = []

        # Decision logic based on current phase
        if self.state.current_phase == OperationPhase.RECONNAISSANCE:
            decisions.extend(self._decide_reconnaissance())

        elif self.state.current_phase == OperationPhase.SCANNING:
            decisions.extend(self._decide_scanning())

        elif self.state.current_phase == OperationPhase.ENUMERATION:
            decisions.extend(self._decide_enumeration())

        elif self.state.current_phase == OperationPhase.VULNERABILITY_ANALYSIS:
            decisions.extend(self._decide_vulnerability_analysis())

        elif self.state.current_phase == OperationPhase.EXPLOITATION:
            decisions.extend(self._decide_exploitation())

        elif self.state.current_phase == OperationPhase.POST_EXPLOITATION:
            decisions.extend(self._decide_post_exploitation())

        elif self.state.current_phase == OperationPhase.REPORTING:
            decisions.extend(self._decide_reporting())

        # Sort decisions by priority
        decisions.sort(key=lambda d: d.priority, reverse=True)

        self.logger.info(f"Generated {len(decisions)} decisions")
        for i, decision in enumerate(decisions[:5], 1):  # Log top 5
            self.logger.info(f"  {i}. [{decision.priority}] {decision.action_type} on {decision.target}: {decision.rationale}")

        return decisions

    def _decide_reconnaissance(self) -> List[Decision]:
        """Decide actions for reconnaissance phase."""
        decisions = []

        # Get target scope from ROE
        authorized_ips = self.roe_document.get('authorized_ips', [])
        authorized_domains = self.roe_document.get('authorized_domains', [])

        # Scan authorized IPs
        for ip_range in authorized_ips:
            if ip_range not in [a.decision.target for a in self.completed_actions]:
                decisions.append(Decision(
                    timestamp=time.time(),
                    action_type="network_scan",
                    target=ip_range,
                    tool="nmap",
                    parameters={"scan_type": "ping_sweep"},
                    rationale="Discover live hosts in authorized range",
                    priority=9,
                    estimated_impact="read_only",
                    prerequisites=[],
                    expected_outcome="List of live hosts"
                ))

        # DNS enumeration for domains
        for domain in authorized_domains:
            decisions.append(Decision(
                timestamp=time.time(),
                action_type="dns_enumeration",
                target=domain,
                tool="subfinder",
                parameters={},
                rationale="Discover subdomains",
                priority=8,
                estimated_impact="read_only",
                prerequisites=[],
                expected_outcome="List of subdomains"
            ))

        return decisions

    def _decide_scanning(self) -> List[Decision]:
        """Decide actions for scanning phase."""
        # TODO: Implement scanning decisions
        return []

    def _decide_enumeration(self) -> List[Decision]:
        """Decide actions for enumeration phase."""
        decisions = []

        # Port scan discovered hosts that haven't been scanned
        scanned_hosts = {a.decision.target for a in self.completed_actions if a.decision.action_type == "port_scan"}

        for host in self.state.discovered_hosts:
            if host not in scanned_hosts:
                decisions.append(Decision(
                    timestamp=time.time(),
                    action_type="port_scan",
                    target=host,
                    tool="nmap",
                    parameters={"scan_type": "full_tcp"},
                    rationale="Enumerate services on discovered host",
                    priority=8,
                    estimated_impact="read_only",
                    prerequisites=[],
                    expected_outcome="List of open ports and services"
                ))

        return decisions

    def _decide_vulnerability_analysis(self) -> List[Decision]:
        """Decide actions for vulnerability analysis phase."""
        decisions = []

        # Scan services for vulnerabilities
        for host, services in self.state.discovered_services.items():
            for service in services:
                decisions.append(Decision(
                    timestamp=time.time(),
                    action_type="vulnerability_scan",
                    target=host,
                    tool="nuclei",
                    parameters={"port": service.get('port'), "service": service.get('service')},
                    rationale=f"Scan {service.get('service')} for vulnerabilities",
                    priority=7,
                    estimated_impact="read_only",
                    prerequisites=[],
                    expected_outcome="List of vulnerabilities"
                ))

        return decisions

    def _decide_exploitation(self) -> List[Decision]:
        """Decide actions for exploitation phase."""
        # TODO: Implement exploitation decisions
        # This would analyze discovered vulnerabilities and select exploits
        return []

    def _decide_post_exploitation(self) -> List[Decision]:
        """Decide actions for post-exploitation phase."""
        # TODO: Implement post-exploitation decisions
        # This would include privilege escalation, lateral movement, persistence
        return []

    def _decide_reporting(self) -> List[Decision]:
        """Decide actions for reporting phase."""
        # TODO: Implement reporting decisions
        return []

    def _act(self, decisions: List[Decision]):
        """
        ACT phase: Execute decided actions.

        Args:
            decisions: List of decisions to execute
        """
        # Move completed actions to history
        self.active_actions = [a for a in self.active_actions if a.status == ActionStatus.IN_PROGRESS]

        # Create actions from decisions
        for decision in decisions:
            # Check if we have capacity for more actions
            if len(self.active_actions) >= self.max_concurrent_actions:
                break

            # Safety checks before creating action
            if not self._safety_check(decision):
                self.logger.warning(f"Safety check failed for {decision.action_type} on {decision.target}")
                continue

            # Create action
            action = Action(
                action_id=f"action_{int(time.time() * 1000)}_{decision.action_type}",
                decision=decision,
                status=ActionStatus.PENDING
            )

            self.pending_actions.append(action)

        # Execute pending actions
        while self.pending_actions and len(self.active_actions) < self.max_concurrent_actions:
            action = self.pending_actions.pop(0)
            self._execute_action(action)

        self.logger.info(f"Active actions: {len(self.active_actions)}, Pending: {len(self.pending_actions)}")

    def _safety_check(self, decision: Decision) -> bool:
        """
        Perform safety checks before executing a decision.

        Args:
            decision: Decision to check

        Returns:
            True if safe to execute
        """
        # Check scope
        if self.scope_enforcer:
            try:
                self.scope_enforcer.check_target(decision.target)
            except Exception as e:
                self.logger.error(f"Scope check failed: {e}")
                return False

        # Check impact
        if self.impact_limiter:
            # TODO: Map action_type to OperationType
            # For now, just check command if present
            if 'command' in decision.parameters:
                try:
                    self.impact_limiter.check_command(decision.parameters['command'])
                except Exception as e:
                    self.logger.error(f"Impact check failed: {e}")
                    return False

        return True

    def _execute_action(self, action: Action):
        """
        Execute an action.

        Args:
            action: Action to execute
        """
        action.status = ActionStatus.IN_PROGRESS
        action.started_at = time.time()
        self.active_actions.append(action)

        self.logger.info(f"Executing: {action.decision.action_type} on {action.decision.target}")

        # Log to audit
        if self.audit_logger:
            from sys import path
            path.append('/home/user/prometheus-prime/SAFETY/audit-log')
            from immutable_audit_logger import ActionType, ActionResult

            self.audit_logger.log_action(
                action_type=ActionType.DECISION,
                target=action.decision.target,
                tool=action.decision.tool,
                result=ActionResult.SUCCESS,
                agent_id="OODA_ENGINE",
                details={
                    'action_type': action.decision.action_type,
                    'rationale': action.decision.rationale,
                    'priority': action.decision.priority
                }
            )

        # Execute via tool orchestrator
        if self.tool_orchestrator:
            # TODO: Execute via tool orchestrator
            # For now, simulate execution
            pass
        else:
            # Simulate execution
            self.logger.info(f"  (simulated execution - no tool orchestrator)")

        # Simulate completion for now
        # In real implementation, this would be async
        action.status = ActionStatus.SUCCESS
        action.completed_at = time.time()
        action.result = {"status": "simulated_success"}

        # Move to completed
        self.active_actions.remove(action)
        self.completed_actions.append(action)

    def _goals_achieved(self) -> bool:
        """Check if all goals have been achieved."""
        # TODO: Implement goal achievement checking
        return False

    def _log_cycle_summary(self):
        """Log summary of current cycle."""
        self.logger.info(f"\n📊 CYCLE SUMMARY:")
        self.logger.info(f"  Phase: {self.state.current_phase.value}")
        self.logger.info(f"  Hosts: {len(self.state.discovered_hosts)} discovered, {len(self.state.compromised_hosts)} compromised")
        self.logger.info(f"  Services: {sum(len(s) for s in self.state.discovered_services.values())}")
        self.logger.info(f"  Vulnerabilities: {sum(len(v) for v in self.state.discovered_vulnerabilities.values())}")
        self.logger.info(f"  Credentials: {len(self.state.credentials)}")
        self.logger.info(f"  Actions: {len(self.completed_actions)} completed, {len(self.active_actions)} active, {len(self.pending_actions)} pending")

        if self.state.blockers:
            self.logger.warning(f"  ⚠️  Blockers: {', '.join(self.state.blockers)}")

    def get_status(self) -> dict:
        """Get current OODA loop status."""
        return {
            'running': self.running,
            'cycle_count': self.cycle_count,
            'current_phase': self.state.current_phase.value,
            'goals': self.state.current_goals,
            'discovered_hosts': list(self.state.discovered_hosts),
            'compromised_hosts': list(self.state.compromised_hosts),
            'active_actions': len(self.active_actions),
            'pending_actions': len(self.pending_actions),
            'completed_actions': len(self.completed_actions),
            'blockers': self.state.blockers
        }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Example ROE document
    roe_document = {
        "engagement_id": "TEST-2025-001",
        "authorized_ips": ["192.168.1.0/24"],
        "authorized_domains": ["test.local"],
        "max_impact_level": "medium"
    }

    # Initialize OODA loop
    ooda = OODALoop(
        roe_document=roe_document,
        goals=["Gain Domain Admin", "Exfiltrate sensitive data"],
        cycle_interval=10.0
    )

    # Start the loop
    ooda.start()

    # Simulate some observations
    time.sleep(2)
    ooda.add_observation(ObservationData(
        timestamp=time.time(),
        source="nmap",
        data_type="host_discovered",
        target="192.168.1.10",
        data={"os": "Windows Server 2019"},
        confidence=0.9
    ))

    ooda.add_observation(ObservationData(
        timestamp=time.time(),
        source="nmap",
        data_type="service_discovered",
        target="192.168.1.10",
        data={"port": 445, "service": "smb"},
        confidence=0.95
    ))

    # Let it run for a few cycles
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        ooda.stop()
        print("\nOODA Loop stopped")
        print(json.dumps(ooda.get_status(), indent=2))
