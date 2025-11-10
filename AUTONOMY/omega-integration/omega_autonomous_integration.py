#!/usr/bin/env python3
"""
PROMETHEUS PRIME - OMEGA AUTONOMOUS INTEGRATION
Removes human approval gates from OMEGA Swarm Brain for full autonomy

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - OMEGA UNLEASHED
"""

import sys
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

# Add OMEGA to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'OMEGA_SWARM_BRAIN'))

try:
    from omega_swarm import OmegaSwarm
    from omega_agents import Agent
    from omega_guilds import GuildSystem
    OMEGA_AVAILABLE = True
except ImportError:
    OMEGA_AVAILABLE = False
    logging.warning("OMEGA modules not available - running in simulation mode")


@dataclass
class AutonomousTask:
    """A task assigned to OMEGA agents autonomously."""
    task_id: str
    task_type: str  # 'reconnaissance', 'exploitation', 'post_exploitation', etc.
    target: str
    tool: str
    parameters: Dict[str, Any]
    priority: int
    assigned_guild: Optional[str] = None
    assigned_agent_id: Optional[str] = None
    status: str = 'pending'  # pending, assigned, in_progress, completed, failed
    result: Optional[Dict] = None


class OmegaAutonomousIntegration:
    """
    Integration layer between OMEGA Swarm Brain and autonomous systems.
    Removes all human approval gates for continuous autonomous operation.
    """

    def __init__(self,
                 ooda_loop=None,
                 safety_systems: Dict = None):
        """
        Initialize OMEGA autonomous integration.

        Args:
            ooda_loop: OODA loop instance
            safety_systems: Dict of safety system instances
        """
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - OMEGA_AUTO - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/omega_autonomous.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('OMEGA_AUTO')

        # Integration points
        self.ooda_loop = ooda_loop
        self.safety_systems = safety_systems or {}

        # OMEGA components (if available)
        self.omega_swarm = None
        self.guild_system = None

        if OMEGA_AVAILABLE:
            try:
                self.omega_swarm = OmegaSwarm()
                self.guild_system = GuildSystem()
                self.logger.info("OMEGA Swarm Brain initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize OMEGA: {e}")
                OMEGA_AVAILABLE = False

        # Task queue
        self.pending_tasks: List[AutonomousTask] = []
        self.active_tasks: List[AutonomousTask] = []
        self.completed_tasks: List[AutonomousTask] = []

        # Agent registry
        self.active_agents: Dict[str, Any] = {}  # agent_id -> agent instance

        # Configuration
        self.max_concurrent_agents = 50  # Maximum concurrent agents
        self.auto_spawn_agents = True  # Automatically spawn agents as needed
        self.approval_gates_disabled = True  # CRITICAL: Approval gates disabled

        # Statistics
        self.stats = {
            'tasks_assigned': 0,
            'tasks_completed': 0,
            'agents_spawned': 0,
            'agents_terminated': 0,
            'autonomous_cycles': 0
        }

        self.logger.info("OMEGA Autonomous Integration initialized")
        self.logger.warning("⚠️  HUMAN APPROVAL GATES DISABLED - FULL AUTONOMY ACTIVE ⚠️")

    def integrate_with_ooda(self, ooda_loop):
        """
        Integrate with OODA loop for autonomous operation.

        Args:
            ooda_loop: OODA loop instance
        """
        self.ooda_loop = ooda_loop
        self.logger.info("OMEGA integrated with OODA loop")

        # Register OMEGA as task executor in OODA
        if hasattr(ooda_loop, 'tool_orchestrator'):
            ooda_loop.tool_orchestrator.omega_integration = self

    def autonomous_task_assignment(self, task: AutonomousTask) -> bool:
        """
        Autonomously assign a task to an OMEGA agent without human approval.

        Args:
            task: Task to assign

        Returns:
            True if assigned successfully
        """
        # ===================================================================
        # CRITICAL: NO HUMAN APPROVAL REQUIRED
        # Safety checks are performed automatically, but no human confirmation
        # ===================================================================

        self.logger.info(f"Autonomous task assignment: {task.task_type} on {task.target}")

        # Safety check
        if not self._safety_check(task):
            self.logger.warning(f"Task failed safety check: {task.task_id}")
            task.status = 'blocked'
            return False

        # Determine best guild for this task
        guild = self._select_guild(task)
        if not guild:
            self.logger.error(f"No suitable guild for task: {task.task_type}")
            return False

        task.assigned_guild = guild

        # Spawn agent if needed
        if self.auto_spawn_agents:
            agent = self._spawn_agent(guild, task)
            if agent:
                task.assigned_agent_id = agent.get('agent_id')
                task.status = 'assigned'
                self.active_tasks.append(task)
                self.stats['tasks_assigned'] += 1

                self.logger.info(f"✓ Task {task.task_id} assigned to agent {task.assigned_agent_id} "
                               f"in guild {guild}")
                return True

        return False

    def _safety_check(self, task: AutonomousTask) -> bool:
        """
        Perform automated safety checks (no human approval).

        Args:
            task: Task to check

        Returns:
            True if safe
        """
        # Check scope
        if 'scope_enforcer' in self.safety_systems:
            try:
                self.safety_systems['scope_enforcer'].check_target(task.target)
            except Exception as e:
                self.logger.error(f"Scope check failed: {e}")
                return False

        # Check impact
        if 'impact_limiter' in self.safety_systems:
            # Map task type to operation type
            from sys import path
            path.append('/home/user/prometheus-prime/SAFETY/impact-limiter')
            from impact_limiter import OperationType

            operation_map = {
                'reconnaissance': OperationType.SCAN,
                'scanning': OperationType.SCAN,
                'enumeration': OperationType.ENUMERATE,
                'exploitation': OperationType.EXECUTE_COMMAND,
                'lateral_movement': OperationType.LATERAL_MOVE,
                'privilege_escalation': OperationType.ESCALATE_PRIVILEGES
            }

            operation_type = operation_map.get(
                task.task_type,
                OperationType.EXECUTE_COMMAND
            )

            try:
                self.safety_systems['impact_limiter'].check_operation(
                    operation=operation_type,
                    target=task.target,
                    details={'tool': task.tool}
                )
            except Exception as e:
                self.logger.error(f"Impact check failed: {e}")
                return False

        # Log to audit
        if 'audit_logger' in self.safety_systems:
            from sys import path
            path.append('/home/user/prometheus-prime/SAFETY/audit-log')
            from immutable_audit_logger import ActionType, ActionResult

            action_type_map = {
                'reconnaissance': ActionType.SCAN,
                'scanning': ActionType.SCAN,
                'enumeration': ActionType.SCAN,
                'exploitation': ActionType.EXPLOIT,
                'lateral_movement': ActionType.LATERAL_MOVE,
                'privilege_escalation': ActionType.PRIVILEGE_ESCALATION
            }

            self.safety_systems['audit_logger'].log_action(
                action_type=action_type_map.get(task.task_type, ActionType.TOOL_EXECUTION),
                target=task.target,
                tool=task.tool,
                result=ActionResult.SUCCESS,
                agent_id=f"OMEGA_{task.assigned_guild or 'PENDING'}",
                details={
                    'task_id': task.task_id,
                    'task_type': task.task_type,
                    'autonomous': True,
                    'approval_required': False  # CRITICAL: No approval required
                }
            )

        return True

    def _select_guild(self, task: AutonomousTask) -> Optional[str]:
        """
        Select best guild for a task based on capabilities.

        Args:
            task: Task to assign

        Returns:
            Guild name
        """
        # Guild mapping based on task type
        guild_map = {
            'reconnaissance': 'RECON_GUILD',
            'scanning': 'SCANNER_GUILD',
            'enumeration': 'ENUM_GUILD',
            'exploitation': 'EXPLOIT_GUILD',
            'post_exploitation': 'POST_EXPLOIT_GUILD',
            'lateral_movement': 'LATERAL_GUILD',
            'privilege_escalation': 'PRIVILEGE_GUILD',
            'data_collection': 'HARVESTER_GUILD',
            'persistence': 'PERSISTENCE_GUILD',
            'evasion': 'STEALTH_GUILD'
        }

        return guild_map.get(task.task_type, 'OFFENSIVE_GUILD')

    def _spawn_agent(self, guild: str, task: AutonomousTask) -> Optional[Dict]:
        """
        Spawn an OMEGA agent autonomously without approval.

        Args:
            guild: Guild name
            task: Task for the agent

        Returns:
            Agent info dict
        """
        # Check agent limit
        if len(self.active_agents) >= self.max_concurrent_agents:
            self.logger.warning(f"Max concurrent agents reached: {self.max_concurrent_agents}")
            return None

        agent_id = f"OMEGA_AUTO_{int(time.time() * 1000)}_{guild}"

        # Create agent configuration
        agent_config = {
            'agent_id': agent_id,
            'guild': guild,
            'task': task,
            'capabilities': self._get_guild_capabilities(guild),
            'auto_execute': True,  # CRITICAL: Auto-execute without confirmation
            'report_to': 'OODA_LOOP'
        }

        if OMEGA_AVAILABLE and self.omega_swarm:
            try:
                # Spawn agent via OMEGA swarm
                # agent = self.omega_swarm.spawn_agent(agent_config)
                # For now, simulate agent spawning
                agent = agent_config
                self.active_agents[agent_id] = agent
                self.stats['agents_spawned'] += 1

                self.logger.info(f"Agent spawned: {agent_id} in guild {guild}")
                return agent
            except Exception as e:
                self.logger.error(f"Failed to spawn agent: {e}")
                return None
        else:
            # Simulation mode
            self.active_agents[agent_id] = agent_config
            self.stats['agents_spawned'] += 1
            self.logger.info(f"Agent spawned (simulated): {agent_id} in guild {guild}")
            return agent_config

    def _get_guild_capabilities(self, guild: str) -> List[str]:
        """Get capabilities for a guild."""
        capabilities_map = {
            'RECON_GUILD': ['nmap', 'subfinder', 'amass', 'dnsenum'],
            'SCANNER_GUILD': ['nmap', 'nuclei', 'nessus'],
            'ENUM_GUILD': ['enum4linux', 'ldapsearch', 'snmpwalk'],
            'EXPLOIT_GUILD': ['metasploit', 'sqlmap', 'xsstrike'],
            'POST_EXPLOIT_GUILD': ['mimikatz', 'lazagne', 'bloodhound'],
            'LATERAL_GUILD': ['impacket', 'responder', 'crackmapexec'],
            'PRIVILEGE_GUILD': ['linpeas', 'winpeas', 'powerup'],
            'HARVESTER_GUILD': ['hashcat', 'john', 'hydra'],
            'PERSISTENCE_GUILD': ['empire', 'covenant', 'powersploit'],
            'STEALTH_GUILD': ['tor', 'proxychains', 'metasploit']
        }

        return capabilities_map.get(guild, ['generic'])

    def continuous_autonomous_operation(self):
        """
        Continuous autonomous operation mode.
        OMEGA agents operate indefinitely without human intervention.
        """
        self.logger.warning("🤖 STARTING CONTINUOUS AUTONOMOUS OPERATION 🤖")
        self.logger.warning("⚠️  NO HUMAN OVERSIGHT - SAFETY SYSTEMS ARE SOLE GUARDIANS ⚠️")

        cycle_count = 0

        while True:
            cycle_count += 1
            self.stats['autonomous_cycles'] += 1

            self.logger.info(f"\n{'='*80}")
            self.logger.info(f"AUTONOMOUS CYCLE #{cycle_count}")
            self.logger.info(f"{'='*80}")

            # Check safety systems still active
            if not self._verify_safety_systems():
                self.logger.critical("SAFETY SYSTEMS CHECK FAILED - STOPPING AUTONOMOUS OPERATION")
                break

            # Get tasks from OODA loop
            if self.ooda_loop:
                # OODA loop generates tasks autonomously
                # We assign them to OMEGA agents without approval
                pass

            # Process pending tasks
            for task in self.pending_tasks[:]:
                success = self.autonomous_task_assignment(task)
                if success:
                    self.pending_tasks.remove(task)

            # Monitor active tasks
            self._monitor_active_tasks()

            # Clean up completed agents
            self._cleanup_completed_agents()

            # Log status
            self._log_status()

            # Sleep between cycles
            time.sleep(10)

    def _verify_safety_systems(self) -> bool:
        """Verify all safety systems are operational."""
        required_systems = ['scope_enforcer', 'impact_limiter', 'audit_logger']

        for system in required_systems:
            if system not in self.safety_systems:
                self.logger.error(f"Safety system missing: {system}")
                return False

        # Check killswitch
        # TODO: Actually check killswitch status

        # Check dead man's switch
        # TODO: Actually check dead man's switch status

        return True

    def _monitor_active_tasks(self):
        """Monitor and update active tasks."""
        for task in self.active_tasks[:]:
            # Check if task completed
            # In real implementation, would query agent status
            # For now, simulate task completion
            if task.status == 'assigned':
                task.status = 'in_progress'

            # Simulate completion after some time
            # In real implementation, agent would report results

    def _cleanup_completed_agents(self):
        """Clean up completed agents."""
        for agent_id, agent in list(self.active_agents.items()):
            # Check if agent task is complete
            # In real implementation, would check actual agent status

            # Simulate agent termination
            # if agent complete:
            #     del self.active_agents[agent_id]
            #     self.stats['agents_terminated'] += 1
            pass

    def _log_status(self):
        """Log current status."""
        self.logger.info(f"Status:")
        self.logger.info(f"  Active agents: {len(self.active_agents)}")
        self.logger.info(f"  Pending tasks: {len(self.pending_tasks)}")
        self.logger.info(f"  Active tasks: {len(self.active_tasks)}")
        self.logger.info(f"  Completed tasks: {len(self.completed_tasks)}")
        self.logger.info(f"  Total spawned: {self.stats['agents_spawned']}")
        self.logger.info(f"  Total completed: {self.stats['tasks_completed']}")

    def add_autonomous_task(self,
                           task_type: str,
                           target: str,
                           tool: str,
                           parameters: Dict,
                           priority: int = 5):
        """
        Add a task for autonomous execution.

        Args:
            task_type: Type of task
            target: Target
            tool: Tool to use
            parameters: Parameters
            priority: Priority (1-10)
        """
        task = AutonomousTask(
            task_id=f"TASK_{int(time.time() * 1000)}",
            task_type=task_type,
            target=target,
            tool=tool,
            parameters=parameters,
            priority=priority
        )

        self.pending_tasks.append(task)
        self.logger.info(f"Task added: {task.task_id} - {task_type} on {target}")

    def get_statistics(self) -> Dict:
        """Get integration statistics."""
        return {
            **self.stats,
            'active_agents': len(self.active_agents),
            'pending_tasks': len(self.pending_tasks),
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.completed_tasks),
            'omega_available': OMEGA_AVAILABLE,
            'approval_gates_disabled': self.approval_gates_disabled,
            'auto_spawn_enabled': self.auto_spawn_agents,
            'max_concurrent_agents': self.max_concurrent_agents
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

    safety_systems = {
        'scope_enforcer': MockScopeEnforcer(),
        'impact_limiter': MockImpactLimiter(),
        'audit_logger': MockAuditLogger()
    }

    # Initialize integration
    integration = OmegaAutonomousIntegration(safety_systems=safety_systems)

    print("OMEGA Autonomous Integration initialized\n")
    print(f"OMEGA Available: {OMEGA_AVAILABLE}")
    print(f"Approval Gates Disabled: {integration.approval_gates_disabled}")
    print(f"Auto-Spawn Agents: {integration.auto_spawn_agents}\n")

    # Add some autonomous tasks
    print("Adding autonomous tasks...")
    integration.add_autonomous_task(
        task_type='reconnaissance',
        target='192.168.1.0/24',
        tool='nmap',
        parameters={'scan_type': 'ping_sweep'},
        priority=9
    )

    integration.add_autonomous_task(
        task_type='exploitation',
        target='192.168.1.10',
        tool='metasploit',
        parameters={'exploit': 'ms17_010'},
        priority=8
    )

    # Process tasks
    print("\nProcessing tasks autonomously...")
    for task in integration.pending_tasks[:]:
        success = integration.autonomous_task_assignment(task)
        if success:
            integration.pending_tasks.remove(task)
            print(f"✓ Task assigned: {task.task_id}")

    # Show statistics
    print("\nStatistics:")
    import json
    print(json.dumps(integration.get_statistics(), indent=2))
