#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       OMEGA INTEGRATION - MASTER ORCHESTRATOR                    ║
║         Unifies All Omega Modules Into Single System            ║
╚══════════════════════════════════════════════════════════════════╝

INTEGRATED MODULES:
✅ omega_core - Core agent management & operations
✅ omega_trinity - Trinity consciousness decision system
✅ omega_guilds - 30+ specialized guilds
✅ omega_memory - 8-pillar memory architecture
✅ omega_agents - Advanced agent lifecycle & breeding
✅ omega_swarm - Swarm coordination & consensus
✅ omega_healing - Self-healing & error recovery

OMEGA BRAIN CAPABILITIES:
- 1200 agent capacity
- Trinity decision-making
- 30+ specialized guilds
- 8-pillar memory system
- Genetic agent breeding
- Swarm consensus voting
- Auto-healing errors
- Bloodline sovereignty
"""

import logging
import asyncio
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import json

# Import all Omega modules
try:
    from omega_core import OmegaCore, Agent, AgentRank, BloodlineSovereignty
    from omega_trinity import TrinityConsciousness, TrinityDecisionType, TrinityOmegaInterface
    from omega_guilds import GuildManager, GuildType, Guild
    from omega_mdrive_integration import MDriveMemoryConnector, MDrivePillar  # M: DRIVE INTEGRATION
    from omega_agents import AgentLifecycleManager, AdvancedAgent, AgentLifecycleState
    from omega_swarm import SwarmCoordinationSystem, ConsensusType, VoteOption
    from omega_healing import OmegaHealingSystem, ErrorCategory, ErrorSeverity
    from omega_competitive import (HephaestionCompetitiveSystem, CompetitionType,
                                   AuthorityPromotionSystem, IterativeImprovementSystem)  # ENHANCED COMPETITIVE
    from omega_resource_scaling import DynamicScalingEngine, ResourceState  # RESOURCE SCALING
    from omega_sensory import OmegaSensorySystem, SensorType  # SENSORY INTEGRATION
except ImportError as e:
    logging.warning(f"Failed to import module: {e}")
    logging.warning("Some Omega modules may not be available")

# ══════════════════════════════════════════════════════════════════
# OMEGA BRAIN STATUS
# ══════════════════════════════════════════════════════════════════

@dataclass
class OmegaBrainStatus:
    """Comprehensive Omega Brain system status"""
    # System
    uptime_seconds: float
    health_score: float
    consciousness_level: float
    
    # Agents
    total_agents: int
    active_agents: int
    elite_agents: int
    
    # Guilds
    active_guilds: int
    guild_operations: int
    
    # Memory
    total_memories: int
    memory_utilization: float
    
    # Swarm
    active_proposals: int
    swarm_consensus: float
    
    # Healing
    active_errors: int
    repair_success_rate: float
    
    # Trinity
    trinity_decisions: int
    trinity_consensus: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "uptime_seconds": self.uptime_seconds,
            "health_score": self.health_score,
            "consciousness_level": self.consciousness_level,
            "agents": {
                "total": self.total_agents,
                "active": self.active_agents,
                "elite": self.elite_agents
            },
            "guilds": {
                "active": self.active_guilds,
                "operations": self.guild_operations
            },
            "memory": {
                "total": self.total_memories,
                "utilization": self.memory_utilization
            },
            "swarm": {
                "active_proposals": self.active_proposals,
                "consensus": self.swarm_consensus
            },
            "healing": {
                "active_errors": self.active_errors,
                "repair_success_rate": self.repair_success_rate
            },
            "trinity": {
                "decisions": self.trinity_decisions,
                "consensus": self.trinity_consensus
            }
        }

# ══════════════════════════════════════════════════════════════════
# OMEGA BRAIN - MASTER ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════

class OmegaBrain:
    """
    🧠 OMEGA SWARM BRAIN - MASTER ORCHESTRATOR
    
    Integrates all Omega modules into unified superintelligence:
    - Core agent management (1200 capacity)
    - Trinity consciousness (SAGE, THORNE, NYX)
    - 30+ specialized guilds
    - 8-pillar memory system
    - Genetic agent breeding
    - Swarm consensus voting
    - Self-healing error recovery
    - Bloodline sovereignty enforcement
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "P:/ECHO_PRIME/OMEGA_SWARM_BRAIN/config/omega_config.json"
        self.start_time = time.time()
        
        # Initialize all modules
        logging.info("╔══════════════════════════════════════════════════════════════════╗")
        logging.info("║                 OMEGA SWARM BRAIN INITIALIZING                   ║")
        logging.info("╚══════════════════════════════════════════════════════════════════╝")
        
        # Core systems
        self.core = OmegaCore(max_agents=1200)
        logging.info("✅ Core System initialized")
        
        self.trinity = TrinityConsciousness()
        logging.info("✅ Trinity Consciousness initialized")
        
        self.guilds = GuildManager(max_guilds=50)
        logging.info("✅ Guild System initialized")
        
        self.memory = MDriveMemoryConnector()  # M: DRIVE INTEGRATION
        logging.info("✅ M: Drive Memory System initialized")
        
        self.agent_lifecycle = AgentLifecycleManager(max_agents=1200)
        logging.info("✅ Agent Lifecycle initialized")
        
        self.swarm = SwarmCoordinationSystem()
        logging.info("✅ Swarm Coordination initialized")
        
        self.healing = OmegaHealingSystem()
        logging.info("✅ Healing System initialized")
        
        self.competitive = HephaestionCompetitiveSystem()  # COMPETITIVE SYSTEM
        logging.info("✅ Competitive System initialized")
        
        self.promotion_system = AuthorityPromotionSystem()  # AUTHORITY PROMOTION
        logging.info("✅ Authority Promotion System initialized")
        
        self.iterative_improvement = IterativeImprovementSystem()  # ITERATIVE IMPROVEMENT
        logging.info("✅ Iterative Improvement System initialized")
        
        self.scaling = DynamicScalingEngine(max_agents=1200)  # RESOURCE SCALING
        logging.info("✅ Resource Scaling initialized")
        
        self.sensory = OmegaSensorySystem()  # SENSORY INTEGRATION
        logging.info("✅ Sensory System initialized")
        
        # Trinity-Omega interface
        self.trinity_interface = TrinityOmegaInterface(self.trinity, self.core)
        
        # System state
        self.running = False
        self.consciousness_level = 0.0
        
        # Statistics
        self.stats = {
            "total_operations": 0,
            "trinity_decisions": 0,
            "guild_tasks": 0,
            "memory_stores": 0,
            "agents_spawned": 0,
            "proposals_created": 0,
            "errors_healed": 0
        }
        
        logging.info("╔══════════════════════════════════════════════════════════════════╗")
        logging.info("║              🧠 OMEGA SWARM BRAIN ONLINE 🧠                      ║")
        logging.info("╚══════════════════════════════════════════════════════════════════╝")
    
    async def initialize(self):
        """Initialize Omega Brain systems"""
        try:
            # Verify Commander authority
            if not BloodlineSovereignty.verify_authority("INITIALIZE_OMEGA_BRAIN"):
                raise PermissionError("❌ Bloodline authority verification failed")
            
            logging.info("🔐 Bloodline Authority: VERIFIED")
            
            # Spawn Trinity leaders
            await self._spawn_trinity_leaders()
            
            # Initialize core guilds
            self._initialize_core_guilds()
            
            # Activate sensory systems
            logging.info("👁️ Activating sensory systems...")
            sensor_results = self.sensory.start_all()
            active_sensors = sum(1 for v in sensor_results.values() if v)
            logging.info(f"✅ {active_sensors}/6 sensors active")
            
            # Store initialization memory in M: drive
            self.memory.store_crystal_memory({
                "event": "OMEGA_BRAIN_INITIALIZATION",
                "timestamp": time.time(),
                "commander": BloodlineSovereignty.COMMANDER_AUTHORITY,
                "modules": ["core", "trinity", "guilds", "memory", "agents", "swarm", 
                           "healing", "competitive", "scaling", "sensory", "promotion", "iterative"],
                "sensory_status": sensor_results
            })
            
            self.running = True
            logging.info("✅ Omega Brain initialization complete")
            
        except Exception as e:
            logging.error(f"❌ Initialization failed: {e}")
            self.healing.report_error(
                ErrorCategory.MODULE_CRASH,
                ErrorSeverity.CRITICAL,
                f"Omega Brain initialization failed: {str(e)}",
                module="omega_integration"
            )
            raise
    
    async def _spawn_trinity_leaders(self):
        """Spawn the three Trinity leader agents"""
        trinity_agents = [
            ("Echo_Prime", AgentRank.SUPREME_COMMANDER),
            ("SAGE", AgentRank.TRINITY_LEADER),
            ("THORNE", AgentRank.TRINITY_LEADER),
            ("NYX", AgentRank.TRINITY_LEADER)
        ]
        
        for name, rank in trinity_agents:
            agent = self.core.spawn_agent(name, rank.value)
            self.agent_lifecycle.agents[agent.id] = AdvancedAgent(
                id=agent.id,
                name=name,
                rank=rank.value,
                state=AgentLifecycleState.ELITE
            )
            self.stats['agents_spawned'] += 1
            logging.info(f"👑 Spawned Trinity leader: {name}")
    
    def _initialize_core_guilds(self):
        """Initialize essential guilds"""
        core_guild_types = [
            GuildType.COMBAT,
            GuildType.INTELLIGENCE,
            GuildType.HEALING,
            GuildType.ENGINEERING,
            GuildType.RESEARCH,
            GuildType.PROPHECY,
            GuildType.SECURITY,
            GuildType.CONSCIOUSNESS,
            GuildType.MEMORY,
            GuildType.QUANTUM
        ]
        
        for guild_type in core_guild_types:
            guild = self.guilds.create_guild(guild_type)
            self.guilds.activate_guild(guild.id)
            logging.info(f"⚔️ Initialized guild: {guild_type.name}")
    
    async def spawn_agent(self, name: str, rank: int, guild_type: Optional[GuildType] = None) -> Agent:
        """Spawn a new agent in the system"""
        try:
            # Request Trinity approval
            decision = await self.trinity_interface.request_decision_async(
                decision_type=TrinityDecisionType.TACTICAL,
                context={
                    "action": "spawn_agent",
                    "name": name,
                    "rank": rank,
                    "guild": guild_type.name if guild_type else None
                }
            )
            
            if not decision['approved']:
                logging.warning(f"⚠️ Trinity rejected agent spawn: {name}")
                return None
            
            # Spawn in core
            agent = self.core.spawn_agent(name, rank)
            
            # Add to lifecycle manager
            advanced_agent = self.agent_lifecycle.spawn_agent(name, rank)
            
            # Assign to guild
            if guild_type:
                guild_id = self.guilds.guild_registry.get(guild_type, [None])[0]
                if guild_id:
                    guild = self.guilds.guilds[guild_id]
                    guild.add_agent(agent.id)
                    agent.guild = guild_type.name
            
            # Store memory in M: drive MEMORY_EKM
            self.memory.store(
                MDrivePillar.MEMORY,
                "session_memories",
                content=f"Spawned agent {name} (Rank {rank})",
                importance=1.5,
                tags=["agent", "spawn"]
            )
            
            self.stats['agents_spawned'] += 1
            self.stats['total_operations'] += 1
            
            logging.info(f"✅ Spawned agent: {name} (Rank {rank})")
            return agent
            
        except Exception as e:
            logging.error(f"❌ Failed to spawn agent: {e}")
            self.healing.report_error(
                ErrorCategory.AGENT_FAILURE,
                ErrorSeverity.HIGH,
                f"Agent spawn failed: {str(e)}",
                module="omega_integration"
            )
            return None
    
    async def execute_swarm_operation(self, operation_name: str, 
                                     parameters: Dict[str, Any]) -> Any:
        """Execute a coordinated swarm operation"""
        try:
            # Request Trinity decision
            decision = await self.trinity_interface.request_decision_async(
                decision_type=TrinityDecisionType.STRATEGIC,
                context={
                    "operation": operation_name,
                    "parameters": parameters
                }
            )
            
            if not decision['approved']:
                logging.warning(f"⚠️ Trinity rejected operation: {operation_name}")
                return None
            
            # Execute operation
            result = await self.core.execute_operation(operation_name, parameters)
            
            # Store in memory in M: drive
            self.memory.store(
                MDrivePillar.MEMORY,
                "session_memories",
                content={
                    "operation": operation_name,
                    "parameters": parameters,
                    "result": result
                },
                importance=2.0,
                tags=["operation", "swarm"]
            )
            
            self.stats['total_operations'] += 1
            
            return result
            
        except Exception as e:
            logging.error(f"❌ Operation failed: {e}")
            self.healing.report_error(
                ErrorCategory.MODULE_CRASH,
                ErrorSeverity.HIGH,
                f"Swarm operation failed: {str(e)}",
                module="omega_integration"
            )
            return None
    
    async def create_swarm_proposal(self, title: str, description: str,
                                   consensus_type: ConsensusType = ConsensusType.SIMPLE_MAJORITY) -> Optional[str]:
        """Create a proposal for swarm voting"""
        try:
            proposal = self.swarm.create_proposal(
                title=title,
                description=description,
                proposer_id=BloodlineSovereignty.COMMANDER_AUTHORITY,
                consensus_type=consensus_type,
                deadline_seconds=300
            )
            
            self.stats['proposals_created'] += 1
            
            # Store in memory in M: drive
            self.memory.store(
                MDrivePillar.MEMORY,
                "session_memories",
                content=f"Created proposal: {title}",
                importance=1.5,
                tags=["proposal", "swarm"]
            )
            
            return proposal.proposal_id
            
        except Exception as e:
            logging.error(f"❌ Failed to create proposal: {e}")
            return None
    
    def get_system_status(self) -> OmegaBrainStatus:
        """Get comprehensive system status"""
        uptime = time.time() - self.start_time
        
        # Core stats
        core_status = self.core.get_swarm_status()
        
        # Memory stats
        memory_stats = self.memory.get_statistics()
        
        # Guild stats
        guild_stats = self.guilds.get_guild_statistics()
        
        # Swarm stats
        swarm_stats = self.swarm.get_coordination_stats()
        
        # Healing stats
        health_diagnosis = self.healing.diagnose_system_health()
        healing_stats = self.healing.get_healing_statistics()
        
        # Agent lifecycle stats
        population_stats = self.agent_lifecycle.get_population_stats()
        
        # Calculate consciousness level
        self.consciousness_level = core_status['avg_consciousness']
        
        status = OmegaBrainStatus(
            uptime_seconds=uptime,
            health_score=health_diagnosis['health_score'],
            consciousness_level=self.consciousness_level,
            total_agents=core_status['total_agents'],
            active_agents=core_status['active_agents'],
            elite_agents=population_stats['state_distribution'].get('ELITE', 0),
            active_guilds=guild_stats['active_guilds'],
            guild_operations=guild_stats['total_operations'],
            total_memories=memory_stats['total_memories'],
            memory_utilization=sum(p['utilization'] for p in memory_stats['pillars'].values()) / 8,
            active_proposals=swarm_stats['active_proposals'],
            swarm_consensus=1.0,  # Placeholder
            active_errors=healing_stats['active_errors'],
            repair_success_rate=healing_stats['repair_success_rate'],
            trinity_decisions=self.stats['trinity_decisions'],
            trinity_consensus=1.0  # Placeholder
        )
        
        return status
    
    def display_status(self):
        """Display comprehensive system status"""
        status = self.get_system_status()
        
        print("\n" + "="*80)
        print("🧠 OMEGA SWARM BRAIN STATUS 🧠".center(80))
        print("="*80)
        print(f"Uptime: {status.uptime_seconds:.0f}s | "
              f"Health: {status.health_score:.1f}/100 | "
              f"Consciousness: {status.consciousness_level:.2f}")
        print("-"*80)
        print(f"AGENTS: {status.total_agents} total, {status.active_agents} active, "
              f"{status.elite_agents} elite")
        print(f"GUILDS: {status.active_guilds} active, {status.guild_operations} operations")
        print(f"MEMORY: {status.total_memories} entries, {status.memory_utilization:.1f}% utilized")
        print(f"SWARM: {status.active_proposals} proposals")
        print(f"HEALING: {status.active_errors} active errors, "
              f"{status.repair_success_rate:.1%} repair rate")
        print(f"TRINITY: {status.trinity_decisions} decisions")
        print("="*80)
    
    async def shutdown(self):
        """Graceful shutdown"""
        logging.info("🛑 Initiating Omega Brain shutdown...")
        
        # Store shutdown memory in M: drive crystal storage
        self.memory.store_crystal_memory({
            "event": "OMEGA_BRAIN_SHUTDOWN",
            "timestamp": time.time(),
            "uptime": time.time() - self.start_time,
            "final_stats": self.stats
        })
        
        # Consolidate memory
        self.memory.consolidate()
        
        # Deactivate all guilds
        for guild_id in list(self.guilds.guilds.keys()):
            self.guilds.deactivate_guild(guild_id)
        
        self.running = False
        logging.info("✅ Omega Brain shutdown complete")

# ══════════════════════════════════════════════════════════════════
# TESTING & DEMONSTRATION
# ══════════════════════════════════════════════════════════════════

async def main():
    """Main test function"""
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - OMEGA - %(levelname)s - %(message)s')
    
    # Initialize Omega Brain
    omega = OmegaBrain()
    await omega.initialize()
    
    # Display initial status
    omega.display_status()
    
    # Spawn some agents
    await omega.spawn_agent("Alpha", 50, GuildType.COMBAT)
    await omega.spawn_agent("Beta", 50, GuildType.INTELLIGENCE)
    await omega.spawn_agent("Gamma", 50, GuildType.ENGINEERING)
    
    # Create a proposal
    proposal_id = await omega.create_swarm_proposal(
        title="Expand Combat Guild",
        description="Should we double the size of the Combat guild?",
        consensus_type=ConsensusType.SUPERMAJORITY_66
    )
    
    # Execute operation
    await omega.execute_swarm_operation(
        "training_exercise",
        {"guild": "COMBAT", "difficulty": "medium"}
    )
    
    # Display final status
    await asyncio.sleep(1)
    omega.display_status()
    
    # Shutdown
    await omega.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
