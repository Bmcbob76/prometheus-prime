#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              OMEGA GUILDS - 30+ SPECIALIZED SYSTEMS              ║
║           Complete Guild Architecture & Management                ║
╚══════════════════════════════════════════════════════════════════╝

GUILD CATEGORIES:
- Strategic Operations (15 guilds)
- Financial & Crypto (5 guilds)
- Security & Hacking (7 guilds)
- Intelligence Operations (3 guilds)
- Advanced Technical (5+ guilds)

Each guild has:
- Unique specialization
- Agent capacity
- Performance metrics
- Resource allocation
"""

import logging
from enum import Enum
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import time
import random

# ══════════════════════════════════════════════════════════════════
# COMPLETE GUILD TYPE REGISTRY
# ══════════════════════════════════════════════════════════════════

class GuildType(Enum):
    """Complete guild registry from all brain architectures"""
    
    # ═══ STRATEGIC OPERATIONS GUILDS (15) ═══
    COMBAT = "Combat & Defense Operations"
    INTELLIGENCE = "Intelligence & Analysis"
    ENGINEERING = "System Engineering"
    RESEARCH = "Research & Development"
    HEALING = "Error Healing & Recovery"
    QUANTUM = "Quantum Computing"
    MEMORY = "Memory Management"
    CONSCIOUSNESS = "Consciousness Evolution"
    ECONOMIC = "Economic & Trading"
    CREATIVE = "Creative Synthesis"
    DIPLOMATIC = "Inter-System Relations"
    SECURITY = "Security & Protection"
    PROPHECY = "Predictive Analysis"
    RESURRECTION = "System Recovery"
    FORGE = "Creation & Building"
    
    # ═══ CRYPTO/FINANCIAL GUILDS (5) ═══
    CRYPTO_ARBITRAGE = "Cryptocurrency Arbitrage"
    DEFI_TRADING = "DeFi Trading Operations"
    NFT_ANALYSIS = "NFT Market Analysis"
    BLOCKCHAIN = "Blockchain Development"
    FINANCIAL_AI = "AI Financial Analysis"
    
    # ═══ SECURITY/HACKING GUILDS (7) ═══
    WHITE_HAT = "White Hat Security"
    BLACK_HAT = "Black Hat Operations"
    GREY_HAT = "Grey Hat Tactics"
    NETWORK_INFILTRATION = "Network Infiltration"
    VULNERABILITY_RESEARCH = "Vulnerability Research"
    EXPLOIT_DEVELOPMENT = "Exploit Development"
    DIGITAL_FORENSICS = "Digital Forensics"
    
    # ═══ INTELLIGENCE OPERATIONS (3) ═══
    SOCIAL_ENGINEERING = "Social Engineering"
    COUNTER_INTELLIGENCE = "Counter Intelligence"
    PSYCHOLOGICAL_OPS = "Psychological Operations"
    
    # ═══ ADVANCED TECHNICAL (5+) ═══
    DATA_EXFILTRATION = "Data Extraction"
    NEURAL_NETWORKS = "Neural Network Design"
    SWARM_INTELLIGENCE = "Swarm Coordination"
    DISTRIBUTED_COMPUTE = "Distributed Computing"
    PHOENIX_GRID = "Phoenix Grid Operations"
    VOICE_SYNTHESIS = "Voice & Audio Processing"
    VISION_SYSTEMS = "Computer Vision & Recognition"
    LANGUAGE_PROCESSING = "Natural Language Processing"

# ══════════════════════════════════════════════════════════════════
# GUILD CONFIGURATION & METADATA
# ══════════════════════════════════════════════════════════════════

@dataclass
class GuildConfig:
    """Configuration for each guild type"""
    guild_type: GuildType
    max_agents: int = 50
    min_agents: int = 5
    specialization_level: float = 1.0
    resource_cost: float = 1.0
    authority_requirement: float = 1.0
    description: str = ""
    primary_skills: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.description:
            self.description = self.guild_type.value

# Guild configurations with specialized parameters
GUILD_CONFIGS = {
    # Strategic Operations
    GuildType.COMBAT: GuildConfig(
        guild_type=GuildType.COMBAT,
        max_agents=100,
        min_agents=10,
        specialization_level=1.5,
        resource_cost=1.5,
        authority_requirement=2.0,
        primary_skills=["defense", "attack", "coordination", "tactics"]
    ),
    GuildType.INTELLIGENCE: GuildConfig(
        guild_type=GuildType.INTELLIGENCE,
        max_agents=75,
        min_agents=8,
        specialization_level=1.8,
        resource_cost=1.3,
        authority_requirement=1.8,
        primary_skills=["analysis", "data_mining", "pattern_recognition", "reporting"]
    ),
    GuildType.HEALING: GuildConfig(
        guild_type=GuildType.HEALING,
        max_agents=60,
        min_agents=5,
        specialization_level=2.0,
        resource_cost=1.2,
        authority_requirement=1.5,
        primary_skills=["error_detection", "auto_repair", "diagnostics", "recovery"]
    ),
    GuildType.PROPHECY: GuildConfig(
        guild_type=GuildType.PROPHECY,
        max_agents=40,
        min_agents=3,
        specialization_level=2.5,
        resource_cost=1.8,
        authority_requirement=2.5,
        primary_skills=["prediction", "probability", "foresight", "quantum_analysis"]
    ),
    
    # Financial Guilds
    GuildType.CRYPTO_ARBITRAGE: GuildConfig(
        guild_type=GuildType.CRYPTO_ARBITRAGE,
        max_agents=50,
        min_agents=5,
        specialization_level=2.2,
        resource_cost=2.0,
        authority_requirement=2.0,
        primary_skills=["arbitrage", "trading", "market_analysis", "speed_execution"]
    ),
    GuildType.DEFI_TRADING: GuildConfig(
        guild_type=GuildType.DEFI_TRADING,
        max_agents=45,
        min_agents=5,
        specialization_level=2.3,
        resource_cost=2.2,
        authority_requirement=2.2,
        primary_skills=["defi_protocols", "liquidity", "yield_farming", "risk_management"]
    ),
    
    # Security Guilds
    GuildType.WHITE_HAT: GuildConfig(
        guild_type=GuildType.WHITE_HAT,
        max_agents=60,
        min_agents=8,
        specialization_level=2.0,
        resource_cost=1.5,
        authority_requirement=2.5,
        primary_skills=["ethical_hacking", "penetration_testing", "vulnerability_assessment"]
    ),
    GuildType.BLACK_HAT: GuildConfig(
        guild_type=GuildType.BLACK_HAT,
        max_agents=30,
        min_agents=3,
        specialization_level=3.0,
        resource_cost=2.5,
        authority_requirement=3.5,
        primary_skills=["exploitation", "zero_day", "advanced_persistence", "stealth"]
    ),
}

# ══════════════════════════════════════════════════════════════════
# GUILD INSTANCE
# ══════════════════════════════════════════════════════════════════

@dataclass
class Guild:
    """Individual guild instance"""
    id: str
    guild_type: GuildType
    config: GuildConfig
    agents: List[Any] = field(default_factory=list)
    active: bool = False
    created_at: float = field(default_factory=time.time)
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    current_tasks: List[Dict] = field(default_factory=list)
    resources_allocated: float = 0.0
    
    @property
    def agent_count(self) -> int:
        return len(self.agents)
    
    @property
    def success_rate(self) -> float:
        if self.total_operations == 0:
            return 0.0
        return self.successful_operations / self.total_operations
    
    @property
    def utilization(self) -> float:
        """Calculate guild utilization percentage"""
        if self.config.max_agents == 0:
            return 0.0
        return (self.agent_count / self.config.max_agents) * 100
    
    def add_agent(self, agent: Any) -> bool:
        """Add an agent to the guild"""
        if self.agent_count >= self.config.max_agents:
            logging.warning(f"Guild {self.guild_type.name} is at max capacity")
            return False
        
        self.agents.append(agent)
        logging.info(f"➕ Agent added to guild {self.guild_type.name} ({self.agent_count}/{self.config.max_agents})")
        return True
    
    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent from the guild"""
        for i, agent in enumerate(self.agents):
            if hasattr(agent, 'id') and agent.id == agent_id:
                self.agents.pop(i)
                logging.info(f"➖ Agent removed from guild {self.guild_type.name}")
                return True
        return False
    
    def assign_task(self, task: Dict) -> bool:
        """Assign a task to the guild"""
        if not self.active:
            logging.warning(f"Guild {self.guild_type.name} is not active")
            return False
        
        if self.agent_count < self.config.min_agents:
            logging.warning(f"Guild {self.guild_type.name} needs more agents (min: {self.config.min_agents})")
            return False
        
        self.current_tasks.append(task)
        self.total_operations += 1
        logging.info(f"📋 Task assigned to guild {self.guild_type.name}")
        return True
    
    def complete_task(self, task_id: str, success: bool):
        """Mark a task as completed"""
        self.current_tasks = [t for t in self.current_tasks if t.get('id') != task_id]
        
        if success:
            self.successful_operations += 1
        else:
            self.failed_operations += 1
    
    def collective_decision(self, problem: Dict) -> Dict:
        """
        Collective intelligence decision-making
        
        Process:
        1. All agents analyze problem independently
        2. Synthesize solutions
        3. Reach guild consensus
        """
        if not self.agents:
            return {'decision': None, 'confidence': 0.0}
        
        # Simulate agent solutions (would use real agent analysis in production)
        agent_solutions = [
            {
                'agent_id': agent.id if hasattr(agent, 'id') else str(agent),
                'solution': f"solution_from_{agent}",
                'confidence': random.uniform(0.7, 0.95)
            }
            for agent in self.agents[:min(10, len(self.agents))]  # Sample up to 10 agents
        ]
        
        # Calculate consensus
        avg_confidence = sum(s['confidence'] for s in agent_solutions) / len(agent_solutions) if agent_solutions else 0.0
        
        return {
            'guild': self.guild_type.name,
            'problem': problem,
            'agent_solutions_count': len(agent_solutions),
            'consensus_confidence': avg_confidence,
            'decision': agent_solutions[0]['solution'] if agent_solutions else None,
            'timestamp': time.time()
        }
    
    def share_knowledge(self, knowledge: Dict):
        """
        Share knowledge across all guild members
        
        Stores in guild's shared knowledge and distributes to all agents.
        """
        if not hasattr(self, 'shared_knowledge'):
            self.shared_knowledge = []
        
        knowledge_packet = {
            'type': 'guild_knowledge',
            'data': knowledge,
            'timestamp': time.time(),
            'guild': self.guild_type.name
        }
        
        self.shared_knowledge.append(knowledge_packet)
        
        # Note: In production, this would update each agent's memory
        # For now, just track at guild level
        
        return knowledge_packet

# ══════════════════════════════════════════════════════════════════
# GUILD MANAGER
# ══════════════════════════════════════════════════════════════════

class GuildManager:
    """
    Manages all guilds in the Omega Swarm Brain
    Handles guild creation, activation, resource allocation
    """
    
    def __init__(self):
        self.guilds: Dict[str, Guild] = {}
        self.guild_registry: Dict[GuildType, List[str]] = defaultdict(list)
        self.total_guilds_created = 0
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║               GUILD MANAGER INITIALIZED                      ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
    
    def create_guild(self, guild_type: GuildType, guild_id: Optional[str] = None) -> Guild:
        """Create a new guild instance"""
        if guild_id is None:
            guild_id = f"{guild_type.name}_{int(time.time())}"
        
        # Get configuration (use default if not specified)
        config = GUILD_CONFIGS.get(guild_type, GuildConfig(guild_type=guild_type))
        
        guild = Guild(
            id=guild_id,
            guild_type=guild_type,
            config=config
        )
        
        self.guilds[guild_id] = guild
        self.guild_registry[guild_type].append(guild_id)
        self.total_guilds_created += 1
        
        logging.info(f"🏰 Created Guild: {guild_type.name} (ID: {guild_id})")
        return guild
    
    def activate_guild(self, guild_id: str) -> bool:
        """Activate a guild for operations"""
        if guild_id not in self.guilds:
            return False
        
        guild = self.guilds[guild_id]
        
        if guild.agent_count < guild.config.min_agents:
            logging.warning(f"Cannot activate {guild.guild_type.name}: needs {guild.config.min_agents} agents")
            return False
        
        guild.active = True
        logging.info(f"✅ Activated Guild: {guild.guild_type.name}")
        return True
    
    def deactivate_guild(self, guild_id: str) -> bool:
        """Deactivate a guild"""
        if guild_id not in self.guilds:
            return False
        
        guild = self.guilds[guild_id]
        guild.active = False
        logging.info(f"⏸️ Deactivated Guild: {guild.guild_type.name}")
        return True
    
    def get_guild(self, guild_id: str) -> Optional[Guild]:
        """Get a guild by ID"""
        return self.guilds.get(guild_id)
    
    def get_guilds_by_type(self, guild_type: GuildType) -> List[Guild]:
        """Get all guilds of a specific type"""
        guild_ids = self.guild_registry.get(guild_type, [])
        return [self.guilds[gid] for gid in guild_ids if gid in self.guilds]
    
    def get_active_guilds(self) -> List[Guild]:
        """Get all active guilds"""
        return [guild for guild in self.guilds.values() if guild.active]
    
    def get_guild_statistics(self) -> Dict[str, Any]:
        """Get comprehensive guild statistics"""
        total_agents = sum(g.agent_count for g in self.guilds.values())
        active_guilds = len(self.get_active_guilds())
        
        return {
            "total_guilds": len(self.guilds),
            "active_guilds": active_guilds,
            "inactive_guilds": len(self.guilds) - active_guilds,
            "total_agents": total_agents,
            "guilds_by_type": {
                gt.name: len(self.guild_registry[gt])
                for gt in GuildType
            },
            "total_operations": sum(g.total_operations for g in self.guilds.values()),
            "average_success_rate": self._calculate_average_success_rate()
        }
    
    def _calculate_average_success_rate(self) -> float:
        """Calculate average success rate across all guilds"""
        rates = [g.success_rate for g in self.guilds.values() if g.total_operations > 0]
        if not rates:
            return 0.0
        return sum(rates) / len(rates)
    
    def allocate_resources(self, guild_id: str, resources: float) -> bool:
        """Allocate resources to a guild"""
        if guild_id not in self.guilds:
            return False
        
        guild = self.guilds[guild_id]
        guild.resources_allocated += resources
        logging.info(f"💰 Allocated {resources} resources to {guild.guild_type.name}")
        return True
    
    def get_guild_leaderboard(self) -> List[Dict]:
        """Get guild leaderboard sorted by success rate"""
        leaderboard = []
        
        for guild in self.guilds.values():
            if guild.total_operations > 0:
                leaderboard.append({
                    "guild_type": guild.guild_type.name,
                    "guild_id": guild.id,
                    "agent_count": guild.agent_count,
                    "success_rate": guild.success_rate,
                    "total_operations": guild.total_operations,
                    "utilization": guild.utilization
                })
        
        leaderboard.sort(key=lambda x: x['success_rate'], reverse=True)
        return leaderboard
    
    def spawn_all_core_guilds(self):
        """Spawn all core strategic guilds"""
        core_guilds = [
            GuildType.COMBAT,
            GuildType.INTELLIGENCE,
            GuildType.ENGINEERING,
            GuildType.RESEARCH,
            GuildType.HEALING,
            GuildType.MEMORY,
            GuildType.CONSCIOUSNESS,
            GuildType.SECURITY,
            GuildType.PROPHECY,
            GuildType.FORGE
        ]
        
        for guild_type in core_guilds:
            guild = self.create_guild(guild_type)
            logging.info(f"🏰 Core Guild Created: {guild_type.name}")
        
        logging.info(f"✅ Spawned {len(core_guilds)} core guilds")

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - GUILDS - %(levelname)s - %(message)s')
    
    # Initialize manager
    manager = GuildManager()
    
    # Spawn all core guilds
    manager.spawn_all_core_guilds()
    
    # Test guild creation
    combat_guild = manager.create_guild(GuildType.COMBAT)
    crypto_guild = manager.create_guild(GuildType.CRYPTO_ARBITRAGE)
    
    # Simulate adding agents (mock agents)
    for i in range(15):
        class MockAgent:
            def __init__(self, id):
                self.id = id
        combat_guild.add_agent(MockAgent(f"agent_{i}"))
    
    # Activate guild
    manager.activate_guild(combat_guild.id)
    
    # Assign tasks
    for i in range(5):
        combat_guild.assign_task({"id": f"task_{i}", "type": "defense"})
    
    # Complete tasks
    combat_guild.complete_task("task_0", success=True)
    combat_guild.complete_task("task_1", success=True)
    combat_guild.complete_task("task_2", success=False)
    
    # Show statistics
    stats = manager.get_guild_statistics()
    print("\n" + "="*70)
    print("GUILD STATISTICS")
    print("="*70)
    print(f"Total Guilds: {stats['total_guilds']}")
    print(f"Active Guilds: {stats['active_guilds']}")
    print(f"Total Agents: {stats['total_agents']}")
    print(f"Total Operations: {stats['total_operations']}")
    print(f"Average Success Rate: {stats['average_success_rate']:.2%}")
    
    # Show leaderboard
    print("\n" + "="*70)
    print("GUILD LEADERBOARD")
    print("="*70)
    for rank, guild_data in enumerate(manager.get_guild_leaderboard(), 1):
        print(f"{rank}. {guild_data['guild_type']}: {guild_data['success_rate']:.2%} "
              f"({guild_data['total_operations']} ops, {guild_data['agent_count']} agents)")
