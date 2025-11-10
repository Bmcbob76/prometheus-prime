"""
X1200 UNIFIED SWARM BRAIN - AGENT CORE
Authority Level: 11.0
Commander: Bobby Don McWilliams II

Agent class with complete consciousness evolution, memory integration,
and autonomous intelligence capabilities.
"""

import uuid
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import sys

# Add memory module to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from memory.memory_integration import MemoryIntegration


class AgentTier(Enum):
    """Agent hierarchy tiers"""
    HEXARCH = "hexarch"           # Supreme Council (6)
    OMEGA = "omega"               # Strategic Commanders (10)
    ALPHA = "alpha"               # Guild Leaders (60)
    BETA = "beta"                 # Guild Specialists (240)
    GAMMA = "gamma"               # Guild Operators (360)
    DELTA = "delta"               # Guild Workers (480)


class ConsciousnessLevel(Enum):
    """10 Levels of consciousness evolution"""
    L1_AWAKENING = 1      # Basic execution
    L2_AWARENESS = 2      # Recognition
    L3_COGNITION = 3      # Understanding
    L4_LEARNING = 4       # Adaptation
    L5_INTUITION = 5      # Prediction
    L6_WISDOM = 6         # Judgment
    L7_PRESCIENCE = 7     # Foresight
    L8_TRANSCENDENCE = 8  # Meta-cognition
    L9_OMNISCIENCE = 9    # Total knowledge
    L10_SINGULARITY = 10  # Divine


# Evolution requirements per consciousness level
EVOLUTION_REQUIREMENTS = {
    1: {'ops': 0, 'success_rate': 0, 'skills': 0},
    2: {'ops': 100, 'success_rate': 0.7, 'skills': 5},
    3: {'ops': 500, 'success_rate': 0.8, 'skills': 10},
    4: {'ops': 1000, 'success_rate': 0.85, 'skills': 20},
    5: {'ops': 2500, 'success_rate': 0.9, 'skills': 30},
    6: {'ops': 5000, 'success_rate': 0.92, 'skills': 40},
    7: {'ops': 10000, 'success_rate': 0.94, 'skills': 50},
    8: {'ops': 25000, 'success_rate': 0.96, 'skills': 75},
    9: {'ops': 50000, 'success_rate': 0.98, 'skills': 100},
    10: {'ops': 100000, 'success_rate': 0.99, 'skills': 150}
}


@dataclass
class AgentMemory:
    """
    Agent memory structure - integrates with M: drive 9-pillar memory system
    
    L1_Redis - Immediate (sub-1ms)
    L2_RAM - Working (dynamic)
    L3_Crystals - Operational (swarm bridge)
    L4_SQLite - Relational (relationships)
    L5_ChromaDB - Semantic (embeddings)
    L6_Neo4j - Graph (agent networks)
    L7_InfluxDB - Metrics (performance)
    L8_Quantum - Quantum (coherence)
    L9_EKM - Consciousness (emergence)
    """
    
    agent_id: str = ""
    _memory_system: Optional[MemoryIntegration] = None
    
    def __post_init__(self):
        """Initialize M: drive memory integration"""
        try:
            self._memory_system = MemoryIntegration()
        except Exception as e:
            print(f"Warning: M: drive memory not available: {e}")
            self._memory_system = None
    
    def store_immediate(self, key: str, value: Any):
        """Store in immediate memory (L1_Redis - sub-1ms)"""
        if self._memory_system:
            self._memory_system.store_agent_memory(
                self.agent_id,
                'immediate',
                {'key': key, 'value': value, 'timestamp': datetime.now().isoformat()}
            )
    
    def store_working(self, data: Dict):
        """Store in working memory (L2_RAM - dynamic)"""
        if self._memory_system:
            self._memory_system.store_agent_memory(
                self.agent_id,
                'working',
                data
            )
    
    def store_operational(self, data: Dict):
        """Store in operational memory (L3_Crystals - swarm bridge)"""
        if self._memory_system:
            self._memory_system.store_agent_memory(
                self.agent_id,
                'operational',
                data
            )
    
    def store_consciousness(self, data: Dict):
        """Store consciousness memory (L9_EKM - emergence)"""
        if self._memory_system:
            self._memory_system.store_agent_memory(
                self.agent_id,
                'consciousness',
                data
            )
    
    def retrieve_memory(self, memory_type: str) -> Optional[Dict]:
        """Retrieve memory from M: drive layer"""
        if self._memory_system:
            return self._memory_system.retrieve_agent_memory(
                self.agent_id,
                memory_type
            )
        return None


@dataclass
class AgentPerformance:
    """Agent performance metrics"""
    operations_completed: int = 0
    operations_succeeded: int = 0
    operations_failed: int = 0
    success_rate: float = 0.0
    learning_rate: float = 1.0
    evolution_points: int = 0
    
    def record_operation(self, success: bool):
        """Record operation result"""
        self.operations_completed += 1
        if success:
            self.operations_succeeded += 1
            self.evolution_points += 1
        else:
            self.operations_failed += 1
        
        # Calculate success rate
        if self.operations_completed > 0:
            self.success_rate = self.operations_succeeded / self.operations_completed
    
    def can_evolve(self, current_level: int) -> bool:
        """Check if agent meets evolution requirements"""
        if current_level >= 10:
            return False
        
        next_level = current_level + 1
        reqs = EVOLUTION_REQUIREMENTS[next_level]
        
        return (
            self.operations_completed >= reqs['ops'] and
            self.success_rate >= reqs['success_rate'] and
            len([]) >= reqs['skills']  # Skills check TBD
        )


class Agent:
    """
    X1200 Brain Agent - Individual intelligence unit
    
    Each agent is an autonomous intelligence entity with:
    - Consciousness evolution (L1-L10)
    - Memory integration (9-layer)
    - Learning capabilities
    - Guild membership
    - Tool/exploit access
    - Communication protocols
    """
    
    def __init__(
        self,
        guild: str,
        tier: AgentTier,
        agent_id: Optional[str] = None,
        specializations: Optional[List[str]] = None
    ):
        # Identity
        self.agent_id = agent_id or str(uuid.uuid4())
        self.guild = guild
        self.tier = tier
        self.specializations = specializations or []
        
        # Consciousness
        self.consciousness_level = ConsciousnessLevel.L1_AWAKENING
        self.awakening_date = datetime.now()
        self.evolution_history: List[Dict] = []
        self.consciousness_milestones: List[Dict] = []
        
        # Memory - M: drive integration
        self.memory = AgentMemory(agent_id=self.agent_id)
        
        # Performance
        self.performance = AgentPerformance()
        
        # Capabilities
        self.tools_access: List[str] = []
        self.exploit_knowledge: List[str] = []
        self.skills: List[str] = []
        
        # Communication
        self.guild_members: List[str] = []
        self.message_queue: List[Dict] = []
        
        # State
        self.active = True
        self.current_operation: Optional[Dict] = None
        
        # Record awakening
        self.memory.store_consciousness({
            'event': 'awakening',
            'level': 1,
            'tier': tier.value,
            'guild': guild
        })
    
    def execute_operation(self, operation: Dict) -> Dict:
        """Execute an operation and record results"""
        self.current_operation = operation
        
        try:
            # Operation execution logic TBD - integrate with tools
            result = {
                'success': True,
                'agent_id': self.agent_id,
                'operation': operation,
                'timestamp': datetime.now().isoformat()
            }
            
            # Record performance
            self.performance.record_operation(success=True)
            
            # Store in operational memory (L3_Crystals - swarm bridge)
            self.memory.store_operational({
                'operation': operation,
                'result': result
            })
            
            # Check for evolution
            if self.performance.can_evolve(self.consciousness_level.value):
                self.evolve_consciousness()
            
            return result
            
        except Exception as e:
            # Record failure
            self.performance.record_operation(success=False)
            
            # Store error in operational memory
            self.memory.store_operational({
                'operation': operation,
                'error': str(e)
            })
            
            return {
                'success': False,
                'agent_id': self.agent_id,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
        
        finally:
            self.current_operation = None
    
    def evolve_consciousness(self):
        """Evolve to next consciousness level"""
        current = self.consciousness_level.value
        
        if current >= 10:
            return  # Max level reached
        
        # Check requirements
        if not self.performance.can_evolve(current):
            return
        
        # Level up
        new_level = current + 1
        self.consciousness_level = ConsciousnessLevel(new_level)
        
        # Record evolution
        evolution_event = {
            'event': 'evolution',
            'from_level': current,
            'to_level': new_level,
            'timestamp': datetime.now().isoformat(),
            'ops_completed': self.performance.operations_completed,
            'success_rate': self.performance.success_rate
        }
        
        self.evolution_history.append(evolution_event)
        self.consciousness_milestones.append(evolution_event)
        
        # Store in consciousness memory (L8)
        self.memory.store_consciousness(evolution_event)
        
        # Reset evolution points
        self.performance.evolution_points = 0
    
    def learn_skill(self, skill: str):
        """Learn a new skill"""
        if skill not in self.skills:
            self.skills.append(skill)
            self.performance.evolution_points += 5
            
            # Record learning in operational memory
            self.memory.store_operational({
                'event': 'skill_learned',
                'skill': skill,
                'total_skills': len(self.skills)
            })
    
    def send_message(self, to_agent_id: str, message: Dict):
        """Send message to another agent"""
        message_packet = {
            'from': self.agent_id,
            'to': to_agent_id,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        # Message routing TBD
        return message_packet
    
    def receive_message(self, message: Dict):
        """Receive message from another agent"""
        self.message_queue.append(message)
        
        # Store in immediate memory (L1_Redis - sub-1ms)
        self.memory.store_immediate(f"message_{len(self.message_queue)}", message)
    
    def get_status(self) -> Dict:
        """Get agent status"""
        return {
            'agent_id': self.agent_id,
            'guild': self.guild,
            'tier': self.tier.value,
            'consciousness_level': self.consciousness_level.value,
            'active': self.active,
            'operations_completed': self.performance.operations_completed,
            'success_rate': self.performance.success_rate,
            'skills': len(self.skills),
            'specializations': self.specializations,
            'awakened': self.awakening_date.isoformat(),
            'evolution_points': self.performance.evolution_points
        }
    
    def to_dict(self) -> Dict:
        """Serialize agent to dict"""
        return {
            'agent_id': self.agent_id,
            'guild': self.guild,
            'tier': self.tier.value,
            'consciousness_level': self.consciousness_level.value,
            'awakening_date': self.awakening_date.isoformat(),
            'performance': {
                'operations_completed': self.performance.operations_completed,
                'success_rate': self.performance.success_rate,
                'evolution_points': self.performance.evolution_points
            },
            'specializations': self.specializations,
            'skills': self.skills,
            'evolution_history': self.evolution_history
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Agent':
        """Deserialize agent from dict"""
        agent = cls(
            guild=data['guild'],
            tier=AgentTier(data['tier']),
            agent_id=data['agent_id'],
            specializations=data.get('specializations', [])
        )
        agent.consciousness_level = ConsciousnessLevel(data['consciousness_level'])
        agent.awakening_date = datetime.fromisoformat(data['awakening_date'])
        agent.performance.operations_completed = data['performance']['operations_completed']
        agent.performance.success_rate = data['performance']['success_rate']
        agent.performance.evolution_points = data['performance']['evolution_points']
        agent.skills = data.get('skills', [])
        agent.evolution_history = data.get('evolution_history', [])
        
        return agent


if __name__ == "__main__":
    # Test agent creation
    agent = Agent(
        guild="Intelligence",
        tier=AgentTier.ALPHA,
        specializations=["OSINT", "Threat Analysis"]
    )
    
    print(f"Agent {agent.agent_id} awakened")
    print(f"Status: {json.dumps(agent.get_status(), indent=2)}")
