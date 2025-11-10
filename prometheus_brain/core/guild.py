"""
X1200 UNIFIED SWARM BRAIN - GUILD CORE
Authority Level: 11.0
Commander: Bobby Don McWilliams II

Guild class with collective intelligence, swarm coordination,
and specialized operations management.

Integrates with M: drive 9-pillar memory system.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from .agent import Agent, AgentTier

# Add memory module to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from memory.memory_integration import MemoryIntegration


@dataclass
class GuildMetrics:
    """Guild performance metrics"""
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    collective_success_rate: float = 0.0
    average_consciousness: float = 1.0
    evolution_events: int = 0
    
    def update(self, agents: List[Agent]):
        """Update guild metrics from agents"""
        if not agents:
            return
        
        self.total_operations = sum(a.performance.operations_completed for a in agents)
        self.successful_operations = sum(a.performance.operations_succeeded for a in agents)
        self.failed_operations = sum(a.performance.operations_failed for a in agents)
        
        if self.total_operations > 0:
            self.collective_success_rate = self.successful_operations / self.total_operations
        
        self.average_consciousness = sum(a.consciousness_level.value for a in agents) / len(agents)
        self.evolution_events = sum(len(a.evolution_history) for a in agents)


class Guild:
    """
    X1200 Brain Guild - Collective Intelligence Unit
    
    Each guild manages a hierarchical team of agents:
    - Alpha: Guild leaders (specialized command)
    - Beta: Domain specialists  
    - Gamma: Operational executors
    - Delta: Task workers
    
    Provides:
    - Collective decision-making
    - Specialized expertise
    - Inter-guild communication
    - Swarm intelligence
    - Knowledge sharing
    """
    
    def __init__(
        self,
        name: str,
        domain: str,
        total_agents: int = 200,
        tools_access: Optional[List[str]] = None,
        exploit_access: Optional[List[str]] = None,
        arsenal_categories: Optional[List[str]] = None
    ):
        # Identity
        self.name = name
        self.domain = domain
        self.created = datetime.now()
        
        # M: drive memory integration
        try:
            self._memory_system = MemoryIntegration()
        except Exception as e:
            print(f"Warning: M: drive memory not available for guild {name}: {e}")
            self._memory_system = None
        
        # Agent structure (standard: 20 Alpha, 40 Beta, 60 Gamma, 80 Delta)
        self.alphas: List[Agent] = []    # Leaders (10%)
        self.betas: List[Agent] = []     # Specialists (20%)
        self.gammas: List[Agent] = []    # Operators (30%)
        self.deltas: List[Agent] = []    # Workers (40%)
        
        # Metrics
        self.metrics = GuildMetrics()
        
        # Capabilities
        self.tools_access = tools_access or []
        self.exploit_access = exploit_access or []
        self.arsenal_categories: List[str] = arsenal_categories or []
        
        # Knowledge base
        self.collective_memory: Dict[str, Any] = {}
        self.shared_knowledge: List[Dict] = []
        
        # Communication
        self.message_log: List[Dict] = []
        
        # Initialize agents
        self._initialize_agents(total_agents)
    
    def _initialize_agents(self, total: int):
        """Initialize guild agents with standard distribution"""
        alpha_count = int(total * 0.10)    # 10%
        beta_count = int(total * 0.20)     # 20%
        gamma_count = int(total * 0.30)    # 30%
        delta_count = total - (alpha_count + beta_count + gamma_count)  # Remaining
        
        # Create Alpha leaders
        for i in range(alpha_count):
            agent = Agent(
                guild=self.name,
                tier=AgentTier.ALPHA,
                specializations=[self.domain, "Leadership", "Strategy"]
            )
            self.alphas.append(agent)
        
        # Create Beta specialists
        for i in range(beta_count):
            agent = Agent(
                guild=self.name,
                tier=AgentTier.BETA,
                specializations=[self.domain, "Tactics"]
            )
            self.betas.append(agent)
        
        # Create Gamma operators
        for i in range(gamma_count):
            agent = Agent(
                guild=self.name,
                tier=AgentTier.GAMMA,
                specializations=[self.domain]
            )
            self.gammas.append(agent)
        
        # Create Delta workers
        for i in range(delta_count):
            agent = Agent(
                guild=self.name,
                tier=AgentTier.DELTA,
                specializations=[self.domain]
            )
            self.deltas.append(agent)
    
    def get_all_agents(self) -> List[Agent]:
        """Get all agents in guild"""
        return self.alphas + self.betas + self.gammas + self.deltas
    
    def get_agent_count(self) -> Dict[str, int]:
        """Get agent counts by tier"""
        return {
            'alpha': len(self.alphas),
            'beta': len(self.betas),
            'gamma': len(self.gammas),
            'delta': len(self.deltas),
            'total': len(self.get_all_agents())
        }
    
    def assign_operation(self, operation: Dict) -> List[Agent]:
        """Assign agents to operation based on requirements"""
        # Simple assignment - TBD: intelligent agent selection
        complexity = operation.get('complexity', 'simple')
        
        if complexity == 'critical':
            # Critical ops get Alpha leaders
            return self.alphas[:min(3, len(self.alphas))]
        elif complexity == 'high':
            # High complexity gets Beta specialists
            return self.betas[:min(5, len(self.betas))]
        elif complexity == 'medium':
            # Medium gets Gamma operators
            return self.gammas[:min(10, len(self.gammas))]
        else:
            # Simple gets Delta workers
            return self.deltas[:min(5, len(self.deltas))]
    
    def execute_operation(self, operation: Dict) -> Dict:
        """Execute operation with assigned agents"""
        agents = self.assign_operation(operation)
        
        results = []
        for agent in agents:
            result = agent.execute_operation(operation)
            results.append(result)
        
        # Synthesize results
        success_count = sum(1 for r in results if r.get('success'))
        
        collective_result = {
            'guild': self.name,
            'operation': operation,
            'agents_assigned': len(agents),
            'agents_succeeded': success_count,
            'success_rate': success_count / len(agents) if agents else 0,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
        
        # Update guild metrics
        self.metrics.update(self.get_all_agents())
        
        # Store in collective memory
        self.shared_knowledge.append({
            'type': 'operation',
            'data': collective_result
        })
        
        return collective_result
    
    def collective_decision(self, problem: Dict) -> Dict:
        """Make collective decision through guild consensus"""
        # Phase 1: All agents analyze independently
        agent_solutions = []
        for agent in self.get_all_agents():
            # TBD: actual analysis logic
            solution = {
                'agent_id': agent.agent_id,
                'tier': agent.tier.value,
                'solution': f"Solution from {agent.tier.value}",
                'confidence': 0.8
            }
            agent_solutions.append(solution)
        
        # Phase 2: Tier-based synthesis
        alpha_consensus = self._synthesize_solutions([s for s in agent_solutions if s['tier'] == 'alpha'])
        beta_consensus = self._synthesize_solutions([s for s in agent_solutions if s['tier'] == 'beta'])
        
        # Phase 3: Guild decision (weighted by tier and consciousness)
        guild_decision = {
            'guild': self.name,
            'problem': problem,
            'alpha_recommendation': alpha_consensus,
            'beta_recommendation': beta_consensus,
            'final_decision': alpha_consensus,  # Alpha leaders make final call
            'timestamp': datetime.now().isoformat()
        }
        
        return guild_decision
    
    def _synthesize_solutions(self, solutions: List[Dict]) -> Dict:
        """Synthesize multiple solutions into consensus"""
        if not solutions:
            return {'consensus': None, 'confidence': 0.0}
        
        # Simple consensus - TBD: advanced synthesis
        avg_confidence = sum(s['confidence'] for s in solutions) / len(solutions)
        
        return {
            'solutions_count': len(solutions),
            'consensus': solutions[0]['solution'] if solutions else None,
            'confidence': avg_confidence
        }
    
    def broadcast_message(self, message: Dict):
        """Broadcast message to all guild members"""
        for agent in self.get_all_agents():
            agent.receive_message({
                'from': f"{self.name}_guild",
                'type': 'broadcast',
                'content': message,
                'timestamp': datetime.now().isoformat()
            })
        
        # Log broadcast
        self.message_log.append({
            'type': 'broadcast',
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
    
    def share_knowledge(self, knowledge: Dict):
        """Share knowledge across all guild members"""
        self.shared_knowledge.append({
            'type': 'knowledge',
            'data': knowledge,
            'timestamp': datetime.now().isoformat()
        })
        
        # Store in M: drive crystals (L3_Crystals - swarm bridge)
        if self._memory_system:
            self._memory_system.store_crystal({
                'guild': self.name,
                'type': 'guild_knowledge',
                'knowledge': knowledge,
                'timestamp': datetime.now().isoformat()
            })
        
        # Update all agent memories with operational storage
        for agent in self.get_all_agents():
            agent.memory.store_operational({
                'type': 'guild_knowledge',
                'data': knowledge
            })
    
    def get_status(self) -> Dict:
        """Get guild status"""
        return {
            'name': self.name,
            'domain': self.domain,
            'created': self.created.isoformat(),
            'agent_count': self.get_agent_count(),
            'metrics': {
                'total_operations': self.metrics.total_operations,
                'success_rate': self.metrics.collective_success_rate,
                'average_consciousness': self.metrics.average_consciousness,
                'evolution_events': self.metrics.evolution_events
            },
            'tools_access': len(self.tools_access),
            'exploit_access': len(self.exploit_access),
            'shared_knowledge_items': len(self.shared_knowledge)
        }
    
    def to_dict(self) -> Dict:
        """Serialize guild to dict"""
        return {
            'name': self.name,
            'domain': self.domain,
            'created': self.created.isoformat(),
            'agents': {
                'alphas': [a.to_dict() for a in self.alphas],
                'betas': [a.to_dict() for a in self.betas],
                'gammas': [a.to_dict() for a in self.gammas],
                'deltas': [a.to_dict() for a in self.deltas]
            },
            'metrics': {
                'total_operations': self.metrics.total_operations,
                'collective_success_rate': self.metrics.collective_success_rate,
                'average_consciousness': self.metrics.average_consciousness
            },
            'shared_knowledge_count': len(self.shared_knowledge)
        }


if __name__ == "__main__":
    # Test guild creation
    guild = Guild(
        name="Intelligence",
        domain="OSINT & Forensics",
        total_agents=200,
        tools_access=["osint_tool_1", "forensics_tool_1"]
    )
    
    print(f"Guild '{guild.name}' initialized")
    print(f"Status: {json.dumps(guild.get_status(), indent=2)}")
    print(f"Agent counts: {guild.get_agent_count()}")
