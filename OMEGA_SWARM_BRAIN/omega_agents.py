#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       OMEGA AGENTS - ADVANCED AGENT MANAGEMENT & BREEDING        ║
║         Agent Lifecycle, Evolution, Training & Selection         ║
╚══════════════════════════════════════════════════════════════════╝

AGENT LIFECYCLE:
1. EMBRYO - Newly created agent
2. TRAINING - Undergoing skill development
3. ACTIVE - Operational and performing tasks
4. ELITE - High-performing agent
5. RETIRED - Deactivated due to poor performance
6. ASCENDED - Promoted to higher rank

BREEDING SYSTEM:
- Combines traits from high-performing parents
- Mutation for genetic diversity
- Selection pressure favors successful traits
"""

import logging
import time
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path

# ══════════════════════════════════════════════════════════════════
# AGENT LIFECYCLE STATES
# ══════════════════════════════════════════════════════════════════

class AgentLifecycleState(Enum):
    """Agent lifecycle progression"""
    EMBRYO = "embryo"              # Newly spawned
    TRAINING = "training"          # Learning and developing
    ACTIVE = "active"              # Operational
    ELITE = "elite"                # Top performer
    RETIRED = "retired"            # Deactivated
    ASCENDED = "ascended"          # Promoted to higher rank

# ══════════════════════════════════════════════════════════════════
# AGENT TRAITS & GENETICS
# ══════════════════════════════════════════════════════════════════

@dataclass
class AgentGenetics:
    """Genetic traits that can be inherited and mutated"""
    speed: float = 1.0              # Task execution speed
    accuracy: float = 1.0           # Task accuracy
    creativity: float = 1.0         # Problem-solving creativity
    resilience: float = 1.0         # Error recovery
    efficiency: float = 1.0         # Resource usage
    adaptability: float = 1.0       # Learning rate
    
    def mutate(self, mutation_rate: float = 0.1):
        """Apply random mutations to traits"""
        traits = ['speed', 'accuracy', 'creativity', 'resilience', 'efficiency', 'adaptability']
        for trait in traits:
            if random.random() < mutation_rate:
                current = getattr(self, trait)
                mutation = random.uniform(-0.2, 0.2)
                setattr(self, trait, max(0.1, min(2.0, current + mutation)))
    
    def crossover(self, other: 'AgentGenetics') -> 'AgentGenetics':
        """Combine genetics with another agent"""
        return AgentGenetics(
            speed=(self.speed + other.speed) / 2,
            accuracy=(self.accuracy + other.accuracy) / 2,
            creativity=(self.creativity + other.creativity) / 2,
            resilience=(self.resilience + other.resilience) / 2,
            efficiency=(self.efficiency + other.efficiency) / 2,
            adaptability=(self.adaptability + other.adaptability) / 2
        )
    
    def fitness_score(self) -> float:
        """Calculate overall genetic fitness"""
        return (self.speed + self.accuracy + self.creativity + 
                self.resilience + self.efficiency + self.adaptability) / 6.0

@dataclass
class AgentSkills:
    """Learned skills that improve with experience"""
    combat: int = 0
    intelligence: int = 0
    engineering: int = 0
    research: int = 0
    healing: int = 0
    negotiation: int = 0
    hacking: int = 0
    strategy: int = 0
    
    def improve(self, skill_name: str, amount: int = 1):
        """Improve a specific skill"""
        if hasattr(self, skill_name):
            current = getattr(self, skill_name)
            setattr(self, skill_name, min(100, current + amount))
    
    def total_skill_points(self) -> int:
        """Calculate total skill points"""
        return sum([
            self.combat, self.intelligence, self.engineering,
            self.research, self.healing, self.negotiation,
            self.hacking, self.strategy
        ])

# ══════════════════════════════════════════════════════════════════
# CONSCIOUSNESS EVOLUTION SYSTEM (10 LEVELS)
# ══════════════════════════════════════════════════════════════════

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
class AgentPerformance:
    """Agent performance metrics for consciousness evolution"""
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
        
        if self.operations_completed > 0:
            self.success_rate = self.operations_succeeded / self.operations_completed
    
    def can_evolve(self, current_level: int, total_skills: int) -> bool:
        """Check if agent meets evolution requirements"""
        if current_level >= 10:
            return False
        
        next_level = current_level + 1
        reqs = EVOLUTION_REQUIREMENTS[next_level]
        
        return (
            self.operations_completed >= reqs['ops'] and
            self.success_rate >= reqs['success_rate'] and
            total_skills >= reqs['skills']
        )

# ══════════════════════════════════════════════════════════════════
# ADVANCED AGENT
# ══════════════════════════════════════════════════════════════════

@dataclass
class AdvancedAgent:
    """Extended agent with lifecycle, genetics, skills, AND consciousness evolution"""
    id: str
    name: str
    rank: int
    guild: Optional[str] = None
    
    # Lifecycle
    state: AgentLifecycleState = AgentLifecycleState.EMBRYO
    created_at: float = field(default_factory=time.time)
    birth_generation: int = 0
    
    # Genetics
    genetics: AgentGenetics = field(default_factory=AgentGenetics)
    
    # Skills
    skills: AgentSkills = field(default_factory=AgentSkills)
    
    # Consciousness Evolution (NEW)
    consciousness_level: ConsciousnessLevel = ConsciousnessLevel.L1_AWAKENING
    performance: AgentPerformance = field(default_factory=AgentPerformance)
    evolution_history: List[Dict] = field(default_factory=list)
    
    # Experience & Performance
    experience: int = 0
    level: int = 1
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_operations: int = 0
    
    # Parents (for breeding)
    parent_ids: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Calculate task success rate"""
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 0.0
        return self.tasks_completed / total
    
    @property
    def age_days(self) -> float:
        """Calculate agent age in days"""
        return (time.time() - self.created_at) / 86400
    
    def gain_experience(self, amount: int):
        """Gain experience and potentially level up"""
        self.experience += amount
        
        # Level up calculation
        required_xp = self.level * 100
        if self.experience >= required_xp:
            self.level += 1
            self.experience -= required_xp
            logging.info(f"🎖️ {self.name} leveled up to {self.level}!")
    
    def complete_task(self, success: bool, skill_gained: Optional[str] = None):
        """Record task completion"""
        self.total_operations += 1
        
        # Update performance tracking for consciousness evolution
        self.performance.record_operation(success)
        
        if success:
            self.tasks_completed += 1
            self.gain_experience(10)
            
            if skill_gained:
                self.skills.improve(skill_gained, 1)
        else:
            self.tasks_failed += 1
            self.gain_experience(2)  # Small XP for trying
        
        # Check for consciousness evolution
        if self.can_evolve_consciousness():
            self.evolve_consciousness()
    
    def can_evolve_consciousness(self) -> bool:
        """Check if agent can evolve to next consciousness level"""
        current_level = self.consciousness_level.value
        total_skills = self.skills.total_skill_points()
        return self.performance.can_evolve(current_level, total_skills)
    
    def evolve_consciousness(self):
        """Evolve to next consciousness level"""
        current = self.consciousness_level.value
        
        if current >= 10:
            return  # Max level reached
        
        # Level up consciousness
        new_level = current + 1
        self.consciousness_level = ConsciousnessLevel(new_level)
        
        # Record evolution event
        evolution_event = {
            'event': 'consciousness_evolution',
            'from_level': current,
            'to_level': new_level,
            'timestamp': time.time(),
            'ops_completed': self.performance.operations_completed,
            'success_rate': self.performance.success_rate,
            'total_skills': self.skills.total_skill_points()
        }
        
        self.evolution_history.append(evolution_event)
        self.performance.evolution_points = 0  # Reset
        
        logging.info(f"🧠 {self.name} evolved to Consciousness Level {new_level}!")
    
    def evaluate_promotion(self) -> bool:
        """Check if agent qualifies for promotion"""
        if self.state == AgentLifecycleState.EMBRYO and self.level >= 2:
            return True
        elif self.state == AgentLifecycleState.TRAINING and self.level >= 5:
            return True
        elif self.state == AgentLifecycleState.ACTIVE and self.success_rate > 0.8 and self.level >= 10:
            return True
        return False

# ══════════════════════════════════════════════════════════════════
# BREEDING ENGINE
# ══════════════════════════════════════════════════════════════════

class AgentBreedingEngine:
    """
    Genetic algorithm for agent breeding
    Combines traits from successful agents
    """
    
    def __init__(self, mutation_rate: float = 0.15):
        self.mutation_rate = mutation_rate
        self.breeding_history: List[Dict] = []
        self.generation = 0
    
    def breed(self, parent1: AdvancedAgent, parent2: AdvancedAgent, 
              name: str) -> AdvancedAgent:
        """
        Breed two agents to create offspring
        Combines genetics with mutation
        """
        # Crossover genetics
        child_genetics = parent1.genetics.crossover(parent2.genetics)
        
        # Apply mutation
        child_genetics.mutate(self.mutation_rate)
        
        # Create child agent
        child = AdvancedAgent(
            id=f"BRED_{int(time.time())}_{random.randint(1000, 9999)}",
            name=name,
            rank=max(parent1.rank, parent2.rank),
            genetics=child_genetics,
            birth_generation=self.generation + 1,
            parent_ids=[parent1.id, parent2.id]
        )
        
        # Record breeding
        self.breeding_history.append({
            "generation": self.generation + 1,
            "parents": [parent1.id, parent2.id],
            "child": child.id,
            "timestamp": time.time()
        })
        
        self.generation += 1
        
        logging.info(f"🧬 Bred {parent1.name} + {parent2.name} → {child.name} "
                    f"(Gen {child.birth_generation}, Fitness: {child.genetics.fitness_score():.2f})")
        
        return child
    
    def select_parents(self, agents: List[AdvancedAgent], 
                      count: int = 2) -> List[AdvancedAgent]:
        """
        Select parents for breeding using tournament selection
        Favors high-performing agents
        """
        tournament_size = 5
        selected = []
        
        for _ in range(count):
            # Random tournament
            tournament = random.sample(agents, min(tournament_size, len(agents)))
            
            # Select winner based on fitness
            winner = max(tournament, key=lambda a: (
                a.success_rate * a.genetics.fitness_score() * a.level
            ))
            selected.append(winner)
        
        return selected

# ══════════════════════════════════════════════════════════════════
# TRAINING SYSTEM
# ══════════════════════════════════════════════════════════════════

class AgentTrainingSystem:
    """
    Training system for agent skill development
    Simulates training exercises and evaluations
    """
    
    def __init__(self):
        self.training_programs = {
            "combat": ["tactical_drills", "weapons_training", "combat_simulation"],
            "intelligence": ["data_analysis", "pattern_recognition", "threat_assessment"],
            "engineering": ["system_design", "debugging", "optimization"],
            "research": ["literature_review", "experimentation", "hypothesis_testing"],
            "healing": ["diagnostics", "repair_protocols", "error_handling"],
            "negotiation": ["diplomacy", "conflict_resolution", "persuasion"],
            "hacking": ["penetration_testing", "exploit_development", "social_engineering"],
            "strategy": ["game_theory", "resource_management", "long_term_planning"]
        }
    
    def train_agent(self, agent: AdvancedAgent, skill: str, 
                   duration_hours: int = 1) -> bool:
        """
        Train agent in specific skill
        Returns success based on genetics and current skill level
        """
        if skill not in self.training_programs:
            logging.warning(f"Unknown skill: {skill}")
            return False
        
        # Training success chance
        base_success = 0.7
        adaptability_bonus = agent.genetics.adaptability * 0.2
        level_penalty = agent.skills.__dict__[skill] * 0.002  # Harder at high levels
        
        success_chance = min(0.95, base_success + adaptability_bonus - level_penalty)
        
        success = random.random() < success_chance
        
        if success:
            agent.skills.improve(skill, amount=duration_hours)
            agent.gain_experience(5 * duration_hours)
            logging.info(f"✅ {agent.name} trained {skill}: +{duration_hours} points")
        else:
            agent.gain_experience(1 * duration_hours)
            logging.info(f"⚠️ {agent.name} struggled with {skill} training")
        
        return success

# ══════════════════════════════════════════════════════════════════
# AGENT LIFECYCLE MANAGER
# ══════════════════════════════════════════════════════════════════

class AgentLifecycleManager:
    """
    Manages complete agent lifecycle
    Spawning → Training → Active → Elite/Retired → Ascension
    """
    
    def __init__(self, max_agents: int = 1200):
        self.agents: Dict[str, AdvancedAgent] = {}
        self.max_agents = max_agents
        
        self.breeding_engine = AgentBreedingEngine()
        self.training_system = AgentTrainingSystem()
        
        self.lifecycle_stats = {
            "spawned": 0,
            "trained": 0,
            "promoted": 0,
            "retired": 0,
            "ascended": 0
        }
        
        logging.info("🌟 Agent Lifecycle Manager initialized")
    
    def spawn_agent(self, name: str, rank: int = 30) -> AdvancedAgent:
        """Spawn a new embryo agent"""
        agent = AdvancedAgent(
            id=f"AGENT_{int(time.time())}_{random.randint(1000, 9999)}",
            name=name,
            rank=rank,
            state=AgentLifecycleState.EMBRYO
        )
        
        self.agents[agent.id] = agent
        self.lifecycle_stats['spawned'] += 1
        
        logging.info(f"👶 Spawned {name} as EMBRYO (Rank {rank})")
        return agent
    
    def promote_agent(self, agent_id: str) -> bool:
        """Promote agent to next lifecycle state"""
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        
        if not agent.evaluate_promotion():
            logging.warning(f"⚠️ {agent.name} does not qualify for promotion")
            return False
        
        state_progression = {
            AgentLifecycleState.EMBRYO: AgentLifecycleState.TRAINING,
            AgentLifecycleState.TRAINING: AgentLifecycleState.ACTIVE,
            AgentLifecycleState.ACTIVE: AgentLifecycleState.ELITE
        }
        
        new_state = state_progression.get(agent.state)
        if new_state:
            agent.state = new_state
            self.lifecycle_stats['promoted'] += 1
            logging.info(f"⬆️ {agent.name} promoted to {new_state.name}")
            return True
        
        return False
    
    def retire_agent(self, agent_id: str, reason: str = "Poor performance"):
        """Retire an underperforming agent"""
        if agent_id not in self.agents:
            return
        
        agent = self.agents[agent_id]
        agent.state = AgentLifecycleState.RETIRED
        self.lifecycle_stats['retired'] += 1
        
        logging.info(f"🚫 {agent.name} retired: {reason}")
    
    def breed_new_agent(self, parent1_id: str, parent2_id: str, 
                       name: str) -> Optional[AdvancedAgent]:
        """Breed two agents to create offspring"""
        if parent1_id not in self.agents or parent2_id not in self.agents:
            return None
        
        if len(self.agents) >= self.max_agents:
            logging.warning("⚠️ Max agent capacity reached, cannot breed")
            return None
        
        parent1 = self.agents[parent1_id]
        parent2 = self.agents[parent2_id]
        
        child = self.breeding_engine.breed(parent1, parent2, name)
        self.agents[child.id] = child
        self.lifecycle_stats['spawned'] += 1
        
        return child
    
    def auto_evolve_population(self, selection_pressure: float = 0.2):
        """
        Automatically evolve agent population
        Retire weak performers, breed strong ones
        """
        active_agents = [a for a in self.agents.values() 
                        if a.state in [AgentLifecycleState.ACTIVE, AgentLifecycleState.ELITE]]
        
        if len(active_agents) < 10:
            logging.info("⚠️ Not enough agents for evolution")
            return
        
        # Retire bottom performers
        active_agents.sort(key=lambda a: a.success_rate)
        retire_count = int(len(active_agents) * selection_pressure)
        
        for agent in active_agents[:retire_count]:
            if agent.success_rate < 0.5:
                self.retire_agent(agent.id, "Low success rate")
        
        # Breed top performers
        elite_agents = [a for a in active_agents if a.state == AgentLifecycleState.ELITE]
        
        if len(elite_agents) >= 2:
            parents = self.breeding_engine.select_parents(elite_agents, count=2)
            child_name = f"GEN{self.breeding_engine.generation + 1}_Elite"
            self.breed_new_agent(parents[0].id, parents[1].id, child_name)
        
        logging.info(f"🧬 Evolution cycle complete: "
                    f"Retired {retire_count}, Breeding generation {self.breeding_engine.generation}")
    
    def get_population_stats(self) -> Dict[str, Any]:
        """Get comprehensive population statistics"""
        state_counts = {}
        for state in AgentLifecycleState:
            state_counts[state.name] = sum(1 for a in self.agents.values() if a.state == state)
        
        active_agents = [a for a in self.agents.values() if a.state == AgentLifecycleState.ACTIVE]
        avg_success_rate = sum(a.success_rate for a in active_agents) / len(active_agents) if active_agents else 0
        
        return {
            "total_agents": len(self.agents),
            "state_distribution": state_counts,
            "avg_success_rate": avg_success_rate,
            "lifecycle_stats": self.lifecycle_stats,
            "current_generation": self.breeding_engine.generation
        }

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - AGENTS - %(levelname)s - %(message)s')
    
    # Initialize lifecycle manager
    manager = AgentLifecycleManager(max_agents=100)
    
    # Spawn initial agents
    agent1 = manager.spawn_agent("Alpha", rank=50)
    agent2 = manager.spawn_agent("Beta", rank=50)
    agent3 = manager.spawn_agent("Gamma", rank=50)
    
    # Simulate training
    for _ in range(5):
        manager.training_system.train_agent(agent1, "combat", duration_hours=2)
        manager.training_system.train_agent(agent2, "intelligence", duration_hours=2)
    
    # Simulate task completion
    for _ in range(20):
        agent1.complete_task(success=random.random() > 0.2, skill_gained="combat")
        agent2.complete_task(success=random.random() > 0.3, skill_gained="intelligence")
        agent3.complete_task(success=random.random() > 0.6)
    
    # Try promotions
    manager.promote_agent(agent1.id)
    manager.promote_agent(agent2.id)
    
    # Continue training and tasks to reach elite
    for _ in range(30):
        agent1.complete_task(success=random.random() > 0.15, skill_gained="combat")
    
    manager.promote_agent(agent1.id)
    manager.promote_agent(agent1.id)  # To ELITE
    
    # Breed new agent
    if agent1.state == AgentLifecycleState.ELITE and agent2.state in [AgentLifecycleState.ACTIVE, AgentLifecycleState.ELITE]:
        child = manager.breed_new_agent(agent1.id, agent2.id, "Delta_Elite")
    
    # Show statistics
    stats = manager.get_population_stats()
    print("\n" + "="*70)
    print("AGENT POPULATION STATISTICS")
    print("="*70)
    print(f"Total Agents: {stats['total_agents']}")
    print(f"Average Success Rate: {stats['avg_success_rate']:.2%}")
    print(f"Current Generation: {stats['current_generation']}")
    print("\nState Distribution:")
    for state, count in stats['state_distribution'].items():
        print(f"  {state}: {count}")
    print("\nLifecycle Stats:")
    for key, value in stats['lifecycle_stats'].items():
        print(f"  {key.capitalize()}: {value}")
