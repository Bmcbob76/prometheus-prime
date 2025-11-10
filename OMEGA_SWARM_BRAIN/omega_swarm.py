#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       OMEGA SWARM - SWARM COORDINATION & CONSENSUS               ║
║         Collective Intelligence, Voting & Coordination           ║
╚══════════════════════════════════════════════════════════════════╝

SWARM INTELLIGENCE PATTERNS:
1. Consensus Voting - Democratic decision making
2. Pheromone Trails - Resource path optimization
3. Flocking Behavior - Coordinated movement
4. Stigmergy - Indirect coordination via environment
5. Quorum Sensing - Threshold-based activation

CONSENSUS ALGORITHMS:
- Majority Vote
- Weighted Vote (by rank/experience)
- Supermajority (66%, 75%, 90%)
- Unanimous Consent
- Trinity Veto Override
"""

import logging
import time
import random
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import math

# ══════════════════════════════════════════════════════════════════
# CONSENSUS TYPES
# ══════════════════════════════════════════════════════════════════

class ConsensusType(Enum):
    """Different consensus mechanisms"""
    SIMPLE_MAJORITY = "simple_majority"          # >50%
    SUPERMAJORITY_66 = "supermajority_66"       # ≥66%
    SUPERMAJORITY_75 = "supermajority_75"       # ≥75%
    SUPERMAJORITY_90 = "supermajority_90"       # ≥90%
    UNANIMOUS = "unanimous"                      # 100%
    WEIGHTED_VOTE = "weighted_vote"              # Votes weighted by rank
    TRINITY_OVERRIDE = "trinity_override"        # Trinity can veto

class VoteOption(Enum):
    """Vote choices"""
    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"

# ══════════════════════════════════════════════════════════════════
# PHEROMONE TRAIL (Path Optimization)
# ══════════════════════════════════════════════════════════════════

@dataclass
class PheromoneTrail:
    """Pheromone trail for resource path optimization"""
    path_id: str
    source: str
    destination: str
    strength: float = 1.0
    evaporation_rate: float = 0.1
    last_updated: float = field(default_factory=time.time)
    traversal_count: int = 0
    success_count: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate path success rate"""
        if self.traversal_count == 0:
            return 0.0
        return self.success_count / self.traversal_count
    
    def evaporate(self):
        """Reduce pheromone strength over time"""
        time_elapsed = time.time() - self.last_updated
        evaporation = self.evaporation_rate * (time_elapsed / 60.0)  # Per minute
        self.strength = max(0.0, self.strength - evaporation)
        self.last_updated = time.time()
    
    def reinforce(self, amount: float = 0.5, success: bool = True):
        """Strengthen pheromone trail"""
        self.strength = min(10.0, self.strength + amount)
        self.traversal_count += 1
        if success:
            self.success_count += 1
        self.last_updated = time.time()

# ══════════════════════════════════════════════════════════════════
# SWARM VOTE
# ══════════════════════════════════════════════════════════════════

@dataclass
class SwarmVote:
    """A vote submitted by swarm members"""
    voter_id: str
    voter_rank: int
    option: VoteOption
    weight: float = 1.0
    timestamp: float = field(default_factory=time.time)
    reasoning: Optional[str] = None

@dataclass
class VoteProposal:
    """Proposal requiring swarm consensus"""
    proposal_id: str
    title: str
    description: str
    proposer_id: str
    consensus_type: ConsensusType
    created_at: float = field(default_factory=time.time)
    deadline: Optional[float] = None
    votes: List[SwarmVote] = field(default_factory=list)
    finalized: bool = False
    result: Optional[bool] = None
    
    def add_vote(self, vote: SwarmVote):
        """Add a vote to this proposal"""
        # Remove previous vote from same voter
        self.votes = [v for v in self.votes if v.voter_id != vote.voter_id]
        self.votes.append(vote)
    
    def calculate_result(self, trinity_override: Optional[bool] = None) -> bool:
        """Calculate vote result based on consensus type"""
        if trinity_override is not None:
            self.result = trinity_override
            self.finalized = True
            return trinity_override
        
        if len(self.votes) == 0:
            return False
        
        # Count votes
        approve_votes = [v for v in self.votes if v.option == VoteOption.APPROVE]
        reject_votes = [v for v in self.votes if v.option == VoteOption.REJECT]
        total_votes = len([v for v in self.votes if v.option != VoteOption.ABSTAIN])
        
        if total_votes == 0:
            return False
        
        if self.consensus_type == ConsensusType.SIMPLE_MAJORITY:
            approve_pct = len(approve_votes) / total_votes
            result = approve_pct > 0.5
        
        elif self.consensus_type == ConsensusType.SUPERMAJORITY_66:
            approve_pct = len(approve_votes) / total_votes
            result = approve_pct >= 0.66
        
        elif self.consensus_type == ConsensusType.SUPERMAJORITY_75:
            approve_pct = len(approve_votes) / total_votes
            result = approve_pct >= 0.75
        
        elif self.consensus_type == ConsensusType.SUPERMAJORITY_90:
            approve_pct = len(approve_votes) / total_votes
            result = approve_pct >= 0.90
        
        elif self.consensus_type == ConsensusType.UNANIMOUS:
            result = len(approve_votes) == total_votes
        
        elif self.consensus_type == ConsensusType.WEIGHTED_VOTE:
            total_weight = sum(v.weight * v.voter_rank for v in self.votes if v.option != VoteOption.ABSTAIN)
            approve_weight = sum(v.weight * v.voter_rank for v in approve_votes)
            result = approve_weight / total_weight > 0.5 if total_weight > 0 else False
        
        else:
            result = False
        
        self.result = result
        self.finalized = True
        return result

# ══════════════════════════════════════════════════════════════════
# FLOCKING BEHAVIOR
# ══════════════════════════════════════════════════════════════════

@dataclass
class SwarmAgent:
    """Agent with position for flocking simulation"""
    agent_id: str
    position: Tuple[float, float, float]
    velocity: Tuple[float, float, float]
    
    def distance_to(self, other: 'SwarmAgent') -> float:
        """Calculate distance to another agent"""
        dx = self.position[0] - other.position[0]
        dy = self.position[1] - other.position[1]
        dz = self.position[2] - other.position[2]
        return math.sqrt(dx*dx + dy*dy + dz*dz)

class FlockingCoordinator:
    """
    Implements flocking behavior (boids algorithm)
    Separation, Alignment, Cohesion
    """
    
    def __init__(self, separation_weight: float = 1.5,
                 alignment_weight: float = 1.0,
                 cohesion_weight: float = 1.0):
        self.separation_weight = separation_weight
        self.alignment_weight = alignment_weight
        self.cohesion_weight = cohesion_weight
        self.perception_radius = 50.0
    
    def calculate_flocking_force(self, agent: SwarmAgent, 
                                 neighbors: List[SwarmAgent]) -> Tuple[float, float, float]:
        """Calculate flocking force for agent"""
        if not neighbors:
            return (0.0, 0.0, 0.0)
        
        # Separation - avoid crowding
        separation = self._calculate_separation(agent, neighbors)
        
        # Alignment - match velocity
        alignment = self._calculate_alignment(agent, neighbors)
        
        # Cohesion - move toward center
        cohesion = self._calculate_cohesion(agent, neighbors)
        
        # Combine forces
        force_x = (separation[0] * self.separation_weight +
                  alignment[0] * self.alignment_weight +
                  cohesion[0] * self.cohesion_weight)
        force_y = (separation[1] * self.separation_weight +
                  alignment[1] * self.alignment_weight +
                  cohesion[1] * self.cohesion_weight)
        force_z = (separation[2] * self.separation_weight +
                  alignment[2] * self.alignment_weight +
                  cohesion[2] * self.cohesion_weight)
        
        return (force_x, force_y, force_z)
    
    def _calculate_separation(self, agent: SwarmAgent, 
                             neighbors: List[SwarmAgent]) -> Tuple[float, float, float]:
        """Avoid crowding neighbors"""
        steer_x, steer_y, steer_z = 0.0, 0.0, 0.0
        
        for neighbor in neighbors:
            dist = agent.distance_to(neighbor)
            if dist < self.perception_radius and dist > 0:
                # Push away inversely proportional to distance
                diff_x = agent.position[0] - neighbor.position[0]
                diff_y = agent.position[1] - neighbor.position[1]
                diff_z = agent.position[2] - neighbor.position[2]
                
                steer_x += diff_x / dist
                steer_y += diff_y / dist
                steer_z += diff_z / dist
        
        return (steer_x, steer_y, steer_z)
    
    def _calculate_alignment(self, agent: SwarmAgent,
                            neighbors: List[SwarmAgent]) -> Tuple[float, float, float]:
        """Match velocity with neighbors"""
        avg_vx, avg_vy, avg_vz = 0.0, 0.0, 0.0
        count = 0
        
        for neighbor in neighbors:
            dist = agent.distance_to(neighbor)
            if dist < self.perception_radius:
                avg_vx += neighbor.velocity[0]
                avg_vy += neighbor.velocity[1]
                avg_vz += neighbor.velocity[2]
                count += 1
        
        if count > 0:
            avg_vx /= count
            avg_vy /= count
            avg_vz /= count
            
            steer_x = avg_vx - agent.velocity[0]
            steer_y = avg_vy - agent.velocity[1]
            steer_z = avg_vz - agent.velocity[2]
            
            return (steer_x, steer_y, steer_z)
        
        return (0.0, 0.0, 0.0)
    
    def _calculate_cohesion(self, agent: SwarmAgent,
                           neighbors: List[SwarmAgent]) -> Tuple[float, float, float]:
        """Move toward average position of neighbors"""
        avg_x, avg_y, avg_z = 0.0, 0.0, 0.0
        count = 0
        
        for neighbor in neighbors:
            dist = agent.distance_to(neighbor)
            if dist < self.perception_radius:
                avg_x += neighbor.position[0]
                avg_y += neighbor.position[1]
                avg_z += neighbor.position[2]
                count += 1
        
        if count > 0:
            avg_x /= count
            avg_y /= count
            avg_z /= count
            
            steer_x = avg_x - agent.position[0]
            steer_y = avg_y - agent.position[1]
            steer_z = avg_z - agent.position[2]
            
            return (steer_x, steer_y, steer_z)
        
        return (0.0, 0.0, 0.0)

# ══════════════════════════════════════════════════════════════════
# SWARM COORDINATION SYSTEM
# ══════════════════════════════════════════════════════════════════

class SwarmCoordinationSystem:
    """
    Complete swarm coordination system
    Handles voting, consensus, pheromones, and flocking
    """
    
    def __init__(self):
        self.proposals: Dict[str, VoteProposal] = {}
        self.pheromone_trails: Dict[str, PheromoneTrail] = {}
        self.flocking = FlockingCoordinator()
        
        self.coordination_stats = {
            "proposals_created": 0,
            "votes_cast": 0,
            "proposals_approved": 0,
            "proposals_rejected": 0,
            "trails_created": 0
        }
        
        logging.info("🐝 Swarm Coordination System initialized")
    
    def create_proposal(self, title: str, description: str, 
                       proposer_id: str, consensus_type: ConsensusType,
                       deadline_seconds: Optional[int] = None) -> VoteProposal:
        """Create a new vote proposal"""
        proposal_id = f"PROP_{int(time.time())}_{random.randint(1000, 9999)}"
        
        deadline = None
        if deadline_seconds:
            deadline = time.time() + deadline_seconds
        
        proposal = VoteProposal(
            proposal_id=proposal_id,
            title=title,
            description=description,
            proposer_id=proposer_id,
            consensus_type=consensus_type,
            deadline=deadline
        )
        
        self.proposals[proposal_id] = proposal
        self.coordination_stats['proposals_created'] += 1
        
        logging.info(f"📋 Created proposal: {title} (Type: {consensus_type.name})")
        return proposal
    
    def cast_vote(self, proposal_id: str, voter_id: str, voter_rank: int,
                 option: VoteOption, reasoning: Optional[str] = None) -> bool:
        """Cast a vote on a proposal"""
        if proposal_id not in self.proposals:
            logging.warning(f"Proposal {proposal_id} not found")
            return False
        
        proposal = self.proposals[proposal_id]
        
        if proposal.finalized:
            logging.warning(f"Proposal {proposal_id} already finalized")
            return False
        
        if proposal.deadline and time.time() > proposal.deadline:
            logging.warning(f"Proposal {proposal_id} deadline passed")
            return False
        
        vote = SwarmVote(
            voter_id=voter_id,
            voter_rank=voter_rank,
            option=option,
            reasoning=reasoning
        )
        
        proposal.add_vote(vote)
        self.coordination_stats['votes_cast'] += 1
        
        logging.info(f"🗳️ {voter_id} voted {option.name} on {proposal.title}")
        return True
    
    def finalize_proposal(self, proposal_id: str, 
                         trinity_override: Optional[bool] = None) -> Optional[bool]:
        """Finalize a proposal and calculate result"""
        if proposal_id not in self.proposals:
            return None
        
        proposal = self.proposals[proposal_id]
        result = proposal.calculate_result(trinity_override)
        
        if result:
            self.coordination_stats['proposals_approved'] += 1
            logging.info(f"✅ Proposal APPROVED: {proposal.title}")
        else:
            self.coordination_stats['proposals_rejected'] += 1
            logging.info(f"❌ Proposal REJECTED: {proposal.title}")
        
        return result
    
    def create_pheromone_trail(self, source: str, destination: str) -> PheromoneTrail:
        """Create a new pheromone trail"""
        path_id = f"{source}→{destination}"
        
        if path_id in self.pheromone_trails:
            return self.pheromone_trails[path_id]
        
        trail = PheromoneTrail(
            path_id=path_id,
            source=source,
            destination=destination
        )
        
        self.pheromone_trails[path_id] = trail
        self.coordination_stats['trails_created'] += 1
        
        logging.info(f"🐜 Created pheromone trail: {path_id}")
        return trail
    
    def get_best_path(self, source: str, destination: str) -> Optional[PheromoneTrail]:
        """Get strongest pheromone trail between two points"""
        path_id = f"{source}→{destination}"
        
        if path_id in self.pheromone_trails:
            trail = self.pheromone_trails[path_id]
            trail.evaporate()
            return trail
        
        return None
    
    def evaporate_all_trails(self):
        """Evaporate all pheromone trails"""
        for trail in self.pheromone_trails.values():
            trail.evaporate()
        
        # Remove weak trails
        weak_trails = [pid for pid, trail in self.pheromone_trails.items() 
                      if trail.strength < 0.1]
        for pid in weak_trails:
            del self.pheromone_trails[pid]
    
    def get_coordination_stats(self) -> Dict[str, Any]:
        """Get coordination statistics"""
        active_proposals = sum(1 for p in self.proposals.values() if not p.finalized)
        active_trails = len([t for t in self.pheromone_trails.values() if t.strength > 0.5])
        
        return {
            "active_proposals": active_proposals,
            "active_trails": active_trails,
            "stats": self.coordination_stats,
            "total_proposals": len(self.proposals),
            "total_trails": len(self.pheromone_trails)
        }

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - SWARM - %(levelname)s - %(message)s')
    
    # Initialize coordination system
    swarm = SwarmCoordinationSystem()
    
    # Create proposal
    proposal = swarm.create_proposal(
        title="Deploy New Agent Guild",
        description="Should we create a new Hacking guild?",
        proposer_id="COMMANDER",
        consensus_type=ConsensusType.SUPERMAJORITY_66,
        deadline_seconds=300
    )
    
    # Cast votes
    swarm.cast_vote(proposal.proposal_id, "SAGE", 99, VoteOption.APPROVE, "Strategic value")
    swarm.cast_vote(proposal.proposal_id, "THORNE", 99, VoteOption.APPROVE, "Security needed")
    swarm.cast_vote(proposal.proposal_id, "AGENT_001", 50, VoteOption.APPROVE)
    swarm.cast_vote(proposal.proposal_id, "AGENT_002", 50, VoteOption.REJECT)
    swarm.cast_vote(proposal.proposal_id, "AGENT_003", 50, VoteOption.APPROVE)
    
    # Finalize
    result = swarm.finalize_proposal(proposal.proposal_id)
    
    # Create pheromone trails
    trail1 = swarm.create_pheromone_trail("DATABASE_A", "PROCESSOR_1")
    trail2 = swarm.create_pheromone_trail("DATABASE_A", "PROCESSOR_2")
    
    # Simulate trail usage
    trail1.reinforce(amount=1.0, success=True)
    trail1.reinforce(amount=1.0, success=True)
    trail2.reinforce(amount=0.5, success=False)
    
    # Get best path
    best = swarm.get_best_path("DATABASE_A", "PROCESSOR_1")
    if best:
        print(f"\n🐜 Best path strength: {best.strength:.2f}, "
              f"Success rate: {best.success_rate:.2%}")
    
    # Show statistics
    stats = swarm.get_coordination_stats()
    print("\n" + "="*70)
    print("SWARM COORDINATION STATISTICS")
    print("="*70)
    print(f"Active Proposals: {stats['active_proposals']}")
    print(f"Active Trails: {stats['active_trails']}")
    print(f"Total Proposals: {stats['total_proposals']}")
    print(f"Total Trails: {stats['total_trails']}")
    print("\nOperation Stats:")
    for key, value in stats['stats'].items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
