#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║    OMEGA COMPETITIVE - HEPHAESTION COMPETITIVE SYSTEM            ║
║       Agent Competition, Ranking, Scoring & Evolution            ║
╚══════════════════════════════════════════════════════════════════╝

HEPHAESTION COMPETITIVE FORGE:
- Agent vs Agent competitions
- Performance scoring & ranking
- Breakthrough detection
- Evolution pressure
- Skill tournaments
- Guild competitions
- Leaderboards & rewards
"""

import logging
import time
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import json

# ══════════════════════════════════════════════════════════════════
# COMPETITION TYPES
# ══════════════════════════════════════════════════════════════════

class CompetitionType(Enum):
    """Types of competitive events"""
    SKILL_DUEL = "skill_duel"              # 1v1 skill competition
    TEAM_BATTLE = "team_battle"            # Team vs team
    GUILD_WAR = "guild_war"                # Guild vs guild
    SURVIVAL = "survival"                  # Last agent standing
    PROBLEM_SOLVING = "problem_solving"    # Problem-solving race
    RESOURCE_GATHERING = "resource_gathering"  # Resource collection
    INNOVATION = "innovation"              # Creative breakthrough
    ENDURANCE = "endurance"                # Long-duration challenge

# ══════════════════════════════════════════════════════════════════
# SCORING METRICS
# ══════════════════════════════════════════════════════════════════

@dataclass
class CompetitionScore:
    """Individual competition score"""
    agent_id: str
    agent_name: str
    
    # Performance metrics
    speed_score: float = 0.0          # Task completion speed
    accuracy_score: float = 0.0       # Accuracy of solution
    efficiency_score: float = 0.0     # Resource efficiency
    creativity_score: float = 0.0     # Creative problem solving
    resilience_score: float = 0.0     # Error recovery
    collaboration_score: float = 0.0  # Team performance
    
    # Calculated scores
    total_score: float = 0.0
    rank: int = 0
    
    # Metadata
    timestamp: float = field(default_factory=time.time)
    competition_id: str = ""
    
    def calculate_total(self, weights: Dict[str, float] = None):
        """Calculate total weighted score"""
        if weights is None:
            weights = {
                "speed": 1.0,
                "accuracy": 1.5,
                "efficiency": 1.0,
                "creativity": 1.2,
                "resilience": 1.3,
                "collaboration": 0.8
            }
        
        self.total_score = (
            self.speed_score * weights.get("speed", 1.0) +
            self.accuracy_score * weights.get("accuracy", 1.0) +
            self.efficiency_score * weights.get("efficiency", 1.0) +
            self.creativity_score * weights.get("creativity", 1.0) +
            self.resilience_score * weights.get("resilience", 1.0) +
            self.collaboration_score * weights.get("collaboration", 1.0)
        )
        
        return self.total_score
    
    def is_breakthrough(self) -> bool:
        """Check if score represents a breakthrough (>100)"""
        return self.total_score > 100.0
    
    def get_breakthrough_bonus(self) -> float:
        """Calculate breakthrough bonus for scores >100"""
        if self.is_breakthrough():
            return (self.total_score - 100.0) * 2.0  # 2x multiplier on excess
        return 0.0

# ══════════════════════════════════════════════════════════════════
# AGENT COMPETITIVE PROFILE
# ══════════════════════════════════════════════════════════════════

@dataclass
class CompetitiveProfile:
    """Agent's competitive history and statistics"""
    agent_id: str
    agent_name: str
    
    # Overall stats
    elo_rating: float = 1500.0
    competitions_entered: int = 0
    competitions_won: int = 0
    competitions_lost: int = 0
    
    # Performance history
    best_score: float = 0.0
    average_score: float = 0.0
    recent_scores: List[float] = field(default_factory=list)
    
    # Skill ratings (0-100)
    skill_ratings: Dict[str, float] = field(default_factory=dict)
    
    # Awards & achievements
    breakthrough_count: int = 0
    innovation_count: int = 0
    awards: List[str] = field(default_factory=list)
    
    # Ranking
    global_rank: int = 0
    guild_rank: int = 0
    
    @property
    def win_rate(self) -> float:
        """Calculate win rate"""
        total = self.competitions_won + self.competitions_lost
        if total == 0:
            return 0.0
        return self.competitions_won / total
    
    def update_elo(self, opponent_elo: float, result: float, k: float = 32.0):
        """
        Update ELO rating after competition
        result: 1.0 (win), 0.5 (draw), 0.0 (loss)
        """
        expected = 1.0 / (1.0 + 10.0 ** ((opponent_elo - self.elo_rating) / 400.0))
        self.elo_rating += k * (result - expected)
    
    def record_score(self, score: float):
        """Record a competition score"""
        self.recent_scores.append(score)
        if len(self.recent_scores) > 20:
            self.recent_scores.pop(0)
        
        if score > self.best_score:
            self.best_score = score
        
        self.average_score = sum(self.recent_scores) / len(self.recent_scores)

# ══════════════════════════════════════════════════════════════════
# COMPETITION EVENT
# ══════════════════════════════════════════════════════════════════

@dataclass
class CompetitionEvent:
    """Individual competition event"""
    competition_id: str
    competition_type: CompetitionType
    title: str
    description: str
    
    # Participants
    participants: List[str] = field(default_factory=list)
    team_assignments: Dict[str, str] = field(default_factory=dict)
    
    # Scores
    scores: Dict[str, CompetitionScore] = field(default_factory=dict)
    
    # Status
    status: str = "pending"  # pending, active, completed
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    # Results
    winner_id: Optional[str] = None
    rankings: List[Tuple[str, float]] = field(default_factory=list)
    
    # Rewards
    rewards: Dict[str, Any] = field(default_factory=dict)
    
    def add_participant(self, agent_id: str, agent_name: str):
        """Add participant to competition"""
        if agent_id not in self.participants:
            self.participants.append(agent_id)
            self.scores[agent_id] = CompetitionScore(
                agent_id=agent_id,
                agent_name=agent_name,
                competition_id=self.competition_id
            )
    
    def record_performance(self, agent_id: str, metrics: Dict[str, float]):
        """Record agent performance metrics"""
        if agent_id not in self.scores:
            return
        
        score = self.scores[agent_id]
        score.speed_score = metrics.get("speed", 0.0)
        score.accuracy_score = metrics.get("accuracy", 0.0)
        score.efficiency_score = metrics.get("efficiency", 0.0)
        score.creativity_score = metrics.get("creativity", 0.0)
        score.resilience_score = metrics.get("resilience", 0.0)
        score.collaboration_score = metrics.get("collaboration", 0.0)
        score.calculate_total()
    
    def finalize(self):
        """Finalize competition and determine winners"""
        self.status = "completed"
        self.end_time = time.time()
        
        # Calculate rankings
        sorted_scores = sorted(
            self.scores.items(),
            key=lambda x: x[1].total_score,
            reverse=True
        )
        
        self.rankings = [(agent_id, score.total_score) for agent_id, score in sorted_scores]
        
        # Assign ranks
        for rank, (agent_id, score_val) in enumerate(self.rankings, 1):
            self.scores[agent_id].rank = rank
        
        # Determine winner
        if self.rankings:
            self.winner_id = self.rankings[0][0]

# ══════════════════════════════════════════════════════════════════
# HEPHAESTION COMPETITIVE SYSTEM
# ══════════════════════════════════════════════════════════════════

class HephaestionCompetitiveSystem:
    """
    Complete competitive system for agent evolution
    Manages competitions, scoring, ranking, and breakthroughs
    """
    
    def __init__(self):
        self.profiles: Dict[str, CompetitiveProfile] = {}
        self.competitions: Dict[str, CompetitionEvent] = {}
        
        # Leaderboards
        self.global_leaderboard: List[Tuple[str, float]] = []
        self.guild_leaderboards: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        
        # Statistics
        self.stats = {
            "total_competitions": 0,
            "active_competitions": 0,
            "total_participants": 0,
            "breakthroughs_detected": 0,
            "innovations_recorded": 0
        }
        
        # Breakthrough thresholds
        self.breakthrough_threshold = 95.0  # Score above this = breakthrough
        self.innovation_threshold = 90.0    # Score above this = innovation
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║       HEPHAESTION COMPETITIVE SYSTEM INITIALIZED             ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
    
    def register_agent(self, agent_id: str, agent_name: str, guild: Optional[str] = None):
        """Register agent in competitive system"""
        if agent_id not in self.profiles:
            self.profiles[agent_id] = CompetitiveProfile(
                agent_id=agent_id,
                agent_name=agent_name
            )
            self.stats['total_participants'] += 1
            logging.info(f"⚔️ Registered {agent_name} in competitive system")
    
    def create_competition(self, comp_type: CompetitionType, title: str,
                          description: str) -> CompetitionEvent:
        """Create a new competition event"""
        comp_id = f"COMP_{int(time.time())}_{random.randint(1000, 9999)}"
        
        competition = CompetitionEvent(
            competition_id=comp_id,
            competition_type=comp_type,
            title=title,
            description=description
        )
        
        self.competitions[comp_id] = competition
        self.stats['total_competitions'] += 1
        self.stats['active_competitions'] += 1
        
        logging.info(f"🏆 Created competition: {title} ({comp_type.name})")
        return competition
    
    def enter_competition(self, comp_id: str, agent_id: str, agent_name: str):
        """Enter agent into competition"""
        if comp_id not in self.competitions:
            logging.warning(f"Competition {comp_id} not found")
            return False
        
        competition = self.competitions[comp_id]
        if competition.status != "pending":
            logging.warning(f"Competition {comp_id} already started/completed")
            return False
        
        competition.add_participant(agent_id, agent_name)
        
        # Register agent if not already registered
        self.register_agent(agent_id, agent_name)
        
        logging.info(f"✅ {agent_name} entered {competition.title}")
        return True
    
    def start_competition(self, comp_id: str):
        """Start a competition"""
        if comp_id not in self.competitions:
            return False
        
        competition = self.competitions[comp_id]
        competition.status = "active"
        competition.start_time = time.time()
        
        logging.info(f"🚀 Started competition: {competition.title}")
        return True
    
    def record_performance(self, comp_id: str, agent_id: str, metrics: Dict[str, float]):
        """Record agent performance in competition"""
        if comp_id not in self.competitions:
            return False
        
        competition = self.competitions[comp_id]
        competition.record_performance(agent_id, metrics)
        
        return True
    
    def finalize_competition(self, comp_id: str) -> Optional[str]:
        """Finalize competition and update ratings"""
        if comp_id not in self.competitions:
            return None
        
        competition = self.competitions[comp_id]
        competition.finalize()
        
        # Update agent profiles
        for rank, (agent_id, score) in enumerate(competition.rankings, 1):
            if agent_id in self.profiles:
                profile = self.profiles[agent_id]
                profile.competitions_entered += 1
                profile.record_score(score)
                
                # Update win/loss
                if rank == 1:
                    profile.competitions_won += 1
                else:
                    profile.competitions_lost += 1
                
                # Detect breakthroughs
                if score >= self.breakthrough_threshold:
                    profile.breakthrough_count += 1
                    self.stats['breakthroughs_detected'] += 1
                    logging.info(f"💥 BREAKTHROUGH! {profile.agent_name} scored {score:.1f}")
                
                elif score >= self.innovation_threshold:
                    profile.innovation_count += 1
                    self.stats['innovations_recorded'] += 1
                    logging.info(f"💡 INNOVATION! {profile.agent_name} scored {score:.1f}")
        
        # Update ELO ratings for 1v1 competitions
        if len(competition.rankings) == 2:
            agent1_id, score1 = competition.rankings[0]
            agent2_id, score2 = competition.rankings[1]
            
            if agent1_id in self.profiles and agent2_id in self.profiles:
                profile1 = self.profiles[agent1_id]
                profile2 = self.profiles[agent2_id]
                
                profile1.update_elo(profile2.elo_rating, 1.0)
                profile2.update_elo(profile1.elo_rating, 0.0)
        
        self.stats['active_competitions'] -= 1
        
        # Update leaderboards
        self.update_leaderboards()
        
        logging.info(f"🏁 Finalized competition: {competition.title}")
        logging.info(f"   Winner: {self.profiles[competition.winner_id].agent_name}")
        
        return competition.winner_id
    
    def simulate_competition(self, comp_id: str):
        """Simulate a competition with random performance"""
        if comp_id not in self.competitions:
            return False
        
        competition = self.competitions[comp_id]
        
        # Start competition
        self.start_competition(comp_id)
        
        # Simulate performance for each participant
        for agent_id in competition.participants:
            metrics = {
                "speed": random.uniform(50, 100),
                "accuracy": random.uniform(50, 100),
                "efficiency": random.uniform(50, 100),
                "creativity": random.uniform(50, 100),
                "resilience": random.uniform(50, 100),
                "collaboration": random.uniform(50, 100)
            }
            self.record_performance(comp_id, agent_id, metrics)
        
        # Finalize
        winner_id = self.finalize_competition(comp_id)
        
        return winner_id
    
    def update_leaderboards(self):
        """Update global and guild leaderboards"""
        # Global leaderboard (by ELO)
        self.global_leaderboard = sorted(
            [(aid, p.elo_rating) for aid, p in self.profiles.items()],
            key=lambda x: x[1],
            reverse=True
        )
        
        # Update global ranks
        for rank, (agent_id, elo) in enumerate(self.global_leaderboard, 1):
            self.profiles[agent_id].global_rank = rank
    
    def get_leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top agents on leaderboard"""
        results = []
        for rank, (agent_id, elo) in enumerate(self.global_leaderboard[:limit], 1):
            profile = self.profiles[agent_id]
            results.append({
                "rank": rank,
                "agent_id": agent_id,
                "agent_name": profile.agent_name,
                "elo_rating": profile.elo_rating,
                "win_rate": profile.win_rate,
                "competitions": profile.competitions_entered,
                "breakthroughs": profile.breakthrough_count
            })
        
        return results
    
    def get_agent_profile(self, agent_id: str) -> Optional[CompetitiveProfile]:
        """Get agent's competitive profile"""
        return self.profiles.get(agent_id)
    
    def get_competition_stats(self) -> Dict[str, Any]:
        """Get comprehensive competition statistics"""
        active_comps = [c for c in self.competitions.values() if c.status == "active"]
        completed_comps = [c for c in self.competitions.values() if c.status == "completed"]
        
        return {
            "stats": self.stats,
            "active_competitions": len(active_comps),
            "completed_competitions": len(completed_comps),
            "registered_agents": len(self.profiles),
            "top_agent": self.global_leaderboard[0] if self.global_leaderboard else None
        }

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - COMPETITIVE - %(levelname)s - %(message)s')
    
    # Initialize competitive system
    hephaestion = HephaestionCompetitiveSystem()
    
    # Register agents
    agents = [
        ("AGENT_001", "Alpha"),
        ("AGENT_002", "Beta"),
        ("AGENT_003", "Gamma"),
        ("AGENT_004", "Delta"),
        ("AGENT_005", "Epsilon")
    ]
    
    for agent_id, agent_name in agents:
        hephaestion.register_agent(agent_id, agent_name)
    
    # Create competition
    comp = hephaestion.create_competition(
        CompetitionType.SKILL_DUEL,
        "Intelligence Challenge #1",
        "Test problem-solving and pattern recognition"
    )
    
    # Enter agents
    for agent_id, agent_name in agents:
        hephaestion.enter_competition(comp.competition_id, agent_id, agent_name)
    
    # Simulate competition
    winner_id = hephaestion.simulate_competition(comp.competition_id)
    
    # Show leaderboard
    leaderboard = hephaestion.get_leaderboard(limit=5)
    
    print("\n" + "="*70)
    print("HEPHAESTION COMPETITIVE LEADERBOARD")
    print("="*70)
    for entry in leaderboard:
        print(f"#{entry['rank']} {entry['agent_name']}: "
              f"ELO {entry['elo_rating']:.0f}, "
              f"Win Rate {entry['win_rate']:.1%}, "
              f"Breakthroughs: {entry['breakthroughs']}")
    
    # Show stats
    stats = hephaestion.get_competition_stats()
    print("\n" + "="*70)
    print("COMPETITION STATISTICS")
    print("="*70)
    print(f"Total Competitions: {stats['stats']['total_competitions']}")
    print(f"Active: {stats['active_competitions']}")
    print(f"Completed: {stats['completed_competitions']}")
    print(f"Registered Agents: {stats['registered_agents']}")
    print(f"Breakthroughs Detected: {stats['stats']['breakthroughs_detected']}")
    print(f"Innovations Recorded: {stats['stats']['innovations_recorded']}")

# ══════════════════════════════════════════════════════════════════
# AUTHORITY PROMOTION SYSTEM
# ══════════════════════════════════════════════════════════════════

class AuthorityPromotionSystem:
    """
    Promote agents based on competitive performance
    Integrates with AgentRank system from omega_core
    """
    
    def __init__(self):
        self.promotion_thresholds = {
            "EMBRYO": {"wins": 0, "elo": 1000, "breakthroughs": 0},
            "RECRUIT": {"wins": 3, "elo": 1100, "breakthroughs": 0},
            "SOLDIER": {"wins": 10, "elo": 1200, "breakthroughs": 1},
            "VETERAN": {"wins": 25, "elo": 1300, "breakthroughs": 3},
            "CAPTAIN": {"wins": 50, "elo": 1400, "breakthroughs": 5},
            "COMMANDER": {"wins": 100, "elo": 1500, "breakthroughs": 10},
            "ELITE_COMMANDER": {"wins": 200, "elo": 1600, "breakthroughs": 20},
            "GUILD_MASTER": {"wins": 400, "elo": 1700, "breakthroughs": 40},
            "DIVINE_COUNCIL": {"wins": 800, "elo": 1800, "breakthroughs": 80},
            "TRINITY_LEADER": {"wins": 1200, "elo": 1900, "breakthroughs": 120},
        }
        
        self.promotion_log: List[Dict[str, Any]] = []
        
        logging.info("👑 Authority Promotion System initialized")
    
    def check_promotion_eligibility(self, profile: 'CompetitiveProfile') -> Optional[str]:
        """Check if agent qualifies for promotion"""
        current_rank_name = self._get_rank_name_from_elo(profile.elo_rating)
        
        for rank_name, thresholds in self.promotion_thresholds.items():
            if (profile.competitions_won >= thresholds["wins"] and
                profile.elo_rating >= thresholds["elo"] and
                profile.breakthrough_count >= thresholds["breakthroughs"]):
                
                # Check if this is higher than current rank
                if self._is_higher_rank(rank_name, current_rank_name):
                    return rank_name
        
        return None
    
    def promote_agent(self, profile: 'CompetitiveProfile', 
                     new_rank: str, reason: str = "competitive_performance") -> bool:
        """Promote agent to new rank"""
        
        promotion_event = {
            "agent_id": profile.agent_id,
            "agent_name": profile.agent_name,
            "old_rank": self._get_rank_name_from_elo(profile.elo_rating),
            "new_rank": new_rank,
            "reason": reason,
            "timestamp": time.time(),
            "stats": {
                "wins": profile.competitions_won,
                "elo": profile.elo_rating,
                "breakthroughs": profile.breakthrough_count
            }
        }
        
        self.promotion_log.append(promotion_event)
        
        logging.info(f"👑 PROMOTION: {profile.agent_name} → {new_rank}")
        logging.info(f"   Wins: {profile.competitions_won} | ELO: {profile.elo_rating} | Breakthroughs: {profile.breakthrough_count}")
        
        return True
    
    def _get_rank_name_from_elo(self, elo: float) -> str:
        """Get rank name from ELO rating"""
        if elo >= 1900:
            return "TRINITY_LEADER"
        elif elo >= 1800:
            return "DIVINE_COUNCIL"
        elif elo >= 1700:
            return "GUILD_MASTER"
        elif elo >= 1600:
            return "ELITE_COMMANDER"
        elif elo >= 1500:
            return "COMMANDER"
        elif elo >= 1400:
            return "CAPTAIN"
        elif elo >= 1300:
            return "VETERAN"
        elif elo >= 1200:
            return "SOLDIER"
        elif elo >= 1100:
            return "RECRUIT"
        else:
            return "EMBRYO"
    
    def _is_higher_rank(self, rank1: str, rank2: str) -> bool:
        """Check if rank1 is higher than rank2"""
        rank_order = [
            "EMBRYO", "RECRUIT", "SOLDIER", "VETERAN", "CAPTAIN",
            "COMMANDER", "ELITE_COMMANDER", "GUILD_MASTER",
            "DIVINE_COUNCIL", "TRINITY_LEADER", "SUPREME_COMMANDER"
        ]
        
        try:
            return rank_order.index(rank1) > rank_order.index(rank2)
        except ValueError:
            return False

# ══════════════════════════════════════════════════════════════════
# ITERATIVE IMPROVEMENT SYSTEM
# ══════════════════════════════════════════════════════════════════

class IterativeImprovementSystem:
    """
    Agents compete in iterative cycles to improve solutions
    Each round: agents submit improvements, best becomes new baseline
    """
    
    def __init__(self, max_rounds: int = 10):
        self.max_rounds = max_rounds
        self.active_challenges: Dict[str, Dict[str, Any]] = {}
        
        logging.info("🔄 Iterative Improvement System initialized")
    
    def create_challenge(self, challenge_id: str, problem: str, 
                        initial_solution: Any = None) -> bool:
        """Create iterative improvement challenge"""
        self.active_challenges[challenge_id] = {
            "problem": problem,
            "current_solution": initial_solution,
            "current_score": 0.0,
            "round": 0,
            "submissions": [],
            "improvement_log": [],
            "leader": None
        }
        
        logging.info(f"🆕 Created challenge: {challenge_id}")
        return True
    
    def submit_improvement(self, challenge_id: str, agent_id: str, 
                          agent_name: str, solution: Any, 
                          score: float) -> Dict[str, Any]:
        """Submit solution improvement for a challenge"""
        if challenge_id not in self.active_challenges:
            return {"success": False, "reason": "challenge_not_found"}
        
        challenge = self.active_challenges[challenge_id]
        
        submission = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "solution": solution,
            "score": score,
            "round": challenge["round"],
            "timestamp": time.time()
        }
        
        challenge["submissions"].append(submission)
        
        # Check if this is an improvement
        improved = score > challenge["current_score"]
        
        result = {
            "success": True,
            "improved": improved,
            "score": score,
            "previous_best": challenge["current_score"],
            "improvement_delta": score - challenge["current_score"],
            "current_leader": challenge["leader"]
        }
        
        if improved:
            # Log improvement
            challenge["improvement_log"].append({
                "round": challenge["round"],
                "agent": agent_name,
                "old_score": challenge["current_score"],
                "new_score": score,
                "delta": score - challenge["current_score"],
                "timestamp": time.time()
            })
            
            # Update current best
            challenge["current_solution"] = solution
            challenge["current_score"] = score
            challenge["leader"] = agent_name
            
            result["became_leader"] = True
            
            logging.info(f"✨ IMPROVEMENT: {agent_name} improved score to {score:.2f} (+{result['improvement_delta']:.2f})")
        
        return result
    
    def advance_round(self, challenge_id: str) -> bool:
        """Advance to next improvement round"""
        if challenge_id not in self.active_challenges:
            return False
        
        challenge = self.active_challenges[challenge_id]
        challenge["round"] += 1
        challenge["submissions"] = []  # Clear for new round
        
        if challenge["round"] >= self.max_rounds:
            logging.info(f"🏁 Challenge {challenge_id} completed ({self.max_rounds} rounds)")
            return False  # Challenge complete
        
        logging.info(f"📊 Challenge {challenge_id} → Round {challenge['round']}")
        return True
    
    def get_challenge_status(self, challenge_id: str) -> Dict[str, Any]:
        """Get current challenge status"""
        if challenge_id not in self.active_challenges:
            return {}
        
        challenge = self.active_challenges[challenge_id]
        return {
            "round": challenge["round"],
            "max_rounds": self.max_rounds,
            "current_score": challenge["current_score"],
            "leader": challenge["leader"],
            "total_improvements": len(challenge["improvement_log"]),
            "submissions_this_round": len(challenge["submissions"])
        }
