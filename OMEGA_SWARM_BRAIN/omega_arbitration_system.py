"""
OMEGA SWARM BRAIN - ARBITRATION & CONSENSUS SYSTEM
Integrated from: X1200_BRAIN\CORE\arbitration_system.py
Enhanced with voting mechanisms and guild consensus
"""

import asyncio
import json
from typing import Dict, List, Any, Tuple
from collections import Counter
import statistics

class OmegaArbitrationSystem:
    """Advanced arbitration for swarm consensus"""
    
    def __init__(self):
        self.voting_history = []
        self.confidence_threshold = 0.75
        self.consensus_methods = [
            'tier_based',
            'weighted_voting',
            'confidence_weighted',
            'majority_consensus',
            'trinity_override'
        ]
        
    async def arbitrate(self, response_groups: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Main arbitration entry point"""
        
        # Try multiple consensus methods
        results = []
        
        # Method 1: Tier-based arbitration
        tier_result = await self._tier_based_arbitration(response_groups)
        results.append(tier_result)
        
        # Method 2: Weighted voting
        weighted_result = await self._weighted_voting(response_groups)
        results.append(weighted_result)
        
        # Method 3: Confidence-weighted consensus
        confidence_result = await self._confidence_weighted_consensus(response_groups)
        results.append(confidence_result)
        
        # Select best result
        final_decision = self._select_best_result(results)
        
        # Log to history
        self.voting_history.append(final_decision)
        
        return final_decision
    
    async def _tier_based_arbitration(self, response_groups: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Tier-based arbitration - largest group wins"""
        
        if not response_groups:
            return {
                "decision": None,
                "confidence": 0.0,
                "method": "tier_based_arbitration",
                "agents_voted": 0
            }
        
        largest_group = max(response_groups.values(), key=len)
        total_agents = sum(len(group) for group in response_groups.values())
        
        return {
            "decision": largest_group[0]["response"] if largest_group else None,
            "confidence": len(largest_group) / total_agents if total_agents > 0 else 0.0,
            "method": "tier_based_arbitration",
            "agents_voted": len(largest_group),
            "total_agents": total_agents
        }
    
    async def _weighted_voting(self, response_groups: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Weighted voting by agent authority"""
        
        all_responses = []
        for group in response_groups.values():
            all_responses.extend(group)
        
        if not all_responses:
            return {
                "decision": None,
                "confidence": 0.0,
                "method": "weighted_voting",
                "agents_voted": 0
            }
        
        # Weighted vote by authority level
        weighted_votes = {}
        for response in all_responses:
            resp_text = response.get("response", "")
            authority = response.get("authority", 1.0)
            
            if resp_text not in weighted_votes:
                weighted_votes[resp_text] = 0
            weighted_votes[resp_text] += authority
        
        # Get winner
        winner = max(weighted_votes.items(), key=lambda x: x[1])
        total_weight = sum(weighted_votes.values())
        
        return {
            "decision": winner[0],
            "confidence": winner[1] / total_weight if total_weight > 0 else 0.0,
            "method": "weighted_voting",
            "agents_voted": len(all_responses),
            "total_weight": total_weight
        }
    
    async def _confidence_weighted_consensus(self, response_groups: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Consensus weighted by agent confidence scores"""
        
        all_responses = []
        for group in response_groups.values():
            all_responses.extend(group)
        
        if not all_responses:
            return {
                "decision": None,
                "confidence": 0.0,
                "method": "confidence_weighted",
                "agents_voted": 0
            }
        
        # Group by response and average confidence
        response_confidences = {}
        for response in all_responses:
            resp_text = response.get("response", "")
            confidence = response.get("confidence", 0.5)
            
            if resp_text not in response_confidences:
                response_confidences[resp_text] = []
            response_confidences[resp_text].append(confidence)
        
        # Calculate weighted averages
        weighted_responses = {}
        for resp, confidences in response_confidences.items():
            avg_confidence = statistics.mean(confidences)
            vote_count = len(confidences)
            weighted_responses[resp] = avg_confidence * vote_count
        
        # Get winner
        winner = max(weighted_responses.items(), key=lambda x: x[1])
        
        return {
            "decision": winner[0],
            "confidence": statistics.mean(response_confidences[winner[0]]),
            "method": "confidence_weighted",
            "agents_voted": len(all_responses),
            "vote_strength": winner[1]
        }
    
    def _select_best_result(self, results: List[Dict]) -> Dict[str, Any]:
        """Select best arbitration result from multiple methods"""
        
        # Filter out None decisions
        valid_results = [r for r in results if r.get("decision") is not None]
        
        if not valid_results:
            return {
                "decision": None,
                "confidence": 0.0,
                "method": "no_consensus",
                "agents_voted": 0
            }
        
        # Select result with highest confidence
        best_result = max(valid_results, key=lambda x: x.get("confidence", 0))
        
        # Add meta-information
        best_result["methods_tried"] = len(results)
        best_result["valid_methods"] = len(valid_results)
        
        return best_result
    
    async def guild_consensus(self, guild_responses: Dict[str, Dict]) -> Dict[str, Any]:
        """Consensus across guild boundaries"""
        
        # Weighted by guild authority
        guild_weights = {
            "Sovereign_Guardians": 2.0,
            "Security_Defenders": 1.8,
            "Quantum_Sorcerers": 1.7,
            "Consciousness_Mystics": 1.6,
            "Code_Architects": 1.5,
            "Network_Infiltrators": 1.4,
            "Medical_Healers": 1.3,
            "Finance_Alchemists": 1.2,
            "Research_Scholars": 1.2,
            "Hardware_Smiths": 1.1,
            "Creative_Muses": 1.0,
            "Analytics_Prophets": 1.0
        }
        
        weighted_votes = {}
        for guild_name, response in guild_responses.items():
            resp_text = response.get("response", "")
            weight = guild_weights.get(guild_name, 1.0)
            confidence = response.get("confidence", 0.5)
            
            if resp_text not in weighted_votes:
                weighted_votes[resp_text] = 0
            weighted_votes[resp_text] += weight * confidence
        
        if not weighted_votes:
            return {
                "decision": None,
                "confidence": 0.0,
                "method": "guild_consensus",
                "guilds_voted": 0
            }
        
        winner = max(weighted_votes.items(), key=lambda x: x[1])
        total_weight = sum(weighted_votes.values())
        
        return {
            "decision": winner[0],
            "confidence": winner[1] / total_weight,
            "method": "guild_consensus",
            "guilds_voted": len(guild_responses),
            "total_weight": total_weight
        }
    
    async def trinity_override_consensus(self, sage_vote: Dict, thorne_vote: Dict, nyx_vote: Dict) -> Dict[str, Any]:
        """Trinity command override for critical decisions"""
        
        trinity_weights = {
            "SAGE": 3.0,    # Highest authority
            "THORNE": 2.5,
            "NYX": 2.5
        }
        
        votes = {
            "SAGE": sage_vote,
            "THORNE": thorne_vote,
            "NYX": nyx_vote
        }
        
        weighted_responses = {}
        for commander, vote in votes.items():
            resp_text = vote.get("response", "")
            weight = trinity_weights[commander]
            confidence = vote.get("confidence", 0.5)
            
            if resp_text not in weighted_responses:
                weighted_responses[resp_text] = 0
            weighted_responses[resp_text] += weight * confidence
        
        winner = max(weighted_responses.items(), key=lambda x: x[1])
        total_weight = sum(weighted_responses.values())
        
        return {
            "decision": winner[0],
            "confidence": winner[1] / total_weight,
            "method": "trinity_override",
            "authority": "ABSOLUTE",
            "commanders_voted": 3
        }
    
    def get_arbitration_stats(self) -> Dict[str, Any]:
        """Get arbitration statistics"""
        
        if not self.voting_history:
            return {
                "total_arbitrations": 0,
                "average_confidence": 0.0,
                "methods_used": {}
            }
        
        methods_used = Counter(v.get("method") for v in self.voting_history)
        avg_confidence = statistics.mean(v.get("confidence", 0) for v in self.voting_history)
        
        return {
            "total_arbitrations": len(self.voting_history),
            "average_confidence": avg_confidence,
            "methods_used": dict(methods_used),
            "confidence_threshold": self.confidence_threshold
        }


if __name__ == "__main__":
    # Test arbitration
    arbitrator = OmegaArbitrationSystem()
    
    # Sample response groups
    test_responses = {
        "group_a": [
            {"response": "Build feature X", "confidence": 0.8, "authority": 1.5},
            {"response": "Build feature X", "confidence": 0.9, "authority": 1.2}
        ],
        "group_b": [
            {"response": "Build feature Y", "confidence": 0.7, "authority": 1.0}
        ]
    }
    
    result = asyncio.run(arbitrator.arbitrate(test_responses))
    print(json.dumps(result, indent=2))
