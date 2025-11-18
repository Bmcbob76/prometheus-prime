#!/usr/bin/env python3
"""
PROMETHEUS PRIME - AUTONOMOUS DECISION ENGINE
AI-powered decision making with 5-model consensus

Authority Level: 11.0
Commander: Bobby Don McWilliams II

DECISION SYSTEM:
- 5-Model AI Consensus: Claude, GPT-4, Gemini, Cohere, Opus
- Multi-criteria decision analysis
- Risk-aware decision making
- Confidence scoring and validation
- Explainable AI decisions
- Human-in-the-loop for critical decisions
"""

import logging
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import json

logger = logging.getLogger("DecisionEngine")


class DecisionType(Enum):
    """Types of decisions"""
    NEXT_ACTION = "next_action"
    TARGET_SELECTION = "target_selection"
    TECHNIQUE_SELECTION = "technique_selection"
    EXPLOIT_SELECTION = "exploit_selection"
    ESCALATION = "escalation"
    PERSISTENCE = "persistence"
    ABORT = "abort"


class ConfidenceLevel(Enum):
    """Decision confidence levels"""
    VERY_LOW = "very_low"  # < 40%
    LOW = "low"  # 40-60%
    MEDIUM = "medium"  # 60-75%
    HIGH = "high"  # 75-90%
    VERY_HIGH = "very_high"  # > 90%


@dataclass
class AIModelResponse:
    """Response from single AI model"""
    model_name: str
    decision: str
    reasoning: str
    confidence: float
    risk_assessment: float
    alternatives: List[str]
    timestamp: str


@dataclass
class ConsensusDecision:
    """Consensus decision from multiple models"""
    decision_id: str
    decision_type: DecisionType
    chosen_action: str
    consensus_confidence: float
    confidence_level: ConfidenceLevel
    model_responses: List[AIModelResponse]
    agreement_score: float
    reasoning: str
    risks: List[str]
    alternatives: List[str]
    requires_approval: bool
    timestamp: str


class DecisionEngine:
    """
    AI-powered decision engine with 5-model consensus.

    Uses multiple AI models for robust decision making:
    1. Claude Sonnet 4.5 - Strategic reasoning
    2. GPT-4 - Tactical analysis
    3. Gemini Pro - Risk assessment
    4. Cohere Command - Alternative perspectives
    5. Claude Opus - Critical validation

    Decision process:
    1. Gather context and options
    2. Query all 5 models independently
    3. Analyze responses for consensus
    4. Calculate confidence and agreement
    5. Make final decision or escalate
    """

    def __init__(self, authority_level: float = 9.0):
        """
        Initialize Decision Engine.

        Args:
            authority_level: Operator authority level
        """
        self.authority_level = authority_level
        self.decision_history: List[ConsensusDecision] = []
        self.decision_count = 0

        # AI model clients (would be initialized with actual API keys)
        self.ai_clients = {
            "claude_sonnet": None,  # Anthropic API
            "gpt4": None,  # OpenAI API
            "gemini": None,  # Google API
            "cohere": None,  # Cohere API
            "claude_opus": None  # Anthropic API
        }

        logger.info("🤖 Decision Engine initialized")
        logger.info(f"   Authority Level: {authority_level}")
        logger.info(f"   AI Models: {len(self.ai_clients)}")

    async def make_decision(self,
                           decision_type: DecisionType,
                           context: Dict,
                           options: List[str],
                           constraints: Optional[Dict] = None) -> ConsensusDecision:
        """
        Make autonomous decision using AI consensus.

        Args:
            decision_type: Type of decision
            context: Decision context and situation data
            options: Available options to choose from
            constraints: Optional constraints (ROE, scope, etc.)

        Returns:
            ConsensusDecision with consensus and confidence
        """
        self.decision_count += 1
        decision_id = f"DEC-{self.decision_count:06d}"

        logger.info(f"\n{'='*60}")
        logger.info(f"🤖 AUTONOMOUS DECISION #{self.decision_count}")
        logger.info(f"   Type: {decision_type.value}")
        logger.info(f"   Options: {len(options)}")
        logger.info(f"{'='*60}")

        # Prepare decision prompt
        prompt = self._prepare_decision_prompt(decision_type, context, options, constraints)

        # Query all AI models in parallel
        logger.info("Consulting AI models...")
        model_responses = await self._query_all_models(prompt, options)

        # Analyze consensus
        logger.info("Analyzing consensus...")
        consensus = self._analyze_consensus(
            decision_id,
            decision_type,
            model_responses,
            options
        )

        # Determine if approval required
        consensus.requires_approval = self._requires_approval(consensus)

        # Store in history
        self.decision_history.append(consensus)

        logger.info(f"\n{'='*60}")
        logger.info(f"✅ DECISION MADE: {consensus.chosen_action}")
        logger.info(f"   Confidence: {consensus.consensus_confidence:.1%}")
        logger.info(f"   Agreement: {consensus.agreement_score:.1%}")
        logger.info(f"   Requires Approval: {consensus.requires_approval}")
        logger.info(f"{'='*60}\n")

        return consensus

    # Legacy interface for existing code
    async def decide(self, intel: Dict) -> Dict:
        """Legacy interface - converts to new decision format"""
        options = ["recon", "exploit", "escalate", "exfiltrate"]
        decision = await self.make_decision(
            DecisionType.NEXT_ACTION,
            intel,
            options
        )
        return {
            "action": decision.chosen_action,
            "domain": "autonomous_operation",
            "confidence": decision.consensus_confidence,
            "rationale": decision.reasoning[:100]
        }

    def _prepare_decision_prompt(self,
                                decision_type: DecisionType,
                                context: Dict,
                                options: List[str],
                                constraints: Optional[Dict]) -> str:
        """Prepare prompt for AI models."""
        prompt = f"""You are an autonomous penetration testing AI making tactical decisions.

DECISION TYPE: {decision_type.value}

CONTEXT:
{json.dumps(context, indent=2)}

AVAILABLE OPTIONS:
{chr(10).join(f"{i+1}. {opt}" for i, opt in enumerate(options))}

CONSTRAINTS:
{json.dumps(constraints, indent=2) if constraints else "None"}

TASK:
Analyze the situation and choose the best option. Provide:
1. Your chosen option (specify the number or name)
2. Detailed reasoning for your choice
3. Confidence score (0.0-1.0)
4. Risk assessment (0.0-1.0, where 1.0 is highest risk)
5. Alternative options you considered

Format your response as JSON:
{{
    "decision": "option name or number",
    "reasoning": "detailed explanation",
    "confidence": 0.0-1.0,
    "risk_assessment": 0.0-1.0,
    "alternatives": ["alt1", "alt2"]
}}
"""
        return prompt

    async def _query_all_models(self, prompt: str, options: List[str]) -> List[AIModelResponse]:
        """Query all AI models in parallel."""
        # In production, this would make actual API calls
        # For now, simulate diverse model responses

        logger.info("   Querying Claude Sonnet...")
        claude_response = await self._simulate_claude_sonnet(prompt, options)

        logger.info("   Querying GPT-4...")
        gpt4_response = await self._simulate_gpt4(prompt, options)

        logger.info("   Querying Gemini Pro...")
        gemini_response = await self._simulate_gemini(prompt, options)

        logger.info("   Querying Cohere...")
        cohere_response = await self._simulate_cohere(prompt, options)

        logger.info("   Querying Claude Opus...")
        opus_response = await self._simulate_claude_opus(prompt, options)

        return [claude_response, gpt4_response, gemini_response, cohere_response, opus_response]

    async def _simulate_claude_sonnet(self, prompt: str, options: List[str]) -> AIModelResponse:
        """Simulate Claude Sonnet response (strategic reasoning)."""
        await asyncio.sleep(0.1)  # Simulate API delay

        # Claude tends to favor strategic, safe approaches
        decision = options[0] if options else "continue_reconnaissance"
        confidence = 0.85
        risk = 0.3

        return AIModelResponse(
            model_name="Claude Sonnet 4.5",
            decision=decision,
            reasoning="Strategic analysis suggests this approach balances effectiveness with risk management. "
                     "Gradual escalation allows for better situational awareness and adaptation.",
            confidence=confidence,
            risk_assessment=risk,
            alternatives=options[1:3] if len(options) > 1 else [],
            timestamp=datetime.now().isoformat()
        )

    async def _simulate_gpt4(self, prompt: str, options: List[str]) -> AIModelResponse:
        """Simulate GPT-4 response (tactical analysis)."""
        await asyncio.sleep(0.1)

        # GPT-4 tends to be pragmatic and direct
        decision = options[0] if options else "exploit_vulnerability"
        confidence = 0.88
        risk = 0.4

        return AIModelResponse(
            model_name="GPT-4",
            decision=decision,
            reasoning="Tactical assessment indicates this is the most efficient path to objective. "
                     "Risk is manageable given available intelligence and tools.",
            confidence=confidence,
            risk_assessment=risk,
            alternatives=options[1:3] if len(options) > 1 else [],
            timestamp=datetime.now().isoformat()
        )

    async def _simulate_gemini(self, prompt: str, options: List[str]) -> AIModelResponse:
        """Simulate Gemini Pro response (risk assessment focus)."""
        await asyncio.sleep(0.1)

        # Gemini tends to emphasize risk analysis
        decision = options[0] if options else "vulnerability_scan"
        confidence = 0.80
        risk = 0.25

        return AIModelResponse(
            model_name="Gemini Pro",
            decision=decision,
            reasoning="Risk analysis shows this approach minimizes detection probability while maintaining "
                     "operational effectiveness. Defense capabilities appear limited.",
            confidence=confidence,
            risk_assessment=risk,
            alternatives=options[1:3] if len(options) > 1 else [],
            timestamp=datetime.now().isoformat()
        )

    async def _simulate_cohere(self, prompt: str, options: List[str]) -> AIModelResponse:
        """Simulate Cohere response (alternative perspectives)."""
        await asyncio.sleep(0.1)

        # Cohere provides diverse viewpoints
        decision = options[1] if len(options) > 1 else options[0]
        confidence = 0.75
        risk = 0.5

        return AIModelResponse(
            model_name="Cohere Command",
            decision=decision,
            reasoning="Alternative analysis suggests considering this option for potentially better outcomes. "
                     "While slightly riskier, the payoff may justify the approach.",
            confidence=confidence,
            risk_assessment=risk,
            alternatives=[options[0]] + options[2:3] if len(options) > 2 else [options[0]] if options else [],
            timestamp=datetime.now().isoformat()
        )

    async def _simulate_claude_opus(self, prompt: str, options: List[str]) -> AIModelResponse:
        """Simulate Claude Opus response (critical validation)."""
        await asyncio.sleep(0.1)

        # Opus provides critical analysis and validation
        decision = options[0] if options else "validate_target_scope"
        confidence = 0.92
        risk = 0.2

        return AIModelResponse(
            model_name="Claude Opus",
            decision=decision,
            reasoning="Critical validation confirms this decision aligns with engagement objectives and constraints. "
                     "Comprehensive analysis supports this as the optimal choice given current intelligence.",
            confidence=confidence,
            risk_assessment=risk,
            alternatives=options[1:3] if len(options) > 1 else [],
            timestamp=datetime.now().isoformat()
        )

    def _analyze_consensus(self,
                          decision_id: str,
                          decision_type: DecisionType,
                          responses: List[AIModelResponse],
                          options: List[str]) -> ConsensusDecision:
        """Analyze model responses to determine consensus."""
        # Count votes for each option
        from collections import Counter
        votes = Counter([r.decision for r in responses])

        # Most common decision
        chosen_action = votes.most_common(1)[0][0]
        vote_count = votes[chosen_action]

        # Calculate agreement score
        agreement_score = vote_count / len(responses)

        # Calculate consensus confidence (weighted average)
        total_confidence = 0.0
        total_weight = 0.0
        for response in responses:
            # Weight by agreement with chosen action
            weight = 1.0 if response.decision == chosen_action else 0.5
            total_confidence += response.confidence * weight
            total_weight += weight

        consensus_confidence = total_confidence / total_weight if total_weight > 0 else 0.0

        # Determine confidence level
        if consensus_confidence >= 0.90:
            confidence_level = ConfidenceLevel.VERY_HIGH
        elif consensus_confidence >= 0.75:
            confidence_level = ConfidenceLevel.HIGH
        elif consensus_confidence >= 0.60:
            confidence_level = ConfidenceLevel.MEDIUM
        elif consensus_confidence >= 0.40:
            confidence_level = ConfidenceLevel.LOW
        else:
            confidence_level = ConfidenceLevel.VERY_LOW

        # Aggregate reasoning
        supporting_reasoning = [r.reasoning for r in responses if r.decision == chosen_action]
        combined_reasoning = " | ".join(supporting_reasoning)

        # Aggregate risks
        risks = []
        avg_risk = sum(r.risk_assessment for r in responses) / len(responses)
        if avg_risk > 0.7:
            risks.append("High detection risk")
        if avg_risk > 0.5:
            risks.append("Moderate operational risk")
        if agreement_score < 0.6:
            risks.append("Low consensus among models")

        # Collect alternatives
        all_alternatives = []
        for response in responses:
            all_alternatives.extend(response.alternatives)
        alternatives = list(set(all_alternatives))[:3]  # Top 3 unique alternatives

        return ConsensusDecision(
            decision_id=decision_id,
            decision_type=decision_type,
            chosen_action=chosen_action,
            consensus_confidence=consensus_confidence,
            confidence_level=confidence_level,
            model_responses=responses,
            agreement_score=agreement_score,
            reasoning=combined_reasoning,
            risks=risks,
            alternatives=alternatives,
            requires_approval=False,  # Set by _requires_approval
            timestamp=datetime.now().isoformat()
        )

    def _requires_approval(self, consensus: ConsensusDecision) -> bool:
        """Determine if decision requires human approval."""
        # Require approval if:
        # 1. Low confidence or agreement
        if consensus.confidence_level in [ConfidenceLevel.VERY_LOW, ConfidenceLevel.LOW]:
            return True
        if consensus.agreement_score < 0.6:
            return True

        # 2. High risk decisions
        avg_risk = sum(r.risk_assessment for r in consensus.model_responses) / len(consensus.model_responses)
        if avg_risk > 0.7:
            return True

        # 3. Critical decision types
        critical_decisions = [DecisionType.ESCALATION, DecisionType.ABORT]
        if consensus.decision_type in critical_decisions:
            return True

        # 4. Authority level check
        if self.authority_level < 11.0:
            # Lower authority requires approval for medium+ risk
            if avg_risk > 0.5:
                return True

        return False

    def explain_decision(self, decision: ConsensusDecision) -> str:
        """Generate human-readable explanation of decision."""
        explanation = f"""
DECISION EXPLANATION
{'='*60}

Decision ID: {decision.decision_id}
Type: {decision.decision_type.value}
Chosen Action: {decision.chosen_action}

CONFIDENCE:
  Consensus: {decision.consensus_confidence:.1%}
  Level: {decision.confidence_level.value.upper()}
  Agreement: {decision.agreement_score:.1%} ({int(decision.agreement_score * 5)}/5 models)

MODEL RESPONSES:
"""

        for response in decision.model_responses:
            vote = "✅" if response.decision == decision.chosen_action else "❌"
            explanation += f"  {vote} {response.model_name}:\n"
            explanation += f"     Decision: {response.decision}\n"
            explanation += f"     Confidence: {response.confidence:.1%}\n"
            explanation += f"     Risk: {response.risk_assessment:.1%}\n"
            explanation += f"     Reasoning: {response.reasoning[:80]}...\n\n"

        explanation += f"\nCONSENSUS REASONING:\n{decision.reasoning[:200]}...\n"

        if decision.risks:
            explanation += f"\nIDENTIFIED RISKS:\n"
            for risk in decision.risks:
                explanation += f"  ⚠️  {risk}\n"

        if decision.alternatives:
            explanation += f"\nALTERNATIVE OPTIONS:\n"
            for alt in decision.alternatives:
                explanation += f"  - {alt}\n"

        explanation += f"\nREQUIRES APPROVAL: {'YES' if decision.requires_approval else 'NO'}\n"
        explanation += f"\n{'='*60}"

        return explanation

    def get_statistics(self) -> Dict:
        """Get decision engine statistics."""
        if not self.decision_history:
            return {"total_decisions": 0}

        from collections import Counter

        total = len(self.decision_history)
        by_type = Counter([d.decision_type.value for d in self.decision_history])
        by_confidence = Counter([d.confidence_level.value for d in self.decision_history])

        avg_confidence = sum(d.consensus_confidence for d in self.decision_history) / total
        avg_agreement = sum(d.agreement_score for d in self.decision_history) / total
        approval_required = sum(1 for d in self.decision_history if d.requires_approval)

        return {
            "total_decisions": total,
            "by_type": dict(by_type),
            "by_confidence_level": dict(by_confidence),
            "average_confidence": avg_confidence,
            "average_agreement": avg_agreement,
            "approval_required_count": approval_required,
            "approval_rate": approval_required / total if total > 0 else 0
        }


if __name__ == "__main__":
    # Test Decision Engine
    import sys
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    async def test_decision_engine():
        print("\n🤖 PROMETHEUS PRIME - AUTONOMOUS DECISION ENGINE")
        print("="*60)

        engine = DecisionEngine(authority_level=11.0)

        # Test 1: Next action decision
        print("\n" + "="*60)
        print("TEST 1: Next Action Decision")
        print("="*60)

        context = {
            "phase": "reconnaissance",
            "target": "192.168.1.100",
            "services_found": ["HTTP", "SSH", "MySQL"],
            "vulnerabilities": ["CVE-2021-41773"]
        }

        options = [
            "continue_reconnaissance",
            "vulnerability_scan",
            "exploit_CVE-2021-41773",
            "credential_brute_force"
        ]

        decision = await engine.make_decision(
            DecisionType.NEXT_ACTION,
            context,
            options
        )

        print("\n" + engine.explain_decision(decision))

        # Test 2: Technique selection
        print("\n" + "="*60)
        print("TEST 2: Technique Selection Decision")
        print("="*60)

        context = {
            "target": "web-server-01",
            "vulnerability": "SQL Injection",
            "defense_level": "medium"
        }

        options = [
            "sqlmap_automated",
            "manual_injection",
            "time_based_blind",
            "union_based"
        ]

        decision = await engine.make_decision(
            DecisionType.TECHNIQUE_SELECTION,
            context,
            options,
            constraints={"stealth": "high", "time_limit": 30}
        )

        print(f"\nChosen: {decision.chosen_action}")
        print(f"Confidence: {decision.consensus_confidence:.1%}")
        print(f"Agreement: {decision.agreement_score:.1%}")

        # Show statistics
        print("\n" + "="*60)
        print("DECISION ENGINE STATISTICS")
        print("="*60)
        stats = engine.get_statistics()
        for key, value in stats.items():
            print(f"{key}: {value}")

    # Run tests
    asyncio.run(test_decision_engine())
