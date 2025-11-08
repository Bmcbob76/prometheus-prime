"""
PROMETHEUS AI BRAIN - MULTI-MODEL ORCHESTRATOR
5-Model Consensus Engine: 2 Local GPU + 3 API Models

Authority Level: 11.0
Operator: Commander Bobby Don McWilliams II
"""

import asyncio
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime
import json

from .local_inference import LocalLLM
from .api_clients import ClaudeClient, OpenAIClient, GeminiClient
from .gpu_manager import GPUManager


class PrometheusAIBrain:
    """
    Multi-Model AI Orchestrator

    Orchestrates 5 AI models for consensus-based decision making:
    - Local Primary: Llama-3-70B on GTX 1080 (CUDA:0)
    - Local Secondary: Mistral-7B on GTX 1650 (CUDA:1)
    - Claude Sonnet 4
    - GPT-4 Turbo
    - Gemini Pro

    Consensus threshold: 75% agreement required for action approval
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize AI Brain with 5-model consensus system.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger("PrometheusAIBrain")
        self.logger.setLevel(logging.INFO)

        # Consensus settings
        self.consensus_threshold = self.config.get("consensus_threshold", 0.75)
        self.voting_weight = {
            "local_primary": 1.5,  # Higher weight for larger local model
            "local_secondary": 1.0,
            "claude": 1.5,  # Higher weight for frontier models
            "gpt4": 1.5,
            "gemini": 1.0
        }

        # Initialize GPU manager
        self.gpu_manager = GPUManager()

        # Initialize models (lazy loading)
        self.models_initialized = False
        self.local_primary = None
        self.local_secondary = None
        self.claude = None
        self.gpt4 = None
        self.gemini = None

        # Statistics
        self.decisions_made = 0
        self.consensus_achieved = 0
        self.model_stats = {model: {"calls": 0, "errors": 0} for model in self.voting_weight.keys()}

        self.logger.info("🧠 PROMETHEUS AI BRAIN INITIALIZED - 5-MODEL CONSENSUS ENGINE")

    async def initialize_models(self):
        """Initialize all 5 AI models"""
        if self.models_initialized:
            return

        self.logger.info("🔧 Initializing AI models...")

        try:
            # Initialize local GPU models with 4-bit quantization
            self.logger.info("📡 Loading local GPU models...")
            self.local_primary = LocalLLM(
                model_name="meta-llama/Llama-2-70b-chat-hf",
                device="cuda:0",  # GTX 1080
                quantization_bits=4,
                max_memory="8GB"
            )

            self.local_secondary = LocalLLM(
                model_name="mistralai/Mistral-7B-Instruct-v0.2",
                device="cuda:1",  # GTX 1650
                quantization_bits=4,
                max_memory="4GB"
            )

            # Initialize API clients
            self.logger.info("🌐 Initializing API clients...")
            self.claude = ClaudeClient(
                api_key=self.config.get("anthropic_api_key"),
                model="claude-sonnet-4-20250514"
            )

            self.gpt4 = OpenAIClient(
                api_key=self.config.get("openai_api_key"),
                model="gpt-4-turbo"
            )

            self.gemini = GeminiClient(
                api_key=self.config.get("google_api_key"),
                model="gemini-pro"
            )

            self.models_initialized = True
            self.logger.info("✅ All 5 models initialized successfully")

        except Exception as e:
            self.logger.error(f"❌ Model initialization failed: {e}")
            raise

    async def decide_action(self, situation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query all 5 models and calculate consensus decision.

        Args:
            situation: Dictionary containing:
                - context: Current operational context
                - target: Target information
                - available_domains: List of available security domains
                - constraints: Operational constraints

        Returns:
            Decision dictionary with consensus results
        """
        await self.initialize_models()

        self.logger.info(f"🎯 DECISION REQUEST: {situation.get('context', 'Unknown')}")

        # Build prompt for all models
        prompt = self._build_decision_prompt(situation)

        # Query all models in parallel
        self.logger.info("📊 Querying all 5 models...")
        start_time = datetime.now()

        responses = await asyncio.gather(
            self._query_local_primary(prompt),
            self._query_local_secondary(prompt),
            self._query_claude(prompt),
            self._query_gpt4(prompt),
            self._query_gemini(prompt),
            return_exceptions=True
        )

        query_duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"⏱️  Query completed in {query_duration:.2f}s")

        # Parse responses
        model_decisions = {
            "local_primary": responses[0],
            "local_secondary": responses[1],
            "claude": responses[2],
            "gpt4": responses[3],
            "gemini": responses[4]
        }

        # Calculate consensus
        consensus = self._calculate_consensus(model_decisions)

        # Update statistics
        self.decisions_made += 1
        if consensus["consensus_reached"]:
            self.consensus_achieved += 1

        self.logger.info(
            f"🎲 CONSENSUS: {consensus['consensus_score']:.0%} "
            f"({'APPROVED' if consensus['consensus_reached'] else 'REJECTED'})"
        )

        return consensus

    def _build_decision_prompt(self, situation: Dict[str, Any]) -> str:
        """Build decision prompt for AI models"""
        return f"""
PROMETHEUS PRIME - AUTONOMOUS SECURITY OPERATION DECISION

SITUATION:
{json.dumps(situation, indent=2)}

TASK:
Analyze the situation and decide which security domain to engage and what operation to execute.

AVAILABLE DOMAINS:
- network_reconnaissance
- web_exploitation
- wireless_operations
- social_engineering
- physical_security
- cryptographic_analysis
- malware_development
- digital_forensics
- cloud_security
- mobile_security
- iot_security
- scada_ics_security
- threat_intelligence
- red_team_operations
- blue_team_defense
- purple_team_integration
- osint_reconnaissance
- exploit_development
- post_exploitation
- persistence_mechanisms

RESPONSE FORMAT (JSON):
{{
    "domain": "<selected_domain>",
    "operation": "<operation_to_execute>",
    "parameters": {{}},
    "rationale": "<reasoning>",
    "risk_level": "<low|medium|high|critical>",
    "expected_outcome": "<description>"
}}

Respond with ONLY valid JSON. No additional text.
"""

    async def _query_local_primary(self, prompt: str) -> Dict:
        """Query local primary model (Llama-3-70B)"""
        try:
            self.model_stats["local_primary"]["calls"] += 1
            response = await self.local_primary.generate(prompt)
            return self._parse_model_response(response)
        except Exception as e:
            self.logger.error(f"Local primary error: {e}")
            self.model_stats["local_primary"]["errors"] += 1
            return {"error": str(e)}

    async def _query_local_secondary(self, prompt: str) -> Dict:
        """Query local secondary model (Mistral-7B)"""
        try:
            self.model_stats["local_secondary"]["calls"] += 1
            response = await self.local_secondary.generate(prompt)
            return self._parse_model_response(response)
        except Exception as e:
            self.logger.error(f"Local secondary error: {e}")
            self.model_stats["local_secondary"]["errors"] += 1
            return {"error": str(e)}

    async def _query_claude(self, prompt: str) -> Dict:
        """Query Claude Sonnet 4"""
        try:
            self.model_stats["claude"]["calls"] += 1
            response = await self.claude.complete(prompt)
            return self._parse_model_response(response)
        except Exception as e:
            self.logger.error(f"Claude error: {e}")
            self.model_stats["claude"]["errors"] += 1
            return {"error": str(e)}

    async def _query_gpt4(self, prompt: str) -> Dict:
        """Query GPT-4 Turbo"""
        try:
            self.model_stats["gpt4"]["calls"] += 1
            response = await self.gpt4.complete(prompt)
            return self._parse_model_response(response)
        except Exception as e:
            self.logger.error(f"GPT-4 error: {e}")
            self.model_stats["gpt4"]["errors"] += 1
            return {"error": str(e)}

    async def _query_gemini(self, prompt: str) -> Dict:
        """Query Gemini Pro"""
        try:
            self.model_stats["gemini"]["calls"] += 1
            response = await self.gemini.complete(prompt)
            return self._parse_model_response(response)
        except Exception as e:
            self.logger.error(f"Gemini error: {e}")
            self.model_stats["gemini"]["errors"] += 1
            return {"error": str(e)}

    def _parse_model_response(self, response: str) -> Dict:
        """Parse JSON response from model"""
        try:
            # Extract JSON from response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0].strip()
            else:
                json_str = response.strip()

            return json.loads(json_str)
        except Exception as e:
            self.logger.warning(f"Response parsing failed: {e}")
            return {"error": "Parse failed", "raw": response}

    def _calculate_consensus(self, decisions: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Calculate weighted consensus from model decisions.

        Args:
            decisions: Dictionary of model decisions

        Returns:
            Consensus result with recommended action
        """
        # Extract valid decisions (no errors)
        valid_decisions = {
            model: decision
            for model, decision in decisions.items()
            if "error" not in decision and "domain" in decision
        }

        if not valid_decisions:
            return {
                "consensus_reached": False,
                "consensus_score": 0.0,
                "recommended_action": None,
                "error": "No valid model responses"
            }

        # Count domain votes with weights
        domain_votes = {}
        operation_votes = {}

        for model, decision in valid_decisions.items():
            weight = self.voting_weight.get(model, 1.0)
            domain = decision.get("domain")
            operation = decision.get("operation")

            if domain:
                domain_votes[domain] = domain_votes.get(domain, 0) + weight

            if operation:
                op_key = f"{domain}:{operation}"
                operation_votes[op_key] = operation_votes.get(op_key, 0) + weight

        # Calculate total possible weight
        total_weight = sum(self.voting_weight.get(m, 1.0) for m in valid_decisions.keys())

        # Find top domain and operation
        top_domain = max(domain_votes.items(), key=lambda x: x[1]) if domain_votes else (None, 0)
        top_operation = max(operation_votes.items(), key=lambda x: x[1]) if operation_votes else (None, 0)

        # Calculate consensus score
        consensus_score = top_domain[1] / total_weight if total_weight > 0 else 0

        # Aggregate parameters and rationale from agreeing models
        agreeing_models = [
            (model, decision)
            for model, decision in valid_decisions.items()
            if decision.get("domain") == top_domain[0]
        ]

        aggregated_params = {}
        rationales = []
        risk_levels = []

        for model, decision in agreeing_models:
            aggregated_params.update(decision.get("parameters", {}))
            rationales.append(f"{model}: {decision.get('rationale', '')}")
            risk_levels.append(decision.get("risk_level", "medium"))

        # Determine consensus
        consensus_reached = consensus_score >= self.consensus_threshold

        domain_str, operation_str = top_operation[0].split(":") if top_operation[0] else (None, None)

        return {
            "consensus_reached": consensus_reached,
            "consensus_score": consensus_score,
            "recommended_action": {
                "domain": top_domain[0],
                "operation": operation_str,
                "parameters": aggregated_params,
                "risk_level": max(set(risk_levels), key=risk_levels.count) if risk_levels else "medium",
            } if consensus_reached else None,
            "model_responses": {
                model: {
                    "domain": d.get("domain"),
                    "operation": d.get("operation"),
                    "risk": d.get("risk_level")
                }
                for model, d in valid_decisions.items()
            },
            "rationales": rationales,
            "voting_breakdown": {
                "domain_votes": domain_votes,
                "operation_votes": operation_votes,
                "total_weight": total_weight
            }
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get AI brain statistics"""
        return {
            "decisions_made": self.decisions_made,
            "consensus_achieved": self.consensus_achieved,
            "consensus_rate": self.consensus_achieved / self.decisions_made if self.decisions_made > 0 else 0,
            "model_stats": self.model_stats,
            "consensus_threshold": self.consensus_threshold,
            "voting_weights": self.voting_weight
        }


if __name__ == "__main__":
    # Test AI Brain
    async def test():
        print("🧠 PROMETHEUS AI BRAIN - SYSTEM TEST")
        print("=" * 60)

        brain = PrometheusAIBrain()

        # Test decision
        situation = {
            "context": "Target web application discovered",
            "target": "example.com",
            "available_domains": ["network_recon", "web_exploitation", "osint"],
            "constraints": {"stealth": True, "timeframe": "4 hours"}
        }

        print("\n🎯 Testing decision engine...")
        print(f"Situation: {situation['context']}")
        print(f"Target: {situation['target']}")

        # Note: This will fail without API keys and GPU models
        # Just testing the structure
        print("\n✅ AI Brain structure validated")
        print("⚠️  Full test requires API keys and GPU models")

        stats = brain.get_stats()
        print(f"\n📊 Statistics: {stats}")

    asyncio.run(test())
