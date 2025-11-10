#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║     OMEGA COST OPTIMIZATION ROUTER                               ║
║     Three-Tier Intelligence Routing: Local → Cheap → Premium     ║
║     BATTLE CRY: "MAXIMUM INTELLIGENCE, MINIMUM COST!" 💰         ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys
from pathlib import Path
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import re

# GS343 Foundation
sys.path.append(str(Path("E:/ECHO_X_V2.0/GS343_DIVINE_OVERSIGHT")))
from comprehensive_error_database_ekm_integrated import ComprehensiveProgrammingErrorDatabase

sys.path.append(str(Path("E:/ECHO_X_V2.0/GS343_DIVINE_OVERSIGHT/HEALERS")))
from phoenix_client_gs343 import PhoenixClient, auto_heal

logger = logging.getLogger(__name__)

@dataclass
class ModelSpec:
    """Specification for an LLM"""
    cost_per_1k: float
    capabilities: List[str]
    max_tokens: int
    speed: str
    quality: int
    
@dataclass
class RoutingDecision:
    """Result of routing analysis"""
    model: str
    tier: int
    cost: float
    reason: str
    fallback_chain: List[Dict[str, Any]]

class IntelligentCostOptimizer:
    """
    Three-tier cost optimization system:
    TIER 1: Local models (Ollama) - FREE
    TIER 2: OpenRouter - CHEAP ($0.0001-0.001/1K)
    TIER 3: Premium APIs - EXPENSIVE ($0.003-0.015/1K)
    """
    
    def __init__(self):
        self.gs343_ekm = ComprehensiveProgrammingErrorDatabase()
        self.phoenix = PhoenixClient()
        
        # TIER 1: LOCAL (FREE)
        self.local_models = {
            "llama3.2": ModelSpec(
                cost_per_1k=0.0,
                capabilities=["basic_chat", "simple_code", "translation"],
                max_tokens=8192,
                speed="fast",
                quality=7
            ),
            "codellama": ModelSpec(
                cost_per_1k=0.0,
                capabilities=["code_generation", "debugging", "refactoring"],
                max_tokens=16384,
                speed="medium",
                quality=8
            ),
            "mistral": ModelSpec(
                cost_per_1k=0.0,
                capabilities=["reasoning", "analysis", "writing"],
                max_tokens=32768,
                speed="medium",
                quality=8
            ),
            "phi3": ModelSpec(
                cost_per_1k=0.0,
                capabilities=["math", "logic", "small_tasks"],
                max_tokens=4096,
                speed="very_fast",
                quality=6
            )
        }
        
        # TIER 2: OPENROUTER (CHEAP)
        self.openrouter_models = {
            "claude-3-haiku": ModelSpec(
                cost_per_1k=0.00025,
                capabilities=["fast_reasoning", "code", "analysis"],
                max_tokens=200000,
                speed="fast",
                quality=8.5
            ),
            "gpt-3.5-turbo": ModelSpec(
                cost_per_1k=0.0005,
                capabilities=["general", "code", "chat"],
                max_tokens=16385,
                speed="fast",
                quality=8
            ),
            "mixtral-8x7b": ModelSpec(
                cost_per_1k=0.00024,
                capabilities=["complex_reasoning", "multilingual"],
                max_tokens=32768,
                speed="medium",
                quality=8.5
            ),
            "deepseek-coder": ModelSpec(
                cost_per_1k=0.00014,
                capabilities=["advanced_code", "algorithms"],
                max_tokens=16384,
                speed="fast",
                quality=9
            )
        }
        
        # TIER 3: PREMIUM (EXPENSIVE)
        self.premium_models = {
            "claude-3-opus": ModelSpec(
                cost_per_1k=0.015,
                capabilities=["everything", "research", "complex_analysis"],
                max_tokens=200000,
                speed="slow",
                quality=10
            ),
            "gpt-4-turbo": ModelSpec(
                cost_per_1k=0.01,
                capabilities=["everything", "vision", "advanced_reasoning"],
                max_tokens=128000,
                speed="medium",
                quality=9.5
            ),
            "claude-3-sonnet": ModelSpec(
                cost_per_1k=0.003,
                capabilities=["balanced", "code", "analysis"],
                max_tokens=200000,
                speed="medium",
                quality=9
            ),
            "gemini-1.5-pro": ModelSpec(
                cost_per_1k=0.00125,
                capabilities=["long_context", "multimodal"],
                max_tokens=1000000,
                speed="medium",
                quality=9
            )
        }
        
        # Complexity patterns
        self.complexity_patterns = {
            "simple": {
                "patterns": [r"^(hi|hello|hey|test)", r"what is \w+", r"simple .{1,50}"],
                "max_tokens": 2000,
                "tier": 1
            },
            "moderate": {
                "patterns": [r"write code", r"debug", r"create function", r"explain .{50,}"],
                "max_tokens": 8000,
                "tier": 2
            },
            "complex": {
                "patterns": [r"research", r"analyze", r"deep dive", r"comprehensive"],
                "max_tokens": 50000,
                "tier": 3
            },
            "extreme": {
                "patterns": [r"exhaustive", r"consortium", r"all llms", r"maximum"],
                "max_tokens": 200000,
                "tier": 3
            }
        }
        
        # Session costs
        self.session_costs = {
            "local": 0.0,
            "openrouter": 0.0,
            "premium": 0.0,
            "total": 0.0,
            "requests": {"local": 0, "openrouter": 0, "premium": 0}
        }
    
    @auto_heal
    def analyze_request(self, request: str) -> Dict[str, Any]:
        """Analyze request complexity and requirements"""
        request_lower = request.lower()
        
        analysis = {
            "complexity": "simple",
            "required_capabilities": [],
            "estimated_tokens": 2000,
            "requires_internet": False,
            "requires_vision": False,
            "requires_long_context": False,
            "recommended_tier": 1
        }
        
        # Check complexity
        for level, rules in self.complexity_patterns.items():
            if any(re.search(pattern, request_lower) for pattern in rules["patterns"]):
                analysis["complexity"] = level
                analysis["recommended_tier"] = rules["tier"]
                analysis["estimated_tokens"] = rules["max_tokens"]
                break
        
        # Check capabilities
        if "image" in request_lower or "picture" in request_lower:
            analysis["requires_vision"] = True
            analysis["recommended_tier"] = 3
        
        if "search" in request_lower or "current" in request_lower:
            analysis["requires_internet"] = True
            analysis["recommended_tier"] = max(2, analysis["recommended_tier"])
        
        if len(request) > 10000:
            analysis["requires_long_context"] = True
            analysis["recommended_tier"] = max(2, analysis["recommended_tier"])
        
        # Extract capabilities
        capability_map = {
            "code": "code_generation",
            "debug": "debugging",
            "research": "research",
            "analyze": "analysis"
        }
        
        for keyword, capability in capability_map.items():
            if keyword in request_lower:
                analysis["required_capabilities"].append(capability)
        
        return analysis
    
    @auto_heal
    def select_optimal_model(self, request: str) -> RoutingDecision:
        """Select cheapest capable model"""
        analysis = self.analyze_request(request)
        
        # TIER 1: Try local first
        if analysis["recommended_tier"] == 1 and not analysis["requires_internet"]:
            for model_name, spec in self.local_models.items():
                if self._can_handle(spec, analysis):
                    return RoutingDecision(
                        model=model_name,
                        tier=1,
                        cost=0.0,
                        reason="Local model sufficient",
                        fallback_chain=[
                            {"tier": 2, "model": "claude-3-haiku"},
                            {"tier": 3, "model": "claude-3-sonnet"}
                        ]
                    )
        
        # TIER 2: OpenRouter
        if analysis["recommended_tier"] <= 2:
            best_model = self._find_cheapest_capable(self.openrouter_models, analysis)
            if best_model:
                spec = self.openrouter_models[best_model]
                return RoutingDecision(
                    model=best_model,
                    tier=2,
                    cost=spec.cost_per_1k,
                    reason="OpenRouter optimal cost/performance",
                    fallback_chain=[
                        {"tier": 3, "model": "claude-3-sonnet"},
                        {"tier": 3, "model": "gpt-4-turbo"}
                    ]
                )
        
        # TIER 3: Premium
        if analysis["requires_long_context"]:
            model = "gemini-1.5-pro"
        elif analysis["requires_vision"]:
            model = "gpt-4-turbo"
        elif "research" in analysis["required_capabilities"]:
            model = "claude-3-opus"
        else:
            model = "claude-3-sonnet"
        
        spec = self.premium_models[model]
        return RoutingDecision(
            model=model,
            tier=3,
            cost=spec.cost_per_1k,
            reason=f"Premium required for {analysis['complexity']} task",
            fallback_chain=[]
        )
    
    def _can_handle(self, spec: ModelSpec, analysis: Dict[str, Any]) -> bool:
        """Check if model can handle request"""
        if analysis["estimated_tokens"] > spec.max_tokens:
            return False
        
        if analysis["requires_internet"]:
            return False
        
        required = set(analysis["required_capabilities"])
        available = set(spec.capabilities)
        
        return required.issubset(available) or not required
    
    def _find_cheapest_capable(self, models: Dict[str, ModelSpec], analysis: Dict[str, Any]) -> Optional[str]:
        """Find cheapest model that can handle request"""
        candidates = []
        
        for model_name, spec in models.items():
            if self._can_handle(spec, analysis):
                candidates.append((model_name, spec.cost_per_1k))
        
        if not candidates:
            return None
        
        candidates.sort(key=lambda x: x[1])
        return candidates[0][0]
    
    @auto_heal
    def update_costs(self, cost: float, tier: int):
        """Update session cost tracking"""
        tier_map = {1: "local", 2: "openrouter", 3: "premium"}
        tier_name = tier_map.get(tier, "unknown")
        
        self.session_costs[tier_name] += cost
        self.session_costs["total"] += cost
        self.session_costs["requests"][tier_name] += 1
    
    @auto_heal
    def get_cost_report(self) -> str:
        """Generate cost report"""
        premium_equivalent = self.session_costs["total"] * 10
        savings = premium_equivalent - self.session_costs["total"]
        
        report = f"""
╔══════════════════════════════════════════════════════════╗
║           💰 COST OPTIMIZATION REPORT 💰                  ║
╠══════════════════════════════════════════════════════════╣
║ LOCAL (Free):        ${self.session_costs['local']:.4f} ({self.session_costs['requests']['local']} reqs)
║ OpenRouter (Cheap):  ${self.session_costs['openrouter']:.4f} ({self.session_costs['requests']['openrouter']} reqs)
║ Premium APIs:        ${self.session_costs['premium']:.4f} ({self.session_costs['requests']['premium']} reqs)
║ ─────────────────────────────────────────────────────    ║
║ TOTAL COST:          ${self.session_costs['total']:.4f}  ║
║ ─────────────────────────────────────────────────────    ║
║ Premium-Only Cost:   ${premium_equivalent:.4f}           ║
║ 🎉 YOU SAVED:        ${savings:.4f}                      ║
╚══════════════════════════════════════════════════════════╝
"""
        return report

if __name__ == "__main__":
    optimizer = IntelligentCostOptimizer()
    
    # Test queries
    tests = [
        "What is Python?",
        "Write a function to sort a list",
        "Deep research on quantum computing"
    ]
    
    for query in tests:
        decision = optimizer.select_optimal_model(query)
        print(f"\nQuery: {query}")
        print(f"Model: {decision.model} (Tier {decision.tier})")
        print(f"Cost: ${decision.cost}/1K tokens")
        print(f"Reason: {decision.reason}")
