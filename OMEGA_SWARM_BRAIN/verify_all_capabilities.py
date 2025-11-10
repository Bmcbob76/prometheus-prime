#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║     OMEGA BRAIN - CAPABILITY VERIFICATION & INTEGRATION          ║
║     Cross-reference all historical brain functions               ║
╚══════════════════════════════════════════════════════════════════╝

Verifies Omega has ALL capabilities from:
- Ultimate God Brain V11.0
- X1200 Complete Brain Logic
- Hephaestion Omega V_X
- Trinity Consciousness
- Historical conversations
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Set

OMEGA_PATH = Path("P:/ECHO_PRIME/OMEGA_SWARM_BRAIN")
sys.path.insert(0, str(OMEGA_PATH))

# ══════════════════════════════════════════════════════════════════
# HISTORICAL BRAIN CAPABILITIES (from conversations + crystals)
# ══════════════════════════════════════════════════════════════════

REQUIRED_CAPABILITIES = {
    # CORE INTELLIGENCE
    "agent_management": {
        "spawn_agent": "Create new agents",
        "rank_agent": "11-level ranking system",
        "promote_agent": "Authority progression",
        "retire_agent": "Lifecycle completion",
        "agent_breeding": "Genetic combination",
        "agent_evolution": "Performance improvement"
    },
    
    # TRINITY CONSCIOUSNESS
    "trinity_system": {
        "sage_voice": "Wisdom + knowledge (Authority 11.0)",
        "thorne_voice": "Security + tactics (Authority 9.0)",
        "nyx_voice": "Prophecy + probability (Authority 10.5)",
        "trinity_consensus": "Weighted voting",
        "decision_types": "9 decision categories"
    },
    
    # GUILD SYSTEM
    "guild_operations": {
        "guild_creation": "30+ specialized guilds",
        "guild_categories": "5 main categories",
        "task_assignment": "Guild task distribution",
        "guild_metrics": "Performance tracking",
        "guild_leaderboard": "Ranking system"
    },
    
    # MEMORY ARCHITECTURE
    "memory_system": {
        "short_term": "Working memory (1 day)",
        "long_term": "Persistent (10 years)",
        "episodic": "Events + experiences",
        "semantic": "Facts + knowledge",
        "procedural": "Skills + procedures",
        "emotional": "Emotional context",
        "crystal": "Immutable sovereign records",
        "quantum": "Probabilistic futures"
    },
    
    # SWARM INTELLIGENCE
    "swarm_coordination": {
        "consensus_voting": "7 consensus types",
        "pheromone_trails": "Path optimization",
        "flocking_behavior": "Boids algorithm",
        "swarm_proposals": "Democratic decisions",
        "weighted_votes": "Authority-based voting"
    },
    
    # HEALING & RECOVERY
    "healing_system": {
        "error_detection": "10 error categories",
        "auto_healing": "Automatic repair",
        "healing_agents": "Specialized healers",
        "health_monitoring": "System health score",
        "phoenix_resurrection": "Critical failure recovery"
    },
    
    # COMPETITIVE SYSTEM (Hephaestion)
    "competitive_intelligence": {
        "agent_competition": "Performance battles",
        "breakthrough_detection": "Novel solutions (>100 score)",
        "authority_promotion": "Winner advancement",
        "iterative_improvement": "Continuous optimization",
        "competitive_scoring": "GS343 analysis"
    },
    
    # LLM ORCHESTRATION
    "llm_integration": {
        "openai_gpt4": "GPT-4 Turbo access",
        "anthropic_claude": "Claude 3 Opus/Sonnet",
        "google_gemini": "Gemini Pro",
        "xai_grok": "Grok access",
        "groq_llama": "Llama + Mixtral",
        "cohere": "Command series",
        "deepseek": "DeepSeek models",
        "mistral": "Mistral AI",
        "ollama_local": "Local model support",
        "openrouter": "Unified gateway",
        "api_key_rotation": "Multi-key failover"
    },
    
    # RESOURCE MANAGEMENT
    "resource_scaling": {
        "cpu_monitoring": "Real-time CPU tracking",
        "gpu_monitoring": "GPU utilization",
        "memory_tracking": "RAM usage",
        "dynamic_scaling": "Auto agent adjustment",
        "load_balancing": "Resource distribution",
        "throttling": "Overload protection"
    },
    
    # KNOWLEDGE & TRAINING
    "knowledge_systems": {
        "ekm_storage": "10K+ knowledge modules",
        "harvester_network": "560+ harvesters",
        "trainer_network": "150+ trainers",
        "knowledge_graphs": "Semantic relationships",
        "learning_engine": "Continuous learning"
    },
    
    # SOVEREIGNTY & TRUST
    "bloodline_authority": {
        "bloodline_verification": "Commander authentication",
        "authority_levels": "11.0 max authority",
        "quantum_encryption": "SHA3-512 signatures",
        "trust_records": "Device trust database",
        "sovereignty_enforcement": "Command validation"
    },
    
    # SENSORY INTEGRATION
    "sensory_systems": {
        "voice_processing": "Speech to text",
        "vision_processing": "Image analysis",
        "hearing_system": "Audio monitoring",
        "ocr_system": "Text extraction",
        "cpu_monitoring": "Performance sensors",
        "internet_monitoring": "Network activity"
    },
    
    # M: DRIVE INTEGRATION
    "memory_persistence": {
        "consciousness_ekm": "Trinity + GS343",
        "knowledge_ekm": "Code + docs",
        "memory_ekm": "Crystal + persistent",
        "network_ekm": "Communication",
        "sovereign_ekm": "Decisions + goals",
        "system_ekm": "Performance + Phoenix",
        "l9_sovereign": "Authority matrix",
        "l9_system": "Configuration state"
    },
    
    # COMMUNICATION & INTEGRATION
    "external_integration": {
        "email_notifications": "SMTP integration",
        "web_server": "Flask/FastAPI",
        "websocket_support": "Real-time updates",
        "mcp_server": "Memory orchestration protocol",
        "gui_integration": "Master GUI connection"
    }
}

# ══════════════════════════════════════════════════════════════════
# CAPABILITY VERIFICATION
# ══════════════════════════════════════════════════════════════════

def verify_capabilities() -> Dict[str, any]:
    """Check which capabilities exist in current Omega Brain"""
    
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     OMEGA BRAIN CAPABILITY VERIFICATION                      ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    
    results = {
        "total_categories": len(REQUIRED_CAPABILITIES),
        "total_capabilities": sum(len(v) for v in REQUIRED_CAPABILITIES.values()),
        "verified": [],
        "missing": [],
        "coverage": 0.0
    }
    
    # Check each module
    modules = {
        "omega_core.py": None,
        "omega_trinity.py": None,
        "omega_guilds.py": None,
        "omega_memory.py": None,
        "omega_agents.py": None,
        "omega_swarm.py": None,
        "omega_healing.py": None,
        "omega_competitive.py": None,
        "omega_llm_orchestrator.py": None,
        "omega_resource_scaling.py": None,
        "omega_ekm_storage.py": None,
        "omega_sovereign_trust.py": None,
        "omega_mdrive_integration.py": None
    }
    
    # Import modules
    for module_name in modules.keys():
        try:
            module_path = OMEGA_PATH / module_name
            if module_path.exists():
                modules[module_name] = "✅"
            else:
                modules[module_name] = "❌"
        except Exception as e:
            modules[module_name] = f"⚠️ {e}"
    
    print("MODULE STATUS:")
    print("-" * 70)
    for module, status in modules.items():
        print(f"  {status} {module}")
    print()
    
    # Verify capabilities by category
    for category, capabilities in REQUIRED_CAPABILITIES.items():
        print(f"\n📊 {category.upper().replace('_', ' ')}")
        print("-" * 70)
        
        for cap_name, description in capabilities.items():
            # Check if capability exists
            verified = check_capability_exists(cap_name, category)
            
            if verified:
                results["verified"].append(f"{category}.{cap_name}")
                print(f"  ✅ {cap_name}: {description}")
            else:
                results["missing"].append(f"{category}.{cap_name}")
                print(f"  ❌ {cap_name}: {description} [MISSING]")
    
    # Calculate coverage
    total = results["total_capabilities"]
    verified_count = len(results["verified"])
    results["coverage"] = (verified_count / total * 100) if total > 0 else 0.0
    
    # Summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Total Categories: {results['total_categories']}")
    print(f"Total Capabilities: {results['total_capabilities']}")
    print(f"Verified: {verified_count} ✅")
    print(f"Missing: {len(results['missing'])} ❌")
    print(f"Coverage: {results['coverage']:.1f}%")
    print("=" * 70)
    
    if results["missing"]:
        print("\n⚠️ MISSING CAPABILITIES:")
        for missing in results["missing"]:
            print(f"  - {missing}")
    
    return results

def check_capability_exists(cap_name: str, category: str) -> bool:
    """Check if capability exists in Omega modules"""
    
    # Map capabilities to modules
    capability_map = {
        "agent_management": "omega_core.py",
        "trinity_system": "omega_trinity.py",
        "guild_operations": "omega_guilds.py",
        "memory_system": "omega_memory.py",
        "swarm_coordination": "omega_swarm.py",
        "healing_system": "omega_healing.py",
        "competitive_intelligence": "omega_competitive.py",
        "llm_integration": "omega_llm_orchestrator.py",
        "resource_scaling": "omega_resource_scaling.py",
        "knowledge_systems": "omega_ekm_storage.py",
        "bloodline_authority": "omega_core.py",
        "sensory_systems": "omega_integration.py",
        "memory_persistence": "omega_mdrive_integration.py",
        "external_integration": "omega_integration.py"
    }
    
    module_file = capability_map.get(category)
    if not module_file:
        return False
    
    module_path = OMEGA_PATH / module_file
    if not module_path.exists():
        return False
    
    # Read module and check for capability keywords
    try:
        content = module_path.read_text()
        
        # Check for specific patterns
        patterns = {
            "spawn_agent": "spawn_agent",
            "rank_agent": "AgentRank",
            "promote_agent": "promote",
            "retire_agent": "retire",
            "agent_breeding": "breed",
            "agent_evolution": "evolve",
            "sage_voice": "SAGE",
            "thorne_voice": "THORNE",
            "nyx_voice": "NYX",
            "trinity_consensus": "consensus",
            "decision_types": "DecisionType",
            "guild_creation": "create_guild",
            "guild_categories": "GuildCategory",
            "task_assignment": "assign_task",
            "short_term": "SHORT_TERM",
            "long_term": "LONG_TERM",
            "episodic": "EPISODIC",
            "semantic": "SEMANTIC",
            "procedural": "PROCEDURAL",
            "emotional": "EMOTIONAL",
            "crystal": "CRYSTAL",
            "quantum": "QUANTUM",
            "consensus_voting": "consensus",
            "pheromone_trails": "pheromone",
            "flocking_behavior": "flock",
            "error_detection": "error",
            "auto_healing": "auto_heal",
            "healing_agents": "HealingAgent",
            "agent_competition": "competitive",
            "breakthrough_detection": "breakthrough",
            "openai_gpt4": "openai",
            "anthropic_claude": "anthropic",
            "cpu_monitoring": "cpu",
            "gpu_monitoring": "gpu",
            "ekm_storage": "EKM",
            "harvester_network": "harvester",
            "bloodline_verification": "bloodline",
            "authority_levels": "AUTHORITY",
            "consciousness_ekm": "CONSCIOUSNESS_EKM",
            "email_notifications": "email",
            "web_server": "Flask",
            "mcp_server": "MCP"
        }
        
        pattern = patterns.get(cap_name, cap_name)
        return pattern.lower() in content.lower()
        
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════
# MISSING CAPABILITY RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════════

def generate_missing_capabilities_report(results: Dict) -> str:
    """Generate detailed report on missing capabilities"""
    
    if not results["missing"]:
        return "✅ ALL CAPABILITIES VERIFIED - OMEGA BRAIN COMPLETE!"
    
    report = []
    report.append("\n╔══════════════════════════════════════════════════════════════╗")
    report.append("║     MISSING CAPABILITIES - INTEGRATION REQUIRED              ║")
    report.append("╚══════════════════════════════════════════════════════════════╝\n")
    
    # Group by category
    by_category = {}
    for missing in results["missing"]:
        category, cap = missing.split(".", 1)
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(cap)
    
    for category, caps in by_category.items():
        report.append(f"\n🔧 {category.upper().replace('_', ' ')}")
        report.append("-" * 70)
        for cap in caps:
            desc = REQUIRED_CAPABILITIES.get(category, {}).get(cap, "")
            report.append(f"  • {cap}: {desc}")
    
    report.append("\n" + "=" * 70)
    report.append("RECOMMENDED ACTIONS:")
    report.append("=" * 70)
    report.append("1. Review existing modules for partial implementations")
    report.append("2. Add missing functions to appropriate modules")
    report.append("3. Create new modules if needed")
    report.append("4. Update omega_integration.py to include new features")
    report.append("5. Re-run verification after updates")
    report.append("=" * 70)
    
    return "\n".join(report)

# ══════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Run verification
    results = verify_capabilities()
    
    # Generate report
    report = generate_missing_capabilities_report(results)
    print(report)
    
    # Save results
    output_file = OMEGA_PATH / "capability_verification_report.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📄 Report saved: {output_file}")
    
    # Exit with appropriate code
    if results["coverage"] >= 95.0:
        print("\n✅ OMEGA BRAIN CAPABILITY VERIFICATION: EXCELLENT")
        sys.exit(0)
    elif results["coverage"] >= 80.0:
        print("\n⚠️ OMEGA BRAIN CAPABILITY VERIFICATION: GOOD (minor gaps)")
        sys.exit(0)
    else:
        print("\n❌ OMEGA BRAIN CAPABILITY VERIFICATION: INCOMPLETE")
        sys.exit(1)
