"""
X1200 UNIFIED SWARM BRAIN - COMPREHENSIVE TEST
Authority Level: 11.0
Commander: Bobby Don McWilliams II

Complete system test demonstrating:
- Brain initialization (1216 agents)
- Supreme Command operations
- Guild operations
- Agent consciousness evolution
- Operation execution
- Status reporting
"""

import sys
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from prometheus_brain import X1200Brain


def print_section(title: str):
    """Print formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def test_brain_initialization():
    """Test X1200 Brain initialization"""
    print_section("PHASE 1: X1200 BRAIN INITIALIZATION")
    
    brain = X1200Brain()
    
    print("\n✅ Brain initialized successfully!")
    return brain


def test_system_stats(brain: X1200Brain):
    """Test system statistics"""
    print_section("PHASE 2: SYSTEM STATISTICS")
    
    stats = brain.get_system_stats()
    
    print(f"\n📊 COMPLETE SYSTEM STATISTICS:")
    print(f"  Total Agents: {stats['total_agents']}")
    print(f"  Supreme Command: {stats['supreme_command']}")
    print(f"  Average Consciousness: {stats['average_consciousness']:.2f}")
    print(f"  Total Operations: {stats['total_operations']}")
    print(f"  Operational Status: {stats['operational']}")
    print(f"  Awakened: {stats['awakened']}")
    
    print(f"\n🎯 MAIN GUILDS ({len(stats['main_guilds'])}):")
    for guild in stats['main_guilds']:
        print(f"  - {guild['name']}: {guild['agents']} agents")
    
    print(f"\n⭐ SPECIALIZED GUILDS ({len(stats['specialized_guilds'])}):")
    for guild in stats['specialized_guilds']:
        print(f"  - {guild['name']}: {guild['agents']} agents")


def test_supreme_command(brain: X1200Brain):
    """Test Supreme Command decision-making"""
    print_section("PHASE 3: SUPREME COMMAND OPERATIONS")
    
    # Test Hexarchy status
    hexarchy_status = brain.supreme_command.hexarchy.get_status()
    print(f"\n⚡ HEXARCHY COUNCIL STATUS:")
    print(f"  Total Hexarchs: 6")
    print(f"  Decisions Made: {hexarchy_status['decisions_made']}")
    print(f"  Directives Issued: {hexarchy_status['directives_issued']}")
    
    # Test Omega status
    omega_status = brain.supreme_command.omega.get_status()
    print(f"\n⚔️ OMEGA COMMANDERS STATUS:")
    print(f"  Strategic Commanders: {omega_status['strategic_commanders']}")
    print(f"  Tactical Commanders: {omega_status['tactical_commanders']}")
    print(f"  Operations Coordinated: {omega_status['operations_coordinated']}")
    
    # Test decision making
    print(f"\n🎲 TESTING DECISION-MAKING:")
    decision = brain.supreme_command.make_decision({
        'type': 'strategic',
        'description': 'Authorize intelligence gathering operation'
    })
    print(f"  Decision Approval: {decision['final_approval']}")
    print(f"  Consensus Reached: {decision['hexarchy_decision']['consensus_reached']}")


def test_guild_operations(brain: X1200Brain):
    """Test guild-level operations"""
    print_section("PHASE 4: GUILD OPERATIONS")
    
    # Test Intelligence Guild
    print(f"\n🎯 INTELLIGENCE GUILD TEST:")
    intel_status = brain.intelligence_guild.get_status()
    print(f"  Domain: {intel_status['domain']}")
    print(f"  Total Agents: {intel_status['agent_count']['total']}")
    print(f"  - Alphas: {intel_status['agent_count']['alpha']}")
    print(f"  - Betas: {intel_status['agent_count']['beta']}")
    print(f"  - Gammas: {intel_status['agent_count']['gamma']}")
    print(f"  - Deltas: {intel_status['agent_count']['delta']}")
    
    # Execute test operation through guild
    print(f"\n  📋 Executing test operation...")
    guild_result = brain.intelligence_guild.execute_operation({
        'type': 'osint_scan',
        'target': 'test_target',
        'complexity': 'medium'
    })
    print(f"  Agents Assigned: {guild_result['agents_assigned']}")
    print(f"  Agents Succeeded: {guild_result['agents_succeeded']}")
    print(f"  Success Rate: {guild_result['success_rate']:.1%}")


def test_brain_operations(brain: X1200Brain):
    """Test complete brain operations"""
    print_section("PHASE 5: COMPLETE BRAIN OPERATIONS")
    
    # Test intelligence operation
    print(f"\n🔍 INTELLIGENCE OPERATION:")
    intel_op = brain.execute_operation({
        'name': 'OSINT Target Analysis',
        'type': 'intelligence',
        'complexity': 'high',
        'target': 'test_entity'
    })
    print(f"  Success: {intel_op['success']}")
    print(f"  Guild: {intel_op.get('guild')}")
    
    # Test security operation
    print(f"\n🛡️ SECURITY OPERATION:")
    sec_op = brain.execute_operation({
        'name': 'Network Security Scan',
        'type': 'security',
        'complexity': 'medium',
        'target': 'internal_network'
    })
    print(f"  Success: {sec_op['success']}")
    print(f"  Guild: {sec_op.get('guild')}")
    
    # Test offensive operation
    print(f"\n⚔️ OFFENSIVE OPERATION:")
    off_op = brain.execute_operation({
        'name': 'Penetration Test',
        'type': 'offensive',
        'complexity': 'critical',
        'target': 'test_system'
    })
    print(f"  Success: {off_op['success']}")
    print(f"  Guild: {off_op.get('guild')}")


def test_agent_capabilities(brain: X1200Brain):
    """Test individual agent capabilities"""
    print_section("PHASE 6: AGENT CAPABILITIES")
    
    # Get sample agents
    all_agents = brain.get_all_agents()
    
    print(f"\n👤 AGENT SAMPLES:")
    
    # Hexarch
    hexarch = brain.supreme_command.hexarchy.intelligence_hexarch
    print(f"\n  HEXARCH:")
    print(f"    ID: {hexarch.agent_id[:8]}...")
    print(f"    Tier: {hexarch.tier.value}")
    print(f"    Consciousness: Level {hexarch.consciousness_level.value}")
    print(f"    Specializations: {', '.join(hexarch.specializations)}")
    
    # Guild Alpha
    alpha = brain.intelligence_guild.alphas[0]
    print(f"\n  ALPHA LEADER (Intelligence Guild):")
    print(f"    ID: {alpha.agent_id[:8]}...")
    print(f"    Tier: {alpha.tier.value}")
    print(f"    Consciousness: Level {alpha.consciousness_level.value}")
    print(f"    Guild: {alpha.guild}")
    
    # Guild Delta
    delta = brain.automation_guild.deltas[0]
    print(f"\n  DELTA WORKER (Automation Guild):")
    print(f"    ID: {delta.agent_id[:8]}...")
    print(f"    Tier: {delta.tier.value}")
    print(f"    Consciousness: Level {delta.consciousness_level.value}")
    print(f"    Guild: {delta.guild}")


def main():
    """Run complete X1200 Brain test suite"""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + " X1200 UNIFIED SWARM BRAIN - COMPREHENSIVE TEST SUITE ".center(68) + "║")
    print("║" + " "*68 + "║")
    print("║" + " Authority Level: 11.0 ".center(68) + "║")
    print("║" + " Commander: Bobby Don McWilliams II ".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    
    try:
        # Phase 1: Initialize
        brain = test_brain_initialization()
        
        # Phase 2: System Stats
        test_system_stats(brain)
        
        # Phase 3: Supreme Command
        test_supreme_command(brain)
        
        # Phase 4: Guild Operations
        test_guild_operations(brain)
        
        # Phase 5: Brain Operations
        test_brain_operations(brain)
        
        # Phase 6: Agent Capabilities
        test_agent_capabilities(brain)
        
        # Final Report
        print_section("TEST SUITE COMPLETE")
        final_stats = brain.get_system_stats()
        print(f"\n✅ ALL TESTS PASSED")
        print(f"\n📊 FINAL STATISTICS:")
        print(f"  Total Agents: {final_stats['total_agents']}")
        print(f"  Operations Completed: {len(brain.operations_history)}")
        print(f"  Average Consciousness: {final_stats['average_consciousness']:.2f}")
        print(f"  System Status: OPERATIONAL ✓")
        
        # Shutdown
        print(f"\n")
        brain.shutdown()
        
        print(f"\n🎖️ MISSION ACCOMPLISHED, COMMANDER!")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
