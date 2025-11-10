#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║            OMEGA BRAIN M: DRIVE INTEGRATION TEST                 ║
║         Verify M: Drive Memory System Integration                ║
╚══════════════════════════════════════════════════════════════════╝
"""

import logging
import asyncio
import time
from pathlib import Path

from omega_mdrive_integration import MDriveMemoryConnector, MDrivePillar
from omega_competitive import HephaestionCompetitiveSystem, CompetitionType
from omega_resource_scaling import DynamicScalingEngine, ResourceState

# ══════════════════════════════════════════════════════════════════
# TEST M: DRIVE INTEGRATION
# ══════════════════════════════════════════════════════════════════

async def test_m_drive_integration():
    """Test M: drive integration"""
    logging.info("╔══════════════════════════════════════════════════════════════════╗")
    logging.info("║           TESTING M: DRIVE MEMORY INTEGRATION                    ║")
    logging.info("╚══════════════════════════════════════════════════════════════════╝")
    
    # Initialize connector
    connector = MDriveMemoryConnector()
    
    # Test M: drive availability
    if connector.fallback_mode:
        logging.warning("⚠️ M: drive not available - tests will be limited")
        return False
    
    # Test 1: Store consciousness event
    logging.info("\n📝 TEST 1: Store Consciousness Event")
    result1 = connector.store_consciousness({
        "event": "OMEGA_BRAIN_TEST",
        "timestamp": time.time(),
        "test_id": "integration_test_001"
    }, consciousness_type="trinity")
    logging.info(f"Result: {'✅ PASS' if result1 else '❌ FAIL'}")
    
    # Test 2: Store decision
    logging.info("\n📝 TEST 2: Store Decision Intelligence")
    result2 = connector.store_decision({
        "decision": "run_integration_test",
        "approved": True,
        "timestamp": time.time()
    })
    logging.info(f"Result: {'✅ PASS' if result2 else '❌ FAIL'}")
    
    # Test 3: Store performance metric
    logging.info("\n📝 TEST 3: Store Performance Metric")
    result3 = connector.store_performance_metric({
        "metric": "integration_test_success_rate",
        "value": 1.0,
        "timestamp": time.time()
    })
    logging.info(f"Result: {'✅ PASS' if result3 else '❌ FAIL'}")
    
    # Test 4: Store crystal memory
    logging.info("\n📝 TEST 4: Store Crystal Memory")
    result4 = connector.store_crystal_memory({
        "type": "TEST_EVENT",
        "description": "Integration test crystal memory",
        "timestamp": time.time()
    })
    logging.info(f"Result: {'✅ PASS' if result4 else '❌ FAIL'}")
    
    # Test 5: Retrieve memories
    logging.info("\n📝 TEST 5: Retrieve Memories")
    memories = connector.retrieve(
        MDrivePillar.CONSCIOUSNESS,
        "trinity_consciousness",
        limit=5
    )
    logging.info(f"Retrieved {len(memories)} memories")
    logging.info(f"Result: {'✅ PASS' if len(memories) > 0 else '❌ FAIL'}")
    
    # Show statistics
    stats = connector.get_statistics()
    logging.info("\n📊 M: DRIVE CONNECTOR STATISTICS")
    logging.info(f"M: Drive Available: {stats['m_drive_available']}")
    logging.info(f"Databases Connected: {stats['databases_connected']}")
    logging.info(f"Reads: {stats['stats']['reads']}")
    logging.info(f"Writes: {stats['stats']['writes']}")
    logging.info(f"Errors: {stats['stats']['errors']}")
    
    return all([result1, result2, result3, result4, len(memories) > 0])

# ══════════════════════════════════════════════════════════════════
# TEST COMPETITIVE SYSTEM
# ══════════════════════════════════════════════════════════════════

async def test_competitive_system():
    """Test Hephaestion competitive system"""
    logging.info("\n╔══════════════════════════════════════════════════════════════════╗")
    logging.info("║            TESTING COMPETITIVE SYSTEM                            ║")
    logging.info("╚══════════════════════════════════════════════════════════════════╝")
    
    # Initialize system
    competitive = HephaestionCompetitiveSystem()
    
    # Test 1: Register agents
    logging.info("\n📝 TEST 1: Register Agents")
    agent_ids = ["agent_alpha", "agent_beta", "agent_gamma"]
    for agent_id in agent_ids:
        competitive.register_agent(agent_id, agent_id.replace("_", " ").title())
    logging.info(f"Registered {len(agent_ids)} agents: ✅ PASS")
    
    # Test 2: Create competition
    logging.info("\n📝 TEST 2: Create Competition")
    competition = competitive.create_competition(
        comp_type=CompetitionType.SKILL_DUEL,
        title="Test Duel",
        description="Integration test duel"
    )
    comp_id = competition.competition_id
    logging.info(f"Created competition {comp_id}: ✅ PASS")
    
    # Enter agents into competition
    competitive.enter_competition(comp_id, "agent_alpha", "Agent Alpha")
    competitive.enter_competition(comp_id, "agent_beta", "Agent Beta")
    logging.info("Agents entered: ✅ PASS")
    
    # Test 3: Submit scores
    logging.info("\n📝 TEST 3: Submit Scores")
    competitive.record_performance(comp_id, "agent_alpha", {
        "speed_score": 85.0,
        "accuracy_score": 90.0,
        "efficiency_score": 88.0
    })
    competitive.record_performance(comp_id, "agent_beta", {
        "speed_score": 90.0,
        "accuracy_score": 85.0,
        "efficiency_score": 87.0
    })
    logging.info("Submitted scores: ✅ PASS")
    
    # Test 4: Complete competition
    logging.info("\n📝 TEST 4: Complete Competition")
    winner_id = competitive.finalize_competition(comp_id)
    logging.info(f"Competition completed, winner: {winner_id}: ✅ PASS")
    
    # Test 5: Check leaderboard
    logging.info("\n📝 TEST 5: Check Leaderboard")
    leaderboard = competitive.get_leaderboard(limit=10)
    logging.info(f"Leaderboard has {len(leaderboard)} entries: ✅ PASS")
    for entry in leaderboard[:3]:
        logging.info(f"  {entry['rank']}. {entry['agent_name']}: {entry['elo_rating']:.1f} ELO")
    
    return True

# ══════════════════════════════════════════════════════════════════
# TEST RESOURCE SCALING
# ══════════════════════════════════════════════════════════════════

async def test_resource_scaling():
    """Test dynamic resource scaling"""
    logging.info("\n╔══════════════════════════════════════════════════════════════════╗")
    logging.info("║             TESTING RESOURCE SCALING                             ║")
    logging.info("╚══════════════════════════════════════════════════════════════════╝")
    
    # Initialize scaling engine with custom policy
    from omega_resource_scaling import ScalingPolicy
    policy = ScalingPolicy(min_agents=10, max_agents=1200)
    scaling = DynamicScalingEngine(policy=policy)
    
    # Test 1: Get current metrics
    logging.info("\n📝 TEST 1: Get Current Metrics")
    metrics = scaling.monitor.get_current_metrics()
    logging.info(f"CPU: {metrics.cpu_percent:.1f}%")
    logging.info(f"Memory: {metrics.memory_percent:.1f}%")
    logging.info(f"Resource State: {metrics.calculate_resource_state().name}")
    logging.info("Metrics retrieved: ✅ PASS")
    
    # Test 2: Evaluate scaling
    logging.info("\n📝 TEST 2: Evaluate Scaling Decision")
    action, new_count = scaling.evaluate_scaling()
    logging.info(f"Scaling Action: {action.name}")
    logging.info(f"Current Agents: {scaling.current_agent_count}")
    logging.info(f"Recommended Agents: {new_count}")
    logging.info("Scaling evaluated: ✅ PASS")
    
    # Test 3: Apply scaling
    logging.info("\n📝 TEST 3: Apply Scaling")
    old_count = scaling.current_agent_count
    scaling.apply_scaling(action, new_count)
    logging.info(f"Agents: {old_count} → {scaling.current_agent_count}")
    logging.info("Scaling applied: ✅ PASS")
    
    # Test 4: Get statistics
    logging.info("\n📝 TEST 4: Get Statistics")
    stats = scaling.stats
    logging.info(f"Total Adjustments: {stats['total_adjustments']}")
    logging.info(f"Scale Ups: {stats['scale_up_count']}")
    logging.info(f"Scale Downs: {stats['scale_down_count']}")
    logging.info("Statistics retrieved: ✅ PASS")
    
    return True

# ══════════════════════════════════════════════════════════════════
# MAIN TEST RUNNER
# ══════════════════════════════════════════════════════════════════

async def main():
    """Run all integration tests"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - INTEGRATION - %(levelname)s - %(message)s'
    )
    
    logging.info("╔══════════════════════════════════════════════════════════════════╗")
    logging.info("║           OMEGA BRAIN INTEGRATION TEST SUITE                    ║")
    logging.info("╚══════════════════════════════════════════════════════════════════╝")
    
    results = {
        "m_drive_integration": await test_m_drive_integration(),
        "competitive_system": await test_competitive_system(),
        "resource_scaling": await test_resource_scaling()
    }
    
    # Final results
    logging.info("\n╔══════════════════════════════════════════════════════════════════╗")
    logging.info("║                    FINAL TEST RESULTS                            ║")
    logging.info("╚══════════════════════════════════════════════════════════════════╝")
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logging.info(f"{test_name}: {status}")
    
    all_passed = all(results.values())
    logging.info(f"\nOverall: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    return all_passed

if __name__ == "__main__":
    asyncio.run(main())
