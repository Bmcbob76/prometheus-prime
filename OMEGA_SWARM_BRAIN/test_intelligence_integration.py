#!/usr/bin/env python3
"""
OMEGA SWARM BRAIN - INTELLIGENCE INTEGRATION TEST
Tests Advanced Intelligence Core integration
Commander: Bobby Don McWilliams II
"""

import asyncio
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from omega_advanced_intelligence import get_intelligence_core


async def test_iq_calculation():
    """Test IQ calculation system"""
    print("\n🧠 === TESTING IQ CALCULATION ===")
    core = get_intelligence_core()
    
    result = await core.calculate_iq()
    print(f"✅ Composite IQ: {result['composite_iq']}")
    print(f"✅ Classification: {result['classification']}")
    print(f"✅ Percentile: {result['percentile']}")
    
    return result['composite_iq'] > 0


async def test_swarm_consensus():
    """Test swarm consensus building"""
    print("\n🤖 === TESTING SWARM CONSENSUS ===")
    core = get_intelligence_core()
    
    result = await core.build_swarm_consensus(
        "What is the optimal approach?",
        ["GPT-4o", "Claude-4", "Gemini-2.5"]
    )
    
    print(f"✅ Consensus Reached: {result['consensus_reached']}")
    print(f"✅ Avg Confidence: {result['avg_confidence']}")
    print(f"✅ Models Voted: {len(result['votes'])}")
    
    return result['consensus_reached']


async def test_pattern_recognition():
    """Test pattern recognition"""
    print("\n🔍 === TESTING PATTERN RECOGNITION ===")
    core = get_intelligence_core()
    
    test_data = [1, 2, 3, 1, 2, 3, 4, 5]
    result = await core.recognize_pattern(test_data)
    
    print(f"✅ Patterns Found: {result['patterns_found']}")
    for pattern in result['patterns']:
        print(f"   - {pattern['type']}: {pattern['description']}")
    
    return result['patterns_found'] > 0


async def test_problem_solving():
    """Test problem solving"""
    print("\n💡 === TESTING PROBLEM SOLVING ===")
    core = get_intelligence_core()
    
    result = await core.solve_problem(
        "Optimize system performance under heavy load",
        "decomposition"
    )
    
    print(f"✅ Strategy Used: {result['strategy']}")
    print(f"✅ Confidence: {result['confidence']}")
    print(f"✅ Steps: {len(result['steps'])}")
    
    return result['confidence'] > 0.7


async def test_strategic_analysis():
    """Test strategic analysis"""
    print("\n📊 === TESTING STRATEGIC ANALYSIS ===")
    core = get_intelligence_core()
    
    result = await core.strategic_analysis(
        "Market expansion into new territories",
        "30 days"
    )
    
    print(f"✅ Risk Level: {result['risk_level']}")
    print(f"✅ Opportunities: {len(result['opportunities'])}")
    print(f"✅ Threats: {len(result['threats'])}")
    print(f"✅ Recommendations: {len(result['recommendations'])}")
    
    return result['confidence'] > 0.7


async def test_memory_enhancement():
    """Test memory enhancement"""
    print("\n💾 === TESTING MEMORY ENHANCEMENT ===")
    core = get_intelligence_core()
    
    initial_metrics = core.memory_enhancement.copy()
    result = await core.enhance_memory({}, 'all')
    
    improved = any(
        result['current_metrics'][k] > initial_metrics[k]
        for k in initial_metrics.keys()
    )
    
    print(f"✅ Recall Accuracy: {result['current_metrics']['recall_accuracy']:.3f}")
    print(f"✅ Retention Rate: {result['current_metrics']['retention_rate']:.3f}")
    print(f"✅ Improvement Detected: {improved}")
    
    return True


async def test_meta_learning():
    """Test meta-learning"""
    print("\n🎓 === TESTING META-LEARNING ===")
    core = get_intelligence_core()
    
    training_data = [
        {'task': 'classification', 'samples': 100},
        {'task': 'regression', 'samples': 150}
    ]
    
    result = await core.train_meta_learning('machine_learning', training_data)
    
    print(f"✅ Task Family: {result['task_family']}")
    print(f"✅ Samples Trained: {result['samples_trained']}")
    print(f"✅ Transfer Rate: {result['current_transfer_rate']:.3f}")
    
    return result['samples_trained'] == len(training_data)


async def test_full_optimization():
    """Test full intelligence optimization"""
    print("\n⚡ === TESTING FULL OPTIMIZATION ===")
    core = get_intelligence_core()
    
    result = await core.optimize_intelligence()
    
    print(f"✅ Optimization Complete: {result['optimization_complete']}")
    print(f"✅ New IQ: {result['new_iq']:.2f}")
    print(f"✅ Improvements Made: {len(result['improvements'])}")
    
    for key, value in result['improvements'].items():
        print(f"   - {key}: {value}")
    
    return result['optimization_complete']


async def test_status_reporting():
    """Test status reporting"""
    print("\n📈 === TESTING STATUS REPORTING ===")
    core = get_intelligence_core()
    
    status = core.get_intelligence_status()
    
    print(f"✅ Current IQ: {status['intelligence_metrics']['current_iq']}")
    print(f"✅ Peak IQ: {status['intelligence_metrics']['peak_iq']}")
    print(f"✅ Pattern Recognition: {status['intelligence_metrics']['pattern_recognition']:.2%}")
    print(f"✅ Problem Solving: {status['intelligence_metrics']['problem_solving']:.2%}")
    print(f"✅ Trainers Active: {status['trainers_active']}")
    
    return status['trainers_active'] > 0


async def run_all_tests():
    """Run complete test suite"""
    print("\n" + "="*70)
    print("🧠 OMEGA ADVANCED INTELLIGENCE - INTEGRATION TEST SUITE")
    print("="*70)
    
    tests = [
        ("IQ Calculation", test_iq_calculation),
        ("Swarm Consensus", test_swarm_consensus),
        ("Pattern Recognition", test_pattern_recognition),
        ("Problem Solving", test_problem_solving),
        ("Strategic Analysis", test_strategic_analysis),
        ("Memory Enhancement", test_memory_enhancement),
        ("Meta-Learning", test_meta_learning),
        ("Full Optimization", test_full_optimization),
        ("Status Reporting", test_status_reporting)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            passed = await test_func()
            results.append((test_name, passed))
            print(f"{'✅' if passed else '❌'} {test_name}: {'PASSED' if passed else 'FAILED'}")
        except Exception as e:
            results.append((test_name, False))
            print(f"❌ {test_name}: EXCEPTION - {e}")
    
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"Passed: {passed}/{total} ({passed/total*100:.1f}%)")
    print(f"Failed: {total-passed}/{total}")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED - INTEGRATION SUCCESSFUL")
        return 0
    else:
        print("\n⚠️ SOME TESTS FAILED - REVIEW REQUIRED")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
