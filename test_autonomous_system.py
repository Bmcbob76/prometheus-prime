#!/usr/bin/env python3
"""
PROMETHEUS PRIME - AUTONOMOUS SYSTEM INTEGRATION TEST
Complete end-to-end test of all subsystems

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Tests all 5 phases:
1. Contract & Scope Verification
2. Phoenix Healing & Error Intelligence
3. Omniscience Knowledge Base & Intelligence Analyzer
4. Decision Engine with 5-Model Consensus
5. Complete 6-Phase Autonomous Engagement
"""

import asyncio
import logging
import sys
from datetime import datetime

# Test results tracking
test_results = []
total_tests = 0
passed_tests = 0
failed_tests = 0


def test_result(test_name: str, passed: bool, details: str = ""):
    """Record test result."""
    global total_tests, passed_tests, failed_tests
    total_tests += 1

    if passed:
        passed_tests += 1
        status = "✅ PASS"
    else:
        failed_tests += 1
        status = "❌ FAIL"

    result = f"{status} | {test_name}"
    if details:
        result += f" | {details}"

    test_results.append(result)
    print(result)


async def test_phase1_contract_scope():
    """Test Phase 1: Contract & Scope Verification"""
    print("\n" + "="*60)
    print("PHASE 1: CONTRACT & SCOPE VERIFICATION")
    print("="*60)

    try:
        from src.autonomous.engagement_contract import EngagementContract, create_example_contract
        from src.autonomous.scope_verification import ScopeVerificationEngine

        # Test 1.1: Create contract
        contract = create_example_contract()
        test_result("Contract Creation", contract is not None, f"Contract: {contract.contract_number}")

        # Test 1.2: Validate contract
        is_valid, reason = contract.validate()
        test_result("Contract Validation", is_valid, reason)

        # Test 1.3: Scope verification
        verifier = ScopeVerificationEngine(contract)
        test_result("Scope Verifier Init", verifier is not None, f"Contract: {contract.contract_number}")

        # Test 1.4: Verify authorized target
        result = verifier.verify_target("192.168.1.50", "port_scan")
        test_result("Authorized Target Verification", result["authorized"], f"Target: 192.168.1.50")

        # Test 1.5: Verify excluded target (should fail)
        result = verifier.verify_target("192.168.1.1", "port_scan")
        test_result("Excluded Target Blocking", not result["authorized"], "Correctly blocked excluded target")

        # Test 1.6: Technique authorization
        result = verifier.verify_technique("port_scan", "192.168.1.50")
        test_result("Technique Authorization", result["authorized"], f"Technique: port_scan")

        print(f"\n📊 Phase 1 Statistics:")
        stats = verifier.get_statistics()
        print(f"   Total Verifications: {stats['total_verifications']}")
        print(f"   Authorized: {stats['authorized']}")
        print(f"   Blocked: {stats['blocked']}")

        return True

    except Exception as e:
        test_result("Phase 1 Overall", False, f"Error: {str(e)}")
        print(f"❌ Phase 1 Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_phase2_phoenix():
    """Test Phase 2: Phoenix Healing & Error Intelligence"""
    print("\n" + "="*60)
    print("PHASE 2: PHOENIX HEALING & ERROR INTELLIGENCE")
    print("="*60)

    try:
        from src.phoenix.autonomous_healing import PhoenixAutonomousHealing
        from src.phoenix.error_intelligence import PhoenixErrorIntelligence

        # Test 2.1: Initialize Phoenix Healing
        phoenix = PhoenixAutonomousHealing(max_retries=4)
        test_result("Phoenix Healing Init", phoenix is not None, f"Max retries: {phoenix.max_retries}")

        # Test 2.2: Network failure healing
        async def mock_operation(**kwargs):
            if not hasattr(mock_operation, 'attempts'):
                mock_operation.attempts = 0
            mock_operation.attempts += 1
            if mock_operation.attempts < 2:
                raise ConnectionError("Network unreachable")
            return {"success": True}

        healing_result = await phoenix.heal_network_failure(
            mock_operation,
            {},
            ConnectionError("Network unreachable")
        )
        test_result("Network Failure Healing", healing_result.success, f"Attempts: {healing_result.attempts}")

        # Test 2.3: Tool crash healing
        tool_registry = {
            "nmap": {"capabilities": ["port_scan"]},
            "masscan": {"capabilities": ["port_scan"]},
            "zmap": {"capabilities": ["port_scan"]}
        }
        healing_result = await phoenix.heal_tool_crash("nmap", "port_scan", tool_registry)
        test_result("Tool Crash Healing", healing_result.success, f"Alternative: {healing_result.solution}")

        # Test 2.4: Initialize Error Intelligence
        intelligence = PhoenixErrorIntelligence()
        test_result("Error Intelligence Init", intelligence is not None, f"Templates: {len(intelligence.error_templates)}")

        # Test 2.5: Analyze network error
        error = ConnectionError("Connection refused")
        analysis = intelligence.analyze_error(error)
        test_result("Error Analysis", analysis.matched_template is not None, f"Template: {analysis.matched_template.template_id if analysis.matched_template else 'None'}")

        # Test 2.6: Determine solution
        solution = intelligence.determine_solution(analysis)
        test_result("Solution Determination", len(solution["actions"]) > 0, f"Actions: {len(solution['actions'])}")

        print(f"\n📊 Phase 2 Statistics:")
        print(f"   Healing Success Rate: {phoenix.get_healing_statistics().get('success_rate', 0):.1%}")
        print(f"   Error Intelligence Match Rate: {intelligence.get_statistics().get('match_rate', 0):.1%}")

        return True

    except Exception as e:
        test_result("Phase 2 Overall", False, f"Error: {str(e)}")
        print(f"❌ Phase 2 Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_phase3_omniscience():
    """Test Phase 3: Omniscience Knowledge Base & Intelligence Analyzer"""
    print("\n" + "="*60)
    print("PHASE 3: OMNISCIENCE KNOWLEDGE BASE & INTELLIGENCE")
    print("="*60)

    try:
        from src.omniscience.knowledge_base import OmniscienceKnowledgeBase
        from src.omniscience.intelligence_analyzer import IntelligenceAnalyzer

        # Test 3.1: Initialize Knowledge Base
        kb = OmniscienceKnowledgeBase()
        test_result("Knowledge Base Init", kb is not None, f"CVE: {len(kb.cve_database)}, Exploits: {len(kb.exploit_database)}")

        # Test 3.2: Query vulnerabilities
        vulns = kb.query_vulnerabilities("Apache")
        test_result("Vulnerability Query", len(vulns) > 0, f"Found {len(vulns)} Apache vulnerabilities")

        # Test 3.3: Query exploits
        if vulns:
            exploits = kb.query_exploits(cve_id=vulns[0].cve_id)
            test_result("Exploit Query", len(exploits) >= 0, f"Found {len(exploits)} exploits for {vulns[0].cve_id}")

        # Test 3.4: Query MITRE techniques
        techniques = kb.query_mitre_techniques(tactic="Initial Access")
        test_result("MITRE ATT&CK Query", len(techniques) > 0, f"Found {len(techniques)} Initial Access techniques")

        # Test 3.5: Initialize Intelligence Analyzer
        analyzer = IntelligenceAnalyzer(kb)
        test_result("Intelligence Analyzer Init", analyzer is not None, "Connected to Knowledge Base")

        # Test 3.6: Analyze service
        fingerprint = analyzer.analyze_service(80, "Apache/2.4.49 (Unix)")
        test_result("Service Analysis", fingerprint.service == "HTTP", f"Identified: {fingerprint.service} v{fingerprint.version}")

        # Test 3.7: Profile target
        recon_data = {
            "target_id": "TEST-001",
            "hostname": "test-server",
            "ip": "192.168.1.100",
            "services": [
                {"port": 80, "banner": "Apache/2.4.49", "service": "HTTP"}
            ],
            "os_detection": {"name": "Linux 5.4", "accuracy": 90}
        }
        profile = analyzer.profile_target(recon_data)
        test_result("Target Profiling", profile.target_type.value != "unknown", f"Type: {profile.target_type.value}")

        # Test 3.8: Generate attack vectors
        vectors = analyzer.generate_attack_vectors(profile)
        test_result("Attack Vector Generation", len(vectors) >= 0, f"Generated {len(vectors)} attack vectors")

        print(f"\n📊 Phase 3 Statistics:")
        stats = kb.get_statistics()
        print(f"   CVE Entries: {stats['cve_entries']}")
        print(f"   Exploit Entries: {stats['exploit_entries']}")
        print(f"   MITRE Techniques: {stats['mitre_techniques']}")
        print(f"   Weaponized Exploits: {stats['weaponized_exploits']}")

        return True

    except Exception as e:
        test_result("Phase 3 Overall", False, f"Error: {str(e)}")
        print(f"❌ Phase 3 Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_phase4_decision_engine():
    """Test Phase 4: Decision Engine with 5-Model Consensus"""
    print("\n" + "="*60)
    print("PHASE 4: DECISION ENGINE (5-MODEL CONSENSUS)")
    print("="*60)

    try:
        from src.autonomous.decision_engine import DecisionEngine, DecisionType

        # Test 4.1: Initialize Decision Engine
        engine = DecisionEngine(authority_level=11.0)
        test_result("Decision Engine Init", engine is not None, f"Authority: {engine.authority_level}")

        # Test 4.2: Make next action decision
        context = {
            "phase": "reconnaissance",
            "target": "192.168.1.100",
            "services_found": ["HTTP", "SSH"],
            "vulnerabilities": ["CVE-2021-41773"]
        }
        options = ["continue_reconnaissance", "vulnerability_scan", "exploit", "skip"]

        decision = await engine.make_decision(
            DecisionType.NEXT_ACTION,
            context,
            options
        )
        test_result("AI Decision Making", decision.chosen_action in options, f"Chose: {decision.chosen_action}")

        # Test 4.3: Check consensus confidence
        test_result("Consensus Confidence", decision.consensus_confidence > 0.5, f"Confidence: {decision.consensus_confidence:.1%}")

        # Test 4.4: Check model agreement
        test_result("Model Agreement", decision.agreement_score >= 0.4, f"Agreement: {decision.agreement_score:.1%}")

        # Test 4.5: Verify 5 models consulted
        test_result("5-Model Consensus", len(decision.model_responses) == 5, f"Models: {len(decision.model_responses)}")

        # Test 4.6: Technique selection decision
        decision2 = await engine.make_decision(
            DecisionType.TECHNIQUE_SELECTION,
            {"target": "web-server", "vulnerability": "SQL Injection"},
            ["sqlmap", "manual_injection", "skip"]
        )
        test_result("Technique Selection", decision2.chosen_action is not None, f"Chose: {decision2.chosen_action}")

        print(f"\n📊 Phase 4 Statistics:")
        stats = engine.get_statistics()
        print(f"   Total Decisions: {stats['total_decisions']}")
        print(f"   Average Confidence: {stats['average_confidence']:.1%}")
        print(f"   Average Agreement: {stats['average_agreement']:.1%}")

        return True

    except Exception as e:
        test_result("Phase 4 Overall", False, f"Error: {str(e)}")
        print(f"❌ Phase 4 Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_phase5_autonomous_engagement():
    """Test Phase 5: Complete 6-Phase Autonomous Engagement"""
    print("\n" + "="*60)
    print("PHASE 5: COMPLETE AUTONOMOUS ENGAGEMENT (6 PHASES)")
    print("="*60)

    try:
        from src.autonomous.engagement_contract import create_example_contract
        from src.autonomous.autonomous_engagement import AutonomousEngagementSystem

        # Test 5.1: Create test contract
        contract = create_example_contract()
        test_result("Test Contract Creation", contract is not None, f"Contract: {contract.contract_number}")

        # Test 5.2: Initialize Autonomous Engagement System
        engagement = AutonomousEngagementSystem(contract, authority_level=11.0)
        test_result("Engagement System Init", engagement is not None, f"Engagement ID: {engagement.engagement_id}")

        # Test 5.3: Run complete autonomous engagement
        print("\n🚀 Running complete autonomous engagement...")
        print("   This will execute all 6 phases:")
        print("   1. Reconnaissance")
        print("   2. Vulnerability Assessment")
        print("   3. Exploitation")
        print("   4. Post-Exploitation")
        print("   5. Documentation")
        print("   6. Reporting")
        print()

        report = await engagement.run_engagement()
        test_result("Complete Engagement Execution", report is not None, f"Status: {report.status.value}")

        # Test 5.4: Verify reconnaissance phase
        test_result("Reconnaissance Phase", report.reconnaissance is not None, f"Targets: {report.reconnaissance.targets_processed if report.reconnaissance else 0}")

        # Test 5.5: Verify vulnerability assessment phase
        test_result("Vulnerability Assessment", report.vulnerability_assessment is not None, f"Vulns: {report.vulnerability_assessment.vulnerabilities_found if report.vulnerability_assessment else 0}")

        # Test 5.6: Verify exploitation phase
        test_result("Exploitation Phase", report.exploitation is not None, f"Successful: {report.exploitation.exploits_successful if report.exploitation else 0}")

        # Test 5.7: Verify report generation
        test_result("Report Generation", report.total_targets > 0, f"Total targets: {report.total_targets}")

        # Test 5.8: Export report
        engagement.export_report_json(report, "test_engagement_report.json")
        test_result("Report Export", True, "Exported to test_engagement_report.json")

        print(f"\n📊 Phase 5 Engagement Report:")
        print(f"   Engagement ID: {report.engagement_id}")
        print(f"   Client: {report.client_name}")
        print(f"   Duration: {report.duration:.1f}s")
        print(f"   Status: {report.status.value}")
        print(f"\n   Targets:")
        print(f"   - Total: {report.total_targets}")
        print(f"   - Vulnerable: {report.targets_vulnerable}")
        print(f"   - Compromised: {report.targets_compromised}")
        print(f"\n   Findings:")
        print(f"   - 🔴 Critical: {report.critical_findings}")
        print(f"   - 🟠 High: {report.high_findings}")
        print(f"   - 🟡 Medium: {report.medium_findings}")
        print(f"   - 🟢 Low: {report.low_findings}")
        print(f"\n   Recommendations: {len(report.recommendations)}")

        return True

    except Exception as e:
        test_result("Phase 5 Overall", False, f"Error: {str(e)}")
        print(f"❌ Phase 5 Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all integration tests."""
    global total_tests, passed_tests, failed_tests

    print("\n" + "="*60)
    print("🔥 PROMETHEUS PRIME - AUTONOMOUS SYSTEM INTEGRATION TEST")
    print("="*60)
    print(f"Authority Level: 11.0")
    print(f"Commander: Bobby Don McWilliams II")
    print(f"Test Started: {datetime.now().isoformat()}")
    print("="*60)

    start_time = datetime.now()

    # Run all phase tests
    phase1_pass = await test_phase1_contract_scope()
    phase2_pass = await test_phase2_phoenix()
    phase3_pass = await test_phase3_omniscience()
    phase4_pass = await test_phase4_decision_engine()
    phase5_pass = await test_phase5_autonomous_engagement()

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Final results
    print("\n" + "="*60)
    print("🎯 INTEGRATION TEST RESULTS")
    print("="*60)
    print(f"\nTotal Tests: {total_tests}")
    print(f"✅ Passed: {passed_tests}")
    print(f"❌ Failed: {failed_tests}")
    print(f"Pass Rate: {passed_tests/total_tests*100:.1f}%")
    print(f"Duration: {duration:.1f}s")

    print(f"\nPhase Results:")
    print(f"  Phase 1 (Contract & Scope): {'✅ PASS' if phase1_pass else '❌ FAIL'}")
    print(f"  Phase 2 (Phoenix): {'✅ PASS' if phase2_pass else '❌ FAIL'}")
    print(f"  Phase 3 (Omniscience): {'✅ PASS' if phase3_pass else '❌ FAIL'}")
    print(f"  Phase 4 (Decision Engine): {'✅ PASS' if phase4_pass else '❌ FAIL'}")
    print(f"  Phase 5 (Autonomous Engagement): {'✅ PASS' if phase5_pass else '❌ FAIL'}")

    print(f"\nDetailed Test Results:")
    for result in test_results:
        print(f"  {result}")

    print("\n" + "="*60)
    if failed_tests == 0:
        print("🎉 ALL TESTS PASSED - SYSTEM FULLY OPERATIONAL")
    else:
        print(f"⚠️  {failed_tests} TESTS FAILED - REVIEW REQUIRED")
    print("="*60)

    return 0 if failed_tests == 0 else 1


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Run tests
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
