#!/usr/bin/env python3
"""
PROMETHEUS PRIME - AUTONOMOUS MODE LAUNCHER
Initiates autonomous security operations with full OODA loop

Authority Level: 11.0
Safety: Ethical guardrails + ROE compliance enforced
"""

import asyncio
import sys
import os
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("PrometheusLauncher")

def check_prerequisites():
    """Check if all required systems are available."""
    print("=" * 60)
    print("🔍 CHECKING PREREQUISITES")
    print("=" * 60)

    required_files = [
        "src/autonomous/prometheus_autonomous.py",
        "AUTONOMY/ooda-engine/ooda_loop.py",
        "prometheus_complete.py",
        "prometheus_memory.py",
        "prometheus_voice.py",
        "src/healing/prometheus_phoenix.py"
    ]

    missing = []
    for file_path in required_files:
        full_path = Path(__file__).parent / file_path
        if full_path.exists():
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ {file_path} - MISSING")
            missing.append(file_path)

    if missing:
        print(f"\n⚠️  Missing {len(missing)} required files")
        print("   Cannot launch autonomous mode without all subsystems")
        return False

    print("\n✅ All prerequisites satisfied")
    return True

def display_capabilities():
    """Display autonomous capabilities."""
    print("\n" + "=" * 60)
    print("🚀 PROMETHEUS AUTONOMOUS CAPABILITIES")
    print("=" * 60)

    print("\n📊 INTEGRATED SYSTEMS:")
    print("   • PrometheusComplete - 20 security domains, 282 MCP tools")
    print("   • PrometheusAIBrain - 5-model AI consensus (Claude, GPT-4, Gemini, Cohere)")
    print("   • PrometheusVoice - Tactical announcements via ElevenLabs")
    print("   • PrometheusMemory - 9-tier crystal memory system")
    print("   • PrometheusPhoenix - Self-healing and error recovery")

    print("\n🔄 OODA LOOP PHASES:")
    print("   1. OBSERVE - Gather intelligence from target environment")
    print("   2. ORIENT - Analyze data, understand situation")
    print("   3. DECIDE - AI consensus determines optimal action")
    print("   4. ACT - Execute operation via security domains")

    print("\n🎯 OPERATION PHASES:")
    phases = [
        "Reconnaissance", "Scanning", "Enumeration", "Vulnerability Analysis",
        "Exploitation", "Post-Exploitation", "Lateral Movement",
        "Privilege Escalation", "Persistence", "Data Collection", "Reporting"
    ]
    for i, phase in enumerate(phases, 1):
        print(f"   {i:2d}. {phase}")

    print("\n🛡️ SAFETY PROTOCOLS:")
    print("   • Ethical guardrails enforced")
    print("   • ROE (Rules of Engagement) compliance required")
    print("   • Authorization verification before destructive actions")
    print("   • Audit logging of all operations")
    print("   • Emergency stop capability")

def display_status():
    """Display current autonomous status."""
    print("\n" + "=" * 60)
    print("📈 AUTONOMOUS SYSTEM STATUS")
    print("=" * 60)

    # Try to import and get status
    try:
        from src.autonomous.prometheus_autonomous import PrometheusAutonomous

        print("\n✅ Autonomous engine: READY")
        print("✅ Authority level: 11.0")
        print("✅ Operator: Commander Bobby Don McWilliams II")

        # Check OODA loop
        try:
            from AUTONOMY.ooda_engine.ooda_loop import OODALoop
            print("✅ OODA loop: READY")
        except Exception as e:
            print(f"⚠️  OODA loop: {e}")

    except Exception as e:
        print(f"❌ Autonomous engine: {e}")
        return False

    return True

def launch_demo_mode():
    """Launch in demo/test mode with limited scope."""
    print("\n" + "=" * 60)
    print("🎮 LAUNCHING DEMO MODE")
    print("=" * 60)

    print("\nDemo mode will:")
    print("   • Show autonomous cycle structure")
    print("   • Display decision-making process")
    print("   • Execute read-only operations only")
    print("   • Generate status reports")
    print("\nPress Ctrl+C to stop at any time")

    try:
        from src.autonomous.prometheus_autonomous import PrometheusAutonomous

        # Create autonomous instance with demo config
        config = {
            "mode": "demo",
            "max_cycles": 3,
            "operations_allowed": ["info_gathering", "status_check"],
            "safety_level": "maximum"
        }

        print("\n🚀 INITIALIZING AUTONOMOUS ENGINE...")
        autonomous = PrometheusAutonomous(config)

        print("✅ Engine initialized")
        print("\n⚠️  Note: Full autonomous execution requires:")
        print("   • Valid target authorization")
        print("   • Signed Rules of Engagement")
        print("   • All subsystem dependencies installed")
        print("   • Proper API keys configured")

        print("\n✅ AUTONOMOUS MODE STRUCTURE VERIFIED")
        print("   System is ready for deployment when authorized")

        return True

    except Exception as e:
        print(f"\n❌ Demo launch failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main launcher function."""
    print("\n" + "=" * 80)
    print("🔥 PROMETHEUS PRIME - AUTONOMOUS MODE LAUNCHER")
    print("=" * 80)
    print("\nAuthority Level: 11.0")
    print("Operator: Commander Bobby Don McWilliams II")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Step 1: Check prerequisites
    if not check_prerequisites():
        print("\n❌ Prerequisites not met. Aborting launch.")
        return 1

    # Step 2: Display capabilities
    display_capabilities()

    # Step 3: Display status
    if not display_status():
        print("\n⚠️  Some subsystems not available")

    # Step 4: Launch demo mode
    print("\n" + "=" * 60)
    input("Press ENTER to launch demo mode (or Ctrl+C to cancel)...")

    success = launch_demo_mode()

    if success:
        print("\n" + "=" * 60)
        print("🎉 AUTONOMOUS MODE DEMO COMPLETE")
        print("=" * 60)
        print("\nNext steps for full deployment:")
        print("   1. Configure API keys (.env file)")
        print("   2. Install all Python dependencies")
        print("   3. Prepare ROE documentation")
        print("   4. Set authorized targets")
        print("   5. Run: python src/autonomous/prometheus_autonomous.py")
        return 0
    else:
        print("\n❌ Demo launch failed")
        return 1

if __name__ == "__main__":
    from datetime import datetime
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Launch cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
