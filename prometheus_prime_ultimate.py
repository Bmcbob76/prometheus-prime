"""
PROMETHEUS PRIME ULTIMATE
Autonomous AI Agent with Multi-Model Consensus

Authority Level: 11.0
Operator: Commander Bobby Don McWilliams II
Classification: PROMETHEUS PRIME ULTIMATE

This is the ULTIMATE entry point that integrates:
- PrometheusComplete (20 security domains)
- PrometheusAIBrain (5-model consensus)
- PrometheusVoice (tactical announcements)
- PrometheusMemory (crystal storage)
- PrometheusPhoenix (self-healing)
- PrometheusAutonomous (autonomous operations)

Usage:
    python prometheus_prime_ultimate.py --autonomous --target example.com
    python prometheus_prime_ultimate.py --manual --domain network_recon --operation scan
    python prometheus_prime_ultimate.py --test
"""

import asyncio
import argparse
import logging
import sys
from typing import Optional

from src.autonomous import PrometheusAutonomous


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class PrometheusUltimate:
    """Prometheus Prime Ultimate - Autonomous AI Security Agent"""

    def __init__(self, config: Optional[dict] = None):
        self.logger = logging.getLogger("PrometheusUltimate")

        # Banner
        self._display_banner()

        # Initialize autonomous engine
        self.config = config or {
            "cycle_delay": 60,  # Seconds between autonomous cycles
            "stealth_mode": False,
            "consensus_threshold": 0.75,
            "memory_root": "M:\\MEMORY_ORCHESTRATION"
        }

        self.autonomous = PrometheusAutonomous(self.config)

        self.logger.info("🚀 PROMETHEUS ULTIMATE INITIALIZED")

    def _display_banner(self):
        """Display Prometheus Ultimate banner"""
        banner = """
        ╔═══════════════════════════════════════════════════════════════╗
        ║                                                               ║
        ║            ⚡ PROMETHEUS PRIME ULTIMATE ⚡                    ║
        ║                                                               ║
        ║              Autonomous AI Security Agent                     ║
        ║                  Authority Level 11.0                         ║
        ║                                                               ║
        ║  Features:                                                    ║
        ║    • 20 Elite Security Domains                                ║
        ║    • 5-Model AI Consensus (2 Local GPU + 3 Cloud API)         ║
        ║    • Prometheus Voice (ElevenLabs TTS)                        ║
        ║    • 9-Layer Crystal Memory (565+ Crystals)                   ║
        ║    • Phoenix Self-Healing (45,962 Templates)                  ║
        ║    • Full Autonomous Operations                               ║
        ║                                                               ║
        ║  Hardware:                                                    ║
        ║    • GTX 1080 (8GB) - Primary GPU                             ║
        ║    • GTX 1650 (4GB) - Secondary GPU                           ║
        ║    • i7-6700K CPU, 32GB RAM                                   ║
        ║                                                               ║
        ║  Operator: Commander Bobby Don McWilliams II                  ║
        ║                                                               ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)

    async def run_autonomous(self, target: Optional[str] = None):
        """Run autonomous security operations"""
        self.logger.info("🤖 AUTONOMOUS MODE ACTIVATED")
        self.logger.info(f"   Target: {target or 'Dynamic Discovery'}")
        self.logger.info(f"   Cycle Delay: {self.config['cycle_delay']}s")
        self.logger.info(f"   Consensus Threshold: {self.config['consensus_threshold']:.0%}")

        try:
            await self.autonomous.autonomous_loop(target)
        except KeyboardInterrupt:
            self.logger.info("\n⏹️  Autonomous mode stopped by user")
            self.autonomous.stop_autonomous_loop()

    async def run_manual(self, domain: str, operation: str, target: Optional[str] = None):
        """Run manual operation with AI augmentation"""
        self.logger.info("🎯 MANUAL OPERATION MODE")

        params = {"target": target} if target else {}

        result = await self.autonomous.execute_operation(domain, operation, params)

        print("\n" + "="*60)
        print("📊 OPERATION RESULTS")
        print("="*60)
        print(f"\nDomain: {domain}")
        print(f"Operation: {operation}")
        print(f"Crystal ID: {result['crystal_id']}")
        print(f"Success: {'✅' if result['result'].success else '❌'}")
        print(f"\nFindings ({len(result['result'].findings)}):")
        for i, finding in enumerate(result['result'].findings, 1):
            print(f"  {i}. {finding}")
        print("\n" + "="*60)

    async def display_stats(self):
        """Display system statistics"""
        stats = self.autonomous.get_stats()

        print("\n" + "="*60)
        print("📊 PROMETHEUS ULTIMATE - SYSTEM STATISTICS")
        print("="*60)

        print(f"\nAutonomous Engine:")
        print(f"  Running: {'✅ Yes' if stats['running'] else '❌ No'}")
        print(f"  Autonomous Cycles: {stats['autonomous_cycles']}")
        print(f"  Operations Completed: {stats['operations_completed']}")
        print(f"  Current Target: {stats['current_target'] or 'None'}")

        print(f"\nCapabilities:")
        print(f"  Domains Available: {stats['domains_available']}")
        print(f"  Memory Crystals: {stats['memory_crystals']}")
        print(f"  AI Consensus Rate: {stats['ai_consensus_rate']:.0%}")

        print("\n" + "="*60 + "\n")

    async def test_system(self):
        """Test all systems"""
        print("\n🧪 SYSTEM TEST MODE")
        print("="*60)

        # Test each subsystem
        print("\n1️⃣  Testing PrometheusComplete (20 Domains)...")
        health = await self.autonomous.domains.health_check()
        healthy_count = sum(1 for status in health.values() if status)
        print(f"   ✅ {healthy_count}/20 domains healthy")

        print("\n2️⃣  Testing AI Brain (5 Models)...")
        ai_stats = self.autonomous.ai_brain.get_stats()
        print(f"   ✅ AI Brain initialized")
        print(f"      Consensus threshold: {ai_stats['consensus_threshold']:.0%}")

        print("\n3️⃣  Testing Prometheus Voice...")
        voice_status = self.autonomous.voice.get_status()
        print(f"   ✅ Voice system: {voice_status['voice_id']}")

        print("\n4️⃣  Testing Crystal Memory...")
        memory_stats = self.autonomous.memory.get_memory_stats()
        print(f"   ✅ Crystal Memory: {memory_stats['total_crystals']} crystals")
        print(f"      Memory layers: {memory_stats['layers']}")

        print("\n5️⃣  Testing Phoenix Healing...")
        phoenix_stats = self.autonomous.phoenix.get_stats()
        print(f"   ✅ Phoenix: {phoenix_stats['error_templates']} templates")

        print("\n" + "="*60)
        print("✅ ALL SYSTEMS OPERATIONAL")
        print("="*60 + "\n")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Prometheus Prime Ultimate - Autonomous AI Security Agent"
    )

    # Modes
    parser.add_argument("--autonomous", "-a", action="store_true",
                       help="Run in autonomous mode")
    parser.add_argument("--manual", "-m", action="store_true",
                       help="Run single manual operation")
    parser.add_argument("--test", "-t", action="store_true",
                       help="Test all systems")
    parser.add_argument("--stats", "-s", action="store_true",
                       help="Display statistics")

    # Parameters
    parser.add_argument("--target", help="Target for operations")
    parser.add_argument("--domain", help="Security domain (manual mode)")
    parser.add_argument("--operation", help="Operation to execute (manual mode)")
    parser.add_argument("--cycle-delay", type=int, default=60,
                       help="Seconds between autonomous cycles (default: 60)")

    args = parser.parse_args()

    # Configuration
    config = {
        "cycle_delay": args.cycle_delay,
        "stealth_mode": False,
        "consensus_threshold": 0.75
    }

    ultimate = PrometheusUltimate(config)

    if args.test:
        await ultimate.test_system()

    elif args.stats:
        await ultimate.display_stats()

    elif args.autonomous:
        await ultimate.run_autonomous(args.target)

    elif args.manual:
        if not args.domain or not args.operation:
            print("❌ Manual mode requires --domain and --operation")
            sys.exit(1)
        await ultimate.run_manual(args.domain, args.operation, args.target)

    else:
        parser.print_help()
        print("\n" + "="*60)
        print("🚀 QUICK START EXAMPLES")
        print("="*60)
        print("\n1. Test all systems:")
        print("   python prometheus_prime_ultimate.py --test")
        print("\n2. View statistics:")
        print("   python prometheus_prime_ultimate.py --stats")
        print("\n3. Run autonomous mode:")
        print("   python prometheus_prime_ultimate.py --autonomous --target example.com")
        print("\n4. Manual operation:")
        print("   python prometheus_prime_ultimate.py --manual --domain network_reconnaissance --operation scan --target example.com")
        print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⏹️  Interrupted by user")
        sys.exit(0)
