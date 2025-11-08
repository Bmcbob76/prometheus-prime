"""
PROMETHEUS AUTONOMOUS ENGINE
Self-directed security operations with AI orchestration

Authority Level: 11.0
Operator: Commander Bobby Don McWilliams II
"""

import asyncio
from typing import Dict, Optional
import logging
from datetime import datetime

# Import existing Prometheus systems
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from prometheus_complete import PrometheusComplete, SecurityDomain
from src.ai_brain import PrometheusAIBrain
from src.voice import PrometheusVoice
from src.memory import PrometheusMemory
from src.healing import PrometheusPhoenix


class PrometheusAutonomous:
    """
    Autonomous Security Operations Engine

    Integrates:
    - PrometheusComplete (20 security domains)
    - PrometheusAIBrain (5-model consensus)
    - PrometheusVoice (tactical announcements)
    - PrometheusMemory (crystal storage)
    - PrometheusPhoenix (self-healing)

    Autonomous Loop:
    1. Gather intelligence
    2. AI decides action (5-model consensus)
    3. Voice announces operation
    4. Execute via PrometheusComplete
    5. Report results via voice
    6. Crystallize in memory
    7. Learn and adapt
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize Prometheus Autonomous Engine.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger("PrometheusAutonomous")
        self.logger.setLevel(logging.INFO)

        # Initialize all subsystems
        self.logger.info("🔥 INITIALIZING PROMETHEUS AUTONOMOUS ENGINE...")

        # Core systems
        self.domains = PrometheusComplete(self.config)
        self.ai_brain = PrometheusAIBrain(self.config)
        self.voice = PrometheusVoice(self.config)
        self.memory = PrometheusMemory(self.config.get("memory_root", "M:\\MEMORY_ORCHESTRATION"))
        self.phoenix = PrometheusPhoenix(self.config)

        # Operational state
        self.running = False
        self.current_target = None
        self.operations_completed = 0
        self.autonomous_cycles = 0

        self.logger.info("🚀 PROMETHEUS AUTONOMOUS ENGINE OPERATIONAL")

    async def autonomous_loop(self, target: Optional[str] = None):
        """
        Main autonomous operation loop.

        Args:
            target: Optional target override (otherwise self-determined)
        """
        self.running = True
        self.current_target = target

        self.logger.info("🎯 AUTONOMOUS LOOP INITIATED")
        await self.voice.speak("Prometheus Prime autonomous mode engaged. Initiating security operations.")

        while self.running:
            try:
                self.autonomous_cycles += 1
                cycle_start = datetime.now()

                self.logger.info(f"\n{'='*60}")
                self.logger.info(f"🔄 AUTONOMOUS CYCLE {self.autonomous_cycles}")
                self.logger.info(f"{'='*60}\n")

                # PHASE 1: Intelligence Gathering
                self.logger.info("📡 PHASE 1: INTELLIGENCE GATHERING")
                intel = await self.gather_intelligence(self.current_target)

                # PHASE 2: AI Decision (5-model consensus)
                self.logger.info("🧠 PHASE 2: AI DECISION ENGINE")
                decision = await self.ai_brain.decide_action(intel)

                # Check consensus
                if not decision.get("consensus_reached"):
                    self.logger.warning("⚠️  No consensus reached - skipping cycle")
                    await self.voice.speak("Consensus not achieved. Awaiting clearer intelligence.")
                    await asyncio.sleep(30)
                    continue

                recommended = decision["recommended_action"]

                # PHASE 3: Voice Announcement
                self.logger.info("🎙️  PHASE 3: OPERATION ANNOUNCEMENT")
                await self.voice.announce_operation(recommended)

                # PHASE 4: Execute Operation
                self.logger.info("⚡ PHASE 4: OPERATION EXECUTION")
                try:
                    domain_enum = SecurityDomain(recommended["domain"])
                    result = await self.domains.execute(
                        domain_enum,
                        recommended["operation"],
                        recommended.get("parameters", {})
                    )

                except Exception as e:
                    self.logger.error(f"❌ Operation failed: {e}")
                    # Engage Phoenix healing
                    await self.phoenix.heal(e)
                    continue

                # PHASE 5: Results Report
                self.logger.info("📊 PHASE 5: RESULTS REPORTING")
                await self.voice.report_results({
                    "success": result.success,
                    "findings": result.findings
                })

                # PHASE 6: Crystallize Memory
                self.logger.info("💎 PHASE 6: MEMORY CRYSTALLIZATION")
                crystal_id = await self.memory.crystallize_operation({
                    "domain": recommended["domain"],
                    "operation": recommended["operation"],
                    "findings": result.findings,
                    "ai_consensus": decision,
                    "results": result.data,
                    "cycle": self.autonomous_cycles
                })

                # PHASE 7: Learn & Adapt
                self.logger.info("🎓 PHASE 7: LEARNING CYCLE")
                # Future: Update AI models based on results

                self.operations_completed += 1

                # Cycle complete
                cycle_duration = (datetime.now() - cycle_start).total_seconds()
                self.logger.info(f"\n✅ CYCLE {self.autonomous_cycles} COMPLETE ({cycle_duration:.1f}s)")
                self.logger.info(f"📈 Total Operations: {self.operations_completed}")

                # Delay before next cycle
                await asyncio.sleep(self.config.get("cycle_delay", 60))

            except KeyboardInterrupt:
                self.logger.info("\n⏹️  Autonomous loop interrupted by user")
                self.running = False
                break

            except Exception as e:
                self.logger.error(f"❌ Autonomous loop error: {e}")
                await self.phoenix.heal(e)
                await asyncio.sleep(30)

        await self.voice.speak("Prometheus Prime autonomous mode disengaged. Standing by.")

    async def gather_intelligence(self, target: Optional[str]) -> Dict:
        """
        Gather intelligence for AI decision making.

        Args:
            target: Target identifier

        Returns:
            Intelligence dictionary
        """
        # Use existing OSINT and reconnaissance domains
        osint_result = await self.domains.execute(
            SecurityDomain.OSINT,
            "gather",
            {"target": target or "autonomous_discovery"}
        )

        intel = {
            "context": "Autonomous security operation",
            "target": target or "dynamic_target",
            "osint_findings": osint_result.findings if osint_result.success else [],
            "available_domains": self.domains.get_available_domains(),
            "constraints": {
                "stealth": self.config.get("stealth_mode", False),
                "timeframe": self.config.get("operation_timeframe", "4 hours")
            },
            "cycle": self.autonomous_cycles
        }

        return intel

    async def execute_operation(self, domain: str, operation: str, params: Dict) -> Dict:
        """
        Execute specific operation (manual override).

        Args:
            domain: Security domain
            operation: Operation name
            params: Operation parameters

        Returns:
            Operation results
        """
        self.logger.info(f"🎯 MANUAL OPERATION: {domain}.{operation}")

        domain_enum = SecurityDomain(domain)
        result = await self.domains.execute(domain_enum, operation, params)

        # Crystallize
        crystal_id = await self.memory.crystallize_operation({
            "domain": domain,
            "operation": operation,
            "findings": result.findings,
            "results": result.data,
            "manual": True
        })

        return {
            "result": result,
            "crystal_id": crystal_id
        }

    def stop_autonomous_loop(self):
        """Stop autonomous loop"""
        self.running = False
        self.logger.info("🛑 Autonomous loop stop requested")

    def get_stats(self) -> Dict:
        """Get autonomous engine statistics"""
        return {
            "running": self.running,
            "autonomous_cycles": self.autonomous_cycles,
            "operations_completed": self.operations_completed,
            "current_target": self.current_target,
            "domains_available": len(self.domains.get_available_domains()),
            "memory_crystals": self.memory.get_memory_stats()["total_crystals"],
            "ai_consensus_rate": self.ai_brain.get_stats().get("consensus_rate", 0)
        }


if __name__ == "__main__":
    async def test():
        print("🚀 PROMETHEUS AUTONOMOUS ENGINE TEST")
        print("=" * 60)

        autonomous = PrometheusAutonomous({
            "cycle_delay": 5,  # 5 seconds for testing
            "stealth_mode": True
        })

        print("\n📊 Engine Stats:")
        stats = autonomous.get_stats()
        for key, value in stats.items():
            if key != "memory_crystals":
                print(f"  {key}: {value}")

        print("\n⚠️  Test mode - would run autonomous loop")
        print("    In production: await autonomous.autonomous_loop('target.com')")

        print("\n✅ Autonomous engine test complete")

    asyncio.run(test())
