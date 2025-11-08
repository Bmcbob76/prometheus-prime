"""
PROMETHEUS PRIME AGENT
Main Entry Point for 20-Domain Security System

Authority Level: 9.9
Operator: Commander Bobby Don McWilliams II
Classification: PROMETHEUS PRIME

Usage:
    python prometheus_prime_agent.py --domain network_recon --operation scan --target example.com
    python prometheus_prime_agent.py --test
    python prometheus_prime_agent.py --interactive
"""

import asyncio
import argparse
import logging
import sys
from typing import Optional

from prometheus_complete import PrometheusComplete, SecurityDomain


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class PrometheusPrimeAgent:
    """Main Prometheus Prime Agent Interface"""

    def __init__(self):
        self.logger = logging.getLogger("PrometheusPrimeAgent")
        self.prometheus = PrometheusComplete()

        self.logger.info("🔥 PROMETHEUS PRIME AGENT INITIALIZED")

    async def execute_operation(
        self,
        domain: str,
        operation: str,
        target: Optional[str] = None
    ):
        """Execute single operation"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"🎯 OPERATION: {domain}.{operation}")
        if target:
            self.logger.info(f"🎯 TARGET: {target}")
        self.logger.info(f"{'='*60}\n")

        try:
            domain_enum = SecurityDomain(domain)
            params = {"target": target} if target else {}

            result = await self.prometheus.execute(domain_enum, operation, params)

            # Display results
            self._display_results(result)

        except ValueError as e:
            self.logger.error(f"❌ Invalid domain: {domain}")
            self.logger.info(f"\n📋 Available domains:")
            for d in self.prometheus.get_available_domains():
                print(f"  • {d}")

        except Exception as e:
            self.logger.error(f"❌ Operation failed: {e}")

    def _display_results(self, result):
        """Display operation results"""
        print(f"\n{'='*60}")
        print(f"📊 OPERATION RESULTS")
        print(f"{'='*60}\n")

        print(f"Domain: {result.domain}")
        print(f"Success: {'✅' if result.success else '❌'} {result.success}")
        print(f"Timestamp: {result.timestamp}")
        print(f"Severity: {result.severity.upper()}")

        print(f"\n🔍 FINDINGS ({len(result.findings)}):")
        for i, finding in enumerate(result.findings, 1):
            print(f"  {i}. {finding}")

        print(f"\n💡 RECOMMENDATIONS ({len(result.recommendations)}):")
        for i, rec in enumerate(result.recommendations, 1):
            print(f"  {i}. {rec}")

        if result.error:
            print(f"\n⚠️  ERROR: {result.error}")

        print(f"\n{'='*60}\n")

    async def test_all_domains(self):
        """Test all 20 domains"""
        self.logger.info("\n🧪 TESTING ALL 20 DOMAINS")
        self.logger.info("="*60)

        health = await self.prometheus.health_check()

        for domain, status in health.items():
            status_icon = "✅" if status else "❌"
            print(f"{status_icon} {domain}")

        stats = self.prometheus.get_stats()
        print(f"\n📊 SYSTEM STATISTICS:")
        print(f"  Operations Executed: {stats['operations_executed']}")
        print(f"  Total Findings: {stats['total_findings']}")
        print(f"  Domains Available: {stats['domains_available']}")
        print(f"  Authority Level: {stats['authority_level']}")

    async def interactive_mode(self):
        """Interactive command mode"""
        print("\n🔥 PROMETHEUS PRIME - INTERACTIVE MODE")
        print("="*60)
        print("Commands:")
        print("  domains - List available domains")
        print("  execute <domain> <operation> [target] - Execute operation")
        print("  stats - Show statistics")
        print("  exit - Exit interactive mode")
        print("="*60 + "\n")

        while True:
            try:
                command = input("prometheus> ").strip()

                if not command:
                    continue

                if command == "exit":
                    break

                elif command == "domains":
                    domains = self.prometheus.get_available_domains()
                    print(f"\n📋 Available Domains ({len(domains)}):")
                    for d in domains:
                        print(f"  • {d}")
                    print()

                elif command == "stats":
                    stats = self.prometheus.get_stats()
                    print(f"\n📊 Statistics:")
                    for key, value in stats.items():
                        if key != "domain_stats":
                            print(f"  {key}: {value}")
                    print()

                elif command.startswith("execute "):
                    parts = command.split()
                    if len(parts) >= 3:
                        domain = parts[1]
                        operation = parts[2]
                        target = parts[3] if len(parts) > 3 else None
                        await self.execute_operation(domain, operation, target)
                    else:
                        print("Usage: execute <domain> <operation> [target]\n")

                else:
                    print(f"Unknown command: {command}\n")

            except KeyboardInterrupt:
                print("\n")
                break
            except Exception as e:
                print(f"❌ Error: {e}\n")

        print("Exiting interactive mode...")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Prometheus Prime - Elite 20-Domain Security System"
    )
    parser.add_argument("--domain", help="Security domain to execute")
    parser.add_argument("--operation", help="Operation to perform")
    parser.add_argument("--target", help="Target for operation")
    parser.add_argument("--test", action="store_true", help="Test all domains")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")

    args = parser.parse_args()

    agent = PrometheusPrimeAgent()

    if args.test:
        await agent.test_all_domains()

    elif args.interactive:
        await agent.interactive_mode()

    elif args.domain and args.operation:
        await agent.execute_operation(args.domain, args.operation, args.target)

    else:
        parser.print_help()
        print("\n🔥 PROMETHEUS PRIME AGENT")
        print("="*60)
        print("Quick Start:")
        print("  --test              Test all 20 domains")
        print("  --interactive       Interactive command mode")
        print("  --domain <domain> --operation <op> [--target <target>]")
        print("\nExample:")
        print("  python prometheus_prime_agent.py --test")
        print("  python prometheus_prime_agent.py --interactive")
        print("  python prometheus_prime_agent.py --domain network_reconnaissance --operation scan --target example.com")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⏹️  Interrupted by user")
        sys.exit(0)
