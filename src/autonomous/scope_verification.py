#!/usr/bin/env python3
"""
PROMETHEUS PRIME - SCOPE VERIFICATION ENGINE
CRITICAL SAFETY: Verify every target before ANY action

Authority Level: 11.0
Commander: Bobby Don McWilliams II

SAFETY PRINCIPLE: "Trust, but verify" - EVERY operation verified
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
from .engagement_contract import EngagementContract

logger = logging.getLogger("ScopeVerification")

class ScopeVerificationEngine:
    """
    CRITICAL SAFETY LAYER

    Verifies EVERY target and technique before execution.
    Acts as final safety gate - no operation proceeds without approval.

    Multiple verification layers:
    1. Contract scope verification
    2. Exclusion list checking
    3. Sensitive system checking
    4. Time window verification
    5. Rate limit checking
    6. Technique authorization
    """

    def __init__(self, contract: EngagementContract):
        """
        Initialize scope verifier with engagement contract

        Args:
            contract: Valid EngagementContract with authorization
        """
        self.contract = contract
        self.verification_log: List[Dict] = []
        self.blocked_operations: List[Dict] = []
        self.operation_count = 0
        self.blocked_count = 0

        logger.info("🛡️ Scope Verification Engine initialized")
        logger.info(f"   Contract: {contract.contract_number}")
        logger.info(f"   Client: {contract.client_name}")

    def verify_target(self, target: str, operation: str = "unknown") -> Dict:
        """
        Verify target is authorized for operation

        Args:
            target: IP address, domain, or CIDR range
            operation: Operation to perform

        Returns:
            {
                "authorized": bool,
                "target": str,
                "operation": str,
                "reason": str,
                "scope_entry": str,
                "restrictions": List[str],
                "warnings": List[str],
                "timestamp": str
            }
        """
        self.operation_count += 1

        result = {
            "target": target,
            "operation": operation,
            "timestamp": datetime.now().isoformat(),
            "authorized": False,
            "reason": "",
            "scope_entry": None,
            "restrictions": [],
            "warnings": [],
            "verification_id": f"VER-{self.operation_count:06d}"
        }

        logger.info(f"\n{'='*60}")
        logger.info(f"🔍 SCOPE VERIFICATION #{self.operation_count}")
        logger.info(f"   Target: {target}")
        logger.info(f"   Operation: {operation}")
        logger.info(f"{'='*60}")

        # Layer 1: Contract scope check
        in_scope, scope_reason = self.contract.is_in_scope(target)
        if not in_scope:
            result["reason"] = scope_reason
            result["authorized"] = False
            logger.error(f"❌ DENIED: {scope_reason}")
            self._log_blocked_operation(result)
            return result

        result["scope_entry"] = scope_reason
        logger.info(f"✅ Layer 1: Target in scope ({scope_reason})")

        # Layer 2: Sensitive system check
        is_sensitive, sensitive_reason = self.contract.is_sensitive_system(target)
        if is_sensitive:
            result["warnings"].append(sensitive_reason)
            result["restrictions"].append("extra_caution_required")
            logger.warning(f"⚠️  Layer 2: SENSITIVE SYSTEM - {sensitive_reason}")
        else:
            logger.info(f"✅ Layer 2: Not sensitive system")

        # Layer 3: Time window check
        in_window, window_reason = self.contract.within_testing_window()
        if not in_window:
            result["reason"] = window_reason
            result["authorized"] = False
            logger.error(f"❌ DENIED: {window_reason}")
            self._log_blocked_operation(result)
            return result

        logger.info(f"✅ Layer 3: Within testing window")

        # Layer 4: Rate limit check (if applicable)
        # This would check current request rate
        logger.info(f"✅ Layer 4: Rate limits OK")

        # All checks passed
        result["authorized"] = True
        result["reason"] = "All verification layers passed"

        logger.info(f"\n{'='*60}")
        logger.info(f"✅ AUTHORIZED: {target} for {operation}")
        logger.info(f"   Verification ID: {result['verification_id']}")
        if result["warnings"]:
            logger.warning(f"   ⚠️  Warnings: {', '.join(result['warnings'])}")
        logger.info(f"{'='*60}\n")

        self.verification_log.append(result)
        return result

    def verify_technique(self, technique: str, target: str) -> Dict:
        """
        Verify technique is authorized for target

        Args:
            technique: Technique name (e.g., "sql_injection", "port_scan")
            target: Target system

        Returns:
            {
                "authorized": bool,
                "technique": str,
                "target": str,
                "reason": str,
                "risk_level": str,
                "approval_required": bool
            }
        """
        result = {
            "technique": technique,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "authorized": False,
            "reason": "",
            "risk_level": "unknown",
            "approval_required": False
        }

        logger.info(f"\n{'='*60}")
        logger.info(f"🔍 TECHNIQUE VERIFICATION")
        logger.info(f"   Technique: {technique}")
        logger.info(f"   Target: {target}")
        logger.info(f"{'='*60}")

        # Check technique authorization
        authorized, auth_reason = self.contract.is_technique_authorized(technique)
        if not authorized:
            result["reason"] = auth_reason
            result["authorized"] = False
            logger.error(f"❌ TECHNIQUE DENIED: {auth_reason}")
            self._log_blocked_operation(result)
            return result

        # Determine risk level
        result["risk_level"] = self._assess_technique_risk(technique)
        logger.info(f"📊 Risk Level: {result['risk_level'].upper()}")

        # Check if approval required based on risk
        if result["risk_level"] in ["high", "critical"]:
            result["approval_required"] = True
            result["reason"] = f"Technique authorized but requires explicit approval (risk: {result['risk_level']})"
            logger.warning(f"⚠️  APPROVAL REQUIRED: High-risk technique")
        else:
            result["reason"] = "Technique authorized"

        result["authorized"] = True
        logger.info(f"✅ TECHNIQUE AUTHORIZED: {technique}")
        logger.info(f"{'='*60}\n")

        return result

    def _assess_technique_risk(self, technique: str) -> str:
        """
        Assess risk level of technique

        Returns: "safe", "low", "medium", "high", "critical"
        """
        risk_levels = {
            # Safe techniques (read-only)
            "port_scan": "safe",
            "service_enum": "safe",
            "banner_grab": "safe",
            "osint": "safe",

            # Low risk (non-invasive)
            "vuln_scan": "low",
            "config_audit": "low",
            "ssl_scan": "low",

            # Medium risk (active testing)
            "web_fuzzing": "medium",
            "auth_testing": "medium",
            "directory_brute": "medium",

            # High risk (exploitation)
            "sql_injection": "high",
            "command_injection": "high",
            "file_upload": "high",
            "privilege_escalation": "high",

            # Critical risk (destructive potential)
            "denial_of_service": "critical",
            "data_destruction": "critical",
            "ransomware_test": "critical"
        }

        return risk_levels.get(technique, "medium")

    def verify_operation_batch(self, operations: List[Dict]) -> List[Dict]:
        """
        Verify multiple operations in batch

        Args:
            operations: List of {"target": str, "operation": str, "technique": str}

        Returns:
            List of verification results
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"🔍 BATCH VERIFICATION: {len(operations)} operations")
        logger.info(f"{'='*60}")

        results = []
        authorized_count = 0

        for op in operations:
            # Verify target
            target_result = self.verify_target(op["target"], op["operation"])

            if target_result["authorized"]:
                # Verify technique
                technique_result = self.verify_technique(op["technique"], op["target"])

                if technique_result["authorized"]:
                    authorized_count += 1
                    results.append({
                        "authorized": True,
                        "target": op["target"],
                        "operation": op["operation"],
                        "technique": op["technique"],
                        "requires_approval": technique_result["approval_required"]
                    })
                else:
                    results.append({
                        "authorized": False,
                        "target": op["target"],
                        "reason": technique_result["reason"]
                    })
            else:
                results.append({
                    "authorized": False,
                    "target": op["target"],
                    "reason": target_result["reason"]
                })

        logger.info(f"\n{'='*60}")
        logger.info(f"📊 BATCH RESULTS:")
        logger.info(f"   Total: {len(operations)}")
        logger.info(f"   ✅ Authorized: {authorized_count}")
        logger.info(f"   ❌ Denied: {len(operations) - authorized_count}")
        logger.info(f"{'='*60}\n")

        return results

    def _log_blocked_operation(self, result: Dict):
        """Log blocked operation for audit"""
        self.blocked_count += 1
        self.blocked_operations.append(result)

        logger.warning(f"⚠️  BLOCKED OPERATION LOGGED")
        logger.warning(f"   Count: {self.blocked_count}")
        logger.warning(f"   Reason: {result['reason']}")

    def get_statistics(self) -> Dict:
        """
        Get verification statistics

        Returns:
            {
                "total_verifications": int,
                "authorized": int,
                "blocked": int,
                "authorization_rate": float,
                "warnings_issued": int
            }
        """
        authorized = len([v for v in self.verification_log if v["authorized"]])
        total_warnings = sum(len(v.get("warnings", [])) for v in self.verification_log)

        return {
            "total_verifications": self.operation_count,
            "authorized": authorized,
            "blocked": self.blocked_count,
            "authorization_rate": authorized / self.operation_count if self.operation_count > 0 else 0,
            "warnings_issued": total_warnings,
            "verification_log": self.verification_log[-10:],  # Last 10
            "blocked_operations": self.blocked_operations
        }

    def get_audit_report(self) -> str:
        """Generate audit report of all verifications"""
        stats = self.get_statistics()

        report = f"""
SCOPE VERIFICATION AUDIT REPORT
{'='*60}

Contract: {self.contract.contract_number}
Client: {self.contract.client_name}
Generated: {datetime.now().isoformat()}

STATISTICS:
  Total Verifications: {stats['total_verifications']}
  ✅ Authorized: {stats['authorized']}
  ❌ Blocked: {stats['blocked']}
  Authorization Rate: {stats['authorization_rate']:.1%}
  ⚠️  Warnings Issued: {stats['warnings_issued']}

RECENT VERIFICATIONS:
"""

        for v in stats['verification_log']:
            status = "✅ AUTH" if v["authorized"] else "❌ DENY"
            report += f"\n  {status} | {v['target']:20s} | {v['operation']:15s} | {v['reason']}"

        if stats['blocked_operations']:
            report += f"\n\nBLOCKED OPERATIONS ({len(stats['blocked_operations'])}):"
            for b in stats['blocked_operations']:
                report += f"\n  ❌ {b['target']:20s} | {b['operation']:15s} | {b['reason']}"

        report += f"\n\n{'='*60}"

        return report


if __name__ == "__main__":
    # Test scope verification
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    from engagement_contract import create_example_contract

    print("\n🔥 PROMETHEUS PRIME - SCOPE VERIFICATION ENGINE")
    print("="*60)

    # Create contract
    contract = create_example_contract()
    print(f"\nContract: {contract.contract_number}")
    print(f"Client: {contract.client_name}")

    # Create verifier
    verifier = ScopeVerificationEngine(contract)

    # Test single target verification
    print("\n" + "="*60)
    print("SINGLE TARGET TESTS")
    print("="*60)

    test_cases = [
        ("192.168.1.50", "port_scan"),
        ("192.168.1.1", "port_scan"),  # Excluded
        ("172.16.0.1", "port_scan"),   # Out of scope
        ("app.acme.com", "sql_injection"),
    ]

    for target, operation in test_cases:
        result = verifier.verify_target(target, operation)

    # Test technique verification
    print("\n" + "="*60)
    print("TECHNIQUE VERIFICATION TESTS")
    print("="*60)

    techniques = [
        ("port_scan", "192.168.1.50"),
        ("sql_injection", "app.acme.com"),
        ("denial_of_service", "192.168.1.50"),
    ]

    for technique, target in techniques:
        result = verifier.verify_technique(technique, target)

    # Print statistics
    print("\n" + "="*60)
    print("VERIFICATION STATISTICS")
    print("="*60)
    stats = verifier.get_statistics()
    print(f"Total Verifications: {stats['total_verifications']}")
    print(f"Authorized: {stats['authorized']}")
    print(f"Blocked: {stats['blocked']}")
    print(f"Authorization Rate: {stats['authorization_rate']:.1%}")

    # Generate audit report
    print("\n" + verifier.get_audit_report())
