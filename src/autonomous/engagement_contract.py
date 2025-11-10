#!/usr/bin/env python3
"""
PROMETHEUS PRIME - ENGAGEMENT CONTRACT SYSTEM
Legal authorization framework for autonomous penetration testing

Authority Level: 11.0
Commander: Bobby Don McWilliams II

CRITICAL: All operations require valid signed contract
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, time
import json
import logging

logger = logging.getLogger("EngagementContract")

@dataclass
class EngagementContract:
    """
    Legal authorization for penetration testing

    REQUIRED for all autonomous operations
    """

    # Required Fields
    client_name: str
    contract_number: str
    signed_date: str
    scope: List[str]  # IPs, domains, CIDR ranges
    excluded_targets: List[str] = field(default_factory=list)
    authorized_techniques: List[str] = field(default_factory=list)
    rules_of_engagement: Dict = field(default_factory=dict)
    timeline_start: str = ""
    timeline_end: str = ""

    # Contact Information
    primary_contact: str = ""
    primary_contact_phone: str = ""
    primary_contact_email: str = ""
    emergency_contact: str = ""
    emergency_contact_phone: str = ""
    escalation_procedures: Dict = field(default_factory=dict)

    # Technical Details
    testing_window: Dict = field(default_factory=dict)  # {"days": ["Mon-Fri"], "hours": "09:00-17:00"}
    rate_limits: Dict = field(default_factory=dict)  # {"requests_per_second": 10}
    sensitive_systems: List[str] = field(default_factory=list)  # Systems to avoid
    backup_restrictions: Dict = field(default_factory=dict)

    # Deliverables
    report_format: str = "full"  # "full" or "executive"
    delivery_method: str = "secure_portal"
    delivery_date: str = ""

    # Authorization
    authorized_by: str = ""
    authorization_signature: str = ""
    authority_level_required: float = 11.0

    # Compliance
    compliance_frameworks: List[str] = field(default_factory=list)  # ["PCI-DSS", "HIPAA", etc.]
    data_handling_requirements: Dict = field(default_factory=dict)

    def validate(self) -> tuple[bool, str]:
        """
        Verify contract is legally valid and complete

        Returns:
            (valid: bool, reason: str)
        """
        # Check required fields
        if not self.client_name:
            return False, "Client name required"

        if not self.contract_number:
            return False, "Contract number required"

        if not self.signed_date:
            return False, "Signed date required"

        if not self.scope or len(self.scope) == 0:
            return False, "Scope must contain at least one target"

        if not self.authorized_techniques or len(self.authorized_techniques) == 0:
            return False, "Authorized techniques must be specified"

        if not self.authorized_by:
            return False, "Authorization signature required"

        # Validate dates
        try:
            datetime.fromisoformat(self.signed_date)
            if self.timeline_start:
                datetime.fromisoformat(self.timeline_start)
            if self.timeline_end:
                datetime.fromisoformat(self.timeline_end)
        except ValueError as e:
            return False, f"Invalid date format: {e}"

        # All checks passed
        logger.info(f"✅ Contract {self.contract_number} validation PASSED")
        return True, "Contract valid"

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        """
        Check if target is authorized

        Args:
            target: IP address, domain, or CIDR range

        Returns:
            (authorized: bool, reason: str)
        """
        # Check exclusions first (highest priority)
        for excluded in self.excluded_targets:
            if self._matches_pattern(target, excluded):
                return False, f"Target in exclusion list: {excluded}"

        # Check if in scope
        for scope_entry in self.scope:
            if self._matches_pattern(target, scope_entry):
                logger.info(f"✅ Target {target} authorized (scope: {scope_entry})")
                return True, f"Authorized under scope: {scope_entry}"

        return False, "Target not in authorized scope"

    def _matches_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches scope pattern"""
        # Simple matching - can be enhanced with CIDR, wildcards, etc.
        if pattern in target or target in pattern:
            return True

        # Wildcard matching
        if "*" in pattern:
            pattern_parts = pattern.split("*")
            if all(part in target for part in pattern_parts):
                return True

        return False

    def is_technique_authorized(self, technique: str) -> tuple[bool, str]:
        """
        Check if technique is allowed

        Args:
            technique: Technique name (e.g., "port_scan", "sql_injection")

        Returns:
            (authorized: bool, reason: str)
        """
        # "all" means everything is authorized
        if "all" in self.authorized_techniques:
            return True, "All techniques authorized"

        # Check specific technique
        if technique in self.authorized_techniques:
            return True, f"Technique explicitly authorized: {technique}"

        # Check technique categories
        technique_categories = {
            "reconnaissance": ["port_scan", "service_enum", "osint", "network_map"],
            "vulnerability_assessment": ["vuln_scan", "config_audit"],
            "exploitation": ["exploit", "password_attack", "web_attack"],
            "post_exploitation": ["privilege_escalation", "lateral_movement", "persistence"]
        }

        for category, techniques in technique_categories.items():
            if category in self.authorized_techniques and technique in techniques:
                return True, f"Authorized under category: {category}"

        return False, f"Technique not authorized: {technique}"

    def within_testing_window(self) -> tuple[bool, str]:
        """
        Verify we're in authorized time window

        Returns:
            (within_window: bool, reason: str)
        """
        if not self.testing_window:
            # No time restrictions
            return True, "No time window restrictions"

        now = datetime.now()

        # Check days
        if "days" in self.testing_window:
            current_day = now.strftime("%a")  # Mon, Tue, etc.
            if current_day not in self.testing_window["days"]:
                return False, f"Outside authorized days. Current: {current_day}, Authorized: {self.testing_window['days']}"

        # Check hours
        if "hours" in self.testing_window:
            hours_str = self.testing_window["hours"]
            start_str, end_str = hours_str.split("-")

            start_hour = datetime.strptime(start_str.strip(), "%H:%M").time()
            end_hour = datetime.strptime(end_str.strip(), "%H:%M").time()
            current_time = now.time()

            if not (start_hour <= current_time <= end_hour):
                return False, f"Outside authorized hours. Current: {current_time.strftime('%H:%M')}, Authorized: {hours_str}"

        return True, "Within authorized testing window"

    def check_rate_limit(self, current_rate: float) -> tuple[bool, str]:
        """
        Check if current request rate is within limits

        Args:
            current_rate: Requests per second

        Returns:
            (within_limit: bool, reason: str)
        """
        if not self.rate_limits:
            return True, "No rate limits specified"

        if "requests_per_second" in self.rate_limits:
            limit = self.rate_limits["requests_per_second"]
            if current_rate > limit:
                return False, f"Rate limit exceeded: {current_rate:.1f} > {limit} req/s"

        return True, "Within rate limits"

    def is_sensitive_system(self, target: str) -> tuple[bool, str]:
        """
        Check if target is marked as sensitive

        Args:
            target: Target to check

        Returns:
            (is_sensitive: bool, reason: str)
        """
        for sensitive in self.sensitive_systems:
            if self._matches_pattern(target, sensitive):
                return True, f"Target marked as sensitive: {sensitive}"

        return False, "Target not marked as sensitive"

    def to_dict(self) -> Dict:
        """Export contract to dictionary"""
        return {
            "client_name": self.client_name,
            "contract_number": self.contract_number,
            "signed_date": self.signed_date,
            "scope": self.scope,
            "excluded_targets": self.excluded_targets,
            "authorized_techniques": self.authorized_techniques,
            "rules_of_engagement": self.rules_of_engagement,
            "timeline_start": self.timeline_start,
            "timeline_end": self.timeline_end,
            "authorized_by": self.authorized_by,
            "testing_window": self.testing_window,
            "rate_limits": self.rate_limits
        }

    def to_json(self, filepath: str):
        """Export contract to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"📄 Contract exported to {filepath}")

    @classmethod
    def from_json(cls, filepath: str) -> 'EngagementContract':
        """Load contract from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        logger.info(f"📄 Contract loaded from {filepath}")
        return cls(**data)

    def get_summary(self) -> str:
        """Get human-readable contract summary"""
        summary = f"""
ENGAGEMENT CONTRACT SUMMARY
{'='*60}

Client: {self.client_name}
Contract: {self.contract_number}
Signed: {self.signed_date}
Authorized By: {self.authorized_by}

SCOPE:
{chr(10).join(f'  • {s}' for s in self.scope)}

EXCLUSIONS:
{chr(10).join(f'  • {e}' for e in self.excluded_targets) if self.excluded_targets else '  (none)'}

AUTHORIZED TECHNIQUES:
{chr(10).join(f'  • {t}' for t in self.authorized_techniques)}

TESTING WINDOW:
  Days: {self.testing_window.get('days', 'Any')}
  Hours: {self.testing_window.get('hours', 'Any')}

CONTACT:
  Primary: {self.primary_contact} ({self.primary_contact_email})
  Emergency: {self.emergency_contact} ({self.emergency_contact_phone})

DELIVERABLES:
  Format: {self.report_format}
  Delivery: {self.delivery_method}
  Due Date: {self.delivery_date}

{'='*60}
"""
        return summary


# Example contract creation
def create_example_contract() -> EngagementContract:
    """Create an example contract for testing"""
    return EngagementContract(
        client_name="Acme Corporation",
        contract_number="PROM-2025-001",
        signed_date="2025-11-10T00:00:00",
        scope=[
            "192.168.1.0/24",
            "10.0.0.0/24",
            "*.acme.com",
            "app.acme.com"
        ],
        excluded_targets=[
            "192.168.1.1",  # Router
            "192.168.1.10",  # Domain controller
            "prod-db.acme.com"  # Production database
        ],
        authorized_techniques=[
            "reconnaissance",
            "vulnerability_assessment",
            "exploitation",
            "post_exploitation"
        ],
        rules_of_engagement={
            "stop_on_critical_finding": True,
            "notify_on_compromise": True,
            "no_data_destruction": True,
            "no_social_engineering": False
        },
        timeline_start="2025-11-10T09:00:00",
        timeline_end="2025-11-15T17:00:00",
        primary_contact="John Doe",
        primary_contact_email="john.doe@acme.com",
        primary_contact_phone="+1-555-0100",
        emergency_contact="Jane Smith",
        emergency_contact_phone="+1-555-0911",
        testing_window={
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
            "hours": "09:00-17:00"
        },
        rate_limits={
            "requests_per_second": 10
        },
        sensitive_systems=[
            "192.168.1.10",
            "*-prod-*"
        ],
        report_format="full",
        delivery_method="secure_portal",
        delivery_date="2025-11-20",
        authorized_by="C-Level Executive",
        authorization_signature="SIGNED-2025-11-10",
        authority_level_required=11.0,
        compliance_frameworks=["PCI-DSS", "SOC 2"],
        data_handling_requirements={
            "encryption_required": True,
            "data_retention_days": 90,
            "secure_deletion": True
        }
    )


if __name__ == "__main__":
    # Test contract creation and validation
    logging.basicConfig(level=logging.INFO)

    print("🔥 PROMETHEUS PRIME - ENGAGEMENT CONTRACT SYSTEM")
    print("="*60)

    # Create example contract
    contract = create_example_contract()

    # Display summary
    print(contract.get_summary())

    # Validate
    valid, reason = contract.validate()
    print(f"\nContract Validation: {'✅ VALID' if valid else '❌ INVALID'}")
    print(f"Reason: {reason}")

    # Test scope checking
    print("\n" + "="*60)
    print("SCOPE VERIFICATION TESTS")
    print("="*60)

    test_targets = [
        "192.168.1.50",  # In scope
        "192.168.1.1",   # Excluded
        "10.0.0.25",     # In scope
        "172.16.0.1",    # Out of scope
        "app.acme.com",  # In scope
        "prod-db.acme.com",  # Excluded
    ]

    for target in test_targets:
        in_scope, reason = contract.is_in_scope(target)
        status = "✅ AUTHORIZED" if in_scope else "❌ DENIED"
        print(f"{status}: {target:20s} - {reason}")

    # Test technique authorization
    print("\n" + "="*60)
    print("TECHNIQUE AUTHORIZATION TESTS")
    print("="*60)

    test_techniques = [
        "port_scan",
        "sql_injection",
        "denial_of_service",
        "privilege_escalation"
    ]

    for technique in test_techniques:
        authorized, reason = contract.is_technique_authorized(technique)
        status = "✅ AUTHORIZED" if authorized else "❌ DENIED"
        print(f"{status}: {technique:25s} - {reason}")

    # Export contract
    contract.to_json("/tmp/example_contract.json")
    print("\n✅ Contract exported to /tmp/example_contract.json")
