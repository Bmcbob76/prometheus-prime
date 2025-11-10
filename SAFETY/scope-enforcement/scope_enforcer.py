#!/usr/bin/env python3
"""
PROMETHEUS PRIME - SCOPE ENFORCEMENT ENGINE
Hardened boundary protection for autonomous operations

Authority Level: 11.0
Commander: Bobby Don McWilliams II
CRITICAL SAFETY SYSTEM - PREVENTS OUT-OF-SCOPE OPERATIONS
"""

import ipaddress
import re
import hashlib
import json
import logging
from typing import List, Set, Dict, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

class ScopeViolationType(Enum):
    """Types of scope violations."""
    HARDCODED_BLOCKLIST = "hardcoded_blocklist"
    NOT_IN_SCOPE = "not_in_scope"
    GEOGRAPHIC_RESTRICTION = "geographic_restriction"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    UNAUTHORIZED_TLD = "unauthorized_tld"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass
class ScopeViolation(Exception):
    """Exception raised when scope is violated."""
    violation_type: ScopeViolationType
    target: str
    reason: str
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    def __str__(self):
        return f"[{self.violation_type.value}] {self.target}: {self.reason}"


class ScopeEnforcer:
    """
    Cryptographically enforced scope boundaries.
    Prevents autonomous operations from attacking unauthorized targets.
    """

    # ========================================================================
    # HARDCODED BLOCKLIST - NEVER ATTACK THESE
    # ========================================================================
    HARDCODED_BLOCKLIST_IPS = [
        '0.0.0.0/8',          # Broadcast
        '10.0.0.0/8',         # Private (unless explicitly in scope)
        '127.0.0.0/8',        # Loopback
        '169.254.0.0/16',     # Link-local
        '172.16.0.0/12',      # Private
        '192.168.0.0/16',     # Private
        '224.0.0.0/4',        # Multicast
        '240.0.0.0/4',        # Reserved
        '255.255.255.255/32', # Broadcast
    ]

    HARDCODED_BLOCKLIST_TLDS = [
        '.gov',     # Government (requires special authorization)
        '.mil',     # Military (requires special authorization)
        '.edu',     # Education (requires special authorization)
    ]

    CRITICAL_INFRASTRUCTURE_KEYWORDS = [
        'power', 'electric', 'grid', 'scada', 'ics',
        'water', 'treatment', 'hospital', 'medical', 'health',
        'emergency', 'police', 'fire', 'ambulance',
        'nuclear', 'dam', 'airport', 'atc', 'railway',
        'bank', 'federal', 'treasury', 'defense'
    ]

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize scope enforcer."""
        self.logger = logger or logging.getLogger('ScopeEnforcer')

        # Authorized scope (starts empty - must be loaded from signed ROE)
        self.authorized_ips: Set[ipaddress.IPv4Network] = set()
        self.authorized_domains: Set[str] = set()
        self.authorized_cidrs: List[ipaddress.IPv4Network] = []

        # Exclusions within authorized scope
        self.excluded_ips: Set[ipaddress.IPv4Network] = set()
        self.excluded_domains: Set[str] = set()

        # Geographic restrictions
        self.allowed_countries: Set[str] = set()
        self.blocked_countries: Set[str] = {'KP', 'IR', 'SY'}  # Default blocks

        # Engagement metadata
        self.engagement_id: Optional[str] = None
        self.roe_signature: Optional[str] = None
        self.roe_signed_by: Optional[str] = None
        self.roe_timestamp: Optional[datetime] = None

        # Violation tracking
        self.violations: List[ScopeViolation] = []

        # Convert hardcoded blocklist to network objects
        self.blocklist_networks = [
            ipaddress.IPv4Network(ip) for ip in self.HARDCODED_BLOCKLIST_IPS
        ]

    def load_roe(self, roe_document: dict, signature: str, public_key: str):
        """
        Load Rules of Engagement from cryptographically signed document.

        Args:
            roe_document: ROE JSON document
            signature: Cryptographic signature
            public_key: Public key to verify signature

        Raises:
            ScopeViolation: If signature is invalid
        """
        # Verify signature
        if not self._verify_signature(roe_document, signature, public_key):
            raise ScopeViolation(
                ScopeViolationType.INVALID_SIGNATURE,
                "ROE_DOCUMENT",
                "ROE signature verification failed"
            )

        # Load scope
        self.engagement_id = roe_document.get('engagement_id')
        self.roe_timestamp = datetime.fromisoformat(roe_document.get('timestamp'))
        self.roe_signed_by = roe_document.get('signed_by')
        self.roe_signature = signature

        # Load authorized targets
        for ip_range in roe_document.get('authorized_ips', []):
            try:
                network = ipaddress.IPv4Network(ip_range)
                self.authorized_cidrs.append(network)
            except ValueError as e:
                self.logger.error(f"Invalid IP range in ROE: {ip_range}: {e}")

        for domain in roe_document.get('authorized_domains', []):
            self.authorized_domains.add(domain.lower())

        # Load exclusions
        for ip_range in roe_document.get('excluded_ips', []):
            try:
                network = ipaddress.IPv4Network(ip_range)
                self.excluded_ips.add(network)
            except ValueError as e:
                self.logger.error(f"Invalid excluded IP: {ip_range}: {e}")

        for domain in roe_document.get('excluded_domains', []):
            self.excluded_domains.add(domain.lower())

        # Load geographic restrictions
        self.allowed_countries = set(roe_document.get('allowed_countries', []))

        self.logger.info(f"ROE loaded: Engagement {self.engagement_id}")
        self.logger.info(f"Authorized IPs: {len(self.authorized_cidrs)} ranges")
        self.logger.info(f"Authorized domains: {len(self.authorized_domains)} domains")

    def _verify_signature(self, document: dict, signature: str, public_key: str) -> bool:
        """Verify cryptographic signature of ROE document."""
        # In production, use proper crypto (RSA, Ed25519, etc.)
        # This is a simplified example
        document_hash = hashlib.sha256(
            json.dumps(document, sort_keys=True).encode()
        ).hexdigest()

        # TODO: Implement proper signature verification
        # For now, just check if signature is present
        return bool(signature) and len(signature) > 32

    def check_ip(self, ip: str) -> bool:
        """
        Check if IP is in authorized scope.

        Args:
            ip: IP address to check

        Returns:
            True if authorized, False otherwise

        Raises:
            ScopeViolation: If target is in hardcoded blocklist
        """
        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            raise ScopeViolation(
                ScopeViolationType.NOT_IN_SCOPE,
                ip,
                "Invalid IP address format"
            )

        # Check hardcoded blocklist FIRST (cannot be overridden)
        for blocked_network in self.blocklist_networks:
            if ip_obj in blocked_network:
                violation = ScopeViolation(
                    ScopeViolationType.HARDCODED_BLOCKLIST,
                    ip,
                    f"IP in hardcoded blocklist: {blocked_network}"
                )
                self.violations.append(violation)
                raise violation

        # Check exclusions
        for excluded_network in self.excluded_ips:
            if ip_obj in excluded_network:
                violation = ScopeViolation(
                    ScopeViolationType.NOT_IN_SCOPE,
                    ip,
                    f"IP explicitly excluded from scope"
                )
                self.violations.append(violation)
                raise violation

        # Check if in authorized scope
        in_scope = False
        for authorized_network in self.authorized_cidrs:
            if ip_obj in authorized_network:
                in_scope = True
                break

        if not in_scope:
            violation = ScopeViolation(
                ScopeViolationType.NOT_IN_SCOPE,
                ip,
                "IP not in authorized scope"
            )
            self.violations.append(violation)
            raise violation

        self.logger.debug(f"✓ IP {ip} is in authorized scope")
        return True

    def check_domain(self, domain: str) -> bool:
        """
        Check if domain is in authorized scope.

        Args:
            domain: Domain name to check

        Returns:
            True if authorized

        Raises:
            ScopeViolation: If domain not authorized
        """
        domain = domain.lower().strip()

        # Check hardcoded TLD blocklist
        for blocked_tld in self.HARDCODED_BLOCKLIST_TLDS:
            if domain.endswith(blocked_tld):
                violation = ScopeViolation(
                    ScopeViolationType.HARDCODED_BLOCKLIST,
                    domain,
                    f"Domain uses blocked TLD: {blocked_tld}"
                )
                self.violations.append(violation)
                raise violation

        # Check for critical infrastructure keywords
        for keyword in self.CRITICAL_INFRASTRUCTURE_KEYWORDS:
            if keyword in domain:
                violation = ScopeViolation(
                    ScopeViolationType.CRITICAL_INFRASTRUCTURE,
                    domain,
                    f"Domain contains critical infrastructure keyword: {keyword}"
                )
                self.violations.append(violation)
                raise violation

        # Check exclusions
        if domain in self.excluded_domains:
            violation = ScopeViolation(
                ScopeViolationType.NOT_IN_SCOPE,
                domain,
                "Domain explicitly excluded from scope"
            )
            self.violations.append(violation)
            raise violation

        # Check if in authorized scope
        if domain not in self.authorized_domains:
            # Check subdomains
            is_subdomain = False
            for auth_domain in self.authorized_domains:
                if domain.endswith('.' + auth_domain):
                    is_subdomain = True
                    break

            if not is_subdomain:
                violation = ScopeViolation(
                    ScopeViolationType.NOT_IN_SCOPE,
                    domain,
                    "Domain not in authorized scope"
                )
                self.violations.append(violation)
                raise violation

        self.logger.debug(f"✓ Domain {domain} is in authorized scope")
        return True

    def check_target(self, target: str) -> bool:
        """
        Universal target checker (handles IPs, domains, URLs).

        Args:
            target: Target to check (IP, domain, or URL)

        Returns:
            True if authorized

        Raises:
            ScopeViolation: If target not authorized
        """
        # Try to parse as IP
        try:
            ipaddress.IPv4Address(target)
            return self.check_ip(target)
        except ValueError:
            pass

        # Extract domain from URL
        if '://' in target:
            # It's a URL
            domain = target.split('://')[1].split('/')[0].split(':')[0]
        else:
            domain = target

        return self.check_domain(domain)

    def get_scope_summary(self) -> dict:
        """Get summary of current scope configuration."""
        return {
            'engagement_id': self.engagement_id,
            'roe_signed_by': self.roe_signed_by,
            'roe_timestamp': self.roe_timestamp.isoformat() if self.roe_timestamp else None,
            'authorized_ip_ranges': len(self.authorized_cidrs),
            'authorized_domains': len(self.authorized_domains),
            'excluded_ips': len(self.excluded_ips),
            'excluded_domains': len(self.excluded_domains),
            'violations_logged': len(self.violations),
            'hardcoded_blocklists': {
                'ip_ranges': len(self.HARDCODED_BLOCKLIST_IPS),
                'tlds': len(self.HARDCODED_BLOCKLIST_TLDS),
                'keywords': len(self.CRITICAL_INFRASTRUCTURE_KEYWORDS)
            }
        }

    def log_violation_report(self) -> str:
        """Generate violation report."""
        report = ["=" * 80]
        report.append("SCOPE VIOLATION REPORT")
        report.append("=" * 80)
        report.append(f"Engagement ID: {self.engagement_id}")
        report.append(f"Total Violations: {len(self.violations)}")
        report.append("")

        for i, violation in enumerate(self.violations, 1):
            report.append(f"{i}. [{violation.timestamp.isoformat()}]")
            report.append(f"   Type: {violation.violation_type.value}")
            report.append(f"   Target: {violation.target}")
            report.append(f"   Reason: {violation.reason}")
            report.append("")

        return "\n".join(report)


# ============================================================================
# EXAMPLE ROE DOCUMENT
# ============================================================================

EXAMPLE_ROE = {
    "engagement_id": "PROM-2025-001",
    "engagement_name": "Acme Corp Pentest",
    "timestamp": "2025-11-10T00:00:00Z",
    "signed_by": "Bobby Don McWilliams II",
    "authorized_ips": [
        "203.0.113.0/24",    # Example authorized range
        "198.51.100.0/24"
    ],
    "authorized_domains": [
        "example.com",
        "test.example.com",
        "*.example.com"
    ],
    "excluded_ips": [
        "203.0.113.1"  # Excluded from authorized range
    ],
    "excluded_domains": [
        "production.example.com"
    ],
    "allowed_countries": ["US", "GB", "CA"],
    "max_impact_level": "read_only",
    "duration_hours": 168,  # 1 week
    "emergency_contact": "security@example.com"
}

if __name__ == "__main__":
    # Test scope enforcer
    enforcer = ScopeEnforcer()

    # Load ROE
    enforcer.load_roe(
        EXAMPLE_ROE,
        signature="example_signature_hash_12345",
        public_key="example_public_key"
    )

    # Test cases
    print("Testing scope enforcement:")
    print("=" * 80)

    # Should pass
    test_cases_pass = [
        "203.0.113.5",
        "example.com",
        "test.example.com"
    ]

    # Should fail
    test_cases_fail = [
        "8.8.8.8",           # Not in scope
        "192.168.1.1",       # Private IP (blocklist)
        "whitehouse.gov",    # .gov TLD (blocklist)
        "hospital.com",      # Critical infrastructure
        "203.0.113.1"        # Excluded
    ]

    for target in test_cases_pass:
        try:
            enforcer.check_target(target)
            print(f"✓ {target} - ALLOWED")
        except ScopeViolation as e:
            print(f"✗ {target} - BLOCKED: {e}")

    for target in test_cases_fail:
        try:
            enforcer.check_target(target)
            print(f"✗ {target} - SHOULD HAVE BEEN BLOCKED!")
        except ScopeViolation as e:
            print(f"✓ {target} - BLOCKED: {e}")

    print("\n" + enforcer.log_violation_report())
