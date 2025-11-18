#!/usr/bin/env python3
"""
PROMETHEUS VOICE AUTHORIZATION SYSTEM
ElevenLabs V3 TTS with Full Emotional Range + Authorization Flow

Authority Level: 11.0
Commander: Bobby Don McWilliams II

AUTHORIZATION FLOW:
1. ANNOUNCE: Prometheus announces operation details with VIGOR
2. DESCRIBE: Explains what the tool does and possible consequences
3. REQUEST APPROVAL: Asks for authorization
4. EXECUTE: Only proceeds if approved OR Authority Level 11.0 overrides
"""

import logging
from typing import Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger("VoiceAuthorization")

class OperationRisk(Enum):
    """Risk levels for operations"""
    SAFE = "safe"  # Read-only, information gathering
    LOW = "low"  # Non-destructive scanning
    MEDIUM = "medium"  # Active reconnaissance, service fingerprinting
    HIGH = "high"  # Exploitation attempts, privilege escalation
    CRITICAL = "critical"  # Destructive operations, counter-attacks, backdoors

class AuthorizationResult(Enum):
    """Authorization decision results"""
    APPROVED = "approved"
    DENIED = "denied"
    OVERRIDE_11_0 = "override_authority_11_0"

class VoiceAuthorizationSystem:
    """
    Voice-based authorization system with ElevenLabs V3 TTS.

    FEATURES:
    - Announces every offensive operation before execution
    - Describes consequences and potential impacts
    - Requires explicit approval for HIGH/CRITICAL operations
    - Authority Level 11.0 can override any denial
    - Full emotional range and dynamic responses
    - VIGOR in all tactical announcements
    """

    def __init__(self, authority_level: float = 9.0, voice_enabled: bool = True):
        """
        Initialize Voice Authorization System.

        Args:
            authority_level: Current operator authority level (1.0-11.0)
            voice_enabled: Whether voice announcements are enabled
        """
        self.authority_level = authority_level
        self.voice_enabled = voice_enabled
        self.operation_history = []

        # Risk categories for tools
        self.tool_risks = self._initialize_tool_risks()

        logger.info(f"🔥 Voice Authorization System initialized - Authority Level: {authority_level}")

    def _initialize_tool_risks(self) -> Dict[str, OperationRisk]:
        """Initialize risk levels for all tool categories."""
        return {
            # SAFE - Read-only operations
            "prom_auto_stats": OperationRisk.SAFE,
            "prom_voice_status": OperationRisk.SAFE,
            "prom_memory_stats": OperationRisk.SAFE,
            "prom_heal_stats": OperationRisk.SAFE,
            "prom_stealth_anonymity": OperationRisk.SAFE,

            # LOW - Non-destructive scanning
            "prom_auto_intel": OperationRisk.LOW,
            "prom_auto_gather": OperationRisk.LOW,
            "prom_memory_search": OperationRisk.LOW,
            "prom_memory_recall": OperationRisk.LOW,
            "prom_memory_list": OperationRisk.LOW,

            # MEDIUM - Active reconnaissance
            "prom_auto_decision": OperationRisk.MEDIUM,
            "prom_memory_store": OperationRisk.MEDIUM,
            "prom_memory_retrieve": OperationRisk.MEDIUM,
            "prom_defense_ids": OperationRisk.MEDIUM,
            "prom_defense_analyze": OperationRisk.MEDIUM,

            # HIGH - Offensive operations
            "prom_auto_execute": OperationRisk.HIGH,
            "prom_stealth_engage": OperationRisk.HIGH,
            "prom_stealth_tor": OperationRisk.HIGH,
            "prom_stealth_vpn": OperationRisk.HIGH,
            "prom_stealth_obfuscate": OperationRisk.HIGH,
            "prom_defense_quarantine": OperationRisk.HIGH,
            "prom_defense_repel": OperationRisk.HIGH,
            "prom_heal": OperationRisk.HIGH,
            "prom_memory_crystallize": OperationRisk.HIGH,
            "prom_memory_learn": OperationRisk.HIGH,

            # CRITICAL - Destructive/dangerous operations
            "prom_auto_loop": OperationRisk.CRITICAL,
            "prom_stealth_backdoor": OperationRisk.CRITICAL,
            "prom_defense_counter": OperationRisk.CRITICAL,
            "prom_defense_reflect": OperationRisk.CRITICAL,
        }

    def get_tool_risk(self, tool_name: str) -> OperationRisk:
        """Get risk level for a tool."""
        return self.tool_risks.get(tool_name, OperationRisk.MEDIUM)

    def _generate_announcement(self, tool_name: str, operation: str, risk: OperationRisk,
                              target: Optional[str] = None, params: Optional[Dict] = None) -> str:
        """Generate tactical announcement text with VIGOR."""

        # Base announcement
        announcement = f"🔥 **PROMETHEUS PRIME - OPERATION INITIATION** 🔥\\n\\n"
        announcement += f"**TOOL**: {tool_name}\\n"
        announcement += f"**OPERATION**: {operation}\\n"
        announcement += f"**RISK LEVEL**: {risk.value.upper()}\\n"

        if target:
            announcement += f"**TARGET**: {target}\\n"

        announcement += "\\n**DESCRIPTION**:\\n"

        # Get tool description and consequences
        description, consequences = self._get_operation_details(tool_name, operation, params)
        announcement += f"{description}\\n\\n"
        announcement += f"**POSSIBLE CONSEQUENCES**:\\n{consequences}\\n\\n"

        # Authorization request based on risk
        if risk in [OperationRisk.HIGH, OperationRisk.CRITICAL]:
            announcement += "⚠️  **AUTHORIZATION REQUIRED**\\n"
            announcement += f"This is a **{risk.value.upper()} RISK** operation.\\n"
            announcement += "\\n**Do you authorize execution of this operation?**\\n"
            announcement += "- Type 'YES' to approve\\n"
            announcement += "- Type 'NO' to deny\\n"
            if self.authority_level >= 11.0:
                announcement += "- Authority Level 11.0 can type 'OVERRIDE' to force execution\\n"
        else:
            announcement += "✅ **AUTO-APPROVED** (Low risk operation)\\n"

        return announcement

    def _get_operation_details(self, tool_name: str, operation: str,
                               params: Optional[Dict] = None) -> Tuple[str, str]:
        """Get detailed description and consequences for an operation."""

        # Tool descriptions
        descriptions = {
            "prom_auto_loop": (
                "Initiates fully autonomous security operation loop with AI-driven decision making. "
                "Prometheus will continuously gather intelligence, make tactical decisions using 5-model "
                "consensus, and execute operations without human intervention.",
                "- Autonomous execution of offensive security operations\\n"
                "- Potential for unintended system compromise\\n"
                "- Network traffic generation that may trigger IDS/IPS\\n"
                "- Legal implications if targeting unauthorized systems\\n"
                "- May escalate privileges or create persistent backdoors"
            ),
            "prom_stealth_backdoor": (
                "Creates sophisticated backdoor with maximum stealth capabilities. Options include "
                "reverse shells, web shells, and rootkits. Backdoor will be obfuscated and designed "
                "to evade detection by antivirus and EDR systems.",
                "- Permanent unauthorized access to target system\\n"
                "- Criminal charges if used without authorization\\n"
                "- Detection may trigger incident response\\n"
                "- Backdoor may be discovered and analyzed\\n"
                "- Attribution risk if forensics traces back to operator"
            ),
            "prom_defense_counter": (
                "Launches active counter-attack against detected attacker. Will perform port scanning, "
                "exploit scanning, and attempt reverse connection to attacker's system. This is an "
                "OFFENSIVE operation against the threat actor.",
                "- Legal gray area - active defense may be illegal\\n"
                "- May escalate conflict with attacker\\n"
                "- Attacker may be using compromised proxy/relay\\n"
                "- Could target innocent third party\\n"
                "- May violate computer fraud laws"
            ),
            "prom_auto_execute": (
                f"Executes specific security operation: {operation}. "
                "Operation will run with full capabilities and may modify target systems.",
                "- Target system modifications\\n"
                "- Network traffic generation\\n"
                "- Potential system instability\\n"
                "- Detection by security controls\\n"
                "- Attribution risk"
            ),
            "prom_stealth_engage": (
                "Activates 6-layer maximum stealth mode: MAC address randomization, multi-VPN chain, "
                "Tor network routing, polymorphic traffic obfuscation, DNS over HTTPS, and kill switch. "
                "All subsequent operations will be maximally anonymized.",
                "- Significantly slower network performance\\n"
                "- Some services may block Tor exit nodes\\n"
                "- Kill switch will disconnect if VPN/Tor fails\\n"
                "- Still not 100% anonymous (timing attacks possible)\\n"
                "- May raise suspicion on monitored networks"
            ),
        }

        # Default description for unlisted tools
        default_desc = (
            f"Executes {tool_name} operation. This is a standard Prometheus Prime capability.",
            "- Operation will execute as designed\\n"
            "- May generate network traffic\\n"
            "- Could be logged by target systems\\n"
            "- Follow all ROE and authorization requirements"
        )

        return descriptions.get(tool_name, default_desc)

    def _speak_announcement(self, text: str):
        """Speak announcement using ElevenLabs V3 TTS with VIGOR."""
        if not self.voice_enabled:
            logger.info("Voice disabled - announcement printed only")
            return

        try:
            # Try to import and use voice system
            from src.voice.prometheus_voice import PrometheusVoice

            voice = PrometheusVoice(config={
                "voice_enabled": True,
                "vigor_mode": True,  # SPEAK WITH VIGOR!
                "emotional_range": "full",
                "personality": "tactical_commander"
            })

            # Speak with tactical commander personality
            logger.info("🔊 Playing voice announcement...")
            voice.announce_operation(text, severity="high", vigor=True)

        except Exception as e:
            logger.warning(f"Voice synthesis failed: {e} - announcement printed only")

    def request_authorization(self, tool_name: str, operation: str,
                            target: Optional[str] = None,
                            params: Optional[Dict] = None,
                            auto_approve_safe: bool = True) -> AuthorizationResult:
        """
        Request authorization for operation execution.

        Args:
            tool_name: Name of the MCP tool
            operation: Operation to perform
            target: Optional target (host, network, etc.)
            params: Optional operation parameters
            auto_approve_safe: Auto-approve SAFE/LOW risk operations

        Returns:
            AuthorizationResult: APPROVED, DENIED, or OVERRIDE_11_0
        """
        risk = self.get_tool_risk(tool_name)

        # Generate and display announcement
        announcement = self._generate_announcement(tool_name, operation, risk, target, params)
        print(announcement)

        # Speak announcement with VIGOR
        self._speak_announcement(announcement)

        # Auto-approve safe operations if configured
        if auto_approve_safe and risk in [OperationRisk.SAFE, OperationRisk.LOW]:
            logger.info(f"✅ Auto-approved {tool_name} (risk: {risk.value})")
            self._record_authorization(tool_name, operation, AuthorizationResult.APPROVED, risk)
            return AuthorizationResult.APPROVED

        # Request approval for higher risk operations
        print("\\n" + "="*80)
        response = input("Authorization Decision [YES/NO/OVERRIDE]: ").strip().upper()
        print("="*80 + "\\n")

        # Process response
        if response == "OVERRIDE":
            if self.authority_level >= 11.0:
                logger.warning(f"⚠️  AUTHORITY LEVEL 11.0 OVERRIDE - {tool_name} forced execution")
                self._record_authorization(tool_name, operation, AuthorizationResult.OVERRIDE_11_0, risk)
                return AuthorizationResult.OVERRIDE_11_0
            else:
                logger.error(f"❌ OVERRIDE DENIED - Authority Level {self.authority_level} insufficient")
                print(f"❌ **OVERRIDE DENIED** - Your authority level ({self.authority_level}) is insufficient.")
                print("   Only Authority Level 11.0 (Commander) can override denials.\\n")
                self._record_authorization(tool_name, operation, AuthorizationResult.DENIED, risk)
                return AuthorizationResult.DENIED

        elif response == "YES":
            logger.info(f"✅ Operation approved: {tool_name}")
            self._record_authorization(tool_name, operation, AuthorizationResult.APPROVED, risk)
            return AuthorizationResult.APPROVED

        else:  # NO or anything else
            logger.info(f"❌ Operation denied: {tool_name}")
            self._record_authorization(tool_name, operation, AuthorizationResult.DENIED, risk)
            return AuthorizationResult.DENIED

    def _record_authorization(self, tool_name: str, operation: str,
                             result: AuthorizationResult, risk: OperationRisk):
        """Record authorization decision for audit trail."""
        from datetime import datetime

        record = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "operation": operation,
            "risk": risk.value,
            "result": result.value,
            "authority_level": self.authority_level
        }

        self.operation_history.append(record)

        # Log to file for audit
        logger.info(f"AUDIT: {record}")

    def get_authorization_history(self, limit: int = 50) -> list:
        """Get recent authorization history."""
        return self.operation_history[-limit:]

    def get_statistics(self) -> Dict:
        """Get authorization statistics."""
        if not self.operation_history:
            return {"total": 0}

        from collections import Counter

        total = len(self.operation_history)
        results = Counter([r["result"] for r in self.operation_history])
        risks = Counter([r["risk"] for r in self.operation_history])

        return {
            "total_requests": total,
            "approved": results.get("approved", 0),
            "denied": results.get("denied", 0),
            "overrides": results.get("override_authority_11_0", 0),
            "by_risk": dict(risks),
            "approval_rate": results.get("approved", 0) / total if total > 0 else 0
        }


# Singleton instance
_auth_system = None

def get_authorization_system(authority_level: float = 9.0,
                            voice_enabled: bool = True) -> VoiceAuthorizationSystem:
    """Get or create the global authorization system instance."""
    global _auth_system
    if _auth_system is None:
        _auth_system = VoiceAuthorizationSystem(authority_level, voice_enabled)
    return _auth_system


def authorize_operation(tool_name: str, operation: str,
                       target: Optional[str] = None,
                       params: Optional[Dict] = None,
                       authority_level: float = 9.0) -> bool:
    """
    Convenience function to request operation authorization.

    Returns:
        bool: True if authorized, False if denied
    """
    auth_system = get_authorization_system(authority_level)
    result = auth_system.request_authorization(tool_name, operation, target, params)

    return result in [AuthorizationResult.APPROVED, AuthorizationResult.OVERRIDE_11_0]


if __name__ == "__main__":
    # Test the authorization system
    print("🔥 PROMETHEUS VOICE AUTHORIZATION SYSTEM - TEST MODE 🔥\\n")

    auth = VoiceAuthorizationSystem(authority_level=11.0, voice_enabled=False)

    # Test 1: Safe operation (auto-approved)
    print("\\n" + "="*80)
    print("TEST 1: Safe Operation (should auto-approve)")
    print("="*80)
    result = auth.request_authorization(
        tool_name="prom_memory_stats",
        operation="get_memory_stats",
        auto_approve_safe=True
    )
    print(f"Result: {result.value}\\n")

    # Test 2: Critical operation (requires approval)
    print("\\n" + "="*80)
    print("TEST 2: Critical Operation (requires manual approval)")
    print("="*80)
    result = auth.request_authorization(
        tool_name="prom_stealth_backdoor",
        operation="create_backdoor",
        target="192.168.1.100",
        params={"backdoor_type": "reverse_shell", "port": 4444},
        auto_approve_safe=False
    )
    print(f"Result: {result.value}\\n")

    # Show statistics
    print("\\n" + "="*80)
    print("AUTHORIZATION STATISTICS")
    print("="*80)
    stats = auth.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
