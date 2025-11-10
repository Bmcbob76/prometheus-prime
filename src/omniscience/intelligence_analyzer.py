#!/usr/bin/env python3
"""
PROMETHEUS PRIME - INTELLIGENCE ANALYZER
AI-powered analysis of gathered intelligence for autonomous decision making

Authority Level: 11.0
Commander: Bobby Don McWilliams II

ANALYSIS CAPABILITIES:
- Service fingerprinting and version detection
- Vulnerability correlation across multiple sources
- Attack path optimization
- Risk assessment and prioritization
- Defensive capability estimation
- Success probability calculation
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import re

logger = logging.getLogger("IntelligenceAnalyzer")


class TargetType(Enum):
    """Target types"""
    WEB_SERVER = "web_server"
    DATABASE = "database"
    FILE_SERVER = "file_server"
    MAIL_SERVER = "mail_server"
    DOMAIN_CONTROLLER = "domain_controller"
    NETWORK_DEVICE = "network_device"
    IOT_DEVICE = "iot_device"
    CLOUD_SERVICE = "cloud_service"
    UNKNOWN = "unknown"


class DefenseLevel(Enum):
    """Estimated defense capability level"""
    MINIMAL = "minimal"  # No or basic security
    LOW = "low"  # Basic firewall, outdated patches
    MEDIUM = "medium"  # Standard security controls
    HIGH = "high"  # Advanced security, EDR, monitoring
    VERY_HIGH = "very_high"  # Enterprise security, SOC, threat hunting
    UNKNOWN = "unknown"


@dataclass
class ServiceFingerprint:
    """Service fingerprint analysis"""
    port: int
    service: str
    version: Optional[str]
    banner: Optional[str]
    confidence: float
    vulnerabilities: List[str]
    default_credentials: bool
    metadata: Dict


@dataclass
class TargetProfile:
    """Comprehensive target profile"""
    target_id: str
    hostname: str
    ip_address: str
    target_type: TargetType
    operating_system: Optional[str]
    os_confidence: float
    services: List[ServiceFingerprint]
    defense_level: DefenseLevel
    vulnerabilities: List[str]
    attack_surface_score: float
    risk_score: float
    value_score: float
    recommended_tactics: List[str]
    timestamp: str


@dataclass
class AttackVector:
    """Potential attack vector"""
    vector_id: str
    target: str
    technique: str
    vulnerability: Optional[str]
    exploit: Optional[str]
    success_probability: float
    impact_score: float
    stealth_score: float
    difficulty: str
    prerequisites: List[str]
    steps: List[str]
    estimated_time: float
    metadata: Dict


class IntelligenceAnalyzer:
    """
    AI-powered intelligence analysis for autonomous operations.

    Analyzes gathered intelligence to:
    1. Profile targets comprehensively
    2. Identify vulnerabilities and attack vectors
    3. Estimate defense capabilities
    4. Calculate success probabilities
    5. Recommend optimal attack paths
    6. Assess risks and impacts
    """

    def __init__(self, knowledge_base=None):
        """
        Initialize Intelligence Analyzer.

        Args:
            knowledge_base: OmniscienceKnowledgeBase instance
        """
        self.knowledge_base = knowledge_base
        self.analyzed_targets: Dict[str, TargetProfile] = {}
        self.attack_vectors: Dict[str, List[AttackVector]] = {}

        logger.info("🧠 Intelligence Analyzer initialized")

    def analyze_service(self, port: int, banner: str, nmap_output: Optional[str] = None) -> ServiceFingerprint:
        """
        Analyze service from banner and fingerprinting data.

        Args:
            port: Port number
            banner: Service banner
            nmap_output: Optional nmap service detection output

        Returns:
            ServiceFingerprint with analysis
        """
        logger.info(f"🔍 ANALYZING SERVICE")
        logger.info(f"   Port: {port}")
        logger.info(f"   Banner: {banner[:60]}...")

        # Service identification patterns
        service_patterns = {
            22: ("SSH", r"SSH-([\d\.]+)-OpenSSH_([\d\.]+)"),
            80: ("HTTP", r"Apache/([\d\.]+)|nginx/([\d\.]+)|IIS/([\d\.]+)"),
            443: ("HTTPS", r"Apache/([\d\.]+)|nginx/([\d\.]+)|IIS/([\d\.]+)"),
            21: ("FTP", r"FTP.*?([\d\.]+)"),
            25: ("SMTP", r"SMTP.*?([\d\.]+)"),
            3306: ("MySQL", r"MySQL.*?([\d\.]+)"),
            5432: ("PostgreSQL", r"PostgreSQL.*?([\d\.]+)"),
            1433: ("MSSQL", r"Microsoft SQL Server.*?([\d\.]+)"),
            3389: ("RDP", r"Remote Desktop Protocol"),
            445: ("SMB", r"Samba ([\d\.]+)|Windows")
        }

        service_name = "unknown"
        version = None
        confidence = 0.5

        # Try to match service pattern
        if port in service_patterns:
            service_name, pattern = service_patterns[port]
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                confidence = 0.9
                if match.groups():
                    version = match.group(1)

        # Query vulnerabilities from knowledge base
        vulnerabilities = []
        if self.knowledge_base and version:
            vulns = self.knowledge_base.query_vulnerabilities(service_name, version)
            vulnerabilities = [v.cve_id for v in vulns[:5]]  # Top 5

        # Check for default credentials
        default_creds = self._check_default_credentials(port, service_name)

        fingerprint = ServiceFingerprint(
            port=port,
            service=service_name,
            version=version,
            banner=banner,
            confidence=confidence,
            vulnerabilities=vulnerabilities,
            default_credentials=default_creds,
            metadata={"analyzed": datetime.now().isoformat()}
        )

        logger.info(f"✅ Service identified: {service_name} {version or 'unknown version'}")
        logger.info(f"   Confidence: {confidence:.1%}")
        logger.info(f"   Vulnerabilities: {len(vulnerabilities)}")

        return fingerprint

    def profile_target(self, recon_data: Dict) -> TargetProfile:
        """
        Create comprehensive target profile from reconnaissance data.

        Args:
            recon_data: Gathered reconnaissance data

        Returns:
            TargetProfile with complete analysis
        """
        target_id = recon_data.get("target_id", "unknown")
        hostname = recon_data.get("hostname", "unknown")
        ip_address = recon_data.get("ip", "unknown")

        logger.info(f"🎯 PROFILING TARGET")
        logger.info(f"   Target: {hostname} ({ip_address})")

        # Analyze services
        services = []
        for service_data in recon_data.get("services", []):
            fingerprint = self.analyze_service(
                service_data["port"],
                service_data.get("banner", ""),
                service_data.get("nmap_output")
            )
            services.append(fingerprint)

        # Determine target type
        target_type = self._determine_target_type(services)

        # Estimate OS
        os_name, os_confidence = self._estimate_os(recon_data.get("os_detection", {}))

        # Estimate defense level
        defense_level = self._estimate_defense_level(services, recon_data)

        # Collect all vulnerabilities
        all_vulns = []
        for service in services:
            all_vulns.extend(service.vulnerabilities)

        # Calculate scores
        attack_surface = self._calculate_attack_surface(services)
        risk_score = self._calculate_risk_score(all_vulns, defense_level)
        value_score = self._calculate_value_score(target_type, services)

        # Recommend tactics
        recommended_tactics = self._recommend_tactics(target_type, services, defense_level)

        profile = TargetProfile(
            target_id=target_id,
            hostname=hostname,
            ip_address=ip_address,
            target_type=target_type,
            operating_system=os_name,
            os_confidence=os_confidence,
            services=services,
            defense_level=defense_level,
            vulnerabilities=all_vulns,
            attack_surface_score=attack_surface,
            risk_score=risk_score,
            value_score=value_score,
            recommended_tactics=recommended_tactics,
            timestamp=datetime.now().isoformat()
        )

        self.analyzed_targets[target_id] = profile

        logger.info(f"✅ TARGET PROFILE COMPLETE")
        logger.info(f"   Type: {target_type.value}")
        logger.info(f"   OS: {os_name} ({os_confidence:.1%})")
        logger.info(f"   Defense Level: {defense_level.value}")
        logger.info(f"   Services: {len(services)}")
        logger.info(f"   Vulnerabilities: {len(all_vulns)}")
        logger.info(f"   Attack Surface: {attack_surface:.1f}/10")
        logger.info(f"   Risk Score: {risk_score:.1f}/10")

        return profile

    def generate_attack_vectors(self, target_profile: TargetProfile) -> List[AttackVector]:
        """
        Generate potential attack vectors for target.

        Args:
            target_profile: TargetProfile to analyze

        Returns:
            List of AttackVector options sorted by viability
        """
        logger.info(f"⚔️  GENERATING ATTACK VECTORS")
        logger.info(f"   Target: {target_profile.hostname}")

        vectors = []
        vector_count = 0

        # Generate vectors for each vulnerable service
        for service in target_profile.services:
            for cve_id in service.vulnerabilities:
                # Get exploit information from knowledge base
                exploits = []
                if self.knowledge_base:
                    exploits = self.knowledge_base.query_exploits(cve_id=cve_id)

                if exploits:
                    for exploit in exploits:
                        vector_count += 1
                        vector = self._create_attack_vector(
                            vector_count,
                            target_profile,
                            service,
                            cve_id,
                            exploit
                        )
                        vectors.append(vector)

        # Sort by viability (success_probability * impact_score * stealth_score)
        vectors.sort(key=lambda v: v.success_probability * v.impact_score * v.stealth_score, reverse=True)

        self.attack_vectors[target_profile.target_id] = vectors

        logger.info(f"✅ Generated {len(vectors)} attack vectors")
        if vectors:
            logger.info(f"   Best vector: {vectors[0].technique} (success: {vectors[0].success_probability:.1%})")

        return vectors

    def _create_attack_vector(self, vector_id: int, profile: TargetProfile,
                             service: ServiceFingerprint, cve_id: str, exploit) -> AttackVector:
        """Create attack vector from exploit information."""
        # Calculate success probability
        base_probability = 0.7
        if exploit.verified:
            base_probability += 0.2
        if profile.defense_level in [DefenseLevel.MINIMAL, DefenseLevel.LOW]:
            base_probability += 0.1
        success_probability = min(1.0, base_probability)

        # Calculate impact score (1-10)
        impact = 7.0
        if "remote code execution" in exploit.description.lower():
            impact = 10.0
        elif "privilege escalation" in exploit.description.lower():
            impact = 9.0
        elif "information disclosure" in exploit.description.lower():
            impact = 5.0

        # Calculate stealth score (1-10)
        stealth = 6.0
        if profile.defense_level in [DefenseLevel.HIGH, DefenseLevel.VERY_HIGH]:
            stealth -= 2.0
        if "exploit" in exploit.exploit_type:
            stealth -= 1.0

        # Determine difficulty
        difficulty = "medium"
        if exploit.verified and service.default_credentials:
            difficulty = "easy"
        elif profile.defense_level == DefenseLevel.VERY_HIGH:
            difficulty = "hard"

        # Determine prerequisites
        prerequisites = []
        if service.port not in [80, 443]:
            prerequisites.append("Network access to target")
        if "authentication" in exploit.description.lower():
            prerequisites.append("Valid credentials")

        # Generate attack steps
        steps = [
            f"1. Verify {service.service} version {service.version or 'unknown'}",
            f"2. Download exploit {exploit.exploit_id} from {exploit.code_url}",
            f"3. Configure exploit for target {profile.ip_address}:{service.port}",
            f"4. Execute exploit and verify access",
            f"5. Establish persistence if successful"
        ]

        # Estimate time
        estimated_time = 30.0  # minutes
        if difficulty == "easy":
            estimated_time = 15.0
        elif difficulty == "hard":
            estimated_time = 60.0

        return AttackVector(
            vector_id=f"VEC-{vector_id:04d}",
            target=f"{profile.hostname} ({profile.ip_address})",
            technique=exploit.title,
            vulnerability=cve_id,
            exploit=exploit.exploit_id,
            success_probability=success_probability,
            impact_score=impact,
            stealth_score=stealth,
            difficulty=difficulty,
            prerequisites=prerequisites,
            steps=steps,
            estimated_time=estimated_time,
            metadata={"generated": datetime.now().isoformat()}
        )

    def _determine_target_type(self, services: List[ServiceFingerprint]) -> TargetType:
        """Determine target type from services."""
        service_names = [s.service.lower() for s in services]

        if any("http" in s for s in service_names):
            return TargetType.WEB_SERVER
        elif any("mysql" in s or "postgresql" in s or "mssql" in s for s in service_names):
            return TargetType.DATABASE
        elif any("smtp" in s or "imap" in s or "pop3" in s for s in service_names):
            return TargetType.MAIL_SERVER
        elif any("ldap" in s or "kerberos" in s for s in service_names):
            return TargetType.DOMAIN_CONTROLLER
        elif any("smb" in s or "ftp" in s or "nfs" in s for s in service_names):
            return TargetType.FILE_SERVER
        else:
            return TargetType.UNKNOWN

    def _estimate_os(self, os_detection: Dict) -> Tuple[str, float]:
        """Estimate operating system."""
        if not os_detection:
            return ("Unknown", 0.0)

        os_name = os_detection.get("name", "Unknown")
        confidence = os_detection.get("accuracy", 0.0) / 100.0

        return (os_name, confidence)

    def _estimate_defense_level(self, services: List[ServiceFingerprint], recon_data: Dict) -> DefenseLevel:
        """Estimate defense capability level."""
        # Count security indicators
        security_score = 0

        # Check for security services
        service_names = [s.service.lower() for s in services]
        if any("firewall" in s or "ids" in s or "ips" in s for s in service_names):
            security_score += 2

        # Check for filtered ports (indicates firewall)
        if recon_data.get("filtered_ports", 0) > 10:
            security_score += 1

        # Check for modern service versions
        modern_versions = sum(1 for s in services if s.version and "2020" in s.version or "2021" in s.version or "2022" in s.version)
        if modern_versions > len(services) * 0.5:
            security_score += 1

        # Check for absence of default credentials
        no_defaults = sum(1 for s in services if not s.default_credentials)
        if no_defaults == len(services):
            security_score += 1

        # Map score to defense level
        if security_score >= 4:
            return DefenseLevel.VERY_HIGH
        elif security_score == 3:
            return DefenseLevel.HIGH
        elif security_score == 2:
            return DefenseLevel.MEDIUM
        elif security_score == 1:
            return DefenseLevel.LOW
        else:
            return DefenseLevel.MINIMAL

    def _calculate_attack_surface(self, services: List[ServiceFingerprint]) -> float:
        """Calculate attack surface score (1-10)."""
        # More services = larger attack surface
        base_score = min(10.0, len(services) * 1.5)

        # Add points for vulnerable services
        vuln_services = sum(1 for s in services if len(s.vulnerabilities) > 0)
        base_score += vuln_services * 0.5

        return min(10.0, base_score)

    def _calculate_risk_score(self, vulnerabilities: List[str], defense_level: DefenseLevel) -> float:
        """Calculate risk score (1-10)."""
        # More vulnerabilities = higher risk for target (lower risk for us)
        vuln_score = min(10.0, len(vulnerabilities) * 2.0)

        # Adjust for defense level (better defenses = higher risk for us)
        defense_multipliers = {
            DefenseLevel.MINIMAL: 0.5,
            DefenseLevel.LOW: 0.7,
            DefenseLevel.MEDIUM: 1.0,
            DefenseLevel.HIGH: 1.3,
            DefenseLevel.VERY_HIGH: 1.6,
            DefenseLevel.UNKNOWN: 1.0
        }

        multiplier = defense_multipliers.get(defense_level, 1.0)
        risk_score = vuln_score * (2.0 - multiplier) * 0.5  # Inverse relationship

        return min(10.0, max(1.0, risk_score))

    def _calculate_value_score(self, target_type: TargetType, services: List[ServiceFingerprint]) -> float:
        """Calculate target value score (1-10)."""
        # Base value by type
        type_values = {
            TargetType.DOMAIN_CONTROLLER: 10.0,
            TargetType.DATABASE: 9.0,
            TargetType.WEB_SERVER: 7.0,
            TargetType.MAIL_SERVER: 7.0,
            TargetType.FILE_SERVER: 6.0,
            TargetType.NETWORK_DEVICE: 8.0,
            TargetType.CLOUD_SERVICE: 9.0,
            TargetType.IOT_DEVICE: 3.0,
            TargetType.UNKNOWN: 5.0
        }

        return type_values.get(target_type, 5.0)

    def _recommend_tactics(self, target_type: TargetType, services: List[ServiceFingerprint],
                          defense_level: DefenseLevel) -> List[str]:
        """Recommend attack tactics."""
        tactics = []

        # Reconnaissance always first
        tactics.append("T1595 - Active Scanning")

        # Based on services
        service_names = [s.service.lower() for s in services]

        if any("http" in s for s in service_names):
            tactics.append("T1190 - Exploit Public-Facing Application")

        if any(s.default_credentials for s in services):
            tactics.append("T1078 - Valid Accounts (default credentials)")

        if any(len(s.vulnerabilities) > 0 for s in services):
            tactics.append("T1190 - Exploit Public-Facing Application")

        # Always consider privilege escalation
        tactics.append("T1068 - Exploitation for Privilege Escalation")

        # Based on defense level
        if defense_level in [DefenseLevel.HIGH, DefenseLevel.VERY_HIGH]:
            tactics.insert(1, "T1027 - Obfuscated Files or Information")
            tactics.insert(1, "T1562 - Impair Defenses")

        return tactics

    def _check_default_credentials(self, port: int, service: str) -> bool:
        """Check if service commonly has default credentials."""
        default_cred_services = {
            21: "FTP",  # anonymous:anonymous
            23: "Telnet",  # admin:admin
            3306: "MySQL",  # root:
            5432: "PostgreSQL",  # postgres:postgres
            1433: "MSSQL",  # sa:sa
            27017: "MongoDB",  # no auth
            6379: "Redis"  # no auth
        }

        return port in default_cred_services

    def get_statistics(self) -> Dict:
        """Get analyzer statistics."""
        total_targets = len(self.analyzed_targets)
        total_vectors = sum(len(v) for v in self.attack_vectors.values())

        return {
            "targets_analyzed": total_targets,
            "attack_vectors_generated": total_vectors,
            "average_vectors_per_target": total_vectors / total_targets if total_targets > 0 else 0
        }


if __name__ == "__main__":
    # Test Intelligence Analyzer
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    print("\n🧠 PROMETHEUS PRIME - INTELLIGENCE ANALYZER")
    print("="*60)

    analyzer = IntelligenceAnalyzer()

    # Test 1: Analyze service
    print("\n" + "="*60)
    print("TEST 1: Service Analysis")
    print("="*60)

    fingerprint = analyzer.analyze_service(
        80,
        "Apache/2.4.49 (Unix) OpenSSL/1.1.1k"
    )
    print(f"\nService: {fingerprint.service}")
    print(f"Version: {fingerprint.version}")
    print(f"Confidence: {fingerprint.confidence:.1%}")
    print(f"Vulnerabilities: {len(fingerprint.vulnerabilities)}")

    # Test 2: Profile target
    print("\n" + "="*60)
    print("TEST 2: Target Profiling")
    print("="*60)

    recon_data = {
        "target_id": "TARGET-001",
        "hostname": "web-server-01",
        "ip": "192.168.1.100",
        "services": [
            {"port": 22, "banner": "SSH-2.0-OpenSSH_8.2", "service": "SSH"},
            {"port": 80, "banner": "Apache/2.4.49 (Unix)", "service": "HTTP"},
            {"port": 443, "banner": "Apache/2.4.49 (Unix) OpenSSL/1.1.1k", "service": "HTTPS"}
        ],
        "os_detection": {"name": "Linux 5.4", "accuracy": 95},
        "filtered_ports": 5
    }

    profile = analyzer.profile_target(recon_data)
    print(f"\nTarget Type: {profile.target_type.value}")
    print(f"Defense Level: {profile.defense_level.value}")
    print(f"Attack Surface: {profile.attack_surface_score:.1f}/10")
    print(f"Risk Score: {profile.risk_score:.1f}/10")
    print(f"Recommended Tactics: {len(profile.recommended_tactics)}")

    # Show statistics
    print("\n" + "="*60)
    print("ANALYZER STATISTICS")
    print("="*60)
    stats = analyzer.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
