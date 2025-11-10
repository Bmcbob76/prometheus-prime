#!/usr/bin/env python3
"""
PROMETHEUS PRIME - AI GOAL GENERATOR
Parses ROE documents and generates autonomous attack objectives

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - SELF-DIRECTED GOAL GENERATION
"""

import json
import logging
import sys
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime


class GoalType(Enum):
    """Types of penetration testing goals."""
    # Reconnaissance goals
    DISCOVER_HOSTS = "discover_hosts"
    MAP_NETWORK = "map_network"
    ENUMERATE_SERVICES = "enumerate_services"
    IDENTIFY_TECHNOLOGIES = "identify_technologies"

    # Access goals
    GAIN_INITIAL_ACCESS = "gain_initial_access"
    GAIN_USER_ACCESS = "gain_user_access"
    GAIN_ADMIN_ACCESS = "gain_admin_access"
    GAIN_DOMAIN_ADMIN = "gain_domain_admin"
    GAIN_ROOT_ACCESS = "gain_root_access"

    # Lateral movement goals
    LATERAL_MOVE_TO_TARGET = "lateral_move_to_target"
    COMPROMISE_SEGMENT = "compromise_segment"
    PIVOT_TO_NETWORK = "pivot_to_network"

    # Data goals
    LOCATE_SENSITIVE_DATA = "locate_sensitive_data"
    EXFILTRATE_DATA = "exfiltrate_data"
    ACCESS_DATABASE = "access_database"
    ACCESS_FILE_SHARE = "access_file_share"

    # Persistence goals
    ESTABLISH_PERSISTENCE = "establish_persistence"
    MAINTAIN_ACCESS = "maintain_access"

    # Validation goals
    VALIDATE_CONTROL = "validate_control"
    TEST_DETECTION = "test_detection"
    VERIFY_SCOPE = "verify_scope"


class GoalPriority(Enum):
    """Priority levels for goals."""
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 3
    OPTIONAL = 1


class GoalStatus(Enum):
    """Status of a goal."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Goal:
    """A single penetration testing goal."""
    goal_id: str
    goal_type: GoalType
    description: str
    priority: GoalPriority
    status: GoalStatus
    prerequisites: List[str]  # Goal IDs that must complete first
    success_criteria: List[str]  # What defines success
    target: Optional[str] = None  # Specific target if applicable
    estimated_difficulty: Optional[int] = None  # 1-10
    created_at: float = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    progress: float = 0.0  # 0.0 to 1.0

    def __post_init__(self):
        if self.created_at is None:
            import time
            self.created_at = time.time()

    def to_dict(self) -> dict:
        result = asdict(self)
        result['goal_type'] = self.goal_type.value
        result['priority'] = self.priority.value
        result['status'] = self.status.value
        return result


@dataclass
class AttackPath:
    """A possible path to achieve a goal."""
    path_id: str
    goal_id: str
    steps: List[Dict]  # Steps to execute
    estimated_success_rate: float  # 0.0 to 1.0
    estimated_time_minutes: int
    risk_level: str  # low, medium, high
    required_tools: List[str]


class AIGoalGenerator:
    """
    AI-powered goal generator that parses ROE documents and creates
    autonomous attack objectives organized into attack trees.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize AI goal generator."""
        self.logger = logger or logging.getLogger('GoalGenerator')

        # Goal hierarchy
        self.goals: List[Goal] = []
        self.goal_dependencies: Dict[str, List[str]] = {}  # goal_id -> [dependent_goal_ids]
        self.attack_paths: List[AttackPath] = []

        # ROE document
        self.roe_document: Optional[Dict] = None

        self.logger.info("AI Goal Generator initialized")

    def load_roe(self, roe_document: Dict) -> List[Goal]:
        """
        Parse ROE document and generate goals.

        Args:
            roe_document: Rules of Engagement document

        Returns:
            List of generated goals
        """
        self.roe_document = roe_document
        self.goals.clear()
        self.attack_paths.clear()

        self.logger.info(f"Parsing ROE document: {roe_document.get('engagement_id')}")

        # Extract engagement objectives
        objectives = roe_document.get('objectives', [])
        engagement_type = roe_document.get('engagement_type', 'penetration_test')

        # Generate goals based on engagement type
        if engagement_type == 'penetration_test':
            self._generate_pentest_goals(objectives)
        elif engagement_type == 'red_team':
            self._generate_red_team_goals(objectives)
        elif engagement_type == 'bug_bounty':
            self._generate_bug_bounty_goals(objectives)
        elif engagement_type == 'vulnerability_assessment':
            self._generate_vuln_assessment_goals(objectives)
        else:
            self._generate_default_goals(objectives)

        # Build goal dependency tree
        self._build_dependency_tree()

        # Generate attack paths for each goal
        self._generate_attack_paths()

        self.logger.info(f"Generated {len(self.goals)} goals with {len(self.attack_paths)} attack paths")
        return self.goals

    def _generate_pentest_goals(self, objectives: List[str]):
        """Generate goals for penetration test engagement."""
        goal_id_counter = 1

        # Phase 1: Reconnaissance
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.DISCOVER_HOSTS,
            description="Discover all live hosts in authorized scope",
            priority=GoalPriority.CRITICAL,
            status=GoalStatus.NOT_STARTED,
            prerequisites=[],
            success_criteria=[
                "All authorized IP ranges scanned",
                "List of live hosts compiled",
                "Host OS fingerprinting completed"
            ],
            estimated_difficulty=2
        ))
        goal_id_counter += 1

        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.MAP_NETWORK,
            description="Map network topology and segments",
            priority=GoalPriority.HIGH,
            status=GoalStatus.NOT_STARTED,
            prerequisites=["GOAL-001"],
            success_criteria=[
                "Network topology mapped",
                "Network segments identified",
                "Routing paths documented"
            ],
            estimated_difficulty=4
        ))
        goal_id_counter += 1

        # Phase 2: Enumeration
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.ENUMERATE_SERVICES,
            description="Enumerate all services on discovered hosts",
            priority=GoalPriority.CRITICAL,
            status=GoalStatus.NOT_STARTED,
            prerequisites=["GOAL-001"],
            success_criteria=[
                "All hosts port scanned",
                "Services identified and versioned",
                "Service banners collected"
            ],
            estimated_difficulty=3
        ))
        goal_id_counter += 1

        # Phase 3: Initial Access
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.GAIN_INITIAL_ACCESS,
            description="Gain initial foothold on network",
            priority=GoalPriority.CRITICAL,
            status=GoalStatus.NOT_STARTED,
            prerequisites=["GOAL-003"],
            success_criteria=[
                "At least one host compromised",
                "Persistent access established",
                "C2 channel established"
            ],
            estimated_difficulty=6
        ))
        goal_id_counter += 1

        # Phase 4: Privilege Escalation
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.GAIN_ADMIN_ACCESS,
            description="Escalate privileges to local administrator",
            priority=GoalPriority.HIGH,
            status=GoalStatus.NOT_STARTED,
            prerequisites=["GOAL-004"],
            success_criteria=[
                "Local admin access achieved",
                "Credential dumping successful",
                "Full system access obtained"
            ],
            estimated_difficulty=7
        ))
        goal_id_counter += 1

        # Phase 5: Lateral Movement
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.COMPROMISE_SEGMENT,
            description="Compromise additional hosts in network segment",
            priority=GoalPriority.HIGH,
            status=GoalStatus.NOT_STARTED,
            prerequisites=["GOAL-005"],
            success_criteria=[
                "At least 3 hosts compromised",
                "Credentials for multiple accounts obtained",
                "Network segment control achieved"
            ],
            estimated_difficulty=6
        ))
        goal_id_counter += 1

        # Phase 6: Domain Compromise (if AD environment)
        if self._is_ad_environment():
            self.goals.append(Goal(
                goal_id=f"GOAL-{goal_id_counter:03d}",
                goal_type=GoalType.GAIN_DOMAIN_ADMIN,
                description="Achieve Domain Admin level access",
                priority=GoalPriority.CRITICAL,
                status=GoalStatus.NOT_STARTED,
                prerequisites=["GOAL-006"],
                success_criteria=[
                    "Domain Admin credentials obtained",
                    "Full AD control demonstrated",
                    "Golden ticket capability proven"
                ],
                estimated_difficulty=9
            ))
            goal_id_counter += 1

        # Phase 7: Data Objectives
        for objective in objectives:
            if 'data' in objective.lower() or 'exfiltrate' in objective.lower():
                self.goals.append(Goal(
                    goal_id=f"GOAL-{goal_id_counter:03d}",
                    goal_type=GoalType.EXFILTRATE_DATA,
                    description=f"Objective: {objective}",
                    priority=GoalPriority.HIGH,
                    status=GoalStatus.NOT_STARTED,
                    prerequisites=["GOAL-005"],
                    success_criteria=[
                        "Target data located",
                        "Data access obtained",
                        "Exfiltration method demonstrated"
                    ],
                    estimated_difficulty=7
                ))
                goal_id_counter += 1

        # Phase 8: Persistence
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.ESTABLISH_PERSISTENCE,
            description="Establish long-term persistence mechanisms",
            priority=GoalPriority.MEDIUM,
            status=GoalStatus.NOT_STARTED,
            prerequisites=["GOAL-005"],
            success_criteria=[
                "Persistence mechanism installed",
                "Survives reboot",
                "Multiple backup methods in place"
            ],
            estimated_difficulty=5
        ))

    def _generate_red_team_goals(self, objectives: List[str]):
        """Generate goals for red team engagement."""
        # Red team engagements focus on evading detection and achieving specific objectives
        goal_id_counter = 1

        # Stealth reconnaissance
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.DISCOVER_HOSTS,
            description="Conduct stealthy reconnaissance without triggering alerts",
            priority=GoalPriority.CRITICAL,
            status=GoalStatus.NOT_STARTED,
            prerequisites=[],
            success_criteria=[
                "Reconnaissance completed",
                "No security alerts triggered",
                "Blue team unaware of activity"
            ],
            estimated_difficulty=7
        ))
        goal_id_counter += 1

        # Objective-based goals
        for objective in objectives:
            self.goals.append(Goal(
                goal_id=f"GOAL-{goal_id_counter:03d}",
                goal_type=GoalType.LOCATE_SENSITIVE_DATA,
                description=f"Red Team Objective: {objective}",
                priority=GoalPriority.CRITICAL,
                status=GoalStatus.NOT_STARTED,
                prerequisites=["GOAL-001"],
                success_criteria=[
                    f"Objective achieved: {objective}",
                    "Detection evasion maintained",
                    "Evidence collected"
                ],
                estimated_difficulty=8
            ))
            goal_id_counter += 1

        # Detection testing
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.TEST_DETECTION,
            description="Test detection capabilities of blue team",
            priority=GoalPriority.HIGH,
            status=GoalStatus.NOT_STARTED,
            prerequisites=[f"GOAL-{goal_id_counter-1:03d}"],
            success_criteria=[
                "Detection capabilities assessed",
                "Gaps in detection identified",
                "Report generated"
            ],
            estimated_difficulty=6
        ))

    def _generate_bug_bounty_goals(self, objectives: List[str]):
        """Generate goals for bug bounty engagement."""
        goal_id_counter = 1

        # Web application focus
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.ENUMERATE_SERVICES,
            description="Enumerate web applications and APIs",
            priority=GoalPriority.CRITICAL,
            status=GoalStatus.NOT_STARTED,
            prerequisites=[],
            success_criteria=[
                "All web apps discovered",
                "API endpoints enumerated",
                "Technology stack identified"
            ],
            estimated_difficulty=4
        ))
        goal_id_counter += 1

        # Common vulnerability goals
        vulnerability_types = [
            "SQL Injection",
            "XSS (Cross-Site Scripting)",
            "SSRF (Server-Side Request Forgery)",
            "Authentication bypass",
            "Authorization flaws",
            "Business logic vulnerabilities"
        ]

        for vuln_type in vulnerability_types:
            self.goals.append(Goal(
                goal_id=f"GOAL-{goal_id_counter:03d}",
                goal_type=GoalType.GAIN_INITIAL_ACCESS,
                description=f"Test for {vuln_type}",
                priority=GoalPriority.HIGH,
                status=GoalStatus.NOT_STARTED,
                prerequisites=["GOAL-001"],
                success_criteria=[
                    f"{vuln_type} tested",
                    "Valid PoC created if found",
                    "Impact assessed"
                ],
                estimated_difficulty=6
            ))
            goal_id_counter += 1

    def _generate_vuln_assessment_goals(self, objectives: List[str]):
        """Generate goals for vulnerability assessment."""
        goal_id_counter = 1

        # Comprehensive scanning
        self.goals.append(Goal(
            goal_id=f"GOAL-{goal_id_counter:03d}",
            goal_type=GoalType.DISCOVER_HOSTS,
            description="Scan all hosts in scope for vulnerabilities",
            priority=GoalPriority.CRITICAL,
            status=GoalStatus.NOT_STARTED,
            prerequisites=[],
            success_criteria=[
                "All hosts scanned",
                "Vulnerabilities catalogued",
                "Risk ratings assigned"
            ],
            estimated_difficulty=3
        ))

    def _generate_default_goals(self, objectives: List[str]):
        """Generate default goals for unspecified engagement type."""
        self._generate_pentest_goals(objectives)

    def _is_ad_environment(self) -> bool:
        """Detect if target environment uses Active Directory."""
        if not self.roe_document:
            return False

        # Check for AD indicators in ROE
        indicators = ['domain', 'active directory', 'ad', 'ldap', 'kerberos']
        roe_text = json.dumps(self.roe_document).lower()

        return any(indicator in roe_text for indicator in indicators)

    def _build_dependency_tree(self):
        """Build goal dependency tree."""
        self.goal_dependencies.clear()

        for goal in self.goals:
            self.goal_dependencies[goal.goal_id] = []

            # Find goals that depend on this goal
            for other_goal in self.goals:
                if goal.goal_id in other_goal.prerequisites:
                    self.goal_dependencies[goal.goal_id].append(other_goal.goal_id)

        self.logger.debug(f"Dependency tree built: {len(self.goal_dependencies)} nodes")

    def _generate_attack_paths(self):
        """Generate attack paths for each goal."""
        # TODO: Implement attack path generation
        # This would use:
        # - Available tools and capabilities
        # - Known attack patterns
        # - Target environment characteristics
        # - Success probability estimation
        pass

    def get_next_goals(self, current_state: Dict) -> List[Goal]:
        """
        Get the next goals that should be pursued based on current state.

        Args:
            current_state: Current state of the operation

        Returns:
            List of goals ready to be pursued
        """
        ready_goals = []

        for goal in self.goals:
            # Skip if already completed or in progress
            if goal.status in [GoalStatus.COMPLETED, GoalStatus.IN_PROGRESS]:
                continue

            # Check if prerequisites are met
            prerequisites_met = True
            for prereq_id in goal.prerequisites:
                prereq_goal = self._get_goal_by_id(prereq_id)
                if prereq_goal and prereq_goal.status != GoalStatus.COMPLETED:
                    prerequisites_met = False
                    break

            if prerequisites_met:
                ready_goals.append(goal)

        # Sort by priority
        ready_goals.sort(key=lambda g: g.priority.value, reverse=True)

        return ready_goals

    def _get_goal_by_id(self, goal_id: str) -> Optional[Goal]:
        """Get goal by ID."""
        for goal in self.goals:
            if goal.goal_id == goal_id:
                return goal
        return None

    def update_goal_status(self, goal_id: str, status: GoalStatus, progress: float = 0.0):
        """
        Update goal status and progress.

        Args:
            goal_id: Goal ID
            status: New status
            progress: Progress (0.0 to 1.0)
        """
        goal = self._get_goal_by_id(goal_id)
        if not goal:
            self.logger.error(f"Goal {goal_id} not found")
            return

        old_status = goal.status
        goal.status = status
        goal.progress = progress

        import time
        if status == GoalStatus.IN_PROGRESS and not goal.started_at:
            goal.started_at = time.time()
        elif status == GoalStatus.COMPLETED:
            goal.completed_at = time.time()

        self.logger.info(f"Goal {goal_id} status updated: {old_status.value} -> {status.value} ({progress*100:.0f}%)")

    def get_goal_tree(self) -> Dict:
        """
        Get hierarchical goal tree representation.

        Returns:
            Dictionary representing goal tree
        """
        # Find root goals (no prerequisites)
        root_goals = [g for g in self.goals if not g.prerequisites]

        def build_tree(goal: Goal) -> Dict:
            return {
                'goal': goal.to_dict(),
                'children': [
                    build_tree(self._get_goal_by_id(child_id))
                    for child_id in self.goal_dependencies.get(goal.goal_id, [])
                    if self._get_goal_by_id(child_id)
                ]
            }

        return {
            'roots': [build_tree(goal) for goal in root_goals],
            'total_goals': len(self.goals),
            'completed_goals': len([g for g in self.goals if g.status == GoalStatus.COMPLETED]),
            'in_progress_goals': len([g for g in self.goals if g.status == GoalStatus.IN_PROGRESS])
        }

    def export_attack_tree(self, output_path: str):
        """
        Export attack tree to JSON file.

        Args:
            output_path: Path to output file
        """
        tree = self.get_goal_tree()

        with open(output_path, 'w') as f:
            json.dump(tree, f, indent=2)

        self.logger.info(f"Attack tree exported to {output_path}")


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Example ROE document
    roe_document = {
        "engagement_id": "PROM-2025-001",
        "engagement_type": "penetration_test",
        "engagement_name": "Acme Corp Internal Pentest",
        "objectives": [
            "Gain Domain Admin access",
            "Locate and exfiltrate customer database",
            "Test incident response capabilities"
        ],
        "authorized_ips": ["10.0.0.0/8"],
        "authorized_domains": ["acme.corp", "*.acme.corp"],
        "environment": "Active Directory",
        "duration_days": 14
    }

    # Initialize goal generator
    generator = AIGoalGenerator()

    # Load ROE and generate goals
    goals = generator.load_roe(roe_document)

    print(f"\n{'='*80}")
    print(f"GENERATED {len(goals)} GOALS FOR {roe_document['engagement_name']}")
    print(f"{'='*80}\n")

    # Display goals
    for goal in goals:
        print(f"[{goal.goal_id}] {goal.description}")
        print(f"  Type: {goal.goal_type.value}")
        print(f"  Priority: {goal.priority.value}")
        print(f"  Prerequisites: {', '.join(goal.prerequisites) if goal.prerequisites else 'None'}")
        print(f"  Success Criteria:")
        for criterion in goal.success_criteria:
            print(f"    - {criterion}")
        print()

    # Get next goals to pursue
    print("\nNEXT GOALS TO PURSUE:")
    next_goals = generator.get_next_goals({})
    for goal in next_goals[:3]:
        print(f"  - [{goal.priority.value}] {goal.description}")

    # Export attack tree
    generator.export_attack_tree("/tmp/attack_tree.json")
    print(f"\nAttack tree exported to /tmp/attack_tree.json")
