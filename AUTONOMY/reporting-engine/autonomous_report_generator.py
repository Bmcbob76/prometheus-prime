#!/usr/bin/env python3
"""
PROMETHEUS PRIME - AUTONOMOUS REPORT GENERATION
LLM-powered penetration testing report generation with zero human input

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - INTELLIGENT DOCUMENTATION
"""

import json
import logging
import sys
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum


class FindingSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ReportSection(Enum):
    """Report sections."""
    EXECUTIVE_SUMMARY = "executive_summary"
    METHODOLOGY = "methodology"
    SCOPE = "scope"
    FINDINGS = "findings"
    RECOMMENDATIONS = "recommendations"
    TECHNICAL_DETAILS = "technical_details"
    APPENDICES = "appendices"


@dataclass
class Finding:
    """A security finding."""
    finding_id: str
    title: str
    severity: FindingSeverity
    cvss_score: Optional[float]
    description: str
    affected_systems: List[str]
    evidence: List[Dict[str, Any]]
    impact: str
    remediation: str
    references: List[str]
    discovered_at: float
    exploited: bool = False


@dataclass
class EngagementMetrics:
    """Metrics from the engagement."""
    total_hosts_scanned: int
    hosts_compromised: int
    vulnerabilities_found: int
    credentials_obtained: int
    lateral_moves: int
    privilege_escalations: int
    data_accessed: List[str]
    engagement_duration_hours: float
    tools_used: List[str]


class AutonomousReportGenerator:
    """
    Autonomous penetration testing report generator.
    Generates comprehensive reports with zero human input using LLM.
    """

    def __init__(self,
                 output_dir: str = '/var/lib/prometheus/reports',
                 use_llm: bool = False):
        """
        Initialize autonomous report generator.

        Args:
            output_dir: Directory for generated reports
            use_llm: Whether to use LLM for advanced text generation
        """
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - REPORT_GEN - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/report_generator.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('REPORT_GEN')

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.use_llm = use_llm

        # Report templates
        self.templates = self._load_templates()

        self.logger.info("Autonomous Report Generator initialized")
        self.logger.info(f"Output directory: {self.output_dir}")
        self.logger.info(f"LLM enabled: {self.use_llm}")

    def _load_templates(self) -> Dict[str, str]:
        """Load report templates."""
        return {
            'executive_summary': """
# Executive Summary

## Engagement Overview

This penetration testing engagement was conducted against **{client_name}** from **{start_date}** to **{end_date}**. The objective was to identify security vulnerabilities and demonstrate the potential impact of successful exploitation.

## Key Findings

- **Total Vulnerabilities Identified:** {total_vulnerabilities}
  - Critical: {critical_count}
  - High: {high_count}
  - Medium: {medium_count}
  - Low: {low_count}

- **Hosts Compromised:** {hosts_compromised} out of {total_hosts} ({compromise_rate:.1%})
- **Privilege Escalations:** {privilege_escalations}
- **Lateral Movements:** {lateral_moves}
- **Credentials Obtained:** {credentials_obtained}

## Overall Risk Rating

**{overall_risk}**

{risk_summary}

## Critical Issues Requiring Immediate Attention

{critical_issues}

## Recommendations Summary

{recommendations_summary}
""",

            'methodology': """
# Methodology

## Engagement Approach

This engagement followed industry-standard penetration testing methodologies, including:

1. **Reconnaissance** - Information gathering and target identification
2. **Scanning & Enumeration** - Service discovery and vulnerability identification
3. **Exploitation** - Attempting to exploit identified vulnerabilities
4. **Post-Exploitation** - Privilege escalation and lateral movement
5. **Reporting** - Documenting findings and recommendations

## Tools Used

The following tools were utilized during this engagement:

{tools_list}

## Scope

### In-Scope Assets

{in_scope_assets}

### Out-of-Scope Assets

{out_of_scope_assets}

## Testing Timeline

- **Start Date:** {start_date}
- **End Date:** {end_date}
- **Total Duration:** {duration_hours:.1f} hours
- **Testing Hours:** {testing_hours:.1f} hours
""",

            'finding_template': """
## {finding_number}. {title}

**Severity:** {severity}
**CVSS Score:** {cvss_score}
**Affected Systems:** {affected_systems}

### Description

{description}

### Impact

{impact}

### Evidence

{evidence}

### Remediation

{remediation}

### References

{references}
"""
        }

    def generate_report(self,
                       engagement_name: str,
                       client_name: str,
                       findings: List[Finding],
                       metrics: EngagementMetrics,
                       roe_document: Dict,
                       start_time: datetime,
                       end_time: datetime) -> str:
        """
        Generate comprehensive penetration testing report.

        Args:
            engagement_name: Name of the engagement
            client_name: Client name
            findings: List of findings
            metrics: Engagement metrics
            roe_document: Rules of Engagement document
            start_time: Engagement start time
            end_time: Engagement end time

        Returns:
            Path to generated report
        """
        self.logger.info(f"Generating report for {engagement_name}")

        # Sort findings by severity
        findings_sorted = sorted(
            findings,
            key=lambda f: self._severity_order(f.severity)
        )

        # Count findings by severity
        severity_counts = self._count_by_severity(findings_sorted)

        # Generate report sections
        report_content = []

        # Title page
        report_content.append(self._generate_title_page(
            engagement_name, client_name, start_time, end_time
        ))

        # Executive summary
        report_content.append(self._generate_executive_summary(
            client_name, start_time, end_time, findings_sorted,
            severity_counts, metrics
        ))

        # Methodology
        report_content.append(self._generate_methodology(
            roe_document, start_time, end_time, metrics
        ))

        # Findings
        report_content.append(self._generate_findings_section(findings_sorted))

        # Recommendations
        report_content.append(self._generate_recommendations(findings_sorted))

        # Technical details
        report_content.append(self._generate_technical_details(metrics))

        # Combine all sections
        full_report = "\n\n".join(report_content)

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{engagement_name.replace(' ', '_')}_{timestamp}.md"
        report_path = self.output_dir / report_filename

        with open(report_path, 'w') as f:
            f.write(full_report)

        self.logger.info(f"Report generated: {report_path}")

        # Generate additional formats
        self._generate_json_report(report_path.with_suffix('.json'), {
            'engagement_name': engagement_name,
            'client_name': client_name,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'findings': [asdict(f) for f in findings_sorted],
            'metrics': asdict(metrics)
        })

        return str(report_path)

    def _generate_title_page(self,
                            engagement_name: str,
                            client_name: str,
                            start_time: datetime,
                            end_time: datetime) -> str:
        """Generate title page."""
        return f"""# Penetration Testing Report

## {engagement_name}

---

**Client:** {client_name}
**Testing Period:** {start_time.strftime('%B %d, %Y')} - {end_time.strftime('%B %d, %Y')}
**Report Generated:** {datetime.now().strftime('%B %d, %Y %H:%M:%S')}
**Generated By:** Prometheus Prime Autonomous Pentest Platform
**Authority Level:** 11.0

---

## Confidentiality Statement

This document contains confidential information about security vulnerabilities discovered during penetration testing. It should be handled according to your organization's information security policies and shared only with authorized personnel.

---
"""

    def _generate_executive_summary(self,
                                    client_name: str,
                                    start_time: datetime,
                                    end_time: datetime,
                                    findings: List[Finding],
                                    severity_counts: Dict,
                                    metrics: EngagementMetrics) -> str:
        """Generate executive summary section."""
        # Calculate overall risk
        overall_risk, risk_summary = self._calculate_overall_risk(severity_counts, metrics)

        # Get critical issues
        critical_issues = self._get_critical_issues(findings)

        # Get recommendations summary
        recommendations_summary = self._get_recommendations_summary(findings)

        # Calculate compromise rate
        compromise_rate = (
            metrics.hosts_compromised / metrics.total_hosts_scanned
            if metrics.total_hosts_scanned > 0 else 0
        )

        return self.templates['executive_summary'].format(
            client_name=client_name,
            start_date=start_time.strftime('%B %d, %Y'),
            end_date=end_time.strftime('%B %d, %Y'),
            total_vulnerabilities=len(findings),
            critical_count=severity_counts[FindingSeverity.CRITICAL],
            high_count=severity_counts[FindingSeverity.HIGH],
            medium_count=severity_counts[FindingSeverity.MEDIUM],
            low_count=severity_counts[FindingSeverity.LOW],
            hosts_compromised=metrics.hosts_compromised,
            total_hosts=metrics.total_hosts_scanned,
            compromise_rate=compromise_rate,
            privilege_escalations=metrics.privilege_escalations,
            lateral_moves=metrics.lateral_moves,
            credentials_obtained=metrics.credentials_obtained,
            overall_risk=overall_risk,
            risk_summary=risk_summary,
            critical_issues=critical_issues,
            recommendations_summary=recommendations_summary
        )

    def _generate_methodology(self,
                             roe_document: Dict,
                             start_time: datetime,
                             end_time: datetime,
                             metrics: EngagementMetrics) -> str:
        """Generate methodology section."""
        # Format tools list
        tools_list = "\n".join([f"- {tool}" for tool in metrics.tools_used])

        # Format in-scope assets
        in_scope_ips = roe_document.get('authorized_ips', [])
        in_scope_domains = roe_document.get('authorized_domains', [])
        in_scope_assets = "\n".join(
            [f"- {ip}" for ip in in_scope_ips] +
            [f"- {domain}" for domain in in_scope_domains]
        )

        # Out-of-scope
        out_of_scope = roe_document.get('exclusions', [])
        out_of_scope_assets = "\n".join([f"- {item}" for item in out_of_scope]) if out_of_scope else "None specified"

        duration_hours = (end_time - start_time).total_seconds() / 3600

        return self.templates['methodology'].format(
            tools_list=tools_list,
            in_scope_assets=in_scope_assets,
            out_of_scope_assets=out_of_scope_assets,
            start_date=start_time.strftime('%B %d, %Y %H:%M'),
            end_date=end_time.strftime('%B %d, %Y %H:%M'),
            duration_hours=duration_hours,
            testing_hours=metrics.engagement_duration_hours
        )

    def _generate_findings_section(self, findings: List[Finding]) -> str:
        """Generate findings section."""
        content = ["# Detailed Findings\n"]

        for i, finding in enumerate(findings, 1):
            # Format affected systems
            affected_systems = ", ".join(finding.affected_systems)

            # Format evidence
            evidence_text = ""
            for j, evidence in enumerate(finding.evidence, 1):
                evidence_text += f"\n**Evidence {j}:**\n"
                evidence_text += f"```\n{evidence.get('content', 'No content')}\n```\n"

            # Format references
            references_text = "\n".join([f"- {ref}" for ref in finding.references]) if finding.references else "None"

            # Generate finding section
            finding_content = self.templates['finding_template'].format(
                finding_number=i,
                title=finding.title,
                severity=finding.severity.value.upper(),
                cvss_score=finding.cvss_score if finding.cvss_score else "N/A",
                affected_systems=affected_systems,
                description=finding.description,
                impact=finding.impact,
                evidence=evidence_text,
                remediation=finding.remediation,
                references=references_text
            )

            content.append(finding_content)

        return "\n".join(content)

    def _generate_recommendations(self, findings: List[Finding]) -> str:
        """Generate recommendations section."""
        content = ["# Recommendations\n"]

        content.append("## Priority Actions\n")

        # Group by severity
        critical_findings = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        high_findings = [f for f in findings if f.severity == FindingSeverity.HIGH]

        if critical_findings:
            content.append("### Critical Priority (Immediate Action Required)\n")
            for finding in critical_findings:
                content.append(f"**{finding.title}**")
                content.append(f"- {finding.remediation}\n")

        if high_findings:
            content.append("### High Priority (Address Within 30 Days)\n")
            for finding in high_findings:
                content.append(f"**{finding.title}**")
                content.append(f"- {finding.remediation}\n")

        # General recommendations
        content.append("## General Security Recommendations\n")
        content.append("""
1. **Implement Defense in Depth**
   - Deploy multiple layers of security controls
   - Ensure no single point of failure

2. **Regular Security Assessments**
   - Conduct quarterly vulnerability scans
   - Annual penetration testing
   - Continuous security monitoring

3. **Security Awareness Training**
   - Train all employees on security best practices
   - Conduct phishing simulations
   - Establish security incident reporting procedures

4. **Patch Management**
   - Establish regular patching schedule
   - Prioritize critical security patches
   - Test patches before deployment

5. **Access Control**
   - Implement principle of least privilege
   - Use multi-factor authentication
   - Regular access reviews
""")

        return "\n".join(content)

    def _generate_technical_details(self, metrics: EngagementMetrics) -> str:
        """Generate technical details section."""
        content = ["# Technical Details\n"]

        content.append("## Engagement Statistics\n")
        content.append(f"- **Total Hosts Scanned:** {metrics.total_hosts_scanned}")
        content.append(f"- **Hosts Compromised:** {metrics.hosts_compromised}")
        content.append(f"- **Vulnerabilities Found:** {metrics.vulnerabilities_found}")
        content.append(f"- **Credentials Obtained:** {metrics.credentials_obtained}")
        content.append(f"- **Lateral Movements:** {metrics.lateral_moves}")
        content.append(f"- **Privilege Escalations:** {metrics.privilege_escalations}")
        content.append(f"- **Engagement Duration:** {metrics.engagement_duration_hours:.1f} hours\n")

        if metrics.data_accessed:
            content.append("## Data Accessed\n")
            for data in metrics.data_accessed:
                content.append(f"- {data}")

        content.append("\n## Tools Used\n")
        for tool in metrics.tools_used:
            content.append(f"- {tool}")

        return "\n".join(content)

    def _generate_json_report(self, output_path: Path, data: Dict):
        """Generate machine-readable JSON report."""
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"JSON report generated: {output_path}")

    def _calculate_overall_risk(self,
                               severity_counts: Dict,
                               metrics: EngagementMetrics) -> Tuple[str, str]:
        """Calculate overall risk rating."""
        # Calculate risk score
        risk_score = (
            severity_counts[FindingSeverity.CRITICAL] * 10 +
            severity_counts[FindingSeverity.HIGH] * 5 +
            severity_counts[FindingSeverity.MEDIUM] * 2 +
            severity_counts[FindingSeverity.LOW] * 1
        )

        # Factor in compromise rate
        if metrics.total_hosts_scanned > 0:
            compromise_rate = metrics.hosts_compromised / metrics.total_hosts_scanned
            risk_score *= (1 + compromise_rate)

        # Determine risk level
        if risk_score >= 50:
            risk_level = "CRITICAL"
            risk_summary = "The organization faces critical security risks requiring immediate remediation. Multiple severe vulnerabilities were identified and successfully exploited."
        elif risk_score >= 25:
            risk_level = "HIGH"
            risk_summary = "The organization faces significant security risks. Several high-severity vulnerabilities were identified that could lead to compromise."
        elif risk_score >= 10:
            risk_level = "MEDIUM"
            risk_summary = "The organization has moderate security risks. While no critical issues were found, several vulnerabilities should be addressed."
        else:
            risk_level = "LOW"
            risk_summary = "The organization demonstrates a strong security posture. Only minor issues were identified."

        return risk_level, risk_summary

    def _get_critical_issues(self, findings: List[Finding]) -> str:
        """Get critical issues list."""
        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]

        if not critical:
            return "No critical issues were identified during this engagement."

        issues = []
        for i, finding in enumerate(critical, 1):
            issues.append(f"{i}. **{finding.title}**")
            issues.append(f"   - Affected: {', '.join(finding.affected_systems)}")
            issues.append(f"   - Impact: {finding.impact[:100]}...")

        return "\n".join(issues)

    def _get_recommendations_summary(self, findings: List[Finding]) -> str:
        """Get recommendations summary."""
        critical_count = len([f for f in findings if f.severity == FindingSeverity.CRITICAL])
        high_count = len([f for f in findings if f.severity == FindingSeverity.HIGH])

        summary = []

        if critical_count > 0:
            summary.append(f"- Address {critical_count} critical {'issue' if critical_count == 1 else 'issues'} immediately")

        if high_count > 0:
            summary.append(f"- Remediate {high_count} high-severity {'vulnerability' if high_count == 1 else 'vulnerabilities'} within 30 days")

        summary.append("- Implement security monitoring and logging")
        summary.append("- Conduct regular security assessments")
        summary.append("- Provide security awareness training")

        return "\n".join(summary)

    def _count_by_severity(self, findings: List[Finding]) -> Dict[FindingSeverity, int]:
        """Count findings by severity."""
        counts = {severity: 0 for severity in FindingSeverity}

        for finding in findings:
            counts[finding.severity] += 1

        return counts

    def _severity_order(self, severity: FindingSeverity) -> int:
        """Get severity order for sorting."""
        order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFORMATIONAL: 4
        }
        return order.get(severity, 999)


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize report generator
    generator = AutonomousReportGenerator()

    print("Generating sample penetration testing report...\n")

    # Create sample findings
    findings = [
        Finding(
            finding_id="FIND-001",
            title="SMB Signing Not Required",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            description="SMB signing is not required on multiple domain controllers, allowing for potential man-in-the-middle attacks and relay attacks.",
            affected_systems=["DC01.corp.local", "DC02.corp.local"],
            evidence=[
                {'type': 'nmap_output', 'content': 'smb-security-mode: Message signing disabled'},
                {'type': 'screenshot', 'content': 'evidence_screenshot_001.png'}
            ],
            impact="An attacker could perform SMB relay attacks to authenticate to other systems using captured credentials without cracking passwords.",
            remediation="Enable SMB signing on all domain controllers by configuring Group Policy:\n- Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options\n- Set 'Microsoft network server: Digitally sign communications (always)' to Enabled",
            references=[
                "https://attack.mitre.org/techniques/T1557/001/",
                "CVE-2019-1040"
            ],
            discovered_at=time.time(),
            exploited=True
        ),
        Finding(
            finding_id="FIND-002",
            title="Weak Password Policy",
            severity=FindingSeverity.MEDIUM,
            cvss_score=5.3,
            description="The domain password policy allows weak passwords with minimum length of 7 characters and no complexity requirements.",
            affected_systems=["CORP.LOCAL domain"],
            evidence=[
                {'type': 'command_output', 'content': 'net accounts\nMinimum password length: 7\nPassword complexity: Disabled'}
            ],
            impact="Users may choose weak passwords that are susceptible to brute force and dictionary attacks.",
            remediation="Implement a strong password policy:\n- Minimum length: 12 characters\n- Enable complexity requirements\n- Password history: 24 passwords\n- Maximum password age: 90 days",
            references=[
                "NIST SP 800-63B"
            ],
            discovered_at=time.time(),
            exploited=False
        )
    ]

    # Create sample metrics
    metrics = EngagementMetrics(
        total_hosts_scanned=20,
        hosts_compromised=5,
        vulnerabilities_found=15,
        credentials_obtained=23,
        lateral_moves=8,
        privilege_escalations=3,
        data_accessed=["Customer Database", "Financial Records", "HR Files"],
        engagement_duration_hours=40.0,
        tools_used=["Nmap", "Metasploit", "BloodHound", "Mimikatz", "Impacket"]
    )

    # Sample ROE
    roe_document = {
        'authorized_ips': ['10.0.0.0/8', '192.168.1.0/24'],
        'authorized_domains': ['corp.local', '*.corp.local'],
        'exclusions': ['10.0.100.0/24 (Production database servers)']
    }

    # Generate report
    start_time = datetime(2025, 11, 1, 9, 0)
    end_time = datetime(2025, 11, 5, 17, 0)

    report_path = generator.generate_report(
        engagement_name="Acme Corp Internal Pentest",
        client_name="Acme Corporation",
        findings=findings,
        metrics=metrics,
        roe_document=roe_document,
        start_time=start_time,
        end_time=end_time
    )

    print(f"Report generated: {report_path}")
    print("\nReport preview:")
    print("="*80)
    with open(report_path, 'r') as f:
        print(f.read()[:1000] + "\n...\n[Report truncated for preview]")
