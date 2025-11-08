"""

RED TEAM OPERATIONS - Operation Reporting
PROMETHEUS-PRIME Domain 1.10
Authority Level: 11

"""

import logging
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.Reporting")


class ReportFormat(Enum):
    """Report output formats"""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"
    DOCX = "docx"


class SeverityLevel(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Security finding"""
    title: str
    severity: SeverityLevel
    description: str
    affected_systems: List[str]
    evidence: List[str]
    remediation: str
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    exploited: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class OperationMetrics:
    """Operation metrics"""
    total_systems_scanned: int
    systems_compromised: int
    credentials_obtained: int
    privilege_escalations: int
    lateral_movements: int
    data_exfiltrated_mb: float
    detection_events: int
    operation_duration_hours: float


@dataclass
class AttackPath:
    """Attack path documentation"""
    path_id: str
    start_point: str
    end_point: str
    steps: List[str]
    techniques_used: List[str]
    duration_minutes: int
    detected: bool


class RedTeamReporter:
    """
    Red Team Operation Reporter
    
    Capabilities:
    - Executive summaries
    - Technical findings reports
    - Attack path visualization
    - IOC documentation
    - Remediation recommendations
    - MITRE ATT&CK mapping
    - Timeline generation
    - Evidence collection
    - Metrics and statistics
    """
    
    def __init__(self):
        self.logger = logger
        self.findings: List[Finding] = []
        self.attack_paths: List[AttackPath] = []
        self.metrics: Optional[OperationMetrics] = None
        self.logger.info("Red Team Reporter initialized")
    
    async def add_finding(
        self,
        title: str,
        severity: SeverityLevel,
        description: str,
        affected_systems: List[str],
        evidence: List[str],
        remediation: str,
        **kwargs
    ) -> Finding:
        """
        Add a security finding
        
        Args:
            title: Finding title
            severity: Severity level
            description: Detailed description
            affected_systems: List of affected systems
            evidence: List of evidence items
            remediation: Remediation steps
            **kwargs: Additional fields
        
        Returns:
            Created Finding object
        """
        finding = Finding(
            title=title,
            severity=severity,
            description=description,
            affected_systems=affected_systems,
            evidence=evidence,
            remediation=remediation,
            **kwargs
        )
        
        self.findings.append(finding)
        self.logger.info(f"Added finding: {title} (Severity: {severity.value})")
        
        return finding
    
    async def add_attack_path(
        self,
        path_id: str,
        start_point: str,
        end_point: str,
        steps: List[str],
        techniques_used: List[str],
        duration_minutes: int,
        detected: bool = False
    ) -> AttackPath:
        """
        Document an attack path
        
        Args:
            path_id: Unique path identifier
            start_point: Starting point
            end_point: Target/goal
            steps: List of steps taken
            techniques_used: MITRE techniques used
            duration_minutes: Time taken
            detected: Whether path was detected
        
        Returns:
            AttackPath object
        """
        path = AttackPath(
            path_id=path_id,
            start_point=start_point,
            end_point=end_point,
            steps=steps,
            techniques_used=techniques_used,
            duration_minutes=duration_minutes,
            detected=detected
        )
        
        self.attack_paths.append(path)
        self.logger.info(f"Added attack path: {path_id}")
        
        return path
    
    async def set_metrics(
        self,
        total_systems_scanned: int,
        systems_compromised: int,
        credentials_obtained: int,
        privilege_escalations: int,
        lateral_movements: int,
        data_exfiltrated_mb: float,
        detection_events: int,
        operation_duration_hours: float
    ) -> OperationMetrics:
        """
        Set operation metrics
        
        Returns:
            OperationMetrics object
        """
        self.metrics = OperationMetrics(
            total_systems_scanned=total_systems_scanned,
            systems_compromised=systems_compromised,
            credentials_obtained=credentials_obtained,
            privilege_escalations=privilege_escalations,
            lateral_movements=lateral_movements,
            data_exfiltrated_mb=data_exfiltrated_mb,
            detection_events=detection_events,
            operation_duration_hours=operation_duration_hours
        )
        
        self.logger.info("Operation metrics set")
        return self.metrics
    
    async def generate_executive_summary(
        self,
        operation_name: str,
        client_name: str,
        operation_date: str
    ) -> str:
        """
        Generate executive summary
        
        Args:
            operation_name: Operation name
            client_name: Client organization name
            operation_date: Operation date
        
        Returns:
            Executive summary markdown
        """
        critical_findings = [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]
        high_findings = [f for f in self.findings if f.severity == SeverityLevel.HIGH]
        
        summary = f"""# Executive Summary

## Red Team Operation: {operation_name}
**Client:** {client_name}  
**Date:** {operation_date}  
**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

### Overview

This report summarizes the findings from a Red Team security assessment conducted against {client_name}'s infrastructure. The assessment simulated real-world attack scenarios to evaluate the organization's security posture, detection capabilities, and incident response procedures.

### Key Findings

"""
        
        if critical_findings:
            summary += f"- **{len(critical_findings)} CRITICAL** vulnerabilities identified\n"
        if high_findings:
            summary += f"- **{len(high_findings)} HIGH** severity issues discovered\n"
        
        if self.metrics:
            summary += f"""
### Assessment Metrics

- **Systems Scanned:** {self.metrics.total_systems_scanned}
- **Systems Compromised:** {self.metrics.systems_compromised} ({(self.metrics.systems_compromised/self.metrics.total_systems_scanned*100):.1f}%)
- **Credentials Obtained:** {self.metrics.credentials_obtained}
- **Privilege Escalations:** {self.metrics.privilege_escalations}
- **Lateral Movements:** {self.metrics.lateral_movements}
- **Detection Rate:** {(self.metrics.detection_events/(len(self.attack_paths) or 1)*100):.1f}%

### Impact Assessment

"""
            
            if self.metrics.systems_compromised > 0:
                summary += f"""The Red Team successfully compromised {self.metrics.systems_compromised} systems, including:
- Domain-level access achieved
- Sensitive data accessed
- Persistence established on critical systems
"""
        
        summary += """
### Recommendations (Priority Order)

1. **Immediate Actions Required:**
   - Patch critical vulnerabilities
   - Reset compromised credentials
   - Review and strengthen access controls
   - Implement enhanced monitoring

2. **Short-term Improvements:**
   - Deploy EDR solutions
   - Implement network segmentation
   - Enhance logging and SIEM rules
   - Conduct security awareness training

3. **Long-term Strategy:**
   - Adopt Zero Trust architecture
   - Implement privileged access management (PAM)
   - Regular penetration testing
   - Continuous security monitoring

### Conclusion

The assessment revealed significant security gaps that require immediate attention. The Red Team was able to achieve domain-level compromise, demonstrating the need for improved security controls and monitoring capabilities.

**Risk Rating: """ + ("CRITICAL" if critical_findings else "HIGH" if high_findings else "MEDIUM") + """**

---
*This is an executive summary. For detailed technical findings, please refer to the Technical Report section.*
"""
        
        return summary
    
    async def generate_technical_report(
        self,
        operation_name: str
    ) -> str:
        """
        Generate detailed technical report
        
        Args:
            operation_name: Operation name
        
        Returns:
            Technical report markdown
        """
        report = f"""# Technical Report

## Red Team Operation: {operation_name}

---

## Table of Contents
1. [Scope and Methodology](#scope-and-methodology)
2. [Attack Timeline](#attack-timeline)
3. [Detailed Findings](#detailed-findings)
4. [Attack Paths](#attack-paths)
5. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
6. [Indicators of Compromise](#indicators-of-compromise)
7. [Remediation Recommendations](#remediation-recommendations)

---

## 1. Scope and Methodology

### Scope
- External network assessment
- Internal network penetration
- Active Directory security
- Application security testing
- Social engineering (limited)

### Methodology
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- MITRE ATT&CK Framework
- Custom Red Team TTPs

---

## 2. Attack Timeline

"""
        
        # Add attack paths to timeline
        for path in sorted(self.attack_paths, key=lambda x: x.duration_minutes):
            report += f"""
### {path.path_id}: {path.start_point}  {path.end_point}
- **Duration:** {path.duration_minutes} minutes
- **Detected:** {'Yes ' if path.detected else 'No '}
- **Steps:**
"""
            for i, step in enumerate(path.steps, 1):
                report += f"  {i}. {step}\n"
        
        report += """
---

## 3. Detailed Findings

"""
        
        # Sort findings by severity
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        sorted_findings = sorted(self.findings, key=lambda x: severity_order[x.severity])
        
        for i, finding in enumerate(sorted_findings, 1):
            report += f"""
### Finding #{i}: {finding.title}

**Severity:** {finding.severity.value.upper()}  
**CVSS Score:** {finding.cvss_score or 'N/A'}  
**CVE IDs:** {', '.join(finding.cve_ids) if finding.cve_ids else 'None'}  
**Exploited:** {'Yes' if finding.exploited else 'No'}

#### Description
{finding.description}

#### Affected Systems
"""
            for system in finding.affected_systems:
                report += f"- {system}\n"
            
            report += f"""
#### Evidence
"""
            for evidence in finding.evidence:
                report += f"- {evidence}\n"
            
            report += f"""
#### Remediation
{finding.remediation}

---
"""
        
        report += """
## 4. Attack Paths

### Attack Path Visualization

```
[Initial Access]  [Execution]  [Persistence]  [Privilege Escalation]  [Lateral Movement]  [Exfiltration]
```

"""
        
        for path in self.attack_paths:
            report += f"""
#### Path: {path.path_id}
```
{path.start_point}
  
"""
            for step in path.steps:
                report += f"  {step}\n  \n"
            report += f"{path.end_point}\n```\n\n"
        
        report += """
---

## 5. MITRE ATT&CK Mapping

### Techniques Used

| Tactic | Technique | Technique ID |
|--------|-----------|--------------|
| Initial Access | Phishing | T1566 |
| Execution | PowerShell | T1059.001 |
| Persistence | Registry Run Keys | T1547.001 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Discovery | Domain Trust Discovery | T1482 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Collection | Data from Local System | T1005 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## 6. Indicators of Compromise (IOCs)

### Network Indicators
```
IP Addresses:
- 192.168.1.100 (C2 Server)
- 10.0.0.50 (Compromised host)

Domains:
- evil.com (C2 domain)
- phish.example.com (Phishing domain)

URLs:
- http://evil.com/payload.exe
- https://evil.com/exfil
```

### Host Indicators
```
File Hashes (SHA256):
- abc123def456... (payload.exe)
- 789xyz012abc... (mimikatz.exe)

File Paths:
- C:\\Windows\\Temp\\payload.exe
- C:\\Users\\Public\\update.bat

Registry Keys:
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update

Scheduled Tasks:
- WindowsUpdate (malicious task)

Services:
- WindowsUpdateService (malicious service)
```

### Process Indicators
```
Suspicious Processes:
- powershell.exe -enc [base64]
- cmd.exe /c whoami
- mimikatz.exe
- procdump.exe -ma lsass.exe

Network Connections:
- powershell.exe  192.168.1.100:443
- rundll32.exe  evil.com:80
```

---

## 7. Remediation Recommendations

### Critical Priority (Immediate)

1. **Patch Critical Vulnerabilities**
   - Apply security updates for identified CVEs
   - Prioritize systems with external exposure
   - Timeline: 24-48 hours

2. **Reset Compromised Credentials**
   - Force password reset for all affected accounts
   - Implement MFA for privileged accounts
   - Timeline: 24 hours

3. **Remove Persistence Mechanisms**
   - Remove malicious scheduled tasks
   - Clean registry run keys
   - Delete malicious services
   - Timeline: 24 hours

### High Priority (1-2 Weeks)

4. **Implement EDR Solution**
   - Deploy endpoint detection and response
   - Configure behavioral monitoring
   - Enable real-time alerting

5. **Network Segmentation**
   - Segment critical systems
   - Implement micro-segmentation
   - Restrict lateral movement

6. **Enhanced Monitoring**
   - Deploy SIEM solution
   - Configure detection rules for attack patterns
   - Monitor for IOCs

### Medium Priority (1 Month)

7. **Security Awareness Training**
   - Phishing awareness training
   - Social engineering simulations
   - Incident reporting procedures

8. **Privileged Access Management**
   - Implement PAM solution
   - Just-in-time access
   - Session recording

9. **Application Whitelisting**
   - Deploy application control
   - Block unsigned executables
   - Restrict PowerShell execution

### Long-term (3-6 Months)

10. **Zero Trust Architecture**
    - Implement identity-based access
    - Continuous verification
    - Least privilege principle

11. **Regular Security Assessments**
    - Quarterly penetration testing
    - Red team exercises
    - Vulnerability assessments

12. **Incident Response Plan**
    - Develop playbooks
    - Conduct tabletop exercises
    - Establish IR team

---

## Appendix A: Evidence Files

All evidence collected during this assessment is stored in the following locations:
- Screenshots: /evidence/screenshots/
- Logs: /evidence/logs/
- Captured credentials: /evidence/credentials/ (encrypted)
- Network captures: /evidence/pcaps/

---

**Report End**
"""
        
        return report
    
    async def generate_json_report(self) -> str:
        """
        Generate JSON format report
        
        Returns:
            JSON report
        """
        report_data = {
            "metadata": {
                "report_type": "red_team_assessment",
                "generated_at": datetime.now().isoformat(),
                "version": "1.0"
            },
            "metrics": asdict(self.metrics) if self.metrics else None,
            "findings": [asdict(f) for f in self.findings],
            "attack_paths": [asdict(p) for p in self.attack_paths],
            "statistics": {
                "total_findings": len(self.findings),
                "critical_findings": len([f for f in self.findings if f.severity == SeverityLevel.CRITICAL]),
                "high_findings": len([f for f in self.findings if f.severity == SeverityLevel.HIGH]),
                "medium_findings": len([f for f in self.findings if f.severity == SeverityLevel.MEDIUM]),
                "low_findings": len([f for f in self.findings if f.severity == SeverityLevel.LOW]),
                "attack_paths": len(self.attack_paths),
                "detected_paths": len([p for p in self.attack_paths if p.detected])
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    async def generate_mitre_attack_navigator(self) -> Dict[str, Any]:
        """
        Generate MITRE ATT&CK Navigator layer JSON
        
        Returns:
            Navigator layer data
        """
        techniques = []
        
        # Extract techniques from attack paths
        for path in self.attack_paths:
            for tech in path.techniques_used:
                if tech not in [t["techniqueID"] for t in techniques]:
                    techniques.append({
                        "techniqueID": tech,
                        "score": 1,
                        "color": "#ff6666" if path.detected else "#66ff66",
                        "comment": f"Used in {path.path_id}"
                    })
        
        layer = {
            "name": "Red Team Assessment",
            "versions": {
                "attack": "11",
                "navigator": "4.5",
                "layer": "4.3"
            },
            "domain": "enterprise-attack",
            "description": "MITRE ATT&CK techniques used during red team assessment",
            "filters": {
                "platforms": ["windows", "linux"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#66ff66", "#ff6666"],
                "minValue": 0,
                "maxValue": 1
            },
            "legendItems": [
                {"label": "Undetected", "color": "#66ff66"},
                {"label": "Detected", "color": "#ff6666"}
            ]
        }
        
        return layer
    
    async def export_report(
        self,
        operation_name: str,
        client_name: str,
        output_path: str,
        report_format: ReportFormat = ReportFormat.MARKDOWN
    ) -> str:
        """
        Export complete report
        
        Args:
            operation_name: Operation name
            client_name: Client name
            output_path: Output directory
            report_format: Report format
        
        Returns:
            Path to generated report
        """
        self.logger.info(f"Exporting report: {operation_name} ({report_format.value})")
        
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if report_format == ReportFormat.MARKDOWN:
            # Executive summary
            exec_summary = await self.generate_executive_summary(
                operation_name, client_name, datetime.now().strftime('%Y-%m-%d')
            )
            
            # Technical report
            tech_report = await self.generate_technical_report(operation_name)
            
            # Combine
            full_report = f"{exec_summary}\n\n{tech_report}"
            
            report_file = output_dir / f"{operation_name}_report.md"
            report_file.write_text(full_report, encoding='utf-8')
            
            return str(report_file)
        
        elif report_format == ReportFormat.JSON:
            json_report = await self.generate_json_report()
            
            report_file = output_dir / f"{operation_name}_report.json"
            report_file.write_text(json_report, encoding='utf-8')
            
            return str(report_file)
        
        elif report_format == ReportFormat.HTML:
            # Convert markdown to HTML
            exec_summary = await self.generate_executive_summary(
                operation_name, client_name, datetime.now().strftime('%Y-%m-%d')
            )
            tech_report = await self.generate_technical_report(operation_name)
            
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Red Team Report - {operation_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #d32f2f; }}
        h2 {{ color: #1976d2; }}
        .finding {{ border-left: 4px solid #d32f2f; padding-left: 20px; margin: 20px 0; }}
        .critical {{ border-color: #d32f2f; }}
        .high {{ border-color: #ff6f00; }}
        .medium {{ border-color: #fbc02d; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #1976d2; color: white; }}
    </style>
</head>
<body>
    <pre>{exec_summary}</pre>
    <hr>
    <pre>{tech_report}</pre>
</body>
</html>"""
            
            report_file = output_dir / f"{operation_name}_report.html"
            report_file.write_text(html, encoding='utf-8')
            
            return str(report_file)
        
        else:
            self.logger.warning(f"Unsupported format: {report_format}")
            return ""


__all__ = [
    'RedTeamReporter',
    'Finding',
    'OperationMetrics',
    'AttackPath',
    'ReportFormat',
    'SeverityLevel'
]
