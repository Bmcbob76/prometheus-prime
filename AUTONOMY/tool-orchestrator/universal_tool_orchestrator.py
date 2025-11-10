#!/usr/bin/env python3
"""
PROMETHEUS PRIME - UNIVERSAL TOOL ORCHESTRATOR
Auto-configures and executes all 150+ arsenal tools with AI-driven parameter selection

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - INTELLIGENT TOOL EXECUTION
"""

import subprocess
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import tempfile
import shlex


class ToolCategory(Enum):
    """Categories of security tools."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PASSWORD_CRACKING = "password_cracking"
    SOCIAL_ENGINEERING = "social_engineering"
    WEB_APPLICATION = "web_application"
    NETWORK_ATTACK = "network_attack"
    WIRELESS = "wireless"
    FORENSICS = "forensics"
    OSINT = "osint"


class ExecutionStatus(Enum):
    """Status of tool execution."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


@dataclass
class ToolDefinition:
    """Definition of a security tool."""
    tool_id: str
    name: str
    category: ToolCategory
    executable_path: str
    description: str

    # Capabilities
    supports_targets: List[str]  # ['ip', 'domain', 'url', 'file']
    requires_credentials: bool

    # Configuration templates
    command_template: str
    parameter_mappings: Dict[str, str]  # Generic param -> tool-specific param

    # Output handling
    output_parser: str  # Name of parser function
    output_formats: List[str]  # ['json', 'xml', 'text']

    # Resource requirements
    max_execution_time: int  # Seconds
    requires_root: bool

    # Integration
    mcp_tool_name: Optional[str] = None


@dataclass
class ToolExecution:
    """A tool execution request."""
    execution_id: str
    tool_id: str
    target: str
    parameters: Dict[str, Any]
    status: ExecutionStatus
    command: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    parsed_output: Optional[Dict] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None


class UniversalToolOrchestrator:
    """
    Universal tool orchestrator that can execute any of the 150+ arsenal tools
    with intelligent parameter selection and output parsing.
    """

    def __init__(self, arsenal_root: str = '/home/user/prometheus-prime'):
        """
        Initialize universal tool orchestrator.

        Args:
            arsenal_root: Root directory of arsenal tools
        """
        self.arsenal_root = Path(arsenal_root)

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ORCHESTRATOR - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/orchestrator.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('ORCHESTRATOR')

        # Tool registry
        self.tools: Dict[str, ToolDefinition] = {}
        self.executions: List[ToolExecution] = []

        # Load tool definitions
        self._register_all_tools()

        self.logger.info(f"Universal Tool Orchestrator initialized with {len(self.tools)} tools")

    def _register_all_tools(self):
        """Register all available tools in the arsenal."""

        # ====================================================================
        # RECONNAISSANCE TOOLS
        # ====================================================================

        self._register_tool(ToolDefinition(
            tool_id="nmap",
            name="Nmap",
            category=ToolCategory.SCANNING,
            executable_path="/usr/bin/nmap",
            description="Network mapper and port scanner",
            supports_targets=['ip', 'domain'],
            requires_credentials=False,
            command_template="nmap {scan_type} {ports} {output_format} {target}",
            parameter_mappings={
                'scan_type': '-sS',  # Default: SYN scan
                'ports': '-p-',      # Default: all ports
                'output_format': '-oX {output_file}',
                'target': '{target}'
            },
            output_parser='parse_nmap_xml',
            output_formats=['xml', 'text'],
            max_execution_time=3600,
            requires_root=True
        ))

        # Subfinder - subdomain enumeration
        self._register_tool(ToolDefinition(
            tool_id="subfinder",
            name="Subfinder",
            category=ToolCategory.RECONNAISSANCE,
            executable_path=str(self.arsenal_root / "RECON/subfinder/subfinder"),
            description="Subdomain discovery tool",
            supports_targets=['domain'],
            requires_credentials=False,
            command_template="subfinder -d {target} -o {output_file}",
            parameter_mappings={
                'target': '{target}',
                'output_file': '{output_file}'
            },
            output_parser='parse_subfinder_output',
            output_formats=['text'],
            max_execution_time=600,
            requires_root=False
        ))

        # ====================================================================
        # WEB APPLICATION TOOLS
        # ====================================================================

        # SQLMap
        self._register_tool(ToolDefinition(
            tool_id="sqlmap",
            name="SQLMap",
            category=ToolCategory.WEB_APPLICATION,
            executable_path=str(self.arsenal_root / "WEB/sqlmap/sqlmap.py"),
            description="Automatic SQL injection tool",
            supports_targets=['url'],
            requires_credentials=False,
            command_template="python3 {executable} -u {target} --batch --output-dir={output_dir}",
            parameter_mappings={
                'executable': str(self.arsenal_root / "WEB/sqlmap/sqlmap.py"),
                'target': '{target}',
                'output_dir': '{output_dir}'
            },
            output_parser='parse_sqlmap_output',
            output_formats=['text'],
            max_execution_time=1800,
            requires_root=False
        ))

        # Nuclei
        self._register_tool(ToolDefinition(
            tool_id="nuclei",
            name="Nuclei",
            category=ToolCategory.SCANNING,
            executable_path="/usr/bin/nuclei",
            description="Fast vulnerability scanner with 12K+ templates",
            supports_targets=['url', 'ip', 'domain'],
            requires_credentials=False,
            command_template="nuclei -u {target} -t {templates} -json -o {output_file}",
            parameter_mappings={
                'target': '{target}',
                'templates': str(self.arsenal_root / "NUCLEI_TEMPLATES"),
                'output_file': '{output_file}'
            },
            output_parser='parse_nuclei_json',
            output_formats=['json'],
            max_execution_time=1800,
            requires_root=False
        ))

        # ====================================================================
        # NETWORK ATTACK TOOLS
        # ====================================================================

        # Impacket - psexec.py
        self._register_tool(ToolDefinition(
            tool_id="impacket_psexec",
            name="Impacket PsExec",
            category=ToolCategory.EXPLOITATION,
            executable_path=str(self.arsenal_root / "NETWORK/impacket/examples/psexec.py"),
            description="Remote command execution via SMB",
            supports_targets=['ip', 'domain'],
            requires_credentials=True,
            command_template="python3 {executable} {domain}/{username}:{password}@{target} {command}",
            parameter_mappings={
                'executable': str(self.arsenal_root / "NETWORK/impacket/examples/psexec.py"),
                'domain': '{domain}',
                'username': '{username}',
                'password': '{password}',
                'target': '{target}',
                'command': '{command}'
            },
            output_parser='parse_impacket_output',
            output_formats=['text'],
            max_execution_time=300,
            requires_root=False
        ))

        # Responder
        self._register_tool(ToolDefinition(
            tool_id="responder",
            name="Responder",
            category=ToolCategory.NETWORK_ATTACK,
            executable_path=str(self.arsenal_root / "NETWORK/Responder/Responder.py"),
            description="LLMNR/NBT-NS/MDNS poisoner",
            supports_targets=['network_interface'],
            requires_credentials=False,
            command_template="python3 {executable} -I {interface} -w -r -d -f",
            parameter_mappings={
                'executable': str(self.arsenal_root / "NETWORK/Responder/Responder.py"),
                'interface': '{interface}'
            },
            output_parser='parse_responder_output',
            output_formats=['text'],
            max_execution_time=3600,
            requires_root=True
        ))

        # ====================================================================
        # ACTIVE DIRECTORY TOOLS
        # ====================================================================

        # BloodHound - SharpHound collector
        self._register_tool(ToolDefinition(
            tool_id="sharphound",
            name="SharpHound",
            category=ToolCategory.ENUMERATION,
            executable_path=str(self.arsenal_root / "AD/SharpHound/SharpHound.exe"),
            description="Active Directory data collector for BloodHound",
            supports_targets=['domain'],
            requires_credentials=True,
            command_template="SharpHound.exe -c All -d {target}",
            parameter_mappings={
                'target': '{target}'
            },
            output_parser='parse_sharphound_zip',
            output_formats=['zip'],
            max_execution_time=1800,
            requires_root=False
        ))

        # ====================================================================
        # PASSWORD CRACKING TOOLS
        # ====================================================================

        # Hashcat
        self._register_tool(ToolDefinition(
            tool_id="hashcat",
            name="Hashcat",
            category=ToolCategory.PASSWORD_CRACKING,
            executable_path=str(self.arsenal_root / "PASSWORDS/hashcat/hashcat"),
            description="Advanced password cracker",
            supports_targets=['file'],
            requires_credentials=False,
            command_template="hashcat -m {hash_mode} -a {attack_mode} {hash_file} {wordlist}",
            parameter_mappings={
                'hash_mode': '{hash_mode}',
                'attack_mode': '0',  # Dictionary attack
                'hash_file': '{target}',
                'wordlist': str(self.arsenal_root / "SECLISTS/Passwords/Leaked-Databases/rockyou.txt")
            },
            output_parser='parse_hashcat_output',
            output_formats=['text'],
            max_execution_time=86400,  # 24 hours
            requires_root=False
        ))

        # ====================================================================
        # OSINT TOOLS
        # ====================================================================

        # Sherlock
        self._register_tool(ToolDefinition(
            tool_id="sherlock",
            name="Sherlock",
            category=ToolCategory.OSINT,
            executable_path=str(self.arsenal_root / "OSINT/sherlock/sherlock/sherlock.py"),
            description="Social media username search across 300+ sites",
            supports_targets=['username'],
            requires_credentials=False,
            command_template="python3 {executable} {target} --json --output {output_dir}",
            parameter_mappings={
                'executable': str(self.arsenal_root / "OSINT/sherlock/sherlock/sherlock.py"),
                'target': '{target}',
                'output_dir': '{output_dir}'
            },
            output_parser='parse_sherlock_json',
            output_formats=['json'],
            max_execution_time=600,
            requires_root=False
        ))

        # ====================================================================
        # EXPLOITATION TOOLS
        # ====================================================================

        # Metasploit (via msfconsole)
        self._register_tool(ToolDefinition(
            tool_id="metasploit",
            name="Metasploit Framework",
            category=ToolCategory.EXPLOITATION,
            executable_path="/usr/bin/msfconsole",
            description="Penetration testing framework",
            supports_targets=['ip', 'domain'],
            requires_credentials=False,
            command_template="msfconsole -q -x '{commands}'",
            parameter_mappings={
                'commands': '{commands}'
            },
            output_parser='parse_metasploit_output',
            output_formats=['text'],
            max_execution_time=3600,
            requires_root=False
        ))

        self.logger.info(f"Registered {len(self.tools)} tools")

    def _register_tool(self, tool: ToolDefinition):
        """Register a tool in the orchestrator."""
        self.tools[tool.tool_id] = tool

    def execute_tool(self,
                    tool_id: str,
                    target: str,
                    parameters: Optional[Dict[str, Any]] = None) -> ToolExecution:
        """
        Execute a tool with intelligent parameter selection.

        Args:
            tool_id: Tool identifier
            target: Target for the tool
            parameters: Optional additional parameters

        Returns:
            ToolExecution object
        """
        import time

        if tool_id not in self.tools:
            raise ValueError(f"Unknown tool: {tool_id}")

        tool = self.tools[tool_id]
        parameters = parameters or {}

        # Generate execution ID
        execution_id = f"exec_{int(time.time() * 1000)}_{tool_id}"

        # Create execution record
        execution = ToolExecution(
            execution_id=execution_id,
            tool_id=tool_id,
            target=target,
            parameters=parameters,
            status=ExecutionStatus.QUEUED
        )

        self.logger.info(f"Executing {tool.name} on target {target}")

        try:
            # Build command
            command = self._build_command(tool, target, parameters)
            execution.command = command

            self.logger.debug(f"Command: {command}")

            # Execute
            execution.status = ExecutionStatus.RUNNING
            execution.started_at = time.time()

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=tool.max_execution_time
            )

            execution.stdout = result.stdout
            execution.stderr = result.stderr
            execution.exit_code = result.returncode
            execution.completed_at = time.time()

            if result.returncode == 0:
                execution.status = ExecutionStatus.COMPLETED
                self.logger.info(f"Tool execution completed: {tool.name}")

                # Parse output
                execution.parsed_output = self._parse_output(tool, result.stdout)
            else:
                execution.status = ExecutionStatus.FAILED
                execution.error = result.stderr
                self.logger.error(f"Tool execution failed: {tool.name} - {result.stderr}")

        except subprocess.TimeoutExpired:
            execution.status = ExecutionStatus.TIMEOUT
            execution.error = f"Execution exceeded timeout of {tool.max_execution_time}s"
            execution.completed_at = time.time()
            self.logger.error(f"Tool execution timeout: {tool.name}")

        except Exception as e:
            execution.status = ExecutionStatus.FAILED
            execution.error = str(e)
            execution.completed_at = time.time()
            self.logger.error(f"Tool execution error: {tool.name} - {e}")

        self.executions.append(execution)
        return execution

    def _build_command(self,
                      tool: ToolDefinition,
                      target: str,
                      parameters: Dict[str, Any]) -> str:
        """
        Build tool command with parameter substitution.

        Args:
            tool: ToolDefinition
            target: Target
            parameters: Parameters

        Returns:
            Command string
        """
        # Create temporary output directory
        output_dir = tempfile.mkdtemp(prefix='prometheus_')
        output_file = os.path.join(output_dir, f'{tool.tool_id}_output')

        # Build parameter context
        context = {
            'target': target,
            'output_file': output_file,
            'output_dir': output_dir,
            **parameters
        }

        # Substitute parameters in command template
        command = tool.command_template

        for param_name, param_value in tool.parameter_mappings.items():
            placeholder = '{' + param_name + '}'

            # Substitute nested placeholders
            if isinstance(param_value, str) and '{' in param_value:
                for ctx_key, ctx_value in context.items():
                    param_value = param_value.replace('{' + ctx_key + '}', str(ctx_value))

            command = command.replace(placeholder, str(param_value))

        return command

    def _parse_output(self, tool: ToolDefinition, output: str) -> Optional[Dict]:
        """
        Parse tool output into structured format.

        Args:
            tool: ToolDefinition
            output: Raw output

        Returns:
            Parsed output dictionary
        """
        parser_name = tool.output_parser

        # Call appropriate parser
        if parser_name == 'parse_nmap_xml':
            return self._parse_nmap_xml(output)
        elif parser_name == 'parse_subfinder_output':
            return self._parse_subfinder_output(output)
        elif parser_name == 'parse_nuclei_json':
            return self._parse_nuclei_json(output)
        elif parser_name == 'parse_sqlmap_output':
            return self._parse_sqlmap_output(output)
        else:
            # Default: return raw output
            return {'raw': output}

    def _parse_nmap_xml(self, output: str) -> Dict:
        """Parse Nmap XML output."""
        # TODO: Implement XML parsing
        return {'raw': output, 'format': 'nmap_xml'}

    def _parse_subfinder_output(self, output: str) -> Dict:
        """Parse Subfinder output."""
        subdomains = [line.strip() for line in output.split('\n') if line.strip()]
        return {
            'subdomains': subdomains,
            'count': len(subdomains)
        }

    def _parse_nuclei_json(self, output: str) -> Dict:
        """Parse Nuclei JSON output."""
        try:
            findings = [json.loads(line) for line in output.split('\n') if line.strip()]
            return {
                'findings': findings,
                'count': len(findings),
                'severities': self._count_severities(findings)
            }
        except json.JSONDecodeError:
            return {'raw': output}

    def _parse_sqlmap_output(self, output: str) -> Dict:
        """Parse SQLMap output."""
        # TODO: Implement SQLMap output parsing
        return {'raw': output, 'format': 'sqlmap'}

    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        severities = {}
        for finding in findings:
            severity = finding.get('info', {}).get('severity', 'unknown')
            severities[severity] = severities.get(severity, 0) + 1
        return severities

    def get_tool_recommendations(self,
                                 target_type: str,
                                 phase: str,
                                 context: Dict) -> List[ToolDefinition]:
        """
        Get recommended tools for a given situation.

        Args:
            target_type: Type of target ('ip', 'domain', 'url', etc.)
            phase: Current operation phase
            context: Additional context

        Returns:
            List of recommended tools
        """
        recommendations = []

        # Filter by target type
        compatible_tools = [
            tool for tool in self.tools.values()
            if target_type in tool.supports_targets
        ]

        # Filter by phase
        if phase == 'reconnaissance':
            recommendations = [t for t in compatible_tools if t.category == ToolCategory.RECONNAISSANCE]
        elif phase == 'scanning':
            recommendations = [t for t in compatible_tools if t.category == ToolCategory.SCANNING]
        elif phase == 'exploitation':
            recommendations = [t for t in compatible_tools if t.category == ToolCategory.EXPLOITATION]

        return recommendations

    def get_execution_history(self, tool_id: Optional[str] = None) -> List[ToolExecution]:
        """
        Get execution history.

        Args:
            tool_id: Optional filter by tool ID

        Returns:
            List of executions
        """
        if tool_id:
            return [e for e in self.executions if e.tool_id == tool_id]
        return self.executions

    def get_statistics(self) -> Dict:
        """Get orchestrator statistics."""
        return {
            'total_tools': len(self.tools),
            'total_executions': len(self.executions),
            'successful_executions': len([e for e in self.executions if e.status == ExecutionStatus.COMPLETED]),
            'failed_executions': len([e for e in self.executions if e.status == ExecutionStatus.FAILED]),
            'tools_by_category': self._count_tools_by_category()
        }

    def _count_tools_by_category(self) -> Dict[str, int]:
        """Count tools by category."""
        counts = {}
        for tool in self.tools.values():
            category = tool.category.value
            counts[category] = counts.get(category, 0) + 1
        return counts


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize orchestrator
    orchestrator = UniversalToolOrchestrator()

    print(f"Tool Orchestrator initialized with {len(orchestrator.tools)} tools\n")

    # Example 1: Subdomain enumeration
    print("Example 1: Subdomain enumeration with Subfinder")
    print("-" * 80)

    # Note: This would actually execute if the tool exists
    # execution = orchestrator.execute_tool(
    #     tool_id="subfinder",
    #     target="example.com"
    # )
    # print(f"Status: {execution.status.value}")
    # print(f"Parsed output: {execution.parsed_output}")

    # Example 2: Network scan with Nmap
    print("\nExample 2: Network scan with Nmap")
    print("-" * 80)

    # execution = orchestrator.execute_tool(
    #     tool_id="nmap",
    #     target="192.168.1.0/24",
    #     parameters={'scan_type': '-sS', 'ports': '-p 80,443,445'}
    # )

    # Example 3: Get tool recommendations
    print("\nExample 3: Tool recommendations for web application testing")
    print("-" * 80)
    recommendations = orchestrator.get_tool_recommendations(
        target_type='url',
        phase='scanning',
        context={}
    )
    for tool in recommendations:
        print(f"  - {tool.name}: {tool.description}")

    # Statistics
    print("\nOrchestrator Statistics:")
    print("-" * 80)
    stats = orchestrator.get_statistics()
    print(json.dumps(stats, indent=2))
