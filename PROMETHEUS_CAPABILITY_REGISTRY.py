#!/usr/bin/env python3
"""
PROMETHEUS PRIME - EXPANDED MCP REGISTRY
All 302 Tools Registered
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("PrometheusRegistry")

class CapabilityCategory(Enum):
    SECURITY_DOMAIN = "security_domain"
    DIAGNOSTIC = "diagnostic"
    BASIC_TOOL = "basic_tool"
    SIGINT = "sigint"
    SPECIALIZED = "specialized"
    ULTIMATE = "ultimate"

class ExpertiseLevel(Enum):
    EXPERT = 4
    MASTER = 5
    GRANDMASTER = 10

@dataclass
class Capability:
    name: str
    category: CapabilityCategory
    description: str
    module_path: str
    class_name: str
    mcp_tool_name: str
    operations: List[str]
    expertise_level: ExpertiseLevel
    is_available: bool = True
    authority_required: float = 9.0

class PrometheusCapabilityRegistry:
    def __init__(self):
        self._capabilities = {}
        self._initialize_capabilities()

    def _initialize_capabilities(self):
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.base_domain",
            class_name="OperationResult", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_fingerprint_spoof"] = Capability(
            name="fingerprint_spoof", category=CapabilityCategory.SECURITY_DOMAIN,
            description="fingerprint_spoof operation", module_path="capabilities.biometric_bypass",
            class_name="BiometricSample", mcp_tool_name="prom_fingerprint_spoof",
            operations=["fingerprint_spoof"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_face_recognition_bypass"] = Capability(
            name="face_recognition_bypass", category=CapabilityCategory.SECURITY_DOMAIN,
            description="face_recognition_bypass operation", module_path="capabilities.biometric_bypass",
            class_name="BiometricSample", mcp_tool_name="prom_face_recognition_bypass",
            operations=["face_recognition_bypass"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_iris_scan_defeat"] = Capability(
            name="iris_scan_defeat", category=CapabilityCategory.SECURITY_DOMAIN,
            description="iris_scan_defeat operation", module_path="capabilities.biometric_bypass",
            class_name="BiometricSample", mcp_tool_name="prom_iris_scan_defeat",
            operations=["iris_scan_defeat"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_voice_cloning_attack"] = Capability(
            name="voice_cloning_attack", category=CapabilityCategory.SECURITY_DOMAIN,
            description="voice_cloning_attack operation", module_path="capabilities.biometric_bypass",
            class_name="BiometricSample", mcp_tool_name="prom_voice_cloning_attack",
            operations=["voice_cloning_attack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_gait_analysis_bypass"] = Capability(
            name="gait_analysis_bypass", category=CapabilityCategory.SECURITY_DOMAIN,
            description="gait_analysis_bypass operation", module_path="capabilities.biometric_bypass",
            class_name="BiometricSample", mcp_tool_name="prom_gait_analysis_bypass",
            operations=["gait_analysis_bypass"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_vein_pattern_spoof"] = Capability(
            name="vein_pattern_spoof", category=CapabilityCategory.SECURITY_DOMAIN,
            description="vein_pattern_spoof operation", module_path="capabilities.biometric_bypass",
            class_name="BiometricSample", mcp_tool_name="prom_vein_pattern_spoof",
            operations=["vein_pattern_spoof"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_multimodal_bypass_strategy"] = Capability(
            name="multimodal_bypass_strategy", category=CapabilityCategory.SECURITY_DOMAIN,
            description="multimodal_bypass_strategy operation", module_path="capabilities.biometric_bypass",
            class_name="BiometricSample", mcp_tool_name="prom_multimodal_bypass_strategy",
            operations=["multimodal_bypass_strategy"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.blue_team",
            class_name="BlueTeam", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_enumerate_s3_buckets"] = Capability(
            name="enumerate_s3_buckets", category=CapabilityCategory.SECURITY_DOMAIN,
            description="enumerate_s3_buckets operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_enumerate_s3_buckets",
            operations=["enumerate_s3_buckets"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_s3_public_access"] = Capability(
            name="check_s3_public_access", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_s3_public_access operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_check_s3_public_access",
            operations=["check_s3_public_access"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_iam_privilege_escalation"] = Capability(
            name="iam_privilege_escalation", category=CapabilityCategory.SECURITY_DOMAIN,
            description="iam_privilege_escalation operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_iam_privilege_escalation",
            operations=["iam_privilege_escalation"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_container_escape_techniques"] = Capability(
            name="container_escape_techniques", category=CapabilityCategory.SECURITY_DOMAIN,
            description="container_escape_techniques operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_container_escape_techniques",
            operations=["container_escape_techniques"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_kubernetes_attack_surface"] = Capability(
            name="kubernetes_attack_surface", category=CapabilityCategory.SECURITY_DOMAIN,
            description="kubernetes_attack_surface operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_kubernetes_attack_surface",
            operations=["kubernetes_attack_surface"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_azure_runbook_exploit"] = Capability(
            name="azure_runbook_exploit", category=CapabilityCategory.SECURITY_DOMAIN,
            description="azure_runbook_exploit operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_azure_runbook_exploit",
            operations=["azure_runbook_exploit"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_gcp_metadata_server_exploit"] = Capability(
            name="gcp_metadata_server_exploit", category=CapabilityCategory.SECURITY_DOMAIN,
            description="gcp_metadata_server_exploit operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_gcp_metadata_server_exploit",
            operations=["gcp_metadata_server_exploit"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_serverless_function_hijack"] = Capability(
            name="serverless_function_hijack", category=CapabilityCategory.SECURITY_DOMAIN,
            description="serverless_function_hijack operation", module_path="capabilities.cloud_exploits",
            class_name="CloudAsset", mcp_tool_name="prom_serverless_function_hijack",
            operations=["serverless_function_hijack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.cloud_security",
            class_name="CloudSecurity", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.crypto_analysis",
            class_name="CryptoAnalysis", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.exploit_dev",
            class_name="ExploitDev", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.forensics",
            class_name="Forensics", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.iot_security",
            class_name="IoTSecurity", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.malware_dev",
            class_name="MalwareDev", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_adb_devices"] = Capability(
            name="adb_devices", category=CapabilityCategory.SECURITY_DOMAIN,
            description="adb_devices operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_adb_devices",
            operations=["adb_devices"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_install_apk"] = Capability(
            name="install_apk", category=CapabilityCategory.SECURITY_DOMAIN,
            description="install_apk operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_install_apk",
            operations=["install_apk"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_extract_apk"] = Capability(
            name="extract_apk", category=CapabilityCategory.SECURITY_DOMAIN,
            description="extract_apk operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_extract_apk",
            operations=["extract_apk"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_frida_hook"] = Capability(
            name="frida_hook", category=CapabilityCategory.SECURITY_DOMAIN,
            description="frida_hook operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_frida_hook",
            operations=["frida_hook"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_objection_repl"] = Capability(
            name="objection_repl", category=CapabilityCategory.SECURITY_DOMAIN,
            description="objection_repl operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_objection_repl",
            operations=["objection_repl"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_root_detection"] = Capability(
            name="check_root_detection", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_root_detection operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_check_root_detection",
            operations=["check_root_detection"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ssl_pinning_bypass"] = Capability(
            name="ssl_pinning_bypass", category=CapabilityCategory.SECURITY_DOMAIN,
            description="ssl_pinning_bypass operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_ssl_pinning_bypass",
            operations=["ssl_pinning_bypass"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ios_jailbreak_detect"] = Capability(
            name="ios_jailbreak_detect", category=CapabilityCategory.SECURITY_DOMAIN,
            description="ios_jailbreak_detect operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_ios_jailbreak_detect",
            operations=["ios_jailbreak_detect"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_mitmproxy_intercept"] = Capability(
            name="mitmproxy_intercept", category=CapabilityCategory.SECURITY_DOMAIN,
            description="mitmproxy_intercept operation", module_path="capabilities.mobile_exploits",
            class_name="MobileDevice", mcp_tool_name="prom_mitmproxy_intercept",
            operations=["mitmproxy_intercept"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.mobile_security",
            class_name="MobileSecurity", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.network_recon",
            class_name="NetworkRecon", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.osint",
            class_name="OSINT", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.persistence",
            class_name="Persistence", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.physical_security",
            class_name="PhysicalSecurity", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.post_exploitation",
            class_name="PostExploitation", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.purple_team",
            class_name="PurpleTeam", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team",
            class_name="RedTeam", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exfil_dns"] = Capability(
            name="exfil_dns", category=CapabilityCategory.SECURITY_DOMAIN,
            description="exfil_dns operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_exfil_dns",
            operations=["exfil_dns"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exfil_http"] = Capability(
            name="exfil_http", category=CapabilityCategory.SECURITY_DOMAIN,
            description="exfil_http operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_exfil_http",
            operations=["exfil_http"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exfil_icmp"] = Capability(
            name="exfil_icmp", category=CapabilityCategory.SECURITY_DOMAIN,
            description="exfil_icmp operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_exfil_icmp",
            operations=["exfil_icmp"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exfil_smb"] = Capability(
            name="exfil_smb", category=CapabilityCategory.SECURITY_DOMAIN,
            description="exfil_smb operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_exfil_smb",
            operations=["exfil_smb"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exfil_email"] = Capability(
            name="exfil_email", category=CapabilityCategory.SECURITY_DOMAIN,
            description="exfil_email operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_exfil_email",
            operations=["exfil_email"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exfil_steganography"] = Capability(
            name="exfil_steganography", category=CapabilityCategory.SECURITY_DOMAIN,
            description="exfil_steganography operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_exfil_steganography",
            operations=["exfil_steganography"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_simulate_exfil_detection"] = Capability(
            name="simulate_exfil_detection", category=CapabilityCategory.SECURITY_DOMAIN,
            description="simulate_exfil_detection operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_simulate_exfil_detection",
            operations=["simulate_exfil_detection"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_exfil",
            class_name="DataExfiltration", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ssh_lateral"] = Capability(
            name="ssh_lateral", category=CapabilityCategory.SECURITY_DOMAIN,
            description="ssh_lateral operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_ssh_lateral",
            operations=["ssh_lateral"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_psexec_lateral"] = Capability(
            name="psexec_lateral", category=CapabilityCategory.SECURITY_DOMAIN,
            description="psexec_lateral operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_psexec_lateral",
            operations=["psexec_lateral"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_wmi_lateral"] = Capability(
            name="wmi_lateral", category=CapabilityCategory.SECURITY_DOMAIN,
            description="wmi_lateral operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_wmi_lateral",
            operations=["wmi_lateral"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_rdp_lateral"] = Capability(
            name="rdp_lateral", category=CapabilityCategory.SECURITY_DOMAIN,
            description="rdp_lateral operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_rdp_lateral",
            operations=["rdp_lateral"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_smb_relay"] = Capability(
            name="smb_relay", category=CapabilityCategory.SECURITY_DOMAIN,
            description="smb_relay operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_smb_relay",
            operations=["smb_relay"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_pass_the_hash"] = Capability(
            name="pass_the_hash", category=CapabilityCategory.SECURITY_DOMAIN,
            description="pass_the_hash operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_pass_the_hash",
            operations=["pass_the_hash"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_winrm_lateral"] = Capability(
            name="winrm_lateral", category=CapabilityCategory.SECURITY_DOMAIN,
            description="winrm_lateral operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_winrm_lateral",
            operations=["winrm_lateral"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_pivoting_setup"] = Capability(
            name="pivoting_setup", category=CapabilityCategory.SECURITY_DOMAIN,
            description="pivoting_setup operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_pivoting_setup",
            operations=["pivoting_setup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_detect_lateral_paths"] = Capability(
            name="detect_lateral_paths", category=CapabilityCategory.SECURITY_DOMAIN,
            description="detect_lateral_paths operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_detect_lateral_paths",
            operations=["detect_lateral_paths"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_lateral_movement",
            class_name="LateralMovement", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_base64_encode"] = Capability(
            name="base64_encode", category=CapabilityCategory.SECURITY_DOMAIN,
            description="base64_encode operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_base64_encode",
            operations=["base64_encode"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_xor_encode"] = Capability(
            name="xor_encode", category=CapabilityCategory.SECURITY_DOMAIN,
            description="xor_encode operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_xor_encode",
            operations=["xor_encode"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_compress_payload"] = Capability(
            name="compress_payload", category=CapabilityCategory.SECURITY_DOMAIN,
            description="compress_payload operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_compress_payload",
            operations=["compress_payload"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_string_reversal"] = Capability(
            name="string_reversal", category=CapabilityCategory.SECURITY_DOMAIN,
            description="string_reversal operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_string_reversal",
            operations=["string_reversal"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_hex_encode"] = Capability(
            name="hex_encode", category=CapabilityCategory.SECURITY_DOMAIN,
            description="hex_encode operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_hex_encode",
            operations=["hex_encode"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_variable_name_obfuscation"] = Capability(
            name="variable_name_obfuscation", category=CapabilityCategory.SECURITY_DOMAIN,
            description="variable_name_obfuscation operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_variable_name_obfuscation",
            operations=["variable_name_obfuscation"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_char_substitution"] = Capability(
            name="char_substitution", category=CapabilityCategory.SECURITY_DOMAIN,
            description="char_substitution operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_char_substitution",
            operations=["char_substitution"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_powershell_obfuscation"] = Capability(
            name="powershell_obfuscation", category=CapabilityCategory.SECURITY_DOMAIN,
            description="powershell_obfuscation operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_powershell_obfuscation",
            operations=["powershell_obfuscation"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_bash_obfuscation"] = Capability(
            name="bash_obfuscation", category=CapabilityCategory.SECURITY_DOMAIN,
            description="bash_obfuscation operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_bash_obfuscation",
            operations=["bash_obfuscation"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_multilayer_obfuscation"] = Capability(
            name="multilayer_obfuscation", category=CapabilityCategory.SECURITY_DOMAIN,
            description="multilayer_obfuscation operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_multilayer_obfuscation",
            operations=["multilayer_obfuscation"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_obfuscation",
            class_name="PayloadObfuscation", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_hashcat_crack"] = Capability(
            name="hashcat_crack", category=CapabilityCategory.SECURITY_DOMAIN,
            description="hashcat_crack operation", module_path="capabilities.red_team_password_attacks",
            class_name="PasswordAttacks", mcp_tool_name="prom_hashcat_crack",
            operations=["hashcat_crack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_john_crack"] = Capability(
            name="john_crack", category=CapabilityCategory.SECURITY_DOMAIN,
            description="john_crack operation", module_path="capabilities.red_team_password_attacks",
            class_name="PasswordAttacks", mcp_tool_name="prom_john_crack",
            operations=["john_crack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_hydra_brute"] = Capability(
            name="hydra_brute", category=CapabilityCategory.SECURITY_DOMAIN,
            description="hydra_brute operation", module_path="capabilities.red_team_password_attacks",
            class_name="PasswordAttacks", mcp_tool_name="prom_hydra_brute",
            operations=["hydra_brute"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_password_spray"] = Capability(
            name="password_spray", category=CapabilityCategory.SECURITY_DOMAIN,
            description="password_spray operation", module_path="capabilities.red_team_password_attacks",
            class_name="PasswordAttacks", mcp_tool_name="prom_password_spray",
            operations=["password_spray"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_dictionary_attack"] = Capability(
            name="dictionary_attack", category=CapabilityCategory.SECURITY_DOMAIN,
            description="dictionary_attack operation", module_path="capabilities.red_team_password_attacks",
            class_name="PasswordAttacks", mcp_tool_name="prom_dictionary_attack",
            operations=["dictionary_attack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_password_attacks",
            class_name="PasswordAttacks", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_create_campaign"] = Capability(
            name="create_campaign", category=CapabilityCategory.SECURITY_DOMAIN,
            description="create_campaign operation", module_path="capabilities.red_team_phishing",
            class_name="PhishingCampaign", mcp_tool_name="prom_create_campaign",
            operations=["create_campaign"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_send_phishing_email"] = Capability(
            name="send_phishing_email", category=CapabilityCategory.SECURITY_DOMAIN,
            description="send_phishing_email operation", module_path="capabilities.red_team_phishing",
            class_name="PhishingCampaign", mcp_tool_name="prom_send_phishing_email",
            operations=["send_phishing_email"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_track_click"] = Capability(
            name="track_click", category=CapabilityCategory.SECURITY_DOMAIN,
            description="track_click operation", module_path="capabilities.red_team_phishing",
            class_name="PhishingCampaign", mcp_tool_name="prom_track_click",
            operations=["track_click"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_generate_landing_page"] = Capability(
            name="generate_landing_page", category=CapabilityCategory.SECURITY_DOMAIN,
            description="generate_landing_page operation", module_path="capabilities.red_team_phishing",
            class_name="PhishingCampaign", mcp_tool_name="prom_generate_landing_page",
            operations=["generate_landing_page"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_campaign_stats"] = Capability(
            name="get_campaign_stats", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_campaign_stats operation", module_path="capabilities.red_team_phishing",
            class_name="PhishingCampaign", mcp_tool_name="prom_get_campaign_stats",
            operations=["get_campaign_stats"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_phishing",
            class_name="PhishingCampaign", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_suid_files"] = Capability(
            name="check_suid_files", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_suid_files operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_check_suid_files",
            operations=["check_suid_files"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_sudo_permissions"] = Capability(
            name="check_sudo_permissions", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_sudo_permissions operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_check_sudo_permissions",
            operations=["check_sudo_permissions"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_capabilities"] = Capability(
            name="check_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_capabilities operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_check_capabilities",
            operations=["check_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_writable_paths"] = Capability(
            name="check_writable_paths", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_writable_paths operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_check_writable_paths",
            operations=["check_writable_paths"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_cron_jobs"] = Capability(
            name="check_cron_jobs", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_cron_jobs operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_check_cron_jobs",
            operations=["check_cron_jobs"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_kernel_version"] = Capability(
            name="check_kernel_version", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_kernel_version operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_check_kernel_version",
            operations=["check_kernel_version"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_run_linpeas"] = Capability(
            name="run_linpeas", category=CapabilityCategory.SECURITY_DOMAIN,
            description="run_linpeas operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_run_linpeas",
            operations=["run_linpeas"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_privesc",
            class_name="PrivilegeEscalation", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_nmap_vuln_scan"] = Capability(
            name="nmap_vuln_scan", category=CapabilityCategory.SECURITY_DOMAIN,
            description="nmap_vuln_scan operation", module_path="capabilities.red_team_vuln_scan",
            class_name="VulnerabilityScanner", mcp_tool_name="prom_nmap_vuln_scan",
            operations=["nmap_vuln_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_nikto_scan"] = Capability(
            name="nikto_scan", category=CapabilityCategory.SECURITY_DOMAIN,
            description="nikto_scan operation", module_path="capabilities.red_team_vuln_scan",
            class_name="VulnerabilityScanner", mcp_tool_name="prom_nikto_scan",
            operations=["nikto_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_cve"] = Capability(
            name="check_cve", category=CapabilityCategory.SECURITY_DOMAIN,
            description="check_cve operation", module_path="capabilities.red_team_vuln_scan",
            class_name="VulnerabilityScanner", mcp_tool_name="prom_check_cve",
            operations=["check_cve"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_service_version_check"] = Capability(
            name="service_version_check", category=CapabilityCategory.SECURITY_DOMAIN,
            description="service_version_check operation", module_path="capabilities.red_team_vuln_scan",
            class_name="VulnerabilityScanner", mcp_tool_name="prom_service_version_check",
            operations=["service_version_check"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ssl_tls_scan"] = Capability(
            name="ssl_tls_scan", category=CapabilityCategory.SECURITY_DOMAIN,
            description="ssl_tls_scan operation", module_path="capabilities.red_team_vuln_scan",
            class_name="VulnerabilityScanner", mcp_tool_name="prom_ssl_tls_scan",
            operations=["ssl_tls_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exploit_check"] = Capability(
            name="exploit_check", category=CapabilityCategory.SECURITY_DOMAIN,
            description="exploit_check operation", module_path="capabilities.red_team_vuln_scan",
            class_name="VulnerabilityScanner", mcp_tool_name="prom_exploit_check",
            operations=["exploit_check"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_vuln_scan",
            class_name="VulnerabilityScanner", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_sql_injection_test"] = Capability(
            name="sql_injection_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="sql_injection_test operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_sql_injection_test",
            operations=["sql_injection_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_sqlmap_scan"] = Capability(
            name="sqlmap_scan", category=CapabilityCategory.SECURITY_DOMAIN,
            description="sqlmap_scan operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_sqlmap_scan",
            operations=["sqlmap_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_xss_test"] = Capability(
            name="xss_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="xss_test operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_xss_test",
            operations=["xss_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_lfi_test"] = Capability(
            name="lfi_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="lfi_test operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_lfi_test",
            operations=["lfi_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_command_injection_test"] = Capability(
            name="command_injection_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="command_injection_test operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_command_injection_test",
            operations=["command_injection_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ssrf_test"] = Capability(
            name="ssrf_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="ssrf_test operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_ssrf_test",
            operations=["ssrf_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_directory_traversal_test"] = Capability(
            name="directory_traversal_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="directory_traversal_test operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_directory_traversal_test",
            operations=["directory_traversal_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.red_team_web_exploits",
            class_name="WebExploits", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.scada_ics",
            class_name="ScadaICS", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_packet_callback"] = Capability(
            name="packet_callback", category=CapabilityCategory.SECURITY_DOMAIN,
            description="Scapy packet handler", module_path="capabilities.sigint_core",
            class_name="SignalIntel", mcp_tool_name="prom_packet_callback",
            operations=["packet_callback"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_sniff_traffic"] = Capability(
            name="sniff_traffic", category=CapabilityCategory.SECURITY_DOMAIN,
            description="Capture network traffic", module_path="capabilities.sigint_core",
            class_name="SignalIntel", mcp_tool_name="prom_sniff_traffic",
            operations=["sniff_traffic"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_analyze_protocols"] = Capability(
            name="analyze_protocols", category=CapabilityCategory.SECURITY_DOMAIN,
            description="Passive network reconnaissance", module_path="capabilities.sigint_core",
            class_name="SignalIntel", mcp_tool_name="prom_analyze_protocols",
            operations=["analyze_protocols"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_extract_credentials"] = Capability(
            name="extract_credentials", category=CapabilityCategory.SECURITY_DOMAIN,
            description="Passive network reconnaissance", module_path="capabilities.sigint_core",
            class_name="SignalIntel", mcp_tool_name="prom_extract_credentials",
            operations=["extract_credentials"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_dns_analysis"] = Capability(
            name="dns_analysis", category=CapabilityCategory.SECURITY_DOMAIN,
            description="Passive network reconnaissance", module_path="capabilities.sigint_core",
            class_name="SignalIntel", mcp_tool_name="prom_dns_analysis",
            operations=["dns_analysis"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.social_engineering",
            class_name="SocialEngineering", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.threat_intel",
            class_name="ThreatIntel", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.web_exploitation",
            class_name="WebExploitation", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_sql_injection_test"] = Capability(
            name="sql_injection_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="sql_injection_test operation", module_path="capabilities.web_exploits",
            class_name="WebExploiter", mcp_tool_name="prom_sql_injection_test",
            operations=["sql_injection_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_xss_test"] = Capability(
            name="xss_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="xss_test operation", module_path="capabilities.web_exploits",
            class_name="WebExploiter", mcp_tool_name="prom_xss_test",
            operations=["xss_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ssrf_test"] = Capability(
            name="ssrf_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="ssrf_test operation", module_path="capabilities.web_exploits",
            class_name="WebExploiter", mcp_tool_name="prom_ssrf_test",
            operations=["ssrf_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_file_upload_bypass"] = Capability(
            name="file_upload_bypass", category=CapabilityCategory.SECURITY_DOMAIN,
            description="file_upload_bypass operation", module_path="capabilities.web_exploits",
            class_name="WebExploiter", mcp_tool_name="prom_file_upload_bypass",
            operations=["file_upload_bypass"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_jwt_manipulation"] = Capability(
            name="jwt_manipulation", category=CapabilityCategory.SECURITY_DOMAIN,
            description="jwt_manipulation operation", module_path="capabilities.web_exploits",
            class_name="WebExploiter", mcp_tool_name="prom_jwt_manipulation",
            operations=["jwt_manipulation"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_lfi_test"] = Capability(
            name="lfi_test", category=CapabilityCategory.SECURITY_DOMAIN,
            description="lfi_test operation", module_path="capabilities.web_exploits",
            class_name="WebExploiter", mcp_tool_name="prom_lfi_test",
            operations=["lfi_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_capabilities"] = Capability(
            name="get_capabilities", category=CapabilityCategory.SECURITY_DOMAIN,
            description="get_capabilities operation", module_path="capabilities.wireless_ops",
            class_name="WirelessOps", mcp_tool_name="prom_get_capabilities",
            operations=["get_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_obfuscate"] = Capability(
            name="obfuscate", category=CapabilityCategory.BASIC_TOOL,
            description="obfuscate operation", module_path="tools.evasion",
            class_name="EvasionTechniques", mcp_tool_name="prom_obfuscate",
            operations=["obfuscate"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_encrypt"] = Capability(
            name="encrypt", category=CapabilityCategory.BASIC_TOOL,
            description="encrypt operation", module_path="tools.evasion",
            class_name="EvasionTechniques", mcp_tool_name="prom_encrypt",
            operations=["encrypt"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_detect_sandbox"] = Capability(
            name="detect_sandbox", category=CapabilityCategory.BASIC_TOOL,
            description="detect_sandbox operation", module_path="tools.evasion",
            class_name="EvasionTechniques", mcp_tool_name="prom_detect_sandbox",
            operations=["detect_sandbox"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_generate_decoy_traffic"] = Capability(
            name="generate_decoy_traffic", category=CapabilityCategory.BASIC_TOOL,
            description="generate_decoy_traffic operation", module_path="tools.evasion",
            class_name="EvasionTechniques", mcp_tool_name="prom_generate_decoy_traffic",
            operations=["generate_decoy_traffic"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_anti_disassembly"] = Capability(
            name="anti_disassembly", category=CapabilityCategory.BASIC_TOOL,
            description="anti_disassembly operation", module_path="tools.evasion",
            class_name="EvasionTechniques", mcp_tool_name="prom_anti_disassembly",
            operations=["anti_disassembly"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_sleep_evasion"] = Capability(
            name="sleep_evasion", category=CapabilityCategory.BASIC_TOOL,
            description="sleep_evasion operation", module_path="tools.evasion",
            class_name="EvasionTechniques", mcp_tool_name="prom_sleep_evasion",
            operations=["sleep_evasion"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_search_exploits"] = Capability(
            name="search_exploits", category=CapabilityCategory.BASIC_TOOL,
            description="search_exploits operation", module_path="tools.exploits",
            class_name="ExploitFramework", mcp_tool_name="prom_search_exploits",
            operations=["search_exploits"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_statistics"] = Capability(
            name="get_statistics", category=CapabilityCategory.BASIC_TOOL,
            description="get_statistics operation", module_path="tools.exploits",
            class_name="ExploitFramework", mcp_tool_name="prom_get_statistics",
            operations=["get_statistics"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_discover_devices"] = Capability(
            name="discover_devices", category=CapabilityCategory.SIGINT,
            description="discover_devices operation", module_path="modules.bluetooth_intelligence",
            class_name="BluetoothIntelligence", mcp_tool_name="prom_discover_devices",
            operations=["discover_devices"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_profile_device"] = Capability(
            name="profile_device", category=CapabilityCategory.SIGINT,
            description="profile_device operation", module_path="modules.bluetooth_intelligence",
            class_name="BluetoothIntelligence", mcp_tool_name="prom_profile_device",
            operations=["profile_device"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_track_proximity"] = Capability(
            name="track_proximity", category=CapabilityCategory.SIGINT,
            description="track_proximity operation", module_path="modules.bluetooth_intelligence",
            class_name="BluetoothIntelligence", mcp_tool_name="prom_track_proximity",
            operations=["track_proximity"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_analyze_ble_advertising"] = Capability(
            name="analyze_ble_advertising", category=CapabilityCategory.SIGINT,
            description="analyze_ble_advertising operation", module_path="modules.bluetooth_intelligence",
            class_name="BluetoothIntelligence", mcp_tool_name="prom_analyze_ble_advertising",
            operations=["analyze_ble_advertising"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_detect_vulnerabilities"] = Capability(
            name="detect_vulnerabilities", category=CapabilityCategory.SIGINT,
            description="detect_vulnerabilities operation", module_path="modules.bluetooth_intelligence",
            class_name="BluetoothIntelligence", mcp_tool_name="prom_detect_vulnerabilities",
            operations=["detect_vulnerabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_lookup"] = Capability(
            name="lookup", category=CapabilityCategory.SIGINT,
            description="lookup operation", module_path="modules.phone_intelligence",
            class_name="PhoneIntelligence", mcp_tool_name="prom_lookup",
            operations=["lookup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_bulk_lookup"] = Capability(
            name="bulk_lookup", category=CapabilityCategory.SIGINT,
            description="bulk_lookup operation", module_path="modules.phone_intelligence",
            class_name="PhoneIntelligence", mcp_tool_name="prom_bulk_lookup",
            operations=["bulk_lookup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_format_phone"] = Capability(
            name="format_phone", category=CapabilityCategory.SIGINT,
            description="format_phone operation", module_path="modules.phone_intelligence",
            class_name="PhoneIntelligence", mcp_tool_name="prom_format_phone",
            operations=["format_phone"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_username_search"] = Capability(
            name="username_search", category=CapabilityCategory.SIGINT,
            description="username_search operation", module_path="modules.social_osint",
            class_name="SocialOSINT", mcp_tool_name="prom_username_search",
            operations=["username_search"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_reddit_profile"] = Capability(
            name="reddit_profile", category=CapabilityCategory.SIGINT,
            description="reddit_profile operation", module_path="modules.social_osint",
            class_name="SocialOSINT", mcp_tool_name="prom_reddit_profile",
            operations=["reddit_profile"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_github_profile"] = Capability(
            name="github_profile", category=CapabilityCategory.SIGINT,
            description="github_profile operation", module_path="modules.social_osint",
            class_name="SocialOSINT", mcp_tool_name="prom_github_profile",
            operations=["github_profile"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_email_to_username"] = Capability(
            name="email_to_username", category=CapabilityCategory.SIGINT,
            description="email_to_username operation", module_path="modules.social_osint",
            class_name="SocialOSINT", mcp_tool_name="prom_email_to_username",
            operations=["email_to_username"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_phone_to_social"] = Capability(
            name="phone_to_social", category=CapabilityCategory.SIGINT,
            description="phone_to_social operation", module_path="modules.social_osint",
            class_name="SocialOSINT", mcp_tool_name="prom_phone_to_social",
            operations=["phone_to_social"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_full_osint_report"] = Capability(
            name="full_osint_report", category=CapabilityCategory.SIGINT,
            description="full_osint_report operation", module_path="modules.social_osint",
            class_name="SocialOSINT", mcp_tool_name="prom_full_osint_report",
            operations=["full_osint_report"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_search_by_location"] = Capability(
            name="search_by_location", category=CapabilityCategory.SIGINT,
            description="search_by_location operation", module_path="modules.social_osint",
            class_name="SocialOSINT", mcp_tool_name="prom_search_by_location",
            operations=["search_by_location"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_capture_traffic"] = Capability(
            name="capture_traffic", category=CapabilityCategory.SIGINT,
            description="capture_traffic operation", module_path="modules.traffic_analysis",
            class_name="TrafficAnalysis", mcp_tool_name="prom_capture_traffic",
            operations=["capture_traffic"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_analyze_protocols"] = Capability(
            name="analyze_protocols", category=CapabilityCategory.SIGINT,
            description="analyze_protocols operation", module_path="modules.traffic_analysis",
            class_name="TrafficAnalysis", mcp_tool_name="prom_analyze_protocols",
            operations=["analyze_protocols"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_identify_top_talkers"] = Capability(
            name="identify_top_talkers", category=CapabilityCategory.SIGINT,
            description="identify_top_talkers operation", module_path="modules.traffic_analysis",
            class_name="TrafficAnalysis", mcp_tool_name="prom_identify_top_talkers",
            operations=["identify_top_talkers"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_monitor_bandwidth"] = Capability(
            name="monitor_bandwidth", category=CapabilityCategory.SIGINT,
            description="monitor_bandwidth operation", module_path="modules.traffic_analysis",
            class_name="TrafficAnalysis", mcp_tool_name="prom_monitor_bandwidth",
            operations=["monitor_bandwidth"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_detect_anomalies"] = Capability(
            name="detect_anomalies", category=CapabilityCategory.SIGINT,
            description="detect_anomalies operation", module_path="modules.traffic_analysis",
            class_name="TrafficAnalysis", mcp_tool_name="prom_detect_anomalies",
            operations=["detect_anomalies"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_analyze_dns_queries"] = Capability(
            name="analyze_dns_queries", category=CapabilityCategory.SIGINT,
            description="analyze_dns_queries operation", module_path="modules.traffic_analysis",
            class_name="TrafficAnalysis", mcp_tool_name="prom_analyze_dns_queries",
            operations=["analyze_dns_queries"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_analyze_http_traffic"] = Capability(
            name="analyze_http_traffic", category=CapabilityCategory.SIGINT,
            description="analyze_http_traffic operation", module_path="modules.traffic_analysis",
            class_name="TrafficAnalysis", mcp_tool_name="prom_analyze_http_traffic",
            operations=["analyze_http_traffic"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_discover_networks"] = Capability(
            name="discover_networks", category=CapabilityCategory.SIGINT,
            description="discover_networks operation", module_path="modules.wifi_intelligence",
            class_name="WiFiIntelligence", mcp_tool_name="prom_discover_networks",
            operations=["discover_networks"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_assess_security"] = Capability(
            name="assess_security", category=CapabilityCategory.SIGINT,
            description="assess_security operation", module_path="modules.wifi_intelligence",
            class_name="WiFiIntelligence", mcp_tool_name="prom_assess_security",
            operations=["assess_security"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_track_clients"] = Capability(
            name="track_clients", category=CapabilityCategory.SIGINT,
            description="track_clients operation", module_path="modules.wifi_intelligence",
            class_name="WiFiIntelligence", mcp_tool_name="prom_track_clients",
            operations=["track_clients"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_channel_analysis"] = Capability(
            name="channel_analysis", category=CapabilityCategory.SIGINT,
            description="channel_analysis operation", module_path="modules.wifi_intelligence",
            class_name="WiFiIntelligence", mcp_tool_name="prom_channel_analysis",
            operations=["channel_analysis"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_detect_rogue_aps"] = Capability(
            name="detect_rogue_aps", category=CapabilityCategory.SIGINT,
            description="detect_rogue_aps operation", module_path="modules.wifi_intelligence",
            class_name="WiFiIntelligence", mcp_tool_name="prom_detect_rogue_aps",
            operations=["detect_rogue_aps"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_run_full_diagnostics"] = Capability(
            name="run_full_diagnostics", category=CapabilityCategory.DIAGNOSTIC,
            description="run_full_diagnostics operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_run_full_diagnostics",
            operations=["run_full_diagnostics"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_detect_gpus"] = Capability(
            name="detect_gpus", category=CapabilityCategory.DIAGNOSTIC,
            description="detect_gpus operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_detect_gpus",
            operations=["detect_gpus"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_cuda_support"] = Capability(
            name="check_cuda_support", category=CapabilityCategory.DIAGNOSTIC,
            description="check_cuda_support operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_cuda_support",
            operations=["check_cuda_support"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_cpu_capabilities"] = Capability(
            name="check_cpu_capabilities", category=CapabilityCategory.DIAGNOSTIC,
            description="check_cpu_capabilities operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_cpu_capabilities",
            operations=["check_cpu_capabilities"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_pytorch"] = Capability(
            name="check_pytorch", category=CapabilityCategory.DIAGNOSTIC,
            description="check_pytorch operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_pytorch",
            operations=["check_pytorch"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_tensorflow"] = Capability(
            name="check_tensorflow", category=CapabilityCategory.DIAGNOSTIC,
            description="check_tensorflow operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_tensorflow",
            operations=["check_tensorflow"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_framework_compatibility"] = Capability(
            name="check_framework_compatibility", category=CapabilityCategory.DIAGNOSTIC,
            description="check_framework_compatibility operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_framework_compatibility",
            operations=["check_framework_compatibility"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_monitor_gpu_utilization"] = Capability(
            name="monitor_gpu_utilization", category=CapabilityCategory.DIAGNOSTIC,
            description="monitor_gpu_utilization operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_monitor_gpu_utilization",
            operations=["monitor_gpu_utilization"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_gpu_memory"] = Capability(
            name="check_gpu_memory", category=CapabilityCategory.DIAGNOSTIC,
            description="check_gpu_memory operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_gpu_memory",
            operations=["check_gpu_memory"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_multi_gpu_setup"] = Capability(
            name="check_multi_gpu_setup", category=CapabilityCategory.DIAGNOSTIC,
            description="check_multi_gpu_setup operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_multi_gpu_setup",
            operations=["check_multi_gpu_setup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_benchmark_inference"] = Capability(
            name="benchmark_inference", category=CapabilityCategory.DIAGNOSTIC,
            description="benchmark_inference operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_benchmark_inference",
            operations=["benchmark_inference"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_benchmark_memory_bandwidth"] = Capability(
            name="benchmark_memory_bandwidth", category=CapabilityCategory.DIAGNOSTIC,
            description="benchmark_memory_bandwidth operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_benchmark_memory_bandwidth",
            operations=["benchmark_memory_bandwidth"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_model_quantization"] = Capability(
            name="check_model_quantization", category=CapabilityCategory.DIAGNOSTIC,
            description="check_model_quantization operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_check_model_quantization",
            operations=["check_model_quantization"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_verify_model_formats"] = Capability(
            name="verify_model_formats", category=CapabilityCategory.DIAGNOSTIC,
            description="verify_model_formats operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_verify_model_formats",
            operations=["verify_model_formats"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_calculate_health_score"] = Capability(
            name="calculate_health_score", category=CapabilityCategory.DIAGNOSTIC,
            description="calculate_health_score operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_calculate_health_score",
            operations=["calculate_health_score"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_summary"] = Capability(
            name="get_summary", category=CapabilityCategory.DIAGNOSTIC,
            description="get_summary operation", module_path="src.diagnostics.ai_ml_diagnostics",
            class_name="AIMLDiagnostics", mcp_tool_name="prom_get_summary",
            operations=["get_summary"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_run_full_diagnostics"] = Capability(
            name="run_full_diagnostics", category=CapabilityCategory.DIAGNOSTIC,
            description="run_full_diagnostics operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_run_full_diagnostics",
            operations=["run_full_diagnostics"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_redis"] = Capability(
            name="test_redis", category=CapabilityCategory.DIAGNOSTIC,
            description="test_redis operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_test_redis",
            operations=["test_redis"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_postgresql"] = Capability(
            name="test_postgresql", category=CapabilityCategory.DIAGNOSTIC,
            description="test_postgresql operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_test_postgresql",
            operations=["test_postgresql"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_mongodb"] = Capability(
            name="test_mongodb", category=CapabilityCategory.DIAGNOSTIC,
            description="test_mongodb operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_test_mongodb",
            operations=["test_mongodb"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_sqlite"] = Capability(
            name="test_sqlite", category=CapabilityCategory.DIAGNOSTIC,
            description="test_sqlite operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_test_sqlite",
            operations=["test_sqlite"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_elasticsearch"] = Capability(
            name="test_elasticsearch", category=CapabilityCategory.DIAGNOSTIC,
            description="test_elasticsearch operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_test_elasticsearch",
            operations=["test_elasticsearch"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_benchmark_read_performance"] = Capability(
            name="benchmark_read_performance", category=CapabilityCategory.DIAGNOSTIC,
            description="benchmark_read_performance operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_benchmark_read_performance",
            operations=["benchmark_read_performance"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_benchmark_write_performance"] = Capability(
            name="benchmark_write_performance", category=CapabilityCategory.DIAGNOSTIC,
            description="benchmark_write_performance operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_benchmark_write_performance",
            operations=["benchmark_write_performance"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_replication_status"] = Capability(
            name="check_replication_status", category=CapabilityCategory.DIAGNOSTIC,
            description="check_replication_status operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_check_replication_status",
            operations=["check_replication_status"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_calculate_health_score"] = Capability(
            name="calculate_health_score", category=CapabilityCategory.DIAGNOSTIC,
            description="calculate_health_score operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_calculate_health_score",
            operations=["calculate_health_score"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_summary"] = Capability(
            name="get_summary", category=CapabilityCategory.DIAGNOSTIC,
            description="get_summary operation", module_path="src.diagnostics.database_diagnostics",
            class_name="DatabaseDiagnostics", mcp_tool_name="prom_get_summary",
            operations=["get_summary"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_run_full_diagnostics"] = Capability(
            name="run_full_diagnostics", category=CapabilityCategory.DIAGNOSTIC,
            description="run_full_diagnostics operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_run_full_diagnostics",
            operations=["run_full_diagnostics"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_internet_connectivity"] = Capability(
            name="test_internet_connectivity", category=CapabilityCategory.DIAGNOSTIC,
            description="test_internet_connectivity operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_test_internet_connectivity",
            operations=["test_internet_connectivity"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_dns_connectivity"] = Capability(
            name="test_dns_connectivity", category=CapabilityCategory.DIAGNOSTIC,
            description="test_dns_connectivity operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_test_dns_connectivity",
            operations=["test_dns_connectivity"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_gateway_connectivity"] = Capability(
            name="test_gateway_connectivity", category=CapabilityCategory.DIAGNOSTIC,
            description="test_gateway_connectivity operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_test_gateway_connectivity",
            operations=["test_gateway_connectivity"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_measure_latency"] = Capability(
            name="measure_latency", category=CapabilityCategory.DIAGNOSTIC,
            description="measure_latency operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_measure_latency",
            operations=["measure_latency"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_measure_jitter"] = Capability(
            name="measure_jitter", category=CapabilityCategory.DIAGNOSTIC,
            description="measure_jitter operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_measure_jitter",
            operations=["measure_jitter"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_bandwidth"] = Capability(
            name="test_bandwidth", category=CapabilityCategory.DIAGNOSTIC,
            description="test_bandwidth operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_test_bandwidth",
            operations=["test_bandwidth"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_dns_resolution"] = Capability(
            name="test_dns_resolution", category=CapabilityCategory.DIAGNOSTIC,
            description="test_dns_resolution operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_test_dns_resolution",
            operations=["test_dns_resolution"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_dns_servers"] = Capability(
            name="test_dns_servers", category=CapabilityCategory.DIAGNOSTIC,
            description="test_dns_servers operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_test_dns_servers",
            operations=["test_dns_servers"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_network_interfaces"] = Capability(
            name="check_network_interfaces", category=CapabilityCategory.DIAGNOSTIC,
            description="check_network_interfaces operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_check_network_interfaces",
            operations=["check_network_interfaces"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_test_common_ports"] = Capability(
            name="test_common_ports", category=CapabilityCategory.DIAGNOSTIC,
            description="test_common_ports operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_test_common_ports",
            operations=["test_common_ports"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_trace_routes"] = Capability(
            name="trace_routes", category=CapabilityCategory.DIAGNOSTIC,
            description="trace_routes operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_trace_routes",
            operations=["trace_routes"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_calculate_network_health"] = Capability(
            name="calculate_network_health", category=CapabilityCategory.DIAGNOSTIC,
            description="calculate_network_health operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_calculate_network_health",
            operations=["calculate_network_health"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_summary"] = Capability(
            name="get_summary", category=CapabilityCategory.DIAGNOSTIC,
            description="get_summary operation", module_path="src.diagnostics.network_diagnostics",
            class_name="NetworkDiagnostics", mcp_tool_name="prom_get_summary",
            operations=["get_summary"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_run_full_diagnostics"] = Capability(
            name="run_full_diagnostics", category=CapabilityCategory.DIAGNOSTIC,
            description="run_full_diagnostics operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_run_full_diagnostics",
            operations=["run_full_diagnostics"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_scan_open_ports"] = Capability(
            name="scan_open_ports", category=CapabilityCategory.DIAGNOSTIC,
            description="scan_open_ports operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_scan_open_ports",
            operations=["scan_open_ports"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_weak_passwords"] = Capability(
            name="check_weak_passwords", category=CapabilityCategory.DIAGNOSTIC,
            description="check_weak_passwords operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_weak_passwords",
            operations=["check_weak_passwords"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_scan_outdated_software"] = Capability(
            name="scan_outdated_software", category=CapabilityCategory.DIAGNOSTIC,
            description="scan_outdated_software operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_scan_outdated_software",
            operations=["scan_outdated_software"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_audit_system_configuration"] = Capability(
            name="audit_system_configuration", category=CapabilityCategory.DIAGNOSTIC,
            description="audit_system_configuration operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_audit_system_configuration",
            operations=["audit_system_configuration"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_security_settings"] = Capability(
            name="check_security_settings", category=CapabilityCategory.DIAGNOSTIC,
            description="check_security_settings operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_security_settings",
            operations=["check_security_settings"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_audit_user_accounts"] = Capability(
            name="audit_user_accounts", category=CapabilityCategory.DIAGNOSTIC,
            description="audit_user_accounts operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_audit_user_accounts",
            operations=["audit_user_accounts"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_cis_compliance"] = Capability(
            name="check_cis_compliance", category=CapabilityCategory.DIAGNOSTIC,
            description="check_cis_compliance operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_cis_compliance",
            operations=["check_cis_compliance"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_encryption_compliance"] = Capability(
            name="check_encryption_compliance", category=CapabilityCategory.DIAGNOSTIC,
            description="check_encryption_compliance operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_encryption_compliance",
            operations=["check_encryption_compliance"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_file_permissions"] = Capability(
            name="check_file_permissions", category=CapabilityCategory.DIAGNOSTIC,
            description="check_file_permissions operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_file_permissions",
            operations=["check_file_permissions"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_sudo_permissions"] = Capability(
            name="check_sudo_permissions", category=CapabilityCategory.DIAGNOSTIC,
            description="check_sudo_permissions operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_sudo_permissions",
            operations=["check_sudo_permissions"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_firewall_status"] = Capability(
            name="check_firewall_status", category=CapabilityCategory.DIAGNOSTIC,
            description="check_firewall_status operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_firewall_status",
            operations=["check_firewall_status"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_antivirus_status"] = Capability(
            name="check_antivirus_status", category=CapabilityCategory.DIAGNOSTIC,
            description="check_antivirus_status operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_antivirus_status",
            operations=["check_antivirus_status"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_security_updates"] = Capability(
            name="check_security_updates", category=CapabilityCategory.DIAGNOSTIC,
            description="check_security_updates operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_check_security_updates",
            operations=["check_security_updates"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_calculate_risk_score"] = Capability(
            name="calculate_risk_score", category=CapabilityCategory.DIAGNOSTIC,
            description="calculate_risk_score operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_calculate_risk_score",
            operations=["calculate_risk_score"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_calculate_security_score"] = Capability(
            name="calculate_security_score", category=CapabilityCategory.DIAGNOSTIC,
            description="calculate_security_score operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_calculate_security_score",
            operations=["calculate_security_score"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_get_summary"] = Capability(
            name="get_summary", category=CapabilityCategory.DIAGNOSTIC,
            description="get_summary operation", module_path="src.diagnostics.security_diagnostics",
            class_name="SecurityDiagnostics", mcp_tool_name="prom_get_summary",
            operations=["get_summary"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_run_full_diagnostics"] = Capability(
            name="run_full_diagnostics", category=CapabilityCategory.DIAGNOSTIC,
            description="Check system information", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_run_full_diagnostics",
            operations=["run_full_diagnostics"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_system_info"] = Capability(
            name="check_system_info", category=CapabilityCategory.DIAGNOSTIC,
            description="Check system information", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_system_info",
            operations=["check_system_info"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_cpu"] = Capability(
            name="check_cpu", category=CapabilityCategory.DIAGNOSTIC,
            description="Check CPU metrics", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_cpu",
            operations=["check_cpu"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_memory"] = Capability(
            name="check_memory", category=CapabilityCategory.DIAGNOSTIC,
            description="Check RAM metrics", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_memory",
            operations=["check_memory"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_disk"] = Capability(
            name="check_disk", category=CapabilityCategory.DIAGNOSTIC,
            description="Check disk usage", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_disk",
            operations=["check_disk"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_network"] = Capability(
            name="check_network", category=CapabilityCategory.DIAGNOSTIC,
            description="Check network connectivity", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_network",
            operations=["check_network"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_gpu"] = Capability(
            name="check_gpu", category=CapabilityCategory.DIAGNOSTIC,
            description="Check GPU status", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_gpu",
            operations=["check_gpu"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_python_environment"] = Capability(
            name="check_python_environment", category=CapabilityCategory.DIAGNOSTIC,
            description="Check Python environment", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_python_environment",
            operations=["check_python_environment"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_dependencies"] = Capability(
            name="check_dependencies", category=CapabilityCategory.DIAGNOSTIC,
            description="Check critical dependencies", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_dependencies",
            operations=["check_dependencies"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_api_keys"] = Capability(
            name="check_api_keys", category=CapabilityCategory.DIAGNOSTIC,
            description="Check API key configuration", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_api_keys",
            operations=["check_api_keys"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_file_structure"] = Capability(
            name="check_file_structure", category=CapabilityCategory.DIAGNOSTIC,
            description="Check file structure integrity", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_file_structure",
            operations=["check_file_structure"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_databases"] = Capability(
            name="check_databases", category=CapabilityCategory.DIAGNOSTIC,
            description="Check database connectivity", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_databases",
            operations=["check_databases"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_benchmark_system"] = Capability(
            name="benchmark_system", category=CapabilityCategory.DIAGNOSTIC,
            description="Benchmark system performance", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_benchmark_system",
            operations=["benchmark_system"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_check_security_posture"] = Capability(
            name="check_security_posture", category=CapabilityCategory.DIAGNOSTIC,
            description="Check security posture", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_check_security_posture",
            operations=["check_security_posture"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_calculate_health_score"] = Capability(
            name="calculate_health_score", category=CapabilityCategory.DIAGNOSTIC,
            description="Calculate overall system health score", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_calculate_health_score",
            operations=["calculate_health_score"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_generate_report"] = Capability(
            name="generate_report", category=CapabilityCategory.DIAGNOSTIC,
            description="Export diagnostics results to JSON", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_generate_report",
            operations=["generate_report"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_export_results"] = Capability(
            name="export_results", category=CapabilityCategory.DIAGNOSTIC,
            description="Export diagnostics results to JSON", module_path="src.diagnostics.system_diagnostics",
            class_name="SystemDiagnostics", mcp_tool_name="prom_export_results",
            operations=["export_results"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_file_hash_all"] = Capability(
            name="file_hash_all", category=CapabilityCategory.SPECIALIZED,
            description="file_hash_all operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_file_hash_all",
            operations=["file_hash_all"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_disk_image_create"] = Capability(
            name="disk_image_create", category=CapabilityCategory.SPECIALIZED,
            description="disk_image_create operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_disk_image_create",
            operations=["disk_image_create"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_strings_extract"] = Capability(
            name="strings_extract", category=CapabilityCategory.SPECIALIZED,
            description="strings_extract operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_strings_extract",
            operations=["strings_extract"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_file_carving"] = Capability(
            name="file_carving", category=CapabilityCategory.SPECIALIZED,
            description="file_carving operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_file_carving",
            operations=["file_carving"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_volatility_analyze"] = Capability(
            name="volatility_analyze", category=CapabilityCategory.SPECIALIZED,
            description="volatility_analyze operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_volatility_analyze",
            operations=["volatility_analyze"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_binwalk_analyze"] = Capability(
            name="binwalk_analyze", category=CapabilityCategory.SPECIALIZED,
            description="binwalk_analyze operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_binwalk_analyze",
            operations=["binwalk_analyze"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_exif_extract"] = Capability(
            name="exif_extract", category=CapabilityCategory.SPECIALIZED,
            description="exif_extract operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_exif_extract",
            operations=["exif_extract"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_timeline_create"] = Capability(
            name="timeline_create", category=CapabilityCategory.SPECIALIZED,
            description="timeline_create operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_timeline_create",
            operations=["timeline_create"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_network_pcap_analyze"] = Capability(
            name="network_pcap_analyze", category=CapabilityCategory.SPECIALIZED,
            description="network_pcap_analyze operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_network_pcap_analyze",
            operations=["network_pcap_analyze"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_registry_analyze"] = Capability(
            name="registry_analyze", category=CapabilityCategory.SPECIALIZED,
            description="registry_analyze operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_registry_analyze",
            operations=["registry_analyze"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_evidence_chain_export"] = Capability(
            name="evidence_chain_export", category=CapabilityCategory.SPECIALIZED,
            description="evidence_chain_export operation", module_path="forensics_toolkit",
            class_name="ForensicsToolkit", mcp_tool_name="prom_evidence_chain_export",
            operations=["evidence_chain_export"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_port_scan"] = Capability(
            name="port_scan", category=CapabilityCategory.SPECIALIZED,
            description="Test network security tools", module_path="network_security",
            class_name="NetworkSecurity", mcp_tool_name="prom_port_scan",
            operations=["port_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_service_banner_grab"] = Capability(
            name="service_banner_grab", category=CapabilityCategory.SPECIALIZED,
            description="Test network security tools", module_path="network_security",
            class_name="NetworkSecurity", mcp_tool_name="prom_service_banner_grab",
            operations=["service_banner_grab"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_nmap_scan"] = Capability(
            name="nmap_scan", category=CapabilityCategory.SPECIALIZED,
            description="Test network security tools", module_path="network_security",
            class_name="NetworkSecurity", mcp_tool_name="prom_nmap_scan",
            operations=["nmap_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_subnet_scan"] = Capability(
            name="subnet_scan", category=CapabilityCategory.SPECIALIZED,
            description="Test network security tools", module_path="network_security",
            class_name="NetworkSecurity", mcp_tool_name="prom_subnet_scan",
            operations=["subnet_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_vulnerability_scan"] = Capability(
            name="vulnerability_scan", category=CapabilityCategory.SPECIALIZED,
            description="Test network security tools", module_path="network_security",
            class_name="NetworkSecurity", mcp_tool_name="prom_vulnerability_scan",
            operations=["vulnerability_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_traceroute"] = Capability(
            name="traceroute", category=CapabilityCategory.SPECIALIZED,
            description="Test network security tools", module_path="network_security",
            class_name="NetworkSecurity", mcp_tool_name="prom_traceroute",
            operations=["traceroute"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_security_headers"] = Capability(
            name="security_headers", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_security_headers",
            operations=["security_headers"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_sql_injection_test"] = Capability(
            name="sql_injection_test", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_sql_injection_test",
            operations=["sql_injection_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_xss_test"] = Capability(
            name="xss_test", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_xss_test",
            operations=["xss_test"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_directory_bruteforce"] = Capability(
            name="directory_bruteforce", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_directory_bruteforce",
            operations=["directory_bruteforce"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_subdomain_enum"] = Capability(
            name="subdomain_enum", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_subdomain_enum",
            operations=["subdomain_enum"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_crawl_links"] = Capability(
            name="crawl_links", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_crawl_links",
            operations=["crawl_links"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ssl_scan"] = Capability(
            name="ssl_scan", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_ssl_scan",
            operations=["ssl_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_technology_detection"] = Capability(
            name="technology_detection", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_technology_detection",
            operations=["technology_detection"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_comprehensive_scan"] = Capability(
            name="comprehensive_scan", category=CapabilityCategory.SPECIALIZED,
            description="Test web security tools", module_path="web_security",
            class_name="WebSecurity", mcp_tool_name="prom_comprehensive_scan",
            operations=["comprehensive_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_wifi_scan"] = Capability(
            name="wifi_scan", category=CapabilityCategory.SPECIALIZED,
            description="wifi_scan operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_wifi_scan",
            operations=["wifi_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_monitor_mode_enable"] = Capability(
            name="monitor_mode_enable", category=CapabilityCategory.SPECIALIZED,
            description="monitor_mode_enable operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_monitor_mode_enable",
            operations=["monitor_mode_enable"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_monitor_mode_disable"] = Capability(
            name="monitor_mode_disable", category=CapabilityCategory.SPECIALIZED,
            description="monitor_mode_disable operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_monitor_mode_disable",
            operations=["monitor_mode_disable"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_airodump_capture"] = Capability(
            name="airodump_capture", category=CapabilityCategory.SPECIALIZED,
            description="airodump_capture operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_airodump_capture",
            operations=["airodump_capture"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_deauth_attack"] = Capability(
            name="deauth_attack", category=CapabilityCategory.SPECIALIZED,
            description="deauth_attack operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_deauth_attack",
            operations=["deauth_attack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_wps_scan"] = Capability(
            name="wps_scan", category=CapabilityCategory.SPECIALIZED,
            description="wps_scan operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_wps_scan",
            operations=["wps_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_wps_attack"] = Capability(
            name="wps_attack", category=CapabilityCategory.SPECIALIZED,
            description="wps_attack operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_wps_attack",
            operations=["wps_attack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_aircrack_crack"] = Capability(
            name="aircrack_crack", category=CapabilityCategory.SPECIALIZED,
            description="aircrack_crack operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_aircrack_crack",
            operations=["aircrack_crack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_bluetooth_scan"] = Capability(
            name="bluetooth_scan", category=CapabilityCategory.SPECIALIZED,
            description="bluetooth_scan operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_bluetooth_scan",
            operations=["bluetooth_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_bluetooth_info"] = Capability(
            name="bluetooth_info", category=CapabilityCategory.SPECIALIZED,
            description="bluetooth_info operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_bluetooth_info",
            operations=["bluetooth_info"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_evil_twin_setup"] = Capability(
            name="evil_twin_setup", category=CapabilityCategory.SPECIALIZED,
            description="evil_twin_setup operation", module_path="wireless_security",
            class_name="WirelessSecurityToolkit", mcp_tool_name="prom_evil_twin_setup",
            operations=["evil_twin_setup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_hash_identify"] = Capability(
            name="hash_identify", category=CapabilityCategory.SPECIALIZED,
            description="hash_identify operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_hash_identify",
            operations=["hash_identify"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_hash_generate"] = Capability(
            name="hash_generate", category=CapabilityCategory.SPECIALIZED,
            description="hash_generate operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_hash_generate",
            operations=["hash_generate"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_john_crack"] = Capability(
            name="john_crack", category=CapabilityCategory.SPECIALIZED,
            description="john_crack operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_john_crack",
            operations=["john_crack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_hashcat_crack"] = Capability(
            name="hashcat_crack", category=CapabilityCategory.SPECIALIZED,
            description="hashcat_crack operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_hashcat_crack",
            operations=["hashcat_crack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_brute_force_generate"] = Capability(
            name="brute_force_generate", category=CapabilityCategory.SPECIALIZED,
            description="brute_force_generate operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_brute_force_generate",
            operations=["brute_force_generate"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_password_strength"] = Capability(
            name="password_strength", category=CapabilityCategory.SPECIALIZED,
            description="password_strength operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_password_strength",
            operations=["password_strength"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_rainbow_table_generate"] = Capability(
            name="rainbow_table_generate", category=CapabilityCategory.SPECIALIZED,
            description="rainbow_table_generate operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_rainbow_table_generate",
            operations=["rainbow_table_generate"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_rainbow_table_lookup"] = Capability(
            name="rainbow_table_lookup", category=CapabilityCategory.SPECIALIZED,
            description="rainbow_table_lookup operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_rainbow_table_lookup",
            operations=["rainbow_table_lookup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_hydra_attack"] = Capability(
            name="hydra_attack", category=CapabilityCategory.SPECIALIZED,
            description="hydra_attack operation", module_path="password_cracking",
            class_name="PasswordCrackingToolkit", mcp_tool_name="prom_hydra_attack",
            operations=["hydra_attack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_binary_info"] = Capability(
            name="binary_info", category=CapabilityCategory.SPECIALIZED,
            description="binary_info operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_binary_info",
            operations=["binary_info"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_disassemble"] = Capability(
            name="disassemble", category=CapabilityCategory.SPECIALIZED,
            description="disassemble operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_disassemble",
            operations=["disassemble"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_radare2_analyze"] = Capability(
            name="radare2_analyze", category=CapabilityCategory.SPECIALIZED,
            description="radare2_analyze operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_radare2_analyze",
            operations=["radare2_analyze"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ghidra_decompile"] = Capability(
            name="ghidra_decompile", category=CapabilityCategory.SPECIALIZED,
            description="ghidra_decompile operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_ghidra_decompile",
            operations=["ghidra_decompile"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_ltrace_trace"] = Capability(
            name="ltrace_trace", category=CapabilityCategory.SPECIALIZED,
            description="ltrace_trace operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_ltrace_trace",
            operations=["ltrace_trace"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_strace_trace"] = Capability(
            name="strace_trace", category=CapabilityCategory.SPECIALIZED,
            description="strace_trace operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_strace_trace",
            operations=["strace_trace"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_malware_static_analysis"] = Capability(
            name="malware_static_analysis", category=CapabilityCategory.SPECIALIZED,
            description="malware_static_analysis operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_malware_static_analysis",
            operations=["malware_static_analysis"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_yara_scan"] = Capability(
            name="yara_scan", category=CapabilityCategory.SPECIALIZED,
            description="yara_scan operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_yara_scan",
            operations=["yara_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_peid_detect"] = Capability(
            name="peid_detect", category=CapabilityCategory.SPECIALIZED,
            description="peid_detect operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_peid_detect",
            operations=["peid_detect"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_upx_unpack"] = Capability(
            name="upx_unpack", category=CapabilityCategory.SPECIALIZED,
            description="upx_unpack operation", module_path="reverse_engineering",
            class_name="ReverseEngineeringToolkit", mcp_tool_name="prom_upx_unpack",
            operations=["upx_unpack"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_privilege_escalation_scan"] = Capability(
            name="privilege_escalation_scan", category=CapabilityCategory.SPECIALIZED,
            description="privilege_escalation_scan operation", module_path="post_exploitation",
            class_name="PostExploitationToolkit", mcp_tool_name="prom_privilege_escalation_scan",
            operations=["privilege_escalation_scan"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_persistence_create"] = Capability(
            name="persistence_create", category=CapabilityCategory.SPECIALIZED,
            description="persistence_create operation", module_path="post_exploitation",
            class_name="PostExploitationToolkit", mcp_tool_name="prom_persistence_create",
            operations=["persistence_create"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_credential_dump"] = Capability(
            name="credential_dump", category=CapabilityCategory.SPECIALIZED,
            description="credential_dump operation", module_path="post_exploitation",
            class_name="PostExploitationToolkit", mcp_tool_name="prom_credential_dump",
            operations=["credential_dump"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_lateral_movement"] = Capability(
            name="lateral_movement", category=CapabilityCategory.SPECIALIZED,
            description="lateral_movement operation", module_path="post_exploitation",
            class_name="PostExploitationToolkit", mcp_tool_name="prom_lateral_movement",
            operations=["lateral_movement"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_data_exfiltration"] = Capability(
            name="data_exfiltration", category=CapabilityCategory.SPECIALIZED,
            description="data_exfiltration operation", module_path="post_exploitation",
            class_name="PostExploitationToolkit", mcp_tool_name="prom_data_exfiltration",
            operations=["data_exfiltration"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_api_endpoint_discovery"] = Capability(
            name="api_endpoint_discovery", category=CapabilityCategory.SPECIALIZED,
            description="api_endpoint_discovery operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_api_endpoint_discovery",
            operations=["api_endpoint_discovery"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_api_parameter_fuzzer"] = Capability(
            name="api_parameter_fuzzer", category=CapabilityCategory.SPECIALIZED,
            description="api_parameter_fuzzer operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_api_parameter_fuzzer",
            operations=["api_parameter_fuzzer"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_graphql_introspection"] = Capability(
            name="graphql_introspection", category=CapabilityCategory.SPECIALIZED,
            description="graphql_introspection operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_graphql_introspection",
            operations=["graphql_introspection"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_jwt_token_analyzer"] = Capability(
            name="jwt_token_analyzer", category=CapabilityCategory.SPECIALIZED,
            description="jwt_token_analyzer operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_jwt_token_analyzer",
            operations=["jwt_token_analyzer"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_swagger_openapi_discovery"] = Capability(
            name="swagger_openapi_discovery", category=CapabilityCategory.SPECIALIZED,
            description="swagger_openapi_discovery operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_swagger_openapi_discovery",
            operations=["swagger_openapi_discovery"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_mitmproxy_intercept"] = Capability(
            name="mitmproxy_intercept", category=CapabilityCategory.SPECIALIZED,
            description="mitmproxy_intercept operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_mitmproxy_intercept",
            operations=["mitmproxy_intercept"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_javascript_deobfuscate"] = Capability(
            name="javascript_deobfuscate", category=CapabilityCategory.SPECIALIZED,
            description="javascript_deobfuscate operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_javascript_deobfuscate",
            operations=["javascript_deobfuscate"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_websocket_interceptor"] = Capability(
            name="websocket_interceptor", category=CapabilityCategory.SPECIALIZED,
            description="websocket_interceptor operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_websocket_interceptor",
            operations=["websocket_interceptor"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_api_rate_limit_detector"] = Capability(
            name="api_rate_limit_detector", category=CapabilityCategory.SPECIALIZED,
            description="api_rate_limit_detector operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_api_rate_limit_detector",
            operations=["api_rate_limit_detector"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_api_authentication_analyzer"] = Capability(
            name="api_authentication_analyzer", category=CapabilityCategory.SPECIALIZED,
            description="api_authentication_analyzer operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_api_authentication_analyzer",
            operations=["api_authentication_analyzer"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_api_response_differ"] = Capability(
            name="api_response_differ", category=CapabilityCategory.SPECIALIZED,
            description="api_response_differ operation", module_path="api_reverse_engineering",
            class_name="WebAPIReverseEngineering", mcp_tool_name="prom_api_response_differ",
            operations=["api_response_differ"], expertise_level=ExpertiseLevel.EXPERT)

        # === ADDITIONAL SYSTEMS (26 operations) ===
        # Autonomous System (2)
        self._capabilities["prom_autonomous_stop"] = Capability(
            name="stop_autonomous_loop", category=CapabilityCategory.SPECIALIZED,
            description="Stop autonomous loop", module_path="src.autonomous.prometheus_autonomous",
            class_name="PrometheusAutonomous", mcp_tool_name="prom_autonomous_stop",
            operations=["stop_autonomous_loop"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_autonomous_stats"] = Capability(
            name="get_stats", category=CapabilityCategory.SPECIALIZED,
            description="Get autonomous loop statistics", module_path="src.autonomous.prometheus_autonomous",
            class_name="PrometheusAutonomous", mcp_tool_name="prom_autonomous_stats",
            operations=["get_stats"], expertise_level=ExpertiseLevel.EXPERT)
        # Voice System (1)
        self._capabilities["prom_voice_status"] = Capability(
            name="get_status", category=CapabilityCategory.SPECIALIZED,
            description="Get voice system status", module_path="src.voice.prometheus_voice",
            class_name="PrometheusVoice", mcp_tool_name="prom_voice_status",
            operations=["get_status"], expertise_level=ExpertiseLevel.EXPERT)
        # Memory System (1)
        self._capabilities["prom_memory_stats"] = Capability(
            name="get_memory_stats", category=CapabilityCategory.SPECIALIZED,
            description="Get crystal memory statistics", module_path="src.memory.crystal_prometheus",
            class_name="PrometheusMemory", mcp_tool_name="prom_memory_stats",
            operations=["get_memory_stats"], expertise_level=ExpertiseLevel.EXPERT)
        # === ULTIMATE CAPABILITIES (13) ===
        # Network (4)
        self._capabilities["prom_bgp_hijacking_ultimate"] = Capability(
            name="bgp_maximum_hijacking", category=CapabilityCategory.ULTIMATE,
            description="Ultimate BGP hijacking", module_path="ULTIMATE_CAPABILITIES.network_exploitation_ultimate",
            class_name="NetworkPlatform", mcp_tool_name="prom_bgp_hijacking_ultimate",
            operations=["bgp_maximum_hijacking"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_ospf_manipulation_ultimate"] = Capability(
            name="ospf_ultimate_protocol_manipulation", category=CapabilityCategory.ULTIMATE,
            description="Ultimate OSPF manipulation", module_path="ULTIMATE_CAPABILITIES.network_exploitation_ultimate",
            class_name="NetworkPlatform", mcp_tool_name="prom_ospf_manipulation_ultimate",
            operations=["ospf_ultimate_protocol_manipulation"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_eigrp_attack_ultimate"] = Capability(
            name="eigrp_advanced_protocol_attack", category=CapabilityCategory.ULTIMATE,
            description="Ultimate EIGRP attack", module_path="ULTIMATE_CAPABILITIES.network_exploitation_ultimate",
            class_name="NetworkPlatform", mcp_tool_name="prom_eigrp_attack_ultimate",
            operations=["eigrp_advanced_protocol_attack"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_dns_corruption_ultimate"] = Capability(
            name="dns_advanced_corruption", category=CapabilityCategory.ULTIMATE,
            description="Ultimate DNS corruption", module_path="ULTIMATE_CAPABILITIES.network_exploitation_ultimate",
            class_name="NetworkPlatform", mcp_tool_name="prom_dns_corruption_ultimate",
            operations=["dns_advanced_corruption"], expertise_level=ExpertiseLevel.GRANDMASTER)
        # Biometric (4)
        self._capabilities["prom_fingerprint_bypass_ultimate"] = Capability(
            name="fingerprint_ultimate_bypass", category=CapabilityCategory.ULTIMATE,
            description="Ultimate fingerprint bypass", module_path="ULTIMATE_CAPABILITIES.biometric_bypass_ultimate",
            class_name="MaximumThreatLevel", mcp_tool_name="prom_fingerprint_bypass_ultimate",
            operations=["fingerprint_ultimate_bypass"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_face_recognition_defeat_ultimate"] = Capability(
            name="face_recognition_elite_defeat", category=CapabilityCategory.ULTIMATE,
            description="Ultimate face recognition defeat", module_path="ULTIMATE_CAPABILITIES.biometric_bypass_ultimate",
            class_name="MaximumThreatLevel", mcp_tool_name="prom_face_recognition_defeat_ultimate",
            operations=["face_recognition_elite_defeat"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_iris_scanner_defeat_ultimate"] = Capability(
            name="iris_scanner_national_defeat", category=CapabilityCategory.ULTIMATE,
            description="Ultimate iris scanner defeat", module_path="ULTIMATE_CAPABILITIES.biometric_bypass_ultimate",
            class_name="MaximumThreatLevel", mcp_tool_name="prom_iris_scanner_defeat_ultimate",
            operations=["iris_scanner_national_defeat"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_voice_cloning_ultimate"] = Capability(
            name="voice_cloning_maximum", category=CapabilityCategory.ULTIMATE,
            description="Ultimate voice cloning", module_path="ULTIMATE_CAPABILITIES.biometric_bypass_ultimate",
            class_name="MaximumThreatLevel", mcp_tool_name="prom_voice_cloning_ultimate",
            operations=["voice_cloning_maximum"], expertise_level=ExpertiseLevel.GRANDMASTER)
        # Cloud (5)
        self._capabilities["prom_aws_privilege_escalation_ultimate"] = Capability(
            name="aws_maximum_privilege_escalation", category=CapabilityCategory.ULTIMATE,
            description="Ultimate AWS privilege escalation", module_path="ULTIMATE_CAPABILITIES.cloud_exploits_ultimate",
            class_name="CloudPlatform", mcp_tool_name="prom_aws_privilege_escalation_ultimate",
            operations=["aws_maximum_privilege_escalation"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_azure_ad_attack_ultimate"] = Capability(
            name="azure_ultimate_active_directory_attack", category=CapabilityCategory.ULTIMATE,
            description="Ultimate Azure AD attack", module_path="ULTIMATE_CAPABILITIES.cloud_exploits_ultimate",
            class_name="CloudPlatform", mcp_tool_name="prom_azure_ad_attack_ultimate",
            operations=["azure_ultimate_active_directory_attack"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_gcp_privilege_escalation_ultimate"] = Capability(
            name="gcp_maximum_privilege_escalation", category=CapabilityCategory.ULTIMATE,
            description="Ultimate GCP privilege escalation", module_path="ULTIMATE_CAPABILITIES.cloud_exploits_ultimate",
            class_name="CloudPlatform", mcp_tool_name="prom_gcp_privilege_escalation_ultimate",
            operations=["gcp_maximum_privilege_escalation"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_kubernetes_compromise_ultimate"] = Capability(
            name="kubernetes_ultimate_compromise", category=CapabilityCategory.ULTIMATE,
            description="Ultimate Kubernetes compromise", module_path="ULTIMATE_CAPABILITIES.cloud_exploits_ultimate",
            class_name="CloudPlatform", mcp_tool_name="prom_kubernetes_compromise_ultimate",
            operations=["kubernetes_ultimate_compromise"], expertise_level=ExpertiseLevel.GRANDMASTER)
        self._capabilities["prom_serverless_exploitation_ultimate"] = Capability(
            name="serverless_ultimate_exploitation", category=CapabilityCategory.ULTIMATE,
            description="Ultimate serverless exploitation", module_path="ULTIMATE_CAPABILITIES.cloud_exploits_ultimate",
            class_name="CloudPlatform", mcp_tool_name="prom_serverless_exploitation_ultimate",
            operations=["serverless_ultimate_exploitation"], expertise_level=ExpertiseLevel.GRANDMASTER)
        # === INTELLIGENCE MODULES (9) ===
        # Phone (4)
        self._capabilities["prom_phone_lookup"] = Capability(
            name="lookup", category=CapabilityCategory.SPECIALIZED,
            description="Lookup phone number", module_path="phone_intelligence",
            class_name="PhoneIntelligence", mcp_tool_name="prom_phone_lookup",
            operations=["lookup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_phone_bulk_lookup"] = Capability(
            name="bulk_lookup", category=CapabilityCategory.SPECIALIZED,
            description="Bulk phone lookup", module_path="phone_intelligence",
            class_name="PhoneIntelligence", mcp_tool_name="prom_phone_bulk_lookup",
            operations=["bulk_lookup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_phone_cache_stats"] = Capability(
            name="get_cache_stats", category=CapabilityCategory.SPECIALIZED,
            description="Phone cache stats", module_path="phone_intelligence",
            class_name="PhoneIntelligence", mcp_tool_name="prom_phone_cache_stats",
            operations=["get_cache_stats"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_phone_clear_cache"] = Capability(
            name="clear_expired_cache", category=CapabilityCategory.SPECIALIZED,
            description="Clear phone cache", module_path="phone_intelligence",
            class_name="PhoneIntelligence", mcp_tool_name="prom_phone_clear_cache",
            operations=["clear_expired_cache"], expertise_level=ExpertiseLevel.EXPERT)
        # Email (3)
        self._capabilities["prom_email_analyze"] = Capability(
            name="analyze", category=CapabilityCategory.SPECIALIZED,
            description="Analyze email", module_path="email_intelligence",
            class_name="EmailIntelligence", mcp_tool_name="prom_email_analyze",
            operations=["analyze"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_email_batch_analyze"] = Capability(
            name="batch_analyze", category=CapabilityCategory.SPECIALIZED,
            description="Batch email analysis", module_path="email_intelligence",
            class_name="EmailIntelligence", mcp_tool_name="prom_email_batch_analyze",
            operations=["batch_analyze"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_email_breach_check"] = Capability(
            name="check_password_breach", category=CapabilityCategory.SPECIALIZED,
            description="Check email breach", module_path="email_intelligence",
            class_name="EmailIntelligence", mcp_tool_name="prom_email_breach_check",
            operations=["check_password_breach"], expertise_level=ExpertiseLevel.EXPERT)
        # Domain (2)
        self._capabilities["prom_domain_lookup"] = Capability(
            name="lookup", category=CapabilityCategory.SPECIALIZED,
            description="Domain lookup", module_path="domain_intelligence",
            class_name="DomainIntelligence", mcp_tool_name="prom_domain_lookup",
            operations=["lookup"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_domain_batch_lookup"] = Capability(
            name="batch_lookup", category=CapabilityCategory.SPECIALIZED,
            description="Batch domain lookup", module_path="domain_intelligence",
            class_name="DomainIntelligence", mcp_tool_name="prom_domain_batch_lookup",
            operations=["batch_lookup"], expertise_level=ExpertiseLevel.EXPERT)

        # === PAYLOAD GENERATION (2) ===
        self._capabilities["prom_payload_generate"] = Capability(
            name="generate", category=CapabilityCategory.BASIC_TOOL,
            description="Generate offensive payloads (reverse/bind shells, meterpreter)", module_path="tools.payloads",
            class_name="PayloadGenerator", mcp_tool_name="prom_payload_generate",
            operations=["generate"], expertise_level=ExpertiseLevel.EXPERT)
        self._capabilities["prom_payload_format"] = Capability(
            name="format_payload", category=CapabilityCategory.BASIC_TOOL,
            description="Format and encode payload for delivery", module_path="tools.payloads",
            class_name="PayloadGenerator", mcp_tool_name="prom_payload_format",
            operations=["format_payload"], expertise_level=ExpertiseLevel.EXPERT)

    def get_all_capabilities(self):
        return list(self._capabilities.values())

    def get_capability(self, name):
        return self._capabilities.get(name)

    def get_mcp_tools(self):
        return [{"name": c.mcp_tool_name, "description": c.description} for c in self._capabilities.values()]

    def get_statistics(self):
        by_cat = {}
        for c in self._capabilities.values():
            by_cat[c.category.value] = by_cat.get(c.category.value, 0) + 1
        return {"total": len(self._capabilities), "by_category": by_cat}

_registry = None

def get_registry():
    global _registry
    if _registry is None:
        _registry = PrometheusCapabilityRegistry()
    return _registry
