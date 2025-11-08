"""
PROMETHEUS-PRIME EXTENDED AGENT CLI
Full capability access with scope-gating and voice integration
Authority Level: 9.9
Voice ID: BVZ5M1JnNXres6AkVgxe

All 30+ capabilities accessible via CLI
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from config_loader import load_config, load_scope, dump_effective_config
from logging_setup import setup_logging
from scope_gate import is_target_allowed, enforce_scope, ScopeViolation
from reporting_engine import write_report

# Import all capability modules
from capabilities.recon_nmap import run_nmap_scan
from capabilities.password_attacks import run_hashcat_attack
from capabilities.lateral_movement import run_psexec, run_wmiexec

# Red Team modules
from capabilities import (
    red_team_ad_attacks,
    red_team_c2,
    red_team_core,
    red_team_evasion,
    red_team_exfil,
    red_team_exploits,
    red_team_lateral_movement,
    red_team_metasploit,
    red_team_mimikatz,
    red_team_obfuscation,
    red_team_password_attacks,
    red_team_persistence,
    red_team_phishing,
    red_team_post_exploit,
    red_team_privesc,
    red_team_recon,
    red_team_reporting,
    red_team_vuln_scan,
    red_team_web_exploits,
    web_exploits,
    mobile_exploits,
    cloud_exploits,
    biometric_bypass,
    sigint_core
)


def _parse_targets_csv(value: str) -> List[str]:
    targets = [t.strip() for t in value.split(",") if t.strip()]
    if not targets:
        raise argparse.ArgumentTypeError("At least one target is required")
    return targets


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--config",
        default="configs/default.yaml",
        help="Path to configuration YAML (default: configs/default.yaml)",
    )
