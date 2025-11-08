"""
PROMETHEUS-PRIME Agent CLI (Lab-only, scope-gated)

Commands:
  - config show                      Show effective configuration
  - scope check --target ...         Check if a target is in lab scope
  - recon nmap --targets ...         Run Nmap recon/vuln-scan against in-scope targets

Usage examples:
  python prometheus_prime_agent.py config show
  python prometheus_prime_agent.py scope check --target 10.0.0.5
  python prometheus_prime_agent.py recon nmap --targets 10.0.0.5,dc01.lab.local --top-ports 1000

Notes:
- All operational actions are blocked if targets are out of scope (see configs/example_scope.yaml).
- Feature flags in configs/default.yaml must enable the relevant capability.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

# Ensure local package imports work when running this script directly
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from config_loader import load_config, load_scope, dump_effective_config
from logging_setup import setup_logging
from scope_gate import is_target_allowed, enforce_scope, ScopeViolation
from reporting_engine import write_report

# Capabilities
from capabilities.recon_nmap import run_nmap_scan
from capabilities.password_attacks import run_hashcat_attack
from capabilities.lateral_movement import run_psexec, run_wmiexec


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


def cmd_config_show(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    setup_logging(cfg)
    print(dump_effective_config(cfg))
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    logger = setup_logging(cfg)
    scope = load_scope(cfg)

    allowed, reasons = is_target_allowed(scope, args.target, port=args.port, protocol=args.protocol)
    banner = scope.get("policy", {}).get("banner", "")
    if banner:
        logger.info(banner)

    if allowed:
        logger.info("Target is IN SCOPE: %s (protocol=%s port=%s)", args.target, args.protocol, args.port)
        for r in reasons:
            logger.info("Reason: %s", r)
        return 0
    else:
        logger.error("Target is OUT OF SCOPE: %s (protocol=%s port=%s)", args.target, args.protocol, args.port)
        for r in reasons:
            logger.error("Reason: %s", r)
        return 2


def cmd_recon_nmap(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    logger = setup_logging(cfg)
    scope = load_scope(cfg)

    targets = _parse_targets_csv(args.targets)

    try:
        result = run_nmap_scan(
            cfg=cfg,
            scope_doc=scope,
            targets=targets,
            top_ports=args.top_ports,
            extra_args=args.extra_arg or None,
            report_title=args.title or "Nmap Recon Scan",
        )
    except ScopeViolation as sv:
        logger.error("Scope violation: %s", sv)
        return 3
    except FileNotFoundError as fnf:
        logger.error("%s", fnf)
        return 4
    except PermissionError as pe:
        logger.error("%s", pe)
        return 5
    except Exception as e:
        logger.exception("Recon failed: %s", e)
        return 6

    logger.info("Completed. Markdown: %s | JSON: %s", result.get("markdown"), result.get("json"))
    return 0


def cmd_password_crack(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    logger = setup_logging(cfg)
    scope = load_scope(cfg)  # offline module; still show banner
    banner = scope.get("policy", {}).get("banner", "")
    if banner:
        logger.info(banner)

    try:
        result = run_hashcat_attack(
            cfg=cfg,
            hash_file=args.hash_file,
            wordlist=args.wordlist,
            mode=args.mode,
            extra_args=args.extra_arg or None,
            session_name=args.session or None,
            write_markdown_report=True,
        )
    except FileNotFoundError as fnf:
        logger.error("%s", fnf)
        return 4
    except PermissionError as pe:
        logger.error("%s", pe)
        return 5
    except Exception as e:
        logger.exception("Password crack failed: %s", e)
        return 6

    logger.info(
        "Completed. Cracked=%d Potfile=%s Report=%s",
        len(result.get("cracked", [])),
        result.get("potfile"),
        result.get("report_markdown"),
    )
    return 0

def cmd_lm_psexec(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    logger = setup_logging(cfg)
    scope = load_scope(cfg)
    banner = scope.get("policy", {}).get("banner", "")
    if banner:
        logger.info(banner)

    try:
        result = run_psexec(
            cfg=cfg,
            scope_doc=scope,
            target=args.target,
            username=args.username,
            password=args.password,
            hash_nt=args.hash_nt,
            command=args.command,
            share=args.share,
            port=args.port,
            options=args.option or None,
        )
    except ScopeViolation as sv:
        logger.error("Scope violation: %s", sv)
        return 3
    except FileNotFoundError as fnf:
        logger.error("%s", fnf)
        return 4
    except PermissionError as pe:
        logger.error("%s", pe)
        return 5
    except Exception as e:
        logger.exception("Lateral movement (psexec) failed: %s", e)
        return 6

    logger.info("LM psexec complete. ReturnCode=%s Report=%s", result.get("returncode"), result.get("report"))
    return 0


def cmd_lm_wmiexec(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    logger = setup_logging(cfg)
    scope = load_scope(cfg)
    banner = scope.get("policy", {}).get("banner", "")
    if banner:
        logger.info(banner)

    try:
        result = run_wmiexec(
            cfg=cfg,
            scope_doc=scope,
            target=args.target,
            username=args.username,
            password=args.password,
            hash_nt=args.hash_nt,
            command=args.command,
            share=args.share,
            options=args.option or None,
        )
    except ScopeViolation as sv:
        logger.error("Scope violation: %s", sv)
        return 3
    except FileNotFoundError as fnf:
        logger.error("%s", fnf)
        return 4
    except PermissionError as pe:
        logger.error("%s", pe)
        return 5
    except Exception as e:
        logger.exception("Lateral movement (wmiexec) failed: %s", e)
        return 6

    logger.info("LM wmiexec complete. ReturnCode=%s Report=%s", result.get("returncode"), result.get("report"))
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prometheus_prime_agent",
        description="PROMETHEUS-PRIME Agent CLI (Lab-only, scope-gated)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # config show
    p_cfg = sub.add_parser("config", help="Configuration commands")
    sub_cfg = p_cfg.add_subparsers(dest="cfg_cmd", required=True)
    p_cfg_show = sub_cfg.add_parser("show", help="Show effective configuration (JSON)")
    _add_common_args(p_cfg_show)
    p_cfg_show.set_defaults(func=cmd_config_show)

    # scope check
    p_scope = sub.add_parser("scope", help="Scope validation commands")
    sub_scope = p_scope.add_subparsers(dest="scope_cmd", required=True)
    p_scope_check = sub_scope.add_parser("check", help="Check if a target is in scope")
    _add_common_args(p_scope_check)
    p_scope_check.add_argument("--target", required=True, help="Target (IP or FQDN)")
    p_scope_check.add_argument("--protocol", choices=["tcp", "udp"], default=None, help="Protocol")
    p_scope_check.add_argument("--port", type=int, default=None, help="Port number")
    p_scope_check.set_defaults(func=cmd_scope_check)

    # recon nmap
    p_recon = sub.add_parser("recon", help="Reconnaissance operations")
    sub_recon = p_recon.add_subparsers(dest="recon_cmd", required=True)

    p_recon_nmap = sub_recon.add_parser("nmap", help="Run Nmap recon/vuln-scan")
    _add_common_args(p_recon_nmap)
    p_recon_nmap.add_argument(
        "--targets",
        required=True,
        help="Comma-separated targets (IPs/FQDNs), e.g., 10.0.0.5,dc01.lab.local",
    )
    p_recon_nmap.add_argument(
        "--top-ports",
        type=int,
        default=None,
        help="Limit to top N ports (overrides default config if provided)",
    )
    p_recon_nmap.add_argument(
        "--extra-arg",
        action="append",
        help="Pass-through extra nmap args (can repeat). Example: --extra-arg -Pn --extra-arg --open",
    )
    p_recon_nmap.add_argument(
        "--title",
        default=None,
        help="Report title override",
    )
    p_recon_nmap.set_defaults(func=cmd_recon_nmap)

    # password crack
    p_pwd = sub.add_parser("password", help="Password attack operations")
    sub_pwd = p_pwd.add_subparsers(dest="password_cmd", required=True)

    p_pwd_crack = sub_pwd.add_parser("crack", help="Run hashcat offline cracking")
    _add_common_args(p_pwd_crack)
    p_pwd_crack.add_argument("--hash-file", required=True, help="Path to hash file (e.g., NTLM hashes)")
    p_pwd_crack.add_argument("--wordlist", required=True, help="Path to wordlist file")
    p_pwd_crack.add_argument("--mode", required=True, type=int, help="hashcat -m mode (e.g., 1000 for NTLM)")
    p_pwd_crack.add_argument("--extra-arg", action="append", help="Pass-through extra hashcat args (repeatable)")
    p_pwd_crack.add_argument("--session", default=None, help="Optional hashcat session name")
    p_pwd_crack.set_defaults(func=cmd_password_crack)

    # lateral movement
    p_lm = sub.add_parser("lm", help="Lateral movement operations")
    sub_lm = p_lm.add_subparsers(dest="lm_cmd", required=True)

    # lm psexec
    p_lm_psexec = sub_lm.add_parser("psexec", help="Impacket psexec - remote command via SMB service")
    _add_common_args(p_lm_psexec)
    p_lm_psexec.add_argument("--target", required=True, help="Target host (IP or FQDN)")
    p_lm_psexec.add_argument("--username", required=True, help="Username (DOMAIN\\user or user)")
    p_lm_psexec.add_argument("--password", default=None, help="Password (optional if --hash-nt provided)")
    p_lm_psexec.add_argument("--hash-nt", dest="hash_nt", default=None, help="NT hash (prefix ':' accepted)")
    p_lm_psexec.add_argument("--command", default="cmd.exe", help="Command to execute (default: cmd.exe)")
    p_lm_psexec.add_argument("--share", default="ADMIN$", help="Remote share (default: ADMIN$)")
    p_lm_psexec.add_argument("--port", type=int, default=445, help="SMB port (default: 445)")
    p_lm_psexec.add_argument("--option", action="append", help="Extra psexec args (repeatable)")
    p_lm_psexec.set_defaults(func=cmd_lm_psexec)

    # lm wmiexec
    p_lm_wmiexec = sub_lm.add_parser("wmiexec", help="Impacket wmiexec - remote command via WMI")
    _add_common_args(p_lm_wmiexec)
    p_lm_wmiexec.add_argument("--target", required=True, help="Target host (IP or FQDN)")
    p_lm_wmiexec.add_argument("--username", required=True, help="Username (DOMAIN\\user or user)")
    p_lm_wmiexec.add_argument("--password", default=None, help="Password (optional if --hash-nt provided)")
    p_lm_wmiexec.add_argument("--hash-nt", dest="hash_nt", default=None, help="NT hash (prefix ':' accepted)")
    p_lm_wmiexec.add_argument("--command", default="whoami", help="Command to execute (default: whoami)")
    p_lm_wmiexec.add_argument("--share", default=None, help="Optional share (e.g., ADMIN$)")
    p_lm_wmiexec.add_argument("--option", action="append", help="Extra wmiexec args (repeatable)")
    p_lm_wmiexec.set_defaults(func=cmd_lm_wmiexec)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
