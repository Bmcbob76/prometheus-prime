"""
Operational Password Attacks (Lab-only, scope-gated policy)
- Wrapper around hashcat for offline password cracking of lab-collected hashes
- Respects feature flag: features.enable_password_attacks
- No network operations are performed by this module
- Writes summaries and optional reports

Usage (programmatic):
    from prometheus_prime.config_loader import load_config, load_scope
    from prometheus_prime.capabilities.password_attacks import run_hashcat_attack

    cfg = load_config()
    scope = load_scope(cfg)  # not directly used here (offline), but kept for policy consistency
    result = run_hashcat_attack(
        cfg=cfg,
        hash_file="C:/lab/hashes.ntlm",
        wordlist="C:/lab/wordlists/rockyou.txt",
        mode=1000,  # NTLM
        extra_args=["--username"]
    )

Outputs:
- sessions/hashcat/potfile.txt (default potfile)
- reports/passwords/&lt;timestamp&gt;_crack_report.md (if reporting enabled)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from reporting_engine import write_report

log = logging.getLogger("PROMETHEUS-PRIME.PasswordAttacks")


def _resolve_hashcat_path(cfg: Dict[str, Any]) -> str:
    configured = (cfg.get("tools", {}) or {}).get("hashcat_path") or ""
    if configured:
        return configured
    hc = shutil.which("hashcat")
    if not hc:
        raise FileNotFoundError(
            "hashcat not found on PATH and tools.hashcat_path not configured. "
            "Install hashcat or set tools.hashcat_path in configs/default.yaml."
        )
    return hc


def _sessions_dir(cfg: Dict[str, Any], subfolder: str = "hashcat") -> Path:
    base = (cfg.get("paths", {}) or {}).get("sessions_dir", "sessions")
    p = Path(__file__).resolve().parents[1].joinpath(base).joinpath(subfolder).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _reports_dir(cfg: Dict[str, Any], subfolder: str = "passwords") -> Path:
    base = (cfg.get("paths", {}) or {}).get("reports_dir", "reports")
    p = Path(__file__).resolve().parents[1].joinpath(base).joinpath(subfolder).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def _parse_potfile(potfile: Path) -> List[Dict[str, str]]:
    """
    Parse hashcat potfile entries (format: hash:plain or with user prefix when --username used)
    Returns: [{'hash': '...', 'password': '...', 'user': 'optional'}]
    """
    results: List[Dict[str, str]] = []
    if not potfile.exists():
        return results
    for line in potfile.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        # Handle possible username:hash:pass formats (depends on mode/args)
        parts = line.split(":")
        if len(parts) >= 3 and "@" in parts[0]:
            # Heuristic: user:hash:pass
            user = parts[0]
            h = parts[1]
            pw = ":".join(parts[2:])
            results.append({"user": user, "hash": h, "password": pw})
        else:
            # hash:password
            h = parts[0]
            pw = ":".join(parts[1:])
            results.append({"hash": h, "password": pw})
    return results


def run_hashcat_attack(
    cfg: Dict[str, Any],
    hash_file: str,
    wordlist: str,
    mode: int,
    extra_args: Optional[List[str]] = None,
    session_name: Optional[str] = None,
    write_markdown_report: bool = True,
) -> Dict[str, Any]:
    """
    Run an offline hashcat attack against a supplied hash file using a wordlist.

    Args:
      cfg: loaded configuration dict
      hash_file: path to hash file (NTLM, LM, bcrypt, etc. depending on mode)
      wordlist: path to wordlist file
      mode: hashcat -m mode (e.g., 0 MD5, 100 NTLM, 1800 sha512crypt, 1000 NTLM)
      extra_args: list of additional hashcat arguments (e.g., ["--username", "--force"])
      session_name: optional session name for hashcat
      write_markdown_report: if True, generate a markdown report

    Returns:
      {
        "command": [...],
        "returncode": int,
        "stdout": "...",
        "stderr": "...",
        "potfile": "path",
        "cracked": [{"hash": "...", "password": "...", "user": "optional"}, ...],
        "report_markdown": "path or None"
      }
    """
    features = cfg.get("features", {}) or {}
    if not features.get("enable_password_attacks"):
        raise PermissionError("Password attacks feature is disabled in config.features.")

    hc_bin = _resolve_hashcat_path(cfg)
    hash_path = Path(hash_file).resolve()
    wordlist_path = Path(wordlist).resolve()

    if not hash_path.exists():
        raise FileNotFoundError(f"Hash file not found: {hash_path}")
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")

    sess_dir = _sessions_dir(cfg)
    potfile = sess_dir.joinpath("potfile.txt").resolve()
    potfile.touch(exist_ok=True)

    cmd = [
        hc_bin,
        "-m",
        str(mode),
        str(hash_path),
        str(wordlist_path),
        "--potfile-path",
        str(potfile),
        "--status",
        "--status-timer",
        "10",
        "--outfile-autohex-disable",
    ]
    if session_name:
        cmd += ["--session", session_name]
    if extra_args:
        cmd += list(extra_args)

    log.info("Executing hashcat: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1, 2, 255):
        # 0 OK, 1 error, 2 aborted, 255 build problem; we still collect outputs
        log.warning("hashcat unexpected exit code: %s", proc.returncode)

    cracked = _parse_potfile(potfile)

    report_path = None
    if write_markdown_report:
        reports_dir = _reports_dir(cfg)
        title = f"Password Attack - mode {mode}"
        summary = {
            "operation": title,
            "targets": [str(hash_path)],
            "findings": {
                "cracked_count": len(cracked),
                "cracked_samples": cracked[:10],  # prevent huge dumps
            },
            "notes": [
                f"Wordlist: {wordlist_path}",
                f"Potfile: {potfile}",
                f"ExitCode: {proc.returncode}",
            ],
        }
        report_path = write_report(
            reports_dir=str(reports_dir),
            title=title,
            summary=summary,
            format=(cfg.get("reporting", {}) or {}).get("default_format", "markdown"),
        )

    result = {
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "potfile": str(potfile),
        "cracked": cracked,
        "report_markdown": str(report_path) if report_path else None,
    }
    log.info("Password attack complete: cracked=%d report=%s", len(cracked), report_path)
    return result


__all__ = ["run_hashcat_attack"]
