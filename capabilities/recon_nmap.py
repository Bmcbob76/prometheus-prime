"""
Operational Nmap Recon (Lab-only, scope-gated)

- Uses system nmap (must be installed and on PATH or configured in tools.nmap_path)
- Enforces lab scope per target before execution
- Respects feature flags (features.enable_recon and features.enable_vuln_scan)
- Produces machine-readable JSON summary and human-readable Markdown report

Usage (programmatic):
    from prometheus_prime.config_loader import load_config, load_scope
    from prometheus_prime.capabilities.recon_nmap import run_nmap_scan

    cfg = load_config()
    scope = load_scope(cfg)
    results = run_nmap_scan(cfg, scope, targets=["10.0.0.5"], top_ports=1000)

Outputs:
- reports/nmap/&lt;timestamp&gt;_scan.md
- reports/nmap/&lt;timestamp&gt;_scan.json
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from scope_gate import enforce_scope, ScopeViolation
from reporting_engine import write_report


log = logging.getLogger("PROMETHEUS-PRIME.NmapRecon")


def _resolve_nmap_path(cfg: Dict[str, Any]) -> str:
    configured = (cfg.get("tools", {}) or {}).get("nmap_path") or ""
    if configured:
        return configured
    nmap = shutil.which("nmap")
    if not nmap:
        raise FileNotFoundError(
            "nmap not found on PATH and tools.nmap_path is not configured. "
            "Install Nmap or set tools.nmap_path in configs/default.yaml."
        )
    return nmap


def _reports_dir(cfg: Dict[str, Any], subfolder: str = "nmap") -> Path:
    base = (cfg.get("paths", {}) or {}).get("reports_dir", "reports")
    p = Path(__file__).resolve().parents[1].joinpath(base).joinpath(subfolder).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _build_nmap_args(
    cfg: Dict[str, Any],
    targets: List[str],
    top_ports: Optional[int] = None,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    recon_cfg = (cfg.get("recon", {}) or {}).get("nmap", {}) or {}
    default_args: List[str] = recon_cfg.get("default_args", ["-sS", "-sV", "-T4"])
    args: List[str] = list(default_args)
    if top_ports:
        args += ["--top-ports", str(top_ports)]
    host_timeout = recon_cfg.get("host_timeout")
    if host_timeout:
        args += ["--host-timeout", str(host_timeout)]
    max_retries = recon_cfg.get("max_retries")
    if isinstance(max_retries, int):
        args += ["--max-retries", str(max_retries)]
    if extra_args:
        args += list(extra_args)
    # Append targets last
    args += targets
    return args


def _parse_nmap_xml(xml_path: Path) -> Dict[str, Any]:
    """
    Parse minimal data from nmap XML into a structured summary:
    hosts: [
      {
        'address': '10.0.0.5',
        'hostname': 'host.example',
        'status': 'up',
        'ports': [
          {'portid': 22, 'proto': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2'}
        ]
      }
    ]
    """
    summary: Dict[str, Any] = {"hosts": []}
    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        address = addr_el.get("addr") if addr_el is not None else None

        hostname = None
        hnames = host.find("hostnames")
        if hnames is not None:
            h = hnames.find("hostname")
            if h is not None:
                hostname = h.get("name")

        ports_list: List[Dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                proto = p.get("protocol")
                portid = int(p.get("portid", "0"))
                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                service_el = p.find("service")
                service = service_el.get("name") if service_el is not None else None
                version = None
                if service_el is not None:
                    product = service_el.get("product") or ""
                    ver = service_el.get("version") or ""
                    extrainfo = service_el.get("extrainfo") or ""
                    version = " ".join(x for x in [product, ver, extrainfo] if x).strip() or None
                ports_list.append(
                    {
                        "portid": portid,
                        "proto": proto,
                        "state": state,
                        "service": service,
                        "version": version,
                    }
                )

        host_entry = {
            "address": address,
            "hostname": hostname,
            "status": status,
            "ports": ports_list,
        }
        summary["hosts"].append(host_entry)

    return summary


def _write_json_report(path: Path, data: Dict[str, Any]) -> Path:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def run_nmap_scan(
    cfg: Dict[str, Any],
    scope_doc: Dict[str, Any],
    targets: List[str],
    top_ports: Optional[int] = None,
    extra_args: Optional[List[str]] = None,
    report_title: str = "Nmap Recon Scan",
) -> Dict[str, Any]:
    """
    Run an nmap scan against in-scope targets and generate reports.

    Raises:
        ScopeViolation: if any target is out-of-scope and hard block is enabled
        FileNotFoundError: if nmap is not found
        RuntimeError: if nmap exits non-zero
    Returns:
        {
          "targets": [...],
          "xml": "path",
          "json": "path",
          "markdown": "path",
          "summary": {...}
        }
    """
    features = cfg.get("features", {}) or {}
    if not (features.get("enable_recon") and features.get("enable_vuln_scan")):
        raise PermissionError("Recon/Vuln-Scan features are disabled in config.features.")

    # Scope enforcement for each target (ports are validated by scope gate later if needed)
    for t in targets:
        enforce_scope(scope_doc, t)

    nmap_bin = _resolve_nmap_path(cfg)
    reports_dir = _reports_dir(cfg)

    # Build command
    args = _build_nmap_args(cfg, targets, top_ports=top_ports, extra_args=extra_args)

    # Use an XML temp file for parsing
    with tempfile.NamedTemporaryFile(prefix="pp_nmap_", suffix=".xml", delete=False) as tmp:
        xml_out = Path(tmp.name)

    cmd = [nmap_bin] + args + ["-oX", str(xml_out)]
    log.info("Executing: %s", " ".join(cmd))

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        log.error("nmap failed (code=%s): %s", proc.returncode, proc.stderr.strip())
        raise RuntimeError(f"nmap failed with exit code {proc.returncode}")

    # Parse and summarize
    summary = _parse_nmap_xml(xml_out)

    # Write JSON and Markdown reports
    json_path = reports_dir.joinpath(xml_out.stem + ".json")
    md_path: Path = write_report(
        reports_dir=str(reports_dir),
        title=report_title,
        summary={
            "operation": report_title,
            "targets": targets,
            "findings": {"nmap_summary": summary},
            "notes": [],
        },
        format=(cfg.get("reporting", {}) or {}).get("default_format", "markdown"),
        subfolder=None,
    )
    _write_json_report(json_path, summary)

    result = {
        "targets": targets,
        "xml": str(xml_out),
        "json": str(json_path),
        "markdown": str(md_path),
        "summary": summary,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "command": cmd,
    }
    log.info("Nmap scan complete: md=%s json=%s", md_path, json_path)
    return result


__all__ = ["run_nmap_scan"]
