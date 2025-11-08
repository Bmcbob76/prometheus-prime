"""
Scope gate for PROMETHEUS-PRIME (Lab-only)
- Validates that targets/protocols/ports are within authorized lab scope
- Intended to be called by all operational modules BEFORE any action
- Works with configurations loaded via config_loader.load_scope()

Scope file structure (example):
{
  "scope": {
    "cidrs": ["10.0.0.0/24", "192.168.56.0/24"],
    "domains": ["lab.local", "corp.lab"],
    "hosts": ["10.0.0.5", "dc01.lab.local"],
    "allowed_ports": ["1-65535", "443", "80"],
    "protocols": ["tcp", "udp"],
    "egress": {
      "allow_to_cidrs": ["10.0.0.0/8"],
      "allow_to_domains": ["lab.local"]
    }
  },
  "policy": {
    "require_confirmation": true,
    "banner": "LAB-ONLY...",
    "hard_block_out_of_scope": true
  }
}
"""

from __future__ import annotations

import re
import socket
from ipaddress import ip_address, ip_network
from typing import Dict, Iterable, List, Optional, Tuple, Union


class ScopeViolation(PermissionError):
    """Raised when an action is outside of authorized lab scope."""


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def _hostname(value: str) -> bool:
    # Very loose hostname/FQDN check
    if _is_ip(value):
        return False
    if len(value) == 0 or len(value) > 253:
        return False
    if "." not in value:
        return False
    labels = value.split(".")
    return all(re.match(r"^[A-Za-z0-9-]{1,63}$", lbl or "") for lbl in labels)


def _port_in_range(port: int, range_spec: str) -> bool:
    """
    Check if a port is within a range spec:
      - "80"
      - "1-1024"
    """
    if "-" in range_spec:
        start_s, end_s = range_spec.split("-", 1)
        try:
            start = int(start_s.strip())
            end = int(end_s.strip())
            return start <= port <= end
        except ValueError:
            return False
    else:
        try:
            return int(range_spec.strip()) == port
        except ValueError:
            return False


def _port_allowed(port: Optional[int], allowed_ports: Iterable[str]) -> bool:
    if port is None:
        return True
    for spec in allowed_ports or []:
        if _port_in_range(port, str(spec)):
            return True
    return False


def _protocol_allowed(protocol: Optional[str], allowed_protocols: Iterable[str]) -> bool:
    if protocol is None:
        return True
    if not allowed_protocols:
        # Default safe protocols if none specified
        return protocol.lower() in ("tcp", "udp")
    return protocol.lower() in [p.lower() for p in allowed_protocols]


def _ip_in_cidrs(ip: str, cidrs: Iterable[str]) -> bool:
    try:
        ip_obj = ip_address(ip)
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            if ip_obj in ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _domain_in_suffixes(host: str, suffixes: Iterable[str]) -> bool:
    host_l = host.lower().rstrip(".")
    for sfx in suffixes or []:
        sfx_l = sfx.lower().lstrip(".")
        if host_l.endswith("." + sfx_l) or host_l == sfx_l:
            return True
    return False


def is_target_allowed(
    scope_doc: Dict,
    target: str,
    port: Optional[int] = None,
    protocol: Optional[str] = None
) -> Tuple[bool, List[str]]:
    """
    Determine if a target/port/protocol is allowed by the scope document.
    Returns (allowed, reasons) where reasons includes validation hints.
    """
    reasons: List[str] = []
    scope = scope_doc.get("scope", {})
    cidrs = scope.get("cidrs", []) or []
    domains = scope.get("domains", []) or []
    hosts = scope.get("hosts", []) or []
    allowed_ports = scope.get("allowed_ports", []) or []
    protocols = scope.get("protocols", []) or []

    # Direct host allow list (IP or FQDN)
    if target in hosts:
        if _protocol_allowed(protocol, protocols) and _port_allowed(port, allowed_ports):
            reasons.append("Target explicitly allowed by hosts list")
            return True, reasons
        else:
            reasons.append("Target is in hosts list but protocol/port not allowed")

    # IP checks
    if _is_ip(target):
        if _ip_in_cidrs(target, cidrs):
            if _protocol_allowed(protocol, protocols) and _port_allowed(port, allowed_ports):
                reasons.append("IP is within authorized CIDRs and port/protocol allowed")
                return True, reasons
            else:
                reasons.append("IP CIDR allowed but protocol/port not allowed")
        else:
            reasons.append("IP is not within any authorized CIDR")

    # Hostname checks
    elif _hostname(target):
        # Try resolve to IP and match CIDRs (best-effort)
        resolved_ok = False
        try:
            resolved = socket.getaddrinfo(target, None)
            ip_candidates = {ai[4][0] for ai in resolved if ai and ai[4]}
            for ip in ip_candidates:
                if _ip_in_cidrs(ip, cidrs):
                    resolved_ok = True
                    break
        except Exception:
            # DNS resolve failure is not conclusive; continue with domain suffix check
            pass

        domain_ok = _domain_in_suffixes(target, domains)
        if domain_ok or resolved_ok:
            if _protocol_allowed(protocol, protocols) and _port_allowed(port, allowed_ports):
                reasons.append("Hostname allowed by domain suffix and/or resolved IP in authorized CIDRs")
                return True, reasons
            else:
                reasons.append("Hostname allowed but protocol/port not allowed")
        else:
            reasons.append("Hostname not in authorized domains and resolved IPs not in CIDRs")

    else:
        reasons.append("Target is neither an IP nor a valid FQDN")

    return False, reasons


def enforce_scope(
    scope_doc: Dict,
    target: str,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    hard_block_out_of_scope: Optional[bool] = None
) -> None:
    """
    Enforce scope; raises ScopeViolation if target is out-of-scope and hard block is enabled.
    """
    policy = scope_doc.get("policy", {})
    hard_block = policy.get("hard_block_out_of_scope", True) if hard_block_out_of_scope is None else hard_block_out_of_scope

    allowed, reasons = is_target_allowed(scope_doc, target, port=port, protocol=protocol)
    if not allowed and hard_block:
        detail = "; ".join(reasons) or "Target outside authorized scope"
        raise ScopeViolation(f"Out-of-scope: {target} (port={port}, protocol={protocol}). {detail}")


__all__ = ["ScopeViolation", "is_target_allowed", "enforce_scope"]
