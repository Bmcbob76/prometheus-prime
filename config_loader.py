"""
Config loader for PROMETHEUS-PRIME
- Loads YAML config (configs/default.yaml by default)
- Loads lab scope file (configs/example_scope.yaml by default)
- Loads .env (optional) and exposes env overrides
- Ensures paths (logs/, reports/, sessions/, payloads/) exist
"""

from __future__ import annotations

import os
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml  # PyYAML
except Exception as e:  # pragma: no cover
    raise ImportError(
        "PyYAML is required to load configuration. Please install with: pip install pyyaml"
    ) from e

try:
    from dotenv import load_dotenv
except Exception as e:  # pragma: no cover
    load_dotenv = None  # graceful fallback


log = logging.getLogger("PROMETHEUS-PRIME.Config")


def _package_root() -> Path:
    """Resolve the package root directory (where this file lives)."""
    return Path(__file__).resolve().parent


def _resolve_path(path_str: str) -> Path:
    """Resolve path relative to package root if not absolute."""
    p = Path(path_str)
    if p.is_absolute():
        return p
    return _package_root().joinpath(p).resolve()


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _env_bool(name: str, default: Optional[bool] = None) -> Optional[bool]:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


def _ensure_dirs(cfg: Dict[str, Any]) -> None:
    paths = cfg.get("paths", {})
    for key in ("logs_dir", "reports_dir", "sessions_dir", "payloads_dir"):
        d = paths.get(key)
        if not d:
            continue
        dp = _resolve_path(d)
        dp.mkdir(parents=True, exist_ok=True)


def load_config(config_path: str = "configs/default.yaml") -> Dict[str, Any]:
    """
    Load main configuration and apply minimal env overrides.

    Env overrides (optional):
      - PP_LOG_LEVEL: overrides logging.level
      - PP_FEATURE_*: enable/disable features via env, e.g., PP_FEATURE_ENABLE_RECON=true
      - PP_SCOPE_FILE: overrides lab.scope_file
    """
    # Load .env if available
    if load_dotenv is not None:
        # Try to load .env from package root and from CWD as a convenience
        for env_path in (Path.cwd() / ".env", _package_root() / ".env"):
            if env_path.exists():
                load_dotenv(dotenv_path=str(env_path), override=False)

    cfg_path = _resolve_path(config_path)
    cfg = _load_yaml_file(cfg_path)

    # Minimal env overrides
    log_level = os.getenv("PP_LOG_LEVEL")
    if log_level:
        cfg.setdefault("logging", {})
        cfg["logging"]["level"] = log_level.upper()

    # Feature flags via env: PP_FEATURE_ENABLE_RECON=true/false, etc.
    features = cfg.setdefault("features", {})
    for k in list(features.keys()):
        env_name = f"PP_FEATURE_{k.upper()}"
        env_val = os.getenv(env_name)
        if env_val is not None:
            features[k] = _env_bool(env_name, features[k])

    # Scope file override
    scope_file_env = os.getenv("PP_SCOPE_FILE")
    if scope_file_env:
        cfg.setdefault("lab", {})
        cfg["lab"]["scope_file"] = scope_file_env

    # Ensure directories exist
    _ensure_dirs(cfg)

    return cfg


def load_scope(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load lab scope as defined in config.
    Returns dict with:
      scope: { cidrs:[], domains:[], hosts:[], allowed_ports:[], protocols:[], egress:{...}}
      policy: { require_confirmation:bool, banner:str, hard_block_out_of_scope:bool }
    """
    lab_cfg = cfg.get("lab", {})
    scope_path = lab_cfg.get("scope_file")
    if not scope_path:
        raise ValueError("lab.scope_file not defined in configuration")

    sp = _resolve_path(scope_path)
    scope = _load_yaml_file(sp)

    # Basic normalization
    scope.setdefault("scope", {})
    scope["scope"].setdefault("cidrs", [])
    scope["scope"].setdefault("domains", [])
    scope["scope"].setdefault("hosts", [])
    scope["scope"].setdefault("allowed_ports", [])
    scope["scope"].setdefault("protocols", [])
    scope["scope"].setdefault("egress", {"allow_to_cidrs": [], "allow_to_domains": []})

    scope.setdefault("policy", {})
    scope["policy"].setdefault("require_confirmation", True)
    scope["policy"].setdefault("banner", "LAB-ONLY")
    scope["policy"].setdefault("hard_block_out_of_scope", True)

    return scope


def dump_effective_config(cfg: Dict[str, Any], out_path: Optional[str] = None) -> str:
    """
    For troubleshooting: returns a JSON string of the current effective config
    and optionally writes it to file.
    """
    pretty = json.dumps(cfg, indent=2, sort_keys=True)
    if out_path:
        p = _resolve_path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(pretty, encoding="utf-8")
    return pretty


__all__ = ["load_config", "load_scope", "dump_effective_config"]
