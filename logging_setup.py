"""
Logging setup for PROMETHEUS-PRIME
- Reads config.logging for level, file, format, rotate
- Installs console + file handlers
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Optional


def setup_logging(cfg: Dict) -> logging.Logger:
    log_cfg = cfg.get("logging", {})
    level_name = str(log_cfg.get("level", "INFO")).upper()
    fmt = log_cfg.get("format", "[%(asctime)s] %(levelname)s %(name)s - %(message)s")
    file_path = log_cfg.get("file", "logs/prometheus_prime.log")
    rotate = bool(log_cfg.get("rotate", False))

    # Resolve path and ensure dir exists
    log_file = Path(__file__).resolve().parent.joinpath(file_path).resolve()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Map level
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Clear any pre-existing handlers if reconfiguring
    for h in list(root.handlers):
        root.removeHandler(h)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(fmt))
    root.addHandler(ch)

    # File handler
    if rotate:
        fh = logging.handlers.RotatingFileHandler(
            filename=str(log_file),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
    else:
        fh = logging.FileHandler(filename=str(log_file), encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(fmt))
    root.addHandler(fh)

    logger = logging.getLogger("PROMETHEUS-PRIME")
    logger.debug("Logging initialized at level %s, file=%s", level_name, log_file)
    return logger


__all__ = ["setup_logging"]
