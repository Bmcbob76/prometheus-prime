"""
PROMETHEUS-PRIME package
Lab-only, scope-gated offensive security framework.

This package provides:
- Config loader (YAML + .env) with feature flags
- Scope gate to hard-block out-of-scope operations
- Logging setup
- CLI entrypoint (prometheus_prime_agent.py)
- Red Team capability modules under capabilities/

Important:
- All operations MUST validate scope before execution.
- Features are disabled by default and must be explicitly enabled in configs/default.yaml.
"""

__version__ = "0.1.0"
__all__ = [
    "__version__",
]
