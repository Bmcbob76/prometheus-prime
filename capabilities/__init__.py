"""
PROMETHEUS-PRIME Red Team capabilities package

Note:
- All operational modules must enforce lab scope using scope_gate.enforce_scope(...)
- External tools (e.g., nmap, msfconsole, impacket) should be invoked only when the corresponding feature flag is enabled in configs/default.yaml and the target is within scope.
- Modules should log via the configured logger namespace: "PROMETHEUS-PRIME.<ModuleName>"
"""
__all__ = []
