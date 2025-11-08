"""PERSISTENCE MECHANISMS DOMAIN"""
from typing import Dict, List
from .base_domain import BaseDomain, OperationResult

class Persistence(BaseDomain):
    async def execute_operation(self, operation: str, params: Dict) -> OperationResult:
        operations = {"registry": self._registry_persistence, "scheduled": self._scheduled_tasks, "service": self._service_install, "backdoor": self._backdoor_user}
        return await operations.get(operation, self._default_op)(params)

    async def _registry_persistence(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"keys": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"], "payload": "backdoor.exe"},
                                  ["Persistence via registry Run key", "Survives reboot"],
                                  "critical", ["Monitor registry changes", "Application whitelisting", "EDR with registry protection"])

    async def _scheduled_tasks(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"task_name": "WindowsUpdate", "trigger": "daily", "hidden": True},
                                  ["Hidden scheduled task created", "Executes daily with SYSTEM privileges"],
                                  "critical", ["Audit scheduled tasks", "Baseline task inventory", "Task creation monitoring"])

    async def _service_install(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"service": "WindowsDefender", "startup": "automatic"},
                                  ["Malicious service installed", "Masquerades as legitimate service"],
                                  "critical", ["Service integrity monitoring", "Code signing", "Service creation alerts"])

    async def _backdoor_user(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"username": "support$", "privileges": "admin", "hidden": True},
                                  ["Hidden admin account created", "Ending $ hides from user list"],
                                  "critical", ["Account creation monitoring", "Regular user audits", "Privileged account management"])

    async def _default_op(self, params: Dict) -> OperationResult:
        return self._create_result(True, {}, ["Persistence check completed"], "low", [])

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> List[str]:
        return ["registry", "scheduled", "service", "backdoor"]
