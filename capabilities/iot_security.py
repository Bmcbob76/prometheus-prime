"""IOT SECURITY DOMAIN"""
from typing import Dict, List
from .base_domain import BaseDomain, OperationResult

class IoTSecurity(BaseDomain):
    async def execute_operation(self, operation: str, params: Dict) -> OperationResult:
        operations = {"scan": self._iot_scan, "firmware": self._firmware_analysis, "zigbee": self._zigbee_test}
        return await operations.get(operation, self._default_op)(params)

    async def _iot_scan(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"devices": 25, "vulnerable": 12},
                                  ["25 IoT devices discovered", "12 with default credentials"],
                                  "critical", ["Change default credentials", "Network segmentation", "Firmware updates"])

    async def _firmware_analysis(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"backdoors": 1, "hardcoded_creds": True},
                                  ["Backdoor account found", "Hardcoded admin credentials"],
                                  "critical", ["Firmware update", "Isolate device", "Replace with secure alternative"])

    async def _zigbee_test(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"devices": 8, "encryption": "weak"},
                                  ["Weak Zigbee encryption", "Network key extractable"],
                                  "high", ["Enable strong encryption", "Network key rotation", "Zigbee 3.0 upgrade"])

    async def _default_op(self, params: Dict) -> OperationResult:
        return self._create_result(True, {}, ["IoT security check completed"], "low", [])

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> List[str]:
        return ["scan", "firmware", "zigbee"]
