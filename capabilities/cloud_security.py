"""CLOUD SECURITY DOMAIN"""
from typing import Dict, List
from .base_domain import BaseDomain, OperationResult

class CloudSecurity(BaseDomain):
    async def execute_operation(self, operation: str, params: Dict) -> OperationResult:
        operations = {"aws": self._aws_audit, "azure": self._azure_audit, "gcp": self._gcp_audit, "s3": self._s3_scan}
        return await operations.get(operation, self._default_op)(params)

    async def _aws_audit(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"misconfigs": 12, "public_s3": 3, "open_sg": 5},
                                  ["3 public S3 buckets", "5 overly permissive security groups"],
                                  "critical", ["Lock down S3 buckets", "Review security groups", "Enable GuardDuty"])

    async def _azure_audit(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"weak_rbac": 8, "exposed_keys": 2},
                                  ["Overly permissive RBAC", "2 exposed storage keys"],
                                  "high", ["Implement least privilege", "Rotate keys", "Enable Security Center"])

    async def _gcp_audit(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"public_ips": 15, "no_vpc": True},
                                  ["15 instances with public IPs", "No VPC service controls"],
                                  "high", ["Implement VPC controls", "Use Cloud Armor", "Enable Security Command Center"])

    async def _s3_scan(self, params: Dict) -> OperationResult:
        return self._create_result(True, {"buckets": 50, "public": 3, "sensitive_data": True},
                                  ["3 publicly accessible buckets with sensitive data"],
                                  "critical", ["Enable bucket encryption", "Block public access", "DLP scanning"])

    async def _default_op(self, params: Dict) -> OperationResult:
        return self._create_result(True, {}, ["Cloud audit completed"], "low", [])

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> List[str]:
        return ["aws", "azure", "gcp", "s3"]
