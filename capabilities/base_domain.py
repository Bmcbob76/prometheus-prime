"""
Base Domain Class for Prometheus Prime Security Operations
Provides standardized interface for all 20 security domains
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging


@dataclass
class OperationResult:
    """Standardized operation result"""
    domain: str
    success: bool
    timestamp: datetime
    data: Dict[str, Any]
    findings: List[str]
    severity: str
    recommendations: List[str]
    error: Optional[str] = None


class BaseDomain(ABC):
    """Base class for all Prometheus security domains"""

    def __init__(self, config: Dict = None):
        """
        Initialize domain with configuration.

        Args:
            config: Domain-specific configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        self.operations_count = 0

    @abstractmethod
    async def execute_operation(self, operation: str, params: Dict) -> OperationResult:
        """
        Execute domain-specific operation.

        Args:
            operation: Operation name
            params: Operation parameters

        Returns:
            OperationResult with execution details
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check domain health status.

        Returns:
            True if healthy, False otherwise
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """
        Get list of available operations in this domain.

        Returns:
            List of operation names
        """
        pass

    def _create_result(self, success: bool, data: Dict, findings: List[str],
                      severity: str, recommendations: List[str],
                      error: Optional[str] = None) -> OperationResult:
        """
        Create standardized operation result.

        Args:
            success: Operation success status
            data: Operation data
            findings: List of findings
            severity: Severity level (low, medium, high, critical)
            recommendations: List of recommendations
            error: Error message if failed

        Returns:
            OperationResult
        """
        self.operations_count += 1
        return OperationResult(
            domain=self.__class__.__name__,
            success=success,
            timestamp=datetime.now(),
            data=data,
            findings=findings,
            severity=severity,
            recommendations=recommendations,
            error=error
        )

    async def validate_params(self, required: List[str], params: Dict) -> bool:
        """
        Validate required parameters.

        Args:
            required: List of required parameter names
            params: Provided parameters

        Returns:
            True if valid, raises ValueError if not
        """
        missing = [p for p in required if p not in params]
        if missing:
            raise ValueError(f"Missing required parameters: {missing}")
        return True
