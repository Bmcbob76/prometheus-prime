"""Error learning for continuous improvement"""
from typing import Dict, List

class ErrorLearning:
    """Learns from errors to improve recovery"""
    def __init__(self):
        self.error_history = []

    async def record_error(self, error: Exception, recovery: Dict):
        """Record error and recovery outcome"""
        self.error_history.append({
            "error_type": type(error).__name__,
            "recovery_success": recovery.get("success"),
            "recovery_method": recovery.get("recovery_attempted")
        })

    async def get_best_recovery(self, error_type: str) -> List[str]:
        """Get best recovery methods for error type based on history"""
        successful = [
            e["recovery_method"]
            for e in self.error_history
            if e["error_type"] == error_type and e["recovery_success"]
        ]
        return successful[:3] if successful else ["default_recovery"]
