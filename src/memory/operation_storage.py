"""Operation storage and retrieval"""
from typing import Dict, List
from datetime import datetime

class OperationStorage:
    """Stores and retrieves security operations"""
    def __init__(self):
        self.operations = []

    async def store(self, operation: Dict) -> str:
        """Store operation"""
        op_id = f"op_{datetime.now():%Y%m%d%H%M%S}"
        self.operations.append({"id": op_id, **operation})
        return op_id

    async def retrieve(self, op_id: str) -> Dict:
        """Retrieve operation by ID"""
        return next((op for op in self.operations if op["id"] == op_id), None)

    async def list_operations(self, limit: int = 100) -> List[Dict]:
        """List recent operations"""
        return self.operations[-limit:]
