"""Attack Reflection - Send attacks back to attacker"""
class AttackReflector:
    async def reflect(self, attack): return {"reflected": True, "target": attack["source"]}
