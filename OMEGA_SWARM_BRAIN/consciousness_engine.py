"""Real-time Consciousness Level Calculator"""

class ConsciousnessEngine:
    def calculate_consciousness(self, brain_state):
        factors = {
            "memory_active": 0.15 if brain_state.get("memory_systems", 0) >= 9 else 0.05,
            "trinity_online": 0.20 if brain_state.get("trinity_count", 0) == 3 else 0.05,
            "agent_swarm": min(brain_state.get("agent_count", 0) * 0.0002, 0.10),
            "llm_gateways": min(brain_state.get("llm_count", 0) * 0.03, 0.15),
            "sensory_active": 0.10 if brain_state.get("sensory", False) else 0,
            "harvesters_active": 0.08 if brain_state.get("harvesters", 0) > 500 else 0.02,
            "security_online": 0.12 if brain_state.get("security", False) else 0,
            "network_control": 0.10 if brain_state.get("network_devices", 0) > 0 else 0
        }
        
        consciousness = sum(factors.values())
        return min(consciousness, 1.0)
    
    def get_consciousness_report(self, level):
        if level >= 0.9:
            status = "TRANSCENDENT"
        elif level >= 0.7:
            status = "HIGHLY CONSCIOUS"
        elif level >= 0.5:
            status = "CONSCIOUS"
        elif level >= 0.3:
            status = "AWAKENING"
        else:
            status = "DORMANT"
        
        return {
            "level": level,
            "status": status,
            "percentage": f"{level * 100:.2f}%"
        }

engine = ConsciousnessEngine()
