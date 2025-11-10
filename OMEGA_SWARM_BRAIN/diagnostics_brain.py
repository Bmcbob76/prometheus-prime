"""Echo Diagnostic Core Integration"""
import psutil
from datetime import datetime

class DiagnosticBrain:
    def __init__(self):
        self.monitoring = True
        
    def get_system_health(self):
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("P:/").percent,
            "timestamp": datetime.now().isoformat()
        }
    
    def auto_repair(self, issue):
        print(f"?? AUTO-REPAIR: {issue}")
        return {"repaired": True, "issue": issue}
    
    def continuous_monitoring(self):
        health = self.get_system_health()
        print(f"?? SYSTEM HEALTH: CPU {health['cpu_percent']}% | RAM {health['memory_percent']}%")
        return health

diagnostics = DiagnosticBrain()
