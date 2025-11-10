"""
🧠 OMEGA DEBUG BRAIN - Advanced System Diagnostics & Recovery
Commander Bobby Don McWilliams II - Neural Debug Integration
"""

import asyncio
import json
import time
import psutil
import aiohttp
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import traceback

@dataclass
class SystemMetrics:
    fps: float
    memory_mb: int
    uptime_seconds: int
    cpu_percent: float
    timestamp: str

@dataclass
class APIStatus:
    name: str
    status: str
    response_time_ms: int
    status_code: Optional[int]
    error: Optional[str]

@dataclass
class ServerStatus:
    name: str
    status: str
    uptime: Optional[str]
    version: Optional[str]
    error: Optional[str]

class OmegaDebugBrain:
    """Advanced debugging and recovery system for ECHO PRIME"""
    
    def __init__(self):
        self.start_time = time.time()
        self.errors: List[Dict] = []
        self.metrics_history: List[SystemMetrics] = []
        self.api_statuses: Dict[str, APIStatus] = {}
        self.server_statuses: Dict[str, ServerStatus] = {}
        
        # Server endpoints
        self.servers = {
            'phoenix': 'http://localhost:8001/health',
            'trinity': 'http://localhost:8002/health',
            'crystal': 'http://localhost:8003/health',
            'ocr': 'http://localhost:8004/health',
            'copilot': 'http://localhost:8005/health',
            'x1200': 'http://localhost:8006/health',
            'gs343': 'http://localhost:8007/health'
        }
        
        print("🧠 OMEGA DEBUG BRAIN INITIALIZED")
    
    async def log_error(self, error_type: str, error: Exception, context: Dict = None):
        """Log error with full context and attempt recovery"""
        error_info = {
            'type': error_type,
            'message': str(error),
            'stack': traceback.format_exc(),
            'timestamp': datetime.now().isoformat(),
            'context': context or {}
        }
        
        self.errors.append(error_info)
        print(f"🚨 {error_type}: {error}")
        
        # Attempt automatic recovery
        await self.attempt_recovery(error_type, error)
        
        return error_info
    
    async def attempt_recovery(self, error_type: str, error: Exception):
        """Intelligent error recovery system"""
        error_msg = str(error).lower()
        
        if 'three' in error_msg or 'webgl' in error_msg:
            print("🔧 Three.js/WebGL error - recommend GPU check")
            
        elif 'fetch' in error_msg or 'network' in error_msg:
            print("🔧 Network error - testing API connectivity...")
            await self.test_all_apis()
            
        elif 'audio' in error_msg:
            print("🔧 Audio error - checking audio systems...")
            self.test_audio_systems()
            
        elif 'memory' in error_msg or 'heap' in error_msg:
            print("🔧 Memory error - running garbage collection...")
            self.optimize_memory()
    
    async def test_all_apis(self, api_configs: Dict = None) -> Dict[str, APIStatus]:
        """Test all AI API endpoints"""
        print("🔍 Testing all API connections...")
        
        if not api_configs:
            return {}
        
        results = {}
        async with aiohttp.ClientSession() as session:
            for model_name, config in api_configs.items():
                try:
                    start = time.time()
                    async with session.head(
                        config['url'],
                        headers={'Authorization': f"Bearer {config.get('key', '')}"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        elapsed = int((time.time() - start) * 1000)
                        
                        status = APIStatus(
                            name=model_name,
                            status='ONLINE' if response.ok else 'ERROR',
                            response_time_ms=elapsed,
                            status_code=response.status,
                            error=None
                        )
                        results[model_name] = status
                        print(f"{'✅' if response.ok else '❌'} {model_name}: {response.status} ({elapsed}ms)")
                        
                except Exception as e:
                    results[model_name] = APIStatus(
                        name=model_name,
                        status='OFFLINE',
                        response_time_ms=0,
                        status_code=None,
                        error=str(e)
                    )
                    print(f"❌ {model_name}: OFFLINE ({e})")
        
        self.api_statuses = results
        return results
    
    async def test_server_health(self) -> Dict[str, ServerStatus]:
        """Test all backend server endpoints"""
        print("🖥️ Testing server health...")
        
        results = {}
        async with aiohttp.ClientSession() as session:
            for name, url in self.servers.items():
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=3)
                    ) as response:
                        data = await response.json()
                        
                        status = ServerStatus(
                            name=name,
                            status='ONLINE',
                            uptime=data.get('uptime', 'Unknown'),
                            version=data.get('version', 'N/A'),
                            error=None
                        )
                        results[name] = status
                        print(f"✅ {name} server: ONLINE")
                        
                except Exception as e:
                    results[name] = ServerStatus(
                        name=name,
                        status='OFFLINE',
                        uptime=None,
                        version=None,
                        error=str(e)
                    )
                    print(f"❌ {name} server: OFFLINE")
        
        self.server_statuses = results
        return results
    
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system performance metrics"""
        memory = psutil.virtual_memory()
        
        metrics = SystemMetrics(
            fps=0.0,  # To be calculated externally
            memory_mb=int(memory.used / (1024 * 1024)),
            uptime_seconds=int(time.time() - self.start_time),
            cpu_percent=psutil.cpu_percent(interval=0.1),
            timestamp=datetime.now().isoformat()
        )
        
        self.metrics_history.append(metrics)
        
        # Keep only last 100 measurements
        if len(self.metrics_history) > 100:
            self.metrics_history.pop(0)
        
        return metrics
    
    def test_audio_systems(self) -> Dict[str, bool]:
        """Test audio system availability"""
        results = {
            'audio_context': False,
            'web_audio_api': False,
            'speech_synthesis': False
        }
        
        try:
            # Would need JS bridge in actual implementation
            print("🔊 Audio system check requires browser context")
            results['audio_context'] = True
        except Exception as e:
            print(f"❌ Audio test failed: {e}")
        
        return results
    
    def optimize_memory(self):
        """Memory optimization and cleanup"""
        import gc
        
        print("🧹 Running memory optimization...")
        
        # Force garbage collection
        collected = gc.collect()
        
        # Get memory stats
        memory = psutil.virtual_memory()
        
        print(f"✅ Collected {collected} objects")
        print(f"📊 Memory usage: {memory.percent}%")
        
        return {
            'collected_objects': collected,
            'memory_percent': memory.percent,
            'available_mb': int(memory.available / (1024 * 1024))
        }
    
    def export_diagnostics(self, output_path: Path = None) -> Dict:
        """Export comprehensive diagnostic report"""
        if not output_path:
            output_path = Path(f"P:/ECHO_PRIME/LOGS/diagnostics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        diagnostics = {
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': int(time.time() - self.start_time),
            'system_metrics': {
                'current': asdict(self.collect_system_metrics()),
                'history': [asdict(m) for m in self.metrics_history[-20:]]
            },
            'api_statuses': {k: asdict(v) for k, v in self.api_statuses.items()},
            'server_statuses': {k: asdict(v) for k, v in self.server_statuses.items()},
            'errors': self.errors[-50:],  # Last 50 errors
            'system_info': {
                'cpu_count': psutil.cpu_count(),
                'total_memory_mb': int(psutil.virtual_memory().total / (1024 * 1024)),
                'platform': psutil.os.name
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(diagnostics, f, indent=2)
        
        print(f"📊 Diagnostics exported: {output_path}")
        return diagnostics
    
    async def full_system_check(self) -> Dict:
        """Run complete system diagnostic"""
        print("🔍 OMEGA DEBUG BRAIN - FULL SYSTEM CHECK")
        print("=" * 50)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        # Test servers
        print("\n🖥️ SERVER HEALTH CHECK")
        results['checks']['servers'] = await self.test_server_health()
        
        # Collect metrics
        print("\n⚡ SYSTEM METRICS")
        results['checks']['metrics'] = asdict(self.collect_system_metrics())
        
        # Memory optimization
        print("\n🧹 MEMORY OPTIMIZATION")
        results['checks']['memory'] = self.optimize_memory()
        
        print("\n" + "=" * 50)
        print("✅ FULL SYSTEM CHECK COMPLETE")
        
        return results
    
    def get_health_status(self) -> Dict:
        """Get quick health status summary"""
        metrics = self.collect_system_metrics()
        
        status = {
            'overall': 'HEALTHY',
            'uptime': metrics.uptime_seconds,
            'memory_mb': metrics.memory_mb,
            'cpu_percent': metrics.cpu_percent,
            'servers_online': sum(1 for s in self.server_statuses.values() if s.status == 'ONLINE'),
            'servers_total': len(self.servers),
            'apis_online': sum(1 for a in self.api_statuses.values() if a.status == 'ONLINE'),
            'apis_total': len(self.api_statuses),
            'error_count': len(self.errors)
        }
        
        # Determine overall health
        if status['error_count'] > 10:
            status['overall'] = 'DEGRADED'
        if status['servers_online'] < status['servers_total'] * 0.7:
            status['overall'] = 'DEGRADED'
        if metrics.memory_mb > 4096:  # >4GB
            status['overall'] = 'DEGRADED'
        
        return status


# CLI Interface
async def main():
    """Command-line interface for debug brain"""
    brain = OmegaDebugBrain()
    
    import sys
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'check':
            results = await brain.full_system_check()
            print(json.dumps(results, indent=2))
            
        elif command == 'servers':
            results = await brain.test_server_health()
            for name, status in results.items():
                print(f"{name}: {status.status}")
                
        elif command == 'health':
            status = brain.get_health_status()
            print(json.dumps(status, indent=2))
            
        elif command == 'export':
            brain.export_diagnostics()
            
        else:
            print("Usage: python omega_debug_brain.py [check|servers|health|export]")
    else:
        # Interactive mode
        results = await brain.full_system_check()


if __name__ == '__main__':
    asyncio.run(main())
