#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║     OMEGA RESOURCE SCALING - DYNAMIC AGENT SCALING               ║
║     CPU/GPU Monitoring & Automatic Agent Scaling                 ║
╚══════════════════════════════════════════════════════════════════╝

RESOURCE-AWARE SCALING:
- Real-time CPU/GPU monitoring
- Dynamic agent count adjustment
- Performance-based scaling
- Resource reservation
- Load balancing
- Throttling & acceleration
"""

import logging
import time
import psutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import platform

# Try to import GPU monitoring (optional)
try:
    import GPUtil
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False
    logging.warning("GPUtil not available - GPU monitoring disabled")

# ══════════════════════════════════════════════════════════════════
# RESOURCE TYPES & STATES
# ══════════════════════════════════════════════════════════════════

class ResourceState(Enum):
    """System resource state"""
    CRITICAL = "critical"      # <10% available
    LOW = "low"               # 10-30% available
    MODERATE = "moderate"     # 30-60% available
    GOOD = "good"             # 60-80% available
    EXCELLENT = "excellent"   # >80% available

class ScalingAction(Enum):
    """Scaling actions"""
    SCALE_DOWN_AGGRESSIVE = "scale_down_aggressive"  # Reduce by 50%
    SCALE_DOWN = "scale_down"                        # Reduce by 25%
    MAINTAIN = "maintain"                            # Keep current
    SCALE_UP = "scale_up"                            # Increase by 25%
    SCALE_UP_AGGRESSIVE = "scale_up_aggressive"      # Increase by 50%

# ══════════════════════════════════════════════════════════════════
# RESOURCE METRICS
# ══════════════════════════════════════════════════════════════════

@dataclass
class ResourceMetrics:
    """System resource metrics"""
    timestamp: float = field(default_factory=time.time)
    
    # CPU
    cpu_percent: float = 0.0
    cpu_count_logical: int = 0
    cpu_count_physical: int = 0
    cpu_freq_current: float = 0.0
    cpu_available_percent: float = 100.0
    
    # Memory
    memory_total_gb: float = 0.0
    memory_used_gb: float = 0.0
    memory_percent: float = 0.0
    memory_available_gb: float = 0.0
    
    # GPU (if available)
    gpu_available: bool = False
    gpu_count: int = 0
    gpu_utilization: List[float] = field(default_factory=list)
    gpu_memory_used: List[float] = field(default_factory=list)
    gpu_memory_total: List[float] = field(default_factory=list)
    gpu_memory_percent: List[float] = field(default_factory=list)
    
    # Disk
    disk_usage_percent: float = 0.0
    disk_available_gb: float = 0.0
    
    # Network
    network_sent_mb: float = 0.0
    network_recv_mb: float = 0.0
    
    def calculate_resource_state(self) -> ResourceState:
        """Calculate overall resource state"""
        # Average key metrics
        cpu_available = 100.0 - self.cpu_percent
        memory_available = 100.0 - self.memory_percent
        
        # GPU if available
        if self.gpu_available and self.gpu_utilization:
            gpu_available = 100.0 - (sum(self.gpu_utilization) / len(self.gpu_utilization))
        else:
            gpu_available = cpu_available
        
        # Weighted average (CPU 40%, Memory 40%, GPU 20%)
        overall_available = (cpu_available * 0.4 + 
                           memory_available * 0.4 + 
                           gpu_available * 0.2)
        
        if overall_available < 10:
            return ResourceState.CRITICAL
        elif overall_available < 30:
            return ResourceState.LOW
        elif overall_available < 60:
            return ResourceState.MODERATE
        elif overall_available < 80:
            return ResourceState.GOOD
        else:
            return ResourceState.EXCELLENT

# ══════════════════════════════════════════════════════════════════
# SCALING POLICY
# ══════════════════════════════════════════════════════════════════

@dataclass
class ScalingPolicy:
    """Policy for automatic agent scaling"""
    # Thresholds
    scale_up_threshold: float = 80.0      # Scale up if > 80% available
    scale_down_threshold: float = 30.0    # Scale down if < 30% available
    critical_threshold: float = 10.0      # Emergency scale down
    
    # Agent limits
    min_agents: int = 10
    max_agents: int = 1200
    
    # Scaling rates
    scale_up_rate: float = 0.25          # Increase by 25%
    scale_down_rate: float = 0.25        # Decrease by 25%
    aggressive_scale_rate: float = 0.50  # Aggressive scaling
    
    # Cool-down periods (seconds)
    scale_up_cooldown: int = 30
    scale_down_cooldown: int = 10
    
    # Performance targets
    target_cpu_usage: float = 70.0
    target_memory_usage: float = 70.0
    target_gpu_usage: float = 70.0

# ══════════════════════════════════════════════════════════════════
# RESOURCE MONITOR
# ══════════════════════════════════════════════════════════════════

class ResourceMonitor:
    """
    Real-time system resource monitoring
    """
    
    def __init__(self):
        self.system_info = {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor()
        }
        
        # GPU detection
        self.gpu_available = GPU_AVAILABLE
        if self.gpu_available:
            try:
                gpus = GPUtil.getGPUs()
                self.gpu_count = len(gpus)
                logging.info(f"🎮 Detected {self.gpu_count} GPU(s)")
            except:
                self.gpu_available = False
                self.gpu_count = 0
        else:
            self.gpu_count = 0
        
        logging.info(f"📊 Resource Monitor initialized on {self.system_info['platform']}")
    
    def get_current_metrics(self) -> ResourceMetrics:
        """Get current system resource metrics"""
        metrics = ResourceMetrics()
        
        # CPU metrics
        metrics.cpu_percent = psutil.cpu_percent(interval=1)
        metrics.cpu_count_logical = psutil.cpu_count(logical=True)
        metrics.cpu_count_physical = psutil.cpu_count(logical=False)
        
        try:
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                metrics.cpu_freq_current = cpu_freq.current
        except:
            pass
        
        metrics.cpu_available_percent = 100.0 - metrics.cpu_percent
        
        # Memory metrics
        memory = psutil.virtual_memory()
        metrics.memory_total_gb = memory.total / (1024**3)
        metrics.memory_used_gb = memory.used / (1024**3)
        metrics.memory_percent = memory.percent
        metrics.memory_available_gb = memory.available / (1024**3)
        
        # GPU metrics
        if self.gpu_available:
            try:
                gpus = GPUtil.getGPUs()
                metrics.gpu_available = True
                metrics.gpu_count = len(gpus)
                
                for gpu in gpus:
                    metrics.gpu_utilization.append(gpu.load * 100)
                    metrics.gpu_memory_used.append(gpu.memoryUsed)
                    metrics.gpu_memory_total.append(gpu.memoryTotal)
                    metrics.gpu_memory_percent.append(gpu.memoryUtil * 100)
            except Exception as e:
                logging.warning(f"GPU monitoring error: {e}")
        
        # Disk metrics
        try:
            disk = psutil.disk_usage('/')
            metrics.disk_usage_percent = disk.percent
            metrics.disk_available_gb = disk.free / (1024**3)
        except:
            pass
        
        # Network metrics
        try:
            net_io = psutil.net_io_counters()
            metrics.network_sent_mb = net_io.bytes_sent / (1024**2)
            metrics.network_recv_mb = net_io.bytes_recv / (1024**2)
        except:
            pass
        
        return metrics

# ══════════════════════════════════════════════════════════════════
# DYNAMIC SCALING ENGINE
# ══════════════════════════════════════════════════════════════════

class DynamicScalingEngine:
    """
    Dynamic agent scaling based on system resources
    """
    
    def __init__(self, policy: Optional[ScalingPolicy] = None):
        self.monitor = ResourceMonitor()
        self.policy = policy or ScalingPolicy()
        
        # Current state
        self.current_agent_count = self.policy.min_agents
        self.target_agent_count = self.policy.min_agents
        
        # Scaling history
        self.scaling_history: List[Dict[str, Any]] = []
        self.last_scale_up_time: float = 0.0
        self.last_scale_down_time: float = 0.0
        
        # Metrics history
        self.metrics_history: List[ResourceMetrics] = []
        self.max_history_size = 100
        
        # Statistics
        self.stats = {
            "scale_up_count": 0,
            "scale_down_count": 0,
            "total_adjustments": 0,
            "peak_agent_count": self.policy.min_agents,
            "lowest_agent_count": self.policy.min_agents
        }
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║         DYNAMIC SCALING ENGINE INITIALIZED                   ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
        logging.info(f"📊 Agent Range: {self.policy.min_agents} - {self.policy.max_agents}")
    
    def evaluate_scaling(self) -> Tuple[ScalingAction, int]:
        """Evaluate if scaling is needed and determine action"""
        metrics = self.monitor.get_current_metrics()
        self.metrics_history.append(metrics)
        
        if len(self.metrics_history) > self.max_history_size:
            self.metrics_history.pop(0)
        
        resource_state = metrics.calculate_resource_state()
        current_time = time.time()
        
        # Check cool-down periods
        can_scale_up = (current_time - self.last_scale_up_time) > self.policy.scale_up_cooldown
        can_scale_down = (current_time - self.last_scale_down_time) > self.policy.scale_down_cooldown
        
        # Calculate available resources
        cpu_available = 100.0 - metrics.cpu_percent
        memory_available = 100.0 - metrics.memory_percent
        
        # Determine scaling action
        action = ScalingAction.MAINTAIN
        new_count = self.current_agent_count
        
        # Critical state - aggressive scale down
        if resource_state == ResourceState.CRITICAL and can_scale_down:
            action = ScalingAction.SCALE_DOWN_AGGRESSIVE
            new_count = max(
                self.policy.min_agents,
                int(self.current_agent_count * (1 - self.policy.aggressive_scale_rate))
            )
        
        # Low resources - scale down
        elif resource_state == ResourceState.LOW and can_scale_down:
            action = ScalingAction.SCALE_DOWN
            new_count = max(
                self.policy.min_agents,
                int(self.current_agent_count * (1 - self.policy.scale_down_rate))
            )
        
        # Excellent resources - scale up
        elif resource_state == ResourceState.EXCELLENT and can_scale_up:
            action = ScalingAction.SCALE_UP_AGGRESSIVE
            new_count = min(
                self.policy.max_agents,
                int(self.current_agent_count * (1 + self.policy.aggressive_scale_rate))
            )
        
        # Good resources - scale up moderately
        elif resource_state == ResourceState.GOOD and can_scale_up:
            action = ScalingAction.SCALE_UP
            new_count = min(
                self.policy.max_agents,
                int(self.current_agent_count * (1 + self.policy.scale_up_rate))
            )
        
        return action, new_count
    
    def apply_scaling(self, action: ScalingAction, new_count: int) -> bool:
        """Apply scaling decision"""
        if action == ScalingAction.MAINTAIN:
            return False
        
        old_count = self.current_agent_count
        self.current_agent_count = new_count
        self.target_agent_count = new_count
        
        # Record scaling event
        scaling_event = {
            "timestamp": time.time(),
            "action": action.name,
            "old_count": old_count,
            "new_count": new_count,
            "change": new_count - old_count,
            "change_percent": ((new_count - old_count) / old_count * 100) if old_count > 0 else 0
        }
        self.scaling_history.append(scaling_event)
        
        # Update timestamps
        if "UP" in action.name:
            self.last_scale_up_time = time.time()
            self.stats['scale_up_count'] += 1
        else:
            self.last_scale_down_time = time.time()
            self.stats['scale_down_count'] += 1
        
        self.stats['total_adjustments'] += 1
        
        # Update peak/lowest
        if new_count > self.stats['peak_agent_count']:
            self.stats['peak_agent_count'] = new_count
        if new_count < self.stats['lowest_agent_count']:
            self.stats['lowest_agent_count'] = new_count
        
        logging.info(f"⚖️ SCALING: {action.name} | {old_count} → {new_count} agents "
                    f"({new_count - old_count:+d})")
        
        return True
    
    def get_optimal_agent_count(self) -> int:
        """Calculate optimal agent count based on resources"""
        metrics = self.monitor.get_current_metrics()
        
        # Calculate based on CPU cores
        cpu_based = int(metrics.cpu_count_logical * 100)
        
        # Calculate based on memory (assume 10MB per agent)
        memory_based = int(metrics.memory_available_gb * 1024 / 10)
        
        # Calculate based on GPU (if available)
        if metrics.gpu_available and metrics.gpu_memory_total:
            # Assume 50MB GPU memory per agent
            gpu_based = int(sum(metrics.gpu_memory_total) / 50)
        else:
            gpu_based = cpu_based
        
        # Take minimum of all constraints
        optimal = min(cpu_based, memory_based, gpu_based, self.policy.max_agents)
        optimal = max(optimal, self.policy.min_agents)
        
        return optimal
    
    def get_resource_summary(self) -> Dict[str, Any]:
        """Get comprehensive resource summary"""
        if not self.metrics_history:
            metrics = self.monitor.get_current_metrics()
        else:
            metrics = self.metrics_history[-1]
        
        resource_state = metrics.calculate_resource_state()
        
        summary = {
            "current_agents": self.current_agent_count,
            "target_agents": self.target_agent_count,
            "optimal_agents": self.get_optimal_agent_count(),
            "resource_state": resource_state.name,
            "cpu": {
                "usage_percent": metrics.cpu_percent,
                "available_percent": metrics.cpu_available_percent,
                "cores_logical": metrics.cpu_count_logical,
                "cores_physical": metrics.cpu_count_physical,
                "frequency_mhz": metrics.cpu_freq_current
            },
            "memory": {
                "total_gb": metrics.memory_total_gb,
                "used_gb": metrics.memory_used_gb,
                "available_gb": metrics.memory_available_gb,
                "usage_percent": metrics.memory_percent
            },
            "gpu": {
                "available": metrics.gpu_available,
                "count": metrics.gpu_count,
                "utilization": metrics.gpu_utilization,
                "memory_percent": metrics.gpu_memory_percent
            },
            "stats": self.stats
        }
        
        return summary

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - SCALING - %(levelname)s - %(message)s')
    
    # Initialize scaling engine
    scaling = DynamicScalingEngine()
    
    # Get initial summary
    summary = scaling.get_resource_summary()
    
    print("\n" + "="*70)
    print("DYNAMIC RESOURCE SCALING - SYSTEM STATUS")
    print("="*70)
    print(f"Resource State: {summary['resource_state']}")
    print(f"Current Agents: {summary['current_agents']}")
    print(f"Optimal Agents: {summary['optimal_agents']}")
    print()
    print(f"CPU: {summary['cpu']['usage_percent']:.1f}% used, "
          f"{summary['cpu']['cores_logical']} logical cores")
    print(f"Memory: {summary['memory']['used_gb']:.1f}GB / "
          f"{summary['memory']['total_gb']:.1f}GB "
          f"({summary['memory']['usage_percent']:.1f}%)")
    
    if summary['gpu']['available']:
        print(f"GPU: {summary['gpu']['count']} GPUs, "
              f"Average utilization: {sum(summary['gpu']['utilization'])/len(summary['gpu']['utilization']):.1f}%")
    else:
        print("GPU: Not available")
    
    # Simulate scaling decisions
    print("\n" + "="*70)
    print("SIMULATING SCALING DECISIONS")
    print("="*70)
    
    for i in range(5):
        time.sleep(2)
        action, new_count = scaling.evaluate_scaling()
        if action != ScalingAction.MAINTAIN:
            scaling.apply_scaling(action, new_count)
    
    # Show final stats
    final_summary = scaling.get_resource_summary()
    print("\n" + "="*70)
    print("SCALING STATISTICS")
    print("="*70)
    print(f"Total Adjustments: {final_summary['stats']['total_adjustments']}")
    print(f"Scale Up Count: {final_summary['stats']['scale_up_count']}")
    print(f"Scale Down Count: {final_summary['stats']['scale_down_count']}")
    print(f"Peak Agents: {final_summary['stats']['peak_agent_count']}")
    print(f"Lowest Agents: {final_summary['stats']['lowest_agent_count']}")
    print(f"Current Agents: {final_summary['current_agents']}")
