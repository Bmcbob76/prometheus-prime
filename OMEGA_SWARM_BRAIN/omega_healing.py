#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       OMEGA HEALING - SELF-HEALING & ERROR RECOVERY              ║
║         Automatic Error Detection, Diagnosis & Repair            ║
╚══════════════════════════════════════════════════════════════════╝

HEALING CAPABILITIES:
1. Error Detection - Monitor system health
2. Auto-Diagnosis - Identify root causes
3. Self-Repair - Automatic fixes
4. Error Database - Known issues & solutions
5. Healing Agents - Specialized repair units
6. Recovery Protocols - Step-by-step fixes

ERROR CATEGORIES:
- Agent Failures
- Memory Leaks
- Network Issues
- Database Corruption
- Module Crashes
- Resource Exhaustion
"""

import logging
import time
import traceback
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import json
import hashlib

# ══════════════════════════════════════════════════════════════════
# ERROR SEVERITY & CATEGORIES
# ══════════════════════════════════════════════════════════════════

class ErrorSeverity(Enum):
    """Error severity levels"""
    CRITICAL = "critical"      # System threatening
    HIGH = "high"             # Major functionality impaired
    MEDIUM = "medium"         # Minor functionality affected
    LOW = "low"               # Cosmetic or minor issue
    INFO = "info"             # Informational only

class ErrorCategory(Enum):
    """Error categories"""
    AGENT_FAILURE = "agent_failure"
    MEMORY_LEAK = "memory_leak"
    NETWORK_ERROR = "network_error"
    DATABASE_ERROR = "database_error"
    MODULE_CRASH = "module_crash"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    AUTHENTICATION_ERROR = "authentication_error"
    DEADLOCK = "deadlock"
    CORRUPTION = "corruption"
    UNKNOWN = "unknown"

# ══════════════════════════════════════════════════════════════════
# ERROR RECORD
# ══════════════════════════════════════════════════════════════════

@dataclass
class ErrorRecord:
    """Individual error record"""
    error_id: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    timestamp: float = field(default_factory=time.time)
    module: Optional[str] = None
    traceback_text: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Healing status
    diagnosed: bool = False
    repaired: bool = False
    repair_attempts: int = 0
    repair_timestamp: Optional[float] = None
    repair_solution: Optional[str] = None
    
    def generate_signature(self) -> str:
        """Generate error signature for matching"""
        sig_string = f"{self.category.value}:{self.module}:{self.message[:100]}"
        return hashlib.md5(sig_string.encode()).hexdigest()

# ══════════════════════════════════════════════════════════════════
# HEALING SOLUTION
# ══════════════════════════════════════════════════════════════════

@dataclass
class HealingSolution:
    """Known solution for specific error"""
    solution_id: str
    error_signature: str
    category: ErrorCategory
    title: str
    description: str
    repair_function: str  # Function name to call
    success_rate: float = 0.0
    usage_count: int = 0
    success_count: int = 0
    
    @property
    def calculated_success_rate(self) -> float:
        """Calculate actual success rate"""
        if self.usage_count == 0:
            return 0.0
        return self.success_count / self.usage_count
    
    def record_attempt(self, success: bool):
        """Record solution attempt"""
        self.usage_count += 1
        if success:
            self.success_count += 1
        self.success_rate = self.calculated_success_rate

# ══════════════════════════════════════════════════════════════════
# HEALING PROTOCOLS
# ══════════════════════════════════════════════════════════════════

class HealingProtocols:
    """
    Collection of automated healing protocols
    Each protocol handles specific error types
    """
    
    @staticmethod
    def restart_agent(agent_id: str, context: Dict) -> bool:
        """Restart a failed agent"""
        try:
            logging.info(f"🔄 Restarting agent: {agent_id}")
            # Implementation would restart actual agent
            time.sleep(0.1)
            return True
        except Exception as e:
            logging.error(f"Failed to restart agent: {e}")
            return False
    
    @staticmethod
    def clear_memory_leak(module: str, context: Dict) -> bool:
        """Clear memory leak"""
        try:
            logging.info(f"🧹 Clearing memory leak in {module}")
            # Implementation would clear caches, reset connections
            time.sleep(0.1)
            return True
        except Exception as e:
            logging.error(f"Failed to clear memory: {e}")
            return False
    
    @staticmethod
    def reconnect_network(endpoint: str, context: Dict) -> bool:
        """Reconnect network connection"""
        try:
            logging.info(f"🔌 Reconnecting to {endpoint}")
            # Implementation would reset connection
            time.sleep(0.1)
            return True
        except Exception as e:
            logging.error(f"Failed to reconnect: {e}")
            return False
    
    @staticmethod
    def repair_database(db_path: str, context: Dict) -> bool:
        """Repair corrupted database"""
        try:
            logging.info(f"🔧 Repairing database: {db_path}")
            # Implementation would run integrity checks, rebuild indexes
            time.sleep(0.2)
            return True
        except Exception as e:
            logging.error(f"Failed to repair database: {e}")
            return False
    
    @staticmethod
    def restart_module(module_name: str, context: Dict) -> bool:
        """Restart crashed module"""
        try:
            logging.info(f"🔄 Restarting module: {module_name}")
            # Implementation would reload module
            time.sleep(0.1)
            return True
        except Exception as e:
            logging.error(f"Failed to restart module: {e}")
            return False
    
    @staticmethod
    def free_resources(resource_type: str, context: Dict) -> bool:
        """Free exhausted resources"""
        try:
            logging.info(f"💾 Freeing {resource_type} resources")
            # Implementation would clean up resources
            time.sleep(0.1)
            return True
        except Exception as e:
            logging.error(f"Failed to free resources: {e}")
            return False
    
    @staticmethod
    def break_deadlock(locked_resources: List[str], context: Dict) -> bool:
        """Break resource deadlock"""
        try:
            logging.info(f"🔓 Breaking deadlock on {len(locked_resources)} resources")
            # Implementation would force release locks
            time.sleep(0.1)
            return True
        except Exception as e:
            logging.error(f"Failed to break deadlock: {e}")
            return False

# ══════════════════════════════════════════════════════════════════
# ERROR DATABASE
# ══════════════════════════════════════════════════════════════════

class ErrorDatabase:
    """
    Database of known errors and their solutions
    Learns from past repairs
    """
    
    def __init__(self):
        self.solutions: Dict[str, HealingSolution] = {}
        self._init_known_solutions()
    
    def _init_known_solutions(self):
        """Initialize with known common solutions"""
        solutions = [
            HealingSolution(
                solution_id="SOL_001",
                error_signature="agent_failure",
                category=ErrorCategory.AGENT_FAILURE,
                title="Restart Failed Agent",
                description="Restart the agent that has stopped responding",
                repair_function="restart_agent"
            ),
            HealingSolution(
                solution_id="SOL_002",
                error_signature="memory_leak",
                category=ErrorCategory.MEMORY_LEAK,
                title="Clear Memory Leak",
                description="Clear caches and reset memory pools",
                repair_function="clear_memory_leak"
            ),
            HealingSolution(
                solution_id="SOL_003",
                error_signature="network_error",
                category=ErrorCategory.NETWORK_ERROR,
                title="Reconnect Network",
                description="Reset network connection and retry",
                repair_function="reconnect_network"
            ),
            HealingSolution(
                solution_id="SOL_004",
                error_signature="database_error",
                category=ErrorCategory.DATABASE_ERROR,
                title="Repair Database",
                description="Run integrity check and rebuild indexes",
                repair_function="repair_database"
            ),
            HealingSolution(
                solution_id="SOL_005",
                error_signature="module_crash",
                category=ErrorCategory.MODULE_CRASH,
                title="Restart Module",
                description="Reload crashed module",
                repair_function="restart_module"
            ),
            HealingSolution(
                solution_id="SOL_006",
                error_signature="resource_exhaustion",
                category=ErrorCategory.RESOURCE_EXHAUSTION,
                title="Free Resources",
                description="Clean up and free exhausted resources",
                repair_function="free_resources"
            ),
            HealingSolution(
                solution_id="SOL_007",
                error_signature="deadlock",
                category=ErrorCategory.DEADLOCK,
                title="Break Deadlock",
                description="Force release locks to break deadlock",
                repair_function="break_deadlock"
            )
        ]
        
        for solution in solutions:
            self.solutions[solution.error_signature] = solution
    
    def find_solution(self, error: ErrorRecord) -> Optional[HealingSolution]:
        """Find solution for given error"""
        # Try exact signature match
        signature = error.generate_signature()
        if signature in self.solutions:
            return self.solutions[signature]
        
        # Try category match
        category_key = error.category.value
        if category_key in self.solutions:
            return self.solutions[category_key]
        
        return None
    
    def add_solution(self, solution: HealingSolution):
        """Add new solution to database"""
        self.solutions[solution.error_signature] = solution
        logging.info(f"➕ Added healing solution: {solution.title}")

# ══════════════════════════════════════════════════════════════════
# HEALING AGENT
# ══════════════════════════════════════════════════════════════════

@dataclass
class HealingAgent:
    """Specialized agent for error healing"""
    agent_id: str
    name: str
    specialization: ErrorCategory
    active: bool = True
    
    # Performance metrics
    errors_handled: int = 0
    successful_repairs: int = 0
    failed_repairs: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate repair success rate"""
        total = self.successful_repairs + self.failed_repairs
        if total == 0:
            return 0.0
        return self.successful_repairs / total
    
    def handle_error(self, error: ErrorRecord, solution: HealingSolution, 
                    protocols: HealingProtocols) -> bool:
        """Handle an error using given solution"""
        self.errors_handled += 1
        
        # Get repair function
        repair_func = getattr(protocols, solution.repair_function, None)
        if not repair_func:
            logging.error(f"Repair function not found: {solution.repair_function}")
            self.failed_repairs += 1
            return False
        
        # Attempt repair
        try:
            logging.info(f"🩹 {self.name} attempting repair: {solution.title}")
            success = repair_func(error.module or "unknown", error.context)
            
            if success:
                self.successful_repairs += 1
                logging.info(f"✅ Successfully repaired: {error.message[:50]}")
            else:
                self.failed_repairs += 1
                logging.warning(f"❌ Failed to repair: {error.message[:50]}")
            
            return success
            
        except Exception as e:
            logging.error(f"Error during repair: {e}")
            self.failed_repairs += 1
            return False

# ══════════════════════════════════════════════════════════════════
# OMEGA HEALING SYSTEM
# ══════════════════════════════════════════════════════════════════

class OmegaHealingSystem:
    """
    Complete self-healing and error recovery system
    Monitors, diagnoses, and repairs errors automatically
    """
    
    def __init__(self, max_error_history: int = 1000):
        self.error_database = ErrorDatabase()
        self.protocols = HealingProtocols()
        
        # Error tracking
        self.error_history: deque = deque(maxlen=max_error_history)
        self.active_errors: Dict[str, ErrorRecord] = {}
        
        # Healing agents
        self.healing_agents: Dict[str, HealingAgent] = {}
        self._init_healing_agents()
        
        # Statistics
        self.healing_stats = {
            "total_errors_detected": 0,
            "total_errors_repaired": 0,
            "total_repair_attempts": 0,
            "auto_heals": 0,
            "manual_interventions": 0
        }
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║          OMEGA HEALING SYSTEM INITIALIZED                    ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
    
    def _init_healing_agents(self):
        """Initialize specialized healing agents"""
        agents = [
            HealingAgent("HEALER_001", "Agent Recovery Specialist", ErrorCategory.AGENT_FAILURE),
            HealingAgent("HEALER_002", "Memory Manager", ErrorCategory.MEMORY_LEAK),
            HealingAgent("HEALER_003", "Network Technician", ErrorCategory.NETWORK_ERROR),
            HealingAgent("HEALER_004", "Database Administrator", ErrorCategory.DATABASE_ERROR),
            HealingAgent("HEALER_005", "Module Supervisor", ErrorCategory.MODULE_CRASH),
        ]
        
        for agent in agents:
            self.healing_agents[agent.agent_id] = agent
            logging.info(f"🩹 Initialized healing agent: {agent.name}")
    
    def report_error(self, category: ErrorCategory, severity: ErrorSeverity,
                    message: str, module: Optional[str] = None,
                    context: Dict[str, Any] = None,
                    auto_heal: bool = True) -> ErrorRecord:
        """Report a new error"""
        error_id = f"ERR_{int(time.time())}_{len(self.error_history)}"
        
        error = ErrorRecord(
            error_id=error_id,
            category=category,
            severity=severity,
            message=message,
            module=module,
            traceback_text=traceback.format_exc() if context and context.get('exception') else None,
            context=context or {}
        )
        
        self.error_history.append(error)
        self.active_errors[error_id] = error
        self.healing_stats['total_errors_detected'] += 1
        
        logging.error(f"🚨 ERROR DETECTED [{severity.name}]: {message}")
        
        # Attempt auto-healing
        if auto_heal and severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH, ErrorSeverity.MEDIUM]:
            self.auto_heal_error(error)
        
        return error
    
    def auto_heal_error(self, error: ErrorRecord) -> bool:
        """Automatically attempt to heal an error"""
        # Find solution
        solution = self.error_database.find_solution(error)
        if not solution:
            logging.warning(f"⚠️ No solution found for error: {error.category.name}")
            return False
        
        # Find appropriate healing agent
        healing_agent = None
        for agent in self.healing_agents.values():
            if agent.specialization == error.category and agent.active:
                healing_agent = agent
                break
        
        if not healing_agent:
            # Use first available agent
            active_agents = [a for a in self.healing_agents.values() if a.active]
            if active_agents:
                healing_agent = active_agents[0]
        
        if not healing_agent:
            logging.error("❌ No healing agents available")
            return False
        
        # Attempt repair
        error.repair_attempts += 1
        self.healing_stats['total_repair_attempts'] += 1
        
        success = healing_agent.handle_error(error, solution, self.protocols)
        
        solution.record_attempt(success)
        
        if success:
            error.repaired = True
            error.repair_timestamp = time.time()
            error.repair_solution = solution.solution_id
            self.healing_stats['total_errors_repaired'] += 1
            self.healing_stats['auto_heals'] += 1
            
            # Remove from active errors
            if error.error_id in self.active_errors:
                del self.active_errors[error.error_id]
        
        return success
    
    def diagnose_system_health(self) -> Dict[str, Any]:
        """Perform comprehensive system health diagnosis"""
        # Analyze recent errors
        recent_errors = list(self.error_history)[-100:]
        
        error_by_category = {}
        error_by_severity = {}
        
        for error in recent_errors:
            error_by_category[error.category.name] = error_by_category.get(error.category.name, 0) + 1
            error_by_severity[error.severity.name] = error_by_severity.get(error.severity.name, 0) + 1
        
        # Calculate health score (0-100)
        health_score = 100.0
        
        # Penalize for active errors
        health_score -= len(self.active_errors) * 5
        
        # Penalize for recent critical errors
        recent_critical = sum(1 for e in recent_errors if e.severity == ErrorSeverity.CRITICAL)
        health_score -= recent_critical * 10
        
        # Bonus for successful repairs
        if self.healing_stats['total_repair_attempts'] > 0:
            repair_rate = self.healing_stats['total_errors_repaired'] / self.healing_stats['total_repair_attempts']
            health_score += repair_rate * 10
        
        health_score = max(0, min(100, health_score))
        
        return {
            "health_score": health_score,
            "status": self._health_status(health_score),
            "active_errors": len(self.active_errors),
            "recent_errors": len(recent_errors),
            "error_by_category": error_by_category,
            "error_by_severity": error_by_severity,
            "healing_agent_performance": {
                agent_id: {
                    "name": agent.name,
                    "success_rate": agent.success_rate,
                    "errors_handled": agent.errors_handled
                }
                for agent_id, agent in self.healing_agents.items()
            }
        }
    
    def _health_status(self, score: float) -> str:
        """Convert health score to status"""
        if score >= 90:
            return "EXCELLENT"
        elif score >= 75:
            return "GOOD"
        elif score >= 50:
            return "FAIR"
        elif score >= 25:
            return "POOR"
        else:
            return "CRITICAL"
    
    def get_healing_statistics(self) -> Dict[str, Any]:
        """Get comprehensive healing statistics"""
        repair_success_rate = 0.0
        if self.healing_stats['total_repair_attempts'] > 0:
            repair_success_rate = (self.healing_stats['total_errors_repaired'] / 
                                  self.healing_stats['total_repair_attempts'])
        
        return {
            "stats": self.healing_stats,
            "repair_success_rate": repair_success_rate,
            "active_errors": len(self.active_errors),
            "known_solutions": len(self.error_database.solutions),
            "healing_agents": len(self.healing_agents)
        }

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - HEALING - %(levelname)s - %(message)s')
    
    # Initialize healing system
    healing = OmegaHealingSystem()
    
    # Simulate various errors
    healing.report_error(ErrorCategory.AGENT_FAILURE, ErrorSeverity.HIGH,
                        "Agent Alpha stopped responding", module="omega_core")
    
    healing.report_error(ErrorCategory.MEMORY_LEAK, ErrorSeverity.MEDIUM,
                        "Memory usage exceeding threshold", module="omega_memory")
    
    healing.report_error(ErrorCategory.NETWORK_ERROR, ErrorSeverity.HIGH,
                        "Connection timeout to swarm server", module="omega_swarm")
    
    healing.report_error(ErrorCategory.DATABASE_ERROR, ErrorSeverity.CRITICAL,
                        "Database corruption detected", module="omega_memory")
    
    # Diagnose system health
    health = healing.diagnose_system_health()
    
    print("\n" + "="*70)
    print("SYSTEM HEALTH DIAGNOSIS")
    print("="*70)
    print(f"Health Score: {health['health_score']:.1f}/100 ({health['status']})")
    print(f"Active Errors: {health['active_errors']}")
    print(f"Recent Errors: {health['recent_errors']}")
    print("\nError Distribution:")
    for category, count in health['error_by_category'].items():
        print(f"  {category}: {count}")
    
    # Healing statistics
    stats = healing.get_healing_statistics()
    print("\n" + "="*70)
    print("HEALING STATISTICS")
    print("="*70)
    print(f"Total Errors Detected: {stats['stats']['total_errors_detected']}")
    print(f"Total Errors Repaired: {stats['stats']['total_errors_repaired']}")
    print(f"Repair Success Rate: {stats['repair_success_rate']:.1%}")
    print(f"Auto-Heals: {stats['stats']['auto_heals']}")
    print(f"Known Solutions: {stats['known_solutions']}")
