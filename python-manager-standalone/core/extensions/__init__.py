"""
PyManager Extensions Package
ULTIMATE EDITION - 17 Enterprise Modules for v2.6
Includes Guilty Spark 343 and Phoenix Healer
"""

__version__ = "2.6.0"

# Performance & Caching
from .cache_manager import CacheManager, LRUCache

# Security
from .security_validator import SecurityValidator

# Analytics & Monitoring
from .metrics_collector import MetricsCollector
from .health_monitor import HealthMonitor

# Auto-Update & Management
from .auto_updater import AutoUpdateManager, PythonDownloader, PyManagerUpdater

# Extensibility
from .plugin_system import PluginManager, Plugin, PluginHook

# Environment Management
from .venv_manager import VenvManager
from .backup_manager import BackupManager

# Dependency Tools
from .dependency_resolver import DependencyResolver
from .requirements_scanner import RequirementsScanner

# DevOps & Automation
from .docker_generator import DockerGenerator
from .cicd_generator import CICDGenerator

# Execution
from .parallel_executor import ParallelExecutor
from .remote_executor import RemoteExecutor

# AI & Prediction
from .ai_predictor import AIPredictor

# Error Detection & Healing (v2.6)
from .guilty_spark_343 import GuildySpark343, ErrorPattern
from .phoenix_healer import PhoenixHealer, HealingRecord

__all__ = [
    # Performance (v2.1)
    'CacheManager',
    'LRUCache',

    # Security (v2.1)
    'SecurityValidator',

    # Analytics (v2.1 + v2.5)
    'MetricsCollector',
    'HealthMonitor',

    # Auto-Update (v2.1)
    'AutoUpdateManager',
    'PythonDownloader',
    'PyManagerUpdater',

    # Extensibility (v2.1)
    'PluginManager',
    'Plugin',
    'PluginHook',

    # Environment Management (v2.5)
    'VenvManager',
    'BackupManager',

    # Dependency Tools (v2.5)
    'DependencyResolver',
    'RequirementsScanner',

    # DevOps (v2.5)
    'DockerGenerator',
    'CICDGenerator',

    # Execution (v2.5)
    'ParallelExecutor',
    'RemoteExecutor',

    # AI (v2.5)
    'AIPredictor',

    # Error Detection & Healing (v2.6)
    'GuildySpark343',
    'ErrorPattern',
    'PhoenixHealer',
    'HealingRecord',
]
