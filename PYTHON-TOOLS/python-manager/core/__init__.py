"""
PyManager Core Package
Universal Python Version Router with Auto-Fix Injection
ULTIMATE EDITION v2.6 - 17 Enterprise Modules
Includes Guilty Spark 343 Error Detection & Phoenix Healer Recovery
"""

__version__ = "2.6.0"
__author__ = "Bobby Don McWilliams II"

from .dispatcher import PyManagerDispatcher
from .dependency_manager import DependencyManager, AutoFixInjector
from .profile_manager import ProfileManager
from .port_manager import PortManager

__all__ = [
    'PyManagerDispatcher',
    'DependencyManager',
    'AutoFixInjector',
    'ProfileManager',
    'PortManager',
]
