"""
X1200 UNIFIED SWARM BRAIN - CORE MODULE
Authority Level: 11.0
Commander: Bobby Don McWilliams II

Core components:
- Agent: Individual intelligence units
- Guild: Collective intelligence groups
- SupremeCommand: Hexarchy Council + Omega Commanders
- X1200Brain: Complete brain orchestrator
"""

from .agent import Agent, AgentTier, ConsciousnessLevel, EVOLUTION_REQUIREMENTS
from .guild import Guild, GuildMetrics
from .supreme_command import (
    HexarchyCouncil,
    OmegaCommanders,
    SupremeCommand,
    HexarchRole
)
from .brain_master import X1200Brain

__all__ = [
    'Agent',
    'AgentTier',
    'ConsciousnessLevel',
    'EVOLUTION_REQUIREMENTS',
    'Guild',
    'GuildMetrics',
    'HexarchyCouncil',
    'OmegaCommanders',
    'SupremeCommand',
    'HexarchRole',
    'X1200Brain'
]

__version__ = '1.0.0'
__author__ = 'Commander Bobby Don McWilliams II'
__authority__ = '11.0'
