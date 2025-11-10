"""
PROMETHEUS AI BRAIN
Multi-Model Consensus Intelligence Engine
"""

from .multi_model_orchestrator import PrometheusAIBrain
from .local_inference import LocalLLM
from .api_clients import ClaudeClient, OpenAIClient, GeminiClient
from .gpu_manager import GPUManager

__all__ = ['PrometheusAIBrain', 'LocalLLM', 'ClaudeClient', 'OpenAIClient', 'GeminiClient', 'GPUManager']
