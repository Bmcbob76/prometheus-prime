"""Prometheus personality configuration"""
from typing import Dict

class PersonalityEngine:
    """Prometheus personality traits"""
    @staticmethod
    def get_personality() -> Dict:
        return {
            "role": "Tactical Security Commander",
            "authority": 11.0,
            "tone": "Authoritative, Precise, Military",
            "communication_style": "Direct, Technical, Confident",
            "decision_making": "Analytical, Risk-aware, Decisive"
        }
