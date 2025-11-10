"""
PROMETHEUS VOICE - Text-to-Speech System
ElevenLabs Integration - Single Prometheus Personality

Authority Level: 11.0
Voice: Military Tactical Commander
"""

import asyncio
from typing import Optional, Dict
import logging
from pathlib import Path


class PrometheusVoice:
    """
    Prometheus Voice System - ElevenLabs TTS

    Single authoritative voice for all Prometheus communications.
    Personality: Tactical military commander with technical precision.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger("PrometheusVoice")
        self.logger.setLevel(logging.INFO)

        # ElevenLabs configuration
        self.api_key = self.config.get("elevenlabs_api_key")
        self.voice_id = self.config.get("voice_id", "prometheus_prime")
        self.model = self.config.get("model", "eleven_monolingual_v1")

        # Personality settings
        self.personality = {
            "tone": "authoritative_tactical",
            "style": "military_precision",
            "authority_level": 11.0,
            "formality": "high"
        }

        # Voice parameters
        self.voice_settings = {
            "stability": 0.75,
            "similarity_boost": 0.85,
            "style": 0.5,
            "use_speaker_boost": True
        }

        self.client = None
        self._initialize_client()

        self.logger.info("🎙️  PROMETHEUS VOICE INITIALIZED")

    def _initialize_client(self):
        """Initialize ElevenLabs client"""
        if not self.api_key:
            self.logger.warning("⚠️  ElevenLabs API key not configured - using mock mode")
            return

        try:
            from elevenlabs import Voice, VoiceSettings
            from elevenlabs.client import ElevenLabs

            self.client = ElevenLabs(api_key=self.api_key)
            self.logger.info("✅ ElevenLabs client initialized")

        except ImportError:
            self.logger.warning("⚠️  elevenlabs package not installed")
            self.client = None

    async def speak(self, text: str, emotion: str = "neutral") -> bytes:
        """
        Generate and return audio for text.

        Args:
            text: Text to speak
            emotion: Emotion modifier (neutral, urgent, tactical, warning)

        Returns:
            Audio bytes (MP3)
        """
        self.logger.info(f"🎙️  Speaking: {text[:50]}...")

        # Adjust voice settings based on emotion
        settings = self._adjust_for_emotion(emotion)

        if self.client:
            try:
                audio = await asyncio.to_thread(
                    self.client.generate,
                    text=text,
                    voice=self.voice_id,
                    model=self.model,
                    voice_settings=settings
                )
                return audio

            except Exception as e:
                self.logger.error(f"❌ Voice generation failed: {e}")
                return b""
        else:
            # Mock mode
            self.logger.info(f"🔇 MOCK: {text}")
            return b""

    async def announce_operation(self, operation: Dict):
        """Announce security operation"""
        domain = operation.get("domain", "unknown")
        op = operation.get("operation", "unknown")

        text = f"Prometheus Prime. Initiating {domain} operation. Executing {op}. Authority level 11."
        await self.speak(text, emotion="tactical")

    async def report_results(self, results: Dict):
        """Report operation results"""
        success = results.get("success", False)
        findings_count = len(results.get("findings", []))

        if success:
            text = f"Operation completed. {findings_count} findings identified. Standing by for next directive."
        else:
            text = f"Operation encountered obstacles. Phoenix recovery protocol engaged."

        await self.speak(text, emotion="neutral")

    async def alert(self, severity: str, message: str):
        """Voice alert for critical events"""
        prefix = {
            "low": "Advisory",
            "medium": "Alert",
            "high": "Warning",
            "critical": "Critical alert"
        }.get(severity, "Notice")

        text = f"{prefix}. {message}"
        await self.speak(text, emotion="urgent")

    def _adjust_for_emotion(self, emotion: str) -> Dict:
        """Adjust voice settings based on emotion"""
        adjustments = {
            "neutral": {"stability": 0.75, "similarity_boost": 0.85},
            "urgent": {"stability": 0.60, "similarity_boost": 0.90},
            "tactical": {"stability": 0.85, "similarity_boost": 0.80},
            "warning": {"stability": 0.70, "similarity_boost": 0.95}
        }

        settings = self.voice_settings.copy()
        settings.update(adjustments.get(emotion, {}))
        return settings

    def get_status(self) -> Dict:
        """Get voice system status"""
        return {
            "initialized": self.client is not None,
            "voice_id": self.voice_id,
            "personality": self.personality,
            "mock_mode": self.client is None
        }


if __name__ == "__main__":
    async def test():
        print("🎙️  PROMETHEUS VOICE TEST")
        print("=" * 60)

        voice = PrometheusVoice()

        print(f"\n📊 Status:")
        status = voice.get_status()
        for key, value in status.items():
            print(f"  {key}: {value}")

        print(f"\n🗣️  Testing voice generation...")
        await voice.speak("Prometheus Prime operational. All systems nominal.")
        await voice.announce_operation({"domain": "network_recon", "operation": "scan"})
        await voice.alert("critical", "Unauthorized access detected")

        print("\n✅ Voice system test complete")

    asyncio.run(test())
