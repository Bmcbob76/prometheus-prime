#!/usr/bin/env python3
"""
PROMETHEUS PRIME - VOICE SYNTHESIS MODULE
==========================================
Authority Level: 11.0
Voice ID: BVZ5M1JnNXres6AkVgxe

Ultra-deep bass voice optimized for cybersecurity authority
"""

import os
import requests
import json
from typing import Optional

class PrometheusVoice:
    """Voice synthesis for Prometheus Prime using ElevenLabs"""
    
    def __init__(self):
        # Load API key from keychain if available
        keychain_path = r'P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env'
        api_keys = []
        
        if os.path.exists(keychain_path):
            # Load from keychain file
            try:
                with open(keychain_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('ELEVENLABS_API_KEY='):
                            # Extract key value
                            key_value = line.split('=', 1)[1].strip()
                            if key_value and not key_value.startswith('#'):
                                api_keys.append(key_value)
            except Exception as e:
                print(f"Warning: Could not load keychain: {e}")
        
        # Use the last (most recent) API key from keychain
        if api_keys:
            self.api_key = api_keys[-1]
            print(f"✅ Loaded API key from keychain (key #{len(api_keys)})")
        else:
            # Default fallback
            self.api_key = 'sk_2c0f0020651d25cc93485dfabfe000b7d3355f930ad44ea5'
            print("⚠️  Using default API key")
        
        # Get configuration from environment (overrides keychain)
        if os.getenv('ELEVENLABS_API_KEY'):
            self.api_key = os.getenv('ELEVENLABS_API_KEY')
            print("✅ API key overridden from environment variable")
        
        # Get voice ID
        self.voice_id = os.getenv('PROMETHEUS_VOICE_ID', 'BVZ5M1JnNXres6AkVgxe')
        
        # Voice settings optimized for deep bass authority
        self.settings = {
            'stability': float(os.getenv('PROMETHEUS_STABILITY', '0.75')),
            'similarity_boost': float(os.getenv('PROMETHEUS_SIMILARITY', '0.95')),
            'style': float(os.getenv('PROMETHEUS_STYLE', '0.65')),
            'use_speaker_boost': os.getenv('PROMETHEUS_SPEAKER_BOOST', 'true').lower() == 'true'
        }
        
        self.model = os.getenv('PROMETHEUS_MODEL', 'eleven_turbo_v3')
        self.output_format = os.getenv('PROMETHEUS_OUTPUT_FORMAT', 'mp3_44100_128')
        
        self.base_url = 'https://api.elevenlabs.io/v1'
        
    def synthesize(self, text: str, output_path: Optional[str] = None) -> bytes:
        """
        Synthesize text to speech using Prometheus Prime voice
        
        Args:
            text: Text to synthesize
            output_path: Optional path to save audio file
            
        Returns:
            Audio bytes
        """
        url = f'{self.base_url}/text-to-speech/{self.voice_id}'
        
        headers = {
            'Accept': 'audio/mpeg',
            'Content-Type': 'application/json',
            'xi-api-key': self.api_key
        }
        
        payload = {
            'text': text,
            'model_id': self.model,
            'voice_settings': self.settings
        }
        
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        audio_data = response.content
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(audio_data)
                
        return audio_data
    
    def announce_launch(self) -> bytes:
        """Prometheus Prime launch announcement"""
        text = """Prometheus Prime Omega Brain activated. 
        Authority Level Eleven Point Zero confirmed. 
        Twenty-nine capabilities online. 
        Memory orchestration synchronized. 
        Ready for command, Commander."""
        
        return self.synthesize(text)
    
    def announce_capability_ready(self, capability: str) -> bytes:
        """Announce capability ready status"""
        text = f"{capability} capability ready for execution."
        return self.synthesize(text)
    
    def announce_operation_complete(self, capability: str, success: bool) -> bytes:
        """Announce operation completion"""
        status = "successful" if success else "failed"
        text = f"{capability} operation {status}. Results stored in memory orchestration."
        return self.synthesize(text)
    
    def announce_target_acquired(self, target: str) -> bytes:
        """Announce target acquisition"""
        text = f"Target acquired: {target}. Initiating reconnaissance."
        return self.synthesize(text)
    
    def announce_credentials_harvested(self, count: int) -> bytes:
        """Announce credential harvest"""
        text = f"Credentials harvested: {count} accounts. Stored in memory vault."
        return self.synthesize(text)
    
    def get_voice_info(self) -> dict:
        """Get voice configuration information"""
        return {
            'voice_id': self.voice_id,
            'model': self.model,
            'output_format': self.output_format,
            'settings': self.settings,
            'api_configured': bool(self.api_key)
        }

# Global instance
_prometheus_voice = None

def get_voice() -> PrometheusVoice:
    """Get or create Prometheus voice instance"""
    global _prometheus_voice
    if _prometheus_voice is None:
        _prometheus_voice = PrometheusVoice()
    return _prometheus_voice

def speak(text: str, output_path: Optional[str] = None) -> bytes:
    """Quick function to synthesize text"""
    voice = get_voice()
    return voice.synthesize(text, output_path)

if __name__ == '__main__':
    # Test voice synthesis
    voice = get_voice()
    
    print("🔥 Prometheus Prime Voice Test")
    print("=" * 50)
    print(f"Voice ID: {voice.voice_id}")
    print(f"Model: {voice.model}")
    print(f"Settings: {json.dumps(voice.settings, indent=2)}")
    print("=" * 50)
    
    # Test announcement
    print("\nGenerating launch announcement...")
    audio = voice.announce_launch()
    
    output_file = 'prometheus_launch_test.mp3'
    with open(output_file, 'wb') as f:
        f.write(audio)
    
    print(f"✅ Audio saved to: {output_file}")
    print(f"✅ Size: {len(audio)} bytes")
