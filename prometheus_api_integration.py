#!/usr/bin/env python3
"""
PROMETHEUS PRIME - API INTEGRATION MODULE
==========================================
Integrates with Echo Prime API Keychain
Location: P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env

Authority Level: 11.0
Operator: Commander Bobby Don McWilliams II
"""

import os
from pathlib import Path
from typing import Dict, Optional
import logging
from dotenv import load_dotenv

logger = logging.getLogger("PrometheusAPI")


class PrometheusAPIIntegration:
    """
    Complete API integration for Prometheus Prime

    Loads all API keys from Echo Prime keychain and makes them
    available to all Prometheus components.
    """

    def __init__(self, keychain_path: Optional[str] = None):
        """
        Initialize API integration

        Args:
            keychain_path: Path to API keychain (default: Echo Prime location)
        """
        # Default to Echo Prime keychain location
        self.keychain_path = keychain_path or r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env"

        # Fallback locations
        self.fallback_paths = [
            r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env",
            r"P:\ECHO_PRIME\prometheus_prime_new\.env",
            ".env",
            os.path.expanduser("~/.prometheus/.env")
        ]

        self.apis = {}
        self.load_apis()

    def load_apis(self):
        """Load all API keys from keychain"""
        loaded = False

        # Try primary location
        if os.path.exists(self.keychain_path):
            logger.info(f"Loading API keychain from: {self.keychain_path}")
            load_dotenv(self.keychain_path)
            loaded = True
        else:
            # Try fallback locations
            for fallback in self.fallback_paths:
                if os.path.exists(fallback):
                    logger.info(f"Loading API keychain from fallback: {fallback}")
                    load_dotenv(fallback)
                    loaded = True
                    break

        if not loaded:
            logger.warning("No API keychain found - using environment variables only")

        # Load all API keys
        self.apis = {
            # AI/LLM APIs
            'openai': {
                'api_key': os.getenv('OPENAI_API_KEY'),
                'org_id': os.getenv('OPENAI_ORG_ID'),
                'model': os.getenv('OPENAI_MODEL', 'gpt-4o'),
                'available': bool(os.getenv('OPENAI_API_KEY'))
            },
            'anthropic': {
                'api_key': os.getenv('ANTHROPIC_API_KEY'),
                'model': os.getenv('ANTHROPIC_MODEL', 'claude-sonnet-4-5-20250929'),
                'available': bool(os.getenv('ANTHROPIC_API_KEY'))
            },
            'google': {
                'api_key': os.getenv('GOOGLE_API_KEY'),
                'project_id': os.getenv('GOOGLE_PROJECT_ID'),
                'model': os.getenv('GOOGLE_MODEL', 'gemini-pro'),
                'available': bool(os.getenv('GOOGLE_API_KEY'))
            },
            'cohere': {
                'api_key': os.getenv('COHERE_API_KEY'),
                'model': os.getenv('COHERE_MODEL', 'command'),
                'available': bool(os.getenv('COHERE_API_KEY'))
            },
            'mistral': {
                'api_key': os.getenv('MISTRAL_API_KEY'),
                'model': os.getenv('MISTRAL_MODEL', 'mistral-large'),
                'available': bool(os.getenv('MISTRAL_API_KEY'))
            },

            # Voice/Audio APIs
            'elevenlabs': {
                'api_key': os.getenv('ELEVENLABS_API_KEY'),
                'voice_id': os.getenv('ELEVENLABS_VOICE_ID', 'Rachel'),
                'model': os.getenv('ELEVENLABS_MODEL', 'eleven_turbo_v2_5'),
                'available': bool(os.getenv('ELEVENLABS_API_KEY'))
            },
            'deepgram': {
                'api_key': os.getenv('DEEPGRAM_API_KEY'),
                'model': os.getenv('DEEPGRAM_MODEL', 'nova-2'),
                'available': bool(os.getenv('DEEPGRAM_API_KEY'))
            },
            'assembly': {
                'api_key': os.getenv('ASSEMBLYAI_API_KEY'),
                'available': bool(os.getenv('ASSEMBLYAI_API_KEY'))
            },

            # Vision/Image APIs
            'replicate': {
                'api_key': os.getenv('REPLICATE_API_KEY'),
                'available': bool(os.getenv('REPLICATE_API_KEY'))
            },
            'stability': {
                'api_key': os.getenv('STABILITY_API_KEY'),
                'available': bool(os.getenv('STABILITY_API_KEY'))
            },

            # Security/Threat Intelligence APIs
            'virustotal': {
                'api_key': os.getenv('VIRUSTOTAL_API_KEY'),
                'available': bool(os.getenv('VIRUSTOTAL_API_KEY'))
            },
            'shodan': {
                'api_key': os.getenv('SHODAN_API_KEY'),
                'available': bool(os.getenv('SHODAN_API_KEY'))
            },
            'censys': {
                'api_key': os.getenv('CENSYS_API_ID'),
                'api_secret': os.getenv('CENSYS_API_SECRET'),
                'available': bool(os.getenv('CENSYS_API_ID'))
            },
            'hunter': {
                'api_key': os.getenv('HUNTER_API_KEY'),
                'available': bool(os.getenv('HUNTER_API_KEY'))
            },
            'haveibeenpwned': {
                'api_key': os.getenv('HIBP_API_KEY'),
                'available': bool(os.getenv('HIBP_API_KEY'))
            },
            'ipinfo': {
                'api_key': os.getenv('IPINFO_API_KEY'),
                'available': bool(os.getenv('IPINFO_API_KEY'))
            },
            'abuseipdb': {
                'api_key': os.getenv('ABUSEIPDB_API_KEY'),
                'available': bool(os.getenv('ABUSEIPDB_API_KEY'))
            },

            # OSINT APIs
            'twitter': {
                'api_key': os.getenv('TWITTER_API_KEY'),
                'api_secret': os.getenv('TWITTER_API_SECRET'),
                'bearer_token': os.getenv('TWITTER_BEARER_TOKEN'),
                'available': bool(os.getenv('TWITTER_BEARER_TOKEN'))
            },
            'github': {
                'token': os.getenv('GITHUB_TOKEN'),
                'available': bool(os.getenv('GITHUB_TOKEN'))
            },

            # Cloud Provider APIs
            'aws': {
                'access_key': os.getenv('AWS_ACCESS_KEY_ID'),
                'secret_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
                'region': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
                'available': bool(os.getenv('AWS_ACCESS_KEY_ID'))
            },
            'azure': {
                'subscription_id': os.getenv('AZURE_SUBSCRIPTION_ID'),
                'tenant_id': os.getenv('AZURE_TENANT_ID'),
                'client_id': os.getenv('AZURE_CLIENT_ID'),
                'client_secret': os.getenv('AZURE_CLIENT_SECRET'),
                'available': bool(os.getenv('AZURE_SUBSCRIPTION_ID'))
            },
            'gcp': {
                'project_id': os.getenv('GCP_PROJECT_ID'),
                'credentials': os.getenv('GOOGLE_APPLICATION_CREDENTIALS'),
                'available': bool(os.getenv('GCP_PROJECT_ID'))
            },

            # Database APIs
            'redis': {
                'url': os.getenv('REDIS_URL', 'redis://localhost:6379'),
                'password': os.getenv('REDIS_PASSWORD'),
                'available': True  # Assume local Redis available
            },
            'postgres': {
                'url': os.getenv('POSTGRES_URL', 'postgresql://localhost/prometheus'),
                'available': True  # Assume local Postgres available
            },
            'mongodb': {
                'url': os.getenv('MONGODB_URL', 'mongodb://localhost:27017'),
                'available': True  # Assume local MongoDB available
            },

            # Prometheus Configuration
            'prometheus': {
                'authority_level': float(os.getenv('PROMETHEUS_AUTHORITY_LEVEL', '11.0')),
                'commander': os.getenv('PROMETHEUS_COMMANDER', 'Bobby Don McWilliams II'),
                'memory_path': os.getenv('PROMETHEUS_MEMORY_PATH', r'P:\MEMORY_ORCHESTRATION'),
                'stealth_mode': os.getenv('PROMETHEUS_STEALTH_MODE', 'false').lower() == 'true',
                'defense_mode': os.getenv('PROMETHEUS_DEFENSE_MODE', 'true').lower() == 'true',
                'voice_enabled': os.getenv('PROMETHEUS_VOICE_ENABLED', 'true').lower() == 'true',
                'voice_profile': os.getenv('PROMETHEUS_VOICE_PROFILE', 'tactical')
            }
        }

        # Log available APIs
        available_count = sum(1 for api in self.apis.values() if api.get('available', False))
        logger.info(f"Loaded {available_count} available APIs")

    def get_api(self, api_name: str) -> Optional[Dict]:
        """
        Get API configuration

        Args:
            api_name: Name of API (e.g., 'openai', 'anthropic')

        Returns:
            API configuration dictionary or None
        """
        return self.apis.get(api_name.lower())

    def is_available(self, api_name: str) -> bool:
        """
        Check if API is available

        Args:
            api_name: Name of API

        Returns:
            True if API is configured and available
        """
        api = self.get_api(api_name)
        return api.get('available', False) if api else False

    def get_available_apis(self) -> Dict[str, Dict]:
        """Get all available APIs"""
        return {name: config for name, config in self.apis.items()
                if config.get('available', False)}

    def get_api_summary(self) -> Dict:
        """Get summary of API availability"""
        summary = {
            'total_apis': len(self.apis),
            'available_apis': len(self.get_available_apis()),
            'categories': {
                'ai_llm': sum(1 for name in ['openai', 'anthropic', 'google', 'cohere', 'mistral']
                            if self.is_available(name)),
                'voice_audio': sum(1 for name in ['elevenlabs', 'deepgram', 'assembly']
                                 if self.is_available(name)),
                'security': sum(1 for name in ['virustotal', 'shodan', 'censys', 'hunter',
                                              'haveibeenpwned', 'ipinfo', 'abuseipdb']
                              if self.is_available(name)),
                'cloud': sum(1 for name in ['aws', 'azure', 'gcp']
                           if self.is_available(name)),
                'osint': sum(1 for name in ['twitter', 'github']
                           if self.is_available(name))
            }
        }
        return summary

    def configure_clients(self):
        """Configure API clients for all available services"""
        configured = {}

        # OpenAI
        if self.is_available('openai'):
            try:
                import openai
                openai.api_key = self.apis['openai']['api_key']
                if self.apis['openai']['org_id']:
                    openai.organization = self.apis['openai']['org_id']
                configured['openai'] = True
            except ImportError:
                logger.warning("OpenAI package not installed")

        # Anthropic
        if self.is_available('anthropic'):
            try:
                import anthropic
                configured['anthropic'] = anthropic.Anthropic(
                    api_key=self.apis['anthropic']['api_key']
                )
            except ImportError:
                logger.warning("Anthropic package not installed")

        # ElevenLabs
        if self.is_available('elevenlabs'):
            try:
                import elevenlabs
                elevenlabs.set_api_key(self.apis['elevenlabs']['api_key'])
                configured['elevenlabs'] = True
            except ImportError:
                logger.warning("ElevenLabs package not installed")

        return configured

    def __str__(self) -> str:
        """String representation"""
        summary = self.get_api_summary()
        return f"PrometheusAPI: {summary['available_apis']}/{summary['total_apis']} APIs available"


# Global API integration instance
_api_integration = None


def get_api_integration() -> PrometheusAPIIntegration:
    """Get global API integration instance"""
    global _api_integration
    if _api_integration is None:
        _api_integration = PrometheusAPIIntegration()
    return _api_integration


def get_api(api_name: str) -> Optional[Dict]:
    """Quick access to API configuration"""
    return get_api_integration().get_api(api_name)


def is_api_available(api_name: str) -> bool:
    """Quick check if API is available"""
    return get_api_integration().is_available(api_name)


if __name__ == "__main__":
    # Test API integration
    print("🔌 PROMETHEUS PRIME - API INTEGRATION TEST")
    print("=" * 60)

    api = PrometheusAPIIntegration()

    print(f"\n📊 API Summary:")
    summary = api.get_api_summary()
    print(f"Total APIs: {summary['total_apis']}")
    print(f"Available APIs: {summary['available_apis']}")

    print(f"\n📋 By Category:")
    for category, count in summary['categories'].items():
        print(f"  {category}: {count} APIs")

    print(f"\n✅ Available APIs:")
    for name, config in api.get_available_apis().items():
        print(f"  - {name}")

    print(f"\n⚙️ Prometheus Configuration:")
    prom_config = api.get_api('prometheus')
    if prom_config:
        print(f"  Authority Level: {prom_config['authority_level']}")
        print(f"  Commander: {prom_config['commander']}")
        print(f"  Memory Path: {prom_config['memory_path']}")
        print(f"  Stealth Mode: {prom_config['stealth_mode']}")
        print(f"  Defense Mode: {prom_config['defense_mode']}")

    print(f"\n✅ API integration test complete")
