"""
API CLIENTS FOR CLOUD AI MODELS
Claude Sonnet 4, GPT-4 Turbo, Gemini Pro
"""

import asyncio
from typing import Optional
import logging


class ClaudeClient:
    """Anthropic Claude API client"""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
        self.logger = logging.getLogger("ClaudeClient")
        self.client = None

        if api_key:
            try:
                from anthropic import AsyncAnthropic
                self.client = AsyncAnthropic(api_key=api_key)
                self.logger.info(f"✅ Claude client initialized: {model}")
            except ImportError:
                self.logger.warning("⚠️  anthropic package not installed")

    async def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        """Generate completion from Claude"""
        if not self.client:
            return self._mock_response()

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text

        except Exception as e:
            self.logger.error(f"Claude API error: {e}")
            return self._mock_response()

    def _mock_response(self) -> str:
        """Mock response for testing"""
        return """{
    "domain": "web_exploitation",
    "operation": "enumerate",
    "parameters": {"target": "example.com"},
    "rationale": "Web application enumeration to identify attack surface",
    "risk_level": "medium",
    "expected_outcome": "Discovery of web technologies and potential vulnerabilities"
}"""


class OpenAIClient:
    """OpenAI GPT-4 API client"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4-turbo"):
        self.api_key = api_key
        self.model = model
        self.logger = logging.getLogger("OpenAIClient")
        self.client = None

        if api_key:
            try:
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(api_key=api_key)
                self.logger.info(f"✅ OpenAI client initialized: {model}")
            except ImportError:
                self.logger.warning("⚠️  openai package not installed")

    async def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        """Generate completion from GPT-4"""
        if not self.client:
            return self._mock_response()

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content

        except Exception as e:
            self.logger.error(f"OpenAI API error: {e}")
            return self._mock_response()

    def _mock_response(self) -> str:
        """Mock response for testing"""
        return """{
    "domain": "osint_reconnaissance",
    "operation": "gather",
    "parameters": {"target": "example.com"},
    "rationale": "OSINT gathering for threat intelligence",
    "risk_level": "low",
    "expected_outcome": "Collection of publicly available information"
}"""


class GeminiClient:
    """Google Gemini API client"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-pro"):
        self.api_key = api_key
        self.model = model
        self.logger = logging.getLogger("GeminiClient")
        self.client = None

        if api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=api_key)
                self.client = genai.GenerativeModel(model)
                self.logger.info(f"✅ Gemini client initialized: {model}")
            except ImportError:
                self.logger.warning("⚠️  google-generativeai package not installed")

    async def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        """Generate completion from Gemini"""
        if not self.client:
            return self._mock_response()

        try:
            response = await asyncio.to_thread(
                self.client.generate_content,
                prompt
            )
            return response.text

        except Exception as e:
            self.logger.error(f"Gemini API error: {e}")
            return self._mock_response()

    def _mock_response(self) -> str:
        """Mock response for testing"""
        return """{
    "domain": "threat_intelligence",
    "operation": "analyze",
    "parameters": {"target": "example.com"},
    "rationale": "Threat intelligence analysis for known IOCs",
    "risk_level": "medium",
    "expected_outcome": "Identification of threat actor activity"
}"""


if __name__ == "__main__":
    # Test API clients
    async def test():
        print("🧪 API CLIENTS TEST")
        print("=" * 60)

        # Test Claude (mock)
        claude = ClaudeClient()
        print("\n🤖 Testing Claude...")
        response = await claude.complete("Test prompt")
        print(f"Response: {response[:100]}...")

        # Test GPT-4 (mock)
        gpt4 = OpenAIClient()
        print("\n🤖 Testing GPT-4...")
        response = await gpt4.complete("Test prompt")
        print(f"Response: {response[:100]}...")

        # Test Gemini (mock)
        gemini = GeminiClient()
        print("\n🤖 Testing Gemini...")
        response = await gemini.complete("Test prompt")
        print(f"Response: {response[:100]}...")

        print("\n✅ All clients tested (mock mode)")

    asyncio.run(test())
