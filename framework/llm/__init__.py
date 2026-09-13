"""
Event Mill LLM Integration

The dispatcher routes across a provider's model tiers; provider clients live in
framework/llm/clients/ and each owns its own SDK. Plugins access the LLM
exclusively through this interface, never a client directly.
"""

from .clients.gemini import GeminiClient
from .dispatcher import (
    ContextBuilder,
    LLMDispatcher,
    TierScopedLLMClient,
)
from .model_client import LLMModelClient
from .providers import TierSpec, load_tier_specs

__all__ = [
    "ContextBuilder",
    "GeminiClient",
    "LLMDispatcher",
    "LLMModelClient",
    "TierScopedLLMClient",
    "TierSpec",
    "load_tier_specs",
]
