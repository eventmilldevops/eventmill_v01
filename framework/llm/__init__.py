"""
Event Mill LLM Integration

MCP client wrapper and context management for LLM interactions.
Plugins access the LLM exclusively through this interface.
"""

from .client import (
    ContextBuilder,
    LLMDispatcher,
    MCPLLMClient,
    TieredLLMClient,
    TierScopedLLMClient,
)
from .providers import TierSpec, load_tier_specs

__all__ = [
    "ContextBuilder",
    "MCPLLMClient",
    "LLMDispatcher",
    "TieredLLMClient",
    "TierScopedLLMClient",
    "TierSpec",
    "load_tier_specs",
]
