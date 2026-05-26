"""
Event Mill LLM Backends

Explicit registry of provider-specific backends.
New providers add an entry here and a sibling module.
"""

from .base import LLMBackend, ModelCapabilities, DocumentPart
from .gemini import GeminiBackend

# Explicit registry — no dynamic import from JSON strings.
# To add a provider: create backends/<name>.py, add entry here.
BACKEND_REGISTRY: dict[str, type[LLMBackend]] = {
    "gcp_gemini": GeminiBackend,
}

__all__ = [
    "LLMBackend",
    "ModelCapabilities",
    "DocumentPart",
    "GeminiBackend",
    "BACKEND_REGISTRY",
]
