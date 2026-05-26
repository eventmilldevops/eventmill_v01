"""
Event Mill LLM Backend — Abstract Base

Defines the provider-specific backend interface that each cloud vendor
implements. One instance per model (e.g., one GeminiBackend for Flash,
one for Pro). The LLMDispatcher holds backends and routes between them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ...plugins.protocol import LLMResponse


@dataclass
class ModelCapabilities:
    """Declared capabilities of a connected model."""
    model_id: str = ""
    tier: str = "light"
    native_document_types: list[str] = field(default_factory=list)
    native_image_types: list[str] = field(default_factory=list)
    max_context_tokens: int = 128_000
    max_output_tokens: int = 8192
    supports_structured_output: bool = False
    supports_reasoning: bool = False


@dataclass
class DocumentPart:
    """A document to include in an LLM request.

    Exactly one of storage_uri, file_path, or inline_bytes should be set.
    The backend tries them in priority order: storage_uri > file_path > inline_bytes.
    """
    mime_type: str
    storage_uri: str | None = None     # gs://, s3:// — preferred (zero-copy)
    file_path: str | None = None       # local filesystem path — fallback
    inline_bytes: bytes | None = None  # raw bytes — last resort


class LLMBackend(ABC):
    """Abstract backend for a specific LLM provider + model.

    One instance per model. The LLMDispatcher holds one per tier.
    Implementations live in sibling modules (gemini.py, etc.).
    """

    @abstractmethod
    def connect(self, api_key: str | None = None) -> bool:
        """Initialize the provider SDK connection.

        Args:
            api_key: API key for the provider.

        Returns:
            True if connection succeeded.
        """
        ...

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Whether this backend has an active connection."""
        ...

    @property
    @abstractmethod
    def model_id(self) -> str:
        """The model identifier string (e.g. 'gemini-2.5-flash')."""
        ...

    @abstractmethod
    def capabilities(self) -> ModelCapabilities:
        """Return this model's declared capabilities."""
        ...

    @abstractmethod
    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Plain text query."""
        ...

    @abstractmethod
    def query_with_documents(
        self,
        prompt: str,
        documents: list[DocumentPart],
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Query with one or more document parts.

        The backend resolves transport internally based on its capabilities
        (native vision, URI reference, inline bytes, or fallback).

        Args:
            prompt: The text prompt / instructions.
            documents: Document parts to include.
            system_context: Optional system context override.
            max_tokens: Maximum output tokens.

        Returns:
            LLMResponse with transport_path indicating ingestion method used.
        """
        ...

    @abstractmethod
    def query_with_images(
        self,
        prompt: str,
        images: list[tuple[bytes, str]],  # (data, mime_type)
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Query with image parts."""
        ...

    @property
    @abstractmethod
    def total_tokens_used(self) -> int:
        """Total tokens consumed across all queries in this session."""
        ...
