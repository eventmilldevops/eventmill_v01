"""
Event Mill LLM Backend — Google Gemini (GCP MVP)

Implements LLMBackend for Gemini models via the google.genai SDK.
Supports native PDF ingestion via Part.from_uri (GCS zero-copy) and
Part.from_bytes (inline).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from .base import LLMBackend, ModelCapabilities, DocumentPart
from ...plugins.protocol import LLMResponse

try:
    from google import genai
    from google.genai import types as genai_types
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

logger = logging.getLogger("eventmill.framework.llm.gemini")


class GeminiBackend(LLMBackend):
    """Gemini-specific backend using google.genai SDK.

    Handles text, image, and native document queries. For documents,
    prefers GCS URI (zero-copy) over inline bytes.
    """

    def __init__(
        self,
        model_id: str = "gemini-2.5-flash",
        tier: str = "light",
        api_key_env: str = "GEMINI_FLASH_API_KEY",
        max_retries: int = 3,
        capabilities_override: ModelCapabilities | None = None,
    ):
        self._model_id = model_id
        self._tier = tier
        self._api_key_env = api_key_env
        self._max_retries = max_retries
        self._client: Any = None  # genai.Client
        self._connected = False
        self._total_tokens_used = 0
        self._capabilities = capabilities_override or self._default_capabilities()

    def _default_capabilities(self) -> ModelCapabilities:
        """Build default capabilities from tier."""
        is_heavy = self._tier == "heavy"
        return ModelCapabilities(
            model_id=self._model_id,
            tier=self._tier,
            native_document_types=["application/pdf"],
            native_image_types=["image/jpeg", "image/png", "image/webp", "image/gif"],
            max_context_tokens=2_097_152 if is_heavy else 1_048_576,
            max_output_tokens=65_536 if is_heavy else 8_192,
            supports_structured_output=True,
            supports_reasoning=is_heavy,
        )

    # --- Connection ---

    def connect(self, api_key: str | None = None) -> bool:
        if not _HAS_GENAI:
            logger.error("google-generativeai package not installed")
            self._connected = False
            return False

        resolved_key = api_key or os.environ.get(self._api_key_env, "")
        if not resolved_key:
            logger.error("No API key for %s (env: %s)", self._model_id, self._api_key_env)
            self._connected = False
            return False

        try:
            self._client = genai.Client(
                api_key=resolved_key,
                http_options={"timeout": 120_000},
            )
            self._connected = True
            logger.info("GeminiBackend connected: %s (tier=%s)", self._model_id, self._tier)
            return True
        except Exception as e:
            logger.error("GeminiBackend connect failed for %s: %s", self._model_id, e)
            self._connected = False
            return False

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def model_id(self) -> str:
        return self._model_id

    def capabilities(self) -> ModelCapabilities:
        return self._capabilities

    @property
    def total_tokens_used(self) -> int:
        return self._total_tokens_used

    # --- Retry helper ---

    @staticmethod
    def _is_retriable(exc: Exception) -> bool:
        msg = str(exc)
        return any(marker in msg for marker in (
            "503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED",
            "DeadlineExceeded", "Timeout", "timed out",
        ))

    def _call_with_retry(self, contents: Any, config: Any) -> Any:
        """Execute generate_content with exponential backoff retry."""
        if self._client is None:
            raise RuntimeError("Backend not initialised — call connect() first")

        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.models.generate_content(
                    model=self._model_id,
                    contents=contents,
                    config=config,
                )
                if hasattr(response, "usage_metadata") and response.usage_metadata:
                    um = response.usage_metadata
                    self._total_tokens_used += getattr(um, "total_token_count", 0)
                return response
            except Exception as exc:
                if attempt < self._max_retries and self._is_retriable(exc):
                    wait = 2 ** attempt
                    logger.warning(
                        "GeminiBackend transient error (attempt %d/%d), retrying in %ds: %s",
                        attempt + 1, self._max_retries + 1, wait, exc,
                    )
                    time.sleep(wait)
                    last_exc = exc
                else:
                    raise
        raise last_exc  # type: ignore[misc]

    def _make_config(
        self, system_context: str | None, max_tokens: int,
    ) -> Any:
        """Build GenerateContentConfig."""
        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
        )
        if system_context:
            config.system_instruction = system_context
        return config

    # --- Query methods ---

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        if not self._connected:
            return LLMResponse(ok=False, error="GeminiBackend not connected")

        try:
            config = self._make_config(system_context, max_tokens)
            response = self._call_with_retry(contents=prompt, config=config)
            return LLMResponse(
                ok=True,
                text=response.text or "",
                model_used=self._model_id,
                transport_path="text",
            )
        except Exception as e:
            logger.error("GeminiBackend query_text failed: %s", e)
            return LLMResponse(ok=False, error=str(e), model_used=self._model_id)

    def query_with_documents(
        self,
        prompt: str,
        documents: list[DocumentPart],
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        if not self._connected:
            return LLMResponse(ok=False, error="GeminiBackend not connected")

        try:
            parts: list[Any] = []
            transport_path = "unknown"

            for doc in documents:
                if doc.storage_uri and doc.storage_uri.startswith("gs://"):
                    parts.append(genai_types.Part.from_uri(
                        file_uri=doc.storage_uri,
                        mime_type=doc.mime_type,
                    ))
                    transport_path = "gs_uri"
                elif doc.inline_bytes:
                    parts.append(genai_types.Part.from_bytes(
                        data=doc.inline_bytes,
                        mime_type=doc.mime_type,
                    ))
                    transport_path = "inline_bytes"
                elif doc.file_path:
                    with open(doc.file_path, "rb") as f:
                        data = f.read()
                    parts.append(genai_types.Part.from_bytes(
                        data=data,
                        mime_type=doc.mime_type,
                    ))
                    transport_path = "inline_bytes"
                else:
                    logger.warning("DocumentPart has no data source, skipping")
                    continue

            parts.append(prompt)
            config = self._make_config(system_context, max_tokens)
            response = self._call_with_retry(contents=parts, config=config)

            return LLMResponse(
                ok=True,
                text=response.text or "",
                model_used=self._model_id,
                transport_path=transport_path,
            )
        except Exception as e:
            logger.error("GeminiBackend query_with_documents failed: %s", e)
            return LLMResponse(ok=False, error=str(e), model_used=self._model_id)

    def query_with_images(
        self,
        prompt: str,
        images: list[tuple[bytes, str]],
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        if not self._connected:
            return LLMResponse(ok=False, error="GeminiBackend not connected")

        try:
            contents: list[Any] = [prompt]
            for data, mime_type in images:
                contents.append(
                    genai_types.Part.from_bytes(data=data, mime_type=mime_type)
                )

            config = self._make_config(system_context, max_tokens)
            response = self._call_with_retry(contents=contents, config=config)

            return LLMResponse(
                ok=True,
                text=response.text or "",
                model_used=self._model_id,
                transport_path="inline_bytes",
            )
        except Exception as e:
            logger.error("GeminiBackend query_with_images failed: %s", e)
            return LLMResponse(ok=False, error=str(e), model_used=self._model_id)
