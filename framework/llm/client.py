"""
Event Mill LLM Client

MCP-based LLM client that implements the LLMQueryInterface protocol.
The framework owns the MCP connection; plugins access LLM via this client.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from ..plugins.protocol import LLMQueryInterface, LLMResponse, QueryHints, ArtifactRef
from .backends.base import DocumentPart

try:
    from google import genai
    from google.genai import types as genai_types
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

logger = logging.getLogger("eventmill.framework.llm")


class MCPLLMClient:
    """LLM client communicating via Model Context Protocol.
    
    This is the framework's LLM integration point. Plugins receive
    a reference to this client via ExecutionContext.llm_query.
    
    The client abstracts away the specific model provider (Gemini, Claude,
    GPT, etc.) behind the MCP transport layer.
    """
    
    def __init__(
        self,
        model_id: str = "gemini-2.5-flash",
        transport: str = "stdio",
        endpoint: str | None = None,
        max_retries: int = 3,
    ):
        """Initialize MCP LLM client.
        
        Args:
            model_id: Model identifier for the LLM provider.
            transport: MCP transport type (stdio or sse).
            endpoint: Provider endpoint URL (if applicable).
            max_retries: Maximum retry attempts for failed queries.
        """
        self.model_id = model_id
        self.transport = transport
        self.endpoint = endpoint
        self.max_retries = max_retries
        self._connected = False
        self._mcp_session = None
        self._genai_client = None
        self._api_key_env_var: str | None = None
        self._total_tokens_used = 0
    
    @property
    def connected(self) -> bool:
        """Whether the client is connected to the MCP server."""
        return self._connected
    
    @property
    def total_tokens_used(self) -> int:
        """Total tokens consumed across all queries in this session."""
        return self._total_tokens_used
    
    def connect(self, api_key: str | None = None) -> bool:
        """Establish connection to the LLM provider.
        
        Args:
            api_key: API key for the provider. If None, uses the
                     key from the environment variable set during init.
        
        Returns:
            True if connection succeeded.
        """
        if not _HAS_GENAI:
            logger.error("google-generativeai package not installed")
            self._connected = False
            return False
        
        resolved_key = api_key or os.environ.get(self._api_key_env_var or "", "")
        if not resolved_key:
            logger.error("No API key available for %s", self.model_id)
            self._connected = False
            return False
        
        try:
            self._genai_client = genai.Client(
                api_key=resolved_key,
                http_options={"timeout": 120_000},  # 120 s per request
            )
            self._connected = True
            logger.info(
                "Connected to %s via Google GenAI SDK", self.model_id,
            )
            return True
        except Exception as e:
            logger.error("Failed to connect to %s: %s", self.model_id, e)
            self._connected = False
            return False
    
    async def disconnect(self) -> None:
        """Close MCP connection."""
        if self._mcp_session:
            # Close MCP session
            pass
        self._connected = False
        logger.info("Disconnected from MCP")
    
    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
    ) -> LLMResponse:
        """Send a text prompt to the LLM via MCP.
        
        Args:
            prompt: The user prompt.
            system_context: Optional system context override.
            max_tokens: Maximum tokens in response.
            grounding_data: Additional context strings.
        
        Returns:
            LLMResponse with text or error.
        """
        if not self._connected:
            return LLMResponse(
                ok=False,
                error="MCP connection not established",
            )
        
        # Build the full prompt with grounding data
        full_prompt = self._build_prompt(prompt, grounding_data)
        
        logger.debug(
            "LLM query: %d chars prompt, max_tokens=%d",
            len(full_prompt),
            max_tokens,
        )
        
        try:
            # MCP query execution will be implemented when
            # the mcp package is integrated. For now, return
            # a placeholder indicating the query would be sent.
            response_text, prompt_tokens, completion_tokens = self._execute_mcp_query(
                prompt=full_prompt,
                system_context=system_context,
                max_tokens=max_tokens,
            )

            return LLMResponse(
                ok=True,
                text=response_text,
                token_usage={
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            )
        except Exception as e:
            if self._is_quota_exhausted(e):
                logger.debug("Quota exhausted on %s (handled by dispatcher)", self.model_id)
            else:
                logger.error("LLM query failed: %s", e)
            return LLMResponse(
                ok=False,
                error=str(e),
            )

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a multimodal prompt to the LLM via MCP.
        
        Args:
            prompt: The text prompt.
            image_data: Raw image bytes.
            image_format: Image format (jpeg, png).
            system_context: Optional system context.
            max_tokens: Maximum tokens in response.
        
        Returns:
            LLMResponse with text or error.
        """
        if not self._connected:
            return LLMResponse(
                ok=False,
                error="MCP connection not established",
            )
        
        logger.debug(
            "Multimodal LLM query: %d chars prompt, %d bytes image (%s)",
            len(prompt),
            len(image_data),
            image_format,
        )
        
        try:
            response_text = self._execute_mcp_multimodal_query(
                prompt=prompt,
                image_data=image_data,
                image_format=image_format,
                system_context=system_context,
                max_tokens=max_tokens,
            )
            
            return LLMResponse(
                ok=True,
                text=response_text,
                token_usage={"prompt_tokens": 0, "completion_tokens": 0},
            )
        except Exception as e:
            if self._is_quota_exhausted(e):
                logger.debug("Quota exhausted on %s (handled by dispatcher)", self.model_id)
            else:
                logger.error("Multimodal LLM query failed: %s", e)
            return LLMResponse(
                ok=False,
                error=str(e),
            )
    
    def _build_prompt(
        self,
        prompt: str,
        grounding_data: list[str] | None,
    ) -> str:
        """Build full prompt with grounding data prefix."""
        parts = []
        
        if grounding_data:
            parts.append("--- Context ---")
            for i, data in enumerate(grounding_data, 1):
                parts.append(f"[Context {i}]")
                parts.append(data)
            parts.append("--- End Context ---\n")
        
        parts.append(prompt)
        return "\n".join(parts)
    
    @staticmethod
    def _is_quota_exhausted(exc: Exception) -> bool:
        """Return True for permanent quota exhaustion (free-tier daily/per-minute cap).
        These errors will NOT recover on retry — fail fast so the dispatcher can
        fall back to another model.
        """
        msg = str(exc)
        return "RESOURCE_EXHAUSTED" in msg and "free_tier" in msg

    @staticmethod
    def _is_retriable(exc: Exception) -> bool:
        """Return True for transient API errors that warrant a retry.
        Quota exhaustion is excluded — it will not recover within the retry window.
        """
        if MCPLLMClient._is_quota_exhausted(exc):
            return False
        msg = str(exc)
        return any(marker in msg for marker in (
            "503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED",
            "DeadlineExceeded", "Timeout", "timed out",
        ))

    def _execute_mcp_query(
        self,
        prompt: str,
        system_context: str | None,
        max_tokens: int,
    ) -> tuple[str, int, int]:
        """Execute a text query via Google GenAI SDK (MCP bridge).

        Returns:
            Tuple of (response_text, prompt_tokens, completion_tokens).

        Uses google.genai directly until full MCP transport
        is integrated.
        """
        if self._genai_client is None:
            raise RuntimeError("Client not initialised — call connect() first")

        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
        )
        if system_context:
            config.system_instruction = system_context

        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._genai_client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                    config=config,
                )
                text = response.text or ""
                # Debug: log finish reason
                if hasattr(response, "candidates") and response.candidates:
                    fr = response.candidates[0].finish_reason
                    print(f"  🔎 Finish reason: {fr}")
                prompt_tokens = 0
                completion_tokens = 0
                if hasattr(response, "usage_metadata") and response.usage_metadata:
                    um = response.usage_metadata
                    prompt_tokens = getattr(um, "prompt_token_count", 0)
                    completion_tokens = getattr(um, "candidates_token_count", 0)
                    total = getattr(um, "total_token_count", prompt_tokens + completion_tokens)
                    self._total_tokens_used += total
                return text, prompt_tokens, completion_tokens
            except Exception as exc:
                if self._is_quota_exhausted(exc):
                    logger.warning(
                        "Quota exhausted on %s — will try fallback model",
                        self.model_id,
                    )
                    raise
                if attempt < self.max_retries and self._is_retriable(exc):
                    wait = 2 ** attempt  # 1 s, 2 s, 4 s …
                    logger.warning(
                        "LLM transient error (attempt %d/%d), retrying in %ds",
                        attempt + 1,
                        self.max_retries + 1,
                        wait,
                    )
                    time.sleep(wait)
                    last_exc = exc
                else:
                    raise
        raise last_exc  # type: ignore[misc]

    def _execute_mcp_multimodal_query(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None,
        max_tokens: int,
    ) -> str:
        """Execute a multimodal query via Google GenAI SDK (MCP bridge)."""
        if self._genai_client is None:
            raise RuntimeError("Client not initialised — call connect() first")
        
        mime_map = {"jpeg": "image/jpeg", "jpg": "image/jpeg", "png": "image/png"}
        mime_type = mime_map.get(image_format.lower(), f"image/{image_format}")
        
        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
        )
        if system_context:
            config.system_instruction = system_context
        
        contents = [
            prompt,
            genai_types.Part.from_bytes(data=image_data, mime_type=mime_type),
        ]
        
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._genai_client.models.generate_content(
                    model=self.model_id,
                    contents=contents,
                    config=config,
                )
                return response.text or ""
            except Exception as exc:
                if self._is_quota_exhausted(exc):
                    logger.warning(
                        "Quota exhausted on %s — will try fallback model",
                        self.model_id,
                    )
                    raise
                if attempt < self.max_retries and self._is_retriable(exc):
                    wait = 2 ** attempt
                    logger.warning(
                        "LLM multimodal transient error (attempt %d/%d), retrying in %ds",
                        attempt + 1,
                        self.max_retries + 1,
                        wait,
                    )
                    time.sleep(wait)
                    last_exc = exc
                else:
                    raise
        raise last_exc  # type: ignore[misc]


class LLMDispatcher:
    """Routes LLM queries to the appropriate backend based on QueryHints.

    Extends the light/heavy tier concept with capability-aware routing
    and native document dispatch.

    Backward-compatible: all existing query_text() calls work unchanged.
    When no QueryHints are provided, falls back to token-count routing:

        max_tokens <= LIGHT_THRESHOLD  →  light / Flash  (fast, cheap)
        max_tokens >  LIGHT_THRESHOLD  →  heavy / Pro    (powerful, expensive)

    If the preferred tier is not connected the other tier is used as fallback.
    """

    LIGHT_THRESHOLD: int = 3500

    def __init__(self, clients: dict[str, MCPLLMClient],
                 preferred_tier: str | None = None) -> None:
        self._clients = clients
        # When set, this tier is preferred over the token-count heuristic.
        # Lets explicit 'connect gemini-2.5-flash' keep Flash as primary.
        self._preferred_tier = preferred_tier

    # --- Protocol compatibility -------------------------------------------------

    @property
    def connected(self) -> bool:
        return any(c.connected for c in self._clients.values())

    @property
    def model_id(self) -> str:
        parts = [c.model_id for tier in ("light", "heavy")
                 if (c := self._clients.get(tier)) and c.connected]
        return " + ".join(parts) if parts else "disconnected"

    @property
    def total_tokens_used(self) -> int:
        return sum(c.total_tokens_used for c in self._clients.values())

    def connected_models(self) -> list[dict[str, str]]:
        return [{"tier": tier, "model_id": c.model_id}
                for tier, c in self._clients.items() if c.connected]

    # --- Routing ---------------------------------------------------------------

    def _route(self, max_tokens: int, hints: QueryHints | None = None,
               document_mime: str | None = None) -> MCPLLMClient:
        """Select the appropriate client based on hints + capabilities.

        Routing priority:
        1. Explicit tier from hints.tier or hints.needs_reasoning
        2. If native document needed + prefers_native_file, prefer backend
           whose underlying model supports that MIME type
        3. Token-count heuristic (legacy fallback when no hints)
        4. Any connected backend as final fallback
        """
        if hints is not None:
            if hints.needs_reasoning or hints.tier == "heavy":
                order = ("heavy", "light")
            else:
                order = ("light", "heavy")
        elif self._preferred_tier:
            # User explicitly chose a model — honour that over token-count heuristic
            other = "light" if self._preferred_tier == "heavy" else "heavy"
            order = (self._preferred_tier, other)
        else:
            prefer_heavy = max_tokens > self.LIGHT_THRESHOLD
            order = ("heavy", "light") if prefer_heavy else ("light", "heavy")

        for tier in order:
            c = self._clients.get(tier)
            if c and c.connected:
                return c
        raise RuntimeError("No LLM client connected — run 'connect' first")

    @staticmethod
    def _is_quota_error(error: str) -> bool:
        """Return True when the error string indicates quota exhaustion."""
        return "RESOURCE_EXHAUSTED" in error or "quota" in error.lower()

    def _fallback_client(self, primary: MCPLLMClient) -> MCPLLMClient | None:
        """Return the other connected tier, or None if unavailable."""
        for tier, c in self._clients.items():
            if c is not primary and c.connected:
                return c
        return None

    # --- LLMQueryInterface methods ---------------------------------------------

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        try:
            client = self._route(max_tokens, hints=hints)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))
        result = client.query_text(
            prompt=prompt,
            system_context=system_context,
            max_tokens=max_tokens,
            grounding_data=grounding_data,
        )
        if not result.ok and self._is_quota_error(result.error or ""):
            fallback = self._fallback_client(client)
            if fallback:
                logger.warning(
                    "Quota exhausted on %s — falling back to %s",
                    client.model_id,
                    fallback.model_id,
                )
                print(
                    f"\n  ⚠️  Quota exhausted on {client.model_id} "
                    f"— retrying with {fallback.model_id}"
                )
                result = fallback.query_text(
                    prompt=prompt,
                    system_context=system_context,
                    max_tokens=max_tokens,
                    grounding_data=grounding_data,
                )
        return result

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        try:
            client = self._route(max_tokens)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))
        result = client.query_multimodal(
            prompt=prompt,
            image_data=image_data,
            image_format=image_format,
            system_context=system_context,
            max_tokens=max_tokens,
        )
        if not result.ok and self._is_quota_error(result.error or ""):
            fallback = self._fallback_client(client)
            if fallback:
                logger.warning(
                    "Quota exhausted on %s — falling back to %s",
                    client.model_id,
                    fallback.model_id,
                )
                print(
                    f"\n  ⚠️  Quota exhausted on {client.model_id} "
                    f"— retrying with {fallback.model_id}"
                )
                result = fallback.query_multimodal(
                    prompt=prompt,
                    image_data=image_data,
                    image_format=image_format,
                    system_context=system_context,
                    max_tokens=max_tokens,
                )
        return result

    def query_with_document(
        self,
        prompt: str,
        artifact: ArtifactRef,
        system_context: str | None = None,
        max_tokens: int = 8192,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Query with a document artifact.

        Resolves the best ingestion path automatically:
          1. Native document + GCS URI (zero-copy for Gemini)
          2. Native document + inline bytes from local file
          3. Fallback: returns ok=False so plugin can use text extraction

        The response's transport_path records which path was used.
        """
        hints = hints or QueryHints(tier="heavy", prefers_native_file=True)
        mime_type = artifact.metadata.get("mime_type", "application/pdf")

        try:
            client = self._route(max_tokens, hints=hints, document_mime=mime_type)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))

        # Check if the underlying model supports native document ingestion.
        # MCPLLMClient doesn't have a capabilities() method — it uses the
        # GenAI SDK directly. For the Gemini provider, PDFs are always
        # supported natively.
        if not self._model_supports_native_doc(client, mime_type):
            return LLMResponse(
                ok=False,
                error="Native document processing not available for this MIME type",
                model_used=client.model_id,
                fallback_reason=f"model {client.model_id} lacks native support for {mime_type}",
            )

        # Build the document part
        doc = DocumentPart(
            mime_type=mime_type,
            storage_uri=artifact.storage_uri,
            file_path=artifact.file_path,
        )

        # Build the full prompt with grounding data
        full_prompt = client._build_prompt(prompt, grounding_data)

        # Delegate to the client's internal GenAI SDK for native doc handling
        return self._execute_document_query(
            client=client,
            prompt=full_prompt,
            doc=doc,
            system_context=system_context,
            max_tokens=max_tokens,
        )

    def supports_native_document(self, mime_type: str) -> bool:
        """Check if any connected model handles this MIME type natively."""
        native_types = {"application/pdf"}
        if mime_type not in native_types:
            return False
        return any(c.connected for c in self._clients.values())

    # --- Internal helpers ------------------------------------------------------

    @staticmethod
    def _model_supports_native_doc(client: MCPLLMClient, mime_type: str) -> bool:
        """Check if a client's model supports native ingestion of a MIME type.

        For Gemini models (the MVP provider), PDFs are always supported.
        """
        if mime_type == "application/pdf":
            return True
        return False

    @staticmethod
    def _execute_document_query(
        client: MCPLLMClient,
        prompt: str,
        doc: DocumentPart,
        system_context: str | None,
        max_tokens: int,
    ) -> LLMResponse:
        """Execute a document query via the GenAI SDK.

        Tries ingestion paths in priority order:
          1. GCS URI (zero-copy) — if storage_uri starts with gs://
          2. Inline bytes from local file_path
        """
        if client._genai_client is None:
            return LLMResponse(ok=False, error="Client not initialised")

        try:
            parts: list = []
            transport_path = "unknown"

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
                return LLMResponse(
                    ok=False,
                    error="DocumentPart has no data source",
                    model_used=client.model_id,
                )

            parts.append(prompt)

            config = genai_types.GenerateContentConfig(
                max_output_tokens=max_tokens,
            )
            if system_context:
                config.system_instruction = system_context

            last_exc: Exception | None = None
            for attempt in range(client.max_retries + 1):
                try:
                    response = client._genai_client.models.generate_content(
                        model=client.model_id,
                        contents=parts,
                        config=config,
                    )
                    if hasattr(response, "usage_metadata") and response.usage_metadata:
                        um = response.usage_metadata
                        client._total_tokens_used += getattr(um, "total_token_count", 0)
                    return LLMResponse(
                        ok=True,
                        text=response.text or "",
                        model_used=client.model_id,
                        transport_path=transport_path,
                    )
                except Exception as exc:
                    if attempt < client.max_retries and client._is_retriable(exc):
                        wait = 2 ** attempt
                        logger.warning(
                            "Document query transient error (attempt %d/%d), "
                            "retrying in %ds: %s",
                            attempt + 1, client.max_retries + 1, wait, exc,
                        )
                        time.sleep(wait)
                        last_exc = exc
                    else:
                        raise
            raise last_exc  # type: ignore[misc]

        except Exception as e:
            logger.error("Document query failed: %s", e)
            return LLMResponse(
                ok=False,
                error=str(e),
                model_used=client.model_id,
            )


# Backward compatibility alias
TieredLLMClient = LLMDispatcher


class ContextBuilder:
    """Builds optimized LLM context from session state.
    
    This is a critical component for Event Mill's LLM context
    optimization strategy. It assembles the minimal context needed
    for each LLM interaction.
    """
    
    def __init__(
        self,
        system_identity: str = "",
        max_context_chars: int = 8000,
    ):
        """Initialize context builder.
        
        Args:
            system_identity: Base system identity prompt.
            max_context_chars: Maximum characters in assembled context.
        """
        self.system_identity = system_identity
        self.max_context_chars = max_context_chars
    
    def build_routing_context(
        self,
        pillar: str,
        tool_descriptions: list[dict[str, str]],
        recent_summaries: list[str],
    ) -> str:
        """Build context for routing decisions.
        
        Args:
            pillar: Active pillar name.
            tool_descriptions: Short descriptions of available tools.
            recent_summaries: Recent tool execution summaries.
        
        Returns:
            Assembled context string.
        """
        parts = []
        
        if self.system_identity:
            parts.append(self.system_identity)
        
        parts.append(f"\nActive investigation pillar: {pillar}")
        
        if tool_descriptions:
            parts.append("\nAvailable tools:")
            for tool in tool_descriptions:
                parts.append(
                    f"  - {tool['name']}: {tool['description']}"
                )
        
        if recent_summaries:
            parts.append("\nRecent analysis results:")
            for summary in recent_summaries:
                parts.append(f"  {summary}")
        
        context = "\n".join(parts)
        return self._truncate(context)
    
    def build_execution_context(
        self,
        tool_name: str,
        tool_description: str,
        user_input: str,
        artifact_summaries: list[str],
        recent_summaries: list[str],
    ) -> str:
        """Build context for tool execution.
        
        Args:
            tool_name: Name of the tool being executed.
            tool_description: Tool's description.
            user_input: The user's original request.
            artifact_summaries: Summaries of loaded artifacts.
            recent_summaries: Recent tool execution summaries.
        
        Returns:
            Assembled context string.
        """
        parts = []
        
        parts.append(f"Executing tool: {tool_name}")
        parts.append(f"Purpose: {tool_description}")
        parts.append(f"\nUser request: {user_input}")
        
        if artifact_summaries:
            parts.append("\nLoaded artifacts:")
            for summary in artifact_summaries:
                parts.append(f"  {summary}")
        
        if recent_summaries:
            parts.append("\nPrior analysis context:")
            for summary in recent_summaries:
                parts.append(f"  {summary}")
        
        context = "\n".join(parts)
        return self._truncate(context)
    
    def build_conversational_context(
        self,
        pillar: str,
        recent_summaries: list[str],
        artifact_count: int,
        user_input: str,
    ) -> str:
        """Build context for conversational interactions.
        
        Args:
            pillar: Active pillar.
            recent_summaries: Recent tool execution summaries.
            artifact_count: Number of loaded artifacts.
            user_input: The user's message.
        
        Returns:
            Assembled context string.
        """
        parts = []
        
        if self.system_identity:
            parts.append(self.system_identity)
        
        parts.append(f"\nInvestigation state: pillar={pillar}, artifacts={artifact_count}")
        
        if recent_summaries:
            parts.append("\nRecent findings:")
            for summary in recent_summaries:
                parts.append(f"  {summary}")
        
        parts.append(f"\nAnalyst: {user_input}")
        
        context = "\n".join(parts)
        return self._truncate(context)
    
    def _truncate(self, text: str) -> str:
        """Truncate text to max_context_chars."""
        if len(text) <= self.max_context_chars:
            return text
        
        truncated = text[:self.max_context_chars - 50]
        return truncated + "\n\n[Context truncated for token budget]"
