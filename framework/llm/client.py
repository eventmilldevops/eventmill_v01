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
from dataclasses import replace
from typing import Any

from ..plugins.protocol import LLMQueryInterface, LLMResponse, QueryHints, ArtifactRef
from .backends.base import DocumentPart
from .providers import (
    TierSpec,
    default_media_resolution,
    load_tier_specs,
    pdf_handling,
    tokens_per_pdf_page,
)

try:
    from google import genai
    from google.genai import types as genai_types
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

logger = logging.getLogger("eventmill.framework.llm")

# Provider-manifest capability token required for native ingestion of a MIME type.
_NATIVE_CAPABILITY_BY_MIME = {
    "application/pdf": "native_pdf",
}

# QueryHints string values -> SDK enum members (Gemini 3.x).
_THINKING_LEVELS = {"minimal", "low", "medium", "high"}
_MEDIA_RESOLUTIONS = {"low", "medium", "high"}


def _build_config(
    system_context: str | None,
    max_tokens: int,
    hints: QueryHints | None = None,
) -> Any:
    """Build a GenerateContentConfig from max_tokens, system context, and hints.

    Shared by the text, multimodal, and document paths so the Gemini 3.x
    controls are applied consistently rather than in three places.

    Unset hints leave the provider default in place. Note that Gemini 3.x
    deprecates temperature/top_p/top_k — this deliberately sets none of them.
    """
    config = genai_types.GenerateContentConfig(max_output_tokens=max_tokens)
    if system_context:
        config.system_instruction = system_context

    if hints is None:
        return config

    # Deep reasoning implies maximum thinking unless the caller was explicit.
    level = hints.thinking_level
    if level is None and hints.needs_reasoning:
        level = "high"
    if level:
        if level in _THINKING_LEVELS:
            config.thinking_config = genai_types.ThinkingConfig(
                thinking_level=level.upper(),
            )
        else:
            logger.warning("Ignoring unknown thinking_level %r", level)

    if hints.media_resolution:
        res = hints.media_resolution
        if res in _MEDIA_RESOLUTIONS:
            config.media_resolution = f"MEDIA_RESOLUTION_{res.upper()}"
        else:
            logger.warning("Ignoring unknown media_resolution %r", res)

    return config


class MCPLLMClient:
    """LLM client communicating via Model Context Protocol.
    
    This is the framework's LLM integration point. Plugins receive
    a reference to this client via ExecutionContext.llm_query.
    
    The client abstracts away the specific model provider (Gemini, Claude,
    GPT, etc.) behind the MCP transport layer.
    """
    
    def __init__(
        self,
        model_id: str = "gemini-3.5-flash",
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
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Send a text prompt to the LLM via MCP.

        Args:
            prompt: The user prompt.
            system_context: Optional system context override.
            max_tokens: Maximum tokens in response.
            grounding_data: Additional context strings.
            hints: Tier selection is a no-op here (a single client has one
                   model), but generation controls — thinking_level,
                   media_resolution, needs_reasoning — are applied.

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
                hints=hints,
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
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Send a multimodal prompt to the LLM via MCP.

        Args:
            prompt: The text prompt.
            image_data: Raw image bytes.
            image_format: Image format (jpeg, png).
            system_context: Optional system context.
            max_tokens: Maximum tokens in response.
            hints: Tier selection is a no-op here; generation controls
                   (thinking_level, media_resolution) are applied.

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
                hints=hints,
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
        hints: QueryHints | None = None,
    ) -> tuple[str, int, int]:
        """Execute a text query via Google GenAI SDK (MCP bridge).

        Returns:
            Tuple of (response_text, prompt_tokens, completion_tokens).

        Uses google.genai directly until full MCP transport
        is integrated.
        """
        if self._genai_client is None:
            raise RuntimeError("Client not initialised — call connect() first")

        config = _build_config(system_context, max_tokens, hints)

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
        hints: QueryHints | None = None,
    ) -> str:
        """Execute a multimodal query via Google GenAI SDK (MCP bridge)."""
        if self._genai_client is None:
            raise RuntimeError("Client not initialised — call connect() first")
        
        mime_map = {"jpeg": "image/jpeg", "jpg": "image/jpeg", "png": "image/png"}
        mime_type = mime_map.get(image_format.lower(), f"image/{image_format}")
        
        config = _build_config(system_context, max_tokens, hints)

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

    Tier selection precedence:

        1. Explicit QueryHints.tier / needs_reasoning — plugins get these
           from their manifest's model_tier via TierScopedLLMClient.
        2. The tier the analyst pinned with 'connect <model_id>'.
        3. Light, for direct framework callers that express no preference.

    Output size does not select a tier. Both Gemini 3.x tiers are
    capacity-identical, so tier signals reasoning depth and cost only —
    plugin manifests drive the choice.

    If the preferred tier is not connected the other tier is used as fallback,
    so a heavy-tier plugin still runs when only Flash is bound.
    """

    def __init__(self, clients: dict[str, MCPLLMClient],
                 preferred_tier: str | None = None,
                 tier_specs: dict[str, TierSpec] | None = None) -> None:
        self._clients = clients
        # When set, this tier is preferred for callers that pass no hints.
        # Lets explicit 'connect gemini-3.5-flash' keep Flash as primary.
        self._preferred_tier = preferred_tier
        # Per-tier capability specs from the provider manifest. Used to clamp
        # max_tokens to what the selected model can actually emit.
        self._tier_specs = (
            tier_specs if tier_specs is not None else load_tier_specs()
        )
        # Output caps keyed by model id, so clamping follows the model that
        # actually runs — an EVENTMILL_MODEL_* override or a retired-model
        # substitution changes the model without changing the tier.
        self._caps_by_model = {
            spec.model_id: spec.max_output_tokens
            for spec in self._tier_specs.values()
        }

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
        1. Explicit tier from hints.tier or hints.needs_reasoning — this is
           where a plugin's manifest model_tier arrives. Hints that set
           neither (e.g. thinking_level only) express no tier opinion and
           fall through.
        2. The tier pinned by 'connect <model_id>'.
        3. Light — the default for framework callers with no preference.
        4. Any connected backend as final fallback.

        When a document MIME type is supplied, tiers whose provider manifest
        does not declare native support for it are demoted in the order.
        """
        if hints is not None and (hints.needs_reasoning or hints.tier):
            if hints.needs_reasoning or hints.tier == "heavy":
                order = ("heavy", "light")
            else:
                order = ("light", "heavy")
        elif self._preferred_tier in ("light", "heavy"):
            # User explicitly chose a model — honour that.
            other = "light" if self._preferred_tier == "heavy" else "heavy"
            order = (self._preferred_tier, other)
        else:
            # No opinion from the caller and nothing pinned. Light is the
            # cheap default; anything needing depth says so in its manifest.
            order = ("light", "heavy")

        if document_mime:
            order = self._prefer_native_capable(order, document_mime)

        for tier in order:
            c = self._clients.get(tier)
            if c and c.connected:
                return c
        # Nothing in the preferred order is connected. Accept any connected
        # client rather than failing (e.g. a legacy single-key setup).
        for c in self._clients.values():
            if c.connected:
                return c
        raise RuntimeError("No LLM client connected — run 'connect' first")

    def _prefer_native_capable(
        self, order: tuple[str, ...], document_mime: str,
    ) -> tuple[str, ...]:
        """Move tiers that natively handle this MIME type to the front.

        Relative order within each group is preserved, so this only breaks
        ties — it never overrides an explicit tier choice that is capable.
        """
        capability = _NATIVE_CAPABILITY_BY_MIME.get(document_mime)
        if not capability or not self._tier_specs:
            return order
        capable = [
            t for t in order
            if capability in (self._tier_specs[t].capabilities
                              if t in self._tier_specs else ())
        ]
        if not capable:
            return order
        return tuple(capable) + tuple(t for t in order if t not in capable)

    def _tier_of(self, client: MCPLLMClient) -> str | None:
        """Reverse-lookup the tier a client is registered under."""
        for tier, c in self._clients.items():
            if c is client:
                return tier
        return None

    def _output_cap(self, client: MCPLLMClient) -> int | None:
        """Output-token cap of the model this client actually runs.

        Keyed by model id first so an EVENTMILL_MODEL_* override or a
        retired-model substitution is clamped against its own cap rather
        than the cap of the tier it is registered under. Falls back to the
        tier spec for a model the manifest does not describe.
        """
        cap = self._caps_by_model.get(client.model_id)
        if cap:
            return cap
        tier = self._tier_of(client)
        spec = self._tier_specs.get(tier) if tier else None
        if spec is None:
            return None
        if client.model_id != spec.model_id:
            logger.warning(
                "No declared output cap for %s — assuming the %s tier cap "
                "(%d). Set EVENTMILL_MAX_OUTPUT_%s if it differs.",
                client.model_id, tier, spec.max_output_tokens, tier.upper(),
            )
        return spec.max_output_tokens

    def _clamp_tokens(self, client: MCPLLMClient, max_tokens: int) -> int:
        """Clamp max_tokens to what the selected model can actually emit.

        Without this, a call sized for one model that lands on a
        lower-capacity one is rejected by the provider.
        """
        cap = self._output_cap(client)
        if cap is None or max_tokens <= cap:
            return max_tokens
        logger.warning(
            "Clamping max_tokens %d → %d for %s (model output cap)",
            max_tokens, cap, client.model_id,
        )
        return cap

    @staticmethod
    def _is_quota_error(error: str) -> bool:
        """Return True when the error string indicates quota exhaustion."""
        return "RESOURCE_EXHAUSTED" in error or "quota" in error.lower()

    @staticmethod
    def _is_model_not_found(error: str) -> bool:
        """Return True when the model id itself was rejected.

        Preview endpoints are retired with ~2 weeks' notice, so a pinned
        preview model can start returning NOT_FOUND without warning.
        """
        lowered = error.lower()
        return (
            "not_found" in lowered
            or "404" in error
            or "is not found for api version" in lowered
            or "was not found" in lowered
        )

    def _retry_on_retired_model(
        self, client: MCPLLMClient, error: str,
    ) -> MCPLLMClient | None:
        """Build a client on the tier's fallback model after a NOT_FOUND.

        Returns None when the error is not a model-id problem or the tier
        declares no fallback.
        """
        if not self._is_model_not_found(error):
            return None
        tier = self._tier_of(client)
        spec = self._tier_specs.get(tier) if tier else None
        if not spec or not spec.fallback_model_id:
            return None
        if spec.fallback_model_id == client.model_id:
            return None

        logger.error(
            "Model %s (tier=%s) returned NOT_FOUND — it may have been retired. "
            "Falling back to %s. Set %s to pin a different model.",
            client.model_id, tier, spec.fallback_model_id,
            "EVENTMILL_MODEL_HEAVY" if tier == "heavy" else "EVENTMILL_MODEL_LIGHT",
        )
        print(
            f"\n  ⚠️  Model {client.model_id} not found — "
            f"retrying with {spec.fallback_model_id}"
        )

        substitute = MCPLLMClient(
            model_id=spec.fallback_model_id,
            transport=client.transport,
            endpoint=client.endpoint,
            max_retries=client.max_retries,
        )
        # Reuse the live connection; only the target model id differs.
        substitute._genai_client = client._genai_client
        substitute._api_key_env_var = client._api_key_env_var
        substitute._connected = client._connected
        # Carry the spend forward — total_tokens_used sums over the live
        # clients, so dropping the original would undercount the session.
        substitute._total_tokens_used = client._total_tokens_used
        # Register it so subsequent calls in this session skip the failed id.
        if tier:
            self._clients[tier] = substitute
        return substitute

    def _fallback_client(self, primary: MCPLLMClient) -> MCPLLMClient | None:
        """Return the other connected tier, or None if unavailable."""
        for tier, c in self._clients.items():
            if c is not primary and c.connected:
                logger.warning(
                    "Tier change: %s (%s) → %s (%s) after quota exhaustion",
                    self._tier_of(primary), primary.model_id, tier, c.model_id,
                )
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
            max_tokens=self._clamp_tokens(client, max_tokens),
            grounding_data=grounding_data,
            hints=hints,
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
                    max_tokens=self._clamp_tokens(fallback, max_tokens),
                    grounding_data=grounding_data,
                    hints=hints,
                )
        elif not result.ok:
            substitute = self._retry_on_retired_model(client, result.error or "")
            if substitute:
                result = substitute.query_text(
                    prompt=prompt,
                    system_context=system_context,
                    max_tokens=self._clamp_tokens(substitute, max_tokens),
                    grounding_data=grounding_data,
                    hints=hints,
                )
        return result

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        try:
            client = self._route(max_tokens, hints=hints)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))
        result = client.query_multimodal(
            prompt=prompt,
            image_data=image_data,
            image_format=image_format,
            system_context=system_context,
            max_tokens=self._clamp_tokens(client, max_tokens),
            hints=hints,
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
                    max_tokens=self._clamp_tokens(fallback, max_tokens),
                    hints=hints,
                )
        elif not result.ok:
            substitute = self._retry_on_retired_model(client, result.error or "")
            if substitute:
                result = substitute.query_multimodal(
                    prompt=prompt,
                    image_data=image_data,
                    image_format=image_format,
                    system_context=system_context,
                    max_tokens=self._clamp_tokens(substitute, max_tokens),
                    hints=hints,
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

        # PDF page cost is set by media_resolution under Gemini 3.x
        # (low 280 / medium 560 / high 1120 tokens per page). Make the default
        # explicit rather than relying on the provider's implicit choice.
        if mime_type == "application/pdf" and hints.media_resolution is None:
            hints = replace(hints, media_resolution=default_media_resolution())

        try:
            client = self._route(max_tokens, hints=hints, document_mime=mime_type)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))

        if mime_type == "application/pdf":
            overflow = self._pdf_context_overflow(client, artifact, hints)
            if overflow:
                return overflow

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
        result = self._execute_document_query(
            client=client,
            prompt=full_prompt,
            doc=doc,
            system_context=system_context,
            max_tokens=self._clamp_tokens(client, max_tokens),
            hints=hints,
        )
        # This path defaults to the heavy tier, which is a Preview endpoint —
        # it is the most likely of the three to meet a retired model id.
        if not result.ok:
            substitute = self._retry_on_retired_model(client, result.error or "")
            if substitute:
                result = self._execute_document_query(
                    client=substitute,
                    prompt=full_prompt,
                    doc=doc,
                    system_context=system_context,
                    max_tokens=self._clamp_tokens(substitute, max_tokens),
                    hints=hints,
                )
        return result

    def _pdf_context_overflow(
        self, client: MCPLLMClient, artifact: ArtifactRef,
        hints: QueryHints,
    ) -> LLMResponse | None:
        """Refuse a PDF that cannot fit the model's context at this resolution.

        A 1000-page PDF costs ~280k tokens at "low", ~560k at "medium", and
        ~1.12M at "high" — the last exceeds the 1,048,576-token window. Catch
        that here with an actionable message instead of an opaque provider
        error partway through the call.

        Returns None when the request fits, or when the page count is unknown.
        """
        handling = pdf_handling()
        max_pages = handling.get("max_pages", 1000)
        max_mb = handling.get("max_size_mb", 50)

        size_mb = self._pdf_size_mb(artifact)
        if size_mb is not None and size_mb > max_mb:
            return LLMResponse(
                ok=False,
                error=(
                    f"PDF is {size_mb:,.1f} MB, above the provider limit of "
                    f"{max_mb} MB. Split the document."
                ),
                model_used=client.model_id,
                fallback_reason="pdf_exceeds_provider_size_limit",
            )

        pages = self._pdf_page_count(artifact)
        if not pages:
            return None

        if pages > max_pages:
            return LLMResponse(
                ok=False,
                error=(
                    f"PDF has {pages:,} pages, above the provider limit of "
                    f"{max_pages:,} pages"
                ),
                model_used=client.model_id,
                fallback_reason="pdf_exceeds_provider_page_limit",
            )

        resolution = hints.media_resolution or default_media_resolution()
        per_page = tokens_per_pdf_page(resolution)
        estimated = pages * per_page

        tier = self._tier_of(client)
        spec = self._tier_specs.get(tier) if tier else None
        context_limit = spec.max_context_tokens if spec else 1_048_576

        if estimated <= context_limit:
            return None

        # Try a cheaper resolution before giving up.
        for cheaper in ("medium", "low"):
            if pages * tokens_per_pdf_page(cheaper) <= context_limit:
                logger.warning(
                    "PDF %d pages at media_resolution=%s needs ~%d tokens "
                    "(limit %d) — use media_resolution=%r instead",
                    pages, resolution, estimated, context_limit, cheaper,
                )
                return LLMResponse(
                    ok=False,
                    error=(
                        f"PDF ({pages:,} pages) needs ~{estimated:,} tokens at "
                        f"media_resolution={resolution!r}, above the "
                        f"{context_limit:,}-token context window. Retry with "
                        f"media_resolution={cheaper!r} (~"
                        f"{pages * tokens_per_pdf_page(cheaper):,} tokens)."
                    ),
                    model_used=client.model_id,
                    fallback_reason="pdf_exceeds_context_at_resolution",
                )

        return LLMResponse(
            ok=False,
            error=(
                f"PDF ({pages:,} pages) needs ~{estimated:,} tokens even at the "
                f"lowest resolution, above the {context_limit:,}-token context "
                "window. Split the document."
            ),
            model_used=client.model_id,
            fallback_reason="pdf_exceeds_context_at_all_resolutions",
        )

    @staticmethod
    def _pdf_page_count(artifact: ArtifactRef) -> int | None:
        """Page count from artifact metadata, or by reading a local file.

        Artifacts that live only in GCS cannot be read here, so the page
        count is recorded at registration time. Returns None when it cannot
        be determined — the guard then defers to the provider rather than
        blocking a request it cannot size, and says so at warning level so a
        silent no-op is visible.
        """
        pages = artifact.metadata.get("pages") or artifact.metadata.get("page_count")
        if isinstance(pages, int) and pages > 0:
            return pages
        if artifact.file_path and os.path.exists(artifact.file_path):
            try:
                from pypdf import PdfReader
                return len(PdfReader(artifact.file_path).pages)
            except Exception as e:
                logger.warning(
                    "Could not read page count from %s: %s", artifact.file_path, e,
                )
                return None
        logger.warning(
            "PDF %s carries no page count and has no readable local file "
            "(storage_uri=%s) — the context-overflow guard cannot size it.",
            artifact.artifact_id, artifact.storage_uri or "none",
        )
        return None

    @staticmethod
    def _pdf_size_mb(artifact: ArtifactRef) -> float | None:
        """Size in MB from artifact metadata, or by stat-ing a local file."""
        size_bytes = artifact.metadata.get("size_bytes")
        if isinstance(size_bytes, int) and size_bytes > 0:
            return size_bytes / (1024 * 1024)
        if artifact.file_path and os.path.exists(artifact.file_path):
            try:
                return os.path.getsize(artifact.file_path) / (1024 * 1024)
            except OSError:
                return None
        return None

    def supports_native_document(self, mime_type: str) -> bool:
        """Check if any connected model handles this MIME type natively."""
        if mime_type not in _NATIVE_CAPABILITY_BY_MIME:
            return False
        return any(
            c.connected and self._model_supports_native_doc(c, mime_type)
            for c in self._clients.values()
        )

    # --- Internal helpers ------------------------------------------------------

    def _model_supports_native_doc(
        self, client: MCPLLMClient, mime_type: str,
    ) -> bool:
        """Check if a client's model supports native ingestion of a MIME type.

        Reads the tier's declared capabilities so this agrees with
        _prefer_native_capable — the provider manifest is the only source of
        truth. With no manifest loaded, defer to the known-native set rather
        than blocking a request the provider can serve.
        """
        capability = _NATIVE_CAPABILITY_BY_MIME.get(mime_type)
        if not capability:
            return False
        tier = self._tier_of(client)
        spec = self._tier_specs.get(tier) if tier else None
        if spec is None:
            return True
        return capability in spec.capabilities

    @staticmethod
    def _execute_document_query(
        client: MCPLLMClient,
        prompt: str,
        doc: DocumentPart,
        system_context: str | None,
        max_tokens: int,
        hints: QueryHints | None = None,
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

            config = _build_config(system_context, max_tokens, hints)

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


class TierScopedLLMClient:
    """Applies a plugin's manifest model_tier as the default for its queries.

    The framework wraps the shared LLMDispatcher in one of these per plugin
    execution. Every query the plugin makes without explicit QueryHints picks
    up the tier its manifest declares; a plugin that passes its own hints
    keeps full control.

    This is the single place the manifest default is applied — LLMDispatcher
    stays plugin-agnostic, and no existing plugin call site has to change.
    """

    def __init__(self, inner: LLMQueryInterface, default_tier: str = "light"):
        self._inner = inner
        # "none" means the plugin declares no LLM work; treat any incidental
        # call as light rather than silently promoting it to Pro.
        self.default_tier = (
            default_tier if default_tier in ("light", "heavy") else "light"
        )

    def _with_default(self, hints: QueryHints | None) -> QueryHints:
        """Fill in the manifest tier when the caller expressed no opinion.

        Only the tier field is supplied. Hints that set other fields —
        thinking_level, media_resolution — keep the manifest tier instead of
        silently demoting the plugin to light.
        """
        if hints is None:
            return QueryHints(tier=self.default_tier)
        if hints.tier is None and not hints.needs_reasoning:
            return replace(hints, tier=self.default_tier)
        return hints

    # --- Pass-through properties -----------------------------------------------

    @property
    def connected(self) -> bool:
        return getattr(self._inner, "connected", False)

    @property
    def model_id(self) -> str:
        return getattr(self._inner, "model_id", "unknown")

    @property
    def total_tokens_used(self) -> int:
        return getattr(self._inner, "total_tokens_used", 0)

    # --- LLMQueryInterface methods ---------------------------------------------

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        return self._inner.query_text(
            prompt=prompt,
            system_context=system_context,
            max_tokens=max_tokens,
            grounding_data=grounding_data,
            hints=self._with_default(hints),
        )

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        return self._inner.query_multimodal(
            prompt=prompt,
            image_data=image_data,
            image_format=image_format,
            system_context=system_context,
            max_tokens=max_tokens,
            hints=self._with_default(hints),
        )

    def query_with_document(
        self,
        prompt: str,
        artifact: ArtifactRef,
        system_context: str | None = None,
        max_tokens: int = 8192,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        # Native document work needs the file path preference regardless of tier.
        resolved = self._with_default(hints)
        if hints is None:
            resolved = replace(resolved, prefers_native_file=True)
        inner_call = getattr(self._inner, "query_with_document", None)
        if inner_call is None:
            return LLMResponse(
                ok=False,
                error="Connected client does not support native document queries",
                fallback_reason="no query_with_document on client",
            )
        return inner_call(
            prompt=prompt,
            artifact=artifact,
            system_context=system_context,
            max_tokens=max_tokens,
            grounding_data=grounding_data,
            hints=resolved,
        )

    def supports_native_document(self, mime_type: str) -> bool:
        checker = getattr(self._inner, "supports_native_document", None)
        return bool(checker(mime_type)) if checker else False


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
