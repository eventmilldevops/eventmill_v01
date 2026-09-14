"""
Event Mill Gemini Client

Everything that knows about Google's GenAI SDK lives here: request
construction, the Gemini 3.x generation controls, response shape, and the
exception text this provider emits. The dispatcher knows none of it.

Formerly MCPLLMClient in framework/llm/client.py. The MCP transport was
deferred and never arrived, so the name described a bridge that does not exist
while the class talked to Gemini directly. The transport/endpoint arguments are
kept because the shell still passes them and an MCP bridge remains plausible.
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any

from ...plugins.protocol import LLMResponse, QueryHints
from ..backends.base import DocumentPart
from ..model_client import PROBE_PROMPT, LLMProbeResult, compose_prompt
from ..providers import DEFAULT_PROVIDER_ID, load_tier_specs, ping_budget

try:
    from google import genai
    from google.genai import types as genai_types
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

logger = logging.getLogger("eventmill.framework.llm")

# QueryHints string values -> SDK enum members (Gemini 3.x).
_THINKING_LEVELS = {"minimal", "low", "medium", "high"}
_MEDIA_RESOLUTIONS = {"low", "medium", "high"}

# A 404 in status position, not a "404" anywhere in the message — request ids,
# byte offsets and echoed log lines all contain those, and a false positive
# permanently substitutes the tier's model for the rest of the session.
_HTTP_404_RE = re.compile(r"(?:^|[\s:\[(])404(?=[\s:,\])]|$)")

# Capabilities Gemini serves natively when no manifest tier is available to
# consult. Deferring to this rather than refusing keeps a manifest-less client
# usable, which is how supports_native_document already behaves.
_ASSUMED_CAPABILITIES = ("text", "multimodal_image", "native_pdf")


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
            # Both fields are enum-typed in the SDK. Passing the string works by
            # coercion but emits a Pydantic serializer warning on every call, so
            # look the member up instead.
            config.thinking_config = genai_types.ThinkingConfig(
                thinking_level=genai_types.ThinkingLevel[level.upper()],
            )
        else:
            logger.warning("Ignoring unknown thinking_level %r", level)

    if hints.media_resolution:
        res = hints.media_resolution
        if res in _MEDIA_RESOLUTIONS:
            config.media_resolution = genai_types.MediaResolution[
                f"MEDIA_RESOLUTION_{res.upper()}"
            ]
        else:
            logger.warning("Ignoring unknown media_resolution %r", res)

    return config


def _finish_reason(response: Any) -> str | None:
    """Stop reason of the first candidate, as a plain string.

    "MAX_TOKENS" means the reply was cut off at the output cap — the SDK
    still returns text and no error, so a caller that ignores this treats a
    half-written answer as a complete one.
    """
    candidates = getattr(response, "candidates", None)
    if not candidates:
        return None
    reason = getattr(candidates[0], "finish_reason", None)
    if reason is None:
        return None
    return str(getattr(reason, "name", None) or reason)


def _model_version(response: Any) -> str | None:
    """Model id the provider reports having served the request.

    Distinct from the id the client was configured with: an alias resolves to a
    dated build, so a provider-side version change inside one alias is
    invisible unless this is recorded. Returns None when the response carries
    nothing — older SDKs and the error paths both omit it.
    """
    version = getattr(response, "model_version", None)
    return str(version) if version else None


def _usage(response: Any) -> dict[str, int] | None:
    """Token counts from the response, including thinking tokens."""
    um = getattr(response, "usage_metadata", None)
    if not um:
        return None
    prompt = getattr(um, "prompt_token_count", 0) or 0
    completion = getattr(um, "candidates_token_count", 0) or 0
    thoughts = getattr(um, "thoughts_token_count", 0) or 0
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "thinking_tokens": thoughts,
        "total_tokens": getattr(um, "total_token_count", 0)
        or (prompt + completion + thoughts),
    }


class GeminiClient:
    """LLM client for Google Gemini via the GenAI SDK.

    Implements LLMModelClient. Plugins never hold one of these directly —
    they receive a TierScopedLLMClient wrapping the shared LLMDispatcher.
    """

    provider_id = DEFAULT_PROVIDER_ID

    def __init__(
        self,
        model_id: str = "gemini-3.8-flash",
        transport: str = "stdio",
        endpoint: str | None = None,
        max_retries: int = 3,
        tier: str | None = None,
        api_key_env_var: str | None = None,
    ):
        """Initialize the Gemini client.

        Args:
            model_id: Model identifier for the LLM provider.
            transport: MCP transport type (stdio or sse).
            endpoint: Provider endpoint URL (if applicable).
            max_retries: Maximum retry attempts for failed queries.
            tier: Tier this client is bound to, for capability lookups.
            api_key_env_var: Environment variable holding this model's key.
        """
        self.model_id = model_id
        self.transport = transport
        self.endpoint = endpoint
        self.max_retries = max_retries
        self.tier = tier
        self._connected = False
        self._mcp_session = None
        self._genai_client = None
        self._api_key_env_var: str | None = api_key_env_var
        self._total_tokens_used = 0

    @property
    def connected(self) -> bool:
        """Whether the client is connected to the provider."""
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
            logger.error("google-genai package not installed")
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
                http_options={"timeout": 180_000},  # 180 s per request
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
        """Close the provider session."""
        if self._mcp_session:
            # Close MCP session
            pass
        self._connected = False
        logger.info("Disconnected from MCP")

    def with_model(self, model_id: str) -> "GeminiClient":
        """Return a client for another model id on this live session.

        Reuses the open SDK handle and carries the session spend forward:
        total_tokens_used sums over the live clients, so a substitute that
        started at zero would undercount the session.
        """
        substitute = GeminiClient(
            model_id=model_id,
            transport=self.transport,
            endpoint=self.endpoint,
            max_retries=self.max_retries,
            tier=self.tier,
            api_key_env_var=self._api_key_env_var,
        )
        substitute._genai_client = self._genai_client
        substitute._connected = self._connected
        substitute._total_tokens_used = self._total_tokens_used
        return substitute

    def supports(self, capability: str) -> bool:
        """Whether this model's tier declares a provider capability token.

        Reads the provider manifest, which is the single source of truth for
        what a tier can do. With no tier bound or no manifest loaded, defers
        to Gemini's known-native set rather than refusing work the provider
        would have served.
        """
        specs = load_tier_specs(self.provider_id) if self.tier else {}
        spec = specs.get(self.tier) if self.tier else None
        if spec is None:
            return capability in _ASSUMED_CAPABILITIES
        return capability in spec.capabilities

    def probe(self) -> LLMProbeResult:
        """Check the key reaches Gemini and this model answers.

        Added for parity with the other providers rather than because Gemini
        needed it: all three clients now prove liveness the same way, so one
        reading of the code covers every provider. Nothing else about this
        client's behaviour changed.

        models.list costs no tokens; the ping costs a handful. Neither touches
        the query paths the plugins use.
        """
        started = time.monotonic()
        base = {
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "tier": self.tier,
        }

        def elapsed() -> int:
            return int((time.monotonic() - started) * 1000)

        if not self._connected or self._genai_client is None:
            return LLMProbeResult(
                **base, auth_ok=False, ping_ok=False, latency_ms=elapsed(),
                error="not connected — call connect() first", error_kind="access",
            )

        try:
            listed = [m.name or "" for m in self._genai_client.models.list()]
        except Exception as e:  # noqa: BLE001 — a probe reports, it does not raise
            return LLMProbeResult(
                **base, auth_ok=False, ping_ok=False, latency_ms=elapsed(),
                error=f"{type(e).__name__}: {e}",
                error_kind=self.classify_error(str(e)),
            )

        # Listings are fully-qualified ("models/gemini-3.8-flash").
        visible = any(n.split("/")[-1] == self.model_id for n in listed)

        max_tokens, level = ping_budget(self.tier or "light", self.provider_id)
        hints = QueryHints(thinking_level=level) if level else None
        result = self.query_text(
            prompt=PROBE_PROMPT, max_tokens=max_tokens, hints=hints,
        )
        text = (result.text or "").strip()
        return LLMProbeResult(
            **base,
            auth_ok=True,
            ping_ok=result.ok,
            model_visible=visible,
            models_listed=len(listed),
            ping_text=text,
            # Gemini spends thinking tokens from the reply's budget, so a cap
            # hit with nothing to show is budget starvation, not a failure.
            ping_truncated=bool(result.truncated and not text),
            latency_ms=elapsed(),
            reported_model=result.model_version or "",
            tokens_used=(result.token_usage or {}).get("total_tokens", 0),
            error=result.error or "",
            error_kind=result.error_kind,
        )

    # --- Error classification --------------------------------------------

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
        if GeminiClient._is_quota_exhausted(exc):
            return False
        msg = str(exc)
        # Google emits the screaming-snake form ("504 DEADLINE_EXCEEDED"), never
        # the camelCase one, so matching only "DeadlineExceeded" made a gateway
        # timeout fatal while 503 and 429 both retried — the one failure class
        # long generations actually hit was the one that never backed off.
        return any(marker in msg for marker in (
            "503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED",
            "504", "DEADLINE_EXCEEDED", "DeadlineExceeded",
            "Timeout", "timed out",
        ))

    @staticmethod
    def classify_error(error: str) -> str:
        """Map Google's error text onto the provider-neutral error_kind set.

        The only place this provider's wire vocabulary is read. Order matters:
        a retired preview model returns NOT_FOUND alongside a 404, and quota
        exhaustion carries RESOURCE_EXHAUSTED alongside a 429, so the more
        specific classification has to be tested first.
        """
        lowered = error.lower()

        # Checked first: a retired model id is not something the other tier or
        # a retry can fix, and its 404 would otherwise read as transient.
        if (
            "not_found" in lowered
            or "is not found for api version" in lowered
            or "was not found" in lowered
            or _HTTP_404_RE.search(error) is not None
        ):
            return "model_not_found"
        if "permission_denied" in lowered or (
            "403" in error and "denied" in lowered
        ):
            return "access"
        if "resource_exhausted" in lowered or "quota" in lowered:
            return "quota"
        if any(marker in error for marker in (
            "503", "UNAVAILABLE", "504", "DEADLINE_EXCEEDED",
            "DeadlineExceeded", "Timeout", "timed out",
        )):
            return "transient"
        if "safety" in lowered or "blocked" in lowered:
            return "content_filtered"
        if "invalid_argument" in lowered or "400" in error:
            return "bad_request"
        return "other"

    def _failure(self, error: str, **kw: Any) -> LLMResponse:
        """Build a classified failure response."""
        return LLMResponse(
            ok=False,
            error=error,
            error_kind=self.classify_error(error),
            provider_id=self.provider_id,
            **kw,
        )

    # --- Queries ----------------------------------------------------------

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Send a text prompt to the LLM.

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
            return self._failure("MCP connection not established")

        # Build the full prompt with grounding data
        full_prompt = compose_prompt(prompt, grounding_data)

        logger.debug(
            "LLM query: %d chars prompt, max_tokens=%d",
            len(full_prompt),
            max_tokens,
        )

        try:
            response_text, usage, reason, served = self._execute_mcp_query(
                prompt=full_prompt,
                system_context=system_context,
                max_tokens=max_tokens,
                hints=hints,
            )

            return LLMResponse(
                ok=True,
                text=response_text,
                model_used=self.model_id,
                model_version=served,
                provider_id=self.provider_id,
                token_usage=usage,
                finish_reason=reason,
                truncated=reason == "MAX_TOKENS",
            )
        except Exception as e:
            if self._is_quota_exhausted(e):
                logger.debug(
                    "Quota exhausted on %s (handled by dispatcher)", self.model_id,
                )
            else:
                logger.error("LLM query failed: %s", e)
            return self._failure(str(e))

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Send a multimodal prompt to the LLM.

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
            return self._failure("MCP connection not established")

        logger.debug(
            "Multimodal LLM query: %d chars prompt, %d bytes image (%s)",
            len(prompt),
            len(image_data),
            image_format,
        )

        try:
            response_text, served = self._execute_mcp_multimodal_query(
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
                model_used=self.model_id,
                model_version=served,
                provider_id=self.provider_id,
                token_usage={"prompt_tokens": 0, "completion_tokens": 0},
            )
        except Exception as e:
            if self._is_quota_exhausted(e):
                logger.debug(
                    "Quota exhausted on %s (handled by dispatcher)", self.model_id,
                )
            else:
                logger.error("Multimodal LLM query failed: %s", e)
            return self._failure(str(e))

    def query_with_document(
        self,
        prompt: str,
        doc: DocumentPart,
        system_context: str | None = None,
        max_tokens: int = 8192,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Query with a resolved document part.

        Gemini reads a GCS URI zero-copy, so a storage_uri is preferred over
        bytes whenever the part carries one. Ingestion paths, in order:
          1. GCS URI (zero-copy) — if storage_uri starts with gs://
          2. Inline bytes already on the part
          3. Inline bytes read from a local file_path

        Grounding data arrives folded into prompt by the dispatcher.
        """
        if self._genai_client is None:
            return self._failure("Client not initialised", model_used=self.model_id)

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
                return self._failure(
                    "DocumentPart has no data source", model_used=self.model_id,
                )

            parts.append(prompt)

            config = _build_config(system_context, max_tokens, hints)

            last_exc: Exception | None = None
            for attempt in range(self.max_retries + 1):
                try:
                    response = self._genai_client.models.generate_content(
                        model=self.model_id,
                        contents=parts,
                        config=config,
                    )
                    usage = _usage(response)
                    if usage:
                        self._total_tokens_used += usage["total_tokens"]
                    reason = _finish_reason(response)
                    if reason == "MAX_TOKENS":
                        logger.warning(
                            "Document reply hit the %d-token output cap on %s "
                            "(%s thinking tokens spent) — the text is partial",
                            max_tokens, self.model_id,
                            (usage or {}).get("thinking_tokens", "?"),
                        )
                    return LLMResponse(
                        ok=True,
                        text=response.text or "",
                        model_used=self.model_id,
                        model_version=_model_version(response),
                        provider_id=self.provider_id,
                        transport_path=transport_path,
                        token_usage=usage,
                        finish_reason=reason,
                        truncated=reason == "MAX_TOKENS",
                    )
                except Exception as exc:
                    if attempt < self.max_retries and self._is_retriable(exc):
                        wait = 2 ** attempt
                        logger.warning(
                            "Document query transient error (attempt %d/%d), "
                            "retrying in %ds: %s",
                            attempt + 1, self.max_retries + 1, wait, exc,
                        )
                        time.sleep(wait)
                        last_exc = exc
                    else:
                        raise
            raise last_exc  # type: ignore[misc]

        except Exception as e:
            logger.error("Document query failed: %s", e)
            return self._failure(str(e), model_used=self.model_id)

    # --- SDK execution ----------------------------------------------------

    def _execute_mcp_query(
        self,
        prompt: str,
        system_context: str | None,
        max_tokens: int,
        hints: QueryHints | None = None,
    ) -> tuple[str, dict[str, int] | None, str | None, str | None]:
        """Execute a text query via the Google GenAI SDK.

        Returns:
            Tuple of (response_text, token_usage, finish_reason, model_version).
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
                reason = _finish_reason(response)
                usage = _usage(response)
                if usage:
                    self._total_tokens_used += usage["total_tokens"]
                if reason == "MAX_TOKENS":
                    logger.warning(
                        "Reply hit the %d-token output cap on %s (%s thinking "
                        "tokens spent) — the text is partial",
                        max_tokens, self.model_id,
                        (usage or {}).get("thinking_tokens", "?"),
                    )
                return text, usage, reason, _model_version(response)
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
    ) -> tuple[str, str | None]:
        """Execute a multimodal query via the Google GenAI SDK.

        Returns:
            Tuple of (response_text, model_version).
        """
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
                return response.text or "", _model_version(response)
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
                        "LLM multimodal transient error (attempt %d/%d), "
                        "retrying in %ds",
                        attempt + 1,
                        self.max_retries + 1,
                        wait,
                    )
                    time.sleep(wait)
                    last_exc = exc
                else:
                    raise
        raise last_exc  # type: ignore[misc]


__all__ = ["GeminiClient"]
