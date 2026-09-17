"""
Event Mill Anthropic Client

Everything that knows about Anthropic's SDK lives here: the Messages API
request shape, adaptive thinking, the effort control, the response shape, and
the exceptions this provider raises. The dispatcher knows none of it.

Three provider facts this client is built around, each verified live rather
than assumed (2026-09-13):

* ``budget_tokens`` is gone on the 5 family — ``models.retrieve`` reports
  ``thinking.types.enabled: false``. Depth is set by ``output_config.effort``
  and the spend is adaptive, so there is no knob to cap thinking directly.
* Sampling parameters are rejected. Sending ``temperature`` is a 400, which is
  the same posture Gemini 3.x takes, so neither client sets one.
* Thinking tokens are output tokens and come out of ``max_tokens``, exactly as
  on Gemini. A reply sized against the full cap gets cut off mid-record.

Text only for now. ``query_multimodal`` and ``query_with_document`` return a
declared failure rather than a wrong answer: the estate's two document modules
stay on Gemini and nothing anywhere consumes multimodal, so implementing them
against an untested path would be speculative. Stage 4 of
docs/specs/multi_provider_llm_clients.md picks them up.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from ...plugins.protocol import LLMResponse, QueryHints
from ..backends.base import DocumentPart
from ..model_client import PROBE_PROMPT, LLMProbeResult, compose_prompt
from ..providers import load_tier_specs, ping_budget

try:
    import anthropic
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

logger = logging.getLogger("eventmill.framework.llm")

PROVIDER_ID = "anthropic"

# QueryHints.thinking_level -> output_config.effort. The provider also accepts
# "xhigh" and "max"; QueryHints has no vocabulary for them, so they are
# unreachable from a plugin and deliberately absent here. "minimal" has no
# equivalent — the shallowest effort is "low".
_EFFORT_BY_LEVEL = {
    "minimal": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
}

# Above this the SDK wants a streamed request: a non-streaming call asking for
# a very large reply can outlive the HTTP timeout. The manifest states the
# threshold; this is the fallback when it cannot be read.
_DEFAULT_STREAM_THRESHOLD = 32768

_ASSUMED_CAPABILITIES = ("text", "multimodal_image", "native_pdf")


def _effort(hints: QueryHints | None) -> str | None:
    """Map portable hints onto this provider's effort control."""
    if hints is None:
        return None
    level = hints.thinking_level
    if level is None and hints.needs_reasoning:
        level = "high"
    if level is None:
        return None
    effort = _EFFORT_BY_LEVEL.get(level)
    if effort is None:
        logger.warning("Ignoring unknown thinking_level %r", level)
    return effort


def _text_of(message: Any) -> str:
    """Concatenate the text blocks of a Messages API response.

    A response also carries thinking blocks, and on a tool turn tool_use
    blocks. Reading ``content[0]`` would return whichever came first.
    """
    parts = []
    for block in getattr(message, "content", None) or []:
        if getattr(block, "type", "") == "text":
            parts.append(getattr(block, "text", "") or "")
    return "".join(parts)


def _usage(message: Any) -> dict[str, int] | None:
    """Token counts, normalised to the same keys every client reports."""
    u = getattr(message, "usage", None)
    if not u:
        return None
    prompt = getattr(u, "input_tokens", 0) or 0
    completion = getattr(u, "output_tokens", 0) or 0
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        # Thinking is billed inside output_tokens and is not reported
        # separately, so it cannot be split out the way Gemini's is.
        "thinking_tokens": 0,
        "total_tokens": prompt + completion,
    }


class AnthropicClient:
    """LLM client for Anthropic Claude via the Messages API.

    Implements LLMModelClient. Plugins never hold one of these directly —
    they receive a TierScopedLLMClient wrapping the shared LLMDispatcher.
    """

    provider_id = PROVIDER_ID

    def __init__(
        self,
        model_id: str = "claude-opus-5",
        tier: str | None = None,
        api_key_env_var: str | None = "ANTHROPIC_API_KEY",
        max_retries: int = 3,
        timeout: float = 180.0,
        provider_id: str | None = None,
    ):
        """Initialize the Anthropic client.

        Args:
            model_id: Model identifier, e.g. "claude-opus-5".
            tier: Tier this client is bound to, for capability lookups.
            api_key_env_var: Environment variable holding the key. One key
                serves both tiers — this provider does not split keys by tier.
            max_retries: Retries the SDK performs on 429/5xx.
            timeout: Per-request timeout in seconds, matching the Gemini
                client's 180 s so a slow heavy-tier call behaves the same way
                whichever provider serves it.
            provider_id: Provider id this client answers as. Defaults to
                "anthropic". Every manifest lookup this client makes and every
                response it stamps reads this rather than the class, so a
                second provider served by the same class passes its own id.
        """
        self.provider_id = provider_id or PROVIDER_ID
        self.model_id = model_id
        self.tier = tier
        self.max_retries = max_retries
        self.timeout = timeout
        self._connected = False
        self._sdk_client: Any = None
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
        """Establish the provider session.

        Builds an SDK handle; it makes no network call, so success here means
        a key was found and the SDK is installed, not that either works. Run
        probe() for that.
        """
        if not _HAS_ANTHROPIC:
            logger.error("anthropic package not installed")
            self._connected = False
            return False

        resolved_key = api_key or os.environ.get(self._api_key_env_var or "", "")
        if not resolved_key:
            logger.error("No API key available for %s", self.model_id)
            self._connected = False
            return False

        try:
            self._sdk_client = anthropic.Anthropic(
                api_key=resolved_key,
                timeout=self.timeout,
                max_retries=self.max_retries,
            )
            self._connected = True
            logger.info("Connected to %s via the Anthropic SDK", self.model_id)
            return True
        except Exception as e:
            logger.error("Failed to connect to %s: %s", self.model_id, e)
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Close the provider session."""
        self._connected = False
        logger.info("Disconnected from Anthropic")

    def with_model(self, model_id: str) -> "AnthropicClient":
        """Return a client for another model id on this live session.

        Reuses the open SDK handle and carries the session spend forward:
        total_tokens_used sums over the live clients, so a substitute that
        started at zero would undercount the session.
        """
        substitute = AnthropicClient(
            model_id=model_id,
            tier=self.tier,
            api_key_env_var=self._api_key_env_var,
            max_retries=self.max_retries,
            timeout=self.timeout,
            provider_id=self.provider_id,
        )
        substitute._sdk_client = self._sdk_client
        substitute._connected = self._connected
        substitute._total_tokens_used = self._total_tokens_used
        return substitute

    def supports(self, capability: str) -> bool:
        """Whether this model's tier declares a provider capability token."""
        specs = load_tier_specs(self.provider_id) if self.tier else {}
        spec = specs.get(self.tier) if self.tier else None
        if spec is None:
            return capability in _ASSUMED_CAPABILITIES
        return capability in spec.capabilities

    def probe(self) -> LLMProbeResult:
        """Check the key reaches Anthropic and this model answers.

        models.list costs no tokens; the ping costs a handful, sized from the
        manifest's thinking reserve rather than a constant.
        """
        started = time.monotonic()
        base = {
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "tier": self.tier,
        }

        def elapsed() -> int:
            return int((time.monotonic() - started) * 1000)

        if not self._connected or self._sdk_client is None:
            return LLMProbeResult(
                **base, auth_ok=False, ping_ok=False, latency_ms=elapsed(),
                error="not connected — call connect() first", error_kind="access",
            )

        try:
            listed = [m.id for m in self._sdk_client.models.list(limit=100).data]
        except Exception as e:  # noqa: BLE001 — a probe reports, it does not raise
            return LLMProbeResult(
                **base, auth_ok=False, ping_ok=False, latency_ms=elapsed(),
                error=f"{type(e).__name__}: {e}", error_kind=self.classify_error(e),
            )

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
            model_visible=self.model_id in listed,
            models_listed=len(listed),
            ping_text=text,
            ping_truncated=bool(result.truncated and not text),
            latency_ms=elapsed(),
            reported_model=result.model_version or "",
            tokens_used=(result.token_usage or {}).get("total_tokens", 0),
            error=result.error or "",
            error_kind=result.error_kind,
        )

    # --- Error classification --------------------------------------------

    @staticmethod
    def classify_error(exc: Exception | str) -> str:
        """Map a provider failure onto the framework's closed vocabulary.

        Typed SDK exceptions first — they carry the status code, which is the
        reliable signal. Falls back to the message only when handed a bare
        string, which is how a re-raised or wrapped error arrives.
        """
        if _HAS_ANTHROPIC and isinstance(exc, Exception):
            if isinstance(exc, anthropic.RateLimitError):
                return "quota"
            if isinstance(exc, (anthropic.AuthenticationError,
                                anthropic.PermissionDeniedError)):
                return "access"
            if isinstance(exc, anthropic.NotFoundError):
                return "model_not_found"
            if isinstance(exc, (anthropic.APIConnectionError,
                                anthropic.APITimeoutError)):
                return "transient"
            if isinstance(exc, anthropic.APIStatusError):
                if exc.status_code >= 500:
                    return "transient"
                if exc.status_code == 413:
                    return "context_overflow"
                # A 400 is the common case and needs its text read: an
                # over-long prompt and a malformed request share the status.
                lowered = str(exc).lower()
                if "too long" in lowered or (
                    "context" in lowered and "exceed" in lowered
                ):
                    return "context_overflow"
                return "bad_request"

        lowered = str(exc).lower()
        if "rate limit" in lowered or "429" in lowered:
            return "quota"
        if "authentication" in lowered or "permission" in lowered or "401" in lowered:
            return "access"
        if "not_found" in lowered or "not found" in lowered:
            return "model_not_found"
        if "too long" in lowered:
            return "context_overflow"
        if "refus" in lowered:
            return "content_filtered"
        return "other"

    def _failure(self, error: str, kind: str | None = None, **kw: Any) -> LLMResponse:
        return LLMResponse(
            ok=False,
            error=error,
            error_kind=kind or "other",
            model_used=self.model_id,
            provider_id=self.provider_id,
            **kw,
        )

    def _stream_threshold(self) -> int:
        """Output size above which the SDK needs a streamed request."""
        from ..providers import load_provider_manifest

        manifest = load_provider_manifest(self.provider_id) or {}
        constraints = manifest.get("request_constraints") or {}
        value = constraints.get("stream_above_output_tokens")
        return int(value) if value else _DEFAULT_STREAM_THRESHOLD

    # --- Queries ----------------------------------------------------------

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Send a text prompt to the model.

        Args:
            prompt: The user prompt.
            system_context: Optional system prompt.
            max_tokens: Ceiling on the reply, thinking included.
            grounding_data: Additional context strings.
            hints: Tier selection is a no-op here (one client, one model);
                   thinking_level maps onto output_config.effort.
        """
        if not self._connected or self._sdk_client is None:
            return self._failure("Anthropic session not established", "access")

        full_prompt = compose_prompt(prompt, grounding_data)
        request: dict[str, Any] = {
            "model": self.model_id,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": full_prompt}],
        }
        if system_context:
            request["system"] = system_context
        effort = _effort(hints)
        if effort:
            request["output_config"] = {"effort": effort}

        logger.debug(
            "Anthropic query: %d chars prompt, max_tokens=%d, effort=%s",
            len(full_prompt), max_tokens, effort or "default",
        )

        try:
            if max_tokens > self._stream_threshold():
                # A large non-streaming reply can outlive the HTTP timeout.
                with self._sdk_client.messages.stream(**request) as stream:
                    message = stream.get_final_message()
            else:
                message = self._sdk_client.messages.create(**request)
        except Exception as e:
            kind = self.classify_error(e)
            if kind == "quota":
                logger.debug(
                    "Quota exhausted on %s (handled by dispatcher)", self.model_id,
                )
            else:
                logger.error("Anthropic query failed: %s", e)
            return self._failure(str(e), kind)

        usage = _usage(message)
        if usage:
            self._total_tokens_used += usage["total_tokens"]

        stop = getattr(message, "stop_reason", None)
        if stop == "refusal":
            details = getattr(message, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            return self._failure(
                f"provider refused the request (category={category})",
                "content_filtered",
                finish_reason=stop,
                token_usage=usage,
            )

        return LLMResponse(
            ok=True,
            text=_text_of(message),
            model_used=self.model_id,
            model_version=getattr(message, "model", None),
            provider_id=self.provider_id,
            token_usage=usage,
            finish_reason=stop,
            truncated=stop == "max_tokens",
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
        """Not implemented for this provider yet.

        The model supports image input; nothing in the plugin estate calls
        this path, so it is declared rather than guessed at. A stated refusal
        beats an untested implementation that looks available.
        """
        return self._failure(
            "query_multimodal is not implemented for the anthropic provider "
            "(no module uses it; see Stage 4 of the multi-provider plan)",
            "bad_request",
        )

    def query_with_document(
        self,
        prompt: str,
        doc: DocumentPart,
        system_context: str | None = None,
        max_tokens: int = 8192,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Not implemented for this provider yet.

        The model reads PDFs natively, but this provider cannot read a GCS URI
        and the framework does not yet materialise bytes for a client that
        lacks the remote_uri_gs capability. Both document modules stay on
        Gemini until Stage 4 adds it.
        """
        return self._failure(
            "query_with_document is not implemented for the anthropic provider "
            "(needs dispatcher-side byte materialisation; see Stage 4)",
            "bad_request",
        )


__all__ = ["AnthropicClient", "PROVIDER_ID"]
