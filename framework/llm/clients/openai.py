"""
Event Mill OpenAI Client

Everything that knows about OpenAI's SDK lives here: the request shape, the
reasoning control, the response shape, and the exceptions this provider raises.
The dispatcher knows none of it.

Four provider facts this client is built around, each verified live rather than
assumed (2026-09-13):

* ``reasoning_effort="minimal"`` is **rejected** by both gpt-5.6 tiers —
  "does not support 'minimal' with this model". ``low`` works. This is the same
  shape as gemini-3.8-flash rejecting ``thinking_level="minimal"``, and it is
  why the manifest declares accepted levels per tier rather than the framework
  assuming its own vocabulary is portable.
* Sampling parameters are rejected: ``temperature=0.3`` is a 400, "Only the
  default (1) value is supported".
* Reasoning tokens are output tokens and come out of ``max_output_tokens``.
  Measured: at a 64-token cap the model spent all 64 on reasoning and returned
  empty content, reported as incomplete with reason ``max_output_tokens``.
* The provider reports no context window. ``models.retrieve`` returns
  ``id``/``created``/``owned_by`` only, so the manifest's
  ``max_context_tokens`` is documented rather than probed and is marked as such.

**API surface.** The Responses API, which is what the plan specifies and what
the current SDK leads with. ``store=False`` is sent on every request: this
platform handles incident data, so a no-retention posture is a declared
property of the client, not an incidental default.

Text only for now. ``query_multimodal`` and ``query_with_document`` return a
declared failure rather than a wrong answer — no module consumes either path.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from ...plugins.protocol import LLMResponse, QueryHints
from ..backends.base import DocumentPart
from ..model_client import PROBE_PROMPT, LLMProbeResult, compose_prompt
from ..providers import accepted_thinking_levels, load_tier_specs, ping_budget

try:
    import openai
    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False

logger = logging.getLogger("eventmill.framework.llm")

PROVIDER_ID = "openai"

# QueryHints.thinking_level -> reasoning_effort. The vocabularies happen to
# coincide, but "minimal" is a 400 on the gpt-5.6 tiers, so it is mapped up to
# the shallowest level the provider actually accepts rather than passed through.
_EFFORT_BY_LEVEL = {
    "minimal": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
}

_ASSUMED_CAPABILITIES = ("text", "multimodal_image")


def _effort(
    hints: QueryHints | None,
    tier: str | None,
    provider_id: str = PROVIDER_ID,
) -> str | None:
    """Map portable hints onto this provider's reasoning control.

    Clamped to what the tier declares it accepts: a level the provider rejects
    fails the whole call, which is worse than running one step shallower.
    """
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
        return None
    accepted = accepted_thinking_levels(tier or "light", provider_id)
    if accepted and effort not in accepted:
        logger.warning(
            "%s does not accept reasoning_effort %r — using %r",
            tier or "light", effort, accepted[0],
        )
        return accepted[0]
    return effort


def _usage(response: Any) -> dict[str, int] | None:
    """Token counts, normalised to the same keys every client reports."""
    u = getattr(response, "usage", None)
    if not u:
        return None
    prompt = getattr(u, "input_tokens", 0) or 0
    completion = getattr(u, "output_tokens", 0) or 0
    details = getattr(u, "output_tokens_details", None)
    reasoning = getattr(details, "reasoning_tokens", 0) if details else 0
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        # Reported separately here, unlike Anthropic. Reasoning is included in
        # output_tokens, so this is a breakdown rather than an addition.
        "thinking_tokens": reasoning or 0,
        "total_tokens": getattr(u, "total_tokens", 0) or (prompt + completion),
    }


class OpenAIClient:
    """LLM client for OpenAI models via the Responses API.

    Implements LLMModelClient. Plugins never hold one of these directly —
    they receive a TierScopedLLMClient wrapping the shared LLMDispatcher.
    """

    provider_id = PROVIDER_ID

    def __init__(
        self,
        model_id: str = "gpt-5.6-sol",
        tier: str | None = None,
        api_key_env_var: str | None = "OPENAI_API_KEY",
        max_retries: int = 3,
        timeout: float = 180.0,
        provider_id: str | None = None,
    ):
        """Initialize the OpenAI client.

        Args:
            model_id: Model identifier, e.g. "gpt-5.6-sol".
            tier: Tier this client is bound to, for capability lookups.
            api_key_env_var: Environment variable holding the key. One key
                serves both tiers — this provider does not split keys by tier.
            max_retries: Retries the SDK performs on 429/5xx.
            timeout: Per-request timeout in seconds, matching the other two
                clients' 180 s.
            provider_id: Provider id this client answers as. Defaults to
                "openai". A second provider served by the same SDK and the
                same class — a specialist model on its own key — passes its
                own id here, because every manifest lookup this client makes
                and every response it stamps reads this rather than the class.
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
        if not _HAS_OPENAI:
            logger.error("openai package not installed")
            self._connected = False
            return False

        resolved_key = api_key or os.environ.get(self._api_key_env_var or "", "")
        if not resolved_key:
            logger.error("No API key available for %s", self.model_id)
            self._connected = False
            return False

        try:
            self._sdk_client = openai.OpenAI(
                api_key=resolved_key,
                timeout=self.timeout,
                max_retries=self.max_retries,
            )
            self._connected = True
            logger.info("Connected to %s via the OpenAI SDK", self.model_id)
            return True
        except Exception as e:
            logger.error("Failed to connect to %s: %s", self.model_id, e)
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Close the provider session."""
        self._connected = False
        logger.info("Disconnected from OpenAI")

    def with_model(self, model_id: str) -> "OpenAIClient":
        """Return a client for another model id on this live session.

        Reuses the open SDK handle and carries the session spend forward:
        total_tokens_used sums over the live clients, so a substitute that
        started at zero would undercount the session.
        """
        substitute = OpenAIClient(
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
        """Check the key reaches OpenAI and this model answers.

        models.list costs no tokens; the ping costs a handful, sized from the
        manifest's reasoning reserve rather than a constant. This provider is
        the reason that rule exists — a 64-token ping came back empty with
        every token spent on reasoning.
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
            listed = [m.id for m in self._sdk_client.models.list().data]
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
        if _HAS_OPENAI and isinstance(exc, Exception):
            if isinstance(exc, openai.RateLimitError):
                return "quota"
            if isinstance(exc, (openai.AuthenticationError,
                                openai.PermissionDeniedError)):
                return "access"
            if isinstance(exc, openai.NotFoundError):
                return "model_not_found"
            if isinstance(exc, (openai.APIConnectionError, openai.APITimeoutError)):
                return "transient"
            if isinstance(exc, openai.BadRequestError):
                lowered = str(exc).lower()
                if "context" in lowered or "too many tokens" in lowered:
                    return "context_overflow"
                if "content" in lowered and "filter" in lowered:
                    return "content_filtered"
                return "bad_request"
            if isinstance(exc, openai.APIStatusError):
                return "transient" if exc.status_code >= 500 else "bad_request"

        lowered = str(exc).lower()
        if "rate limit" in lowered or "429" in lowered:
            return "quota"
        if "authentication" in lowered or "permission" in lowered or "401" in lowered:
            return "access"
        if "does not exist" in lowered or "not found" in lowered:
            return "model_not_found"
        if "context length" in lowered:
            return "context_overflow"
        if "content filter" in lowered:
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
            max_tokens: Ceiling on the reply, reasoning included.
            grounding_data: Additional context strings.
            hints: Tier selection is a no-op here (one client, one model);
                   thinking_level maps onto reasoning_effort.
        """
        if not self._connected or self._sdk_client is None:
            return self._failure("OpenAI session not established", "access")

        full_prompt = compose_prompt(prompt, grounding_data)
        request: dict[str, Any] = {
            "model": self.model_id,
            "input": full_prompt,
            "max_output_tokens": max_tokens,
            # Incident data: never retained provider-side. Declared, not default.
            # The Responses API stores by default, so this is load-bearing here
            # in a way it was not on the older completions surface.
            "store": False,
        }
        if system_context:
            request["instructions"] = system_context
        effort = _effort(hints, self.tier, self.provider_id)
        if effort:
            request["reasoning"] = {"effort": effort}

        logger.debug(
            "OpenAI query: %d chars prompt, max_output_tokens=%d, effort=%s",
            len(full_prompt), max_tokens, effort or "default",
        )

        try:
            response = self._sdk_client.responses.create(**request)
        except Exception as e:
            kind = self.classify_error(e)
            if kind == "quota":
                logger.debug(
                    "Quota exhausted on %s (handled by dispatcher)", self.model_id,
                )
            else:
                logger.error("OpenAI query failed: %s", e)
            return self._failure(str(e), kind)

        usage = _usage(response)
        if usage:
            self._total_tokens_used += usage["total_tokens"]

        status = getattr(response, "status", None)
        details = getattr(response, "incomplete_details", None)
        reason = getattr(details, "reason", None) if details else None

        # The Responses API reports failure on the object rather than raising,
        # so a caller reading output_text alone treats a refusal as an answer.
        if status == "failed":
            err = getattr(response, "error", None)
            message = getattr(err, "message", None) or "provider reported failure"
            return self._failure(
                message, self.classify_error(message),
                finish_reason=status, token_usage=usage,
            )
        if reason == "content_filter":
            return self._failure(
                "provider filtered the response", "content_filtered",
                finish_reason=reason, token_usage=usage,
            )

        return LLMResponse(
            ok=True,
            text=getattr(response, "output_text", None) or "",
            model_used=self.model_id,
            model_version=getattr(response, "model", None),
            provider_id=self.provider_id,
            token_usage=usage,
            finish_reason=reason or status,
            # "max_output_tokens" is this provider's spelling of Gemini's
            # MAX_TOKENS. With no content behind it, reasoning consumed the
            # whole budget.
            truncated=reason == "max_output_tokens",
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
        this path, so it is declared rather than guessed at.
        """
        return self._failure(
            "query_multimodal is not implemented for the openai provider "
            "(no module uses it; see Stage 3 of the multi-provider plan)",
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

        This provider cannot read a GCS URI and the framework does not yet
        materialise bytes for a client lacking the remote_uri_gs capability.
        Both document modules stay on Gemini until Stage 3 adds it.
        """
        return self._failure(
            "query_with_document is not implemented for the openai provider "
            "(needs dispatcher-side byte materialisation; see Stage 3)",
            "bad_request",
        )


__all__ = ["OpenAIClient", "PROVIDER_ID"]
