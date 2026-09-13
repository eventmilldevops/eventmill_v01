"""
Event Mill LLM Model Client

The internal contract every provider client implements. The dispatcher is
written against this and nothing else — it never imports a vendor SDK, and it
never reaches through a client into provider-specific state.

One provider owns one client. There is no universal client that understands
every vendor, and no cross-provider fallback: a session started on one provider
stays on that provider's tiers. That is a data-handling boundary, not a routing
convenience.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..plugins.protocol import LLMResponse, QueryHints
from .backends.base import DocumentPart

# Closed vocabulary for LLMResponse.error_kind. The client classifies its own
# provider's failures into these; the dispatcher routes on the result. Without
# it, every new provider forces its own exception text into the dispatcher.
#
#   quota            — rate or spend limit reached; the other tier may serve
#   access           — key not entitled to this model; the other tier may serve
#   model_not_found  — the model id itself was rejected (retired preview)
#   transient        — worth retrying as-is (503, 504, timeouts)
#   context_overflow — input too large for the model's window
#   content_filtered — provider refused on safety grounds
#   bad_request      — malformed request; retrying changes nothing
#   other            — classified as nothing more specific
ERROR_KINDS = (
    "quota",
    "access",
    "model_not_found",
    "transient",
    "context_overflow",
    "content_filtered",
    "bad_request",
    "other",
)

# error_kinds for which the dispatcher should try the other connected tier.
# Both mean "this model cannot serve the request but another one might", and
# neither recovers from a retry against the same model.
TIER_CHANGE_KINDS = frozenset({"quota", "access"})


def compose_prompt(prompt: str, grounding_data: list[str] | None) -> str:
    """Prefix a prompt with grounding context.

    Provider-neutral: it is string assembly, not a request shape. Lives here
    because both the dispatcher (document path, where the protocol takes a
    composed prompt) and each client (text path, where the protocol takes
    grounding_data) need exactly the same layout, and two copies would drift.
    """
    if not grounding_data:
        return prompt

    parts = ["--- Context ---"]
    for i, data in enumerate(grounding_data, 1):
        parts.append(f"[Context {i}]")
        parts.append(data)
    parts.append("--- End Context ---\n")
    parts.append(prompt)
    return "\n".join(parts)


@runtime_checkable
class LLMModelClient(Protocol):
    """One model, on one provider, behind one interface.

    Everything the dispatcher is allowed to know about a client. Anything a
    client needs that is not here — an SDK handle, a request builder, a
    vendor's enum — stays inside the client.
    """

    # --- Identity ---------------------------------------------------------

    provider_id: str
    """Provider manifest id, e.g. "gcp_gemini". Recorded on every response."""

    model_id: str
    """Model id this client was configured to call."""

    tier: str | None
    """The tier this client is bound to ("light" / "heavy"), if known."""

    # --- State ------------------------------------------------------------

    @property
    def connected(self) -> bool:
        """Whether the client holds a usable session."""
        ...

    @property
    def total_tokens_used(self) -> int:
        """Tokens consumed by this client over the session."""
        ...

    # --- Lifecycle --------------------------------------------------------

    def connect(self, api_key: str | None = None) -> bool:
        """Establish the provider session. True on success."""
        ...

    def with_model(self, model_id: str) -> "LLMModelClient":
        """Return a client for another model id on the same live session.

        Not a factory. The substitute has to reuse the open connection and
        carry the session's token spend forward, or a retired-model retry
        silently undercounts the session and re-authenticates for nothing.
        Each provider decides what carrying a connection forward means.
        """
        ...

    def supports(self, capability: str) -> bool:
        """Whether this client's model declares a provider capability token."""
        ...

    # --- Queries ----------------------------------------------------------

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        ...

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        ...

    def query_with_document(
        self,
        prompt: str,
        doc: DocumentPart,
        system_context: str | None = None,
        max_tokens: int = 8192,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Query with a resolved document part.

        The client picks the ingestion path from what the DocumentPart carries
        — a remote URI its provider can read, or bytes. The dispatcher has
        already resolved the artifact, run the size guard and clamped the
        budget; it takes no view on how the document reaches the provider.

        Grounding data arrives folded into ``prompt``: the dispatcher composes
        it with ``compose_prompt`` so this signature stays about the document.
        """
        ...


__all__ = [
    "ERROR_KINDS",
    "TIER_CHANGE_KINDS",
    "LLMModelClient",
    "compose_prompt",
]
