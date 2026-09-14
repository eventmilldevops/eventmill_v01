"""
Event Mill LLM Dispatcher

Routes queries across a provider's model tiers, clamps output budgets, guards
oversized documents and retries retired model ids. It holds LLMModelClient
instances and talks to them through that interface only.

No vendor SDK is imported here, and none may be: the moment the dispatcher
knows how one provider ships a document or phrases an error, adding the next
provider means editing this file. tests/framework/test_provider_seam.py
enforces that mechanically.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import replace
from typing import Any

from ..plugins.protocol import LLMQueryInterface, LLMResponse, QueryHints, ArtifactRef
from .backends.base import DocumentPart
from .model_client import (
    TIER_CHANGE_KINDS,
    LLMModelClient,
    compose_prompt,
)
from .providers import (
    DEFAULT_PROVIDER_ID,
    TierSpec,
    default_media_resolution,
    load_tier_specs,
    pdf_handling,
    tokens_per_pdf_page,
)

logger = logging.getLogger("eventmill.framework.llm")

# Provider-manifest capability token required for native ingestion of a MIME type.
_NATIVE_CAPABILITY_BY_MIME = {
    "application/pdf": "native_pdf",
}

# A 404 in status position, not a "404" anywhere in the message — request ids,
# byte offsets and echoed log lines all contain those, and a false positive
# permanently substitutes the tier's model for the rest of the session.
# Used only by the string-matching fallback, for a client that classified
# nothing; a client that sets error_kind never reaches it.
_HTTP_404_RE = re.compile(r"(?:^|[\s:\[(])404(?=[\s:,\])]|$)")


def _provider_of(client: LLMModelClient) -> str:
    """Provider a client belongs to, defaulting for a fake that declares none."""
    return getattr(client, "provider_id", None) or DEFAULT_PROVIDER_ID


def _by_provider_tier(
    clients: dict[Any, LLMModelClient],
) -> dict[tuple[str, str], LLMModelClient]:
    """Normalise a client map to (provider_id, tier) keys.

    Accepts the tier-keyed form every caller used before providers were
    separable — unambiguous, because the client carries its own provider_id.
    Keeping both shapes valid is what let this change stay inside the
    dispatcher instead of rippling through the shell and the suite.
    """
    out: dict[tuple[str, str], LLMModelClient] = {}
    for key, client in clients.items():
        if isinstance(key, tuple):
            out[(str(key[0]), str(key[1]))] = client
        else:
            out[(_provider_of(client), str(key))] = client
    return out


def _specs_by_provider_tier(
    specs: dict[Any, TierSpec],
    providers: tuple[str, ...] = (),
) -> dict[tuple[str, str], TierSpec]:
    """Normalise a tier-spec map to (provider_id, tier) keys.

    A tier-keyed dict means "the specs for this dispatcher's clients", so it is
    attached to the providers actually bound rather than to whatever
    provider_id the spec objects happen to carry. Those two can disagree — a
    caller building TierSpec values by hand gets the default provider_id while
    its clients declare their own — and a mismatch is invisible: every lookup
    misses, so clamping silently falls back to defaults and a retired-model
    retry quietly stops happening.
    """
    out: dict[tuple[str, str], TierSpec] = {}
    for key, spec in specs.items():
        if isinstance(key, tuple):
            out[(str(key[0]), str(key[1]))] = spec
            continue
        targets = providers or (getattr(spec, "provider_id", DEFAULT_PROVIDER_ID),)
        for provider_id in targets:
            out.setdefault((provider_id, str(key)), spec)
    return out


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

    # Read by TierScopedLLMClient to decide whether it may pass a provider
    # scope down. Duck-typed rather than an isinstance check, so a test fake
    # can opt in or out without importing this class.
    accepts_provider_scope = True

    def __init__(self, clients: dict[Any, LLMModelClient],
                 preferred_tier: str | None = None,
                 tier_specs: dict[Any, TierSpec] | None = None,
                 preferred_provider: str | None = None) -> None:
        # Keyed by (provider_id, tier). Keyed by tier alone it could not
        # express two vendors bound at once: registering an Anthropic client
        # under "heavy" would evict Gemini Pro and send every heavy plugin to
        # a provider nobody selected.
        #
        # A tier-keyed dict is still accepted and normalised, because each
        # client already knows its own provider_id — so every existing caller
        # keeps working and the change stays inside this class.
        self._clients = _by_provider_tier(clients)
        # When set, this tier is preferred for callers that pass no hints.
        # Lets explicit 'connect gemini-3.8-flash' keep Flash as primary.
        self._preferred_tier = preferred_tier
        # The provider serving callers that name none. First one bound unless
        # stated, so a single-provider session behaves exactly as before.
        self._preferred_provider = preferred_provider
        # Capability specs per (provider_id, tier), used to clamp max_tokens
        # to what the selected model can actually emit. Loaded per provider
        # when not supplied, so a second vendor's caps are never read off the
        # first vendor's manifest.
        if tier_specs is not None:
            self._tier_specs = _specs_by_provider_tier(
                tier_specs, providers=tuple(dict.fromkeys(
                    p for p, _ in self._clients
                )),
            )
        else:
            self._tier_specs = {}
            for provider_id in dict.fromkeys(p for p, _ in self._clients):
                for tier, spec in load_tier_specs(provider_id).items():
                    self._tier_specs[(provider_id, tier)] = spec
            if not self._tier_specs:
                self._tier_specs = _specs_by_provider_tier(load_tier_specs())
        # Output caps keyed by model id, so clamping follows the model that
        # actually runs — an EVENTMILL_MODEL_* override or a retired-model
        # substitution changes the model without changing the tier.
        self._caps_by_model = {
            spec.model_id: spec.max_output_tokens
            for spec in self._tier_specs.values()
        }
        self._context_by_model = {
            spec.model_id: spec.max_context_tokens
            for spec in self._tier_specs.values()
        }

    # --- Protocol compatibility -------------------------------------------------

    @property
    def connected(self) -> bool:
        return any(c.connected for c in self._clients.values())

    @property
    def model_id(self) -> str:
        parts = [c.model_id
                 for provider_id in self.bound_providers()
                 for tier in ("light", "heavy")
                 if (c := self._clients.get((provider_id, tier))) and c.connected]
        return " + ".join(parts) if parts else "disconnected"

    @property
    def total_tokens_used(self) -> int:
        return sum(c.total_tokens_used for c in self._clients.values())

    def bound_providers(self) -> tuple[str, ...]:
        """Providers with at least one connected client, in bind order."""
        return tuple(dict.fromkeys(
            provider_id for (provider_id, _), c in self._clients.items()
            if c.connected
        ))

    @property
    def default_provider(self) -> str | None:
        """Provider serving callers that name none.

        The one explicitly preferred if it is actually bound, else the first
        bound. With a single provider this is that provider, which is why a
        one-vendor session is unaffected by any of this.
        """
        bound = self.bound_providers()
        if self._preferred_provider and self._preferred_provider in bound:
            return self._preferred_provider
        return bound[0] if bound else None

    def client_at(
        self, tier: str, provider: str | None = None,
    ) -> LLMModelClient | None:
        """The client registered for a tier of a provider, if any.

        The supported way to ask what is bound where. Callers used to index
        the client map by tier directly, which stopped meaning anything once
        two vendors could hold the same tier at once.
        """
        selected = provider or self.default_provider
        if selected is None:
            return None
        return self._clients.get((selected, tier))

    def connected_models(self) -> list[dict[str, str]]:
        # provider_id rides along because with two vendors bound, "heavy" no
        # longer identifies a model — and a run record that cannot say which
        # provider served it is not interpretable afterwards.
        return [{"provider_id": provider_id, "tier": tier, "model_id": c.model_id}
                for (provider_id, tier), c in self._clients.items() if c.connected]

    # --- Routing ---------------------------------------------------------------

    def _route(self, max_tokens: int, hints: QueryHints | None = None,
               document_mime: str | None = None,
               provider: str | None = None) -> LLMModelClient:
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

        # Provider is resolved before tier, and never falls through to
        # another vendor. An operator running a module on Anthropic to compare
        # it against Gemini gets Anthropic or an error — silently answering
        # from the other vendor would make the comparison meaningless and the
        # output unattributable.
        selected = provider or self.default_provider
        if selected is None:
            raise RuntimeError("No LLM client connected — run 'connect' first")
        if provider and provider not in self.bound_providers():
            raise RuntimeError(
                f"Provider {provider!r} is not bound — bound: "
                f"{', '.join(self.bound_providers()) or 'none'}"
            )

        if document_mime:
            order = self._prefer_native_capable(order, document_mime, selected)

        for tier in order:
            c = self._clients.get((selected, tier))
            if c and c.connected:
                return c
        # No tier of the selected provider is in the preferred order. Take any
        # connected tier of that same provider rather than failing (e.g. a
        # legacy single-key setup, or a manifest declaring one tier).
        for (provider_id, _), c in self._clients.items():
            if provider_id == selected and c.connected:
                return c
        raise RuntimeError(
            f"No connected client for provider {selected!r} — run 'connect' first"
        )

    def _prefer_native_capable(
        self, order: tuple[str, ...], document_mime: str, provider: str,
    ) -> tuple[str, ...]:
        """Move tiers that natively handle this MIME type to the front.

        Relative order within each group is preserved, so this only breaks
        ties — it never overrides an explicit tier choice that is capable.
        Scoped to one provider: native support is a property of a model, and
        Gemini reading PDFs natively says nothing about another vendor's tier.
        """
        capability = _NATIVE_CAPABILITY_BY_MIME.get(document_mime)
        if not capability or not self._tier_specs:
            return order
        capable = [
            t for t in order
            if capability in (
                self._tier_specs[(provider, t)].capabilities
                if (provider, t) in self._tier_specs else ()
            )
        ]
        if not capable:
            return order
        return tuple(capable) + tuple(t for t in order if t not in capable)

    def _attributed(
        self, result: LLMResponse, client: LLMModelClient,
    ) -> LLMResponse:
        """Ensure the response names the provider that served it.

        Each client stamps its own provider_id and this does not override one.
        It is a backstop: with several vendors bound concurrently, a response
        that cannot say who produced it is not interpretable afterwards, and a
        client that simply forgot would produce unattributable output rather
        than an error. Too important to leave to every client getting it right.

        Attributing to the routed client is correct even after a tier change or
        a retired-model substitution: both stay within the same provider by
        construction, so the vendor is unchanged either way.
        """
        if result.provider_id:
            return result
        return replace(result, provider_id=_provider_of(client))

    def _locate(self, client: LLMModelClient) -> tuple[str, str] | None:
        """Reverse-lookup the (provider_id, tier) a client is registered under."""
        for key, c in self._clients.items():
            if c is client:
                return key
        return None

    def _tier_of(self, client: LLMModelClient) -> str | None:
        """Tier a client is registered under, without its provider."""
        located = self._locate(client)
        return located[1] if located else None

    def _spec_of(self, client: LLMModelClient) -> TierSpec | None:
        """Tier spec for a client, looked up by its own provider and tier.

        Looking this up by tier alone would read a second vendor's caps off
        the first vendor's manifest — and the two are not interchangeable:
        Anthropic and OpenAI cap output at 128k against Gemini's 65,536.
        """
        located = self._locate(client)
        return self._tier_specs.get(located) if located else None

    def _output_cap(self, client: LLMModelClient) -> int | None:
        """Output-token cap of the model this client actually runs.

        Keyed by model id first so an EVENTMILL_MODEL_* override or a
        retired-model substitution is clamped against its own cap rather
        than the cap of the tier it is registered under. Falls back to the
        tier spec for a model the manifest does not describe.
        """
        cap = self._caps_by_model.get(client.model_id)
        if cap:
            return cap
        spec = self._spec_of(client)
        tier = spec.tier if spec else None
        if spec is None:
            return None
        if client.model_id != spec.model_id:
            logger.warning(
                "No declared output cap for %s — assuming the %s tier cap "
                "(%d). Set EVENTMILL_MAX_OUTPUT_%s if it differs.",
                client.model_id, tier, spec.max_output_tokens, tier.upper(),
            )
        return spec.max_output_tokens

    def _context_cap(self, client: LLMModelClient) -> int:
        """Input context window of the model this client actually runs.

        Keyed by model id for the same reason as _output_cap: an
        EVENTMILL_MODEL_* override or a retired-model substitution changes
        the model without changing the tier it is registered under.
        """
        cap = self._context_by_model.get(client.model_id)
        if cap:
            return cap
        spec = self._spec_of(client)
        return spec.max_context_tokens if spec else 1_048_576

    def _clamp_tokens(self, client: LLMModelClient, max_tokens: int) -> int:
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
    def _is_access_error(error: str) -> bool:
        """Return True when the key is not entitled to this model.

        A single legacy GEMINI_API_KEY binds both tiers, and it may reach
        Flash but not the Pro preview. That returns PERMISSION_DENIED, which
        is neither a quota problem nor a retired model id — without this,
        heavy-tier plugins hard-fail on a key that could still serve them
        from the other tier.
        """
        lowered = error.lower()
        return "permission_denied" in lowered or (
            "403" in error and "denied" in lowered
        )

    def _kind_of(self, result: LLMResponse) -> str:
        """Classify a failure, preferring what the client already decided.

        A client that owns its provider's exceptions classifies them into the
        shared error_kind vocabulary, and this routes on that. The string
        matching below is the fallback for a client that classified nothing —
        it reads Google's wire vocabulary and is the last thing in the
        dispatcher that does.
        """
        if result.error_kind:
            return result.error_kind
        error = result.error or ""
        if self._is_model_not_found(error):
            return "model_not_found"
        if self._is_access_error(error):
            return "access"
        if self._is_quota_error(error):
            return "quota"
        return "other"

    def _should_try_other_tier(self, result: LLMResponse) -> bool:
        """Whether this failure is worth retrying on the other connected tier."""
        return self._kind_of(result) in TIER_CHANGE_KINDS

    @staticmethod
    def _is_model_not_found(error: str) -> bool:
        """Return True when the model id itself was rejected.

        Preview endpoints are retired with ~2 weeks' notice, so a pinned
        preview model can start returning NOT_FOUND without warning.
        """
        lowered = error.lower()
        return (
            "not_found" in lowered
            or "is not found for api version" in lowered
            or "was not found" in lowered
            or _HTTP_404_RE.search(error) is not None
        )

    def _retry_on_retired_model(
        self, client: LLMModelClient, result: LLMResponse,
    ) -> LLMModelClient | None:
        """Rebind the tier to its fallback model after a NOT_FOUND.

        Returns None when the failure is not a model-id problem or the tier
        declares no fallback.
        """
        if self._kind_of(result) != "model_not_found":
            return None
        located = self._locate(client)
        spec = self._tier_specs.get(located) if located else None
        tier = located[1] if located else None
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

        # The client decides what carrying a live connection forward means:
        # it has to reuse the open session and keep the spend, because
        # total_tokens_used sums over the live clients and a substitute that
        # started at zero would undercount the session.
        substitute = client.with_model(spec.fallback_model_id)
        # Register it so subsequent calls in this session skip the failed id.
        # Under its own (provider, tier), so a retired model on one vendor
        # cannot displace another vendor's client at the same tier.
        if located:
            self._clients[located] = substitute
        return substitute

    def _fallback_client(self, primary: LLMModelClient) -> LLMModelClient | None:
        """Return the other connected tier **of the same provider**, or None.

        This is the one place the data-handling boundary lives. A quota
        failure must never move a session to another vendor: nobody chose it,
        investigation data would reach a provider the operator did not select,
        and the output would be unattributable afterwards.

        Deliberate provider selection is the requirement; silent failover is
        the hazard. The two differ by who decided and whether it is recorded,
        which is why this method is three lines of constraint rather than a
        policy spanning the design.
        """
        located = self._locate(primary)
        provider = located[0] if located else _provider_of(primary)
        for (provider_id, tier), c in self._clients.items():
            if provider_id != provider:
                continue
            if c is not primary and c.connected:
                logger.warning(
                    "Tier change within %s: %s (%s) → %s (%s) after quota "
                    "exhaustion", provider,
                    located[1] if located else "?", primary.model_id,
                    tier, c.model_id,
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
        provider: str | None = None,
    ) -> LLMResponse:
        try:
            client = self._route(max_tokens, hints=hints, provider=provider)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))
        result = client.query_text(
            prompt=prompt,
            system_context=system_context,
            max_tokens=self._clamp_tokens(client, max_tokens),
            grounding_data=grounding_data,
            hints=hints,
        )
        if not result.ok and self._should_try_other_tier(result):
            fallback = self._fallback_client(client)
            if fallback:
                logger.warning(
                    "%s unavailable (%s) — falling back to %s",
                    client.model_id,
                    self._kind_of(result),
                    fallback.model_id,
                )
                print(
                    f"\n  ⚠️  {client.model_id} unavailable "
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
            substitute = self._retry_on_retired_model(client, result)
            if substitute:
                result = substitute.query_text(
                    prompt=prompt,
                    system_context=system_context,
                    max_tokens=self._clamp_tokens(substitute, max_tokens),
                    grounding_data=grounding_data,
                    hints=hints,
                )
        return self._attributed(result, client)

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        hints: QueryHints | None = None,
        provider: str | None = None,
    ) -> LLMResponse:
        try:
            client = self._route(max_tokens, hints=hints, provider=provider)
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
        if not result.ok and self._should_try_other_tier(result):
            fallback = self._fallback_client(client)
            if fallback:
                logger.warning(
                    "%s unavailable (%s) — falling back to %s",
                    client.model_id,
                    self._kind_of(result),
                    fallback.model_id,
                )
                print(
                    f"\n  ⚠️  {client.model_id} unavailable "
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
            substitute = self._retry_on_retired_model(client, result)
            if substitute:
                result = substitute.query_multimodal(
                    prompt=prompt,
                    image_data=image_data,
                    image_format=image_format,
                    system_context=system_context,
                    max_tokens=self._clamp_tokens(substitute, max_tokens),
                    hints=hints,
                )
        return self._attributed(result, client)

    def query_with_document(
        self,
        prompt: str,
        artifact: ArtifactRef,
        system_context: str | None = None,
        max_tokens: int = 8192,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
        provider: str | None = None,
    ) -> LLMResponse:
        """Query with a document artifact.

        Resolves the artifact into a DocumentPart, applies the policy the
        provider cannot decide — the size guard and the output clamp — and
        hands the part to the client, which picks the ingestion path its own
        provider supports. The response's transport_path records which one.

        Returns ok=False when no connected model ingests this MIME type
        natively, so the plugin can fall back to text extraction.
        """
        hints = hints or QueryHints(tier="heavy", prefers_native_file=True)
        mime_type = artifact.metadata.get("mime_type", "application/pdf")

        # PDF page cost is set by media_resolution
        # (low 280 / medium 560 / high 1120 tokens per page). Make the default
        # explicit rather than relying on the provider's implicit choice.
        if mime_type == "application/pdf" and hints.media_resolution is None:
            hints = replace(hints, media_resolution=default_media_resolution())

        try:
            client = self._route(
                max_tokens, hints=hints, document_mime=mime_type,
                provider=provider,
            )
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))

        if mime_type == "application/pdf":
            overflow = self._pdf_context_overflow(client, artifact, hints)
            if overflow:
                return overflow

        # Check if the underlying model supports native document ingestion.
        # Read from the provider manifest rather than asked of the SDK, so
        # this agrees with the routing that chose the client.
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

        # Grounding data is folded in here rather than passed along: the
        # document signature stays about the document, and composing it is
        # string assembly no provider needs a say in.
        full_prompt = compose_prompt(prompt, grounding_data)

        result = client.query_with_document(
            prompt=full_prompt,
            doc=doc,
            system_context=system_context,
            max_tokens=self._clamp_tokens(client, max_tokens),
            hints=hints,
        )
        # The heavy tier is a Preview endpoint, so this path is the most
        # likely of the three to meet a retired model id. Plugins arrive here
        # through TierScopedLLMClient with their manifest tier already set —
        # the heavy default above applies only to direct framework callers.
        if not result.ok:
            substitute = self._retry_on_retired_model(client, result)
            if substitute:
                result = substitute.query_with_document(
                    prompt=full_prompt,
                    doc=doc,
                    system_context=system_context,
                    max_tokens=self._clamp_tokens(substitute, max_tokens),
                    hints=hints,
                )
        return self._attributed(result, client)

    def _pdf_context_overflow(
        self, client: LLMModelClient, artifact: ArtifactRef,
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

        context_limit = self._context_cap(client)

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
        self, client: LLMModelClient, mime_type: str,
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
        spec = self._spec_of(client)
        if spec is None:
            return True
        return capability in spec.capabilities


class TierScopedLLMClient:
    """Applies a plugin's manifest model_tier as the default for its queries.

    The framework wraps the shared LLMDispatcher in one of these per plugin
    execution. Every query the plugin makes without explicit QueryHints picks
    up the tier its manifest declares; a plugin that passes its own hints
    keeps full control.

    This is the single place the manifest default is applied — LLMDispatcher
    stays plugin-agnostic, and no existing plugin call site has to change.
    """

    def __init__(self, inner: LLMQueryInterface, default_tier: str = "light",
                 default_provider: str | None = None):
        self._inner = inner
        # "none" means the plugin declares no LLM work; treat any incidental
        # call as light rather than silently promoting it to Pro.
        self.default_tier = (
            default_tier if default_tier in ("light", "heavy") else "light"
        )
        # Provider for this execution, when the operator selected one. This is
        # the right home for it and QueryHints is not: hints are plugin-facing,
        # so a provider field there would put vendor choice in plugin code and
        # let a plugin override an operator's A/B selection — which would make
        # the comparison unattributable and break "the analysis tools do not
        # change". None means the dispatcher's session default serves.
        self.default_provider = default_provider

    def _provider_kwargs(self) -> dict[str, str]:
        """Provider scope to pass inward, if there is one and it is accepted.

        Duck-typed on the inner object, because TierScopedLLMClient also wraps
        bare clients and test fakes whose query methods take no provider.
        """
        if not self.default_provider:
            return {}
        if not getattr(self._inner, "accepts_provider_scope", False):
            return {}
        return {"provider": self.default_provider}

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
            **self._provider_kwargs(),
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
            **self._provider_kwargs(),
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
            **self._provider_kwargs(),
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
