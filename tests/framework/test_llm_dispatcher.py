"""
Tests for LLM tier routing.

Pins the precedence rule the framework depends on:
    per-call QueryHints > manifest model_tier > light

Output size never selects a tier - both Gemini 3.x tiers are
capacity-identical, so tier means reasoning depth and cost only.
"""

from __future__ import annotations

import pytest

from framework.llm.client import LLMDispatcher, TierScopedLLMClient, _build_config
from framework.llm.providers import (
    TierSpec,
    default_media_resolution,
    load_tier_specs,
    tokens_per_pdf_page,
)
from framework.plugins.protocol import ArtifactRef, LLMResponse, QueryHints


class FakeClient:
    """Stand-in for MCPLLMClient that records what it was asked to do."""

    def __init__(self, model_id: str, connected: bool = True,
                 fail_with: str | None = None):
        self.model_id = model_id
        self.connected = connected
        self.total_tokens_used = 0
        self.calls: list[dict] = []
        self._fail_with = fail_with

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.calls.append(
            {"kind": "text", "max_tokens": max_tokens, "hints": hints}
        )
        if self._fail_with:
            return LLMResponse(ok=False, error=self._fail_with)
        return LLMResponse(ok=True, text=f"answer from {self.model_id}")

    def query_multimodal(self, prompt, image_data, image_format,
                         system_context=None, max_tokens=4096, hints=None):
        self.calls.append(
            {"kind": "multimodal", "max_tokens": max_tokens, "hints": hints}
        )
        if self._fail_with:
            return LLMResponse(ok=False, error=self._fail_with)
        return LLMResponse(ok=True, text=f"answer from {self.model_id}")

    def _build_prompt(self, prompt, grounding_data=None):
        return prompt


def _specs() -> dict[str, TierSpec]:
    """Tier specs mirroring the real Gemini 3.x values.

    Both tiers are capacity-identical (1,048,576 in / 65,536 out) — tier
    signals reasoning depth and cost, not how much fits.
    """
    return {
        "light": TierSpec("light", "flash", "K_LIGHT", 65536, 1_048_576, "low",
                          ("text", "native_pdf")),
        "heavy": TierSpec("heavy", "pro", "K_HEAVY", 65536, 1_048_576, "high",
                          ("text", "native_pdf", "deep_reasoning"),
                          fallback_model_id="flash"),
    }


def _asymmetric_specs() -> dict[str, TierSpec]:
    """Specs with differing output caps, to exercise per-tier clamping."""
    return {
        "light": TierSpec("light", "flash", "K_LIGHT", 8192, 1_048_576, "low",
                          ("text",)),
        "heavy": TierSpec("heavy", "pro", "K_HEAVY", 65536, 1_048_576, "high",
                          ("text", "deep_reasoning")),
    }


@pytest.fixture
def clients():
    return {"light": FakeClient("flash"), "heavy": FakeClient("pro")}


@pytest.fixture
def dispatcher(clients):
    return LLMDispatcher(clients=clients, tier_specs=_specs())


# ---------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------


class TestRoutingPrecedence:
    def test_explicit_light_hint_beats_token_heuristic(self, dispatcher, clients):
        # 16384 would route heavy on token count alone.
        dispatcher.query_text(
            "p", max_tokens=16384, hints=QueryHints(tier="light"),
        )
        assert clients["light"].calls
        assert not clients["heavy"].calls

    def test_explicit_heavy_hint_routes_heavy_at_low_token_counts(
        self, dispatcher, clients,
    ):
        dispatcher.query_text("p", max_tokens=100, hints=QueryHints(tier="heavy"))
        assert clients["heavy"].calls
        assert not clients["light"].calls

    def test_needs_reasoning_forces_heavy(self, dispatcher, clients):
        dispatcher.query_text(
            "p", max_tokens=100,
            hints=QueryHints(tier="light", needs_reasoning=True),
        )
        assert clients["heavy"].calls
        assert not clients["light"].calls

    def test_unhinted_calls_default_to_light_at_any_size(self, dispatcher, clients):
        """Output size must not select a tier - the tiers are the same size."""
        dispatcher.query_text("p", max_tokens=100)
        dispatcher.query_text("p", max_tokens=60_000)
        assert len(clients["light"].calls) == 2
        assert not clients["heavy"].calls

    def test_hints_without_a_tier_express_no_opinion(self, clients):
        """thinking_level alone must not override the analyst's pinned tier."""
        pinned = LLMDispatcher(
            clients=clients, preferred_tier="heavy", tier_specs=_specs(),
        )
        pinned.query_text("p", max_tokens=100, hints=QueryHints(thinking_level="low"))
        assert clients["heavy"].calls
        assert not clients["light"].calls

    def test_pinned_tier_beats_the_light_default(self, clients):
        pinned = LLMDispatcher(
            clients=clients, preferred_tier="heavy", tier_specs=_specs(),
        )
        pinned.query_text("p", max_tokens=16384)
        assert clients["heavy"].calls
        assert not clients["light"].calls

    def test_hints_beat_pinned_tier(self, clients):
        pinned = LLMDispatcher(
            clients=clients, preferred_tier="light", tier_specs=_specs(),
        )
        pinned.query_text("p", max_tokens=100, hints=QueryHints(tier="heavy"))
        assert clients["heavy"].calls


# ---------------------------------------------------------------------------
# Manifest tier via TierScopedLLMClient
# ---------------------------------------------------------------------------


class TestTierScopedClient:
    def test_manifest_tier_applied_when_plugin_passes_no_hints(
        self, dispatcher, clients,
    ):
        scoped = TierScopedLLMClient(dispatcher, default_tier="light")
        scoped.query_text("p", max_tokens=4096)
        assert clients["light"].calls
        assert not clients["heavy"].calls

    def test_plugin_hints_override_manifest_tier(self, dispatcher, clients):
        scoped = TierScopedLLMClient(dispatcher, default_tier="light")
        scoped.query_text("p", max_tokens=100, hints=QueryHints(tier="heavy"))
        assert clients["heavy"].calls
        assert not clients["light"].calls

    def test_heavy_manifest_tier_routes_heavy_at_low_token_counts(
        self, dispatcher, clients,
    ):
        scoped = TierScopedLLMClient(dispatcher, default_tier="heavy")
        scoped.query_text("p", max_tokens=100)
        assert clients["heavy"].calls

    def test_unknown_tier_falls_back_to_light(self, dispatcher):
        assert TierScopedLLMClient(
            dispatcher, default_tier="none",
        ).default_tier == "light"
        assert TierScopedLLMClient(
            dispatcher, default_tier="",
        ).default_tier == "light"

    def test_multimodal_carries_the_manifest_tier(self, dispatcher, clients):
        scoped = TierScopedLLMClient(dispatcher, default_tier="heavy")
        scoped.query_multimodal("p", b"\x00", "png", max_tokens=100)
        assert clients["heavy"].calls
        assert not clients["light"].calls


    def test_partial_hints_keep_the_manifest_tier(self, dispatcher, clients):
        """Hints that say nothing about tier must not demote a heavy plugin.

        QueryHints carries tier-irrelevant fields (thinking_level,
        media_resolution). Setting one of those alone used to route the
        plugin to light, because tier defaulted to "light" rather than None.
        """
        scoped = TierScopedLLMClient(dispatcher, default_tier="heavy")
        scoped.query_text("p", max_tokens=100, hints=QueryHints(thinking_level="low"))
        assert clients["heavy"].calls
        assert not clients["light"].calls

    def test_partial_hints_are_otherwise_preserved(self, dispatcher, clients):
        scoped = TierScopedLLMClient(dispatcher, default_tier="heavy")
        scoped.query_text(
            "p", max_tokens=100,
            hints=QueryHints(thinking_level="low", media_resolution="low"),
        )
        sent = clients["heavy"].calls[0]["hints"]
        assert sent.tier == "heavy"
        assert sent.thinking_level == "low"
        assert sent.media_resolution == "low"


# ---------------------------------------------------------------------------
# Output-token clamping
# ---------------------------------------------------------------------------


class TestTokenClamping:
    def test_clamps_to_the_model_output_cap(self, dispatcher, clients):
        # Both Gemini 3.x tiers cap output at 65,536.
        dispatcher.query_text("p", max_tokens=200_000, hints=QueryHints(tier="light"))
        assert clients["light"].calls[0]["max_tokens"] == 65536

    def test_does_not_clamp_within_cap(self, dispatcher, clients):
        dispatcher.query_text("p", max_tokens=16384, hints=QueryHints(tier="heavy"))
        assert clients["heavy"].calls[0]["max_tokens"] == 16384

    def test_clamping_is_per_tier(self, clients):
        """A tier with a lower cap clamps independently of the other."""
        d = LLMDispatcher(clients=clients, tier_specs=_asymmetric_specs())
        d.query_text("p", max_tokens=16384, hints=QueryHints(tier="light"))
        d.query_text("p", max_tokens=16384, hints=QueryHints(tier="heavy"))
        assert clients["light"].calls[0]["max_tokens"] == 8192
        assert clients["heavy"].calls[0]["max_tokens"] == 16384

    def test_no_clamping_without_tier_specs(self, clients):
        loose = LLMDispatcher(clients=clients, tier_specs={})
        loose.query_text("p", max_tokens=999_999, hints=QueryHints(tier="light"))
        assert clients["light"].calls[0]["max_tokens"] == 999_999

    def test_clamps_to_the_model_that_actually_runs(self):
        """An env override can point a tier at a model with a different cap.

        The heavy tier here runs light's model, so it must clamp to 8,192 -
        clamping to the heavy tier's 65,536 would be rejected by the provider.
        """
        clients = {"light": FakeClient("flash"), "heavy": FakeClient("flash")}
        d = LLMDispatcher(clients=clients, tier_specs=_asymmetric_specs())
        d.query_text("p", max_tokens=16384, hints=QueryHints(tier="heavy"))
        assert clients["heavy"].calls[0]["max_tokens"] == 8192


# ---------------------------------------------------------------------------
# Quota fallback across tiers
# ---------------------------------------------------------------------------


class TestQuotaFallback:
    def test_falls_back_to_other_tier_and_reclamps(self):
        clients = {
            "heavy": FakeClient("pro", fail_with="429 RESOURCE_EXHAUSTED quota"),
            "light": FakeClient("flash"),
        }
        # Asymmetric caps so the re-clamp on fallback is observable.
        d = LLMDispatcher(clients=clients, tier_specs=_asymmetric_specs())
        result = d.query_text("p", max_tokens=16384, hints=QueryHints(tier="heavy"))

        assert result.ok
        # Heavy took it at full size, light got it clamped to its own cap.
        assert clients["heavy"].calls[0]["max_tokens"] == 16384
        assert clients["light"].calls[0]["max_tokens"] == 8192

    def test_falls_back_when_the_key_lacks_access_to_the_model(self):
        """One legacy key binds both tiers but may not be entitled to Pro."""
        clients = {
            "heavy": FakeClient("pro", fail_with="403 PERMISSION_DENIED for model"),
            "light": FakeClient("flash"),
        }
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        result = d.query_text("p", max_tokens=100, hints=QueryHints(tier="heavy"))

        assert result.ok
        assert clients["light"].calls

    def test_non_quota_error_does_not_fall_back(self):
        clients = {
            "heavy": FakeClient("pro", fail_with="400 INVALID_ARGUMENT"),
            "light": FakeClient("flash"),
        }
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        result = d.query_text("p", max_tokens=100, hints=QueryHints(tier="heavy"))

        assert not result.ok
        assert not clients["light"].calls


# ---------------------------------------------------------------------------
# Degraded configurations
# ---------------------------------------------------------------------------


class TestDegradedSetups:
    def test_single_light_client_serves_a_heavy_request(self):
        """Legacy single-key setup must answer, not raise."""
        clients = {"light": FakeClient("flash")}
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        result = d.query_text("p", max_tokens=100, hints=QueryHints(tier="heavy"))
        assert result.ok
        assert clients["light"].calls

    def test_unroutable_tier_key_still_answers(self):
        """A client registered under a non-tier key is better than no client."""
        clients = {"default": FakeClient("flash")}
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        result = d.query_text("p", max_tokens=100)
        assert result.ok

    def test_no_connected_client_returns_error_not_exception(self):
        clients = {"light": FakeClient("flash", connected=False)}
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        result = d.query_text("p", max_tokens=100)
        assert not result.ok
        assert "No LLM client connected" in (result.error or "")


# ---------------------------------------------------------------------------
# Provider manifest
# ---------------------------------------------------------------------------


class TestProviderManifest:
    def test_ships_light_and_heavy_tiers(self):
        specs = load_tier_specs()
        assert set(specs) == {"light", "heavy"}
        assert "deep_reasoning" in specs["heavy"].capabilities
        assert "deep_reasoning" not in specs["light"].capabilities

    def test_tiers_are_capacity_identical(self):
        """Gemini 3.x: tier signals reasoning depth and cost, not capacity.

        Guards against a stale-cap regression — the manifest previously
        declared light at 8,192 output tokens against a real 65,536.
        """
        specs = load_tier_specs()
        assert (
            specs["light"].max_output_tokens
            == specs["heavy"].max_output_tokens
            == 65_536
        )
        assert (
            specs["light"].max_context_tokens
            == specs["heavy"].max_context_tokens
            == 1_048_576
        )

    def test_preview_heavy_tier_declares_a_fallback(self):
        """The heavy model is a Preview endpoint and can be retired."""
        specs = load_tier_specs()
        assert specs["heavy"].fallback_model_id
        assert specs["heavy"].fallback_model_id != specs["heavy"].model_id

    def test_model_id_override_from_env(self, monkeypatch):
        monkeypatch.setenv("EVENTMILL_MODEL_LIGHT", "gemini-experimental")
        assert load_tier_specs()["light"].model_id == "gemini-experimental"

    def test_unknown_provider_returns_empty(self):
        assert load_tier_specs("no_such_provider") == {}


# ---------------------------------------------------------------------------
# Gemini 3.x generation controls
# ---------------------------------------------------------------------------


class TestGenerationControls:
    """thinking_level and media_resolution must reach GenerateContentConfig."""

    @staticmethod
    def _cfg(hints):
        return _build_config("sys", 4096, hints)

    def test_no_hints_leaves_provider_defaults(self):
        cfg = self._cfg(None)
        assert cfg.thinking_config is None
        assert cfg.media_resolution is None

    def test_default_hints_leave_provider_defaults(self):
        cfg = self._cfg(QueryHints())
        assert cfg.thinking_config is None
        assert cfg.media_resolution is None

    def test_needs_reasoning_implies_high_thinking(self):
        cfg = self._cfg(QueryHints(needs_reasoning=True))
        assert cfg.thinking_config.thinking_level == "HIGH"

    def test_explicit_thinking_level_wins_over_needs_reasoning(self):
        cfg = self._cfg(QueryHints(needs_reasoning=True, thinking_level="minimal"))
        assert cfg.thinking_config.thinking_level == "MINIMAL"

    def test_bulk_work_can_request_low_thinking(self):
        cfg = self._cfg(QueryHints(tier="light", thinking_level="low"))
        assert cfg.thinking_config.thinking_level == "LOW"

    def test_media_resolution_is_applied(self):
        cfg = self._cfg(QueryHints(media_resolution="low"))
        assert cfg.media_resolution == "MEDIA_RESOLUTION_LOW"

    def test_unknown_values_are_ignored_not_fatal(self):
        cfg = self._cfg(QueryHints(thinking_level="turbo", media_resolution="ultra"))
        assert cfg.thinking_config is None
        assert cfg.media_resolution is None

    def test_system_context_and_max_tokens_still_set(self):
        cfg = _build_config("be terse", 1234, QueryHints())
        assert cfg.system_instruction == "be terse"
        assert cfg.max_output_tokens == 1234

    def test_hints_reach_the_client_not_just_routing(self, dispatcher, clients):
        """Regression: the dispatcher routed on hints but dropped them."""
        hints = QueryHints(tier="light", thinking_level="low")
        dispatcher.query_text("p", max_tokens=100, hints=hints)
        assert clients["light"].calls[0]["hints"] is hints


# ---------------------------------------------------------------------------
# PDF context budget
# ---------------------------------------------------------------------------


class TestPdfContextGuard:
    """A PDF that cannot fit must be refused with an actionable message."""

    @staticmethod
    def _artifact(pages):
        return ArtifactRef(
            "a1", "pdf_report", "/nonexistent.pdf",
            metadata={"mime_type": "application/pdf", "pages": pages},
        )

    def _check(self, dispatcher, pages, resolution):
        return dispatcher._pdf_context_overflow(
            dispatcher._clients["heavy"],
            self._artifact(pages),
            QueryHints(media_resolution=resolution),
        )

    def test_thousand_pages_fits_at_medium(self, dispatcher):
        assert self._check(dispatcher, 1000, "medium") is None

    def test_thousand_pages_fits_at_low(self, dispatcher):
        assert self._check(dispatcher, 1000, "low") is None

    def test_thousand_pages_refused_at_high(self, dispatcher):
        r = self._check(dispatcher, 1000, "high")
        assert r is not None and not r.ok
        assert r.fallback_reason == "pdf_exceeds_context_at_resolution"
        # The message must name the resolution that would work.
        assert "medium" in r.error

    def test_small_pdf_fits_at_high(self, dispatcher):
        assert self._check(dispatcher, 200, "high") is None

    def test_above_provider_page_limit_refused(self, dispatcher):
        r = self._check(dispatcher, 1200, "medium")
        assert r is not None and not r.ok
        assert r.fallback_reason == "pdf_exceeds_provider_page_limit"

    def test_above_provider_size_limit_refused(self, dispatcher):
        art = ArtifactRef(
            "a1", "pdf_report", "",
            metadata={
                "mime_type": "application/pdf",
                "pages": 40,
                "size_bytes": 200 * 1024 * 1024,
            },
        )
        r = dispatcher._pdf_context_overflow(
            dispatcher._clients["heavy"], art, QueryHints(),
        )
        assert r is not None and not r.ok
        assert r.fallback_reason == "pdf_exceeds_provider_size_limit"

    def test_page_count_comes_from_metadata_when_present(self):
        """A GCS-resolved artifact has no local file to read."""
        art = ArtifactRef(
            "a1", "pdf_report", "/nonexistent.pdf",
            storage_uri="gs://bucket/report.pdf",
            metadata={"mime_type": "application/pdf", "pages": 42},
        )
        assert LLMDispatcher._pdf_page_count(art) == 42

    def test_page_count_unknown_for_unsizable_artifact(self):
        art = ArtifactRef(
            "a1", "pdf_report", "",
            storage_uri="gs://bucket/report.pdf",
            metadata={"mime_type": "application/pdf"},
        )
        assert LLMDispatcher._pdf_page_count(art) is None

    def test_context_limit_follows_the_model_that_actually_runs(self, clients):
        """An override can point a tier at a model with a smaller window.

        _clamp_tokens is keyed by model id for this reason; the context guard
        must agree, or a PDF is waved through against a budget the running
        model does not have.
        """
        specs = {
            "light": TierSpec("light", "flash", "K_LIGHT", 65536, 1_048_576,
                              "low", ("text", "native_pdf")),
            "heavy": TierSpec("heavy", "pro", "K_HEAVY", 65536, 128_000,
                              "high", ("text", "native_pdf")),
        }
        # The heavy client runs light's model, so it gets light's window.
        clients["heavy"] = FakeClient("flash")
        d = LLMDispatcher(clients=clients, tier_specs=specs)
        art = ArtifactRef(
            "a1", "pdf_report", "",
            metadata={"mime_type": "application/pdf", "pages": 500},
        )
        assert d._pdf_context_overflow(
            clients["heavy"], art, QueryHints(media_resolution="medium"),
        ) is None
        # A client genuinely on the small-window model is refused.
        refused = d._pdf_context_overflow(
            FakeClient("pro"), art, QueryHints(media_resolution="medium"),
        )
        assert refused is not None and not refused.ok
        assert "128,000" in (refused.error or "")

    def test_unknown_page_count_defers_to_provider(self, dispatcher):
        art = ArtifactRef(
            "a1", "pdf_report", "",
            metadata={"mime_type": "application/pdf"},
        )
        result = dispatcher._pdf_context_overflow(
            dispatcher._clients["heavy"], art, QueryHints(media_resolution="high"),
        )
        assert result is None


class TestPdfPageCost:
    """Per-page cost is set by media_resolution under Gemini 3.x, not a constant."""

    def test_cost_rises_with_resolution(self):
        assert tokens_per_pdf_page("low") == 280
        assert tokens_per_pdf_page("medium") == 560
        assert tokens_per_pdf_page("high") == 1120

    def test_default_is_medium(self):
        assert default_media_resolution() == "medium"
        assert tokens_per_pdf_page() == tokens_per_pdf_page("medium")

    def test_unknown_resolution_falls_back_to_default(self):
        assert tokens_per_pdf_page("nonsense") == 560


# ---------------------------------------------------------------------------
# Retired model fallback
# ---------------------------------------------------------------------------


class TestRetiredModelFallback:
    """A pinned Preview model can start returning NOT_FOUND without warning."""

    def test_detects_model_not_found(self):
        for err in (
            "404 NOT_FOUND",
            "models/gemini-3.1-pro-preview is not found for API version v1beta",
            "publisher model was not found",
        ):
            assert LLMDispatcher._is_model_not_found(err), err

    def test_does_not_confuse_quota_with_not_found(self):
        assert not LLMDispatcher._is_model_not_found("429 RESOURCE_EXHAUSTED quota")

    def test_a_404_outside_status_position_is_not_a_retired_model(self):
        """A false positive rewrites the tier's model for the whole session."""
        for err in (
            "400 INVALID_ARGUMENT: request id req-404abc rejected",
            "400 INVALID_ARGUMENT: byte offset 40412 invalid",
            "500 INTERNAL: upstream said 4045 bytes",
        ):
            assert not LLMDispatcher._is_model_not_found(err), err

    def test_no_fallback_when_tier_declares_none(self, clients):
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        # light declares no fallback_model_id
        assert d._retry_on_retired_model(clients["light"], "404 NOT_FOUND") is None

    def test_non_not_found_errors_do_not_substitute(self, clients):
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        assert d._retry_on_retired_model(clients["heavy"], "500 INTERNAL") is None

    def test_multimodal_retries_on_a_retired_model(self, clients, monkeypatch):
        clients["heavy"]._fail_with = "404 NOT_FOUND"
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        substitute = FakeClient("flash")
        monkeypatch.setattr(d, "_retry_on_retired_model", lambda c, e: substitute)

        result = d.query_multimodal(
            "p", b"data", "png", hints=QueryHints(tier="heavy"),
        )
        assert result.ok
        assert substitute.calls[0]["kind"] == "multimodal"

    def test_document_query_retries_on_a_retired_model(self, clients, monkeypatch):
        """The document path defaults to the Preview model, so it needs this most."""
        d = LLMDispatcher(clients=clients, tier_specs=_specs())
        substitute = FakeClient("flash")
        monkeypatch.setattr(d, "_retry_on_retired_model", lambda c, e: substitute)

        attempts = []

        def fake_exec(client, prompt, doc, system_context, max_tokens, hints=None):
            attempts.append(client)
            if len(attempts) == 1:
                return LLMResponse(ok=False, error="404 NOT_FOUND")
            return LLMResponse(ok=True, text="ok")

        monkeypatch.setattr(d, "_execute_document_query", fake_exec)
        art = ArtifactRef(
            "a1", "pdf_report", "", metadata={"mime_type": "application/pdf"},
        )
        result = d.query_with_document("p", art)

        assert result.ok
        assert attempts[0] is clients["heavy"]
        assert attempts[1] is substitute


# ---------------------------------------------------------------------------
# Native document capability
# ---------------------------------------------------------------------------


class TestNativeDocumentCapability:
    """The provider manifest decides, not a hardcoded MIME list."""

    @staticmethod
    def _specs_where_only_heavy_is_native():
        return {
            "light": TierSpec("light", "flash", "K_LIGHT", 65536, 1_048_576,
                              "low", ("text",)),
            "heavy": TierSpec("heavy", "pro", "K_HEAVY", 65536, 1_048_576,
                              "high", ("text", "native_pdf")),
        }

    def test_capability_follows_the_manifest(self, clients):
        d = LLMDispatcher(
            clients=clients, tier_specs=self._specs_where_only_heavy_is_native(),
        )
        assert d._model_supports_native_doc(clients["heavy"], "application/pdf")
        assert not d._model_supports_native_doc(clients["light"], "application/pdf")

    def test_supported_when_any_connected_tier_declares_it(self, clients):
        d = LLMDispatcher(
            clients=clients, tier_specs=self._specs_where_only_heavy_is_native(),
        )
        assert d.supports_native_document("application/pdf")

    def test_unsupported_when_no_tier_declares_it(self, clients):
        specs = {
            "light": TierSpec("light", "flash", "K_LIGHT", 65536, 1_048_576,
                              "low", ("text",)),
            "heavy": TierSpec("heavy", "pro", "K_HEAVY", 65536, 1_048_576,
                              "high", ("text",)),
        }
        d = LLMDispatcher(clients=clients, tier_specs=specs)
        assert not d.supports_native_document("application/pdf")

    def test_unknown_mime_type_is_never_native(self, dispatcher):
        assert not dispatcher.supports_native_document("application/zip")
