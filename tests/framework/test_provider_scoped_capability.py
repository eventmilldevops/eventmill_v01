"""
Capability and output-limit questions answer for the provider that will serve.

A live run of threat_intel_ingester pinned to OpenAI, with Gemini also bound,
planned nine native PDF batches and had every one refused: the ingester asked
``supports_native_document`` and the dispatcher answered for *any* connected
client, so Gemini's native PDF support was reported to a plugin that could
only ever be routed to OpenAI. The same run sized its batches with Gemini's
output cap, because the plugins read limits from the default provider's
manifest whatever the operator had selected.

Routing never crosses providers, so neither question has a cross-provider
answer. These tests pin both to the provider ``query_with_document`` and
``query_text`` would actually use.

Real provider ids are used on purpose: ``output_limits`` reads the provider
manifests, and the point is that two real vendors' figures differ.
"""

import inspect

import pytest

from framework.llm.dispatcher import LLMDispatcher, TierScopedLLMClient
from framework.llm.providers import OutputLimits, TierSpec, output_limits
from framework.plugins.protocol import ArtifactRef

from tests.framework.test_provider_seam import PublicOnlyClient

PDF = "application/pdf"


def _spec(tier: str, provider_id: str, capabilities: tuple[str, ...]) -> TierSpec:
    return TierSpec(
        tier=tier, model_id=f"{provider_id}-{tier}", api_key_env="KEY",
        max_output_tokens=65536, max_context_tokens=1_000_000,
        cost_tier="low", capabilities=capabilities, provider_id=provider_id,
    )


def _dispatcher(preferred_provider: str | None = None) -> LLMDispatcher:
    """Gemini reads PDFs natively; OpenAI does not (no native_pdf capability)."""
    clients, specs = {}, {}
    for provider_id, caps in (
        ("gcp_gemini", ("text", "native_pdf")),
        ("openai", ("text", "multimodal_image")),
    ):
        for tier in ("light", "heavy"):
            clients[(provider_id, tier)] = PublicOnlyClient(
                f"{provider_id}-{tier}", tier, provider_id,
            )
            specs[(provider_id, tier)] = _spec(tier, provider_id, caps)
    return LLMDispatcher(
        clients=clients, tier_specs=specs, preferred_provider=preferred_provider,
    )


def _pdf_artifact(tmp_path) -> ArtifactRef:
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-fake")
    return ArtifactRef(
        artifact_id="art_pdf", artifact_type="pdf_report",
        file_path=str(pdf), metadata={"mime_type": PDF},
    )


class TestNativeSupportIsScopedToOneProvider:
    def test_a_named_provider_answers_for_itself_only(self) -> None:
        dispatcher = _dispatcher()
        assert dispatcher.supports_native_document(PDF, provider="gcp_gemini")
        assert not dispatcher.supports_native_document(PDF, provider="openai")

    def test_with_no_provider_named_the_session_default_answers(self) -> None:
        # The defect: this returned True because Gemini was bound, although a
        # query naming no provider is routed to OpenAI.
        assert not _dispatcher(preferred_provider="openai").supports_native_document(PDF)
        assert _dispatcher(preferred_provider="gcp_gemini").supports_native_document(PDF)

    @pytest.mark.parametrize("provider", ["gcp_gemini", "openai"])
    def test_the_wrapper_passes_the_operators_provider_inward(
        self, provider: str,
    ) -> None:
        # Gemini is the dispatcher default here, so a wrapper that dropped
        # the scope would answer True for openai.
        scoped = TierScopedLLMClient(
            _dispatcher(), default_tier="light", default_provider=provider,
        )
        assert scoped.supports_native_document(PDF) is (provider == "gcp_gemini")

    @pytest.mark.parametrize("provider", ["gcp_gemini", "openai"])
    def test_the_answer_agrees_with_what_the_document_call_does(
        self, provider: str, tmp_path,
    ) -> None:
        # The contract a plugin relies on: if it is told native is available,
        # the native call is not refused for lack of support, and vice versa.
        scoped = TierScopedLLMClient(
            _dispatcher(), default_tier="light", default_provider=provider,
        )
        result = scoped.query_with_document("summarise", _pdf_artifact(tmp_path))
        refused = "lacks native support" in (result.fallback_reason or "")
        assert scoped.supports_native_document(PDF) is not refused

    def test_the_plugin_facing_signature_still_takes_no_provider(self) -> None:
        scoped = TierScopedLLMClient(_dispatcher(), default_provider="openai")
        params = inspect.signature(scoped.supports_native_document).parameters
        assert "provider" not in params


class TestOutputLimitsComeFromTheServingProvider:
    def test_the_two_vendors_really_differ(self) -> None:
        # Otherwise every test below would pass against the old behaviour.
        assert output_limits("light", "medium", "openai") != output_limits(
            "light", "medium", "gcp_gemini",
        )

    def test_the_dispatcher_resolves_like_routing(self) -> None:
        dispatcher = _dispatcher(preferred_provider="openai")
        assert dispatcher.output_limits("light", "medium") == output_limits(
            "light", "medium", "openai",
        )
        assert dispatcher.output_limits(
            "light", "medium", provider="gcp_gemini",
        ) == output_limits("light", "medium", "gcp_gemini")

    def test_the_wrapper_answers_for_the_operators_provider(self) -> None:
        scoped = TierScopedLLMClient(
            _dispatcher(), default_tier="heavy", default_provider="openai",
        )
        assert scoped.output_limits(thinking_level="high") == output_limits(
            "heavy", "high", "openai",
        )

    def test_the_tier_defaults_to_the_manifest_tier(self) -> None:
        scoped = TierScopedLLMClient(
            _dispatcher(), default_tier="heavy", default_provider="openai",
        )
        assert scoped.output_limits() == output_limits("heavy", None, "openai")

    def test_a_bare_client_answers_for_its_own_provider(self) -> None:
        bare = PublicOnlyClient("solo", "light", "openai")
        scoped = TierScopedLLMClient(bare, default_tier="light")
        assert scoped.output_limits("light", "low") == output_limits(
            "light", "low", "openai",
        )

    def test_the_plugin_facing_signature_takes_no_provider(self) -> None:
        scoped = TierScopedLLMClient(_dispatcher(), default_provider="openai")
        assert "provider" not in inspect.signature(scoped.output_limits).parameters

    def test_the_content_budget_is_cap_less_reserve(self) -> None:
        assert OutputLimits(1000, 300).content_budget == 700
        assert OutputLimits(100, 300).content_budget == 1
