"""
One vendor reached under several provider ids.

Adopting a lab's specialist model alongside its general one broke an identity
the rest of the system had been able to assume: that a provider id names a
vendor. Three provider ids now reach OpenAI through one client class, so what
used to be a class attribute has to be per instance, and "how many vendors
agree" stops being answerable from provider ids alone.

These are the guards on that. Nothing here makes a network call — connect()
builds an SDK handle without touching the wire, and the dispatcher is exercised
against a fake.
"""

from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell
from framework.llm import factory
from framework.llm.dispatcher import LLMDispatcher
from framework.llm.providers import load_provider_manifest, load_tier_specs, vendor_of
from framework.plugins.protocol import LLMResponse

# One vendor under several provider ids. These reach different models on a
# different key from "openai", so they bind and are attributed independently,
# but they are the same lab.
DAYBREAK_PROVIDERS = ("openai_daybreak_red", "openai_daybreak_blue")

OPENAI_BACKED = ("openai",) + DAYBREAK_PROVIDERS

EXPECTED_VENDORS = {
    "gcp_gemini": "google",
    "anthropic": "anthropic",
    "openai": "openai",
    "openai_daybreak_red": "openai",
    "openai_daybreak_blue": "openai",
}


@pytest.fixture(autouse=True)
def clean_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip every LLM env var so a developer's .env cannot change an outcome."""
    for name in (
        "EVENTMILL_LLM_PROVIDERS",
        "EVENTMILL_MODEL_LIGHT", "EVENTMILL_MODEL_HEAVY",
        "EVENTMILL_MAX_OUTPUT_LIGHT", "EVENTMILL_MAX_OUTPUT_HEAVY",
        "GEMINI_API_KEY", "GEMINI_FLASH_API_KEY", "GEMINI_PRO_API_KEY",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_DAYBREAK_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    for provider_id in EXPECTED_VENDORS:
        token = provider_id.upper()
        for tier in ("LIGHT", "HEAVY"):
            monkeypatch.delenv(f"EVENTMILL_MODEL_{token}_{tier}", raising=False)
            monkeypatch.delenv(f"EVENTMILL_MAX_OUTPUT_{token}_{tier}", raising=False)
    load_provider_manifest.cache_clear()


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------


class TestBothColoursAreOrdinaryProviders:
    """Nothing about these is a special case. That is the design."""

    @pytest.mark.parametrize("provider_id", DAYBREAK_PROVIDERS)
    def test_both_tiers_are_declared_on_one_model(self, provider_id: str) -> None:
        # Both tiers on purpose. With one tier declared, a light-tier plugin
        # would reach this provider only through _route's take-any-connected-
        # tier fallback, which works by accident rather than by intent; and
        # _fallback_client would become a hazard rather than a wasted retry,
        # because the other tier of the provider would be a different model.
        specs = load_tier_specs(provider_id)
        assert set(specs) == {"light", "heavy"}
        assert len({s.model_id for s in specs.values()}) == 1

    @pytest.mark.parametrize("provider_id", DAYBREAK_PROVIDERS)
    def test_no_fallback_model_is_declared(self, provider_id: str) -> None:
        # openai.json's heavy tier falls back to Terra when Sol is retired.
        # There is no equivalent here: the only correct substitute for this
        # model is this model, and a comparison run quietly answered from
        # something else is worse than a failed run.
        for spec in load_tier_specs(provider_id).values():
            assert spec.fallback_model_id == ""

    @pytest.mark.parametrize("provider_id", DAYBREAK_PROVIDERS)
    def test_the_two_colours_are_different_models(self, provider_id: str) -> None:
        red = load_tier_specs("openai_daybreak_red")["heavy"].model_id
        blue = load_tier_specs("openai_daybreak_blue")["heavy"].model_id
        assert red != blue
        assert load_tier_specs("openai")["heavy"].model_id not in (red, blue)

    def test_both_colours_read_one_key_that_is_not_the_standard_one(self) -> None:
        for provider_id in DAYBREAK_PROVIDERS:
            assert factory.key_env_vars(provider_id) == ("OPENAI_DAYBREAK_API_KEY",)
        assert factory.key_env_vars("openai") == ("OPENAI_API_KEY",)

    @pytest.mark.parametrize("provider_id", DAYBREAK_PROVIDERS)
    def test_the_manifest_advertises_no_document_capability(
        self, provider_id: str,
    ) -> None:
        # An unverified capability token is a promise the router acts on.
        for spec in load_tier_specs(provider_id).values():
            assert "native_pdf" not in spec.capabilities


# ---------------------------------------------------------------------------
# Vendor is a separate question from provider
# ---------------------------------------------------------------------------


class TestVendorIsNotProviderId:
    @pytest.mark.parametrize(
        "provider_id,vendor", sorted(EXPECTED_VENDORS.items()),
    )
    def test_every_provider_declares_its_vendor(
        self, provider_id: str, vendor: str,
    ) -> None:
        assert vendor_of(provider_id) == vendor

    def test_three_provider_ids_resolve_to_one_vendor(self) -> None:
        # The whole reason the field exists.
        assert {vendor_of(p) for p in OPENAI_BACKED} == {"openai"}

    def test_a_colour_is_not_its_own_vendor(self) -> None:
        for provider_id in DAYBREAK_PROVIDERS:
            assert vendor_of(provider_id) != provider_id

    def test_an_unreadable_manifest_falls_back_to_the_provider_id(self) -> None:
        # A provider whose manifest cannot be read must not silently join
        # another vendor's bloc, so it is its own vendor until told otherwise.
        assert vendor_of("no_such_provider") == "no_such_provider"


# ---------------------------------------------------------------------------
# Client identity
# ---------------------------------------------------------------------------


class TestIdentityIsPerInstance:
    """The failure this guards: one class, one class-level provider_id.

    All three OpenAI-backed providers are served by OpenAIClient. While
    identity lived on the class, every one of them reported "openai" — so
    responses were misattributed, and every manifest lookup the client made
    read openai.json no matter which model it was really talking to.
    """

    def test_a_client_answers_as_the_provider_it_was_built_for(self) -> None:
        from framework.llm.clients.openai import OpenAIClient

        red = OpenAIClient(
            model_id="gpt-daybreak-red-latest", tier="heavy",
            api_key_env_var="OPENAI_DAYBREAK_API_KEY",
            provider_id="openai_daybreak_red",
        )
        assert red.provider_id == "openai_daybreak_red"
        assert OpenAIClient(model_id="gpt-5.6-sol", tier="heavy").provider_id == (
            "openai"
        )

    def test_a_substitute_keeps_the_identity(self) -> None:
        # with_model is the retired-model retry path. A substitute that shed
        # its identity would put a provider in the record that never served
        # the call.
        from framework.llm.clients.openai import OpenAIClient

        red = OpenAIClient(
            model_id="gpt-daybreak-red-latest", tier="heavy",
            provider_id="openai_daybreak_red",
        )
        assert red.with_model("gpt-daybreak-red-2026-09").provider_id == (
            "openai_daybreak_red"
        )

    def test_capability_lookup_reads_the_instance_manifest(self) -> None:
        from framework.llm.clients.openai import OpenAIClient

        red = OpenAIClient(
            model_id="gpt-daybreak-red-latest", tier="heavy",
            provider_id="openai_daybreak_red",
        )
        std = OpenAIClient(model_id="gpt-5.6-sol", tier="heavy")
        # Declared by openai.json's heavy tier, withheld by Daybreak's until
        # it is probed. Reading the wrong manifest would hide the difference.
        assert std.supports("function_calling") is True
        assert red.supports("function_calling") is False

    def test_the_sdk_install_hint_names_an_extra_that_exists(self) -> None:
        # Derived from the provider id, this produced
        # eventmill[llm-openai_daybreak_red] and eventmill[llm-gcp_gemini],
        # neither of which is a real extra.
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        for provider_id in OPENAI_BACKED:
            assert factory.sdk_install_target(provider_id) == "eventmill[llm-openai]"
        assert "llm-gcp_gemini" not in factory.sdk_install_target("gcp_gemini")
        for provider_id in factory.known_providers():
            target = factory.sdk_install_target(provider_id)
            if "[" in target:
                extra = target.split("[", 1)[1].rstrip("]")
                assert f"{extra} = [" in pyproject, (
                    f"{provider_id} points at an extra pyproject does not define"
                )


# ---------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------


class TestConcurrentBinding:
    def test_three_openai_backed_providers_bind_without_overwriting(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("K_SERVICE", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-standard")
        monkeypatch.setenv("OPENAI_DAYBREAK_API_KEY", "sk-daybreak")
        monkeypatch.setenv("EVENTMILL_LLM_PROVIDERS", " ".join(OPENAI_BACKED))
        shell = EventMillShell(workspace_path=tmp_path)
        shell.do_connect("")

        bound = shell.llm_client._clients
        assert set(bound) == {
            (provider_id, tier)
            for provider_id in OPENAI_BACKED for tier in ("light", "heavy")
        }
        # Six registrations, six distinct clients: none evicted another.
        assert len({id(c) for c in bound.values()}) == 6
        for (provider_id, _), client in bound.items():
            assert client.provider_id == provider_id, (
                f"{provider_id} bound a {client.provider_id} client"
            )
        assert {c.model_id for c in bound.values()} == {
            "gpt-5.6-terra", "gpt-5.6-sol",
            "gpt-daybreak-red-latest", "gpt-daybreak-blue-latest",
        }

    def test_the_standard_key_never_reaches_a_daybreak_provider(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Separate entitlements. A fallback from one key to the other would
        # look like it worked while billing and logging somewhere else.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-standard")
        for provider_id in DAYBREAK_PROVIDERS:
            clients, failures = factory.build_clients(provider_id, connect=False)
            assert clients == {}
            assert failures
            assert all("OPENAI_DAYBREAK_API_KEY" in f for f in failures)

    def test_a_missing_daybreak_key_leaves_every_other_provider_available(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The placeholder-seeded steady state: adopting a vendor must never be
        # a precondition for the vendors already in use.
        monkeypatch.setenv("GEMINI_FLASH_API_KEY", "k-flash")
        monkeypatch.setenv("GEMINI_PRO_API_KEY", "k-pro")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-standard")
        monkeypatch.setenv("OPENAI_DAYBREAK_API_KEY", factory.PLACEHOLDER)
        available = set(factory.available_providers())
        assert available == {"gcp_gemini", "anthropic", "openai"}
        assert not available & set(DAYBREAK_PROVIDERS)


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


class _FakeDaybreakClient:
    """Minimal client that answers as a Daybreak provider."""

    provider_id = "openai_daybreak_red"
    model_id = "gpt-daybreak-red-latest"
    connected = True
    total_tokens_used = 0

    def supports(self, capability: str) -> bool:
        return True

    def query_text(self, **kwargs: object) -> LLMResponse:
        return LLMResponse(ok=True, text="{}", model_used=self.model_id)


class TestResponseAttribution:
    def test_the_dispatcher_stamps_the_vendor(self) -> None:
        """Vendor is derived once, centrally, from the provider manifest.

        Asking every client to remember which lab it speaks for is how
        attribution drifts — which is the mistake the class-level provider_id
        had already made.
        """
        dispatcher = LLMDispatcher(
            {("openai_daybreak_red", "heavy"): _FakeDaybreakClient()}
        )
        result = dispatcher.query_text(prompt="x", provider="openai_daybreak_red")

        assert result.ok
        assert result.provider_id == "openai_daybreak_red"
        assert result.vendor == "openai"

    def test_provider_and_vendor_answer_different_questions(self) -> None:
        # A reader counting how far a route's support extends needs the
        # vendor; a reader comparing two models needs the provider. Collapsing
        # them is what would let one lab's two models read as two independent
        # opinions.
        dispatcher = LLMDispatcher(
            {("openai_daybreak_red", "heavy"): _FakeDaybreakClient()}
        )
        result = dispatcher.query_text(prompt="x", provider="openai_daybreak_red")
        assert result.provider_id != result.vendor
