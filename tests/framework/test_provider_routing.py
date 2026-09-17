"""
Tests for routing with more than one provider bound at once.

Stage 2 of docs/specs/multi_provider_llm_clients.md: LLMDispatcher._clients is
keyed by (provider_id, tier) rather than tier alone. Keyed by tier it could not
express the state at all — registering a second vendor's client under "heavy"
evicted the first vendor's heavy model and silently rerouted every heavy plugin.

The class that matters most here is TestQuotaFailureNeverCrossesVendors. Several
providers bound at once is the requirement; automatic failover *between* them is
the hazard, and the difference is who chose and whether the output says so.
"""

import pytest

from framework.llm.dispatcher import LLMDispatcher, TierScopedLLMClient
from framework.llm.providers import TierSpec
from framework.plugins.protocol import QueryHints

from tests.framework.test_provider_seam import PublicOnlyClient


def _spec(tier: str, model_id: str, provider_id: str,
          max_output: int = 65536) -> TierSpec:
    return TierSpec(
        tier=tier, model_id=model_id, api_key_env="KEY",
        max_output_tokens=max_output, max_context_tokens=1_000_000,
        cost_tier="low", capabilities=("text", "native_pdf"),
        provider_id=provider_id,
    )


@pytest.fixture
def two_providers() -> tuple[LLMDispatcher, dict[str, PublicOnlyClient]]:
    """Two vendors, both tiers each — the state a tier-keyed map cannot hold."""
    clients = {
        ("alpha", "light"): PublicOnlyClient("alpha-light", "light", "alpha"),
        ("alpha", "heavy"): PublicOnlyClient("alpha-heavy", "heavy", "alpha"),
        ("beta", "light"): PublicOnlyClient("beta-light", "light", "beta"),
        ("beta", "heavy"): PublicOnlyClient("beta-heavy", "heavy", "beta"),
    }
    specs = {
        ("alpha", "light"): _spec("light", "alpha-light", "alpha"),
        ("alpha", "heavy"): _spec("heavy", "alpha-heavy", "alpha"),
        ("beta", "light"): _spec("light", "beta-light", "beta", 128_000),
        ("beta", "heavy"): _spec("heavy", "beta-heavy", "beta", 128_000),
    }
    dispatcher = LLMDispatcher(clients=clients, tier_specs=specs)
    by_name = {c.model_id: c for c in clients.values()}
    return dispatcher, by_name


class TestFourClientsCoexist:
    """The state the rekey exists to express."""

    def test_all_four_are_registered_and_reported(self, two_providers) -> None:
        dispatcher, _ = two_providers
        assert dispatcher.bound_providers() == ("alpha", "beta")
        reported = dispatcher.connected_models()
        assert len(reported) == 4
        assert {(r["provider_id"], r["tier"]) for r in reported} == {
            ("alpha", "light"), ("alpha", "heavy"),
            ("beta", "light"), ("beta", "heavy"),
        }

    def test_the_same_tier_on_two_vendors_does_not_collide(
        self, two_providers,
    ) -> None:
        # The whole point: under the old key, the second "heavy" registered
        # would have evicted the first.
        dispatcher, _ = two_providers
        assert dispatcher.client_at("heavy", "alpha").model_id == "alpha-heavy"
        assert dispatcher.client_at("heavy", "beta").model_id == "beta-heavy"

    def test_every_response_names_the_provider_that_served_it(
        self, two_providers,
    ) -> None:
        # With vendors running concurrently this stops being a convenience:
        # two records from one session may come from two vendors.
        dispatcher, _ = two_providers
        for provider_id in ("alpha", "beta"):
            result = dispatcher.query_text("hello", provider=provider_id)
            assert result.ok
            assert result.provider_id == provider_id


class TestProviderIsResolvedBeforeTier:
    def test_the_first_bound_provider_serves_callers_naming_none(
        self, two_providers,
    ) -> None:
        dispatcher, _ = two_providers
        assert dispatcher.default_provider == "alpha"
        assert dispatcher.query_text("hi").provider_id == "alpha"

    def test_an_explicit_preference_wins_when_it_is_bound(self) -> None:
        clients = {
            ("alpha", "light"): PublicOnlyClient("alpha-light", "light", "alpha"),
            ("beta", "light"): PublicOnlyClient("beta-light", "light", "beta"),
        }
        dispatcher = LLMDispatcher(clients=clients, preferred_provider="beta")
        assert dispatcher.default_provider == "beta"
        assert dispatcher.query_text("hi").provider_id == "beta"

    def test_an_unbound_preference_falls_back_to_what_is_bound(self) -> None:
        # Naming a provider that never bound must not leave the session dead;
        # it is a misconfiguration, not a reason to refuse every query.
        clients = {
            ("alpha", "light"): PublicOnlyClient("alpha-light", "light", "alpha"),
        }
        dispatcher = LLMDispatcher(clients=clients, preferred_provider="beta")
        assert dispatcher.default_provider == "alpha"

    def test_tier_is_selected_within_the_named_provider(
        self, two_providers,
    ) -> None:
        dispatcher, _ = two_providers
        result = dispatcher.query_text(
            "hi", hints=QueryHints(tier="heavy"), provider="beta",
        )
        assert result.model_used == "beta-heavy"

    def test_an_unbound_provider_is_refused_by_name(self, two_providers) -> None:
        # Refused rather than silently served by whoever is bound: an operator
        # comparing vendors must never be answered by the wrong one.
        dispatcher, _ = two_providers
        result = dispatcher.query_text("hi", provider="gamma")
        assert not result.ok
        assert "gamma" in result.error
        assert "alpha" in result.error and "beta" in result.error

    def test_clamping_reads_the_serving_provider_s_cap(
        self, two_providers,
    ) -> None:
        # alpha caps at 65_536 and beta at 128_000, as Gemini and the other two
        # actually differ. Reading one vendor's cap for another's model is how
        # a call gets rejected at the provider.
        dispatcher, by_name = two_providers
        dispatcher.query_text("hi", max_tokens=100_000, provider="alpha")
        dispatcher.query_text("hi", max_tokens=100_000, provider="beta")
        assert by_name["alpha-light"].calls[0]["max_tokens"] == 65_536
        assert by_name["beta-light"].calls[0]["max_tokens"] == 100_000


class TestQuotaFailureNeverCrossesVendors:
    """The one data-handling boundary in the design.

    Deliberate provider selection is the requirement; silent failover is the
    hazard. A quota failure moving a session to another vendor would send
    investigation data to a provider nobody chose and leave the result
    unattributable afterwards.
    """

    @pytest.fixture
    def exhausted_alpha(self) -> tuple[LLMDispatcher, dict]:
        clients = {
            ("alpha", "light"): PublicOnlyClient(
                "alpha-light", "light", "alpha", fail_with="RESOURCE_EXHAUSTED",
            ),
            ("alpha", "heavy"): PublicOnlyClient("alpha-heavy", "heavy", "alpha"),
            ("beta", "light"): PublicOnlyClient("beta-light", "light", "beta"),
            ("beta", "heavy"): PublicOnlyClient("beta-heavy", "heavy", "beta"),
        }
        return LLMDispatcher(clients=clients), {c.model_id: c for c in
                                                clients.values()}

    def test_quota_falls_back_to_the_other_tier_of_the_same_provider(
        self, exhausted_alpha,
    ) -> None:
        dispatcher, by_name = exhausted_alpha
        result = dispatcher.query_text("hi", provider="alpha")
        assert result.ok
        assert result.model_used == "alpha-heavy"
        assert result.provider_id == "alpha"

    def test_no_other_vendor_is_ever_called(self, exhausted_alpha) -> None:
        dispatcher, by_name = exhausted_alpha
        dispatcher.query_text("hi", provider="alpha")
        assert by_name["beta-light"].calls == []
        assert by_name["beta-heavy"].calls == []

    def test_a_provider_with_no_healthy_tier_fails_rather_than_hopping(
        self,
    ) -> None:
        # Both of alpha's tiers are exhausted and beta is bound and healthy.
        # The call must still fail: answering from beta is exactly the silent
        # failover this forbids.
        clients = {
            ("alpha", "light"): PublicOnlyClient(
                "alpha-light", "light", "alpha", fail_with="RESOURCE_EXHAUSTED",
            ),
            ("alpha", "heavy"): PublicOnlyClient(
                "alpha-heavy", "heavy", "alpha", fail_with="RESOURCE_EXHAUSTED",
            ),
            ("beta", "light"): PublicOnlyClient("beta-light", "light", "beta"),
        }
        dispatcher = LLMDispatcher(clients=clients)
        by_name = {c.model_id: c for c in clients.values()}

        result = dispatcher.query_text("hi", provider="alpha")

        assert not result.ok
        assert by_name["beta-light"].calls == []

    def test_the_retired_model_substitute_stays_on_its_own_provider(
        self,
    ) -> None:
        clients = {
            ("alpha", "heavy"): PublicOnlyClient(
                "alpha-heavy", "heavy", "alpha", fail_with="NOT_FOUND",
            ),
            ("beta", "heavy"): PublicOnlyClient("beta-heavy", "heavy", "beta"),
        }
        specs = {
            ("alpha", "heavy"): TierSpec(
                tier="heavy", model_id="alpha-heavy", api_key_env="KEY",
                max_output_tokens=65536, max_context_tokens=1_000_000,
                cost_tier="high", capabilities=("text",),
                fallback_model_id="alpha-heavy-ga", provider_id="alpha",
            ),
            ("beta", "heavy"): _spec("heavy", "beta-heavy", "beta"),
        }
        dispatcher = LLMDispatcher(clients=clients, tier_specs=specs)

        dispatcher.query_text("hi", hints=QueryHints(tier="heavy"),
                              provider="alpha")

        # Substituted in place, under its own key — beta's heavy slot is
        # untouched, where a tier-keyed map would have overwritten it.
        assert dispatcher.client_at("heavy", "alpha").model_id == "alpha-heavy-ga"
        assert dispatcher.client_at("heavy", "beta").model_id == "beta-heavy"


class TestProviderScopeRidesTheWrapperNotTheHints:
    """Provider choice is an operator decision, so it never reaches QueryHints.

    A provider field on QueryHints would put vendor selection in plugin code
    and let a plugin override an operator's A/B choice — which would make the
    comparison silently unattributable.
    """

    def test_the_scoped_client_sends_its_provider(self, two_providers) -> None:
        dispatcher, _ = two_providers
        scoped = TierScopedLLMClient(
            dispatcher, default_tier="heavy", default_provider="beta",
        )
        result = scoped.query_text("hi")
        assert result.provider_id == "beta"
        assert result.model_used == "beta-heavy"

    def test_no_provider_scope_means_the_session_default(
        self, two_providers,
    ) -> None:
        dispatcher, _ = two_providers
        scoped = TierScopedLLMClient(dispatcher, default_tier="light")
        assert scoped.query_text("hi").provider_id == "alpha"

    def test_query_hints_carries_no_provider_field(self) -> None:
        assert not hasattr(QueryHints(), "provider")

    def test_a_plugin_cannot_reach_the_provider_argument(
        self, two_providers,
    ) -> None:
        # A plugin holds the scoped wrapper, whose signature has no provider.
        # This is what keeps "the analysis tools do not change" true.
        import inspect

        dispatcher, _ = two_providers
        scoped = TierScopedLLMClient(dispatcher, default_provider="beta")
        assert "provider" not in inspect.signature(scoped.query_text).parameters

    def test_wrapping_a_bare_client_ignores_the_scope(self) -> None:
        # TierScopedLLMClient also wraps clients that take no provider kwarg;
        # passing one would be a TypeError at the first plugin call.
        bare = PublicOnlyClient("solo", "light", "alpha")
        scoped = TierScopedLLMClient(
            bare, default_tier="light", default_provider="beta",
        )
        assert scoped.query_text("hi").ok


class TestSingleProviderBehaviourIsUnchanged:
    """The rekey must be invisible to a one-vendor session.

    Every existing caller passes a tier-keyed dict, and the suite's fixtures
    still do. If that stopped working the change would have rippled through
    the shell and every test rather than staying inside the dispatcher.
    """

    def test_a_tier_keyed_dict_is_still_accepted(self) -> None:
        clients = {
            "light": PublicOnlyClient("solo-light", "light", "solo"),
            "heavy": PublicOnlyClient("solo-heavy", "heavy", "solo"),
        }
        dispatcher = LLMDispatcher(clients=clients)
        assert dispatcher.bound_providers() == ("solo",)
        assert dispatcher.client_at("heavy").model_id == "solo-heavy"
        assert dispatcher.query_text("hi").provider_id == "solo"

    def test_tier_keyed_specs_attach_to_the_bound_provider(self) -> None:
        # The specs' own provider_id defaults to gcp_gemini while the clients
        # declare "solo". Keying the specs off the spec objects would make
        # every lookup miss — silently, since clamping just falls back to
        # defaults and the retired-model retry stops happening.
        clients = {"light": PublicOnlyClient("solo-light", "light", "solo")}
        specs = {"light": TierSpec(
            tier="light", model_id="solo-light", api_key_env="KEY",
            max_output_tokens=4096, max_context_tokens=100,
            cost_tier="low", capabilities=("text",),
        )}
        dispatcher = LLMDispatcher(clients=clients, tier_specs=specs)
        client = dispatcher.client_at("light")
        assert dispatcher._spec_of(client) is specs["light"]
        dispatcher.query_text("hi", max_tokens=99_999)
        assert client.calls[0]["max_tokens"] == 4096
