"""
Tests for three-provider configuration, key discovery and liveness probing.

Stage 2a of docs/specs/multi_provider_llm_clients.md: Anthropic and OpenAI
become configurable and provably reachable, while Gemini stays the only
provider bound for tool execution. The last class here is the guard on that
last clause — with LLMDispatcher._clients still keyed by tier alone, an
Anthropic client registered under "heavy" would evict Gemini Pro and silently
route every heavy plugin to another vendor.

Nothing here makes a network call. probe() is exercised against fakes; the live
runs are recorded in docs/change_log/2026-09-13-three-provider-clients.md.
"""

from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell
from framework.llm import factory
from framework.llm.dispatcher import LLMDispatcher
from framework.llm.model_client import PROBE_PROMPT, LLMProbeResult
from framework.llm.providers import (
    PING_CONTENT_TOKENS,
    accepted_thinking_levels,
    load_provider_manifest,
    load_tier_specs,
    ping_budget,
    thinking_reserve_tokens,
)

ALL_PROVIDERS = ("gcp_gemini", "anthropic", "openai")

# What each provider's manifest is expected to declare. Wired to the models the
# operator chose, so a silent manifest edit fails here rather than at a vendor.
EXPECTED_TIERS = {
    "gcp_gemini": {"light": "gemini-3.8-flash", "heavy": "gemini-3.1-pro-preview"},
    "anthropic": {"light": "claude-sonnet-5", "heavy": "claude-opus-5"},
    "openai": {"light": "gpt-5.6-terra", "heavy": "gpt-5.6-sol"},
}

EXPECTED_KEY_ENV = {
    "gcp_gemini": ("GEMINI_FLASH_API_KEY", "GEMINI_PRO_API_KEY"),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
}


@pytest.fixture(autouse=True)
def clean_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip every LLM env var so a developer's .env cannot change an outcome.

    The shell loads .env at startup, and EVENTMILL_MODEL_HEAVY is pinned there.
    A test that read the ambient environment would pass or fail by machine.
    """
    for name in (
        "EVENTMILL_LLM_PROVIDERS",
        "EVENTMILL_MODEL_LIGHT", "EVENTMILL_MODEL_HEAVY",
        "EVENTMILL_MAX_OUTPUT_LIGHT", "EVENTMILL_MAX_OUTPUT_HEAVY",
        "GEMINI_API_KEY", "GEMINI_FLASH_API_KEY", "GEMINI_PRO_API_KEY",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    for provider in ALL_PROVIDERS:
        token = provider.upper()
        for tier in ("LIGHT", "HEAVY"):
            monkeypatch.delenv(f"EVENTMILL_MODEL_{token}_{tier}", raising=False)
            monkeypatch.delenv(f"EVENTMILL_MAX_OUTPUT_{token}_{tier}", raising=False)
    load_provider_manifest.cache_clear()


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------


class TestEveryProviderDeclaresBothTiers:
    """One heavy and one light model per provider is the settled decision."""

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_both_tiers_resolve_to_the_expected_model(self, provider_id: str) -> None:
        specs = load_tier_specs(provider_id)
        assert set(specs) == {"light", "heavy"}
        for tier, model_id in EXPECTED_TIERS[provider_id].items():
            assert specs[tier].model_id == model_id

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_every_tier_names_a_key_env_var(self, provider_id: str) -> None:
        specs = load_tier_specs(provider_id)
        assert all(s.api_key_env for s in specs.values())
        assert factory.key_env_vars(provider_id) == EXPECTED_KEY_ENV[provider_id]

    def test_only_gemini_splits_keys_by_tier(self) -> None:
        # Gemini uses two so bulk Flash work cannot consume Pro quota; neither
        # other vendor issues per-tier keys, so one key serves both there.
        assert len(factory.key_env_vars("gcp_gemini")) == 2
        assert len(factory.key_env_vars("anthropic")) == 1
        assert len(factory.key_env_vars("openai")) == 1

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_caps_and_context_are_positive(self, provider_id: str) -> None:
        for spec in load_tier_specs(provider_id).values():
            assert spec.max_output_tokens > 0
            assert spec.max_context_tokens > 0

    def test_the_new_providers_declare_the_probed_output_cap(self) -> None:
        # Read out of each vendor's own over-limit 400 rather than assumed, and
        # double Gemini's 65_536 — so clamping cannot be shared between them.
        for provider_id in ("anthropic", "openai"):
            for spec in load_tier_specs(provider_id).values():
                assert spec.max_output_tokens == 128_000

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_provider_id_is_stamped_on_every_spec(self, provider_id: str) -> None:
        # A spec that cannot say which provider it came from makes a
        # cross-provider comparison unattributable.
        for spec in load_tier_specs(provider_id).values():
            assert spec.provider_id == provider_id


# ---------------------------------------------------------------------------
# Env overrides
# ---------------------------------------------------------------------------


class TestModelOverridesAreProviderQualified:
    """A global model pin must not reach across vendors.

    .env pins EVENTMILL_MODEL_HEAVY=gemini-3.1-pro-preview. Before Stage 2a
    that would have retargeted Anthropic's and OpenAI's heavy tiers at a Gemini
    model id the moment their manifests loaded — the same silent-failure class
    as the 09-12 pin that made a model swap inert.
    """

    def test_unqualified_override_reaches_the_default_provider(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVENTMILL_MODEL_HEAVY", "gemini-9-experimental")
        assert load_tier_specs("gcp_gemini")["heavy"].model_id == (
            "gemini-9-experimental"
        )

    @pytest.mark.parametrize("provider_id", ("anthropic", "openai"))
    def test_unqualified_override_does_not_reach_another_provider(
        self, provider_id: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVENTMILL_MODEL_HEAVY", "gemini-3.1-pro-preview")
        monkeypatch.setenv("EVENTMILL_MODEL_LIGHT", "gemini-3.8-flash")
        specs = load_tier_specs(provider_id)
        assert specs["heavy"].model_id == EXPECTED_TIERS[provider_id]["heavy"]
        assert specs["light"].model_id == EXPECTED_TIERS[provider_id]["light"]

    def test_qualified_override_reaches_its_own_provider_only(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVENTMILL_MODEL_ANTHROPIC_HEAVY", "claude-fable-5-1")
        assert load_tier_specs("anthropic")["heavy"].model_id == "claude-fable-5-1"
        assert load_tier_specs("openai")["heavy"].model_id == "gpt-5.6-sol"
        assert load_tier_specs("gcp_gemini")["heavy"].model_id == (
            "gemini-3.1-pro-preview"
        )

    def test_output_cap_override_is_qualified_the_same_way(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Paired with the model override: a substitute rarely shares the
        # manifest model's cap, and clamping against the wrong one fails at
        # the provider.
        monkeypatch.setenv("EVENTMILL_MAX_OUTPUT_HEAVY", "4096")
        assert load_tier_specs("gcp_gemini")["heavy"].max_output_tokens == 4096
        assert load_tier_specs("anthropic")["heavy"].max_output_tokens == 128_000

        monkeypatch.setenv("EVENTMILL_MAX_OUTPUT_OPENAI_LIGHT", "8192")
        assert load_tier_specs("openai")["light"].max_output_tokens == 8192


# ---------------------------------------------------------------------------
# Thinking levels and the ping budget
# ---------------------------------------------------------------------------


class TestThinkingLevelsAreNotPortable:
    """A level that is valid QueryHints vocabulary can still be a 400."""

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_minimal_is_excluded_everywhere(self, provider_id: str) -> None:
        # Measured: gemini-3.8-flash rejects thinking_level "minimal", and both
        # gpt-5.6 tiers reject reasoning_effort "minimal". Anthropic has no such
        # level at all. So nothing may pick it as the shallowest option.
        for tier in ("light", "heavy"):
            assert "minimal" not in accepted_thinking_levels(tier, provider_id)

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_levels_are_ordered_shallowest_first(self, provider_id: str) -> None:
        for tier in ("light", "heavy"):
            levels = accepted_thinking_levels(tier, provider_id)
            assert levels, f"{provider_id}/{tier} declares no thinking levels"
            assert levels[0] == "low"


class TestPingBudgetComesFromTheManifest:
    """A flat small ping budget is flaky, not merely wrong.

    Measured twice at the same 64-token cap, gemini-3.8-flash returned empty
    text on one run (thinking spent the budget) and "OK" on the next. So the
    ping has to be sized from the reserve the provider declares.
    """

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_budget_exceeds_the_declared_reserve(self, provider_id: str) -> None:
        for tier in ("light", "heavy"):
            budget, level = ping_budget(tier, provider_id)
            assert level == "low"
            assert budget == thinking_reserve_tokens(level, provider_id) + (
                PING_CONTENT_TOKENS
            )
            assert budget > PING_CONTENT_TOKENS

    @pytest.mark.parametrize("provider_id", ALL_PROVIDERS)
    def test_budget_never_exceeds_the_tier_cap(self, provider_id: str) -> None:
        for tier, spec in load_tier_specs(provider_id).items():
            budget, _ = ping_budget(tier, provider_id)
            assert budget <= spec.max_output_tokens

    def test_the_probe_prompt_is_shared_by_every_client(self) -> None:
        # Byte-identical across providers, or a latency or token comparison
        # between them is measuring two different questions.
        from framework.llm.clients.anthropic import AnthropicClient
        from framework.llm.clients.gemini import GeminiClient
        from framework.llm.clients.openai import OpenAIClient

        for cls in (GeminiClient, AnthropicClient, OpenAIClient):
            assert hasattr(cls, "probe")
        assert PROBE_PROMPT


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestConfiguredProviders:
    def test_unset_means_gemini_alone(self) -> None:
        # An existing deployment that sets nothing must behave exactly as
        # before Stage 2a.
        assert factory.configured_providers("") == ("gcp_gemini",)

    def test_space_separated_order_is_preserved(self) -> None:
        ids = factory.configured_providers("anthropic gcp_gemini openai")
        assert ids == ("anthropic", "gcp_gemini", "openai")

    def test_duplicates_collapse(self) -> None:
        assert factory.configured_providers("openai openai") == ("openai",)

    def test_an_unknown_id_is_refused_by_name(self) -> None:
        # Refused rather than skipped: a typo would otherwise leave the
        # provider silently absent, which looks like a working session until a
        # tool tries to use it. deploy-cloudrun-secrets.sh refuses identically.
        with pytest.raises(factory.UnknownProviderError) as excinfo:
            factory.configured_providers("gcp_gemini anthropik")
        assert "anthropik" in str(excinfo.value)
        assert "gcp_gemini" in str(excinfo.value)

    def test_the_registry_matches_the_deploy_script(self) -> None:
        # A provider that deploys but cannot bind, or binds but cannot deploy,
        # is the failure this pins.
        script = Path("cloud_install/deploy-cloudrun-secrets.sh")
        if not script.exists():  # pragma: no cover — repo layout guard
            pytest.skip("deploy script not present")
        text = script.read_text(encoding="utf-8")
        for provider_id in factory.known_providers():
            assert provider_id in text, f"{provider_id} unknown to the deploy path"


class TestKeyAvailability:
    def test_a_placeholder_key_counts_as_missing(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # provision-gcp-project.sh seeds unadopted providers with the literal
        # "placeholder" so every deployment mounts the same secret set. It is
        # not a key, and treating it as one would bind a provider that 401s.
        monkeypatch.setenv("ANTHROPIC_API_KEY", factory.PLACEHOLDER)
        assert factory.missing_keys("anthropic") == ("ANTHROPIC_API_KEY",)
        assert factory.available_providers("anthropic") == ()

    def test_whitespace_only_key_counts_as_missing(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "   ")
        assert factory.missing_keys("openai") == ("OPENAI_API_KEY",)

    def test_a_real_key_makes_a_configured_provider_available(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        assert factory.available_providers("anthropic openai") == (
            "anthropic", "openai",
        )

    def test_a_keyless_configured_provider_warns_rather_than_raising(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    ) -> None:
        # A placeholder-seeded deployment is the expected steady state.
        # Refusing to start over one would make adopting a vendor a deployment
        # event instead of a secret version plus a restart.
        monkeypatch.setenv("GEMINI_FLASH_API_KEY", "k")
        monkeypatch.setenv("GEMINI_PRO_API_KEY", "k")
        with caplog.at_level("WARNING"):
            available = factory.available_providers("gcp_gemini anthropic")
        assert available == ("gcp_gemini",)
        assert "ANTHROPIC_API_KEY" in caplog.text

    def test_status_reports_unconfigured_providers_too(self) -> None:
        # An operator asking why a vendor is absent needs it listed as
        # unconfigured, not missing from the table.
        rows = factory.provider_status("gcp_gemini")
        assert {r["provider_id"] for r in rows} == set(factory.known_providers())
        by_id = {r["provider_id"]: r for r in rows}
        assert by_id["gcp_gemini"]["configured"] is True
        assert by_id["gcp_gemini"]["is_default"] is True
        assert by_id["anthropic"]["configured"] is False

    def test_status_survives_an_unknown_id(self) -> None:
        rows = factory.provider_status("nonsense")
        assert any(r["config_error"] for r in rows)
        assert all(not r["configured"] or r["provider_id"] == "gcp_gemini"
                   for r in rows)


class TestClientConstruction:
    @pytest.mark.parametrize(
        "provider_id,class_name",
        [("gcp_gemini", "GeminiClient"),
         ("anthropic", "AnthropicClient"),
         ("openai", "OpenAIClient")],
    )
    def test_each_provider_resolves_to_its_own_client(
        self, provider_id: str, class_name: str,
    ) -> None:
        cls = factory.client_class(provider_id)
        assert cls.__name__ == class_name
        assert cls.provider_id == provider_id

    def test_an_unknown_provider_cannot_be_built(self) -> None:
        with pytest.raises(factory.UnknownProviderError):
            factory.client_class("bedrock")

    def test_a_tier_without_a_key_is_skipped_with_a_message(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # One tier reachable is a usable session — it is how a Gemini setup
        # with only a Flash key already behaves.
        monkeypatch.setenv("GEMINI_FLASH_API_KEY", "k")
        clients, failures = factory.build_clients("gcp_gemini", connect=False)
        assert set(clients) == {"light"}
        assert any("GEMINI_PRO_API_KEY" in f for f in failures)

    def test_building_without_connecting_touches_no_session(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        clients, failures = factory.build_clients("anthropic", connect=False)
        assert set(clients) == {"light", "heavy"}
        assert failures == []
        assert all(not c.connected for c in clients.values())
        assert clients["heavy"].model_id == "claude-opus-5"
        assert clients["light"].model_id == "claude-sonnet-5"

    def test_no_keys_at_all_yields_no_clients_and_no_exception(self) -> None:
        clients, failures = factory.build_clients("openai", connect=False)
        assert clients == {}
        assert len(failures) == 2


# ---------------------------------------------------------------------------
# probe()
# ---------------------------------------------------------------------------


class TestProbeResultReporting:
    """Budget starvation is its own diagnostic, not a failure."""

    def _result(self, **kw: object) -> LLMProbeResult:
        base = dict(
            provider_id="openai", model_id="gpt-5.6-sol", tier="heavy",
            auth_ok=True, ping_ok=True,
        )
        base.update(kw)
        return LLMProbeResult(**base)  # type: ignore[arg-type]

    def test_ok_requires_both_phases(self) -> None:
        assert self._result().ok
        assert not self._result(auth_ok=False, ping_ok=False).ok
        assert not self._result(ping_ok=False).ok

    def test_a_truncated_ping_still_counts_as_reachable(self) -> None:
        # The key, the model and the query path all work; only the budget was
        # too small. Reporting this as a connectivity failure would make the
        # probe cry wolf on a working key.
        result = self._result(ping_truncated=True, latency_ms=900)
        assert result.ok
        assert "truncated" in result.summary()

    def test_an_auth_failure_says_so_rather_than_blaming_the_ping(self) -> None:
        result = self._result(
            auth_ok=False, ping_ok=False, error="AuthenticationError: 401",
        )
        assert result.summary().startswith("auth failed")

    def test_a_ping_failure_is_distinguished_from_an_auth_failure(self) -> None:
        # A key can list models and still not be entitled to one of them.
        result = self._result(ping_ok=False, error="PermissionDenied on this model")
        assert result.summary().startswith("ping failed")

    def test_an_unconnected_client_probes_without_raising(self) -> None:
        from framework.llm.clients.anthropic import AnthropicClient

        result = AnthropicClient(model_id="claude-opus-5", tier="heavy").probe()
        assert not result.ok
        assert not result.auth_ok
        assert result.error_kind == "access"
        assert "connect" in result.error


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


class TestOnlyGeminiIsBoundForToolExecution:
    """Stage 2a makes three providers reachable; it binds exactly one.

    LLMDispatcher._clients is still keyed by tier alone. An AnthropicClient
    registered under "heavy" would evict Gemini Pro and route every heavy
    plugin to another vendor without anyone choosing it. Until the
    (provider_id, tier) rekey lands, that must be impossible by construction.
    """

    @pytest.fixture
    def shell(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("K_SERVICE", raising=False)
        monkeypatch.setenv("GEMINI_FLASH_API_KEY", "k-flash")
        monkeypatch.setenv("GEMINI_PRO_API_KEY", "k-pro")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv(
            "EVENTMILL_LLM_PROVIDERS", "gcp_gemini anthropic openai",
        )
        return EventMillShell(workspace_path=tmp_path)

    def test_discovery_offers_gemini_tiers_only(self, shell: EventMillShell) -> None:
        # Three providers configured and keyed, yet only Gemini's tiers are
        # offered for binding. do_connect hands these ids to GeminiClient, so
        # an Anthropic row here would bind a client that fails on first use.
        assert shell._available_models
        assert {m["provider"] for m in shell._available_models} == {"gcp_gemini"}
        assert {m["tier"] for m in shell._available_models} == {"light", "heavy"}

    def test_connect_binds_only_gemini_clients(
        self, shell: EventMillShell,
    ) -> None:
        # connect() builds an SDK handle without a network call, so this runs
        # offline against dummy keys.
        shell.do_connect("")
        assert isinstance(shell.llm_client, LLMDispatcher)
        bound = shell.llm_client._clients
        # Keyed by (provider_id, tier) since the rekey — which is exactly what
        # makes this assertion possible to state rather than merely hope for.
        assert set(bound) == {("gcp_gemini", "light"), ("gcp_gemini", "heavy")}
        for (provider_id, tier), client in bound.items():
            assert client.provider_id == "gcp_gemini" == provider_id, (
                f"{tier} bound to {client.provider_id} — plugin routing hijacked"
            )
        assert shell.llm_client.bound_providers() == ("gcp_gemini",)

    def test_probing_another_provider_does_not_bind_it(
        self, shell: EventMillShell, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The read-only surface must stay read-only: an operator checking a key
        # must not thereby change what serves the next tool run.
        shell.do_connect("")
        before = dict(shell.llm_client._clients)

        monkeypatch.setattr(
            factory, "build_clients", lambda pid, connect=True: ({}, ["stubbed"]),
        )
        shell.do_providers("probe anthropic")

        assert shell.llm_client._clients == before

    def test_the_image_installs_every_provider_sdk(self) -> None:
        """The container must carry an SDK for every provider it can configure.

        Observed on Cloud Run 2026-09-14: 'providers probe anthropic' reported
        "anthropic package not installed". The keys had arrived — the failure
        came from build_clients' connect step, which runs only after the key
        check passes — but Dockerfile.cloudrun installed four extras and
        neither LLM one. google-genai is a base dependency, so Gemini worked
        and hid the gap.

        Correct in source, absent in the environment: the same failure class as
        the .env model pin. This is the cheap guard against a third instance.
        """
        import tomllib

        pyproject = tomllib.loads(
            Path("pyproject.toml").read_text(encoding="utf-8")
        )
        extras = set(pyproject["project"]["optional-dependencies"])
        llm_extras = {e for e in extras if e.startswith("llm-")}
        assert llm_extras, "no llm-* extras declared"

        dockerfile = Path("cloud_install/Dockerfile.cloudrun")
        if not dockerfile.exists():  # pragma: no cover — repo layout guard
            pytest.skip("cloud run Dockerfile not present")
        text = dockerfile.read_text(encoding="utf-8")
        for extra in sorted(llm_extras):
            assert extra in text, (
                f"{extra} is declared but the Cloud Run image never installs "
                f"it — that provider will report 'package not installed'"
            )

    def test_every_llm_sdk_declares_an_upper_bound(self) -> None:
        """No vendor SDK may float to an untested major version.

        Observed 2026-09-14: `google-genai>=1.69.0` with no ceiling meant the
        Cloud Run image installed 2.x while every test and every live
        verification ran against 1.69. The image built clean and the skew was
        invisible until an SDK-shaped symptom appeared. The two extras added
        the day before carried the same latent bug — unbounded, they resolve
        to anthropic 1.x and openai 3.x.

        The SDK is the one dependency whose behaviour IS the product here, so
        an unbounded range is a silent-failure generator rather than a
        convenience.
        """
        import tomllib

        from packaging.requirements import Requirement

        pyproject = tomllib.loads(
            Path("pyproject.toml").read_text(encoding="utf-8")
        )
        declared = list(pyproject["project"]["dependencies"])
        for extra, items in pyproject["project"]["optional-dependencies"].items():
            if extra.startswith("llm-"):
                declared += items

        sdk_names = {"google-genai", "anthropic", "openai"}
        seen = set()
        for raw in declared:
            req = Requirement(raw)
            if req.name not in sdk_names:
                continue
            seen.add(req.name)
            operators = {s.operator for s in req.specifier}
            assert operators & {"<", "<=", "==", "~="}, (
                f"{req.name} has no upper bound ({req.specifier}) — a build "
                f"will silently install an untested major version"
            )

        assert "google-genai" in seen, "the Gemini SDK is no longer declared"

    def test_the_ci_path_mounts_every_provider_secret(self) -> None:
        """cloudbuild.yaml must mount what deploy-cloudrun-secrets.sh mounts.

        The two deploy paths duplicate the secret list, so they drift silently:
        a key present via one path and absent via the other looks like a
        working deployment until a provider is probed.
        """
        cloudbuild = Path("cloud_install/cloudbuild.yaml")
        if not cloudbuild.exists():  # pragma: no cover — repo layout guard
            pytest.skip("cloudbuild.yaml not present")
        text = cloudbuild.read_text(encoding="utf-8")
        for provider_id in factory.known_providers():
            for env_var in factory.key_env_vars(provider_id):
                assert env_var in text, (
                    f"{env_var} is never mounted by the CI deploy path"
                )
        assert factory.PROVIDERS_ENV in text

    def test_the_providers_table_names_every_known_provider(
        self, shell: EventMillShell, capsys: pytest.CaptureFixture,
    ) -> None:
        shell.do_providers("")
        out = capsys.readouterr().out
        for provider_id in factory.known_providers():
            assert provider_id in out
        # And it says which models each would use, so a wrong tier is visible
        # before anything is bound.
        assert "claude-opus-5" in out
        assert "gpt-5.6-sol" in out
