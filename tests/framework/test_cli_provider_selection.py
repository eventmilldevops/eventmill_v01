"""
Tests for 'use <provider> [for <tool>]' — the runtime A/B control.

Stage B of docs/specs/projector_three_vendor_run.md, the CLI half of Stage 5 in
docs/specs/multi_provider_llm_clients.md. Binding three vendors at once was
Stage A; this is what points a module at one of them.

The property under test throughout is that the selection reaches
TierScopedLLMClient and nothing else. Provider choice is an operator decision:
a plugin must not be able to see it, and the dispatcher's own default must keep
serving anything the operator has not spoken about.

Nothing here makes a network call — connect() builds an SDK handle without one.
Building a shell costs several seconds (plugin discovery plus the ATT&CK
tables), so the common three-provider session is built once for the module and
its selection state is reset per test.
"""

import pytest

from framework.cli import shell as shell_module
from framework.cli.shell import EventMillShell
from framework.llm.providers import load_provider_manifest

ALL_THREE = "gcp_gemini anthropic openai"

# Heavy tier, and its profile_actor action is deterministic and offline — so a
# real run builds a real wrapper without spending a token.
TOOL = "adversary_path_projector"
OFFLINE_RUN = f"{TOOL} --action profile_actor --threat_actor APT29"

# Anything here would otherwise be read from the developer's .env, where
# EVENTMILL_MODEL_HEAVY is pinned — a test that saw it would pass by machine.
_AMBIENT = (
    "EVENTMILL_LLM_PROVIDERS",
    "EVENTMILL_MODEL_LIGHT", "EVENTMILL_MODEL_HEAVY",
    "EVENTMILL_MAX_OUTPUT_LIGHT", "EVENTMILL_MAX_OUTPUT_HEAVY",
    "GEMINI_API_KEY", "K_SERVICE",
)
_KEYS = {
    "GEMINI_FLASH_API_KEY": "k-flash",
    "GEMINI_PRO_API_KEY": "k-pro",
    "ANTHROPIC_API_KEY": "sk-ant-test",
    "OPENAI_API_KEY": "sk-test",
}


def _running_line(capsys: pytest.CaptureFixture) -> str:
    """The 'Running <tool> ...' line alone.

    Asserting against the whole transcript would match the tool's own prose —
    a projection report says "on" a great deal.
    """
    for line in capsys.readouterr().out.splitlines():
        if line.strip().startswith("Running "):
            return line
    return ""


def _apply_env(mp: pytest.MonkeyPatch, providers: str) -> None:
    for name in _AMBIENT:
        mp.delenv(name, raising=False)
    for env_var, value in _KEYS.items():
        mp.setenv(env_var, value)
    mp.setenv("EVENTMILL_LLM_PROVIDERS", providers)
    load_provider_manifest.cache_clear()


@pytest.fixture(scope="module")
def _shared_shell(tmp_path_factory):
    """One connected three-provider session, shared by the module."""
    mp = pytest.MonkeyPatch()
    _apply_env(mp, ALL_THREE)
    shell = EventMillShell(workspace_path=tmp_path_factory.mktemp("workspace"))
    shell.do_new("provider selection")
    shell.do_connect("")
    yield shell
    mp.undo()
    load_provider_manifest.cache_clear()


@pytest.fixture
def connected(_shared_shell: EventMillShell) -> EventMillShell:
    """The shared shell with any previous test's selection cleared."""
    _shared_shell._provider_default = None
    _shared_shell._provider_by_tool.clear()
    return _shared_shell


@pytest.fixture
def make_shell(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """A session of its own, for tests that need a different provider list."""
    def _make(providers: str = ALL_THREE, connect: bool = True) -> EventMillShell:
        _apply_env(monkeypatch, providers)
        shell = EventMillShell(workspace_path=tmp_path)
        shell.do_new("provider selection")
        if connect:
            shell.do_connect("")
        return shell
    return _make


@pytest.fixture
def spy_wrapper(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Record what TierScopedLLMClient is constructed with on each run."""
    calls: list[dict] = []
    real = shell_module.TierScopedLLMClient

    def _spy(inner, **kwargs):
        calls.append(dict(kwargs))
        return real(inner, **kwargs)

    monkeypatch.setattr(shell_module, "TierScopedLLMClient", _spy)
    return calls


class TestTheSelectionReachesTheWrapper:
    """'use' has to change what serves a run, not only what the shell prints."""

    def test_a_session_default_scopes_every_tool(
        self, connected: EventMillShell, spy_wrapper,
    ) -> None:
        connected.do_use("anthropic")
        connected.do_run(OFFLINE_RUN)

        assert spy_wrapper, "no wrapper was built — the run never reached the LLM path"
        assert spy_wrapper[-1]["default_provider"] == "anthropic"
        # The manifest tier still drives the model; only the vendor moved.
        assert spy_wrapper[-1]["default_tier"] == "heavy"

    def test_a_per_tool_override_scopes_only_that_tool(
        self, connected: EventMillShell, spy_wrapper,
    ) -> None:
        connected.do_use(f"openai for {TOOL}")

        assert connected._provider_for(TOOL) == "openai"
        assert connected._provider_for("threat_model_analyzer") is None

        connected.do_run(OFFLINE_RUN)
        assert spy_wrapper[-1]["default_provider"] == "openai"

    def test_a_per_tool_override_beats_the_session_default(
        self, connected: EventMillShell,
    ) -> None:
        connected.do_use("anthropic")
        connected.do_use(f"openai for {TOOL}")

        assert connected._provider_for(TOOL) == "openai"
        assert connected._provider_for("threat_model_analyzer") == "anthropic"

    def test_selecting_nothing_leaves_the_dispatcher_to_decide(
        self, connected: EventMillShell, spy_wrapper,
    ) -> None:
        # None must keep meaning "whatever the dispatcher chose". Naming the
        # default explicitly here would look harmless and would silently pin a
        # session that had expressed no opinion.
        connected.do_run(OFFLINE_RUN)
        assert spy_wrapper[-1]["default_provider"] is None

    def test_ask_follows_the_session_default(
        self, connected: EventMillShell,
    ) -> None:
        # 'ask:' is the operator reasoning over their own session, so the
        # vendor they chose should answer it.
        connected.do_use("openai")
        assert connected._provider_kwargs(connected._provider_default) == {
            "provider": "openai",
        }

    def test_ask_ignores_a_per_tool_override(
        self, connected: EventMillShell,
    ) -> None:
        connected.do_use(f"openai for {TOOL}")
        assert connected._provider_kwargs(connected._provider_default) == {}


class TestTheSelectionIsRefusedWhenItCannotHold:
    """A selection that cannot be honoured must fail now, not at the first call."""

    def test_an_unbound_provider_is_refused(
        self, make_shell, capsys: pytest.CaptureFixture,
    ) -> None:
        shell = make_shell("gcp_gemini")
        shell.do_use("anthropic")

        out = capsys.readouterr().out
        assert "not bound" in out
        assert "gcp_gemini" in out
        assert shell._provider_default is None

    def test_an_unknown_tool_name_is_refused(
        self, connected: EventMillShell, capsys: pytest.CaptureFixture,
    ) -> None:
        # A typo would otherwise sit in the map and never match a run, which
        # reads as "the override did nothing" long after the mistake.
        connected.do_use("anthropic for adversary_path_projecter")

        assert "Tool not found" in capsys.readouterr().out
        assert connected._provider_by_tool == {}

    def test_selecting_before_connect_says_so(
        self, make_shell, capsys: pytest.CaptureFixture,
    ) -> None:
        shell = make_shell(connect=False)
        shell.do_use("anthropic")

        assert "connect" in capsys.readouterr().out
        assert shell._provider_default is None

    def test_reconnecting_drops_a_selection_that_no_longer_binds(
        self, make_shell, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        shell = make_shell()
        shell.do_use(f"anthropic for {TOOL}")

        monkeypatch.setenv("EVENTMILL_LLM_PROVIDERS", "gcp_gemini")
        shell._provider_specs = shell._load_provider_specs()
        shell._available_models = shell._discover_models()
        shell.do_connect("")

        assert shell._provider_by_tool == {}
        assert "no longer bound" in capsys.readouterr().out


class TestClearingAndReporting:
    def test_use_default_clears_everything(
        self, connected: EventMillShell,
    ) -> None:
        connected.do_use("anthropic")
        connected.do_use(f"openai for {TOOL}")

        connected.do_use("default")
        assert connected._provider_default is None
        assert connected._provider_by_tool == {}

    def test_use_default_for_a_tool_clears_only_that_tool(
        self, connected: EventMillShell,
    ) -> None:
        connected.do_use("anthropic")
        connected.do_use(f"openai for {TOOL}")

        connected.do_use(f"default for {TOOL}")
        assert connected._provider_by_tool == {}
        assert connected._provider_default == "anthropic"

    def test_bare_use_reports_the_selection(
        self, connected: EventMillShell, capsys: pytest.CaptureFixture,
    ) -> None:
        connected.do_use(f"openai for {TOOL}")
        capsys.readouterr()

        connected.do_use("")
        out = capsys.readouterr().out
        assert "gcp_gemini" in out          # the session default, unstated
        assert f"{TOOL}" in out and "openai" in out
        assert "anthropic" in out           # listed as bound

    def test_the_run_line_names_the_vendor_when_there_is_a_choice(
        self, connected: EventMillShell, capsys: pytest.CaptureFixture,
    ) -> None:
        # A three-vendor transcript has to say which vendor produced each line.
        connected.do_use("anthropic")
        capsys.readouterr()

        connected.do_run(OFFLINE_RUN)
        assert "on anthropic" in _running_line(capsys)

    def test_a_single_vendor_session_says_nothing_extra(
        self, make_shell, capsys: pytest.CaptureFixture,
    ) -> None:
        # With one provider bound and nothing selected there is no choice to
        # report, and an unchanged session's output must stay unchanged.
        shell = make_shell("gcp_gemini")
        capsys.readouterr()

        shell.do_run(OFFLINE_RUN)
        assert " on " not in _running_line(capsys)


class TestTheSelectionNeverReachesPluginCode:
    """The operator's choice must not be visible to, or overridable by, a tool."""

    def test_the_context_hands_the_plugin_a_wrapper_with_no_provider_argument(
        self, connected: EventMillShell, spy_wrapper,
    ) -> None:
        import inspect

        connected.do_use("anthropic")
        connected.do_run(OFFLINE_RUN)

        scoped = shell_module.TierScopedLLMClient(
            connected.llm_client, **spy_wrapper[-1],
        )
        assert "provider" not in inspect.signature(scoped.query_text).parameters
        assert "provider" not in inspect.signature(
            scoped.query_with_document
        ).parameters
