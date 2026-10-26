"""Tab completion for 'use <provider | default> for <tool_name>'."""

from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EventMillShell:
    monkeypatch.delenv("K_SERVICE", raising=False)
    sh = EventMillShell(workspace_path=tmp_path)
    monkeypatch.setattr(sh, "_bound_providers", lambda: ("gcp_gemini", "anthropic", "openai"))
    return sh


def _complete(shell: EventMillShell, line: str) -> list[str]:
    """What readline would offer with the cursor at the end of ``line``."""
    begidx = len(line) - len(line.split(" ")[-1])
    return shell.complete_use(line[begidx:], line, begidx, len(line))


class TestProvider:
    def test_every_bound_provider_and_default(self, shell):
        assert _complete(shell, "use ") == ["gcp_gemini", "anthropic", "openai", "default"]

    def test_a_prefix_narrows_it(self, shell):
        assert _complete(shell, "use an") == ["anthropic"]
        assert _complete(shell, "use de") == ["default"]

    def test_before_connect_offers_what_connect_would_bind(self, shell, monkeypatch):
        monkeypatch.setattr(shell, "_bound_providers", lambda: ())
        monkeypatch.setenv("EVENTMILL_LLM_PROVIDERS", "anthropic gcp_gemini")
        assert _complete(shell, "use ") == ["anthropic", "gcp_gemini", "default"]

    def test_a_bad_provider_list_still_completes(self, shell, monkeypatch):
        monkeypatch.setattr(shell, "_bound_providers", lambda: ())
        monkeypatch.setenv("EVENTMILL_LLM_PROVIDERS", "no_such_vendor")
        assert "anthropic" in _complete(shell, "use ")


class TestFor:
    @pytest.mark.parametrize("line", ["use anthropic ", "use anthropic f", "use default "])
    def test_for_follows_any_first_word(self, shell, line):
        assert _complete(shell, line) == ["for"]

    def test_nothing_else_follows_the_first_word(self, shell):
        assert _complete(shell, "use anthropic x") == []


class TestTool:
    def test_any_tool_after_for(self, shell):
        tools = _complete(shell, "use openai for ")
        assert "threat_intel_ingester" in tools
        assert tools == sorted(tools)

    def test_a_prefix_narrows_it(self, shell):
        assert _complete(shell, "use anthropic for threat_intel_") == ["threat_intel_ingester"]

    def test_clearing_offers_the_overridden_tools(self, shell):
        shell._provider_by_tool["threat_intel_ingester"] = "anthropic"
        assert _complete(shell, "use default for ") == ["threat_intel_ingester"]

    def test_clearing_with_no_overrides_offers_every_tool(self, shell):
        assert "threat_intel_ingester" in _complete(shell, "use default for ")

    def test_nothing_after_the_tool(self, shell):
        assert _complete(shell, "use anthropic for threat_intel_ingester ") == []
