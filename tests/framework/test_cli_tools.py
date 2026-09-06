"""
Tests for the 'tools' CLI command.

'tools' listed every loaded plugin regardless of the active pillar, which
is not what the architecture spec describes. It is now scoped to the
active pillar, with tools from other pillars surfacing when they name it
in their manifest's also_useful_in, or when they consume an artifact type
the session has loaded.
"""

from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell
from framework.session.models import Pillar


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EventMillShell:
    """A shell with a session in the threat_modeling pillar."""
    monkeypatch.delenv("K_SERVICE", raising=False)

    sh = EventMillShell(workspace_path=tmp_path)
    sh.session_manager.new_session("test")
    sh.session_manager.set_pillar(Pillar.THREAT_MODELING)
    return sh


def _load_artifact(shell: EventMillShell, artifact_type: str, name: str) -> None:
    """Register a file in the session as a loaded artifact."""
    path = Path(shell.workspace_path) / name
    path.write_text("x")
    shell.session_manager.register_artifact(
        artifact_type=artifact_type,
        file_path=str(path),
        source_tool=None,
    )


# ---------------------------------------------------------------------------
# Pillar scoping
# ---------------------------------------------------------------------------


class TestPillarScoping:
    """The active pillar decides what a bare 'tools' shows."""

    def test_lists_only_active_pillar_by_default(self, shell, capsys):
        shell.onecmd("tools")
        out = capsys.readouterr().out
        assert "threat_model_analyzer" in out
        assert "attack_path_visualizer" in out
        assert "pcap_metadata_summary" not in out
        assert "log_searcher" not in out

    def test_names_the_pillar_it_scoped_to(self, shell, capsys):
        shell.onecmd("tools")
        assert "threat_modeling tools" in capsys.readouterr().out

    def test_footer_counts_what_is_hidden(self, shell, capsys):
        shell.onecmd("tools")
        out = capsys.readouterr().out
        total = len(shell.plugin_loader.list_all())
        offered = len(shell.plugin_loader.get_for_pillar(Pillar.THREAT_MODELING))
        assert f"{total - offered} more in other pillars" in out
        assert "tools --all" in out

    def test_all_shows_every_pillar(self, shell, capsys):
        shell.onecmd("tools --all")
        out = capsys.readouterr().out
        assert "threat_model_analyzer" in out
        assert "pcap_metadata_summary" in out
        assert "log_searcher" in out
        assert "more in other pillars" not in out

    def test_named_pillar_still_works(self, shell, capsys):
        shell.onecmd("tools network_forensics")
        out = capsys.readouterr().out
        assert "pcap_metadata_summary" in out
        assert "threat_model_analyzer" not in out

    def test_unknown_pillar_lists_the_real_ones(self, shell, capsys):
        shell.onecmd("tools nope")
        out = capsys.readouterr().out
        assert "No tools for pillar" in out
        assert "threat_modeling" in out

    def test_no_active_pillar_lists_everything(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("K_SERVICE", raising=False)
        sh = EventMillShell(workspace_path=tmp_path)
        sh.session_manager.new_session("test")
        capsys.readouterr()
        sh.onecmd("tools")
        out = capsys.readouterr().out
        assert "pcap_metadata_summary" in out
        assert "log_searcher" in out
        assert "Set a pillar with 'pillar <name>'" in out


# ---------------------------------------------------------------------------
# Cross-pillar relevance
# ---------------------------------------------------------------------------


class TestRelatedTools:
    """A loaded artifact is what makes another pillar's tool relevant."""

    def test_pcap_surfaces_network_tools_in_threat_modeling(self, shell, capsys):
        _load_artifact(shell, "pcap", "capture.pcap")
        shell.onecmd("tools")
        out = capsys.readouterr().out
        assert "Related" in out
        assert "pcap_metadata_summary" in out
        assert "pcap_threat_hunter" in out

    def test_unrelated_tools_stay_hidden(self, shell, capsys):
        _load_artifact(shell, "pcap", "capture.pcap")
        shell.onecmd("tools")
        out = capsys.readouterr().out
        assert "log_searcher" not in out
        assert "firewall_log_aggregator" not in out

    def test_no_related_section_without_artifacts(self, shell, capsys):
        shell.onecmd("tools")
        assert "Related" not in capsys.readouterr().out

    def test_related_tools_are_not_double_counted(self, shell, capsys):
        _load_artifact(shell, "pcap", "capture.pcap")
        shell.onecmd("tools")
        out = capsys.readouterr().out
        total = len(shell.plugin_loader.list_all())
        listed = sum(
            1 for p in shell.plugin_loader.list_all() if f"run {p.tool_name} " in out
        )
        assert f"{total - listed} more in other pillars" in out

    def test_footer_names_only_pillars_with_hidden_tools(self, shell, capsys):
        _load_artifact(shell, "pcap", "capture.pcap")
        shell.onecmd("tools")
        out = capsys.readouterr().out
        assert "log_analysis" in out.rsplit("more in other pillars", 1)[-1]

    def test_active_pillar_tools_are_never_duplicated(self, shell, capsys):
        _load_artifact(shell, "json_events", "events.json")
        shell.onecmd("tools")
        out = capsys.readouterr().out
        assert out.count("run attack_path_visualizer") == 1


# ---------------------------------------------------------------------------
# also_useful_in
# ---------------------------------------------------------------------------


class TestBorrowedTools:
    """A manifest can offer a tool in a pillar it does not belong to."""

    def test_borrowed_tool_is_listed(self, shell, capsys):
        shell.onecmd("tools")
        out = capsys.readouterr().out
        assert "threat_intel_ingester" in out

    def test_borrowed_tool_shows_its_real_pillar(self, shell, capsys):
        shell.onecmd("tools")
        out = capsys.readouterr().out
        assert "log_analysis" in out.split("Related")[0]
        assert "also_useful_in" in out

    def test_borrowed_tool_is_not_counted_as_hidden(self, shell, capsys):
        shell.onecmd("tools")
        out = capsys.readouterr().out
        total = len(shell.plugin_loader.list_all())
        offered = len(shell.plugin_loader.get_for_pillar(Pillar.THREAT_MODELING))
        assert f"{total - offered} more in other pillars" in out

    def test_borrowed_tool_still_listed_under_its_own_pillar(self, shell, capsys):
        shell.onecmd("tools log_analysis")
        out = capsys.readouterr().out
        assert "threat_intel_ingester" in out
        assert "also_useful_in" not in out

    def test_no_footnote_when_nothing_is_borrowed(self, shell, capsys):
        shell.onecmd("tools network_forensics")
        assert "also_useful_in" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------


class TestToolsArguments:
    """Tests for the argument grammar."""

    def test_unknown_flag(self, shell, capsys):
        shell.onecmd("tools --nope")
        assert "Unknown flag --nope" in capsys.readouterr().out

    def test_pillar_and_all_together(self, shell, capsys):
        shell.onecmd("tools network_forensics --all")
        assert "not both" in capsys.readouterr().out

    def test_two_pillars(self, shell, capsys):
        shell.onecmd("tools network_forensics log_analysis")
        assert "Usage: tools" in capsys.readouterr().out
