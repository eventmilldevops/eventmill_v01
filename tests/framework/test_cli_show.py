"""Tests for full-render output after `run` and the `show` command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell
from framework.session.models import Pillar


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EventMillShell:
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    sh = EventMillShell(workspace_path=tmp_path)
    sh.session_manager.new_session("test")
    sh.session_manager.set_pillar(Pillar.THREAT_MODELING)
    return sh


def _register_text(shell: EventMillShell, path: Path, artifact_type: str = "text") -> str:
    art = shell.session_manager.register_artifact(
        artifact_type=artifact_type,
        file_path=str(path),
        source_tool="test",
        metadata={},
    )
    return art.artifact_id


class TestShow:
    def test_prints_whole_text_file(self, shell, tmp_path, capsys):
        path = tmp_path / "render.txt"
        lines = [f"line {i}" for i in range(300)]
        path.write_text("\n".join(lines), encoding="utf-8")
        aid = _register_text(shell, path)

        shell.do_show(aid)
        out = capsys.readouterr().out
        assert "line 0" in out
        assert "line 299" in out
        assert "(300 lines)" in out
        assert "more line(s)" not in out

    def test_max_lines_limit_tells_how_to_see_rest(self, shell, tmp_path, capsys):
        path = tmp_path / "render.txt"
        path.write_text("\n".join(f"line {i}" for i in range(50)), encoding="utf-8")
        aid = _register_text(shell, path)

        shell.do_show(f"{aid} 10")
        out = capsys.readouterr().out
        assert "line 9" in out
        assert "line 10" not in out
        assert "40 more line(s)" in out
        assert f"show {aid}" in out

    def test_json_is_pretty_printed(self, shell, tmp_path, capsys):
        path = tmp_path / "out.json"
        path.write_text(json.dumps({"a": {"b": [1, 2]}}), encoding="utf-8")
        aid = _register_text(shell, path, artifact_type="json_events")

        shell.do_show(aid)
        out = capsys.readouterr().out
        assert '"b": [' in out

    def test_unknown_artifact(self, shell, capsys):
        shell.do_show("art_nope")
        assert "Artifact not found" in capsys.readouterr().out

    def test_binary_artifact_refused(self, shell, tmp_path, capsys):
        path = tmp_path / "capture.pcap"
        path.write_bytes(b"\x00\x01\x02")
        aid = _register_text(shell, path, artifact_type="pcap")
        shell.do_show(aid)
        assert "not a text artifact" in capsys.readouterr().out

    def test_usage_without_args(self, shell, capsys):
        shell.do_show("")
        assert "Usage: show" in capsys.readouterr().out


class TestRunPrintsFullRender:
    """`run attack_path_visualizer` must show the whole drawing, not the
    2000-character LLM summary, and must say where the files are."""

    def _stages(self, n: int) -> list[dict]:
        return [
            {
                "name": f"Stage {i:02d} with a deliberately long name to widen output",
                "mitre_technique_id": f"T1{i:03d}",
                "technique_claimed": "A technique description that wraps across the box " * 2,
                "stage_present": True,
                "controls": [
                    {"control_name": f"Control {i}-{j}", "control_type": "preventive",
                     "effectiveness_rating": "moderate"}
                    for j in range(3)
                ],
                "gaps_detected": [f"Gap {i}"],
            }
            for i in range(14)
        ]

    def test_full_visualization_printed_and_file_listed(self, shell, capsys):
        payload = {"format": "ascii", "attack_type": "ransomware", "stages": self._stages(14)}
        shell.do_run("attack_path_visualizer " + json.dumps(payload))
        out = capsys.readouterr().out

        assert "Completed successfully" in out
        assert "Rendered output:" in out
        # Every stage box is on screen, including the last one
        assert "14. Stage 13" in out
        assert "(truncated)" not in out
        # The run summary itself is short and points at the full rendering
        assert "Rendered 14 attack stages" in out
        assert "Output files" in out
        assert "show <id>" in out

    def test_both_format_prints_ascii_and_mermaid(self, shell, capsys):
        payload = {"format": "both", "attack_type": "apt", "stages": self._stages(6)}
        shell.do_run("attack_path_visualizer " + json.dumps(payload))
        out = capsys.readouterr().out
        assert "```mermaid" in out
        assert "6. Stage 05" in out
