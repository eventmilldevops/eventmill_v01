"""Tests for `export --all` and auto-export of run outputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell
from framework.cloud.resolver import StorageResolverConfig, create_local_resolver
from framework.session.models import Pillar

PREFIX = "testmill"


@pytest.fixture
def storage_base(tmp_path: Path) -> Path:
    return tmp_path / "storage"


@pytest.fixture
def shell(tmp_path: Path, storage_base: Path, monkeypatch: pytest.MonkeyPatch) -> EventMillShell:
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("EVENTMILL_AUTO_EXPORT", raising=False)
    monkeypatch.delenv("EVENTMILL_AUTO_EXPORT_TOOLS", raising=False)
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    sh = EventMillShell(workspace_path=tmp_path)
    sh.storage_resolver = create_local_resolver(
        base_path=storage_base,
        config=StorageResolverConfig(bucket_prefix=PREFIX),
    )
    sh.session_manager.new_session("test")
    sh.session_manager.set_pillar(Pillar.THREAT_MODELING)
    return sh


def _register(shell: EventMillShell, path: Path, source_tool: str | None, artifact_type: str = "text") -> str:
    path.write_text(f"content of {path.name}", encoding="utf-8")
    art = shell.session_manager.register_artifact(
        artifact_type=artifact_type,
        file_path=str(path),
        source_tool=source_tool,
        metadata={},
    )
    return art.artifact_id


def _exports(storage_base: Path) -> list[str]:
    root = storage_base / f"{PREFIX}-common" / "exports"
    if not root.exists():
        return []
    return sorted(
        str(p.relative_to(root)).replace("\\", "/")
        for p in root.rglob("*")
        if p.is_file() and not p.name.endswith(".meta.json")
    )


class TestExportAll:
    def test_exports_tool_outputs_and_skips_inputs(self, shell, tmp_path, storage_base, capsys):
        _register(shell, tmp_path / "input.log", source_tool=None, artifact_type="log_stream")
        _register(shell, tmp_path / "graph.mmd", source_tool="attack_path_visualizer")
        _register(shell, tmp_path / "iocs.json", source_tool="threat_intel_ingester", artifact_type="json_events")

        shell.do_export("--all")
        out = capsys.readouterr().out

        assert _exports(storage_base) == [
            "attack_path_visualizer/graph.mmd",
            "threat_intel_ingester/iocs.json",
        ]
        assert "Exported 2/2" in out
        assert "1 loaded input(s) skipped" in out

    def test_subfolder(self, shell, tmp_path, storage_base):
        _register(shell, tmp_path / "graph.mmd", source_tool="attack_path_visualizer")
        shell.do_export("--all incident-42")
        assert _exports(storage_base) == ["attack_path_visualizer/incident-42/graph.mmd"]

    def test_nothing_to_export(self, shell, tmp_path, capsys):
        _register(shell, tmp_path / "input.log", source_tool=None, artifact_type="log_stream")
        shell.do_export("--all")
        out = capsys.readouterr().out
        assert "No tool-produced artifacts" in out
        assert "1 loaded input(s) skipped" in out

    def test_missing_file_reported_but_others_continue(self, shell, tmp_path, storage_base, capsys):
        _register(shell, tmp_path / "gone.txt", source_tool="attack_path_visualizer")
        (tmp_path / "gone.txt").unlink()
        _register(shell, tmp_path / "kept.txt", source_tool="attack_path_visualizer")
        shell.do_export("--all")
        out = capsys.readouterr().out
        assert "missing on disk" in out
        assert "Exported 1/2" in out
        assert _exports(storage_base) == ["attack_path_visualizer/kept.txt"]

    def test_single_export_still_works(self, shell, tmp_path, storage_base, capsys):
        aid = _register(shell, tmp_path / "graph.mmd", source_tool="attack_path_visualizer")
        shell.do_export(aid)
        assert "Uploaded" in capsys.readouterr().out
        assert _exports(storage_base) == ["attack_path_visualizer/graph.mmd"]


class TestAutoExport:
    PAYLOAD = json.dumps({
        "format": "mermaid",
        "attack_type": "test",
        "stages": [
            {"name": "Initial Access", "mitre_technique_id": "T1566", "stage_present": True, "controls": []},
            {"name": "Impact", "mitre_technique_id": "T1486", "stage_present": True, "controls": []},
        ],
    })

    def test_off_by_default_locally(self, shell, storage_base, capsys):
        shell.do_run("attack_path_visualizer " + self.PAYLOAD)
        assert "Auto-export" not in capsys.readouterr().out
        assert _exports(storage_base) == []

    def test_visualizer_output_exported_when_enabled(self, shell, storage_base, monkeypatch, capsys):
        monkeypatch.setenv("EVENTMILL_AUTO_EXPORT", "1")
        shell.do_run("attack_path_visualizer " + self.PAYLOAD)
        out = capsys.readouterr().out
        assert "Auto-export" in out
        assert "Uploaded" in out
        exported = _exports(storage_base)
        assert len(exported) == 1
        assert exported[0].startswith("attack_path_visualizer/attack_path_visualizer_")

    def test_cloud_run_detection(self, shell, storage_base, monkeypatch):
        monkeypatch.setenv("K_SERVICE", "eventmill")
        shell.do_run("attack_path_visualizer " + self.PAYLOAD)
        assert len(_exports(storage_base)) == 1

    def test_tool_list_filters(self, shell, storage_base, monkeypatch, capsys):
        monkeypatch.setenv("EVENTMILL_AUTO_EXPORT", "1")
        monkeypatch.setenv("EVENTMILL_AUTO_EXPORT_TOOLS", "threat_intel_ingester")
        shell.do_run("attack_path_visualizer " + self.PAYLOAD)
        assert "Auto-export" not in capsys.readouterr().out
        assert _exports(storage_base) == []

    def test_wildcard_and_empty(self, shell, monkeypatch):
        monkeypatch.setenv("EVENTMILL_AUTO_EXPORT", "1")
        monkeypatch.setenv("EVENTMILL_AUTO_EXPORT_TOOLS", "*")
        assert shell._auto_export_enabled("anything")
        monkeypatch.setenv("EVENTMILL_AUTO_EXPORT_TOOLS", "")
        assert not shell._auto_export_enabled("attack_path_visualizer")

    def test_failure_does_not_fail_run(self, shell, monkeypatch, capsys):
        monkeypatch.setenv("EVENTMILL_AUTO_EXPORT", "1")

        def boom(**kwargs):
            raise RuntimeError("bucket unreachable")

        monkeypatch.setattr(shell.storage_resolver, "upload", boom)
        shell.do_run("attack_path_visualizer " + self.PAYLOAD)
        out = capsys.readouterr().out
        assert "Completed successfully" in out
        assert "Export failed: bucket unreachable" in out
