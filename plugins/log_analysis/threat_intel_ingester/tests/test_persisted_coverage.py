"""Coverage and status must survive being written to the artifact.

They existed only on the returned ToolResult, so they vanished the moment the
artifact was read back. An export outlives the session that produced it, and a
file read from the bucket months later had no trace of having been built from
part of a report, or of having fallen back to the regex baseline.
"""

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_intel_ingester_tool_persist"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


@pytest.fixture
def tool_instance():
    return _tool_mod.ThreatIntelIngester()


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
    model_used: str | None = "mock-light"
    transport_path: str | None = "text"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class MockArtifactRef:
    artifact_id: str
    artifact_type: str
    file_path: str
    source_tool: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class MockReferenceDataView:
    _data: dict = field(default_factory=dict)

    def get(self, key: str, default=None):
        return self._data.get(key, default)


@dataclass
class MockExecutionContext:
    session_id: str = "test_session_persist"
    selected_pillar: str = "log_analysis"
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)
    logger: Any = None
    reference_data: MockReferenceDataView = field(
        default_factory=MockReferenceDataView
    )
    llm_enabled: bool = False
    llm_query: Any = None
    register_artifact: Callable | None = None
    limits: dict = field(default_factory=dict)


class _TextLLM:
    def __init__(self, response):
        self.response = response

    def supports_native_document(self, mime_type: str) -> bool:
        return False

    def query_text(self, prompt, **kwargs):
        return self.response


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    report = tmp_path / "report.txt"
    report.write_text("Beaconing to 198.51.100.7 over 443.\n", encoding="utf-8")
    artifact = MockArtifactRef(
        artifact_id="art_txt", artifact_type="text", file_path=str(report),
    )
    written: list[str] = []

    def register(artifact_type, file_path, source_tool, metadata):
        written.append(file_path)
        return MockArtifactRef(
            artifact_id="art_out", artifact_type=artifact_type, file_path=file_path,
        )

    def go(tool, llm):
        ctx = MockExecutionContext(
            artifacts=[artifact], llm_enabled=llm is not None,
            llm_query=llm, register_artifact=register,
        )
        result = tool.execute({"artifact_id": "art_txt"}, ctx)
        assert result.ok, result.message
        assert written, "no artifact was written"
        return result, json.loads(Path(written[-1]).read_text(encoding="utf-8"))

    return go


_GOOD = json.dumps({
    "refined_iocs": [
        {"value": "198.51.100.7", "ioc_type": "ip", "confidence": "high",
         "priority": "medium", "context": "c2", "related_mitre": [],
         "is_false_positive": False},
    ],
    "additional_mitre_techniques": [],
    "report_metadata": {"title": "Report"},
    "attack_graph": {"paths": [], "convergence_points": [], "branch_points": []},
})


class TestArtifactRoundTrip:
    def test_status_survives_the_round_trip(self, tool_instance, run):
        _, persisted = run(tool_instance, _TextLLM(_Resp(text=_GOOD)))
        assert persisted["analysis_status"] == "complete"
        assert "analysis_notes" in persisted

    def test_coverage_survives_the_round_trip(self, tool_instance, run):
        _, persisted = run(tool_instance, _TextLLM(_Resp(text=_GOOD)))
        cov = persisted["coverage"]
        assert {"pages_total", "pages_read", "pages_dropped"} <= set(cov)

    def test_the_ingestion_mode_survives(self, tool_instance, run):
        """Whether these indicators were refined or are a regex baseline is
        the first thing a later reader needs, and it was not written down."""
        _, persisted = run(tool_instance, None)
        assert persisted["ingestion_mode"] == "regex_only"
        assert persisted["analysis_status"] == "degraded"

    def test_a_degraded_run_says_so_in_the_file(self, tool_instance, run):
        _, persisted = run(tool_instance, None)
        assert any(
            n.startswith("DEGRADED INPUT") for n in persisted["analysis_notes"]
        )

    def test_a_truncated_run_says_so_in_the_file(self, tool_instance, run):
        _, persisted = run(tool_instance, _TextLLM(
            _Resp(text=_GOOD, truncated=True, finish_reason="MAX_TOKENS"),
        ))
        assert persisted["analysis_status"] == "partial"
        assert any(
            n.startswith("TRUNCATED OUTPUT") for n in persisted["analysis_notes"]
        )

    def test_the_persisted_status_matches_the_returned_one(
        self, tool_instance, run,
    ):
        """Two copies of the same judgement that could disagree would be worse
        than one."""
        result, persisted = run(tool_instance, _TextLLM(
            _Resp(text=_GOOD, truncated=True),
        ))
        summary = result.result["summary"]
        assert persisted["analysis_status"] == summary["analysis_status"]
        assert persisted["analysis_notes"] == summary["analysis_notes"]

    def test_the_data_itself_is_unchanged(self, tool_instance, run):
        """Additive only — existing consumers read these keys."""
        _, persisted = run(tool_instance, _TextLLM(_Resp(text=_GOOD)))
        for key in ("report_metadata", "iocs", "mitre_mappings", "attack_graph"):
            assert key in persisted
