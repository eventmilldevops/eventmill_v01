"""Chunk failures must be visible, and a rejection must not be undone.

Two defects with one shape — `if not refined_iocs:` answered two different
questions at once, and per-chunk failures were counted only into log lines:

1. A model that assessed every candidate as a false positive produced an empty
   `refined_iocs`, which triggered the regex baseline and **reinstated the exact
   indicators it had just rejected**, at `confidence: "low"`, under
   `ingestion_mode: "regex_only"`. A correct filtering result became a wrong one.
2. A run where some chunks failed and others succeeded merged the survivors and
   reported exactly like a clean run. The candidates in the failed chunks were
   never assessed and nothing said so.
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
    _name = "threat_intel_ingester_tool_chunkfail"
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
    session_id: str = "test_session_cf"
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


# Every IP the fixture report contains. A stub that answers about only
# some of them is a partial assessment, which the run now reports as such
# — so a test about rejection or a clean run has to answer about all.
ALL_CANDIDATES = ["198.51.100.7", "203.0.113.9", "192.0.2.44"]


def _reply(values, false_positive=False):
    return json.dumps({
        "refined_iocs": [
            {"value": v, "ioc_type": "ip", "confidence": "high",
             "priority": "medium", "context": "c2", "related_mitre": [],
             "is_false_positive": false_positive}
            for v in values
        ],
        "additional_mitre_techniques": [],
        "report_metadata": {"title": "Report"},
        "attack_graph": {"paths": [], "convergence_points": [],
                         "branch_points": []},
    })


class _ScriptedLLM:
    """Answers each chunked call from a list, so failures can be placed."""

    def __init__(self, replies):
        self._replies = list(replies)
        self._i = 0
        self.calls = 0

    def supports_native_document(self, mime_type: str) -> bool:
        return False

    def query_text(self, prompt, **kwargs):
        self.calls += 1
        reply = self._replies[min(self._i, len(self._replies) - 1)]
        self._i += 1
        if isinstance(reply, Exception):
            raise reply
        return reply


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    report = tmp_path / "report.txt"
    report.write_text(
        "Beaconing to 198.51.100.7 and 203.0.113.9 and 192.0.2.44 over 443.\n",
        encoding="utf-8",
    )
    artifact = MockArtifactRef(
        artifact_id="art_txt", artifact_type="text", file_path=str(report),
    )

    def register(artifact_type, file_path, source_tool, metadata):
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
        return result

    return go


# ---------------------------------------------------------------------------
# A rejection is an answer, not an absence of one
# ---------------------------------------------------------------------------


class TestAllCandidatesRejected:
    def test_zero_iocs_and_mode_stays_llm(self, tool_instance, run):
        """The defect: the regex baseline reinstated what the model rejected."""
        llm = _ScriptedLLM([_Resp(text=_reply(
            ["198.51.100.7", "203.0.113.9", "192.0.2.44"], false_positive=True,
        ))])
        result = run(tool_instance, llm)
        summary = result.result["summary"]
        assert result.result["iocs"] == [], (
            "reinstating rejected indicators turns a correct filtering result "
            "into a wrong one"
        )
        assert summary["ingestion_mode"] == "llm", "not the regex baseline"

    def test_the_empty_result_is_reported_as_complete(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text=_reply(ALL_CANDIDATES, True))])
        summary = run(tool_instance, llm).result["summary"]
        assert summary["analysis_status"] == "complete"

    def test_it_says_the_emptiness_is_the_assessment(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text=_reply(ALL_CANDIDATES, True))])
        result = run(tool_instance, llm)
        summary = result.result["summary"]
        assert summary["candidates_rejected"] >= 1
        assert any(
            n.startswith("NO INDICATORS ACCEPTED")
            for n in summary["analysis_notes"]
        )
        assert "NO INDICATORS ACCEPTED" in tool_instance.summarize_for_llm(result)

    def test_accepted_candidates_still_come_through(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text=_reply(ALL_CANDIDATES, False))])
        result = run(tool_instance, llm)
        assert result.result["iocs"], "a normal run is unaffected"
        assert result.result["summary"]["analysis_status"] == "complete"


class TestRefinementUnavailable:
    def test_no_llm_still_yields_the_regex_baseline(self, tool_instance, run):
        """The fallback must survive — it is only the reinstatement of an
        explicit rejection that was wrong."""
        summary = run(tool_instance, None).result["summary"]
        assert summary["ingestion_mode"] == "regex_only"
        assert summary["analysis_status"] == "degraded"

    def test_a_total_failure_still_yields_the_regex_baseline(
        self, tool_instance, run,
    ):
        llm = _ScriptedLLM([_Resp(ok=False, text=None, error="transport died")])
        result = run(tool_instance, llm)
        summary = result.result["summary"]
        assert summary["ingestion_mode"] == "regex_only"
        assert summary["analysis_status"] == "degraded"
        assert result.result["iocs"], "the baseline is better than nothing here"

    def test_unparseable_json_is_a_failure_not_a_rejection(
        self, tool_instance, run,
    ):
        """The model answered, but nothing could be read from it. That is not
        an assessment that every candidate was a false positive."""
        llm = _ScriptedLLM([_Resp(text="this is not json at all")])
        summary = run(tool_instance, llm).result["summary"]
        assert summary["ingestion_mode"] == "regex_only"
        assert summary["analysis_status"] == "degraded"


# ---------------------------------------------------------------------------
# Chunk failures reach the result
# ---------------------------------------------------------------------------


class TestChunkFailuresAreCounted:
    def test_a_clean_run_reports_no_failures(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text=_reply(ALL_CANDIDATES))])
        summary = run(tool_instance, llm).result["summary"]
        assert summary["chunks_failed"] == 0
        assert summary["analysis_status"] == "complete"

    def test_the_breakdown_separates_cause(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(ok=False, text=None, error="died")])
        summary = run(tool_instance, llm).result["summary"]
        b = summary["chunk_failure_breakdown"]
        assert b["llm_call"] == 1
        assert b["json_parse"] == 0 and b["exception"] == 0

    def test_a_json_failure_is_counted_as_one(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text="not json")])
        b = run(tool_instance, llm).result["summary"]["chunk_failure_breakdown"]
        assert b["json_parse"] == 1 and b["llm_call"] == 0

    def test_an_exception_is_counted_as_one(self, tool_instance, run):
        llm = _ScriptedLLM([RuntimeError("transport exploded")])
        b = run(tool_instance, llm).result["summary"]["chunk_failure_breakdown"]
        assert b["exception"] == 1


class TestPartialChunkFailureIsNotComplete:
    """The milestone case: some chunks worked, some did not. The merged result
    looks exactly like a clean one, so the status has to carry the difference."""

    def _fields(self, **kw):
        base = dict(
            ingestion_mode="llm", pages_total=0, pages_read=0,
            truncated_chunks=[],
        )
        base.update(kw)
        return _tool_mod._analysis_fields(**base)

    def test_some_chunks_failed_makes_it_partial(self):
        f = self._fields(chunks_attempted=10, chunks_failed=4)
        assert f["analysis_status"] == "partial"
        assert any("4 of 10" in n for n in f["analysis_notes"])
        assert any(n.startswith("INCOMPLETE ANALYSIS") for n in f["analysis_notes"])

    def test_no_chunks_failed_stays_complete(self):
        assert self._fields(
            chunks_attempted=10, chunks_failed=0,
        )["analysis_status"] == "complete"

    def test_rejection_alone_does_not_make_it_partial(self):
        """The work was done; this is its result."""
        f = self._fields(accepted_none=True, candidates_rejected=12)
        assert f["analysis_status"] == "complete"
        assert any("12 candidate" in n for n in f["analysis_notes"])

    def test_rejection_plus_a_failed_chunk_is_partial(self):
        """Some candidates were rejected, others were never seen at all. The
        second fact is the one that makes the answer incomplete."""
        f = self._fields(
            chunks_attempted=5, chunks_failed=1,
            accepted_none=True, candidates_rejected=3,
        )
        assert f["analysis_status"] == "partial"
        assert len(f["analysis_notes"]) == 2

    def test_regex_only_still_outranks_a_chunk_failure(self):
        f = self._fields(
            ingestion_mode="regex_only", chunks_attempted=5, chunks_failed=5,
        )
        assert f["analysis_status"] == "degraded"

    def test_the_status_leads_when_chunks_failed(self, tool_instance):
        result = type("R", (), {
            "ok": True,
            "output_artifacts": [],
            "result": {
                "report_metadata": {
                    "title": "A Report", "artifact_type": "text",
                    "page_count": 1,
                },
                "summary": {
                    "total_iocs": 1, "ioc_breakdown": {"ip": 1},
                    "high_priority_count": 0, "mitre_technique_count": 0,
                    **self._fields(chunks_attempted=10, chunks_failed=4),
                },
                "mitre_mappings": [], "iocs": [],
            },
        })()
        assert tool_instance.summarize_for_llm(result).startswith("PARTIAL")


# ---------------------------------------------------------------------------
# Candidates the model never answered about
# ---------------------------------------------------------------------------


class TestUnassessedCandidates:
    """The count of rejections says nothing about candidates the model never
    mentioned. Rejecting three of three is an assessment; rejecting three of
    forty is not, and both used to report identically as "complete"."""

    def test_a_partial_verdict_is_not_a_complete_assessment(
        self, tool_instance, run,
    ):
        # Three candidates in the report, a verdict on one.
        llm = _ScriptedLLM([_Resp(text=_reply(["198.51.100.7"], True))])
        summary = run(tool_instance, llm).result["summary"]
        assert summary["candidates_unassessed"] == 2
        assert summary["analysis_status"] == "partial", (
            "two candidates were neither accepted nor ruled out"
        )

    def test_the_gap_is_named(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text=_reply(["198.51.100.7"], True))])
        result = run(tool_instance, llm)
        notes = result.result["summary"]["analysis_notes"]
        assert any(n.startswith("UNASSESSED CANDIDATES") for n in notes)
        assert "UNASSESSED CANDIDATES" in tool_instance.summarize_for_llm(result)

    def test_a_full_verdict_reports_none_unassessed(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text=_reply(ALL_CANDIDATES, True))])
        summary = run(tool_instance, llm).result["summary"]
        assert summary["candidates_unassessed"] == 0
        assert summary["analysis_status"] == "complete"

    def test_the_rejection_note_counts_verdicts_not_candidates(
        self, tool_instance, run,
    ):
        """It said "all N candidate(s)" while N was what came back, so a
        verdict on 3 of 40 read as an assessment of everything."""
        llm = _ScriptedLLM([_Resp(text=_reply(["198.51.100.7"], True))])
        notes = run(tool_instance, llm).result["summary"]["analysis_notes"]
        rejection = next(n for n in notes if n.startswith("NO INDICATORS"))
        assert "the model assessed 1 candidate" in rejection
        assert "all 1" not in rejection

    def test_technique_matches_are_not_counted_as_unassessed(
        self, tool_instance, run, tmp_path,
    ):
        """mitre_technique candidates are asked for as techniques, not as
        indicators, so their absence from refined_iocs is correct."""
        report = tmp_path / "report.txt"
        report.write_text(
            "T1566 and T1078 and T1027 seen; beaconing to 198.51.100.7.\n",
            encoding="utf-8",
        )
        llm = _ScriptedLLM([_Resp(text=_reply(["198.51.100.7"], False))])
        summary = run(tool_instance, llm).result["summary"]
        assert summary["candidates_unassessed"] == 0


class TestCoverageUnit:
    """A text artifact is measured in lines. Reporting 114 lines as 114 pages
    is how a summary gets mistaken for the report it summarises."""

    def test_a_text_artifact_is_counted_in_lines(self, tool_instance, run):
        llm = _ScriptedLLM([_Resp(text=_reply(ALL_CANDIDATES, False))])
        result = run(tool_instance, llm)
        assert result.result["summary"]["coverage_unit"] == "lines"

    def test_the_note_names_the_unit(self):
        note = _tool_mod._analysis_fields(
            ingestion_mode="llm", pages_total=114, pages_read=40,
            truncated_chunks=[], unit="lines",
        )["analysis_notes"][0]
        assert "40 of 114 lines" in note
        assert "pages" not in note
