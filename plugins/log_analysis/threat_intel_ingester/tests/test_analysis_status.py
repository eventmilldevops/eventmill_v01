"""One status for the ingestion, stated before anything else.

summarize_for_llm is capped at 2000 characters by PluginExecutor and truncates
from the end, so coverage and truncation warnings placed after the IOC content
were the part most likely to be cut. analysis_status leads instead.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_intel_ingester_tool_analysis"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()

STATUSES = ("complete", "partial", "degraded")


@pytest.fixture
def tool_instance():
    return _tool_mod.ThreatIntelIngester()


def _fields(mode="llm", pages_total=10, pages_read=10, cut=()):
    return _tool_mod._analysis_fields(
        ingestion_mode=mode,
        pages_total=pages_total,
        pages_read=pages_read,
        truncated_chunks=list(cut),
    )


class TestStatusIsDerived:
    def test_a_clean_run_is_complete(self):
        f = _fields()
        assert f["analysis_status"] == "complete"
        assert f["analysis_notes"] == []

    def test_dropped_pages_make_it_partial(self):
        f = _fields(pages_total=2500, pages_read=2000)
        assert f["analysis_status"] == "partial"
        assert any("2000 of 2500" in n for n in f["analysis_notes"])

    def test_a_truncated_chunk_makes_it_partial(self):
        f = _fields(cut=[3])
        assert f["analysis_status"] == "partial"
        assert any("chunk 3" in n for n in f["analysis_notes"])

    def test_several_truncated_chunks_read_naturally(self):
        f = _fields(cut=[2, 5])
        assert any("chunks 2, 5" in n for n in f["analysis_notes"])

    def test_the_regex_baseline_is_degraded_not_partial(self):
        """Unrefined indicators are a different kind of answer, not less of the
        same one: nothing classified them or ruled out false positives."""
        f = _fields(mode="regex_only")
        assert f["analysis_status"] == "degraded"
        assert any(n.startswith("DEGRADED INPUT") for n in f["analysis_notes"])

    def test_degraded_outranks_partial(self):
        f = _fields(mode="regex_only", pages_total=10, pages_read=4, cut=[1])
        assert f["analysis_status"] == "degraded"
        assert len(f["analysis_notes"]) == 3, "every cause is still named"

    def test_every_status_is_reachable(self):
        assert {
            _fields()["analysis_status"],
            _fields(cut=[1])["analysis_status"],
            _fields(mode="regex_only")["analysis_status"],
        } == set(STATUSES)

    def test_the_status_is_in_the_declared_enum(self):
        schema = json.loads(
            (PLUGIN_DIR / "schemas" / "output.schema.json").read_text(encoding="utf-8")
        )
        declared = (
            schema["properties"]["result"]["properties"]["summary"]
            ["properties"]["analysis_status"]["enum"]
        )
        assert set(declared) == set(STATUSES)


def _result(**summary_fields):
    summary = {
        "total_iocs": 2,
        "ioc_breakdown": {"ip": 2},
        "high_priority_count": 0,
        "mitre_technique_count": 0,
    }
    summary.update(summary_fields)
    return type("R", (), {
        "ok": True,
        "output_artifacts": [],
        "result": {
            "report_metadata": {
                "title": "A Report", "artifact_type": "pdf_report",
                "page_count": 9,
            },
            "summary": summary,
            "mitre_mappings": [],
            "iocs": [],
        },
    })()


class TestStatusLeadsTheSummary:
    @pytest.mark.parametrize("status", ["partial", "degraded"])
    def test_a_non_complete_status_is_the_first_thing_said(
        self, tool_instance, status,
    ):
        text = tool_instance.summarize_for_llm(_result(
            analysis_status=status,
            analysis_notes=["INCOMPLETE COVERAGE: only 2 of 9 pages were read"],
        ))
        assert text.startswith(status.upper()), text[:80]

    def test_it_precedes_the_report_identity(self, tool_instance):
        """Even the title comes second — the reader needs to know what kind of
        answer this is before reading any of it."""
        text = tool_instance.summarize_for_llm(_result(
            analysis_status="degraded", analysis_notes=["DEGRADED INPUT: regex only"],
        ))
        assert text.index("DEGRADED") < text.index("A Report")

    def test_complete_says_nothing_about_status(self, tool_instance):
        text = tool_instance.summarize_for_llm(_result(
            analysis_status="complete", analysis_notes=[],
        ))
        assert text.startswith("Ingested")
        for marker in ("COMPLETE", "PARTIAL", "DEGRADED"):
            assert marker not in text

    def test_a_missing_status_is_treated_as_complete(self, tool_instance):
        assert tool_instance.summarize_for_llm(_result()).startswith("Ingested")

    def test_the_warning_survives_the_2000_character_cap(self, tool_instance):
        text = tool_instance.summarize_for_llm(_result(
            analysis_status="partial",
            analysis_notes=["TRUNCATED OUTPUT: " + "cause. " * 400],
        ))
        assert text[:2000].startswith("PARTIAL")
