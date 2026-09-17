"""One status for the run, stated before anything else.

Coverage, truncation and degradation were each reported in their own field and
their own sentence at the end of summarize_for_llm. PluginExecutor caps that
summary at 2000 characters, so a warning placed after the content is exactly
the part that gets cut. analysis_status collapses them into one judgement and
puts it first.
"""

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool_analysis"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()

STATUSES = ("complete", "partial", "degraded")


@pytest.fixture
def tool():
    t = _tool_mod.ThreatReportAnalyzer()
    t._truncations = []
    t._degradations = []
    t._last_pdf_pages = None
    return t


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = "Summary body."
    error: str | None = None
    model_used: str = "fake-model"
    transport_path: str = "inline_bytes"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class _LLM:
    doc_response: Any = field(default_factory=_Resp)
    text_response: Any = field(default_factory=_Resp)
    native: bool = True

    def supports_native_document(self, mime_type: str) -> bool:
        return self.native and mime_type == "application/pdf"

    def query_with_document(self, prompt, artifact, **kwargs):
        return self.doc_response

    def query_text(self, prompt, **kwargs):
        return self.text_response


@dataclass
class _Context:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Each status is reachable
# ---------------------------------------------------------------------------


class TestStatusIsDerived:
    def test_a_clean_run_is_complete(self, tool):
        f = tool._analysis_fields()
        assert f["analysis_status"] == "complete"
        assert f["analysis_notes"] == []

    def test_dropped_pages_make_it_partial(self, tool):
        tool._last_pdf_pages = (2500, 2000)
        f = tool._analysis_fields()
        assert f["analysis_status"] == "partial"
        assert any("2000 of 2500" in n for n in f["analysis_notes"])
        assert any(n.startswith("INCOMPLETE COVERAGE") for n in f["analysis_notes"])

    def test_truncation_makes_it_partial(self, tool):
        tool._note_truncation("the synthesis stopped at the output cap")
        f = tool._analysis_fields()
        assert f["analysis_status"] == "partial"
        assert any(n.startswith("TRUNCATED OUTPUT") for n in f["analysis_notes"])

    def test_a_fallback_makes_it_degraded(self, tool):
        tool._note_degradation("pages 1-20 has no section summary")
        f = tool._analysis_fields()
        assert f["analysis_status"] == "degraded"
        assert any(n.startswith("DEGRADED INPUT") for n in f["analysis_notes"])

    def test_degraded_outranks_partial(self, tool):
        """A run that stopped analysing part of the report is a more serious
        statement than one that analysed all of it less completely."""
        tool._last_pdf_pages = (100, 50)
        tool._note_truncation("cut off")
        tool._note_degradation("fell back to extracted text")
        f = tool._analysis_fields()
        assert f["analysis_status"] == "degraded"
        assert len(f["analysis_notes"]) == 3, "every cause is still named"

    def test_every_status_is_reachable(self, tool):
        seen = {tool._analysis_fields()["analysis_status"]}
        tool._last_pdf_pages = (10, 5)
        seen.add(tool._analysis_fields()["analysis_status"])
        tool._note_degradation("x")
        seen.add(tool._analysis_fields()["analysis_status"])
        assert seen == set(STATUSES)

    def test_the_status_is_in_the_declared_enum(self, tool):
        import json
        schema = json.loads(
            (PLUGIN_DIR / "schemas" / "output.schema.json").read_text(encoding="utf-8")
        )
        declared = (
            schema["properties"]["summaries"]["items"]
            ["properties"]["analysis_status"]["enum"]
        )
        assert set(declared) == set(STATUSES)


# ---------------------------------------------------------------------------
# The status leads, and survives the 2000-character cap
# ---------------------------------------------------------------------------


def _result(**summary_fields):
    base = {
        "report_path": "v/r.pdf",
        "summary_path": "gs://b/x.md",
        "word_count": 900,
        "chunk_count": 3,
    }
    base.update(summary_fields)
    return type("R", (), {
        "ok": True,
        "result": {"action": "summarize", "summaries": [base]},
    })()


class TestStatusLeadsTheSummary:
    @pytest.mark.parametrize("status", ["partial", "degraded"])
    def test_a_non_complete_status_is_the_first_thing_said(self, tool, status):
        text = tool.summarize_for_llm(_result(
            analysis_status=status,
            analysis_notes=["INCOMPLETE COVERAGE: only 2 of 9 pages were read"],
        ))
        assert text.startswith(status.upper()), text[:80]

    def test_complete_says_nothing_about_status(self, tool):
        text = tool.summarize_for_llm(_result(
            analysis_status="complete", analysis_notes=[],
        ))
        assert text.startswith("Summarized")
        for marker in ("COMPLETE", "PARTIAL", "DEGRADED"):
            assert marker not in text

    def test_a_missing_status_is_treated_as_complete(self, tool):
        """Older persisted results carry no status; they must not render a
        warning the run never made."""
        assert tool.summarize_for_llm(_result()).startswith("Summarized")

    def test_the_warning_survives_the_2000_character_cap(self, tool):
        """PluginExecutor truncates from the end, so a warning at the front is
        the one that reaches downstream reasoning."""
        text = tool.summarize_for_llm(_result(
            analysis_status="degraded",
            analysis_notes=["DEGRADED INPUT: " + "cause. " * 400],
        ))
        assert text[:2000].startswith("DEGRADED")

    def test_notes_are_not_repeated_after_the_content(self, tool):
        """They were separate trailing sentences before 1.4; saying each cause
        twice wastes a capped budget."""
        text = tool.summarize_for_llm(_result(
            analysis_status="partial",
            analysis_notes=["TRUNCATED OUTPUT: the synthesis stopped"],
        ))
        assert text.count("TRUNCATED OUTPUT") == 1


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


class TestStatusOnRealRuns:
    def _run(self, tool, tmp_path, monkeypatch, llm):
        pdf = tmp_path / "r.pdf"
        pdf.write_bytes(b"%PDF-fake")
        monkeypatch.setattr(tool, "_resolve_report_path", lambda *a, **k: pdf)
        monkeypatch.setattr(tool, "_get_generated_path", lambda ctx: tmp_path)
        return tool.execute(
            {"action": "summarize", "report_path": "v/r.pdf", "max_words": 2000},
            _Context(llm_query=llm),
        )

    def test_a_clean_native_run_is_complete(self, tool, tmp_path, monkeypatch):
        result = self._run(tool, tmp_path, monkeypatch, _LLM())
        s = result.result["summaries"][0]
        assert s["analysis_status"] == "complete"
        assert s["analysis_notes"] == []

    def test_a_truncated_native_run_is_partial(self, tool, tmp_path, monkeypatch):
        result = self._run(tool, tmp_path, monkeypatch, _LLM(
            doc_response=_Resp(text="short", truncated=True),
        ))
        s = result.result["summaries"][0]
        assert s["analysis_status"] == "partial"
        assert s["analysis_notes"]

    def test_falling_back_to_extracted_text_is_degraded(
        self, tool, tmp_path, monkeypatch,
    ):
        """The native attempt failed, so the PDF was read as pypdf text: no
        page images, no layout, no tables."""
        monkeypatch.setattr(
            tool, "_split_pdf_into_chunks",
            lambda f: [_tool_mod.Chunk(0, "extracted text", 100, "pdf", 1, 9)],
        )
        result = self._run(tool, tmp_path, monkeypatch, _LLM(
            doc_response=_Resp(ok=False, text=None, error="transport died"),
        ))
        s = result.result["summaries"][0]
        assert s["analysis_status"] == "degraded"
        assert any("extracted text" in n for n in s["analysis_notes"])
        assert tool.summarize_for_llm(result).startswith("DEGRADED")
