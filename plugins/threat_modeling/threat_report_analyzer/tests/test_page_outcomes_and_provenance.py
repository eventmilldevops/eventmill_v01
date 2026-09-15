"""Stage 1.7 — an unreadable page is not a page that was read.
Stage 1.6 — coverage and status travel with the export, not only the result.

A page pypdf could not read and a page that is genuinely blank both appended ""
and both counted toward pages_read, so the coverage numbers could not tell a
scanned page from an empty one. And every coverage and status field lived only
on the returned ToolResult, which does not survive the session that produced
it — a summary read back from the bucket carried no trace of having been built
from part of a report, or of having failed halfway.
"""

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool_pages"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


@pytest.fixture
def tool():
    t = _tool_mod.ThreatReportAnalyzer()
    t._truncations = []
    t._degradations = []
    t._provenance = []
    t._last_pdf_pages = None
    t._last_pdf_page_outcomes = None
    return t


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = "Summary body."
    error: str | None = None
    model_used: str = "gemini-3.8-flash"
    model_version: str | None = None
    provider_id: str | None = "gcp_gemini"
    transport_path: str = "inline_bytes"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class _LLM:
    doc_response: Any = field(default_factory=_Resp)
    text_response: Any = field(default_factory=_Resp)

    def supports_native_document(self, mime_type: str) -> bool:
        return mime_type == "application/pdf"

    def query_with_document(self, prompt, artifact, **kwargs):
        return self.doc_response

    def query_text(self, prompt, **kwargs):
        return self.text_response


@dataclass
class _Context:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)


class _Page:
    """One pypdf page: text, blank, or one that raises on extract_text()."""

    def __init__(self, text=None, raises=False):
        self._text = text
        self._raises = raises

    def extract_text(self):
        if self._raises:
            raise ValueError("cannot decode content stream")
        return self._text


class _Reader:
    def __init__(self, pages):
        self.pages = pages


def _patch_pypdf(monkeypatch, pages):
    import types
    fake = types.ModuleType("pypdf")
    fake.PdfReader = lambda path: _Reader(pages)
    monkeypatch.setitem(sys.modules, "pypdf", fake)


# ---------------------------------------------------------------------------
# 1.7 — per-page outcomes
# ---------------------------------------------------------------------------


class TestPageOutcomes:
    def test_text_blank_and_unreadable_are_counted_separately(
        self, tool, tmp_path, monkeypatch,
    ):
        """The plan's fixture, exactly: one text page, one blank page, and one
        whose extract_text() raises."""
        _patch_pypdf(monkeypatch, [
            _Page("real content here"), _Page(""), _Page(raises=True),
        ])
        tool._split_pdf_into_chunks(tmp_path / "r.pdf")
        cov = tool._coverage_fields()
        assert cov["pages_read"] == 1
        assert cov["pages_empty"] == 1
        assert cov["pages_extract_failed"] == 1
        assert cov["pages_total"] == 3

    def test_a_blank_page_is_not_a_failure(self, tool, tmp_path, monkeypatch):
        """Reporting a legitimate blank page as a defect trains operators to
        ignore the field."""
        _patch_pypdf(monkeypatch, [_Page("content"), _Page("   \n ")])
        tool._split_pdf_into_chunks(tmp_path / "r.pdf")
        cov = tool._coverage_fields()
        assert cov["pages_extract_failed"] == 0
        assert cov["pages_empty"] == 1
        assert tool._analysis_fields()["analysis_status"] == "complete"

    def test_an_unreadable_page_makes_the_run_partial(
        self, tool, tmp_path, monkeypatch,
    ):
        _patch_pypdf(monkeypatch, [_Page("content"), _Page(raises=True)])
        tool._split_pdf_into_chunks(tmp_path / "r.pdf")
        f = tool._analysis_fields()
        assert f["analysis_status"] == "partial"
        assert any(n.startswith("UNREADABLE PAGES") for n in f["analysis_notes"])

    def test_an_unreadable_page_is_not_a_dropped_page(
        self, tool, tmp_path, monkeypatch,
    ):
        """pages_dropped means never attempted. Calling a failed extraction
        "dropped" would hide that the file itself is the problem."""
        _patch_pypdf(monkeypatch, [_Page("content"), _Page(raises=True)])
        tool._split_pdf_into_chunks(tmp_path / "r.pdf")
        assert tool._coverage_fields()["pages_dropped"] == 0

    def test_a_fully_readable_pdf_reports_all_pages_read(
        self, tool, tmp_path, monkeypatch,
    ):
        _patch_pypdf(monkeypatch, [_Page("a"), _Page("b"), _Page("c")])
        tool._split_pdf_into_chunks(tmp_path / "r.pdf")
        cov = tool._coverage_fields()
        assert cov["pages_read"] == 3 and cov["pages_dropped"] == 0
        assert cov["pages_empty"] == 0 and cov["pages_extract_failed"] == 0

    def test_native_ingestion_claims_no_per_page_counts(self, tool):
        """It reads the document whole; inventing counts it never made would
        be worse than saying nothing."""
        assert tool._coverage_fields() == {}

    def test_outcomes_do_not_leak_between_runs(self, tool, tmp_path, monkeypatch):
        _patch_pypdf(monkeypatch, [_Page(raises=True)])
        tool._split_pdf_into_chunks(tmp_path / "r.pdf")
        assert tool._coverage_fields()["pages_extract_failed"] == 1
        tool._last_pdf_pages = None
        tool._last_pdf_page_outcomes = None
        assert tool._coverage_fields() == {}


# ---------------------------------------------------------------------------
# 1.6 — the export carries its own provenance
# ---------------------------------------------------------------------------


class TestProvenanceBlock:
    def test_it_names_source_run_model_and_status(self, tool):
        tool._note_model(_Resp())
        block = tool._provenance_block("vendor/r.pdf", "20260915T120000Z")
        assert "vendor/r.pdf" in block
        assert "20260915T120000Z" in block
        assert "gcp_gemini/gemini-3.8-flash" in block
        assert "complete" in block

    def test_it_prefers_the_model_the_provider_reports(self, tool):
        """model_used is what was asked for; model_version is what ran."""
        tool._note_model(_Resp(model_used="gemini-3.8-flash",
                               model_version="gemini-3.8-flash-002"))
        assert "gemini-3.8-flash-002" in tool._provenance_block("r.pdf", "s")

    def test_each_provider_is_named_once(self, tool):
        for _ in range(5):
            tool._note_model(_Resp())
        assert len(tool._provenance) == 1

    def test_it_says_so_when_no_llm_answered(self, tool):
        assert "(no LLM)" in tool._provenance_block("r.pdf", "s")

    def test_it_carries_every_analysis_note(self, tool):
        tool._note_truncation("the synthesis stopped at the output cap")
        tool._note_degradation("pages 1-20 has no section summary")
        block = tool._provenance_block("r.pdf", "s")
        assert "degraded" in block
        assert "TRUNCATED OUTPUT" in block and "DEGRADED INPUT" in block

    def test_it_reports_page_outcomes_when_measured(
        self, tool, tmp_path, monkeypatch,
    ):
        _patch_pypdf(monkeypatch, [_Page("a"), _Page(""), _Page(raises=True)])
        tool._split_pdf_into_chunks(tmp_path / "r.pdf")
        block = tool._provenance_block("r.pdf", "s")
        assert "1 read of 3" in block
        assert "1 blank" in block and "1 unreadable" in block

    def test_it_says_nothing_about_pages_when_nothing_measured_them(self, tool):
        assert "Pages:" not in tool._provenance_block("r.pdf", "s")


class TestExportsCarryTheBlock:
    def _run(self, tool, tmp_path, monkeypatch, llm):
        pdf = tmp_path / "r.pdf"
        pdf.write_bytes(b"%PDF-fake")
        monkeypatch.setattr(tool, "_resolve_report_path", lambda *a, **k: pdf)
        monkeypatch.setattr(tool, "_get_generated_path", lambda ctx: tmp_path)
        monkeypatch.setattr(tool, "_get_common_bucket_path", lambda ctx: tmp_path)
        return tool.execute(
            {"action": "summarize", "report_path": "vendor/r.pdf",
             "max_words": 2000},
            _Context(llm_query=llm),
        )

    def test_the_written_summary_round_trips_its_status(
        self, tool, tmp_path, monkeypatch,
    ):
        """The plan's test: write the artifact, read it back, assert coverage
        and status survive."""
        result = self._run(tool, tmp_path, monkeypatch, _LLM(
            doc_response=_Resp(text="a summary", truncated=True),
        ))
        path = Path(result.result["summaries"][0]["summary_path"])
        if not path.is_absolute():
            path = tmp_path / path
        written = path.read_text(encoding="utf-8")
        assert written.startswith("<!-- Event Mill threat_report_analyzer -->")
        assert "**Analysis status:** partial" in written
        assert "vendor/r.pdf" in written
        assert "gcp_gemini/gemini-3.8-flash" in written
        assert "TRUNCATED OUTPUT" in written
        assert "a summary" in written, "the summary itself still follows"

    def test_a_clean_run_still_records_what_answered(
        self, tool, tmp_path, monkeypatch,
    ):
        result = self._run(tool, tmp_path, monkeypatch, _LLM())
        path = Path(result.result["summaries"][0]["summary_path"])
        if not path.is_absolute():
            path = tmp_path / path
        written = path.read_text(encoding="utf-8")
        assert "**Analysis status:** complete" in written
        assert "gcp_gemini/gemini-3.8-flash" in written
