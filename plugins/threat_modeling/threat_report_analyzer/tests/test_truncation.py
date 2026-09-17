"""A truncated reply must not be reported as a complete summary.

All three of this plugin's LLM calls checked only `response.ok` and dropped
`LLMResponse.truncated` on the floor, so a summary that stopped at the output
cap halfway through a report was indistinguishable from one that covered it.
The text is still kept — a partial answer beats none — but the fact now travels
with the result and reaches `summarize_for_llm`.
"""

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool_truncation"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


@pytest.fixture
def tool_instance():
    return _tool_mod.ThreatReportAnalyzer()


@dataclass
class _Resp:
    ok: bool = True
    text: str = "Summary body mentioning T1059 and more."
    error: str | None = None
    model_used: str = "fake-model"
    transport_path: str = "inline_bytes"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class _LLM:
    doc_response: _Resp = field(default_factory=_Resp)
    text_response: _Resp = field(default_factory=_Resp)
    doc_calls: list = field(default_factory=list)
    text_calls: list = field(default_factory=list)

    def supports_native_document(self, mime_type: str) -> bool:
        return mime_type == "application/pdf"

    def query_with_document(self, prompt, artifact, **kwargs):
        self.doc_calls.append(kwargs)
        return self.doc_response

    def query_text(self, prompt, **kwargs):
        self.text_calls.append(kwargs)
        return self.text_response


@dataclass
class _Context:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)


def _chunk(content="body text", index=0, page_start=40, page_end=60):
    return _tool_mod.Chunk(
        index=index,
        content=content,
        token_estimate=500,
        source_type="pdf",
        page_start=page_start,
        page_end=page_end,
    )


def _run_native(tool_instance, tmp_path, monkeypatch, response):
    pdf = tmp_path / "r.pdf"
    pdf.write_bytes(b"%PDF-fake")
    monkeypatch.setattr(tool_instance, "_resolve_report_path", lambda *a, **k: pdf)
    monkeypatch.setattr(tool_instance, "_get_generated_path", lambda ctx: tmp_path)
    llm = _LLM(doc_response=response)
    result = tool_instance.execute(
        {"action": "summarize", "report_path": "v/r.pdf", "max_words": 2000},
        _Context(llm_query=llm),
    )
    assert llm.doc_calls, "the native path did not run"
    return result


# ---------------------------------------------------------------------------
# The native whole-document call
# ---------------------------------------------------------------------------


class TestNativeTruncation:
    def test_a_clean_run_reports_no_truncation(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        result = _run_native(tool_instance, tmp_path, monkeypatch, _Resp())
        s = result.result["summaries"][0]
        assert s["truncated"] is False
        assert s["truncation_notes"] == []

    def test_a_truncated_summary_is_marked(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        result = _run_native(
            tool_instance, tmp_path, monkeypatch,
            _Resp(text="short", truncated=True, finish_reason="MAX_TOKENS"),
        )
        s = result.result["summaries"][0]
        assert s["truncated"] is True
        assert s["truncation_notes"], "the cause must be named, not just flagged"

    def test_the_truncated_text_is_kept(self, tool_instance, tmp_path, monkeypatch):
        """The defect is the silence, not the content."""
        result = _run_native(
            tool_instance, tmp_path, monkeypatch,
            _Resp(text="short but real", truncated=True),
        )
        assert result.ok
        assert result.result["summaries"][0]["summary"] == "short but real"

    def test_truncation_reaches_the_llm_summary(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        """summarize_for_llm is what downstream reasoning actually sees, so a
        result marked truncated must not read there as a complete summary."""
        result = _run_native(
            tool_instance, tmp_path, monkeypatch,
            _Resp(text="short", truncated=True),
        )
        text = tool_instance.summarize_for_llm(result)
        assert "TRUNCATED OUTPUT" in text
        assert "partial" in text.lower()

    def test_a_clean_run_says_nothing_about_truncation(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        result = _run_native(tool_instance, tmp_path, monkeypatch, _Resp())
        assert "TRUNCATED" not in tool_instance.summarize_for_llm(result)


# ---------------------------------------------------------------------------
# Section summaries and synthesis
# ---------------------------------------------------------------------------


class TestSectionTruncation:
    def test_a_truncated_section_is_marked_on_its_chunk(self, tool_instance):
        llm = _LLM(text_response=_Resp(text="cut", truncated=True))
        cs = tool_instance._summarize_chunk(
            _chunk(), "r.pdf", "vendor", [], _Context(llm_query=llm),
        )
        assert cs["truncated"] is True
        assert cs["summary"] == "cut", "the partial summary is still kept"

    def test_a_clean_section_is_not_marked(self, tool_instance):
        llm = _LLM(text_response=_Resp(text="full summary"))
        cs = tool_instance._summarize_chunk(
            _chunk(), "r.pdf", "vendor", [], _Context(llm_query=llm),
        )
        assert cs["truncated"] is False

    def test_the_note_names_the_page_range(self, tool_instance):
        """"A section was cut off" is not actionable; which section is."""
        tool_instance._truncations = []
        llm = _LLM(text_response=_Resp(text="cut", truncated=True))
        tool_instance._summarize_chunk(
            _chunk(page_start=40, page_end=60), "r.pdf", "vendor", [],
            _Context(llm_query=llm),
        )
        assert any("40" in n and "60" in n for n in tool_instance._truncations)


class TestSynthesisTruncation:
    def test_a_truncated_synthesis_is_recorded(self, tool_instance):
        tool_instance._truncations = []
        llm = _LLM(text_response=_Resp(text="partial synthesis", truncated=True))
        out = tool_instance._synthesize_summaries(
            [{"chunk_index": 0, "page_start": 1, "page_end": 10, "summary": "a"},
             {"chunk_index": 1, "page_start": 11, "page_end": 20, "summary": "b"}],
            "r.pdf", [], 2000, _Context(llm_query=llm),
        )
        assert out == "partial synthesis", "the partial synthesis is still used"
        assert tool_instance._truncations, "but the fact must be recorded"

    def test_a_clean_synthesis_records_nothing(self, tool_instance):
        tool_instance._truncations = []
        llm = _LLM(text_response=_Resp(text="full synthesis"))
        tool_instance._synthesize_summaries(
            [{"chunk_index": 0, "page_start": 1, "page_end": 10, "summary": "a"},
             {"chunk_index": 1, "page_start": 11, "page_end": 20, "summary": "b"}],
            "r.pdf", [], 2000, _Context(llm_query=llm),
        )
        assert tool_instance._truncations == []


class TestTruncationStateIsPerRun:
    def test_a_previous_runs_truncation_does_not_leak(self, tool_instance):
        """A value left over from an earlier report would describe the wrong
        run, the same reason _last_pdf_pages is reset."""
        tool_instance._truncations = ["stale note from an earlier report"]
        assert tool_instance._truncation_fields()["truncated"] is True
        tool_instance._truncations = []
        assert tool_instance._truncation_fields() == {
            "truncated": False, "truncation_notes": [],
        }

    def test_the_helper_does_not_share_state_between_instances(self):
        """A mutable class attribute would collect notes across every run."""
        a = _tool_mod.ThreatReportAnalyzer()
        b = _tool_mod.ThreatReportAnalyzer()
        a._note_truncation("only a's")
        assert b._truncation_fields()["truncation_notes"] == []
