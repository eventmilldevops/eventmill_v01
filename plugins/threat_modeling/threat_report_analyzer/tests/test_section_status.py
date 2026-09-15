"""Raw extracted text must never be presented as a section summary.

`summary_text` was initialised to `chunk.content[:3000]` — raw pypdf output —
and only replaced inside `if response.ok`. A failed call left the excerpt in
place; a call starved of output budget returned ok=True with no text and left
an empty string. Neither was marked, and both then travelled two ways: into a
file named `<report>.<stamp>.chunk_NNN.summary.md`, and into the synthesis
prompt under a `[Pages 40-60]` label the model could not distinguish from a
real section summary.
"""

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool_status"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()

RAW = "RAW PYPDF TEXT that no model ever summarised. " * 40


@pytest.fixture
def tool_instance():
    t = _tool_mod.ThreatReportAnalyzer()
    t._truncations = []
    t._degradations = []
    return t


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = "Section summary mentioning T1059."
    error: str | None = None
    model_used: str = "fake-model"
    transport_path: str = "text"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class _LLM:
    text_response: Any = field(default_factory=_Resp)
    raises: bool = False

    def supports_native_document(self, mime_type: str) -> bool:
        return False

    def query_text(self, prompt, **kwargs):
        if self.raises:
            raise RuntimeError("transport exploded")
        return self.text_response


@dataclass
class _Context:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)


def _chunk(content=RAW, index=0, page_start=40, page_end=60):
    return _tool_mod.Chunk(
        index=index,
        content=content,
        token_estimate=500,
        source_type="pdf",
        page_start=page_start,
        page_end=page_end,
    )


def _summarize(tool_instance, response=None, raises=False):
    llm = _LLM(text_response=response or _Resp(), raises=raises)
    return tool_instance._summarize_chunk(
        _chunk(), "r.pdf", "vendor", [], _Context(llm_query=llm),
    )


# ---------------------------------------------------------------------------
# Status is stated, and raw text never occupies "summary"
# ---------------------------------------------------------------------------


class TestSectionStatus:
    def test_a_good_reply_is_complete(self, tool_instance):
        cs = _summarize(tool_instance)
        assert cs["status"] == "complete"
        assert cs["summary"] == "Section summary mentioning T1059."
        assert cs["raw_excerpt"] is None, "no excerpt is needed or kept"

    def test_a_truncated_reply_is_partial_and_keeps_its_text(self, tool_instance):
        cs = _summarize(tool_instance, _Resp(text="cut off here", truncated=True))
        assert cs["status"] == "partial"
        assert cs["summary"] == "cut off here", "partial still holds analysis"

    def test_an_empty_reply_is_empty_not_complete(self, tool_instance):
        """Budget starvation: ok=True, no text, because thinking spent the
        whole output budget. The transport reports no error at all."""
        cs = _summarize(tool_instance, _Resp(text=""))
        assert cs["status"] == "empty"
        assert cs["summary"] is None

    def test_a_whitespace_only_reply_is_empty(self, tool_instance):
        cs = _summarize(tool_instance, _Resp(text="   \n  "))
        assert cs["status"] == "empty"
        assert cs["summary"] is None

    def test_a_failed_call_is_failed(self, tool_instance):
        cs = _summarize(tool_instance, _Resp(ok=False, text=None, error="boom"))
        assert cs["status"] == "failed"
        assert cs["summary"] is None

    def test_an_exception_is_failed(self, tool_instance):
        cs = _summarize(tool_instance, raises=True)
        assert cs["status"] == "failed"
        assert cs["summary"] is None

    def test_no_llm_at_all_is_failed(self, tool_instance):
        cs = tool_instance._summarize_chunk(
            _chunk(), "r.pdf", "vendor", [], _Context(llm_query=None),
        )
        assert cs["status"] == "failed"
        assert cs["summary"] is None

    @pytest.mark.parametrize("response,raises", [
        (_Resp(text=""), False),
        (_Resp(ok=False, text=None), False),
        (None, True),
    ])
    def test_raw_text_is_never_in_the_summary_key(
        self, tool_instance, response, raises,
    ):
        """The defect, stated directly."""
        cs = _summarize(tool_instance, response, raises=raises)
        assert cs["summary"] is None
        assert cs["raw_excerpt"] and cs["raw_excerpt"].startswith("RAW PYPDF")
        assert cs["status"] in ("empty", "failed")

    def test_every_status_is_in_the_declared_vocabulary(self, tool_instance):
        seen = {
            _summarize(tool_instance)["status"],
            _summarize(tool_instance, _Resp(text="x", truncated=True))["status"],
            _summarize(tool_instance, _Resp(text=""))["status"],
            _summarize(tool_instance, _Resp(ok=False))["status"],
        }
        assert seen == set(_tool_mod.CHUNK_STATUSES)


# ---------------------------------------------------------------------------
# The synthesis prompt cannot mistake raw text for a summary
# ---------------------------------------------------------------------------


class TestSynthesisPromptLabelsSubstitutions:
    def _prompt_for(self, tool_instance, chunk_dicts):
        captured = {}

        class _Capture:
            def supports_native_document(self, m):
                return False

            def query_text(self, prompt, **kwargs):
                captured["prompt"] = prompt
                return _Resp(text="final report")

        tool_instance._synthesize_summaries(
            chunk_dicts, "r.pdf", [], 2000, _Context(llm_query=_Capture()),
        )
        return captured["prompt"]

    def test_a_failed_section_is_labelled_in_the_prompt(self, tool_instance):
        prompt = self._prompt_for(tool_instance, [
            {"chunk_index": 0, "page_start": 1, "page_end": 20,
             "status": "complete", "summary": "real analysis"},
            {"chunk_index": 1, "page_start": 40, "page_end": 60,
             "status": "failed", "summary": None, "raw_excerpt": RAW},
        ])
        assert "SECTION SUMMARY FAILED" in prompt
        assert "treat as unsummarised source" in prompt
        assert "Pages 40–60 — SECTION SUMMARY FAILED" in prompt

    def test_an_empty_section_is_labelled_distinctly(self, tool_instance):
        prompt = self._prompt_for(tool_instance, [
            {"chunk_index": 0, "page_start": 40, "page_end": 60,
             "status": "empty", "summary": None, "raw_excerpt": RAW},
        ])
        assert "SECTION SUMMARY EMPTY" in prompt

    def test_a_truncated_section_is_labelled_but_keeps_its_summary(
        self, tool_instance,
    ):
        prompt = self._prompt_for(tool_instance, [
            {"chunk_index": 0, "page_start": 1, "page_end": 20,
             "status": "partial", "summary": "half an analysis"},
        ])
        assert "TRUNCATED at the output cap" in prompt
        assert "half an analysis" in prompt

    def test_a_complete_section_carries_no_notice(self, tool_instance):
        prompt = self._prompt_for(tool_instance, [
            {"chunk_index": 0, "page_start": 1, "page_end": 20,
             "status": "complete", "summary": "real analysis"},
        ])
        assert "SECTION SUMMARY" not in prompt
        assert "[Pages 1–20]" in prompt


# ---------------------------------------------------------------------------
# What gets written to a file named ".summary.md"
# ---------------------------------------------------------------------------


class TestExportedChunkText:
    def test_a_substitution_carries_its_notice_into_the_file(self, tool_instance):
        body = tool_instance._chunk_export_text({
            "chunk_index": 0, "page_start": 40, "page_end": 60,
            "status": "failed", "summary": None, "raw_excerpt": RAW,
        })
        assert body.startswith("> SECTION SUMMARY FAILED")
        assert "RAW PYPDF" in body, "the excerpt is still kept, just labelled"

    def test_a_complete_summary_is_written_verbatim(self, tool_instance):
        body = tool_instance._chunk_export_text({
            "chunk_index": 0, "page_start": 1, "page_end": 20,
            "status": "complete", "summary": "real analysis",
        })
        assert body == "real analysis"

    def test_the_chunk_file_is_still_written_for_a_failed_section(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        """A missing file is itself ambiguous — it cannot distinguish a section
        that failed from one that was never attempted."""
        monkeypatch.setattr(tool_instance, "_get_generated_path", lambda ctx: tmp_path)
        monkeypatch.setattr(
            tool_instance, "_get_common_bucket_path", lambda ctx: tmp_path,
        )
        art = tool_instance._write_chunk_artifact(
            {"chunk_index": 3, "page_start": 40, "page_end": 60,
             "status": "failed", "summary": None, "raw_excerpt": RAW,
             "techniques": []},
            "vendor/r.pdf", _Context(), "20260915T120000Z",
        )
        assert art is not None
        written = Path(art["file_path"]).read_text(encoding="utf-8")
        # Since Stage 1.6 every export opens with a provenance block; the
        # substitution notice follows it and still precedes the raw text.
        assert written.startswith("<!-- Event Mill threat_report_analyzer -->")
        assert "> SECTION SUMMARY FAILED" in written
        assert written.index("SECTION SUMMARY FAILED") < written.index("RAW PYPDF")


# ---------------------------------------------------------------------------
# The run says it was degraded
# ---------------------------------------------------------------------------


class TestDegradationIsRecorded:
    def test_a_failed_section_degrades_the_run(self, tool_instance):
        _summarize(tool_instance, _Resp(ok=False))
        fields = tool_instance._degradation_fields()
        assert fields["degraded"] is True
        assert any("40" in n for n in fields["degradation_notes"])

    def test_an_empty_section_degrades_the_run(self, tool_instance):
        _summarize(tool_instance, _Resp(text=""))
        assert tool_instance._degradation_fields()["degraded"] is True

    def test_a_complete_section_does_not(self, tool_instance):
        _summarize(tool_instance)
        assert tool_instance._degradation_fields() == {
            "degraded": False, "degradation_notes": [],
        }

    def test_a_truncated_section_is_not_a_degradation(self, tool_instance):
        """It is partial analysis, not a fallback to a worse input. It is
        reported as truncated instead."""
        _summarize(tool_instance, _Resp(text="cut", truncated=True))
        assert tool_instance._degradation_fields()["degraded"] is False
        assert tool_instance._truncation_fields()["truncated"] is True

    def test_a_failed_synthesis_degrades_the_run(self, tool_instance):
        llm = _LLM(text_response=_Resp(ok=False, text=None, error="boom"))
        out = tool_instance._synthesize_summaries(
            [{"chunk_index": 0, "page_start": 1, "page_end": 20,
              "status": "complete", "summary": "a"},
             {"chunk_index": 1, "page_start": 21, "page_end": 40,
              "status": "complete", "summary": "b"}],
            "r.pdf", [], 2000, _Context(llm_query=llm),
        )
        assert "a" in out and "b" in out, "the concatenation is still returned"
        notes = tool_instance._degradation_fields()["degradation_notes"]
        assert any("concatenation" in n for n in notes)

    def test_an_empty_synthesis_reply_degrades_the_run(self, tool_instance):
        """ok=True with no text is the starvation case again."""
        llm = _LLM(text_response=_Resp(text=""))
        tool_instance._synthesize_summaries(
            [{"chunk_index": 0, "page_start": 1, "page_end": 20,
              "status": "complete", "summary": "a"}],
            "r.pdf", [], 2000, _Context(llm_query=llm),
        )
        assert tool_instance._degradation_fields()["degraded"] is True

    def test_a_good_synthesis_does_not_degrade(self, tool_instance):
        llm = _LLM(text_response=_Resp(text="a real synthesised report"))
        out = tool_instance._synthesize_summaries(
            [{"chunk_index": 0, "page_start": 1, "page_end": 20,
              "status": "complete", "summary": "a"}],
            "r.pdf", [], 2000, _Context(llm_query=llm),
        )
        assert out == "a real synthesised report"
        assert tool_instance._degradation_fields()["degraded"] is False

    def test_state_does_not_leak_between_instances(self):
        a = _tool_mod.ThreatReportAnalyzer()
        b = _tool_mod.ThreatReportAnalyzer()
        a._note_degradation("only a's")
        assert b._degradation_fields()["degradation_notes"] == []


class TestDegradationReachesTheLLMSummary:
    def test_degradation_is_stated(self, tool_instance):
        result = type("R", (), {
            "ok": True,
            "result": {
                "action": "summarize",
                "summaries": [{
                    "report_path": "v/r.pdf",
                    "summary_path": "gs://b/x.md",
                    "word_count": 900,
                    "chunk_count": 3,
                    "degraded": True,
                    "degradation_notes": ["pages 40-60 has no section summary"],
                    # Stage 1.4 routes every cause through analysis_notes so
                    # the status can lead; _analysis_fields() builds these from
                    # the degradation record, covered in test_analysis_status.
                    "analysis_status": "degraded",
                    "analysis_notes": [
                        "DEGRADED INPUT: pages 40-60 has no section summary "
                        "(failed); raw extracted text stood in for it"
                    ],
                }],
            },
        })()
        text = tool_instance.summarize_for_llm(result)
        assert text.startswith("DEGRADED"), "the status has to lead"
        assert "DEGRADED INPUT" in text
        assert "raw extracted text stood in for it" in text

    def test_a_clean_run_says_nothing(self, tool_instance):
        result = type("R", (), {
            "ok": True,
            "result": {
                "action": "summarize",
                "summaries": [{
                    "report_path": "v/r.pdf",
                    "summary_path": "gs://b/x.md",
                    "word_count": 900,
                    "chunk_count": 3,
                    "degraded": False,
                    "degradation_notes": [],
                }],
            },
        })()
        assert "DEGRADED" not in tool_instance.summarize_for_llm(result)
