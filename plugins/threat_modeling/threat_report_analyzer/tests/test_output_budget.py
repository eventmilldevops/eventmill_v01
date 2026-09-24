"""Output-budget sizing for the analyzer's LLM calls.

Every call this plugin makes used to pass a bare integer max_tokens with no
reserve subtracted, so all three were sized below the thinking reserve for the
level they requested and the model could spend the whole budget on thinking and
return empty text. These tests pin the two properties that prevent that: the
budget covers content *plus* the declared reserve, and the level the budget was
sized for is the level actually requested.
"""

import ast
import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from framework.llm.providers import max_output_tokens_for_tier, thinking_reserve_tokens

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool_budget"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()
_SOURCE = (PLUGIN_DIR / "tool.py").read_text(encoding="utf-8")


@pytest.fixture
def tool_instance():
    return _tool_mod.ThreatReportAnalyzer()


@dataclass
class _Resp:
    ok: bool = True
    text: str = "T1059 summary body"
    error: str | None = None
    model_used: str = "fake-model"
    transport_path: str = "inline_bytes"
    fallback_reason: str | None = None


@dataclass
class _RecordingLLM:
    """Records the kwargs of every call, which is what these tests assert on."""

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


def _chunk(content="body text", index=0):
    return _tool_mod.Chunk(
        index=index,
        content=content,
        token_estimate=500,
        source_type="pdf",
        page_start=1,
        page_end=10,
    )


def _query_hints_calls():
    return [
        node for node in ast.walk(ast.parse(_SOURCE))
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "QueryHints"
    ]


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------


class TestBudgetHelper:
    def test_budget_is_content_plus_the_declared_reserve(self):
        for level in ("low", "medium", "high"):
            assert _tool_mod._budget("heavy", level, 1000) == (
                1000 + thinking_reserve_tokens(level)
            )

    def test_budget_never_exceeds_the_tier_cap(self):
        cap = max_output_tokens_for_tier("heavy")
        assert _tool_mod._budget("heavy", "high", 10_000_000) == cap

    def test_reserve_figures_are_read_not_restated(self):
        """A copied constant drifts from the manifest silently. This is the
        defect removed from the PDF page limits on 2026-09-14."""
        for figure in ("4096", "16384", "32768", "65536"):
            assert figure not in _SOURCE, (
                f"{figure} looks like a restated provider figure; "
                f"framework/llm/providers/<id>.json owns those"
            )


class TestBudgetFollowsTheServingProvider:
    """The figures come from the LLM handle, which knows the operator's
    provider. They used to be read from the default provider's manifest, so a
    run on OpenAI was sized with Gemini's cap."""

    @dataclass
    class _Scoped:
        limits: Any
        asked: list = field(default_factory=list)

        def output_limits(self, tier=None, thinking_level=None):
            self.asked.append((tier, thinking_level))
            return self.limits

    def test_the_handles_figures_are_used(self):
        from framework.llm.providers import OutputLimits

        # A cap above the default provider's: only the handle can supply it.
        handle = self._Scoped(OutputLimits(200_000, 10))
        assert max_output_tokens_for_tier("heavy") < 100_010
        assert _tool_mod._budget("heavy", "high", 100_000, handle) == 100_010
        assert handle.asked == [("heavy", "high")]

    def test_a_handle_that_cannot_answer_gets_the_default_figures(self):
        class _Broken:
            def output_limits(self, tier=None, thinking_level=None):
                raise RuntimeError("no")

        for handle in (None, _Broken(), self._Scoped(limits="not limits")):
            assert _tool_mod._budget("heavy", "low", 1000, handle) == (
                1000 + thinking_reserve_tokens("low")
            )

    def test_the_native_call_is_sized_by_the_handle(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        from framework.llm.providers import OutputLimits

        class _ScopedRecording(_RecordingLLM):
            def output_limits(self, tier=None, thinking_level=None):
                return OutputLimits(200_000, 7)

        pdf = tmp_path / "r.pdf"
        pdf.write_bytes(b"%PDF-fake")
        monkeypatch.setattr(tool_instance, "_resolve_report_path", lambda *a, **k: pdf)
        monkeypatch.setattr(tool_instance, "_get_generated_path", lambda ctx: tmp_path)
        llm = _ScopedRecording()
        tool_instance.execute(
            {"action": "summarize", "report_path": "v/r.pdf", "max_words": 2000},
            _Context(llm_query=llm),
        )
        assert llm.doc_calls[0]["max_tokens"] == 2000 * 8 + 7


# ---------------------------------------------------------------------------
# Budget and level cannot drift apart
# ---------------------------------------------------------------------------


class TestEveryCallSiteNamesItsLevel:
    """A budget sized for one level and a call made at another is the defect:
    a bare needs_reasoning=True resolves to "high" inside the client
    (gemini.py:71-72) while the budget was sized for the provider default."""

    def test_no_query_hints_omits_thinking_level(self):
        built = _query_hints_calls()
        assert built, "expected the plugin to build QueryHints"
        for node in built:
            names = {kw.arg for kw in node.keywords}
            assert "thinking_level" in names, (
                f"QueryHints at line {node.lineno} names no thinking_level, so "
                f"the depth it runs at is decided downstream and invisibly"
            )

    def test_no_call_site_relies_on_bare_needs_reasoning(self):
        for node in _query_hints_calls():
            names = {kw.arg for kw in node.keywords}
            if "needs_reasoning" in names:
                assert "thinking_level" in names, (
                    f"line {node.lineno}: needs_reasoning without an explicit "
                    f"level hides a promotion to high from the budget"
                )


# ---------------------------------------------------------------------------
# The native whole-PDF call and its operator override
# ---------------------------------------------------------------------------


def _run_native(tool_instance, tmp_path, monkeypatch):
    pdf = tmp_path / "r.pdf"
    pdf.write_bytes(b"%PDF-fake")
    monkeypatch.setattr(tool_instance, "_resolve_report_path", lambda *a, **k: pdf)
    monkeypatch.setattr(tool_instance, "_get_generated_path", lambda ctx: tmp_path)
    llm = _RecordingLLM()
    tool_instance.execute(
        {"action": "summarize", "report_path": "v/r.pdf", "max_words": 2000},
        _Context(llm_query=llm),
    )
    assert llm.doc_calls, "the native path did not run"
    return llm.doc_calls[0]


class TestNativeCallBudget:
    def test_budget_covers_content_and_the_default_levels_reserve(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        call = _run_native(tool_instance, tmp_path, monkeypatch)
        level = _tool_mod.DEFAULT_NATIVE_THINKING_LEVEL
        assert call["hints"].thinking_level == level
        assert call["max_tokens"] >= 2000 * 8 + thinking_reserve_tokens(level)
        assert call["max_tokens"] <= max_output_tokens_for_tier("heavy")

    def test_the_override_moves_the_level_and_the_budget_together(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv(_tool_mod.NATIVE_THINKING_ENV_OVERRIDE, "high")
        call = _run_native(tool_instance, tmp_path, monkeypatch)
        assert call["hints"].thinking_level == "high"
        assert call["max_tokens"] >= 2000 * 8 + thinking_reserve_tokens("high")

    def test_an_unusable_override_falls_back_rather_than_failing(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv(_tool_mod.NATIVE_THINKING_ENV_OVERRIDE, "ludicrous")
        call = _run_native(tool_instance, tmp_path, monkeypatch)
        assert call["hints"].thinking_level == _tool_mod.DEFAULT_NATIVE_THINKING_LEVEL

    def test_the_level_is_pinned_not_inherited_from_a_vendor(self):
        """gcp_gemini declares medium and anthropic high. A call naming no
        level gets a different depth per vendor for identical work, and the
        budget stays sized for whichever default was assumed."""
        from framework.llm.providers import load_provider_manifest

        declared = {
            (load_provider_manifest(pid) or {})
            .get("output_budget", {})
            .get("default_thinking_level")
            for pid in ("gcp_gemini", "anthropic")
        }
        assert len(declared) > 1, (
            "the vendor defaults now agree, which makes this test stale but "
            "does not make inheriting them correct"
        )
        assert _tool_mod.DEFAULT_NATIVE_THINKING_LEVEL in _tool_mod.NATIVE_THINKING_LEVELS

    def test_the_offered_levels_are_accepted_by_every_provider(self):
        """"minimal" is declared only by gcp_gemini and is a 400 elsewhere, so
        offering it in the override would hand the operator a broken setting."""
        from framework.llm.providers import accepted_thinking_levels

        for pid in ("gcp_gemini", "anthropic", "openai"):
            accepted = accepted_thinking_levels("heavy", pid)
            for level in _tool_mod.NATIVE_THINKING_LEVELS:
                assert level in accepted, f"{level} not accepted by {pid}"


# ---------------------------------------------------------------------------
# The section and synthesis calls
# ---------------------------------------------------------------------------


class TestChunkAndSynthesisBudgets:
    def test_section_summary_covers_its_content_plus_low_reserve(self, tool_instance):
        llm = _RecordingLLM()
        tool_instance._summarize_chunk(
            _chunk(), "r.pdf", "vendor", [], _Context(llm_query=llm),
        )
        call = llm.text_calls[0]
        assert call["hints"].thinking_level == "low"
        assert call["max_tokens"] >= 3072 + thinking_reserve_tokens("low")

    def test_single_pass_covers_its_word_target_plus_low_reserve(self, tool_instance):
        llm = _RecordingLLM()
        tool_instance._summarize_chunk(
            _chunk(), "r.pdf", "vendor", [], _Context(llm_query=llm), max_words=2000,
        )
        call = llm.text_calls[0]
        assert call["hints"].thinking_level == "low"
        assert call["max_tokens"] >= 2000 * 8 + thinking_reserve_tokens("low")

    def test_synthesis_covers_its_word_target_plus_high_reserve(self, tool_instance):
        llm = _RecordingLLM()
        tool_instance._synthesize_summaries(
            [{"chunk_index": 0, "page_start": 1, "page_end": 10, "summary": "s"}],
            "r.pdf", [], 2000, _Context(llm_query=llm),
        )
        call = llm.text_calls[0]
        assert call["hints"].thinking_level == "high"
        assert call["max_tokens"] >= 2000 * 8 + thinking_reserve_tokens("high")


class TestNoCallIsSizedBelowItsOwnReserve:
    """Stage 1.1's acceptance condition, stated once over every call site."""

    def test_every_recorded_call(self, tool_instance, tmp_path, monkeypatch):
        llm = _RecordingLLM()
        pdf = tmp_path / "r.pdf"
        pdf.write_bytes(b"%PDF-fake")
        monkeypatch.setattr(tool_instance, "_resolve_report_path", lambda *a, **k: pdf)
        monkeypatch.setattr(tool_instance, "_get_generated_path", lambda ctx: tmp_path)
        tool_instance.execute(
            {"action": "summarize", "report_path": "v/r.pdf", "max_words": 2000},
            _Context(llm_query=llm),
        )
        tool_instance._summarize_chunk(
            _chunk(), "r.pdf", "vendor", [], _Context(llm_query=llm),
        )
        tool_instance._synthesize_summaries(
            [{"chunk_index": 0, "page_start": 1, "page_end": 10, "summary": "s"}],
            "r.pdf", [], 2000, _Context(llm_query=llm),
        )
        recorded = llm.doc_calls + llm.text_calls
        assert recorded
        for call in recorded:
            level = call["hints"].thinking_level
            assert call["max_tokens"] > thinking_reserve_tokens(level), (
                f"a {call['max_tokens']}-token budget at level {level!r} sits "
                f"entirely inside the thinking reserve, so content can be "
                f"starved to empty text with ok=True"
            )
