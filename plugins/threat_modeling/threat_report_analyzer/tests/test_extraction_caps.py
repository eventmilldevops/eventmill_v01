"""A cap is defensible; a silent cap is not, and a random one is not at all.

`_extract_key_findings` returned `findings[:10]` and `_extract_techniques`
returned `list(set(techniques))[:20]`. Both dropped in silence - nothing
counted the remainder and no note reached `analysis_status` - and the second
was worse than lossy: `set` has no ordering, so *which* twenty ids survived
varied between identical runs over identical text. It is the one place in
either report tool where two runs disagreed about what the report said.

The technique cap also applied twice: once per chunk inside `_summarize_chunk`
and again on the cross-chunk union, which was `list({...})` as well. A
16-batch report could lose techniques at both levels, unreproducibly, and
`relevant_techniques` is what a reader takes as "the techniques this report
covers".

Now both are order-stable by first appearance, both are counted, and anything
dropped reaches the result as a note.
"""

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool_caps"
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
    t._last_pdf_pages = None
    t._dropped = {}
    return t


def _technique_summary(n, start=1000):
    return "Summary. " + " ".join(f"T{start + i}" for i in range(n))


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


class TestTechniqueOrderIsStable:
    def test_the_plan_s_case_repeats_identically(self, tool):
        """The plan's test: a summary naming 25 techniques must yield a stable
        ordering across repeated calls."""
        summary = _technique_summary(25)
        runs = [
            _tool_mod.ThreatReportAnalyzer()._extract_techniques(summary)
            for _ in range(8)
        ]
        assert all(r == runs[0] for r in runs), (
            "identical text produced different technique lists"
        )
        assert len(runs[0]) == 25, "25 is well under the limit and none is cut"

    def test_the_order_is_first_appearance(self, tool):
        ids = tool._extract_techniques(
            "T1566 then T1059 then T1566 again then T1021."
        )
        assert ids == ["T1566", "T1059", "T1021"]

    def test_repeats_are_deduplicated(self, tool):
        ids = tool._extract_techniques("T1059 T1059 T1059")
        assert ids == ["T1059"]

    def test_which_ids_survive_the_cap_is_deterministic(self, tool, monkeypatch):
        """The part `set` made unreproducible: not just the order of the list,
        but its membership once the cap bites."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        summary = _technique_summary(25)
        runs = [
            _tool_mod.ThreatReportAnalyzer()._extract_techniques(summary)
            for _ in range(8)
        ]
        assert all(r == runs[0] for r in runs)
        assert len(runs[0]) == 20
        assert runs[0][0] == "T1000", "the first twenty named, not an arbitrary twenty"


class TestFindingOrderIsStable:
    def test_findings_keep_document_order(self, tool):
        summary = "\n".join(f"- Finding number {i} of some length" for i in range(5))
        assert tool._extract_key_findings(summary) == [
            f"Finding number {i} of some length" for i in range(5)
        ]


# ---------------------------------------------------------------------------
# What is dropped is counted and said
# ---------------------------------------------------------------------------


class TestDroppingIsReported:
    def test_five_dropped_techniques_are_stated(self, tool, monkeypatch):
        """The plan's test: the result must state that five were dropped."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        tool._extract_techniques(_technique_summary(25))
        fields = tool._analysis_fields()
        assert fields["analysis_status"] == "partial"
        note = [n for n in fields["analysis_notes"] if n.startswith("LIST TRUNCATED")]
        assert len(note) == 1
        assert "5 technique(s)" in note[0]

    def test_dropped_findings_are_stated(self, tool, monkeypatch):
        monkeypatch.setattr(_tool_mod, "_MAX_KEY_FINDINGS", 3)
        summary = "\n".join(f"- Finding number {i} of some length" for i in range(7))
        assert len(tool._extract_key_findings(summary)) == 3
        notes = tool._analysis_fields()["analysis_notes"]
        assert any("4 key finding(s)" in n for n in notes)

    def test_nothing_dropped_says_nothing(self, tool):
        tool._extract_techniques(_technique_summary(25))
        tool._extract_key_findings(
            "\n".join(f"- Finding number {i} of some length" for i in range(7))
        )
        fields = tool._analysis_fields()
        assert fields["analysis_status"] == "complete"
        assert fields["analysis_notes"] == []

    def test_the_cap_counts_across_both_levels(self, tool, monkeypatch):
        """The per-chunk cap is not the only one a long report meets - the
        cross-chunk union is capped too, so drops accumulate."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        tool._extract_techniques(_technique_summary(25, start=1000))
        tool._extract_techniques(_technique_summary(23, start=2000))
        notes = tool._analysis_fields()["analysis_notes"]
        assert any("8 technique(s)" in n for n in notes), notes

    def test_the_raised_limits_do_not_fire_on_an_ordinary_report(self, tool):
        """Operator decision, 2026-09-15: keep a bound, set it where a real
        report does not reach it. 10 and 20 fired routinely; 50 and 200 are
        there for a runaway summary, not for ordinary work."""
        assert _tool_mod._MAX_KEY_FINDINGS == 50
        assert _tool_mod._MAX_RELEVANT_TECHNIQUES == 200
        tool._extract_techniques(_technique_summary(60))
        tool._extract_key_findings(
            "\n".join(f"- Finding number {i} of some length" for i in range(40))
        )
        assert tool._dropped == {}


# ---------------------------------------------------------------------------
# Through a real run
# ---------------------------------------------------------------------------
#
# The extractors are helpers. Whether the run's result carries what they found
# is a separate question, and Stage 2 has twice been caught by a mutation
# check that only exercised a helper.


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    model_used: str = "fake-model"
    transport_path: str = "inline_bytes"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class _LLM:
    body: str = "Summary body."

    def supports_native_document(self, mime_type: str) -> bool:
        return False

    def query_with_document(self, prompt, artifact, **kwargs):
        return _Resp(text=self.body)

    def query_text(self, prompt, **kwargs):
        return _Resp(text=self.body)


@dataclass
class _Context:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)


@pytest.fixture
def run_report(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)

    def go(body, report_text="A short threat report about an intrusion.",
           tool=None, chunk_tokens=None, **payload):
        report = vault / "report.txt"
        report.write_text(report_text, encoding="utf-8")
        tool = tool or _tool_mod.ThreatReportAnalyzer()
        if chunk_tokens:
            tool.MAX_TOKENS_PER_CHUNK = chunk_tokens
        result = tool._summarize_report(
            {"report_path": str(report), **payload},
            _Context(llm_query=_LLM(body=body)),
        )
        assert result.ok, result.message
        return tool, result

    return go


def _long_report(paragraphs=6, words=200):
    return "\n\n".join(
        f"Section {i}. " + ("narrative " * words) for i in range(paragraphs)
    )


class TestTheRunReportsItsOwnCap:
    def test_a_capped_run_says_so_in_its_result(self, run_report, monkeypatch):
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        _, result = run_report(_technique_summary(25))
        summary = result.result["summaries"][0]
        assert summary["analysis_status"] == "partial"
        assert any(
            n.startswith("LIST TRUNCATED") for n in summary["analysis_notes"]
        ), summary["analysis_notes"]

    def test_the_capped_list_is_what_the_result_carries(
        self, run_report, monkeypatch,
    ):
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        _, result = run_report(_technique_summary(25))
        techniques = result.result["summaries"][0]["relevant_techniques"]
        assert len(techniques) == 20
        assert techniques[0] == "T1000"

    def test_an_uncapped_run_is_complete(self, run_report):
        _, result = run_report(_technique_summary(25))
        summary = result.result["summaries"][0]
        assert len(summary["relevant_techniques"]) == 25
        assert summary["analysis_status"] == "complete"

    def test_two_identical_runs_agree(self, run_report, monkeypatch):
        """The property the nondeterministic cap broke, asserted end to end."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        body = _technique_summary(25)
        first = run_report(body)[1].result["summaries"][0]["relevant_techniques"]
        second = run_report(body)[1].result["summaries"][0]["relevant_techniques"]
        assert first == second

    def test_the_dropped_count_resets_between_runs(self, run_report, monkeypatch):
        """Run state, not instance state. The same tool object summarises many
        reports in a session, and a count left over from a previous one would
        put its note on this one - the shape `_truncations` and `_degradations`
        are already reset for."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        tool, _ = run_report(_technique_summary(25))
        assert tool._dropped == {"technique": 5}
        _, result = run_report("Summary with no techniques at all.", tool=tool)
        assert tool._dropped == {}
        assert result.result["summaries"][0]["analysis_status"] == "complete"


class TestIgnoreCaps:
    """Added 2026-09-15 after a live run cut seven key findings.

    A reported cap is still a cap. "Key findings" is read as the findings that
    matter, and being told seven were left out says neither which seven nor how
    to get them back. Both lists are extracted from a summary the model already
    produced - no extra call, no extra tokens - so an operator who wants all of
    them can have all of them.
    """

    def test_nothing_is_dropped_when_the_bounds_are_waived(
        self, run_report, monkeypatch,
    ):
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        tool, result = run_report(_technique_summary(25), ignore_caps=True)
        summary = result.result["summaries"][0]
        assert len(summary["relevant_techniques"]) == 25
        assert tool._dropped == {}

    def test_key_findings_survive_in_full(self, run_report, monkeypatch):
        """The case the operator hit: 57 findings, 7 cut."""
        monkeypatch.setattr(_tool_mod, "_MAX_KEY_FINDINGS", 50)
        body = "\n".join(
            f"- Finding number {i} of some length" for i in range(57)
        )
        _, capped = run_report(body)
        assert len(capped.result["summaries"][0]["key_findings"]) == 50
        _, whole = run_report(body, ignore_caps=True)
        assert len(whole.result["summaries"][0]["key_findings"]) == 57

    def test_a_waived_run_is_complete_not_partial(self, run_report, monkeypatch):
        """Nothing was left out, so there is nothing to caveat. The LIST
        TRUNCATED note must not fire."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        _, result = run_report(_technique_summary(25), ignore_caps=True)
        summary = result.result["summaries"][0]
        assert summary["analysis_status"] == "complete"
        assert not any(
            n.startswith("LIST TRUNCATED") for n in summary["analysis_notes"]
        )

    def test_the_result_says_which_run_it_was(self, run_report, monkeypatch):
        """Two runs of one report returning lists of different lengths is
        correct here, so the result has to carry which one produced it."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        _, waived = run_report(_technique_summary(25), ignore_caps=True)
        _, bounded = run_report(_technique_summary(25))
        assert waived.result["summaries"][0]["caps_waived"] is True
        assert bounded.result["summaries"][0]["caps_waived"] is False

    def test_the_export_header_states_it(self, run_report, monkeypatch):
        """The file outlives the session, and a list's length means nothing
        without knowing whether anything was allowed to bound it."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        tool, _ = run_report(_technique_summary(25), ignore_caps=True)
        assert "ignore_caps" in tool._provenance_block("v/r.pdf", "stamp")

    def test_a_bounded_run_says_nothing_about_bounds(
        self, run_report, monkeypatch,
    ):
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        tool, _ = run_report(_technique_summary(25))
        assert "ignore_caps" not in tool._provenance_block("v/r.pdf", "stamp")

    def test_the_setting_does_not_leak_into_the_next_run(
        self, run_report, monkeypatch,
    ):
        """Run state, like _dropped. One tool object summarises many reports."""
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        tool, _ = run_report(_technique_summary(25), ignore_caps=True)
        _, result = run_report(_technique_summary(25), tool=tool)
        summary = result.result["summaries"][0]
        assert summary["caps_waived"] is False
        assert len(summary["relevant_techniques"]) == 20

    def test_it_is_off_by_default(self, run_report, monkeypatch):
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", 20)
        _, result = run_report(_technique_summary(25))
        assert len(result.result["summaries"][0]["relevant_techniques"]) == 20

    def test_the_flag_is_declared_in_the_input_schema(self):
        """The CLI types --flags from this schema, and a bare --ignore_caps
        only arrives as a boolean because the schema says it is one."""
        import json
        schema = json.loads(
            (PLUGIN_DIR / "schemas" / "input.schema.json").read_text(
                encoding="utf-8"
            )
        )
        spec = schema["properties"]["ignore_caps"]
        assert spec["type"] == "boolean"
        assert spec["default"] is False


class TestTheCrossChunkUnionIsCappedToo:
    """The per-chunk cap is not the only one a long report meets. The union
    that follows it was `list({...})` as well, so a 16-batch report could lose
    techniques at both levels, unreproducibly."""

    def _run(self, run_report, monkeypatch, limit=20, n=25):
        monkeypatch.setattr(_tool_mod, "_MAX_RELEVANT_TECHNIQUES", limit)
        return run_report(
            _technique_summary(n),
            report_text=_long_report(),
            chunk_tokens=200,
        )

    def test_the_run_really_uses_several_chunks(self, run_report, monkeypatch):
        _, result = self._run(run_report, monkeypatch)
        assert result.result["summaries"][0]["chunk_count"] > 1

    def test_the_union_keeps_first_appearance_order(self, run_report, monkeypatch):
        _, result = self._run(run_report, monkeypatch)
        techniques = result.result["summaries"][0]["relevant_techniques"]
        assert techniques == [f"T{1000 + i}" for i in range(20)]

    def test_two_identical_multi_chunk_runs_agree(self, run_report, monkeypatch):
        first = self._run(run_report, monkeypatch)[1]
        second = self._run(run_report, monkeypatch)[1]
        assert (
            first.result["summaries"][0]["relevant_techniques"]
            == second.result["summaries"][0]["relevant_techniques"]
        )

    def test_the_union_reports_what_it_cut(self, run_report, monkeypatch):
        _, result = self._run(run_report, monkeypatch)
        notes = result.result["summaries"][0]["analysis_notes"]
        assert any(n.startswith("LIST TRUNCATED") for n in notes), notes
