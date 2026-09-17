"""A candidate must be asked about beside the text it was found in.

The chunked path used to make two independent splits and pair them by index:
`ioc_batches` sliced `fallback_iocs` fifty at a time, `text_chunks` split
`fallback_text` on paragraph boundaries, and chunk *i* sent `ioc_batches[i]`
with `text_chunks[i]`. The two orderings have no relationship at all.

On the whole-document path the candidate order is type-major - the regex pass
loops `for ioc_type in ioc_types` - so the first batch was in practice every
IP in the document, appendix included, sent beside the document's first 6,000
characters. The model was asked to judge an indicator against text that never
mentioned it.

The fix builds text units first and takes each unit's candidates from that
unit's pages, so the pairing is true by construction. The property these tests
hold is exactly that: **every candidate in a prompt appears in that prompt's
text.** 2.0's `candidates_not_submitted == 0` is the other half - the rewrite
must not lose coverage while it gains alignment.
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
    _name = "threat_intel_ingester_tool_alignment"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()
IOC_TYPES = ["ip", "domain", "hash_sha256", "cve"]


def _pages(specs):
    """Build page texts from (page_number -> sentence) specs."""
    return [text for text in specs]


def _units(page_texts, **kw):
    page_iocs = _tool_mod._page_iocs(page_texts, IOC_TYPES)
    return _tool_mod._build_chunk_units(page_texts, page_iocs, IOC_TYPES, **kw)


# ---------------------------------------------------------------------------
# The property
# ---------------------------------------------------------------------------


class TestEveryCandidateIsInItsOwnPrompt:
    def test_the_plan_s_property_on_a_paged_report(self):
        """The plan's test: every candidate in a chunk's prompt must have its
        source page inside that chunk's page range."""
        page_texts = [
            f"Page {n}: beaconing to 198.51.100.{n} over 443. " + ("x " * 1800)
            for n in range(1, 8)
        ]
        units = _units(page_texts)
        assert len(units) > 1, "the fixture must actually split"
        for unit in units:
            for ioc in unit.iocs:
                assert ioc.value in unit.text, (
                    f"{ioc.value} was sent with text that does not contain it"
                )

    def test_an_appendix_indicator_is_not_paired_with_the_introduction(self):
        """The concrete shape of the defect: type-major candidate order put
        every IP in one batch, and that batch went out beside the opening
        pages. Here the appendix IP must travel with the appendix."""
        intro = "Introduction. The actor phished staff. " + ("narrative " * 700)
        middle = "Execution used powershell. " + ("narrative " * 700)
        appendix = "Appendix A indicators: 203.0.113.99 and evil.example.com."
        units = _units([intro, middle, appendix])
        holders = [u for u in units if any(
            i.value == "203.0.113.99" for i in u.iocs
        )]
        assert len(holders) == 1
        assert "Appendix A" in holders[0].text
        assert "Introduction" not in holders[0].text

    def test_a_single_page_bigger_than_the_budget_still_aligns(self):
        """A text artifact is one page, so page granularity buys nothing and
        the split has to happen inside the page with candidates re-extracted
        per piece. This is the path every non-PDF report takes."""
        body = (
            "First section mentions 198.51.100.1. " + ("filler " * 1200)
            + "\n\nSecond section mentions 203.0.113.2. " + ("filler " * 1200)
        )
        units = _units([body], paged=False)
        assert len(units) > 1
        for unit in units:
            for ioc in unit.iocs:
                assert ioc.value in unit.text

    def test_a_candidate_is_asked_about_once(self):
        """The operator's choice: global dedupe, so cost does not move. A value
        on two pages is submitted with the first unit whose text holds it."""
        page_texts = [
            "Page one names 198.51.100.7. " + ("x " * 1800),
            "Page two names 198.51.100.7 again. " + ("x " * 1800),
        ]
        units = _units(page_texts)
        holders = [u for u in units if any(
            i.value == "198.51.100.7" for i in u.iocs
        )]
        assert len(holders) == 1, "asked about once"
        assert "Page one" in holders[0].text, "in a unit that contains it"


class TestTheCapSplitsWithinTheUnit:
    def test_a_crowded_unit_keeps_its_text_on_every_piece(self):
        """`_MAX_IOC_PER_CHUNK` used to be applied to a flat candidate list, so
        the overflow batch was paired with whatever text chunk shared its
        index - or, past the end, with no text at all."""
        page = "Indicators: " + " ".join(
            f"198.51.100.{n}" for n in range(1, 121)
        )
        units = _units([page], max_iocs=50)
        assert len(units) == 3, "120 candidates at 50 per call"
        assert len({u.text for u in units}) == 1, "all three carry the text"
        for unit in units:
            for ioc in unit.iocs:
                assert ioc.value in unit.text

    def test_no_candidate_is_lost_to_the_cap(self):
        page = "Indicators: " + " ".join(
            f"198.51.100.{n}" for n in range(1, 121)
        )
        units = _units([page], max_iocs=50)
        submitted = {i.value for u in units for i in u.iocs}
        assert len(submitted) == 120


class TestPageLabelsAndGaps:
    def test_a_unit_carries_its_page_label(self):
        page_texts = [f"Page {n} text. " + ("x " * 1800) for n in (1, 2, 3)]
        units = _units(page_texts)
        text = _tool_mod._unit_report_text(units[0])
        assert text.startswith("[Report page")

    def test_a_non_paged_artifact_gets_no_page_label(self):
        """A text file is not page one of anything; labelling it that way
        would be a measurement nobody made."""
        units = _units(["Some report text with 198.51.100.1."], paged=False)
        assert units[0].page_label is None
        assert _tool_mod._unit_report_text(units[0]) == units[0].text

    def test_a_gap_between_page_runs_is_stated(self):
        """On the native-failure path the chunked units cover only the pages
        the native path could not finish, so consecutive units can jump. Left
        unmarked, a section starting at page 6 reads as continuing one that
        ended at page 2."""
        page_texts = [f"Page {n} text. " + ("x " * 1800) for n in range(1, 8)]
        units = _units(page_texts, pages=[1, 2, 6, 7])
        gapped = [u for u in units if u.gap_before]
        assert gapped, "the jump from 2 to 6 must be marked"
        assert gapped[0].gap_pages == (3, 5)
        assert "not shown here" in _tool_mod._unit_report_text(gapped[0])

    def test_contiguous_pages_report_no_gap(self):
        page_texts = [f"Page {n} text. " + ("x " * 1800) for n in range(1, 8)]
        units = _units(page_texts, pages=[1, 2, 3, 4])
        assert not any(u.gap_before for u in units)

    def test_a_blank_page_is_not_a_gap(self):
        """A blank page is skipped while packing, but it was still covered.
        Calling it a gap would tell the model it was analysed elsewhere, which
        nobody can check and which is not true."""
        page_texts = [
            "Page 1 text. " + ("x " * 1800),
            "",
            "Page 3 text. " + ("x " * 1800),
        ]
        units = _units(page_texts)
        assert not any(u.gap_before for u in units)

    def test_only_the_uncovered_pages_are_named_in_a_gap(self):
        """Page 3 is blank and page 4 was read natively. Only page 4 is the
        gap - and the note must not claim page 3 went somewhere it did not."""
        page_texts = [f"Page {n} text. " + ("x " * 1800) for n in range(1, 7)]
        page_texts[2] = ""
        units = _units(page_texts, pages=[1, 2, 3, 5, 6])
        gapped = [u for u in units if u.gap_before]
        assert gapped
        assert gapped[0].gap_pages == (4, 4)


# ---------------------------------------------------------------------------
# 2.0's tripwire: the rewrite must not lose coverage
# ---------------------------------------------------------------------------


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
    session_id: str = "test_session_alignment"
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


def _prompt_candidates(prompt):
    out = []
    for line in prompt.splitlines():
        if line.startswith("- [") and "] " in line and " | " in line:
            out.append(line.split("] ", 1)[1].split(" |", 1)[0])
    return out


def _prompt_report_text(prompt):
    """The report text as the prompt carries it, for the alignment assertion."""
    marker = "REPORT TEXT"
    idx = prompt.find(marker)
    return prompt[idx:] if idx >= 0 else prompt


class _RecordingLLM:
    """Accepts everything, and keeps each prompt so the pairing can be checked
    on a real run rather than on the builder in isolation."""

    def __init__(self, native=False, fail_pages=()):
        self.prompts: list[str] = []
        self.doc_prompts: list[str] = []
        self.grounding: list = []
        self.native = native
        self.fail_pages = set(fail_pages)

    def supports_native_document(self, mime_type):
        return self.native and mime_type == "application/pdf"

    @staticmethod
    def _body(values):
        return json.dumps({
            "refined_iocs": [
                {"value": v, "ioc_type": "ip", "confidence": "high",
                 "priority": "medium", "context": "c2", "related_mitre": [],
                 "is_false_positive": False}
                for v in values
            ],
            "additional_mitre_techniques": [],
            "report_metadata": {"title": "T"},
            "attack_graph": {"paths": [], "convergence_points": [],
                             "branch_points": []},
        })

    def query_with_document(self, prompt, artifact, system_context=None,
                            max_tokens=8192, grounding_data=None, hints=None):
        label = str((artifact.metadata or {}).get("page_range", "whole"))
        self.doc_prompts.append(prompt)
        self.grounding.append(grounding_data)
        if any(f"p{p}" == label or label == "whole" and self.fail_pages
               for p in self.fail_pages):
            return _Resp(ok=False, error="forced failure")
        return _Resp(text=self._body(_prompt_candidates(prompt)))

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.prompts.append(prompt)
        self.grounding.append(grounding_data)
        return _Resp(text=self._body(_prompt_candidates(prompt)))


@pytest.fixture
def run_text_report(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))

    def go(body, llm=None):
        report = tmp_path / "report.txt"
        report.write_text(body, encoding="utf-8")
        artifact = MockArtifactRef(
            artifact_id="art_txt", artifact_type="text", file_path=str(report),
        )
        ctx = MockExecutionContext(
            artifacts=[artifact], llm_enabled=True,
            llm_query=llm or _RecordingLLM(),
            register_artifact=lambda artifact_type, file_path, source_tool,
            metadata: MockArtifactRef("out", artifact_type, file_path),
        )
        result = _tool_mod.ThreatIntelIngester().execute(
            {"artifact_id": "art_txt"}, ctx,
        )
        assert result.ok, result.message
        return result, ctx.llm_query

    return go


@pytest.fixture
def run_pdf_report(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))

    def fake_split(path, ranges, out_dir, stem=None):
        out = []
        for a, b in ranges:
            f = Path(out_dir) / f"{stem}_p{a}-{b}.pdf"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b"%PDF-fake")
            out.append(f)
        return out

    monkeypatch.setattr(_tool_mod, "split_pdf", fake_split)

    def go(page_texts, llm):
        monkeypatch.setattr(
            _tool_mod, "extract_pdf_page_texts",
            lambda path, max_pages=50: page_texts[:max_pages],
        )
        pdf = tmp_path / "report.pdf"
        pdf.write_bytes(b"%PDF-fake")
        artifact = MockArtifactRef(
            artifact_id="art_pdf", artifact_type="pdf_report",
            file_path=str(pdf),
        )
        ctx = MockExecutionContext(
            artifacts=[artifact], llm_enabled=True, llm_query=llm,
            register_artifact=lambda artifact_type, file_path, source_tool,
            metadata: MockArtifactRef("out", artifact_type, file_path),
        )
        result = _tool_mod.ThreatIntelIngester().execute(
            {"artifact_id": "art_pdf"}, ctx,
        )
        assert result.ok, result.message
        return result

    return go


LONG_PAGES = [
    f"Page {n}. Beaconing to 198.51.100.{n} over 443. " + ("narrative " * 700)
    for n in range(1, 6)
]


class TestNothingIsLeftUnsubmitted:
    """2.0's invariant, kept as the tripwire for exactly this rewrite. If 2.5
    breaks page coverage these are what say so."""

    def test_pure_chunked_run(self, run_text_report):
        body = "\n\n".join(LONG_PAGES)
        result, llm = run_text_report(body)
        assert len(llm.prompts) > 1, "the fixture must split"
        assert result.result["summary"]["candidates_not_submitted"] == 0

    def test_a_short_single_chunk_run(self, run_text_report):
        result, llm = run_text_report(
            "Short report naming 198.51.100.1 and evil.example.com.",
        )
        assert result.result["summary"]["candidates_not_submitted"] == 0

    def test_a_crowded_run_where_the_cap_splits_a_unit(self, run_text_report):
        body = "Indicators: " + " ".join(
            f"198.51.100.{n}" for n in range(1, 121)
        )
        result, llm = run_text_report(body)
        assert len(llm.prompts) >= 3
        assert result.result["summary"]["candidates_not_submitted"] == 0

    def test_a_chunked_pdf_run(self, run_pdf_report):
        llm = _RecordingLLM(native=False)
        result = run_pdf_report(LONG_PAGES, llm)
        assert len(llm.prompts) > 1
        assert result.result["summary"]["candidates_not_submitted"] == 0

    def test_every_prompt_pairs_its_candidates_with_its_own_text(
        self, run_text_report,
    ):
        """The property, asserted on a real run rather than on the builder -
        the merge tests in Stage 2 were twice caught passing on a helper while
        the path that called it was broken."""
        body = "\n\n".join(LONG_PAGES)
        _, llm = run_text_report(body)
        assert len(llm.prompts) > 1
        for prompt in llm.prompts:
            text = _prompt_report_text(prompt)
            for value in _prompt_candidates(prompt):
                assert value in text, (
                    f"{value} was submitted with text that does not contain it"
                )


class TestThePromptCarriesThePageLabel:
    def test_a_chunked_pdf_prompt_names_its_pages(self, run_pdf_report):
        """Asserted on the prompt the run actually sent, not on the formatter:
        a page label the assembly never reaches the prompt with is a label the
        model cannot cite."""
        llm = _RecordingLLM(native=False)
        run_pdf_report(LONG_PAGES, llm)
        assert len(llm.prompts) > 1
        assert all("[Report page" in p for p in llm.prompts)

    def test_a_text_prompt_carries_no_page_label(self, run_text_report):
        body = "\n\n".join(LONG_PAGES)
        _, llm = run_text_report(body)
        assert not any("[Report page" in p for p in llm.prompts)

    def test_the_chunk_label_records_the_pages_it_read(self, run_pdf_report):
        """Which feeds every occurrence recorded against that chunk. Before
        2.5 a chunk had no page range at all, so an indicator found on the
        chunked path could only say which chunk saw it."""
        llm = _RecordingLLM(native=False)
        result = run_pdf_report(LONG_PAGES, llm)
        labels = [
            o["batch_label"]
            for ioc in result.result["iocs"]
            for o in ioc.get("occurrences", [])
        ]
        assert labels, "the run must produce occurrences"
        assert any("page" in (label or "") for label in labels)

    def test_an_occurrence_from_a_chunk_carries_its_page_range(
        self, run_pdf_report,
    ):
        """The label is prose; the page range is the field a consumer reads.
        Both have to be there, and a label built from the unit says nothing
        about whether the range reached the provenance record."""
        llm = _RecordingLLM(native=False)
        result = run_pdf_report(LONG_PAGES, llm)
        occs = [
            o for ioc in result.result["iocs"]
            for o in ioc.get("occurrences", [])
        ]
        assert occs, "the run must produce occurrences"
        assert all(o["page_start"] is not None for o in occs), (
            "a chunked occurrence with no page range cannot say where in the "
            "report the indicator was seen"
        )
        for ioc in result.result["iocs"]:
            page = int(ioc["value"].rsplit(".", 1)[1])
            first = ioc["occurrences"][0]
            assert first["page_start"] <= page <= first["page_end"], (
                f"{ioc['value']} is on page {page}, recorded against pages "
                f"{first['page_start']}-{first['page_end']}"
            )


class TestThePromptsAreGrounded:
    """Found 2026-09-16: the grounding check read a reference_data key that
    nothing writes.

    `context.reference_data.get("mitre_attack_enterprise")` - the shell
    supplies `mitre_techniques` and `mitre_relationships`, and that key is read
    in one place and written in none. So `grounding` was always empty and every
    prompt went out with no ATT&CK anchor, on both the native and chunked
    paths. The reconciler downstream was doing the entire job.
    """

    @staticmethod
    def _anchor(grounding):
        """The plugin's contract is to *pass* grounding_data; the dispatcher
        composes it into the prompt (`compose_prompt`), so a stub client never
        sees it in the prompt text. Assert where the plugin's job ends."""
        return " ".join(grounding or [])

    def test_the_chunked_call_names_the_release(self, run_text_report):
        from framework.reference_data import mitre_attack
        body = "\n\n".join(LONG_PAGES)
        _, llm = run_text_report(body)
        assert llm.grounding, "no call was made"
        for g in llm.grounding:
            assert mitre_attack.attack_version() in self._anchor(g), (
                "the call carries no ATT&CK release"
            )

    def test_the_call_rules_out_the_retired_tactic(self, run_text_report):
        """The concrete cost of no grounding: the model writes v14-era tactic
        names and the reconciler has to correct them afterwards. The live run
        needed four corrections and two analyst flags."""
        body = "\n\n".join(LONG_PAGES)
        _, llm = run_text_report(body)
        assert llm.grounding
        for g in llm.grounding:
            anchor = self._anchor(g)
            assert "Defense Evasion" in anchor
            assert "Stealth" in anchor

    def test_the_native_path_is_grounded_too(self, run_pdf_report):
        """The path a real report takes, and the one the 154-page run used."""
        from framework.reference_data import mitre_attack
        llm = _RecordingLLM(native=True)
        run_pdf_report(LONG_PAGES, llm)
        assert llm.doc_prompts, "the native path must have been taken"
        assert llm.grounding
        for g in llm.grounding:
            assert mitre_attack.attack_version() in self._anchor(g)


class TestTheChunkedPathIsNotSupersededByItself:
    def test_a_truncated_chunk_stands(self):
        """2.5 gave chunk results a page range. Supersession is page-range
        containment, and `chunked_pages` holds those same pages - so without a
        guard a truncated chunk would be read as replaced by itself and stop
        supplying canonical values."""
        prov = [{
            "label": "chunk 1/2 (pages 1-2)", "attempt_id": 1,
            "source": "chunked", "page_start": 1, "page_end": 2,
            "truncated": True, "superseded_by": None,
        }]
        marked = _tool_mod._mark_superseded(prov, {1, 2})
        assert marked == 0
        assert prov[0]["superseded_by"] is None

    def test_a_native_partial_is_still_superseded_by_the_chunked_re_read(self):
        """The case the guard must not break: a truncated native batch that
        could not be bisected hands its pages to the chunked path."""
        prov = [{
            "label": "p1-4", "attempt_id": 1, "page_start": 1, "page_end": 4,
            "truncated": True, "superseded_by": None,
        }]
        marked = _tool_mod._mark_superseded(prov, {1, 2, 3, 4})
        assert marked == 1
        assert prov[0]["superseded_by"]
