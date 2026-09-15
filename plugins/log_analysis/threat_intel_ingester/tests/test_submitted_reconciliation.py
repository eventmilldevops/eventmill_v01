"""The reconciliation is measured against what reached a prompt.

Stage 1.5 compared verdicts against `raw_iocs`, the whole-document regex pass.
Stage 2.0 compares them against a recorded set of the candidates actually
placed into a prompt, and reports what `raw_iocs` held and no prompt carried as
a separate `candidates_not_submitted`.

**The two baselines are equivalent on every run today.** Every `IOC_PATTERNS`
entry is contiguous over non-whitespace, so none can match across the "\n\n"
page join, which makes the per-page union equal to the whole-document pass; and
`plan_ingestion` batches pages contiguously while every failing batch hands its
pages to the chunked path. So this is not a defect fix. It is here because 2.5
rewrites prompt assembly into page units, and a candidate dropped by that
rewrite would otherwise be reported as the model's silence rather than as our
own coverage gap.

The last class is the point of the file: the invariant, as a tripwire for 2.5.
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
    _name = "threat_intel_ingester_tool_submitted"
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
    session_id: str = "test_session_submitted"
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


def _echo_reply(values, label="whole"):
    """A verdict for each value handed in, so nothing is unassessed by luck."""
    return json.dumps({
        "refined_iocs": [
            {"value": v, "ioc_type": "ip", "confidence": "high",
             "priority": "medium", "context": f"seen in {label}",
             "related_mitre": [], "is_false_positive": False}
            for v in values
        ],
        "additional_mitre_techniques": [],
        "report_metadata": {"title": "Report"},
        "attack_graph": {"paths": [], "convergence_points": [],
                         "branch_points": []},
    })


def _prompt_candidates(prompt: str) -> list[str]:
    vals = []
    for line in prompt.splitlines():
        if line.startswith("- [ip] "):
            vals.append(line.split("- [ip] ", 1)[1].split(" |", 1)[0])
    return vals


class _EchoLLM:
    """Answers every call about exactly the candidates that call carried."""

    def __init__(self, native: bool = False, answer_about=None):
        self.native = native
        self.doc_calls: list[list[str]] = []
        self.text_calls: list[list[str]] = []
        # None means "answer about everything in the prompt"; a callable gets
        # the prompt's candidates and returns the subset to answer about.
        self.answer_about = answer_about

    def supports_native_document(self, mime_type: str) -> bool:
        return self.native and mime_type == "application/pdf"

    def _answer(self, prompt, label):
        given = _prompt_candidates(prompt)
        answered = self.answer_about(given) if self.answer_about else given
        return _Resp(text=_echo_reply(answered, label))

    def query_with_document(self, prompt, artifact, system_context=None,
                            max_tokens=8192, grounding_data=None, hints=None):
        label = (artifact.metadata or {}).get("page_range", "whole")
        self.doc_calls.append(_prompt_candidates(prompt))
        return self._answer(prompt, str(label))

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.text_calls.append(_prompt_candidates(prompt))
        return self._answer(prompt, "text")


# ---------------------------------------------------------------------------
# The reporting contract
# ---------------------------------------------------------------------------


def _fields(**kw):
    base = dict(
        ingestion_mode="llm", pages_total=10, pages_read=10, truncated_chunks=[],
    )
    base.update(kw)
    return _tool_mod._analysis_fields(**base)


class TestNotSubmittedIsItsOwnNote:
    def test_it_makes_the_run_partial(self):
        f = _fields(candidates_not_submitted=4)
        assert f["analysis_status"] == "partial"

    def test_it_says_no_model_was_asked(self):
        f = _fields(candidates_not_submitted=4)
        note = next(
            n for n in f["analysis_notes"]
            if n.startswith("CANDIDATES NOT SUBMITTED")
        )
        assert "4 indicator candidate(s)" in note
        assert "no model was asked about them" in note

    def test_it_is_distinct_from_the_unassessed_note(self):
        """The whole reason for a second counter: one note cannot say whether
        the model was asked and stayed silent, or was never asked."""
        f = _fields(candidates_not_submitted=4, candidates_unassessed=3)
        kinds = [n.split(":")[0] for n in f["analysis_notes"]]
        assert "CANDIDATES NOT SUBMITTED" in kinds
        assert "UNASSESSED CANDIDATES" in kinds
        assert len(f["analysis_notes"]) == 2

    def test_not_submitted_is_reported_before_unassessed(self):
        """Coverage first, then the model's silence: a reader who never asked
        about a candidate does not need to hear about the verdict it lacks."""
        notes = _fields(
            candidates_not_submitted=1, candidates_unassessed=1,
        )["analysis_notes"]
        assert notes[0].startswith("CANDIDATES NOT SUBMITTED")

    def test_zero_says_nothing(self):
        f = _fields(candidates_not_submitted=0)
        assert f["analysis_status"] == "complete"
        assert f["analysis_notes"] == []

    def test_it_is_declared_in_the_schema(self):
        schema = json.loads(
            (PLUGIN_DIR / "schemas" / "output.schema.json").read_text(
                encoding="utf-8",
            )
        )
        summary = (
            schema["properties"]["result"]["properties"]["summary"]["properties"]
        )
        assert "candidates_not_submitted" in summary
        assert summary["candidates_not_submitted"]["type"] == "integer"


def _dense_pages(n_pages: int, per_page: int) -> list[str]:
    return [
        "\n".join(
            f"198.{pg + 1}.{i // 250}.{i % 250} scanner" for i in range(per_page)
        )
        for pg in range(n_pages)
    ]


@pytest.fixture
def pdf_run(tmp_path, monkeypatch):
    """A native PDF run with no pdfplumber or pypdf involved."""
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

    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-fake")
    artifact = MockArtifactRef(
        artifact_id="art_pdf", artifact_type="pdf_report", file_path=str(pdf),
    )

    def register(artifact_type, file_path, source_tool, metadata):
        return MockArtifactRef(
            artifact_id="art_out", artifact_type=artifact_type,
            file_path=file_path,
        )

    def go(tool, pages, llm):
        monkeypatch.setattr(
            _tool_mod, "extract_pdf_page_texts",
            lambda path, max_pages=50: pages[:max_pages],
        )
        ctx = MockExecutionContext(
            artifacts=[artifact], llm_enabled=True, llm_query=llm,
            register_artifact=register,
        )
        result = tool.execute({"artifact_id": "art_pdf"}, ctx)
        assert result.ok, result.message
        return result

    return go


# ---------------------------------------------------------------------------
# The reconciliation reads the submitted map, not raw_iocs
# ---------------------------------------------------------------------------


@pytest.fixture
def text_run(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    report = tmp_path / "report.txt"
    report.write_text(
        "Beaconing to 198.51.100.7, 203.0.113.9 and 192.0.2.44 over 443.\n",
        encoding="utf-8",
    )
    artifact = MockArtifactRef(
        artifact_id="art_txt", artifact_type="text", file_path=str(report),
    )

    def register(artifact_type, file_path, source_tool, metadata):
        return MockArtifactRef(
            artifact_id="art_out", artifact_type=artifact_type,
            file_path=file_path,
        )

    def go(tool, llm):
        ctx = MockExecutionContext(
            artifacts=[artifact], llm_enabled=llm is not None, llm_query=llm,
            register_artifact=register,
        )
        result = tool.execute({"artifact_id": "art_txt"}, ctx)
        assert result.ok, result.message
        return result

    return go


class TestReconciliationUsesTheSubmittedSet:
    def test_a_complete_answer_leaves_both_counters_zero(
        self, tool_instance, text_run,
    ):
        summary = text_run(tool_instance, _EchoLLM()).result["summary"]
        assert summary["candidates_unassessed"] == 0
        assert summary["candidates_not_submitted"] == 0
        assert summary["analysis_status"] == "complete"

    def test_silence_about_a_submitted_candidate_is_unassessed(
        self, tool_instance, text_run,
    ):
        """Answered about one of three: the other two were asked about and got
        no verdict, which is the model's silence, not a coverage gap."""
        llm = _EchoLLM(answer_about=lambda given: given[:1])
        summary = text_run(tool_instance, llm).result["summary"]
        assert summary["candidates_unassessed"] == 2
        assert summary["candidates_not_submitted"] == 0
        assert summary["analysis_status"] == "partial"

    def test_a_candidate_kept_out_of_every_prompt_is_not_submitted(
        self, tool_instance, pdf_run, monkeypatch,
    ):
        """The case 2.5 could introduce, simulated by dropping one candidate
        from the per-page pass that builds the native batches while leaving
        raw_iocs intact. It must be charged to coverage, not to the model.

        A batched native run is the only shape where this is expressible: a
        whole-document batch is given raw_iocs directly, and the chunked path
        takes fallback_iocs from raw_iocs, so neither reads page_iocs.
        """
        pages = _dense_pages(12, 30)
        real = _tool_mod._page_iocs

        def _shrink(page_texts, ioc_types):
            out = real(page_texts, ioc_types)
            out[0] = out[0][:-1]  # page 1 loses its last candidate
            return out

        monkeypatch.setattr(_tool_mod, "_page_iocs", _shrink)

        llm = _EchoLLM(native=True)
        summary = pdf_run(tool_instance, pages, llm).result["summary"]
        assert len(llm.doc_calls) > 1, "the plan must actually have split"
        assert summary["candidates_not_submitted"] == 1, (
            "a candidate no prompt carried must not be reported as the "
            "model's silence"
        )
        assert summary["candidates_unassessed"] == 0
        assert summary["analysis_status"] == "partial"
        assert any(
            n.startswith("CANDIDATES NOT SUBMITTED")
            for n in summary["analysis_notes"]
        )


# ---------------------------------------------------------------------------
# The invariant. This is the regression tripwire for 2.5.
# ---------------------------------------------------------------------------


class TestEveryCandidateReachesAPrompt:
    """`candidates_not_submitted` must be 0 on every run shape. If 2.5's
    rewrite of prompt assembly breaks page coverage, these fail."""

    def test_whole_document_native_run(self, tool_instance, pdf_run):
        pages = _dense_pages(3, 4)
        summary = pdf_run(
            tool_instance, pages, _EchoLLM(native=True),
        ).result["summary"]
        assert summary["candidates_not_submitted"] == 0
        assert summary["native_calls"] == 1, "the whole document in one call"

    def test_page_batched_native_run(self, tool_instance, pdf_run):
        pages = _dense_pages(12, 30)
        llm = _EchoLLM(native=True)
        summary = pdf_run(tool_instance, pages, llm).result["summary"]
        assert len(llm.doc_calls) > 1, "the plan must actually have split"
        assert summary["candidates_not_submitted"] == 0

    def test_native_run_that_partially_falls_back(self, tool_instance, pdf_run):
        """Pages whose native call fails go to the chunked path; their
        candidates are submitted there, so the count stays 0."""
        pages = _dense_pages(12, 30)

        class _HalfFailing(_EchoLLM):
            def query_with_document(self, prompt, artifact, **kw):
                self.doc_calls.append(_prompt_candidates(prompt))
                if len(self.doc_calls) == 1:
                    return _Resp(ok=False, text=None,
                                 error="504 DEADLINE_EXCEEDED")
                return self._answer(prompt, "doc")

        llm = _HalfFailing(native=True)
        summary = pdf_run(tool_instance, pages, llm).result["summary"]
        assert llm.text_calls, "the failed pages must have gone to the text path"
        assert summary["candidates_not_submitted"] == 0

    def test_pure_chunked_run(self, tool_instance, pdf_run):
        """No native support at all: everything goes through the text path,
        and every IOC batch must still be submitted."""
        pages = _dense_pages(12, 30)
        llm = _EchoLLM(native=False)
        summary = pdf_run(tool_instance, pages, llm).result["summary"]
        assert not llm.doc_calls
        assert len(llm.text_calls) > 1, "the text must actually have chunked"
        assert summary["candidates_not_submitted"] == 0
