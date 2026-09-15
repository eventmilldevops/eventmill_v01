"""A retry must beat the partial it replaced, and nothing reported is dropped.

Two defects with one cause. `_merge_llm_chunk_results` is first-wins on
`(ioc_type, value.lower())` and `(technique_id, tactic)`, and the native loop
appends a truncated partial to `native_batch_results` *before* running the
bisected retry that replaces it:

1. **The partial won its own retry.** The log said the retry succeeded while
   the merged answer came from the reply that was cut off - the one finding
   whose behaviour was the opposite of what the logs reported.
2. **Every later report of an entity was discarded.** `(ioc_type, value)` is an
   entity identity, not an evidence identity: several procedures share one
   technique and one indicator carries several roles, and all but the first
   sighting was thrown away.

Supersession is by page-range containment rather than label match, because
`PageRange.label` is derived from the page numbers - bisecting `p1-4` yields
`p1-2` and `p3-4`, and no child ever shares its parent's label.
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
    _name = "threat_intel_ingester_tool_mergeprov"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


@pytest.fixture
def tool_instance():
    return _tool_mod.ThreatIntelIngester()


# ---------------------------------------------------------------------------
# The merge, on its own
# ---------------------------------------------------------------------------


def _ioc(value, **kw):
    base = {
        "value": value, "ioc_type": "ip", "confidence": "high",
        "priority": "medium", "context": "c2", "related_mitre": [],
        "is_false_positive": False,
    }
    base.update(kw)
    return base


def _tech(tid, tactic="Execution", **kw):
    base = {
        "technique_id": tid, "tactic": tactic, "technique_name": "Whatever",
        "confidence": "inferred", "report_context": "something happened",
    }
    base.update(kw)
    return base


def _result(iocs=(), techs=(), meta=None, paths=()):
    return {
        "refined_iocs": list(iocs),
        "additional_mitre_techniques": list(techs),
        "report_metadata": meta or {},
        "attack_graph": {"paths": list(paths), "convergence_points": [],
                         "branch_points": []},
    }


def _prov(label, attempt, start=None, end=None, truncated=False,
          superseded_by=None):
    return {
        "label": label, "attempt_id": attempt, "page_start": start,
        "page_end": end, "truncated": truncated,
        "superseded_by": superseded_by,
    }


class TestOccurrencesAreKept:
    def test_one_technique_two_procedures(self):
        """The plan's test: two chunks reporting the same technique with
        different procedures must merge to one technique with two
        occurrences."""
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(techs=[_tech("T1059", report_context="powershell -enc")]),
                _result(techs=[_tech("T1059", report_context="wmic process call")]),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        techs = merged["additional_mitre_techniques"]
        assert len(techs) == 1, "one entity"
        occ = techs[0]["occurrences"]
        assert len(occ) == 2, "two sightings"
        assert [o["context"] for o in occ] == [
            "powershell -enc", "wmic process call",
        ]

    def test_the_canonical_scalars_are_still_first_wins(self):
        """Downstream consumers read the top level; it must not move."""
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1", confidence="medium")]),
                _result(iocs=[_ioc("1.1.1.1", confidence="high")]),
            ],
            [_prov("a", 1), _prov("b", 2)],
        )
        assert merged["refined_iocs"][0]["confidence"] == "medium"

    def test_an_occurrence_records_where_it_came_from(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [_result(iocs=[_ioc("1.1.1.1")])],
            [_prov("p3-7", 4, start=3, end=7)],
        )
        occ = merged["refined_iocs"][0]["occurrences"][0]
        assert occ["batch_label"] == "p3-7"
        assert occ["attempt_id"] == 4
        assert (occ["page_start"], occ["page_end"]) == (3, 7)

    def test_no_provenance_still_merges(self):
        """The pre-2.2 call shape keeps working."""
        merged = _tool_mod._merge_llm_chunk_results(
            [_result(iocs=[_ioc("1.1.1.1")]), _result(iocs=[_ioc("1.1.1.1")])]
        )
        assert len(merged["refined_iocs"]) == 1
        assert len(merged["refined_iocs"][0]["occurrences"]) == 2


class TestConflictsAreRecordedNotResolved:
    def test_a_disagreement_is_recorded(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1", confidence="high")]),
                _result(iocs=[_ioc("1.1.1.1", confidence="low")]),
            ],
            [_prov("a", 1), _prov("b", 2)],
        )
        conflicts = merged["refined_iocs"][0]["conflicts"]
        assert len(conflicts) == 1
        c = conflicts[0]
        assert c["field"] == "confidence"
        assert (c["canonical"], c["reported"]) == ("high", "low")
        assert c["batch_label"] == "b"
        assert merged["merge_stats"]["conflicts"] == 1

    def test_it_is_not_resolved_by_taking_the_higher_confidence(self):
        """A later correction and a lower-confidence restatement are not
        distinguishable by value, so neither wins on value."""
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1", confidence="low")]),
                _result(iocs=[_ioc("1.1.1.1", confidence="high")]),
            ],
            [_prov("a", 1), _prov("b", 2)],
        )
        assert merged["refined_iocs"][0]["confidence"] == "low", (
            "first-wins, with the disagreement reported rather than guessed at"
        )

    def test_a_false_positive_disagreement_is_a_conflict(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1", is_false_positive=False)]),
                _result(iocs=[_ioc("1.1.1.1", is_false_positive=True)]),
            ],
            [_prov("a", 1), _prov("b", 2)],
        )
        fields = {
            c["field"] for c in merged["refined_iocs"][0]["conflicts"]
        }
        assert "is_false_positive" in fields

    def test_agreement_raises_nothing(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [_result(iocs=[_ioc("1.1.1.1")]), _result(iocs=[_ioc("1.1.1.1")])],
            [_prov("a", 1), _prov("b", 2)],
        )
        assert "conflicts" not in merged["refined_iocs"][0]
        assert merged["merge_stats"]["conflicts"] == 0

    def test_the_identity_fields_are_never_conflicts(self):
        """A different ioc_type or value is a different entity, not a
        disagreement about this one."""
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1")]),
                _result(iocs=[_ioc("1.1.1.1", ioc_type="domain")]),
            ],
            [_prov("a", 1), _prov("b", 2)],
        )
        assert len(merged["refined_iocs"]) == 2
        assert all("conflicts" not in e for e in merged["refined_iocs"])


class TestSupersededResultsLose:
    def test_a_superseded_partial_does_not_set_the_canonical_value(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1", confidence="low")]),
                _result(iocs=[_ioc("1.1.1.1", confidence="high")]),
            ],
            [
                _prov("p1-4", 1, 1, 4, truncated=True, superseded_by="p1-2"),
                _prov("p1-2", 2, 1, 2),
            ],
        )
        assert merged["refined_iocs"][0]["confidence"] == "high", (
            "the retry is the answer, not the reply that was cut off"
        )

    def test_a_superseded_partial_raises_no_conflict(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1", confidence="low")]),
                _result(iocs=[_ioc("1.1.1.1", confidence="high")]),
            ],
            [
                _prov("p1-4", 1, 1, 4, truncated=True, superseded_by="p1-2"),
                _prov("p1-2", 2, 1, 2),
            ],
        )
        assert "conflicts" not in merged["refined_iocs"][0]

    def test_it_still_leaves_its_occurrence_behind(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1", confidence="low")]),
                _result(iocs=[_ioc("1.1.1.1", confidence="high")]),
            ],
            [
                _prov("p1-4", 1, 1, 4, truncated=True, superseded_by="p1-2"),
                _prov("p1-2", 2, 1, 2),
            ],
        )
        occ = merged["refined_iocs"][0]["occurrences"]
        assert len(occ) == 2
        assert [o.get("superseded") for o in occ] == [None, True] or (
            [o.get("superseded") for o in occ] == [True, None]
        )

    def test_an_entity_only_the_partial_reported_is_retained(self):
        """Skipping superseded results wholesale would destroy evidence the
        retry never restated, which is the failure this stage exists to stop."""
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(iocs=[_ioc("1.1.1.1"), _ioc("2.2.2.2")]),
                _result(iocs=[_ioc("1.1.1.1")]),
            ],
            [
                _prov("p1-4", 1, 1, 4, truncated=True, superseded_by="p1-2"),
                _prov("p1-2", 2, 1, 2),
            ],
        )
        values = [e["value"] for e in merged["refined_iocs"]]
        assert "2.2.2.2" in values
        only = next(e for e in merged["refined_iocs"] if e["value"] == "2.2.2.2")
        assert only["recovered_from_partial"] is True
        assert merged["merge_stats"]["recovered_from_partial"] == 1

    def test_report_metadata_does_not_come_from_a_superseded_result(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(meta={"title": "from the cut-off reply"}),
                _result(meta={"title": "from the retry"}),
            ],
            [
                _prov("p1-4", 1, 1, 4, truncated=True, superseded_by="p1-2"),
                _prov("p1-2", 2, 1, 2),
            ],
        )
        assert merged["report_metadata"]["title"] == "from the retry"


# ---------------------------------------------------------------------------
# _mark_superseded: containment, not labels
# ---------------------------------------------------------------------------


class TestMarkSuperseded:
    def test_two_halves_replace_their_parent(self):
        prov = [
            _prov("p1-4", 1, 1, 4, truncated=True),
            _prov("p1-2", 2, 1, 2),
            _prov("p3-4", 3, 3, 4),
        ]
        assert _tool_mod._mark_superseded(prov, set()) == 1
        assert prov[0]["superseded_by"] == "p1-2, p3-4"

    def test_one_half_alone_is_not_enough(self):
        """Half the pages re-read is not a replacement: the other half's
        candidates exist only in the partial."""
        prov = [
            _prov("p1-4", 1, 1, 4, truncated=True),
            _prov("p1-2", 2, 1, 2),
        ]
        assert _tool_mod._mark_superseded(prov, set()) == 0
        assert prov[0]["superseded_by"] is None

    def test_the_chunked_path_replaces_an_unsplittable_partial(self):
        """A truncated single page cannot be bisected, so its pages go to the
        chunked text path - which re-submits every candidate on them."""
        prov = [_prov("p7", 1, 7, 7, truncated=True)]
        assert _tool_mod._mark_superseded(prov, {7}) == 1
        assert prov[0]["superseded_by"] == "chunked text path"

    def test_a_partial_nobody_replaced_stands(self):
        prov = [_prov("p7", 1, 7, 7, truncated=True)]
        assert _tool_mod._mark_superseded(prov, set()) == 0
        assert prov[0]["superseded_by"] is None

    def test_a_grandchild_chain_still_replaces_the_root(self):
        """p1-4 bisects into p1-2 and p3-4; p1-2 truncates too and bisects
        into p1 and p2. The root is covered through its replaced child."""
        prov = [
            _prov("p1-4", 1, 1, 4, truncated=True),
            _prov("p1-2", 2, 1, 2, truncated=True),
            _prov("p3-4", 3, 3, 4),
            _prov("p1", 4, 1, 1),
            _prov("p2", 5, 2, 2),
        ]
        assert _tool_mod._mark_superseded(prov, set()) == 2
        assert prov[1]["superseded_by"] == "p1, p2"
        assert prov[0]["superseded_by"] is not None

    def test_an_untruncated_result_is_never_superseded(self):
        prov = [_prov("p1-2", 1, 1, 2), _prov("p1-2 again", 2, 1, 2)]
        assert _tool_mod._mark_superseded(prov, set()) == 0

    def test_a_chunked_result_has_no_page_range_and_is_left_alone(self):
        prov = [_prov("chunk 1/3", 1, truncated=True)]
        assert _tool_mod._mark_superseded(prov, {1, 2, 3}) == 0
        assert prov[0]["superseded_by"] is None


# ---------------------------------------------------------------------------
# The notes
# ---------------------------------------------------------------------------


def _fields(**kw):
    base = dict(
        ingestion_mode="llm", pages_total=10, pages_read=10, truncated_chunks=[],
    )
    base.update(kw)
    return _tool_mod._analysis_fields(**base)


class TestMergeNotes:
    def test_a_conflict_makes_the_run_partial(self):
        f = _fields(merge_conflicts=2)
        assert f["analysis_status"] == "partial"
        assert any(n.startswith("UNRESOLVED CONFLICTS") for n in f["analysis_notes"])

    def test_a_recovered_record_makes_the_run_partial(self):
        f = _fields(recovered_from_partial=1)
        assert f["analysis_status"] == "partial"
        note = next(
            n for n in f["analysis_notes"]
            if n.startswith("RECOVERED FROM A PARTIAL REPLY")
        )
        assert "were not restated by the attempt that replaced it" in note

    def test_neither_fires_on_a_clean_merge(self):
        f = _fields(merge_conflicts=0, recovered_from_partial=0)
        assert f["analysis_status"] == "complete"


# ---------------------------------------------------------------------------
# End to end: the retry really does win
# ---------------------------------------------------------------------------


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
    model_used: str | None = "mock-light"
    transport_path: str | None = "native"
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
    session_id: str = "test_session_mergeprov"
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


def _candidates(prompt):
    return [
        line.split("- [ip] ", 1)[1].split(" |", 1)[0]
        for line in prompt.splitlines() if line.startswith("- [ip] ")
    ]


class _PartialThenRetryLLM:
    """The first document call comes back cut off, saying `low`; every call
    after it is clean and says `high`.

    The transport reports the truncation while the body still parses, which is
    the shape that produced the defect: a usable partial is appended, and the
    bisected retry that replaces it lands behind it in the merge.
    """

    def __init__(self, extra_in_partial=()):
        self.doc_calls: list[dict] = []
        self.text_calls: list[list[str]] = []
        self.extra_in_partial = list(extra_in_partial)

    def supports_native_document(self, mime_type: str) -> bool:
        return mime_type == "application/pdf"

    @staticmethod
    def _body(values, confidence, label):
        return json.dumps({
            "refined_iocs": [
                {"value": v, "ioc_type": "ip", "confidence": confidence,
                 "priority": "medium", "context": f"seen in {label}",
                 "related_mitre": [], "is_false_positive": False}
                for v in values
            ],
            "additional_mitre_techniques": [],
            "report_metadata": {"title": f"from {label}"},
            "attack_graph": {"paths": [], "convergence_points": [],
                             "branch_points": []},
        })

    def query_with_document(self, prompt, artifact, system_context=None,
                            max_tokens=8192, grounding_data=None, hints=None):
        label = str((artifact.metadata or {}).get("page_range", "whole"))
        vals = _candidates(prompt)
        self.doc_calls.append({"label": label, "candidates": vals})
        if len(self.doc_calls) == 1:
            return _Resp(
                text=self._body(
                    vals + self.extra_in_partial, "low", "the cut-off reply",
                ),
                finish_reason="MAX_TOKENS",
                truncated=True,
            )
        return _Resp(text=self._body(vals, "high", label))

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        vals = _candidates(prompt)
        self.text_calls.append(vals)
        return _Resp(text=self._body(vals, "high", "the chunked re-read"))


@pytest.fixture
def pdf_run(tmp_path, monkeypatch):
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


FOUR_PAGES = [f"Beaconing to 198.51.100.{n} over 443." for n in (1, 2, 3, 4)]


class TestTheRetryBeatsThePartialEndToEnd:
    def test_the_merged_confidence_comes_from_the_retry(
        self, tool_instance, pdf_run,
    ):
        """The plan's test: a partial asserting low followed by a successful
        retry asserting high must merge to high."""
        llm = _PartialThenRetryLLM()
        result = pdf_run(tool_instance, FOUR_PAGES, llm)
        assert len(llm.doc_calls) >= 3, (
            f"the whole batch must have bisected: {llm.doc_calls}"
        )
        assert llm.doc_calls[0]["label"] == "whole"
        confidences = {i["confidence"] for i in result.result["iocs"]}
        assert confidences == {"high"}, (
            "the reply that was cut off must not supply the merged answer"
        )

    def test_the_partial_is_recorded_as_superseded(
        self, tool_instance, pdf_run,
    ):
        llm = _PartialThenRetryLLM()
        summary = pdf_run(tool_instance, FOUR_PAGES, llm).result["summary"]
        assert summary["merge_stats"]["superseded_results"] == 1
        assert summary["native_attempts"] == len(llm.doc_calls)

    def test_the_partials_own_sighting_survives_as_an_occurrence(
        self, tool_instance, pdf_run,
    ):
        llm = _PartialThenRetryLLM()
        result = pdf_run(tool_instance, FOUR_PAGES, llm)
        ioc = result.result["iocs"][0]
        assert any(o.get("superseded") for o in ioc["occurrences"]), (
            "losing the merge is not the same as being erased"
        )

    def test_metadata_comes_from_the_retry_not_the_partial(
        self, tool_instance, pdf_run,
    ):
        llm = _PartialThenRetryLLM()
        result = pdf_run(tool_instance, FOUR_PAGES, llm)
        assert result.result["report_metadata"]["title"] != "from the cut-off reply"

    def test_an_indicator_only_the_partial_saw_is_kept_and_flagged(
        self, tool_instance, pdf_run,
    ):
        """The retry does not restate it, so it survives only here. It must
        not be dropped, and it must not be reported as unassessed either."""
        llm = _PartialThenRetryLLM(extra_in_partial=["10.0.0.99"])
        result = pdf_run(tool_instance, FOUR_PAGES, llm)
        summary = result.result["summary"]
        values = [i["value"] for i in result.result["iocs"]]
        assert "10.0.0.99" in values
        recovered = next(
            i for i in result.result["iocs"] if i["value"] == "10.0.0.99"
        )
        assert recovered["recovered_from_partial"] is True
        assert summary["merge_stats"]["recovered_from_partial"] == 1
        assert summary["analysis_status"] == "partial"
        assert any(
            n.startswith("RECOVERED FROM A PARTIAL REPLY")
            for n in summary["analysis_notes"]
        )

    def test_the_reconciliation_does_not_regress(
        self, tool_instance, pdf_run,
    ):
        """Stage 1's guarantee: a candidate every attempt answered about must
        not read as unassessed once superseded results stop winning."""
        llm = _PartialThenRetryLLM()
        summary = pdf_run(tool_instance, FOUR_PAGES, llm).result["summary"]
        assert summary["candidates_unassessed"] == 0
        assert summary["candidates_not_submitted"] == 0


class TestTheUnsplittablePartial:
    def test_the_chunked_re_read_supersedes_it(self, tool_instance, pdf_run):
        """A single page cannot be bisected, so it goes to the chunked text
        path - and that re-read must beat the partial, for the same reason a
        bisected retry does. This path was not in the original write-up."""
        llm = _PartialThenRetryLLM()
        result = pdf_run(tool_instance, ["Beaconing to 198.51.100.1 now."], llm)
        summary = result.result["summary"]
        assert len(llm.doc_calls) == 1, "one page, no bisect possible"
        assert llm.text_calls, "its pages must have gone to the chunked path"
        assert summary["merge_stats"]["superseded_results"] == 1
        assert {i["confidence"] for i in result.result["iocs"]} == {"high"}


# ---------------------------------------------------------------------------
# The output contract
# ---------------------------------------------------------------------------


class TestTheSchemaDeclaresTheNewEvidence:
    """Nothing here sets additionalProperties: false, so an undeclared field
    would validate and go undocumented. Declared on purpose."""

    @staticmethod
    def _schema():
        return json.loads(
            (PLUGIN_DIR / "schemas" / "output.schema.json").read_text(
                encoding="utf-8",
            )
        )["properties"]["result"]["properties"]

    @pytest.mark.parametrize("collection", ["iocs", "mitre_mappings"])
    @pytest.mark.parametrize(
        "field", ["occurrences", "conflicts", "recovered_from_partial"],
    )
    def test_entity_fields_are_declared(self, collection, field):
        props = self._schema()[collection]["items"]["properties"]
        assert field in props

    def test_the_conflict_fields_match_the_code(self):
        """The enum is what a reader trusts; drift makes it a lie."""
        schema = self._schema()
        for collection, expected in (
            ("iocs", _tool_mod._IOC_CONFLICT_FIELDS),
            ("mitre_mappings", _tool_mod._MITRE_CONFLICT_FIELDS),
        ):
            declared = (
                schema[collection]["items"]["properties"]["conflicts"]
                ["items"]["properties"]["field"]["enum"]
            )
            assert tuple(declared) == tuple(expected), collection

    def test_the_summary_fields_are_declared(self):
        summary = self._schema()["summary"]["properties"]
        assert "merge_stats" in summary
        assert "native_attempts" in summary
        assert set(summary["merge_stats"]["properties"]) == {
            "conflicts", "recovered_from_partial", "superseded_results",
            "occurrences",
        }

    def test_merge_stats_keys_match_what_the_merge_returns(self):
        produced = set(
            _tool_mod._merge_llm_chunk_results([])["merge_stats"]
        )
        declared = set(
            self._schema()["summary"]["properties"]["merge_stats"]["properties"]
        )
        assert produced == declared


# ---------------------------------------------------------------------------
# Found by the first live runs, 2026-09-15
# ---------------------------------------------------------------------------


class TestTechniqueNameIsNotAConflict:
    """A live run raised four conflicts for 'Spearphishing Attachment' vs
    'Phishing: Spearphishing Attachment' - the same technique, named two ways -
    and any conflict sets the run partial, so a spelling degraded the status.
    The reconciler overwrites the name from the local ATT&CK lookup anyway."""

    def test_two_namings_of_one_technique_agree(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(techs=[_tech(
                    "T1566.001", tactic="Initial Access",
                    technique_name="Spearphishing Attachment")]),
                _result(techs=[_tech(
                    "T1566.001", tactic="Initial Access",
                    technique_name="Phishing: Spearphishing Attachment")]),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        tech = merged["additional_mitre_techniques"][0]
        assert "conflicts" not in tech
        assert merged["merge_stats"]["conflicts"] == 0
        assert len(tech["occurrences"]) == 2, "still both sightings"

    def test_a_confidence_disagreement_is_still_a_conflict(self):
        merged = _tool_mod._merge_llm_chunk_results(
            [
                _result(techs=[_tech("T1059", confidence="inferred")]),
                _result(techs=[_tech("T1059", confidence="explicit")]),
            ],
            [_prov("a", 1), _prov("b", 2)],
        )
        assert merged["merge_stats"]["conflicts"] == 1


class TestRejectionOverDissent:
    """A live run reported 25 conflicts and showed the reader 17. The missing
    eight belonged to two indicators whose canonical verdict was
    `is_false_positive: true` while other chunks called them real: the
    false-positive filter dropped the records and took their conflict entries
    with them. The rejection stands - Stage 1.5's rule - but it is not silent.
    """

    def test_the_note_fires_and_makes_the_run_partial(self):
        f = _fields(rejected_with_dissent=2)
        assert f["analysis_status"] == "partial"
        note = next(
            n for n in f["analysis_notes"]
            if n.startswith("REJECTED OVER DISSENT")
        )
        assert "another batch assessed them as real" in note
        assert "only record of the disagreement" in note

    def test_it_is_separate_from_the_conflicts_note(self):
        f = _fields(merge_conflicts=8, rejected_with_dissent=2)
        kinds = {n.split(":")[0] for n in f["analysis_notes"]}
        assert {"UNRESOLVED CONFLICTS", "REJECTED OVER DISSENT"} <= kinds

    def test_silent_when_nothing_was_rejected_over_dissent(self):
        f = _fields(rejected_with_dissent=0)
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
        assert "rejected_with_dissent" in summary
        assert summary["rejected_with_dissent"]["type"] == "array"

    def test_an_undisputed_rejection_is_not_dissent(self, tool_instance, pdf_run):
        """Every attempt agreeing it is a false positive is an assessment, not
        a disagreement - it must not raise this note."""
        class _AllFP(_PartialThenRetryLLM):
            @staticmethod
            def _body(values, confidence, label):
                return json.dumps({
                    "refined_iocs": [
                        {"value": v, "ioc_type": "ip", "confidence": "low",
                         "priority": "low", "context": label,
                         "related_mitre": [], "is_false_positive": True}
                        for v in values
                    ],
                    "additional_mitre_techniques": [],
                    "report_metadata": {"title": "t"},
                    "attack_graph": {"paths": [], "convergence_points": [],
                                     "branch_points": []},
                })

            def query_with_document(self, prompt, artifact, **kw):
                self.doc_calls.append(
                    {"label": "whole", "candidates": _candidates(prompt)}
                )
                return _Resp(text=self._body(_candidates(prompt), "low", "x"))

        result = pdf_run(tool_instance, FOUR_PAGES, _AllFP())
        s = result.result["summary"]
        assert s["rejected_with_dissent"] == []
        assert not any(
            n.startswith("REJECTED OVER DISSENT") for n in s["analysis_notes"]
        )
        assert any(
            n.startswith("NO INDICATORS ACCEPTED") for n in s["analysis_notes"]
        ), "the existing rejection reporting is untouched"

    def test_a_disputed_rejection_is_captured_end_to_end(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        """The live shape: one batch calls it a false positive, another calls
        it real, the canonical verdict is the rejection, and the record leaves
        the output. Its conflict must not leave with it unrecorded."""
        monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
        # Two text chunks over one candidate, so two calls see the same value.
        monkeypatch.setattr(_tool_mod, "_MAX_TEXT_CHARS_PER_CHUNK", 200)
        report = tmp_path / "disputed.txt"
        report.write_text(
            "Section one names 198.51.100.7 as shared CDN space.\n\n"
            + ("Padding for the second chunk. " * 12)
            + "\n\nSection two re-confirms 198.51.100.7 as live C2.\n",
            encoding="utf-8",
        )
        artifact = MockArtifactRef(
            artifact_id="art_disputed", artifact_type="text",
            file_path=str(report),
        )

        class _DisputingLLM:
            def __init__(self):
                self.calls = 0

            def supports_native_document(self, mime_type):
                return False

            def query_text(self, prompt, **kw):
                self.calls += 1
                # First call rejects it, second says it is real.
                fp = self.calls == 1
                return _Resp(text=json.dumps({
                    "refined_iocs": [{
                        "value": "198.51.100.7", "ioc_type": "ip",
                        "confidence": "low" if fp else "high",
                        "priority": "low" if fp else "high",
                        "context": f"call {self.calls}", "related_mitre": [],
                        "is_false_positive": fp,
                    }],
                    "additional_mitre_techniques": [],
                    "report_metadata": {"title": "Disputed"},
                    "attack_graph": {"paths": [], "convergence_points": [],
                                     "branch_points": []},
                }))

        llm = _DisputingLLM()
        ctx = MockExecutionContext(
            artifacts=[artifact], llm_enabled=True, llm_query=llm,
            register_artifact=lambda artifact_type, file_path, source_tool,
            metadata: MockArtifactRef("out", artifact_type, file_path),
        )
        result = tool_instance.execute({"artifact_id": "art_disputed"}, ctx)
        assert result.ok, result.message
        assert llm.calls >= 2, "the text must have split into two calls"

        s = result.result["summary"]
        assert [i["value"] for i in result.result["iocs"]] == [], (
            "the rejection stands - Stage 1.5's rule is not undone"
        )
        assert s["rejected_with_dissent"] == ["198.51.100.7"], (
            "a rejection another batch argued against must be named, or the "
            "conflict leaves the output with the record"
        )
        assert any(
            n.startswith("REJECTED OVER DISSENT") for n in s["analysis_notes"]
        )
        assert s["analysis_status"] == "partial"
