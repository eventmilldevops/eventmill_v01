"""Two batches disagreeing about names must not cost a path or an actor.

Both defects are the same shape as Stage 2.2's: a merge that treats a *name*
as an identity and drops whatever arrives second under it.

1. **`path_id` is a slug, not an identity.** Separate model calls coin slugs
   independently, so two batches describing unrelated paths can both call
   theirs `initial-access-to-exfil`. The union kept the first and dropped the
   second outright, with nothing recorded to say a second existed.
2. **`report_metadata` was taken object-at-a-time.** The first batch to fill
   in *any* field took the whole record, so a batch that recognised only the
   title discarded the batch that identified the actor - and a report naming
   two groups reported one.

Reconciliation is on the step sequence for paths and field-by-field for
metadata. Ids are namespaced only on a real collision, so a run whose slugs do
not collide - which is every single-batch run - emits the ids it emitted
before.
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
    _name = "threat_intel_ingester_tool_graphattr"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


def _step(tid, tactic="Execution", leads_to=()):
    return {"technique_id": tid, "tactic": tactic, "leads_to": list(leads_to)}


def _path(pid, steps, description="a path"):
    return {"path_id": pid, "description": description, "steps": list(steps)}


def _result(meta=None, paths=()):
    return {
        "refined_iocs": [],
        "additional_mitre_techniques": [],
        "report_metadata": meta or {},
        "attack_graph": {
            "paths": list(paths), "convergence_points": [], "branch_points": [],
        },
    }


def _prov(label, attempt, superseded_by=None):
    return {
        "label": label, "attempt_id": attempt, "page_start": None,
        "page_end": None, "truncated": False, "superseded_by": superseded_by,
    }


def _merge(results, provenance):
    return _tool_mod._merge_llm_chunk_results(results, provenance)


# ---------------------------------------------------------------------------
# 2.3 - path_id
# ---------------------------------------------------------------------------


class TestCollidingPathIds:
    def test_two_batches_same_slug_different_steps_yield_two_paths(self):
        """The plan's test: two batches emitting the same path_id with
        different node sequences must yield two paths."""
        merged = _merge(
            [
                _result(paths=[_path("initial-access-to-exfil", [
                    _step("T1566.001", "Initial Access", ["T1059.001"]),
                    _step("T1059.001"),
                ])]),
                _result(paths=[_path("initial-access-to-exfil", [
                    _step("T1190", "Initial Access", ["T1505.003"]),
                    _step("T1505.003", "Persistence"),
                ])]),
            ],
            [_prov("p1-10", 1), _prov("p11-20", 2)],
        )
        paths = merged["attack_graph"]["paths"]
        assert len(paths) == 2, "both paths survive"
        ids = [p["path_id"] for p in paths]
        assert len(set(ids)) == 2, "and they are distinguishable"

    def test_the_first_path_keeps_its_slug(self):
        """Namespacing the loser, not both: an id nobody collided with is not
        rewritten, so nothing downstream moves on a run without a collision."""
        merged = _merge(
            [
                _result(paths=[_path("phish-to-exfil", [_step("T1566")])]),
                _result(paths=[_path("phish-to-exfil", [_step("T1190")])]),
            ],
            [_prov("p1-10", 1), _prov("p11-20", 2)],
        )
        paths = merged["attack_graph"]["paths"]
        assert paths[0]["path_id"] == "phish-to-exfil"
        assert paths[1]["path_id"] == "p11-20:phish-to-exfil"
        assert paths[1]["original_path_id"] == "phish-to-exfil"
        assert merged["merge_stats"]["paths_namespaced"] == 1

    def test_no_collision_leaves_every_id_untouched(self):
        """The regression that matters to consumers: both read path_id as a
        display label, and a run with distinct slugs must look exactly as it
        did before 2.3."""
        merged = _merge(
            [
                _result(paths=[_path("phish-to-exfil", [_step("T1566")])]),
                _result(paths=[_path("exploit-to-persist", [_step("T1190")])]),
            ],
            [_prov("p1-10", 1), _prov("p11-20", 2)],
        )
        assert [p["path_id"] for p in merged["attack_graph"]["paths"]] == [
            "phish-to-exfil", "exploit-to-persist",
        ]
        assert merged["merge_stats"]["paths_namespaced"] == 0

    def test_same_steps_different_slugs_is_one_path(self):
        """Reconcile on nodes and edges, not the slug - in both directions.
        Two batches that described the same path are not two paths because
        they named it differently."""
        merged = _merge(
            [
                _result(paths=[_path("phish-to-exfil", [
                    _step("T1566", "Initial Access", ["T1059"]), _step("T1059"),
                ])]),
                _result(paths=[_path("email-to-shell", [
                    _step("T1566", "Initial Access", ["T1059"]), _step("T1059"),
                ])]),
            ],
            [_prov("p1-10", 1), _prov("p11-20", 2)],
        )
        paths = merged["attack_graph"]["paths"]
        assert len(paths) == 1
        assert paths[0]["path_id"] == "phish-to-exfil"
        assert paths[0]["batch_labels"] == ["p1-10", "p11-20"], (
            "both sightings recorded"
        )

    def test_a_differing_leads_to_is_a_different_path(self):
        """Edges are part of the identity, not only nodes: the same techniques
        wired differently describe a different route through the report."""
        merged = _merge(
            [
                _result(paths=[_path("a", [
                    _step("T1566", "Initial Access", ["T1059"]), _step("T1059"),
                ])]),
                _result(paths=[_path("b", [
                    _step("T1566", "Initial Access", ["T1053"]), _step("T1059"),
                ])]),
            ],
            [_prov("p1-10", 1), _prov("p11-20", 2)],
        )
        assert len(merged["attack_graph"]["paths"]) == 2

    def test_pathless_paths_do_not_collapse_into_one(self):
        """An empty step list is not an identity - every path with no steps
        would share it, and merging them would lose their descriptions."""
        merged = _merge(
            [
                _result(paths=[_path("a", [], description="first")]),
                _result(paths=[_path("b", [], description="second")]),
            ],
            [_prov("p1-10", 1), _prov("p11-20", 2)],
        )
        paths = merged["attack_graph"]["paths"]
        assert [p["description"] for p in paths] == ["first", "second"]


class TestSupersededPaths:
    def test_a_partial_does_not_re_report_the_path_its_retry_restated(self):
        """Same rule as every other record a superseded partial holds: it
        contributes only what nothing else reported. Its truncated draft of a
        path the retry restated in full is not a second path."""
        merged = _merge(
            [
                _result(paths=[_path("phish-to-exfil", [
                    _step("T1566", "Initial Access", ["T1059"]),
                    _step("T1059"), _step("T1041", "Exfiltration"),
                ])]),
                _result(paths=[_path("phish-to-exfil", [
                    _step("T1566", "Initial Access", ["T1059"]),
                ])]),
            ],
            [_prov("p1-5", 2), _prov("p1-10", 1, superseded_by="p1-5, p6-10")],
        )
        paths = merged["attack_graph"]["paths"]
        assert len(paths) == 1, "the retry's full path, not the cut-off draft"
        assert len(paths[0]["steps"]) == 3

    def test_a_path_only_the_partial_reported_is_kept_and_flagged(self):
        """Evidence the retry did not restate is not discarded - it is kept and
        named, so a reader knows it rests on a reply that was cut off."""
        merged = _merge(
            [
                _result(paths=[_path("phish-to-exfil", [_step("T1566")])]),
                _result(paths=[_path("lateral-move", [_step("T1021")])]),
            ],
            [_prov("p1-5", 2), _prov("p1-10", 1, superseded_by="p1-5, p6-10")],
        )
        paths = merged["attack_graph"]["paths"]
        assert len(paths) == 2
        assert paths[1]["path_id"] == "lateral-move"
        assert paths[1]["recovered_from_partial"] is True


# ---------------------------------------------------------------------------
# 2.4 - actors and campaigns
# ---------------------------------------------------------------------------


class TestMetadataMergesPerField:
    def test_two_actors_both_survive(self):
        """The plan's test: chunk 1 naming actor A and chunk 2 naming actor B
        must yield both."""
        merged = _merge(
            [
                _result(meta={"attributed_actor": "APT-A",
                              "attribution_confidence": "high"}),
                _result(meta={"attributed_actor": "APT-B",
                              "attribution_confidence": "low"}),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        meta = merged["report_metadata"]
        assert [a["name"] for a in meta["actors"]] == ["APT-A", "APT-B"]
        assert meta["attributed_actor"] == "APT-A", "the scalar is unchanged"

    def test_each_actor_keeps_the_confidence_stated_with_it(self):
        """Attribution confidence is per actor, not per report: a later section
        qualifying an earlier assertion is the case this exists for, and one
        report-level scalar cannot carry it."""
        merged = _merge(
            [
                _result(meta={"attributed_actor": "APT-A",
                              "attribution_confidence": "high"}),
                _result(meta={"attributed_actor": "APT-B",
                              "attribution_confidence": "low"}),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        actors = merged["report_metadata"]["actors"]
        assert [a["confidence"] for a in actors] == ["high", "low"]
        assert [a["batch_label"] for a in actors] == ["chunk 1/2", "chunk 2/2"]

    def test_a_later_batch_fills_a_field_the_first_left_blank(self):
        """The defect behind the actor loss: object-at-a-time first-wins meant
        a batch that recognised only the title discarded the batch that
        identified the actor."""
        merged = _merge(
            [
                _result(meta={"title": "Operation Something"}),
                _result(meta={"attributed_actor": "APT-B",
                              "source_organization": "SomeVendor"}),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        meta = merged["report_metadata"]
        assert meta["title"] == "Operation Something"
        assert meta["attributed_actor"] == "APT-B"
        assert meta["source_organization"] == "SomeVendor"

    def test_an_empty_value_does_not_claim_a_field(self):
        """A model that emits the key with an empty string has not answered."""
        merged = _merge(
            [
                _result(meta={"attributed_actor": "", "title": "T"}),
                _result(meta={"attributed_actor": "APT-B"}),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        assert merged["report_metadata"]["attributed_actor"] == "APT-B"
        assert [a["name"] for a in merged["report_metadata"]["actors"]] == [
            "APT-B",
        ]

    def test_the_same_actor_twice_is_one_actor(self):
        """Every batch covering the campaign restates its actor; that is
        restatement, not a second group."""
        merged = _merge(
            [
                _result(meta={"attributed_actor": "APT-A"}),
                _result(meta={"attributed_actor": "apt-a"}),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        assert len(merged["report_metadata"]["actors"]) == 1

    def test_campaigns_are_collected_the_same_way(self):
        merged = _merge(
            [
                _result(meta={"campaign_name": "Op One"}),
                _result(meta={"campaign_name": "Op Two"}),
            ],
            [_prov("chunk 1/2", 1), _prov("chunk 2/2", 2)],
        )
        meta = merged["report_metadata"]
        assert [c["name"] for c in meta["campaigns"]] == ["Op One", "Op Two"]
        assert meta["campaign_name"] == "Op One"

    def test_no_metadata_stays_empty(self):
        """A run that reported nothing does not grow two empty lists nobody
        wrote."""
        merged = _merge([_result()], [_prov("chunk 1/1", 1)])
        assert merged["report_metadata"] == {}

    def test_a_second_actor_does_not_make_the_run_partial(self):
        """Two groups in one report is complete work, not a caveat about it.
        Every note but NO INDICATORS ACCEPTED forces `partial`, so this
        deliberately reaches the reader through report_metadata instead."""
        fields = _tool_mod._analysis_fields(
            ingestion_mode="llm", pages_total=3, pages_read=3,
            truncated_chunks=[],
        )
        assert fields["analysis_status"] == "complete"
        assert fields["analysis_notes"] == []


class TestTheSummaryNamesEveryActor:
    def _summary(self, meta):
        class _R:
            ok = True
            message = None
            output_artifacts = []
            result = {
                "report_metadata": meta,
                "summary": {"total_iocs": 0, "ioc_breakdown": {}},
                "mitre_mappings": [],
                "iocs": [],
            }
        return _tool_mod.ThreatIntelIngester().summarize_for_llm(_R())

    def test_a_second_actor_is_named(self):
        """summarize_for_llm is what downstream reasoning actually sees. A
        single-actor line there reads as the report's whole attribution."""
        text = self._summary({
            "attributed_actor": "APT-A", "attribution_confidence": "high",
            "actors": [
                {"name": "APT-A", "confidence": "high"},
                {"name": "APT-B", "confidence": "low"},
            ],
            "campaigns": [],
        })
        assert "APT-A" in text
        assert "APT-B" in text

    def test_one_actor_reads_exactly_as_before(self):
        text = self._summary({
            "attributed_actor": "APT-A", "attribution_confidence": "high",
            "actors": [{"name": "APT-A", "confidence": "high"}],
            "campaigns": [],
        })
        assert "elsewhere in the report" not in text


# ---------------------------------------------------------------------------
# End to end, through execute
# ---------------------------------------------------------------------------
#
# Driving `_merge_llm_chunk_results` proves the merge keeps the evidence. It
# proves nothing about whether the result the caller builds still carries it -
# the assembly at the end of `execute` reads named keys off the merged
# metadata, and a merge that collects actors nobody copies out is a merge
# whose work is thrown away one function later. Stage 2 has already been
# caught by exactly that: two tests passed on the fix and on the defect
# because they drove a helper rather than a run.


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
    session_id: str = "test_session_graphattr"
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


class _TwoSectionsDisagreeLLM:
    """Each chunk names its own actor and campaign, and both coin the same
    path slug for structurally different paths.

    This is the shape a real multi-section report produces: separate calls,
    each seeing part of the document, each naming what it saw.
    """

    def __init__(self):
        self.calls = 0

    def supports_native_document(self, mime_type: str) -> bool:
        return False

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.calls += 1
        n = self.calls
        if n == 1:
            meta = {"title": "Operation Something",
                    "attributed_actor": "APT-A",
                    "attribution_confidence": "high",
                    "campaign_name": "Op One"}
            steps = [_step("T1566", "Initial Access", ["T1059"]),
                     _step("T1059")]
        else:
            meta = {"attributed_actor": "APT-B",
                    "attribution_confidence": "low",
                    "campaign_name": "Op Two",
                    "source_organization": "SomeVendor"}
            steps = [_step("T1190", "Initial Access", ["T1505.003"]),
                     _step("T1505.003", "Persistence")]
        return _Resp(text=json.dumps({
            "refined_iocs": [
                {"value": v, "ioc_type": "ip", "confidence": "high",
                 "priority": "medium", "context": "c2", "related_mitre": [],
                 "is_false_positive": False}
                for v in _prompt_candidates(prompt)
            ],
            "additional_mitre_techniques": [],
            "report_metadata": meta,
            "attack_graph": {
                "paths": [_path("initial-access-to-exfil", steps)],
                "convergence_points": [], "branch_points": [],
            },
        }))


def _prompt_candidates(prompt):
    return [
        line.split("- [ip] ", 1)[1].split(" |", 1)[0]
        for line in prompt.splitlines() if line.startswith("- [ip] ")
    ]


@pytest.fixture
def two_chunk_run(tmp_path, monkeypatch):
    """A text report long enough to need two LLM chunks."""
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    filler = "Narrative about the intrusion. " * 260  # > 6000 chars per half
    body = (
        f"Beaconing to 198.51.100.1 over 443.\n\n{filler}\n\n"
        f"Second stage reached 203.0.113.9 on 8443.\n\n{filler}\n"
    )
    report = tmp_path / "report.txt"
    report.write_text(body, encoding="utf-8")
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
            artifacts=[artifact], llm_enabled=True, llm_query=llm,
            register_artifact=register,
        )
        result = tool.execute({"artifact_id": "art_txt"}, ctx)
        assert result.ok, result.message
        return result

    return go


class TestTheResultCarriesWhatTheMergeKept:
    def test_both_actors_reach_the_returned_result(self, two_chunk_run):
        llm = _TwoSectionsDisagreeLLM()
        result = two_chunk_run(_tool_mod.ThreatIntelIngester(), llm)
        assert llm.calls >= 2, "the fixture must actually produce two chunks"
        meta = result.result["report_metadata"]
        assert [a["name"] for a in meta["actors"]] == ["APT-A", "APT-B"]
        assert meta["attributed_actor"] == "APT-A"

    def test_both_campaigns_reach_the_returned_result(self, two_chunk_run):
        result = two_chunk_run(
            _tool_mod.ThreatIntelIngester(), _TwoSectionsDisagreeLLM(),
        )
        meta = result.result["report_metadata"]
        assert [c["name"] for c in meta["campaigns"]] == ["Op One", "Op Two"]
        assert meta["campaign_name"] == "Op One"

    def test_a_later_chunk_still_fills_a_field_the_first_left_blank(
        self, two_chunk_run,
    ):
        result = two_chunk_run(
            _tool_mod.ThreatIntelIngester(), _TwoSectionsDisagreeLLM(),
        )
        meta = result.result["report_metadata"]
        assert meta["title"] == "Operation Something"
        assert meta["source_organization"] == "SomeVendor"

    def test_both_colliding_paths_reach_the_returned_result(self, two_chunk_run):
        result = two_chunk_run(
            _tool_mod.ThreatIntelIngester(), _TwoSectionsDisagreeLLM(),
        )
        paths = result.result["attack_graph"]["paths"]
        assert len(paths) == 2, "the second path is no longer dropped"
        assert len({p["path_id"] for p in paths}) == 2
        assert result.result["summary"]["merge_stats"]["paths_namespaced"] == 1

    def test_the_run_is_still_complete(self, two_chunk_run):
        """Two actors and a slug collision are things the report contained,
        not things that went wrong while reading it."""
        result = two_chunk_run(
            _tool_mod.ThreatIntelIngester(), _TwoSectionsDisagreeLLM(),
        )
        assert result.result["summary"]["analysis_status"] == "complete"
