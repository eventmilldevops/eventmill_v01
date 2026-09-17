"""Contract tests for stage N1 of attack path normalization.

Section 7 and 7a of ``docs/specs/attack_path_detection_normalization.md``.
Every test runs without a provider, a network or a flow map.

The fixtures are copies of four real projector export pairs, all produced on
one code revision against flow maps that live in this repository. Copies, not
builders: a builder re-derives the fixture from the same assumptions the
normalizer encodes, so it cannot catch a misreading of a real export.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
FIXTURES = PLUGIN_DIR / "tests" / "fixtures"


def _load_normalization():
    name = "attack_path_detection_designer_normalization"
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "normalization.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


nz = _load_normalization()

# stamp -> (graph nodes, gap nodes). The counts are the N1 acceptance gate.
CORPUS = {
    "20260917_022646": 9,
    "20260917_122549": 11,
    "20260917_123525": 10,
    "20260917_124121": 13,
}
TOTAL_NODES = 43


def _read(stamp: str, role: str) -> dict:
    prefix = "path_graph" if role == "graph" else "scenario_seed"
    path = FIXTURES / f"{prefix}_{stamp}.json"
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _doc(stamp: str, role: str, document: dict | None = None):
    prefix = "path_graph" if role == "graph" else "scenario_seed"
    return nz.load_document(
        document if document is not None else _read(stamp, role),
        f"{prefix}_{stamp}.json",
    )


def _pair(stamp: str):
    return _doc(stamp, "graph"), _doc(stamp, "seed")


# ---------------------------------------------------------------------------
# Identity and the N1 gate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stamp,expected", sorted(CORPUS.items()))
def test_graph_only_and_seed_only_yield_the_same_node_keys(stamp, expected):
    """The gate: each supplied input independently produces the same keys."""
    graph, seed = _pair(stamp)
    from_graph = nz.normalize(graph)
    from_seed = nz.normalize(seed)
    joined = nz.normalize(graph, seed)

    assert len(joined.nodes) == expected
    assert from_graph.node_keys == from_seed.node_keys == joined.node_keys
    assert [n.draft_id for n in from_graph.nodes] == [
        n.draft_id for n in from_seed.nodes
    ]


def test_corpus_totals_forty_three_nodes():
    total = sum(len(nz.normalize(*_pair(stamp)).nodes) for stamp in CORPUS)
    assert total == TOTAL_NODES


def test_the_three_identities_are_distinct_on_a_verified_pair():
    graph, seed = _pair("20260917_122549")
    assert graph.artifact.value != seed.artifact.value  # per document, by design
    assert graph.projection.value == seed.projection.value  # per run
    assert graph.projection.status == "verified"

    result = nz.normalize(graph, seed)
    keys = {node.key for node in result.nodes}
    assert len(keys) == len(result.nodes)  # occurrence keys are unique


def test_draft_id_does_not_depend_on_which_document_supplied_the_node():
    graph, seed = _pair("20260917_124121")
    ids_graph = [n.draft_id for n in nz.normalize(graph).nodes]
    ids_seed = [n.draft_id for n in nz.normalize(seed).nodes]
    ids_pair = [n.draft_id for n in nz.normalize(graph, seed).nodes]
    assert ids_graph == ids_seed == ids_pair
    assert len(set(ids_pair)) == len(ids_pair)


def test_actor_is_the_only_variable_and_identities_still_differ():
    """Same flow map, same hash, same application, different actor.

    Identity must derive from the projection, not from the estate.
    """
    fox = _doc("20260917_022646", "graph")
    spider = _doc("20260917_122549", "graph")
    assert fox.document["application"] == spider.document["application"]
    assert (
        fox.document["provenance"]["flow_map_sha256"]
        == spider.document["provenance"]["flow_map_sha256"]
    )
    assert fox.projection.value != spider.projection.value

    fox_keys = {n.key for n in nz.normalize(fox).nodes}
    spider_keys = {n.key for n in nz.normalize(spider).nodes}
    assert not (fox_keys & spider_keys)


# ---------------------------------------------------------------------------
# Node identity rules, section 1.1
# ---------------------------------------------------------------------------

def test_no_within_path_technique_component_repeat_in_the_corpus():
    """Records the property the synthetic case below has to stand in for."""
    for stamp in CORPUS:
        document = _read(stamp, "graph")
        for path in document["attack_graph"]["paths"]:
            pairs = [(s["technique_id"], s["component_id"]) for s in path["steps"]]
            assert len(pairs) == len(set(pairs))


def test_a_within_path_repeat_survives_as_two_nodes():
    """Synthetic, because no real fixture exercises it.

    Derived from the committed fixture rather than stored as a near-duplicate:
    relabel one step so it duplicates an earlier step of the same path exactly.
    A repeated pair is legitimate modelling, not a defect, so no warning fires.
    """
    document = copy.deepcopy(_read("20260917_124121", "graph"))
    path = next(
        p
        for p in document["attack_graph"]["paths"]
        if p["path_id"] == "portal-api-docstore"
    )
    donor = path["steps"][0]
    victim = path["steps"][3]
    victim["technique_id"] = donor["technique_id"]
    victim["component_id"] = donor["component_id"]

    result = nz.normalize(_doc("20260917_124121", "graph", document))
    repeated = [
        n
        for n in result.nodes
        if n.path_id == "portal-api-docstore"
        and n.fields["technique_id"] == donor["technique_id"]
        and n.fields["component_id"] == donor["component_id"]
    ]
    assert len(repeated) == 2
    assert repeated[0].node_index != repeated[1].node_index
    assert repeated[0].draft_id != repeated[1].draft_id
    assert result.warnings == []


def test_cross_path_repeats_stay_distinct():
    """T1190@portal, T1552@portal and T1078@claims_api each occur twice."""
    result = nz.normalize(*_pair("20260917_124121"))
    seen = [(n.fields["technique_id"], n.fields["component_id"]) for n in result.nodes]
    assert len(seen) != len(set(seen))  # the corpus really does repeat across paths
    assert len({n.key for n in result.nodes}) == len(result.nodes)


def test_event_ids_restart_per_scenario_and_do_not_collide():
    result = nz.normalize(*_pair("20260917_123525"))
    first_events = [
        n for n in result.nodes if n.fields.get("source_event_id") == "AE-0001"
    ]
    assert len(first_events) == 2  # one per path
    assert len({n.key for n in first_events}) == 2


# ---------------------------------------------------------------------------
# Pair gating, section 4.2
# ---------------------------------------------------------------------------

def test_a_verified_pair_joins_on_run_id_without_a_flag():
    result = nz.normalize(*_pair("20260917_022646"))
    assert result.pair["provenance_status"] == "verified"
    assert result.pair["pair_join"] == "run_id"
    assert result.pair["verified"] is True


def test_a_pair_from_two_different_runs_is_refused():
    graph = _doc("20260917_122549", "graph")
    seed = _doc("20260917_124121", "seed")
    result = nz.normalize(graph, seed)
    assert result.pair["join"] is False
    assert result.pair["provenance_status"] == "conflict"
    assert any(w["code"] == "PAIR_REFUSED" for w in result.warnings)
    # The primary source is still processed alone.
    assert len(result.nodes) == CORPUS["20260917_122549"]


def test_cross_fixture_contamination_is_refused_even_on_the_same_flow_map():
    """Fox Kitten graph with Scattered Spider seed: same map, same hash."""
    graph = _doc("20260917_022646", "graph")
    seed = _doc("20260917_122549", "seed")
    result = nz.normalize(graph, seed)
    assert result.pair["join"] is False
    assert len(result.nodes) == CORPUS["20260917_022646"]


def _strip_provenance(stamp: str, role: str) -> dict:
    document = copy.deepcopy(_read(stamp, role))
    document.pop("provenance", None)
    return document


def test_legacy_documents_derive_an_equal_projection_identity():
    """No fixture lacks provenance any more, so the legacy case is synthetic."""
    stripped_graph = _strip_provenance("20260917_122549", "graph")
    stripped_seed = _strip_provenance("20260917_122549", "seed")
    graph = _doc("20260917_122549", "graph", stripped_graph)
    seed = _doc("20260917_122549", "seed", stripped_seed)
    assert graph.projection.status == "derived"
    assert graph.projection.value == seed.projection.value

    refused = nz.normalize(graph, seed)
    assert refused.pair["join"] is False
    assert refused.pair["provenance_status"] == "derived"

    joined = nz.normalize(graph, seed, accept_unverified_pair=True)
    assert joined.pair["join"] is True
    assert joined.pair["pair_join"] == "asserted_by_operator"
    assert joined.pair["provenance_status"] == "derived"  # never upgraded to verified
    assert len(joined.nodes) == CORPUS["20260917_122549"]


def test_a_derived_identity_still_separates_two_different_projections():
    graph = _doc(
        "20260917_122549", "graph", _strip_provenance("20260917_122549", "graph")
    )
    seed = _doc(
        "20260917_124121", "seed", _strip_provenance("20260917_124121", "seed")
    )
    assert graph.projection.value != seed.projection.value
    assert nz.normalize(graph, seed, accept_unverified_pair=True).pair["join"] is False


def test_a_mixed_pair_is_refused():
    """One document with provenance and one without has nothing to check."""
    graph = _doc("20260917_122549", "graph")
    seed = _doc("20260917_122549", "seed", _strip_provenance("20260917_122549", "seed"))
    result = nz.normalize(graph, seed)
    assert result.pair["join"] is False
    assert "provenance" in (result.pair["reason"] or "")


def test_two_documents_of_the_same_role_are_not_a_pair():
    first = _doc("20260917_122549", "graph")
    second = _doc("20260917_122549", "graph")
    assert nz.normalize(first, second).pair["join"] is False


# ---------------------------------------------------------------------------
# Provenance field names, read from the export not the draft
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stamp", sorted(CORPUS))
def test_provenance_names_match_the_export(stamp):
    provenance = _read(stamp, "graph")["provenance"]
    assert "actor_attack_id" in provenance
    assert "actor_attck_id" not in provenance
    # There is no provider key at this level; attribution lives inside model.
    assert "provider" not in provenance
    assert provenance["model"]["provider"]
    assert provenance["model"]["model_configured"]
    assert provenance["model"]["model_served"]


@pytest.mark.parametrize("stamp", sorted(CORPUS))
def test_engagement_reads_model_and_not_provider(stamp):
    result = nz.normalize(*_pair(stamp))
    engagement = result.engagement
    assert engagement["model_attribution_present"] is True
    assert engagement["model_attribution"]["vendor"]
    assert engagement["actor_attack_id"].startswith("G")
    assert engagement["attack_version"] == "19.2"


def test_absent_model_is_distinguished_from_a_null_one():
    document = copy.deepcopy(_read("20260917_122549", "graph"))
    document["provenance"].pop("model")
    absent = nz.normalize(_doc("20260917_122549", "graph", document))
    assert absent.engagement["model_attribution_present"] is False
    assert absent.engagement["model_attribution"] is None


# ---------------------------------------------------------------------------
# Canonicalization, rule 3a
# ---------------------------------------------------------------------------

def test_state_check_joins_on_every_node_of_the_corpus():
    """43 of 43 match byte-for-byte, 0 conflicts, 9 of them gap nodes."""
    matched = 0
    gaps = 0
    for stamp in CORPUS:
        result = nz.normalize(*_pair(stamp))
        assert not [
            c for c in result.input_conflicts if c["draft_field"] == "state_check"
        ]
        for node in result.nodes:
            rebuilt = nz.join_state_check(
                node.fields["state_check"], node.fields["state_note"]
            )
            assert rebuilt == node.fields["state_check_raw"]
            matched += 1
            if node.fields["state_check"] == "gap":
                gaps += 1
                assert node.fields["state_note"]
    assert matched == TOTAL_NODES
    assert gaps == 9


def test_the_separator_is_an_em_dash():
    assert nz.STATE_NOTE_SEPARATOR == " — "
    assert nz.split_state_check("gap — needs code_execution") == (
        "gap",
        "needs code_execution",
    )
    assert nz.split_state_check("ok") == ("ok", "")


def test_a_mangled_separator_raises_an_encoding_warning_not_conflicts():
    """A transport that cannot carry U+2014 must not produce content conflicts."""
    document = copy.deepcopy(_read("20260917_122549", "seed"))
    mangled = 0
    for scenario in document["scenarios"]:
        for event in scenario["attack_sequence"]:
            if " — " in (event.get("state_check") or ""):
                event["state_check"] = event["state_check"].replace(" — ", " - ")
                mangled += 1
    assert mangled == 3

    graph = _doc("20260917_122549", "graph")
    seed = _doc("20260917_122549", "seed", document)
    result = nz.normalize(graph, seed)
    encoding = [w for w in result.warnings if w["code"] == "STATE_NOTE_ENCODING"]
    assert len(encoding) == mangled
    # The note survives on the graph side, so the finding is not lost.
    gap_nodes = [n for n in result.nodes if n.fields["state_check"] == "gap"]
    assert all(n.fields["state_note"] for n in gap_nodes)


def test_a_gap_node_keeps_its_continuity_finding():
    result = nz.normalize(*_pair("20260917_022646"))
    gap = [n for n in result.nodes if n.fields["state_check"] == "gap"]
    assert len(gap) == 1
    assert gap[0].path_id == "scm-to-vault"
    assert "network_reach" in gap[0].fields["state_note"]


# ---------------------------------------------------------------------------
# Transition, the second canonicalization
# ---------------------------------------------------------------------------

def test_all_transition_shapes_and_both_readings_of_null():
    counts = {"entry": 0, "declared_flow": 0, "in_place": 0, "undeclared": 0}
    for stamp in CORPUS:
        for node in nz.normalize(*_pair(stamp)).nodes:
            counts[node.fields["transition"]["movement"]] += 1
    assert counts == {"entry": 8, "declared_flow": 18, "in_place": 16, "undeclared": 1}


def test_in_place_is_not_reported_as_missing_data():
    result = nz.normalize(*_pair("20260917_124121"))
    in_place = [
        n for n in result.nodes if n.fields["transition"]["movement"] == "in_place"
    ]
    assert in_place
    for node in in_place:
        assert node.review_flags == []


def test_an_undeclared_transition_raises_a_review_flag():
    result = nz.normalize(*_pair("20260917_123525"))
    flagged = [
        n
        for n in result.nodes
        if any(f["code"] == "UNDECLARED_TRANSITION" for f in n.review_flags)
    ]
    assert len(flagged) == 1
    assert flagged[0].path_id == "phishing-to-blob"
    assert flagged[0].node_index == 2
    assert flagged[0].fields["component_id"] == "entry_api"


def test_the_graph_object_wins_and_the_seed_prose_is_kept():
    result = nz.normalize(*_pair("20260917_124121"))
    flows = [
        n for n in result.nodes if n.fields["transition"]["movement"] == "declared_flow"
    ]
    assert flows
    node = flows[0]
    assert node.fields["transition"]["evidence"] == "structured"
    assert isinstance(node.fields["transition_raw"], str)
    assert node.provenance_by_field["transition"]["role"] == "graph"
    assert node.provenance_by_field["transition_raw"]["role"] == "seed"


def test_the_seed_prose_cannot_carry_crosses_boundary():
    """Which is why a representation difference is never a conflict here."""
    parsed = nz.canonical_transition(
        "flow f4: partner_api -> event_bus (kafka, authenticated)",
        component_id="event_bus",
        previous_component_id="partner_api",
        source=nz.SEED_ROLE,
    )
    assert parsed["movement"] == "declared_flow"
    assert parsed["crosses_boundary"] is None
    assert parsed["evidence"] == "text"

    structured = nz.canonical_transition(
        {
            "flow": "f4",
            "from": "partner_api",
            "to": "event_bus",
            "protocol": "kafka",
            "authenticated": True,
            "crosses_boundary": False,
        },
        component_id="event_bus",
        previous_component_id="partner_api",
        source=nz.GRAPH_ROLE,
    )
    assert nz.transitions_agree(structured, parsed)


def test_transition_representation_difference_produces_no_conflicts():
    for stamp in CORPUS:
        result = nz.normalize(*_pair(stamp))
        assert not [
            c for c in result.input_conflicts if c["draft_field"] == "transition"
        ]


# ---------------------------------------------------------------------------
# Union merge and precedence, section 4.3
# ---------------------------------------------------------------------------

def test_union_merge_keeps_what_each_document_alone_carries():
    result = nz.normalize(*_pair("20260917_122549"))
    node = result.nodes[0]
    graph_only = ("component_id", "mitigations", "uncovered_mitigations",
                  "controls_in_play")
    for name in graph_only:
        assert name in node.fields
        assert node.provenance_by_field[name]["role"] == "graph"
    seed_only = ("source_event_id", "sequence_order", "access_source",
                 "success_indicators")
    for name in seed_only:
        assert name in node.fields
        assert node.provenance_by_field[name]["role"] == "seed"


def test_every_field_carries_an_origin_and_a_pointer():
    result = nz.normalize(*_pair("20260917_123525"))
    for node in result.nodes:
        assert set(node.provenance_by_field) >= set(node.fields)
        for name, entry in node.provenance_by_field.items():
            assert entry["origin"] in {"graph", "seed", "pair_agreed", "derived"}
            assert entry["pointer"].startswith("/")
            assert entry["document"]


def test_a_shared_field_that_agrees_is_recorded_pair_agreed():
    result = nz.normalize(*_pair("20260917_022646"))
    node = result.nodes[0]
    assert node.provenance_by_field["technique_id"]["origin"] == "pair_agreed"
    assert node.provenance_by_field["tactic"]["origin"] == "pair_agreed"


def test_a_shared_field_that_disagrees_conflicts_and_keeps_the_graph_value():
    document = copy.deepcopy(_read("20260917_122549", "seed"))
    event = document["scenarios"][0]["attack_sequence"][1]
    original = event["precondition"]
    event["precondition"] = "mutated for the precedence test"

    graph = _doc("20260917_122549", "graph")
    seed = _doc("20260917_122549", "seed", document)
    result = nz.normalize(graph, seed)

    conflicts = [
        c for c in result.input_conflicts if c["draft_field"] == "precondition"
    ]
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict["kept"] == original
    assert conflict["rejected"] == "mutated for the precedence test"
    assert conflict["kept_pointer"].startswith("/attack_graph/")
    assert conflict["rejected_pointer"].startswith("/scenarios/")

    node = next(
        n
        for n in result.nodes
        if n.node_index == 1 and n.path_id == conflict["path_id"]
    )
    assert node.fields["precondition"] == original
    # The join happened, but it is not reported verified.
    assert result.pair["join"] is True
    assert result.pair["verified"] is False
    assert any(w["code"] == "PAIR_CONTENT_CONFLICT" for w in result.warnings)


def test_pointers_name_the_real_source_key():
    result = nz.normalize(*_pair("20260917_124121"))
    node = result.nodes[0]
    assert node.provenance_by_field["asset_name"]["pointer"].endswith("/asset")
    assert node.provenance_by_field["expected_result"]["pointer"].endswith("/result")
    assert node.provenance_by_field["source_event_id"]["pointer"].endswith("/event_id")


# ---------------------------------------------------------------------------
# Single-source behaviour
# ---------------------------------------------------------------------------

def test_a_single_scenario_normalizes_on_its_own():
    seed = _read("20260917_124121", "seed")
    scenario = seed["scenarios"][0]
    document = dict(scenario)
    document["actor"] = seed["actor"]
    document["application"] = seed["application"]
    document["provenance"] = seed["provenance"]

    source = nz.load_document(document, "single_scenario.json")
    assert source.role == nz.SCENARIO_ROLE
    result = nz.normalize(source)
    assert len(result.nodes) == len(scenario["attack_sequence"])
    assert all(node.fields.get("component_id") is None for node in result.nodes)


def test_seed_only_input_carries_no_component_id():
    """Which is why scenario-only input can never bind to an estate."""
    result = nz.normalize(_doc("20260917_122549", "seed"))
    assert all("component_id" not in n.fields for n in result.nodes)
    assert all(n.fields["asset_name"] for n in result.nodes)


def test_normalizing_is_deterministic():
    first = nz.normalize(*_pair("20260917_123525")).as_dict()
    second = nz.normalize(*_pair("20260917_123525")).as_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_an_unrecognized_document_is_refused():
    with pytest.raises(nz.NormalizationError):
        nz.load_document({"source_tool": "something_else"}, "x.json")
