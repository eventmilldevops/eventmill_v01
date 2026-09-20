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


@pytest.mark.parametrize("with_map", [False, True])
def test_every_field_carries_an_origin_and_a_pointer(with_map):
    """Enriched fields are held to the same rule as the exports' own.

    A derived field has no document to point at, so it names the fields it was
    computed from instead — the question every field must answer is where its
    value came from, not which file it was copied out of.
    """
    flow_map = _map(MAP_FOR_STAMP["20260917_123525"]) if with_map else None
    result = nz.normalize(*_pair("20260917_123525"), flow_map=flow_map)
    for node in result.nodes:
        assert set(node.provenance_by_field) >= set(node.fields)
        for name, entry in node.provenance_by_field.items():
            assert entry["origin"] in {
                "graph", "seed", "pair_agreed", "derived", "flow_map",
                "reference_data",
            }
            if entry["origin"] == "derived":
                assert entry["basis"]
                continue
            if entry["origin"] == "seed" and not entry["pointer"]:
                assert name == "control_catalogue"  # no per-node pointer exists
                continue
            assert entry["pointer"].startswith("/")
            assert entry["document"]
            if entry["origin"] == "flow_map":
                assert entry["flow_map_lineage"] == result.flow_map["lineage"]


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


# ---------------------------------------------------------------------------
# Flow map lineage, stage N2 (section 4.2, decision 9)
# ---------------------------------------------------------------------------

FLOW_MAPS = FIXTURES / "flow_maps"

# Which repository map each run was projected against, per its provenance.
MAP_FOR_STAMP = {
    "20260917_022646": "telemetry_saas_flow_map.json",
    "20260917_122549": "telemetry_saas_flow_map.json",
    "20260917_123525": "application_b_flow_map.json",
    "20260917_124121": "claims_portal_flow_map.json",
}

FLOW_MAP_CODES = {
    "FLOW_MAP_EDITED",
    "FLOW_MAP_UNHASHED",
    "FLOW_MAP_APPLICATION_MISMATCH",
    "FLOW_MAP_COMPONENT_UNRESOLVED",
}


def _read_map(filename: str) -> dict:
    with open(FLOW_MAPS / filename, encoding="utf-8") as handle:
        return json.load(handle)


def _map(filename: str, document: dict | None = None):
    return nz.load_flow_map(
        document if document is not None else _read_map(filename), filename
    )


def _codes(result) -> list[str]:
    return [w["code"] for w in result.warnings]


@pytest.mark.parametrize("stamp", sorted(MAP_FOR_STAMP))
@pytest.mark.parametrize("role", ["graph", "seed"])
def test_the_projector_hash_is_reproduced_from_the_repository_maps(stamp, role):
    """Plugins cannot share code, so this is the check that the two agree."""
    recorded = _read(stamp, role)["provenance"]["flow_map_sha256"]
    assert nz.flow_map_hash(_read_map(MAP_FOR_STAMP[stamp])) == recorded


@pytest.mark.parametrize("stamp", sorted(MAP_FOR_STAMP))
def test_the_projected_map_reads_same_map_and_fits(stamp):
    result = nz.normalize(*_pair(stamp), flow_map=_map(MAP_FOR_STAMP[stamp]))
    record = result.flow_map
    assert record["supplied"] is True
    assert record["lineage"] == nz.LINEAGE_SAME
    assert record["application_matches"] is True
    assert record["components_unresolved"] == []
    assert record["components_resolved"]
    assert not FLOW_MAP_CODES & set(_codes(result))


def test_an_edited_map_is_recorded_and_used_not_refused():
    """The analyst's corrected copy is the expected case, not a conflict."""
    stamp = "20260917_124121"
    edited = copy.deepcopy(_read_map(MAP_FOR_STAMP[stamp]))
    edited["components"][0]["controls"].append(
        {"name": "WAF rule added from inside knowledge", "control_type": "perimeter"}
    )
    baseline = nz.normalize(*_pair(stamp))
    result = nz.normalize(*_pair(stamp), flow_map=_map("edited.json", edited))

    assert result.flow_map["lineage"] == nz.LINEAGE_EDITED
    edited_warnings = [w for w in result.warnings if w["code"] == "FLOW_MAP_EDITED"]
    assert len(edited_warnings) == 1
    assert edited_warnings[0]["severity"] == nz.SEVERITY_ADVISORY
    assert result.flow_map["components_unresolved"] == []
    # Nothing downstream moves because the map was edited.
    assert result.pair["verified"] is True
    assert [n.draft_id for n in result.nodes] == [n.draft_id for n in baseline.nodes]


def test_reordering_or_reformatting_a_map_is_not_an_edit():
    stamp = "20260917_123525"
    original = _read_map(MAP_FOR_STAMP[stamp])
    reordered = dict(reversed(list(original.items())))
    reparsed = json.loads(json.dumps(reordered, indent=4))
    result = nz.normalize(_doc(stamp, "graph"), flow_map=_map("copy.json", reparsed))
    assert result.flow_map["lineage"] == nz.LINEAGE_SAME


def test_an_export_without_a_hash_needs_no_operator_flag():
    stamp = "20260917_122549"
    graph_document = copy.deepcopy(_read(stamp, "graph"))
    seed_document = copy.deepcopy(_read(stamp, "seed"))
    for document in (graph_document, seed_document):
        del document["provenance"]["flow_map_sha256"]
    graph = _doc(stamp, "graph", graph_document)
    seed = _doc(stamp, "seed", seed_document)

    result = nz.normalize(graph, seed, flow_map=_map(MAP_FOR_STAMP[stamp]))
    assert result.flow_map["lineage"] == nz.LINEAGE_UNHASHED
    assert result.flow_map["export_sha256"] is None
    assert "FLOW_MAP_UNHASHED" in _codes(result)
    assert result.pair["verified"] is True  # the run_id join is untouched


def test_the_wrong_map_is_told_apart_by_fit_not_by_hash():
    """Hash alone reads a foreign map as edited; application and components
    are what say it is the wrong estate."""
    result = nz.normalize(
        *_pair("20260917_122549"), flow_map=_map("claims_portal_flow_map.json")
    )
    record = result.flow_map
    assert record["lineage"] == nz.LINEAGE_EDITED
    assert record["application_matches"] is False
    assert record["components_resolved"] == []
    assert record["components_unresolved"]
    codes = _codes(result)
    assert "FLOW_MAP_APPLICATION_MISMATCH" in codes
    assert codes.count("FLOW_MAP_COMPONENT_UNRESOLVED") == len(
        record["components_unresolved"]
    )


def test_a_removed_component_is_reported_per_component_with_its_node_count():
    stamp = "20260917_124121"
    trimmed = copy.deepcopy(_read_map(MAP_FOR_STAMP[stamp]))
    trimmed["components"] = [
        c for c in trimmed["components"] if c["id"] != "doc_store"
    ]
    result = nz.normalize(*_pair(stamp), flow_map=_map("trimmed.json", trimmed))

    expected_nodes = sum(
        1 for n in result.nodes if n.fields.get("component_id") == "doc_store"
    )
    assert expected_nodes > 0
    assert result.flow_map["components_unresolved"] == ["doc_store"]
    unresolved = [
        w for w in result.warnings if w["code"] == "FLOW_MAP_COMPONENT_UNRESOLVED"
    ]
    assert len(unresolved) == 1
    assert unresolved[0]["severity"] == nz.SEVERITY_BLOCKING
    assert unresolved[0]["location"] == "doc_store"
    assert f"{expected_nodes} node(s)" in unresolved[0]["message"]
    assert result.flow_map["application_matches"] is True


def test_without_a_map_the_record_still_says_which_map_would_bind():
    stamp = "20260917_022646"
    result = nz.normalize(*_pair(stamp))
    record = result.flow_map
    assert record["supplied"] is False
    assert record["export_sha256"] == _read(stamp, "graph")["provenance"][
        "flow_map_sha256"
    ]
    assert "lineage" not in record
    assert not FLOW_MAP_CODES & set(_codes(result))


def test_seed_only_input_has_no_components_to_resolve():
    stamp = "20260917_124121"
    result = nz.normalize(_doc(stamp, "seed"), flow_map=_map(MAP_FOR_STAMP[stamp]))
    assert result.flow_map["lineage"] == nz.LINEAGE_SAME
    assert result.flow_map["components_resolved"] == []
    assert result.flow_map["components_unresolved"] == []


@pytest.mark.parametrize(
    "document",
    [[], "flow map", {"application": "Claims Portal"}, {"components": "none"}],
)
def test_something_that_is_not_a_flow_map_is_refused(document):
    with pytest.raises(nz.FlowMapError):
        nz.load_flow_map(document, "not_a_map.json")


# ---------------------------------------------------------------------------
# The closed code catalogue, section 4.4
# ---------------------------------------------------------------------------

SPEC = PLUGIN_DIR.parents[2] / "docs" / "specs" / "attack_path_detection_normalization.md"


def test_every_warning_carries_its_catalogue_severity():
    graph = _doc("20260917_122549", "graph")
    seed = _doc("20260917_124121", "seed")
    results = [
        nz.normalize(graph, seed),
        nz.normalize(
            *_pair("20260917_122549"), flow_map=_map("claims_portal_flow_map.json")
        ),
    ]
    warnings = [w for result in results for w in result.warnings]
    assert warnings
    for warning in warnings:
        assert warning["severity"] == nz.WARNING_CODES[warning["code"]]


def test_an_undeclared_code_cannot_be_emitted():
    with pytest.raises(KeyError):
        nz._warning("SOMETHING_NEW", "x", "y")
    with pytest.raises(KeyError):
        nz._review_flag("SOMETHING_NEW", "y")


# ---------------------------------------------------------------------------
# Flow-map join and grading, stage N3a (sections 4.3 rule 4 and 5)
# ---------------------------------------------------------------------------

# Section 5, restated over the 2026-09-17 corpus.
PARTIAL_COMPONENTS = {"users", "front_door", "claims_db", "doc_store"}


def _joined(stamp: str):
    return nz.normalize(*_pair(stamp), flow_map=_map(MAP_FOR_STAMP[stamp]))


def test_the_grade_gate_across_the_whole_corpus():
    """38 component_bound + 5 partial with the map; 43 asset_named without."""
    with_map: dict[str, int] = {}
    without_map: dict[str, int] = {}
    seed_only: dict[str, int] = {}
    for stamp in CORPUS:
        for source, sink in (
            (_joined(stamp), with_map),
            (nz.normalize(*_pair(stamp)), without_map),
            (nz.normalize(_doc(stamp, "seed")), seed_only),
        ):
            for grade, count in source.inventory["completeness"].items():
                sink[grade] = sink.get(grade, 0) + count

    assert with_map == {"component_bound": 38, "component_bound_partial": 5}
    assert without_map == {"asset_named": TOTAL_NODES}
    assert seed_only == {"asset_text_only": TOTAL_NODES}


def test_the_partial_grade_names_what_is_missing():
    partial = [
        node
        for stamp in CORPUS
        for node in _joined(stamp).nodes
        if node.fields["context_completeness"] == "component_bound_partial"
    ]
    assert len(partial) == 5
    assert {n.fields["component_id"] for n in partial} == PARTIAL_COMPONENTS
    for node in partial:
        assert node.fields["telemetry_requirements"]
        assert all(
            "logsource.product stays unset" in requirement
            for requirement in node.fields["telemetry_requirements"]
        )
    # authentication 'none' is a declared absence, not a product to name.
    front_door = next(n for n in partial if n.fields["component_id"] == "front_door")
    assert front_door.fields["authentication"] == "none"
    assert front_door.fields["technologies"]


def test_a_bound_node_carries_the_estate_fields_the_exports_lack():
    node = next(
        n for n in _joined("20260917_124121").nodes if n.fields["component_id"] == "portal"
    )
    assert node.fields["zone"]
    assert node.fields["technologies"] == ["nginx", "django"]
    assert node.fields["authentication"] == "saml_sso"
    assert node.fields["data_classification"] == "pii"
    assert node.fields["crown_jewel"] is False
    assert node.provenance_by_field["zone"]["origin"] == "flow_map"
    assert node.provenance_by_field["zone"]["flow_map_lineage"] == "same_map"


def test_a_crown_jewel_is_read_from_the_map_not_guessed():
    nodes = _joined("20260917_124121").nodes
    jewels = {n.fields["component_id"] for n in nodes if n.fields["crown_jewel"]}
    assert jewels <= {"claims_db", "doc_store"}
    assert jewels


def test_an_unresolved_component_is_not_enriched_and_stays_asset_named():
    stamp = "20260917_124121"
    trimmed = copy.deepcopy(_read_map(MAP_FOR_STAMP[stamp]))
    trimmed["components"] = [c for c in trimmed["components"] if c["id"] != "doc_store"]
    result = nz.normalize(*_pair(stamp), flow_map=_map("trimmed.json", trimmed))

    orphans = [n for n in result.nodes if n.fields["component_id"] == "doc_store"]
    assert orphans
    for node in orphans:
        assert node.fields["context_completeness"] == "asset_named"
        # Absent, not null: the existing convention for a field that does not
        # apply, as with component_id on a seed-only node.
        assert "zone" not in node.fields
        assert "technologies" not in node.fields
        assert node.fields["control_catalogue"] == []
    # The rest of the map is still used.
    assert result.inventory["completeness"]["component_bound"] > 0


def test_the_map_never_overwrites_an_export_value():
    stamp = "20260917_124121"
    renamed = copy.deepcopy(_read_map(MAP_FOR_STAMP[stamp]))
    component = next(c for c in renamed["components"] if c["id"] == "portal")
    component["name"] = "Renamed in the analyst's copy"
    result = nz.normalize(*_pair(stamp), flow_map=_map("renamed.json", renamed))

    node = next(n for n in result.nodes if n.fields["component_id"] == "portal")
    assert node.fields["asset_name"] != "Renamed in the analyst's copy"
    conflict = next(
        c for c in result.input_conflicts if c["draft_field"] == "asset_name"
    )
    assert conflict["rejected"] == "Renamed in the analyst's copy"
    assert conflict["kept"] == node.fields["asset_name"]
    # A map disagreeing with an export is not the two documents disagreeing.
    assert result.pair["verified"] is True


def test_a_port_comes_only_from_the_map():
    stamp = "20260917_122549"
    unmapped = nz.normalize(*_pair(stamp))
    assert all("port" not in n.fields for n in unmapped.nodes)
    flowing = [
        n
        for n in _joined(stamp).nodes
        if (n.fields["transition"] or {}).get("flow_id")
    ]
    assert flowing
    assert all("port" in n.fields for n in flowing)


# ---------------------------------------------------------------------------
# Controls, stage N3b (section 1.4, decision 10)
# ---------------------------------------------------------------------------

def test_controls_come_from_the_component_when_a_map_is_supplied():
    node = next(
        n for n in _joined("20260917_124121").nodes if n.fields["component_id"] == "portal"
    )
    controls = node.fields["control_catalogue"]
    assert controls
    assert {c["name"] for c in controls} == {"WAF"}
    assert all(c["evidence"] == "structured" for c in controls)
    assert controls[0]["detection_capability"] == "medium"
    assert controls[0]["mitre_mitigation_id"] == "M1050"
    assert node.provenance_by_field["control_catalogue"]["origin"] == "flow_map"


def test_without_a_map_a_control_attaches_by_name_and_component_id():
    """Decision 10: the name alone is not a key."""
    result = nz.normalize(*_pair("20260917_124121"))
    attached = [n for n in result.nodes if n.fields["control_catalogue"]]
    assert attached
    for node in attached:
        component_id = node.fields["component_id"]
        for control in node.fields["control_catalogue"]:
            assert control["evidence"] == "text"
            assert control["control_id"]
            assert control["name"] in {
                c["name"] for c in node.fields["controls_in_play"]
            }
        assert component_id
        assert node.provenance_by_field["control_catalogue"]["origin"] == "seed"


def test_a_repeated_control_name_does_not_cross_components():
    """'WAF' protects two Claims Portal components; the ids keep them apart."""
    seed = _read("20260917_124121", "seed")
    names = [
        control["name"]
        for scenario in seed["scenarios"]
        for control in scenario["security_controls"]
    ]
    repeated = {name for name in names if names.count(name) > 1}
    assert repeated  # the corpus really does repeat a control name

    result = nz.normalize(*_pair("20260917_124121"))
    for node in result.nodes:
        component_id = node.fields["component_id"]
        for control in node.fields["control_catalogue"]:
            entry = next(
                c
                for scenario in seed["scenarios"]
                for c in scenario["security_controls"]
                if c["control_id"] == control["control_id"]
            )
            assert f"({component_id})" in entry["description"]


def test_a_control_written_for_another_component_is_not_attached():
    stamp = "20260917_124121"
    document = copy.deepcopy(_read(stamp, "seed"))
    for scenario in document["scenarios"]:
        for control in scenario["security_controls"]:
            control["description"] = "Protects something else (not_a_component)."
    graph = _doc(stamp, "graph")
    seed = _doc(stamp, "seed", document)
    result = nz.normalize(graph, seed)
    assert all(n.fields["control_catalogue"] == [] for n in result.nodes)


def test_monitoring_claim_is_derived_and_never_coverage():
    joined = _joined("20260917_124121")
    claims = {n.fields["monitoring_claim"] for n in joined.nodes}
    assert claims <= {"none", "partial", "claimed"}
    for node in joined.nodes:
        detecting = node.fields.get("detecting_controls") or []
        capable = any(
            (c.get("detection_capability") or "") in ("medium", "high")
            for c in node.fields["control_catalogue"]
        )
        expected = "claimed" if detecting else ("partial" if capable else "none")
        assert node.fields["monitoring_claim"] == expected
        assert node.provenance_by_field["monitoring_claim"]["origin"] == "derived"
        assert node.provenance_by_field["monitoring_claim"]["basis"]


def test_enrichment_does_not_move_node_identity():
    stamp = "20260917_123525"
    plain = nz.normalize(*_pair(stamp))
    enriched = _joined(stamp)
    assert [n.draft_id for n in plain.nodes] == [n.draft_id for n in enriched.nodes]
    assert plain.node_keys == enriched.node_keys


def test_enrichment_is_deterministic():
    first = _joined("20260917_022646").as_dict()
    second = _joined("20260917_022646").as_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# Mitigations, stage N3c (section 1.4b, decision 11)
# ---------------------------------------------------------------------------

def _mutate_graph(stamp: str, mutate):
    document = copy.deepcopy(_read(stamp, "graph"))
    mutate(document)
    return nz.normalize(_doc(stamp, "graph", document))


def test_the_focus_cut_matches_the_spec_worked_example():
    """022646 / web-exploit-to-db step 1 (T1190): M1016 (5), M1048 (14)."""
    node = next(
        n
        for n in _joined("20260917_022646").nodes
        if n.path_id == "web-exploit-to-db" and n.node_index == 0
    )
    assert node.fields["technique_id"] == "T1190"
    assert [m["m_id"] for m in node.fields["mitigation_focus"]] == ["M1016", "M1048"]
    assert [m["technique_breadth"] for m in node.fields["mitigation_focus"]] == [5, 14]
    assert node.fields["mitigation_focus"][0]["name"] == "Vulnerability Scanning"
    # The broadest uncovered mitigation is exactly what the cut excludes.
    assert "M1026" in node.fields["uncovered_mitigations"]
    assert "M1026" not in [m["m_id"] for m in node.fields["mitigation_focus"]]


def test_the_corpus_covers_six_of_one_hundred_and_sixty_nine():
    covered = total = 0
    for stamp in CORPUS:
        coverage = nz.normalize(*_pair(stamp)).inventory["mitigation_coverage"]
        covered += coverage["covered"]
        total += coverage["total"]
    assert (covered, total) == (6, 169)


def test_the_export_lists_are_never_rewritten():
    """They are the provenance; the derived views sit beside them."""
    stamp = "20260917_124121"
    raw = _read(stamp, "graph")["attack_graph"]["paths"][0]["steps"][0]
    node = _joined(stamp).nodes[0]
    assert node.fields["mitigations"] == raw["mitigations"]
    assert node.fields["uncovered_mitigations"] == raw["uncovered_mitigations"]
    covered = {m["m_id"] for m in node.fields["mitigations_covered"]}
    assert covered == set(raw["mitigations"]) - set(raw["uncovered_mitigations"])


def test_a_focus_entry_is_never_a_coverage_claim():
    """An all-broad node yields an empty cut, and that is not a defect."""
    result = _mutate_graph(
        "20260917_122549",
        lambda d: d["attack_graph"]["paths"][0]["steps"][0].update(
            mitigations=[], uncovered_mitigations=[]
        ),
    )
    node = result.nodes[0]
    assert node.fields["mitigation_focus"] == []
    assert node.fields["mitigation_coverage"]["total"] == 0
    assert not [w for w in result.warnings if w["code"] == "MITIGATION_UNRESOLVED"]


def test_an_unknown_mitigation_id_is_reported_not_ranked():
    def mutate(document):
        step = document["attack_graph"]["paths"][0]["steps"][0]
        step["mitigations"] = ["M9999", "M1016"]
        step["uncovered_mitigations"] = ["M9999", "M1016"]

    result = _mutate_graph("20260917_122549", mutate)
    node = result.nodes[0]
    assert [m["m_id"] for m in node.fields["mitigation_focus"]] == ["M1016"]
    assert node.fields["mitigation_coverage"]["unresolved"] == ["M9999"]
    assert "M9999" not in node.fields["mitigation_names"]
    warning = next(w for w in result.warnings if w["code"] == "MITIGATION_UNRESOLVED")
    assert warning["location"] == "M9999"
    assert warning["severity"] == nz.SEVERITY_ADVISORY


def test_the_tag_caveat_is_computed_from_the_map():
    """Decision 11: the counts are in no export, so they come from the map."""
    node = _joined("20260917_022646").nodes[0]
    caveat = node.fields["mitigation_coverage"]["tag_caveat"]
    assert caveat["control_count"] == 8
    assert caveat["tagged_control_count"] == 7
    assert caveat["components_without_controls"] == ["ci_runner"]
    assert caveat["flow_map_lineage"] == "same_map"
    assert "tag_caveat_reason" not in node.fields["mitigation_coverage"]


def test_without_a_map_the_caveat_is_null_and_says_why():
    coverage = nz.normalize(*_pair("20260917_022646")).nodes[0].fields[
        "mitigation_coverage"
    ]
    assert coverage["tag_caveat"] is None
    assert "not evidence that controls are untagged" in coverage["tag_caveat_reason"]


def test_mitigation_names_are_looked_up_not_asserted():
    node = _joined("20260917_124121").nodes[0]
    entry = node.provenance_by_field["mitigation_names"]
    assert entry["origin"] == "reference_data"
    assert entry["document"] == "mitre_relationships.json"


# ---------------------------------------------------------------------------
# Taxonomy, stage N3d (section 1.6)
# ---------------------------------------------------------------------------

def test_the_corpus_needs_no_reconciliation():
    """The projector already answered to v19.2; agreement is the expectation."""
    for stamp in CORPUS:
        taxonomy = nz.normalize(*_pair(stamp)).inventory["taxonomy"]
        assert set(taxonomy) == {"technique:current", "tactic:as_supplied"}


def test_stealth_survives_and_defense_evasion_is_not_restored():
    stealth = [
        n
        for stamp in CORPUS
        for n in nz.normalize(*_pair(stamp)).nodes
        if n.fields["tactic"] == "Stealth"
    ]
    assert stealth  # the corpus really does carry the v19 name
    for node in stealth:
        assert node.fields["tactic_status"] == "as_supplied"
    assert not [
        n
        for stamp in CORPUS
        for n in nz.normalize(*_pair(stamp)).nodes
        if n.fields["tactic"] == "Defense Evasion"
    ]


def test_a_retired_tactic_resolves_to_the_successor_the_technique_uses():
    """Synthetic: no current export carries a retired tactic."""

    def mutate(document):
        step = document["attack_graph"]["paths"][0]["steps"][0]
        step["technique_id"] = "T1078"
        step["tactic"] = "Defense Evasion"

    result = _mutate_graph("20260917_122549", mutate)
    node = result.nodes[0]
    assert node.fields["tactic"] == "Stealth"
    assert node.fields["tactic_status"] == "reconciled"
    assert node.fields["tactic_as_supplied"] == "Defense Evasion"


def test_an_unresolvable_tactic_keeps_the_export_value():
    result = _mutate_graph(
        "20260917_122549",
        lambda d: d["attack_graph"]["paths"][0]["steps"][0].update(
            tactic="Lateral Thinking"
        ),
    )
    node = result.nodes[0]
    assert node.fields["tactic"] == "Lateral Thinking"
    assert node.fields["tactic_status"] == "unresolved"
    assert any(w["code"] == "TACTIC_UNRESOLVED" for w in result.warnings)


def test_a_retired_technique_is_remapped_beside_the_export_value():
    result = _mutate_graph(
        "20260917_122549",
        lambda d: d["attack_graph"]["paths"][0]["steps"][0].update(
            technique_id="T1562.001",
            technique_name="Impair Defenses: Disable or Modify Tools",
        ),
    )
    node = result.nodes[0]
    assert node.fields["technique_id"] == "T1562.001"  # never rewritten
    assert node.fields["technique_id_current"] == "T1685"
    assert node.fields["technique_status"] == "retired_remapped"
    assert node.fields["technique_remap_basis"] == "curated"
    assert any(w["code"] == "TECHNIQUE_RETIRED" for w in result.warnings)


def test_an_unknown_technique_is_flagged_never_guessed():
    result = _mutate_graph(
        "20260917_122549",
        lambda d: d["attack_graph"]["paths"][0]["steps"][0].update(
            technique_id="T9999", technique_name="Entirely invented"
        ),
    )
    node = result.nodes[0]
    assert node.fields["technique_status"] == "unresolved"
    assert "technique_id_current" not in node.fields
    assert any(w["code"] == "TECHNIQUE_UNRESOLVED" for w in result.warnings)


def test_a_case_difference_is_reconciled_not_corrected():
    result = _mutate_graph(
        "20260917_122549",
        lambda d: d["attack_graph"]["paths"][0]["steps"][0].update(
            tactic="initial access"
        ),
    )
    node = result.nodes[0]
    assert node.fields["tactic"] == "Initial Access"
    assert node.fields["tactic_status"] == "reconciled"
    assert node.fields["tactic_as_supplied"] == "initial access"


def test_n3c_and_n3d_do_not_move_node_identity():
    stamp = "20260917_123525"
    enriched = _joined(stamp)
    plain = nz.normalize(*_pair(stamp))
    assert [n.draft_id for n in plain.nodes] == [n.draft_id for n in enriched.nodes]


# ---------------------------------------------------------------------------
# Grounding and the assessment tuple, stage G1 (designer plan sections 4 and 5)
# ---------------------------------------------------------------------------

def test_every_node_carries_both_tuple_elements_with_a_basis():
    for stamp in CORPUS:
        for node in nz.normalize(*_pair(stamp)).nodes:
            assessment = node.fields["assessment"]
            assert assessment["version"]
            assert assessment["attack_version"] == "19.2"
            for name in ("actor_evidence", "multistep_access"):
                element = assessment["tuple"][name]
                assert isinstance(element["value"], bool)
                assert element["reason_codes"]


def test_actor_evidence_is_the_association_not_the_export_field():
    """`actor_support: procedure_documented` may coexist with a false tuple."""
    nodes = [n for stamp in CORPUS for n in nz.normalize(*_pair(stamp)).nodes]
    documented = [n for n in nodes if n.fields["actor_support"] == "procedure_documented"]
    assert documented
    for node in documented:
        # The export value is never rewritten by the assessment.
        assert node.fields["actor_support"] == "procedure_documented"


def test_an_unmapped_technique_is_not_established_rather_than_denied():
    result = _mutate_graph(
        "20260917_122549",
        lambda d: d["attack_graph"]["paths"][0]["steps"][0].update(
            technique_id="T1200", technique_name="Hardware Additions"
        ),
    )
    element = result.nodes[0].fields["assessment"]["tuple"]["actor_evidence"]
    assert element["value"] is False
    assert element["reason_codes"] == ["not_established_in_local_sources"]
    assert "does not establish that the actor never uses it" in element["basis"]
    assert element["warning"] is True


def test_a_documented_technique_records_direct_support():
    node = nz.normalize(*_pair("20260917_122549")).nodes[0]
    element = node.fields["assessment"]["tuple"]["actor_evidence"]
    assert element["value"] is True
    assert element["support"] == "direct"


def test_multistep_access_discriminates_across_the_corpus():
    """A constant is not an assessment.

    `access_source: model` is on every node of every fixture, so triggering on
    it made this element true 43 of 43. It is a qualifier now, and the value
    comes from the state gaps and the one undeclared transition.
    """
    values = [
        n.fields["assessment"]["tuple"]["multistep_access"]["value"]
        for stamp in CORPUS
        for n in nz.normalize(*_pair(stamp)).nodes
    ]
    assert (values.count(True), values.count(False)) == (10, 33)

    node = nz.normalize(*_pair("20260917_122549")).nodes[0]
    element = node.fields["assessment"]["tuple"]["multistep_access"]
    assert element["qualifiers"] == ["access_state_modelled_not_declared"]
    assert "access_state_modelled_not_declared" not in element["reason_codes"]


def test_actor_evidence_is_true_by_construction_on_a_projector_pack():
    """Recorded, not asserted as a virtue: the actor filter is upstream.

    If this ever reads false on an unmutated projector pack, the projector
    built a path from a technique it had not mapped to the actor.
    """
    values = [
        n.fields["assessment"]["tuple"]["actor_evidence"]["value"]
        for stamp in CORPUS
        for n in nz.normalize(*_pair(stamp)).nodes
    ]
    assert values == [True] * TOTAL_NODES


def test_a_state_gap_always_forces_multistep_access_true():
    gaps = [
        n
        for stamp in CORPUS
        for n in nz.normalize(*_pair(stamp)).nodes
        if n.fields["state_check"] == "gap"
    ]
    assert len(gaps) == 9  # the corpus's nine gap nodes
    for node in gaps:
        element = node.fields["assessment"]["tuple"]["multistep_access"]
        assert element["value"] is True
        assert "inherited_state_gap" in element["reason_codes"]
        assert element["warning"] is True


def test_procedure_evidence_carries_its_source_and_a_hash():
    node = nz.normalize(*_pair("20260917_122549")).nodes[0]
    evidence = node.fields["procedure_evidence"]
    assert evidence
    for entry in evidence:
        assert entry["source_id"]
        assert entry["relation"] in {"actor", "software"}
        assert len(entry["content_sha256"]) == 16
        assert "index reference" in entry["provenance_limitation"]
    assert len(evidence) <= 3


def test_grounding_does_not_rewrite_the_export_or_move_identity():
    stamp = "20260917_124121"
    plain = [n.draft_id for n in nz.normalize(*_pair(stamp)).nodes]
    assert plain == [n.draft_id for n in _joined(stamp).nodes]


# ---------------------------------------------------------------------------
# The digest, a troubleshooting view of the pack
# ---------------------------------------------------------------------------

def test_the_digest_is_three_lines_a_node_and_names_what_is_doubtful():
    result = _joined("20260917_022646")
    lines = nz.digest_lines(result)
    assert len(lines) == len(result.nodes) * 3

    gap_node = next(i for i, n in enumerate(result.nodes) if n.fields["state_check"] == "gap")
    detail = lines[gap_node * 3 + 1]
    assert "state gap" in detail
    assert "multistep_access=true ?" in detail
    assert "component_bound" in detail
    assert lines[gap_node * 3 + 2].startswith("  focus:")


def test_the_digest_says_when_a_focus_cut_is_empty():
    result = _mutate_graph(
        "20260917_122549",
        lambda d: d["attack_graph"]["paths"][0]["steps"][0].update(
            mitigations=[], uncovered_mitigations=[]
        ),
    )
    assert "none narrow enough" in nz.digest_lines(result)[2]


def test_the_spec_catalogue_lists_every_code():
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("### 4.4", 1)[1].split("\n## ", 1)[0]
    for code in [*nz.WARNING_CODES, *nz.REVIEW_FLAG_CODES]:
        assert f"`{code}`" in section, f"{code} is not in spec section 4.4"
    for code, severity in nz.WARNING_CODES.items():
        assert f"| `{code}` | {severity} |" in section
