"""Stage G1a: joining the telemetry reference library to a node.

Specification: `docs/specs/telemetry_reference_library.md` §5, and the
`protocol: physical` convention registered in
`docs/specs/reserved_vocabulary.md` §1.
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


def _load(filename: str, alias: str):
    spec = importlib.util.spec_from_file_location(alias, PLUGIN_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


nz = _load("normalization.py", "attack_path_detection_designer_normalization")
tl = _load("telemetry.py", "attack_path_detection_designer_telemetry")

MAP_FOR_STAMP = {
    "20260917_022646": "telemetry_saas",
    "20260917_122549": "telemetry_saas",
    "20260917_123525": "application_b",
    "20260917_124121": "claims_portal",
}


def _read(stamp: str, role: str) -> dict:
    prefix = "path_graph" if role == "graph" else "scenario_seed"
    with open(FIXTURES / f"{prefix}_{stamp}.json", encoding="utf-8") as handle:
        return json.load(handle)


def _doc(stamp: str, role: str, document: dict | None = None):
    prefix = "path_graph" if role == "graph" else "scenario_seed"
    return nz.load_document(
        document if document is not None else _read(stamp, role),
        f"{prefix}_{stamp}.json",
    )


def _map(name: str, document: dict | None = None):
    if document is None:
        with open(FIXTURES / "flow_maps" / f"{name}_flow_map.json", encoding="utf-8") as h:
            document = json.load(h)
    return nz.load_flow_map(document, f"{name}_flow_map.json")


def _joined(stamp: str, flow_map=None):
    return nz.normalize(
        _doc(stamp, "graph"),
        _doc(stamp, "seed"),
        flow_map=flow_map if flow_map is not None else _map(MAP_FOR_STAMP[stamp]),
    )


def _all_nodes(with_map: bool = True):
    for stamp in MAP_FOR_STAMP:
        result = _joined(stamp) if with_map else nz.normalize(*(
            _doc(stamp, "graph"), _doc(stamp, "seed")
        ))
        yield from result.nodes


# ---------------------------------------------------------------------------
# Readiness is its own axis
# ---------------------------------------------------------------------------

def test_readiness_distribution_across_the_corpus():
    counts: dict[str, int] = {}
    for node in _all_nodes():
        value = node.fields["telemetry_readiness"]
        counts[value] = counts.get(value, 0) + 1
    assert counts == {"stream_available": 38, "periodic_only": 2, "none_declared": 3}


def test_without_a_map_nothing_is_observable():
    """The library joins on the component, so it needs the estate."""
    assert {n.fields["telemetry_readiness"] for n in _all_nodes(with_map=False)} == {
        "none_declared"
    }


def test_readiness_is_not_the_completeness_grade():
    """A node can be bound to the estate and still have nothing to look at."""
    pairs = {
        (n.fields["context_completeness"], n.fields["telemetry_readiness"])
        for n in _all_nodes()
    }
    readiness_by_grade: dict[str, set] = {}
    for grade, readiness in pairs:
        readiness_by_grade.setdefault(grade, set()).add(readiness)
    assert any(len(values) > 1 for values in readiness_by_grade.values())


def test_a_component_declaring_no_technology_has_nothing_to_observe():
    bare = {
        n.fields.get("component_id")
        for n in _all_nodes()
        if n.fields["telemetry_readiness"] == "none_declared"
    }
    assert bare == {"doc_store", "users"}
    for node in _all_nodes():
        if node.fields.get("component_id") in bare:
            assert not node.fields.get("technologies")


def test_every_node_records_the_library_version():
    versions = {n.fields["telemetry_library_version"] for n in _all_nodes()}
    assert len(versions) == 1
    assert versions.pop() not in ("", "unknown")


# ---------------------------------------------------------------------------
# The physical rule
# ---------------------------------------------------------------------------

def test_a_physical_hop_draws_physical_sources_not_network_ones():
    """A wall port's technology is ethernet; no packet observes a person."""
    fields = {
        "technologies": ["ethernet-wall-port", "cisco-ios"],
        "transition": {"movement": "declared_flow", "protocol": "physical"},
    }
    attached = tl.attach(fields, component_type="network_device")
    source_ids = {c["source_id"] for c in attached["telemetry_candidates"]}

    assert "badge.door_event" in source_ids
    assert "badge.door_contact_alarm" in source_ids
    assert "netflow.records" not in source_ids
    assert attached["observation_medium"] == "physical"
    assert all(
        c["matched_on"] == "physical_hop" for c in attached["telemetry_candidates"]
    )


def test_an_out_of_band_hop_is_named_as_such():
    fields = {"technologies": [], "transition": {"protocol": "lte"}}
    assert tl.attach(fields)["observation_medium"] == "out_of_band"


def test_an_ordinary_hop_is_network():
    fields = {"technologies": ["postgres"], "transition": {"protocol": "postgres"}}
    attached = tl.attach(fields, component_type="database")
    assert attached["observation_medium"] == "network"
    assert "pgaudit.object_access" in {
        c["source_id"] for c in attached["telemetry_candidates"]
    }


# ---------------------------------------------------------------------------
# What a draft may not conclude from a candidate
# ---------------------------------------------------------------------------

def test_decision_support_alone_is_not_readiness():
    """An asset register makes another control judgeable; it observes nothing."""
    candidates = [
        {
            "source_id": "inventory.asset_register",
            "control_function": "decision_support",
            "cadence": "on_request",
            "artefact": "human_readable",
            "collection_status": "unknown",
            "latency": "as current as the last update",
        }
    ]
    assert tl.readiness(candidates) == "none_declared"


def test_a_periodic_source_is_not_a_stream():
    candidates = [
        {
            "source_id": "asset_audit.quarterly_report",
            "control_function": "variance_management",
            "cadence": "quarterly",
            "artefact": "human_readable",
            "collection_status": "unknown",
            "latency": "up to 90 days",
        }
    ]
    assert tl.readiness(candidates) == "periodic_only"


def test_notes_say_what_is_unconfirmed_and_what_is_not_a_stream():
    node = next(n for n in _all_nodes() if n.fields["telemetry_candidates"])
    notes = " ".join(node.fields["telemetry_notes"])
    assert "collection status unknown" in notes


def test_candidates_carry_what_a_draft_needs_and_not_the_whole_entry():
    node = next(n for n in _all_nodes() if n.fields["telemetry_candidates"])
    candidate = node.fields["telemetry_candidates"][0]
    assert set(candidate) >= {
        "source_id",
        "matched_on",
        "necessity",
        "collection_status",
        "artefact",
        "cadence",
        "owner",
        "control_function",
        "absent_without_enrichment",
    }
    assert "version_scope" not in candidate


def test_the_join_does_not_move_node_identity():
    stamp = "20260917_123525"
    plain = [n.draft_id for n in nz.normalize(_doc(stamp, "graph"), _doc(stamp, "seed")).nodes]
    assert plain == [n.draft_id for n in _joined(stamp).nodes]


def test_provenance_points_at_the_library():
    node = next(_all_nodes())
    entry = node.provenance_by_field["telemetry_candidates"]
    assert entry["origin"] == "reference_data"
    assert entry["document"] == "telemetry_library.json"
    assert entry["basis"]
