"""Contract tests for the telemetry reference library.

Specification: ``docs/specs/telemetry_reference_library.md``. The library is an
inventory of what an estate can observe; these tests hold it to the rules that
keep it honest rather than to its contents, which will grow.
"""

from __future__ import annotations

import pytest

from framework.reference_data.mitre_attack import enrich_technique
from framework.reference_data.telemetry_library import (
    ATTACK_RELATIONS,
    CONTROL_FUNCTIONS,
    RELATION_KINDS,
    SUPPORT_EFFECTS,
    all_sources,
    get_source,
    library_version,
    sources_for_component,
    sources_for_estate,
    supporting_sources,
    unmapped_behaviours,
    validate_library,
)

ESTATES = (
    "claims_portal",
    "telemetry_saas",
    "plant_ot",
    "branch_physical",
    "loyalty_commerce",
)


def test_the_library_validates():
    assert validate_library() == []


def test_the_version_is_pinned():
    """Every draft records it beside the ATT&CK release."""
    assert library_version() not in ("", "unknown")


@pytest.mark.parametrize("estate", ESTATES)
def test_every_example_estate_has_sources(estate):
    """The seed is limited to the maps we have - and covers all of them."""
    assert sources_for_estate(estate)


# ---------------------------------------------------------------------------
# Section 3: never an invented identifier
# ---------------------------------------------------------------------------

def test_every_attack_id_exists_in_the_local_release():
    for source in all_sources():
        for observation in source.get("observes") or []:
            if observation["attack_relation"] == "unmapped":
                continue
            entry = enrich_technique(observation["attack_id"])
            assert entry, f"{source['source_id']} cites {observation['attack_id']}"
            assert entry["matrix"] == observation["matrix"]


def test_unmapped_behaviours_carry_a_local_id_and_never_an_attack_id():
    unmapped = unmapped_behaviours()
    assert unmapped
    for observation in unmapped:
        assert observation["local_id"].startswith("EM-")
        assert "attack_id" not in observation
        assert observation["rationale"]


def test_adjacent_mappings_state_how_they_differ():
    adjacent = [
        (s["source_id"], o)
        for s in all_sources()
        for o in s.get("observes") or []
        if o["attack_relation"] == "adjacent"
    ]
    assert adjacent
    for source_id, observation in adjacent:
        assert observation["relation_kind"] in RELATION_KINDS, source_id
        assert observation["rationale"], source_id


def test_the_ics_matrix_is_used_where_it_fits():
    """`unmapped` means outside ATT&CK, not outside the enterprise matrix."""
    ics = [
        o
        for s in all_sources()
        for o in s.get("observes") or []
        if o.get("matrix") == "ics"
    ]
    assert ics
    for observation in ics:
        assert enrich_technique(observation["attack_id"])["matrix"] == "ics"


# ---------------------------------------------------------------------------
# Section 4: function, cadence and the sources that are not streams
# ---------------------------------------------------------------------------

def test_every_source_declares_what_it_does_to_risk():
    for source in all_sources():
        assert source["control_function"]["domain"] in CONTROL_FUNCTIONS
        assert source["control_function"]["note"]


def test_decision_support_entries_never_claim_a_detection():
    """They make another control work; counting them as detections double counts."""
    entries = supporting_sources()
    assert entries
    for source in entries:
        assert source.get("supports"), source["source_id"]
        for edge in source["supports"]:
            assert edge["effect"] in SUPPORT_EFFECTS
        for observation in source.get("observes") or []:
            assert observation["attack_relation"] == "unmapped", source["source_id"]


def test_the_audits_are_variance_management_not_attack_detection():
    """The reclassification that FAIR-CAM's function axis forced."""
    for source_id in ("asset_audit.quarterly_report", "badge_audit.monthly_report"):
        assert get_source(source_id)["control_function"]["domain"] == "variance_management"


def test_a_dead_collector_is_distinguishable_from_a_quiet_estate():
    heartbeat = get_source("collector.heartbeat")
    assert heartbeat["control_function"]["domain"] == "variance_management"
    assert heartbeat["supports"][0]["effect"] == "verifies_operation"


def test_sources_that_are_not_streams_are_represented():
    """A log-only library declares the branch estate's best controls invisible."""
    periodic = [
        s
        for s in all_sources()
        if s["availability"]["cadence"] in ("monthly", "quarterly", "on_request")
    ]
    assert periodic
    human = [s for s in all_sources() if s["availability"]["artefact"] != "machine_readable"]
    assert human
    assert get_source("cctv.retention_index")["availability"]["cadence"] == "on_request"


def test_every_source_names_an_owner():
    """Acting on most of these needs someone outside security."""
    owners = {s["availability"]["owner"] for s in all_sources()}
    assert {"Facilities", "Finance", "Customer service"} <= owners


# ---------------------------------------------------------------------------
# Specific claims the specification makes about particular sources
# ---------------------------------------------------------------------------

def test_kubernetes_api_audit_does_not_claim_to_see_file_reads():
    """A mounted-token read produces no API audit event; another source sees it."""
    api = get_source("kubernetes.api_audit")
    assert "file_reads_inside_the_container" in api["fields"]["absent_without_enrichment"]
    assert not any(
        o["attack_relation"] == "exact" and o["attack_id"] == "T1552.001"
        for o in api["observes"]
    )
    files = get_source("container.file_access")
    assert any(
        o["attack_relation"] == "exact" and o["attack_id"] == "T1552.001"
        for o in files["observes"]
    )


def test_separation_of_duties_records_a_joined_identity():
    ledger = get_source("ledger.adjustment_audit")
    assert ledger["join_keys"]["actor"] == "actor_account"
    assert ledger["join_keys"]["approver"] == "approver_account"
    assert ledger["join_keys"]["same_artefact"] is True
    assert any(
        o.get("local_id") == "EM-PROC-0003" for o in ledger["observes"]
    )


def test_the_control_behind_dual_approval_is_named_as_decision_support():
    roles = get_source("identity.role_assignment_export")
    assert roles["control_function"]["domain"] == "decision_support"
    effects = {e["effect"] for e in roles["supports"]}
    assert "enables_trigger" in effects
    assert any("Dual approval" in e["control"] for e in roles["supports"])


def test_netflow_says_plainly_that_it_cannot_see_the_cellular_path():
    netflow = get_source("netflow.records")
    assert "cellular" in netflow["control_function"]["note"]


def test_pgaudit_is_reachable_from_a_postgres_component():
    matched = {s["source_id"] for s in sources_for_component(["postgres", "pgaudit"], "database")}
    assert {"postgres.session", "pgaudit.object_access"} <= matched


def test_a_component_with_no_matching_technology_returns_nothing():
    assert sources_for_component(["nothing-we-know-about"], component_type=None) == []


def test_relations_are_drawn_from_the_declared_vocabulary():
    for source in all_sources():
        for observation in source.get("observes") or []:
            assert observation["attack_relation"] in ATTACK_RELATIONS
