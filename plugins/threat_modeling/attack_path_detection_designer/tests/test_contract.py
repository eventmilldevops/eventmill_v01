"""Contract compliance tests for attack_path_detection_designer."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest


@dataclass
class FakeArtifact:
    """Stands in for framework.plugins.protocol.ArtifactRef."""

    artifact_id: str
    artifact_type: str
    file_path: str
    storage_uri: str | None = None
    source_tool: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class FakeContext:
    """Only the read-only artifact list this tool touches."""

    artifacts: list[Any] = field(default_factory=list)

PLUGIN_DIR = Path(__file__).resolve().parent.parent
FIXTURES = PLUGIN_DIR / "tests" / "fixtures"


def _load_tool_module():
    name = "attack_path_detection_designer_tool"
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "tool.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_tool_mod = _load_tool_module()


@pytest.fixture
def tool():
    return _tool_mod.AttackPathDetectionDesigner()


@pytest.fixture
def graph_path() -> str:
    return str(FIXTURES / "path_graph_20260917_122549.json")


@pytest.fixture
def seed_path() -> str:
    return str(FIXTURES / "scenario_seed_20260917_122549.json")


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def test_manifest_matches_the_schema_enums():
    with open(PLUGIN_DIR / "manifest.json", encoding="utf-8") as handle:
        manifest = json.load(handle)
    with open(
        PLUGIN_DIR.parents[2] / "docs" / "specs" / "manifest_schema.json",
        encoding="utf-8",
    ) as handle:
        schema = json.load(handle)

    for name in schema["required"]:
        assert name in manifest, f"manifest is missing required field '{name}'"
    assert manifest["stability"] in schema["properties"]["stability"]["enum"]
    assert manifest["timeout_class"] in schema["properties"]["timeout_class"]["enum"]
    assert manifest["model_tier"] in schema["properties"]["model_tier"]["enum"]
    unregistered = set(manifest) - set(schema["properties"])
    assert not unregistered, f"manifest carries unregistered field(s): {unregistered}"


def test_the_plugin_is_not_auto_invocable():
    """Decision 7: the flag is whole-plugin, and generation lands here."""
    with open(PLUGIN_DIR / "manifest.json", encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["safe_for_auto_invoke"] is False


def test_entry_point_and_class_name_resolve():
    with open(PLUGIN_DIR / "manifest.json", encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert (PLUGIN_DIR / manifest["entry_point"]).exists()
    assert hasattr(_tool_mod, manifest["class_name"])
    assert (PLUGIN_DIR / manifest["input_schema"]).exists()
    assert (PLUGIN_DIR / manifest["output_schema"]).exists()


# ---------------------------------------------------------------------------
# Protocol surface
# ---------------------------------------------------------------------------

def test_metadata_names_the_implemented_and_planned_actions(tool):
    metadata = tool.metadata()
    assert metadata["tool_name"] == "attack_path_detection_designer"
    assert metadata["actions"] == ["validate_input", "digest", "generate_detections"]
    assert metadata["planned_actions"] == ["normalize_paths"]


def test_a_planned_action_says_so(tool):
    result = tool.validate_inputs({"action": "normalize_paths", "sources": ["x"]})
    assert result.ok is False
    assert any("planned" in error for error in result.errors)


def test_an_unknown_action_is_rejected(tool):
    result = tool.validate_inputs({"action": "invent_detections", "sources": ["x"]})
    assert result.ok is False


def test_missing_input_is_rejected(tool):
    assert tool.validate_inputs({}).ok is False
    assert tool.validate_inputs({"sources": []}).ok is False
    assert tool.validate_inputs({"artifact_ids": []}).ok is False


def test_more_than_two_documents_is_rejected(tool, graph_path, seed_path):
    assert tool.validate_inputs({"sources": [graph_path, seed_path, graph_path]}).ok is False
    mixed = {"artifact_ids": ["art_1", "art_2"], "sources": [graph_path]}
    assert tool.validate_inputs(mixed).ok is False


def test_artifact_ids_pass_validation_without_a_context(tool):
    """They cannot be resolved here: validation does not receive the context."""
    assert tool.validate_inputs({"artifact_ids": ["art_1", "art_2"]}).ok is True


def test_a_missing_file_is_named(tool):
    result = tool.validate_inputs({"sources": ["no_such_export.json"]})
    assert result.ok is False
    assert any("no_such_export.json" in error for error in result.errors)


def test_valid_inputs_pass(tool, graph_path, seed_path):
    assert tool.validate_inputs({"sources": [graph_path, seed_path]}).ok is True


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def test_execute_normalizes_a_verified_pair(tool, graph_path, seed_path):
    result = tool.execute({"sources": [graph_path, seed_path]}, context=None)
    assert result.ok is True
    assert result.result["node_count"] == 11
    assert result.result["pair_status"] == "verified"
    assert result.result["conflict_count"] == 0
    assert result.result["pair"]["verified"] is True


def test_execute_on_a_single_document(tool, graph_path):
    result = tool.execute({"sources": [graph_path]}, context=None)
    assert result.ok is True
    assert result.result["pair_status"] == "single_source"
    assert result.result["node_count"] == 11


def test_execute_resolves_a_pair_of_artifact_ids(tool, graph_path, seed_path):
    """The container route: the registry knows where an export actually landed."""
    context = FakeContext(
        [
            FakeArtifact("art_graph", "json_events", graph_path),
            FakeArtifact("art_seed", "json_events", seed_path),
            FakeArtifact("art_other", "text", "irrelevant.txt"),
        ]
    )
    result = tool.execute({"artifact_ids": ["art_graph", "art_seed"]}, context)
    assert result.ok is True
    assert result.result["node_count"] == 11
    assert result.result["pair_status"] == "verified"


def test_artifact_ids_and_paths_normalize_identically(tool, graph_path, seed_path):
    context = FakeContext(
        [
            FakeArtifact("art_graph", "json_events", graph_path),
            FakeArtifact("art_seed", "json_events", seed_path),
        ]
    )
    by_artifact = tool.execute({"artifact_ids": ["art_graph", "art_seed"]}, context)
    by_path = tool.execute({"sources": [graph_path, seed_path]}, context)
    assert [n["draft_id"] for n in by_artifact.result["nodes"]] == [
        n["draft_id"] for n in by_path.result["nodes"]
    ]


def test_a_singular_artifact_id_is_accepted(tool, graph_path):
    """The shell speaks the singular, and injects file_path beside it."""
    context = FakeContext([FakeArtifact("art_graph", "json_events", graph_path)])
    result = tool.execute(
        {"artifact_id": "art_graph", "file_path": graph_path, "path": graph_path},
        context,
    )
    assert result.ok is True
    # The injected path must not be read a second time as a phantom pair.
    assert result.result["node_count"] == 11
    assert result.result["pair_status"] == "single_source"


def test_the_shell_injected_file_path_alone_still_works(tool, graph_path):
    result = tool.execute({"file_path": graph_path, "path": graph_path}, context=None)
    assert result.ok is True
    assert result.result["node_count"] == 11


def test_an_unknown_artifact_id_names_itself(tool):
    result = tool.execute({"artifact_ids": ["art_nope"]}, FakeContext([]))
    assert result.ok is False
    assert result.error_code == "ARTIFACT_NOT_FOUND"
    assert "art_nope" in result.message


def test_a_registered_artifact_with_no_readable_file_says_where_it_lives(tool):
    """Cloud Run registers an export whose bytes may not be on this disk."""
    artifact = FakeArtifact(
        "art_remote",
        "json_events",
        "/nonexistent/adversary_path_graph.json",
        storage_uri="gs://evtm-v011-common/exports/adversary_path_projector/x.json",
    )
    result = tool.execute({"artifact_ids": ["art_remote"]}, FakeContext([artifact]))
    assert result.ok is False
    assert result.error_code == "ARTIFACT_UNAVAILABLE"
    assert "gs://" in result.message


def test_a_missing_context_does_not_crash_artifact_resolution(tool):
    result = tool.execute({"artifact_ids": ["art_graph"]}, context=None)
    assert result.ok is False
    assert result.error_code == "ARTIFACT_NOT_FOUND"


def test_unreadable_input_is_an_error_not_an_exception(tool, tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    result = tool.execute({"sources": [str(broken)]}, context=None)
    assert result.ok is False
    assert result.error_code == "INPUT_UNREADABLE"


def test_an_unrecognized_document_is_an_error(tool, tmp_path):
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"source_tool": "something_else"}), encoding="utf-8")
    result = tool.execute({"sources": [str(other)]}, context=None)
    assert result.ok is False
    assert result.error_code == "INPUT_UNRECOGNIZED"


def test_execute_writes_no_artifact_at_this_stage(tool, graph_path, seed_path):
    """The context pack artifact is stage N4."""
    result = tool.execute({"sources": [graph_path, seed_path]}, context=None)
    assert result.output_artifacts is None


# ---------------------------------------------------------------------------
# summarize_for_llm
# ---------------------------------------------------------------------------

def test_summary_leads_with_status_and_stays_within_budget(tool, graph_path, seed_path):
    with open(PLUGIN_DIR / "manifest.json", encoding="utf-8") as handle:
        budget = json.load(handle)["summary_budget"]

    result = tool.execute({"sources": [graph_path, seed_path]}, context=None)
    summary = tool.summarize_for_llm(result)

    assert summary.startswith("Normalized 11 nodes")
    assert len(summary) < budget
    assert "gcp_gemini" in summary
    assert "Context grades: asset_named 11." in summary
    assert "Mitigations: " in summary
    assert "Taxonomy v19.2: " in summary


def test_summary_does_not_paste_node_bodies(tool, graph_path, seed_path):
    result = tool.execute({"sources": [graph_path, seed_path]}, context=None)
    summary = tool.summarize_for_llm(result)
    first_rationale = result.result["nodes"][0]["rationale"]
    assert first_rationale not in summary


def test_summary_of_a_failure_names_the_error(tool):
    failed = _tool_mod.ToolResult(
        ok=False, error_code="INPUT_UNREADABLE", message="Could not read x.json"
    )
    assert "INPUT_UNREADABLE" in tool.summarize_for_llm(failed)


def test_summary_says_when_no_flow_map_was_supplied(tool, graph_path):
    result = tool.execute({"sources": [graph_path]}, context=None)
    assert "Flow map: none supplied." in tool.summarize_for_llm(result)


def test_summary_separates_blocking_from_advisory_warnings(tool, graph_path, seed_path):
    wrong_map = str(FLOW_MAPS / "claims_portal_flow_map.json")
    result = tool.execute(
        {"sources": [graph_path, seed_path], "flow_map_path": wrong_map}, context=None
    )
    summary = tool.summarize_for_llm(result)
    assert "Warnings (blocking): FLOW_MAP_COMPONENT_UNRESOLVED" in summary
    assert "Warnings (advisory): FLOW_MAP_APPLICATION_MISMATCH" in summary
    assert "application 'Claims Portal' differs" in summary


# ---------------------------------------------------------------------------
# Flow map input, stage N2
# ---------------------------------------------------------------------------

FLOW_MAPS = FIXTURES / "flow_maps"


@pytest.fixture
def map_path() -> str:
    return str(FLOW_MAPS / "telemetry_saas_flow_map.json")


def test_the_digest_is_short_enough_to_read(tool, graph_path, seed_path, map_path):
    """The pack is machine-facing; this is the troubleshooting view of it."""
    payload = {
        "action": "digest",
        "sources": [graph_path, seed_path],
        "flow_map_path": map_path,
    }
    assert tool.validate_inputs(payload).ok is True
    result = tool.execute(payload, context=None)
    assert result.ok is True
    assert "nodes" not in result.result  # never the pack itself
    assert len(result.result["digest"]) == 11 * 3

    summary = tool.summarize_for_llm(result)
    assert len(summary) < 4000
    assert "component_bound" in summary
    assert "focus:" in summary


def test_a_long_digest_loses_whole_nodes_and_says_how_many(tool):
    data = {
        "node_count": 60,
        "pair_status": "verified",
        "conflict_count": 0,
        "completeness": {"asset_named": 60},
        "digest": [f"line {n} " + "x" * 100 for n in range(180)],
    }
    summary = _tool_mod._bounded_digest(data)
    assert len(summary) < 4000
    assert "more node(s)" in summary
    # Cut on a node boundary: never a half-rendered node.
    body = [line for line in summary.split("\n")[1:] if line.startswith("line ")]
    assert len(body) % 3 == 0


def test_a_flow_map_by_path_reports_its_lineage(tool, graph_path, seed_path, map_path):
    result = tool.execute(
        {"sources": [graph_path, seed_path], "flow_map_path": map_path}, context=None
    )
    assert result.ok is True
    assert result.result["flow_map_lineage"] == "same_map"
    summary = tool.summarize_for_llm(result)
    assert "Flow map: same_map (telemetry_saas_flow_map.json)" in summary
    assert "Warnings" not in summary


def test_a_flow_map_by_artifact_id_resolves_through_the_registry(
    tool, graph_path, seed_path, map_path
):
    context = FakeContext(
        [
            FakeArtifact("art_graph", "json_events", graph_path),
            FakeArtifact("art_seed", "json_events", seed_path),
            FakeArtifact("art_map", "json_events", map_path),
        ]
    )
    result = tool.execute(
        {"artifact_ids": ["art_graph", "art_seed"], "flow_map_artifact_id": "art_map"},
        context,
    )
    assert result.ok is True
    assert result.result["flow_map"]["lineage"] == "same_map"


def test_a_joined_run_reports_its_grade_distribution(
    tool, graph_path, seed_path, map_path
):
    result = tool.execute(
        {"sources": [graph_path, seed_path], "flow_map_path": map_path}, context=None
    )
    assert result.result["completeness"] == {"component_bound": 11}
    summary = tool.summarize_for_llm(result)
    assert "Context grades: component_bound 11." in summary
    assert len(summary) < 4000


def test_the_summary_never_pastes_an_enriched_node(tool, graph_path, seed_path, map_path):
    result = tool.execute(
        {"sources": [graph_path, seed_path], "flow_map_path": map_path}, context=None
    )
    summary = tool.summarize_for_llm(result)
    node = result.result["nodes"][0]
    assert node["rationale"] not in summary
    assert str(node["control_catalogue"]) not in summary


def test_an_edited_flow_map_succeeds(tool, graph_path, map_path, tmp_path):
    with open(map_path, encoding="utf-8") as handle:
        edited = json.load(handle)
    edited["description"] = "corrected by an analyst with inside knowledge"
    edited_path = tmp_path / "telemetry_saas_flow_map.json"
    edited_path.write_text(json.dumps(edited), encoding="utf-8")

    result = tool.execute(
        {"sources": [graph_path], "flow_map_path": str(edited_path)}, context=None
    )
    assert result.ok is True
    assert result.result["flow_map_lineage"] == "edited_map"
    assert "FLOW_MAP_EDITED" in tool.summarize_for_llm(result)


def test_an_unknown_flow_map_artifact_names_itself(tool, graph_path):
    result = tool.execute(
        {"sources": [graph_path], "flow_map_artifact_id": "art_nomap"}, FakeContext([])
    )
    assert result.ok is False
    assert result.error_code == "ARTIFACT_NOT_FOUND"
    assert "art_nomap" in result.message


def test_a_prose_flow_map_points_at_n5(tool, graph_path, tmp_path):
    prose = tmp_path / "flow_map.md"
    prose.write_text("# Flow map\n\nThe portal talks to the API.", encoding="utf-8")
    result = tool.execute(
        {"sources": [graph_path], "flow_map_path": str(prose)}, context=None
    )
    assert result.ok is False
    assert result.error_code == "FLOW_MAP_UNREADABLE"
    assert "N5" in result.message


def test_an_export_passed_as_the_flow_map_is_refused(tool, graph_path, seed_path):
    result = tool.execute(
        {"sources": [graph_path], "flow_map_path": seed_path}, context=None
    )
    assert result.ok is False
    assert result.error_code == "FLOW_MAP_NOT_OBJECT"


def test_the_flow_map_is_supplied_once(tool, graph_path, map_path):
    both = {
        "sources": [graph_path],
        "flow_map_path": map_path,
        "flow_map_artifact_id": "art_map",
    }
    assert tool.validate_inputs(both).ok is False


def test_a_missing_flow_map_file_is_named(tool, graph_path):
    result = tool.validate_inputs(
        {"sources": [graph_path], "flow_map_path": "no_such_map.json"}
    )
    assert result.ok is False
    assert any("no_such_map.json" in error for error in result.errors)


def test_every_error_code_the_tool_returns_is_declared():
    source = (PLUGIN_DIR / "tool.py").read_text(encoding="utf-8")
    returned = set(re.findall(r'error_code="([A-Z_]+)"', source))
    assert returned
    assert returned <= set(_tool_mod.ERROR_CODES)


def test_the_spec_catalogue_lists_every_error_code():
    spec = PLUGIN_DIR.parents[2] / "docs" / "specs" / "attack_path_detection_normalization.md"
    section = spec.read_text(encoding="utf-8").split("### 4.4", 1)[1].split("\n## ", 1)[0]
    for code in _tool_mod.ERROR_CODES:
        assert f"| `{code}` |" in section, f"{code} is not in spec section 4.4"


def test_summary_reports_a_refused_pair(tool):
    graph = str(FIXTURES / "path_graph_20260917_122549.json")
    seed = str(FIXTURES / "scenario_seed_20260917_124121.json")
    result = tool.execute({"sources": [graph, seed]}, context=None)
    summary = tool.summarize_for_llm(result)
    assert "PAIR_REFUSED" in summary
