"""Contract compliance tests for attack_path_detection_designer."""

from __future__ import annotations

import importlib.util
import json
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
    assert metadata["actions"] == ["validate_input"]
    assert "normalize_paths" in metadata["planned_actions"]


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
    assert "unenriched" in summary


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


def test_summary_reports_a_refused_pair(tool):
    graph = str(FIXTURES / "path_graph_20260917_122549.json")
    seed = str(FIXTURES / "scenario_seed_20260917_124121.json")
    result = tool.execute({"sources": [graph, seed]}, context=None)
    summary = tool.summarize_for_llm(result)
    assert "PAIR_REFUSED" in summary
