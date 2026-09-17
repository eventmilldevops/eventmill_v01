"""Contract compliance tests for attack_path_detection_designer."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

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


def test_missing_sources_is_rejected(tool):
    assert tool.validate_inputs({}).ok is False
    assert tool.validate_inputs({"sources": []}).ok is False


def test_more_than_two_sources_is_rejected(tool, graph_path, seed_path):
    result = tool.validate_inputs({"sources": [graph_path, seed_path, graph_path]})
    assert result.ok is False


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
