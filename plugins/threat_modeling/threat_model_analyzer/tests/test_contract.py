"""Contract compliance tests for threat_model_analyzer."""

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "threat_model_analyzer_tool"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod

_tool_mod = _load_tool_module()


@pytest.fixture
def manifest():
    with open(PLUGIN_DIR / "manifest.json") as f:
        return json.load(f)


@pytest.fixture
def plugin_instance():
    return _tool_mod.ThreatModelAnalyzer()


@pytest.fixture
def scenario_with_data(plugin_instance):
    """Create a scenario pre-populated with controls and events."""
    # Create scenario
    result = plugin_instance.execute({
        "action": "create_scenario",
        "name": "Ransomware via Phishing",
        "description": "APT group targets org via spear phishing",
        "source_type": "threat_model",
        "threat_actor": "APT29",
        "objective": "Deploy ransomware and exfiltrate data",
        "target_assets": ["email_server", "domain_controller", "file_shares"],
        "entry_vectors": ["spear_phishing", "watering_hole"],
    }, None)
    scenario_id = result.result["scenario_id"]

    # Add controls
    plugin_instance.execute({
        "action": "add_control",
        "scenario_id": scenario_id,
        "name": "Email Gateway",
        "control_type": "perimeter",
        "description": "Filters malicious attachments",
        "implementation_status": "implemented",
        "bypass_difficulty": "medium",
    }, None)

    plugin_instance.execute({
        "action": "add_control",
        "scenario_id": scenario_id,
        "name": "EDR Agent",
        "control_type": "endpoint",
        "description": "Endpoint detection and response",
        "implementation_status": "partial",
        "bypass_difficulty": "high",
    }, None)

    plugin_instance.execute({
        "action": "add_control",
        "scenario_id": scenario_id,
        "name": "Legacy Firewall",
        "control_type": "network",
        "description": "Old network firewall",
        "implementation_status": "implemented",
        "bypass_difficulty": "low",
    }, None)

    # Add events
    plugin_instance.execute({
        "action": "add_event",
        "scenario_id": scenario_id,
        "name": "Phishing Email Delivery",
        "description": "Send spear phishing email with malicious attachment",
        "sequence_order": 1,
        "technique_name": "Phishing",
        "technique_id": "T1566",
        "target_asset": "email_server",
        "blocking_controls": ["SC-0001"],
    }, None)

    plugin_instance.execute({
        "action": "add_event",
        "scenario_id": scenario_id,
        "name": "Malware Execution",
        "description": "User opens attachment, malware executes",
        "sequence_order": 2,
        "technique_name": "User Execution",
        "technique_id": "T1204",
        "target_asset": "workstation",
        "detecting_controls": ["SC-0002"],
    }, None)

    plugin_instance.execute({
        "action": "add_event",
        "scenario_id": scenario_id,
        "name": "Lateral Movement",
        "description": "Move to domain controller",
        "sequence_order": 3,
        "technique_name": "Remote Services",
        "technique_id": "T1021",
        "target_asset": "domain_controller",
    }, None)

    return scenario_id


class TestManifest:
    def test_required_fields(self, manifest):
        for field in ["tool_name", "version", "pillar", "entry_point", "class_name"]:
            assert field in manifest

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "threat_model_analyzer"

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "threat_model_analyzer"

    def test_validate_analyze_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "analyze_document", "document_content": "Test content"
        })
        assert result.ok

    def test_validate_analyze_missing_content(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "analyze_document"})
        assert not result.ok

    def test_validate_create_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "create_scenario", "name": "Test", "description": "Desc"
        })
        assert result.ok

    def test_validate_create_missing_name(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "create_scenario", "description": "Desc"
        })
        assert not result.ok

    def test_validate_add_control_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "add_control", "scenario_id": "TS-0001",
            "name": "WAF", "control_type": "application"
        })
        assert result.ok

    def test_validate_add_control_invalid_type(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "add_control", "scenario_id": "TS-0001",
            "name": "WAF", "control_type": "invalid"
        })
        assert not result.ok

    def test_validate_add_event_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "add_event", "scenario_id": "TS-0001",
            "name": "Step 1", "sequence_order": 1
        })
        assert result.ok

    def test_validate_gap_missing_id(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "gap_analysis"})
        assert not result.ok

    def test_validate_invalid_action(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "destroy"})
        assert not result.ok


class TestCreateScenario:
    def test_create(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "create_scenario",
            "name": "Test Scenario",
            "description": "A test threat scenario",
            "threat_actor": "APT1",
            "target_assets": ["web_server"],
        }, None)
        assert result.ok
        assert result.result["scenario_id"] == "TS-0001"
        assert result.result["name"] == "Test Scenario"

    def test_create_multiple(self, plugin_instance):
        plugin_instance.execute({
            "action": "create_scenario", "name": "S1", "description": "D1"
        }, None)
        result = plugin_instance.execute({
            "action": "create_scenario", "name": "S2", "description": "D2"
        }, None)
        assert result.result["scenario_id"] == "TS-0002"


class TestAddControl:
    def test_add_control(self, plugin_instance):
        plugin_instance.execute({
            "action": "create_scenario", "name": "S1", "description": "D1"
        }, None)
        result = plugin_instance.execute({
            "action": "add_control",
            "scenario_id": "TS-0001",
            "name": "WAF",
            "control_type": "application",
            "description": "Web application firewall",
            "bypass_difficulty": "high",
        }, None)
        assert result.ok
        assert result.result["control_id"] == "SC-0001"
        assert result.result["control_type"] == "application"

    def test_add_to_nonexistent_scenario(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "add_control",
            "scenario_id": "TS-9999",
            "name": "WAF",
            "control_type": "application",
        }, None)
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"


class TestAddEvent:
    def test_add_event(self, plugin_instance):
        plugin_instance.execute({
            "action": "create_scenario", "name": "S1", "description": "D1"
        }, None)
        result = plugin_instance.execute({
            "action": "add_event",
            "scenario_id": "TS-0001",
            "name": "Initial Access",
            "description": "Phishing email",
            "sequence_order": 1,
            "technique_name": "Phishing",
            "technique_id": "T1566",
        }, None)
        assert result.ok
        assert result.result["event_id"] == "AE-0001"
        assert result.result["technique_id"] == "T1566"

    def test_add_to_nonexistent_scenario(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "add_event",
            "scenario_id": "TS-9999",
            "name": "Step 1",
            "sequence_order": 1,
        }, None)
        assert not result.ok


class TestListScenarios:
    def test_empty(self, plugin_instance):
        result = plugin_instance.execute({"action": "list_scenarios"}, None)
        assert result.ok
        assert result.result["scenarios"] == []

    def test_with_data(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({"action": "list_scenarios"}, None)
        assert result.ok
        scenarios = result.result["scenarios"]
        assert len(scenarios) == 1
        assert scenarios[0]["scenario_id"] == scenario_with_data
        assert scenarios[0]["controls_count"] == 3
        assert scenarios[0]["events_count"] == 3


class TestGapAnalysis:
    def test_gap_analysis(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({
            "action": "gap_analysis",
            "scenario_id": scenario_with_data,
        }, None)
        assert result.ok
        gap = result.result["gap_analysis"]

        # Step 2 (detect only) and Step 3 (unprotected) should be unprotected
        assert len(gap["unprotected_events"]) == 2

        # EDR Agent is partial
        assert len(gap["weak_controls"]) == 1
        assert gap["weak_controls"][0]["name"] == "EDR Agent"

        # Legacy Firewall is low bypass difficulty
        assert len(gap["easy_bypass"]) == 1
        assert gap["easy_bypass"][0]["name"] == "Legacy Firewall"

        assert gap["total_issues"] == 4  # 2 unprotected + 1 weak + 1 easy

    def test_gap_nonexistent(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "gap_analysis", "scenario_id": "TS-9999"
        }, None)
        assert not result.ok


class TestExport:
    def test_export_markdown(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({
            "action": "export",
            "scenario_id": scenario_with_data,
        }, None)
        assert result.ok
        md = result.result["markdown"]
        assert "Ransomware via Phishing" in md
        assert "T1566" in md
        assert "Email Gateway" in md
        assert "UNPROTECTED" in md

    def test_export_to_file(self, plugin_instance, scenario_with_data, tmp_path):
        out = str(tmp_path / "scenario.md")
        result = plugin_instance.execute({
            "action": "export",
            "scenario_id": scenario_with_data,
            "output_path": out,
        }, None)
        assert result.ok
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "Ransomware" in content

    def test_export_nonexistent(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "export", "scenario_id": "TS-9999"
        }, None)
        assert not result.ok


class TestAnalyzeDocument:
    def test_analyze_without_llm(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "analyze_document",
            "document_content": "This is a sample threat model document describing attack paths.",
            "source_type": "threat_model",
        }, None)
        assert result.ok
        assert result.result["ai_analysis"] is None
        assert result.result["content_length"] > 0


class TestSummarize:
    def test_summarize_create(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "create_scenario", "name": "Test", "description": "D"
        }, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "TS-0001" in summary

    def test_summarize_list(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({"action": "list_scenarios"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "1 scenario" in summary

    def test_summarize_gap(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({
            "action": "gap_analysis", "scenario_id": scenario_with_data
        }, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "issues" in summary.lower()

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="Not found")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()


# ---------------------------------------------------------------------------
# Phase 3 of adversary_path_projector: export_scenario / import_scenario
# ---------------------------------------------------------------------------

@dataclass
class FakeArtifact:
    artifact_id: str
    artifact_type: str
    file_path: str


@dataclass
class FakeContext:
    artifacts: list = field(default_factory=list)
    llm_query: Any = None


def _seed_scenario(path_id: str) -> dict[str, Any]:
    """One scenario in the shape adversary_path_projector's seed emits."""
    return {
        "path_id": path_id,
        "name": f"APT29 (G0016) vs Customer Portal: {path_id}",
        "description": "Exploit the portal, pivot to the database.",
        "source_type": "actor_projection",
        "threat_actor_profile": "APT29 (G0016)",
        "attack_objective": "Read customer records.",
        "target_assets": ["Customer database", "Portal frontend"],
        "entry_vectors": ["web"],
        "security_controls": [
            {"control_id": "SC-0001", "name": "WAF", "control_type": "perimeter",
             "description": "Protects Portal frontend (web).",
             "implementation_status": "implemented", "bypass_difficulty": "medium",
             "bypass_requirements": [], "detection_capability": "high"},
            {"control_id": "SC-0002", "name": "Database firewall",
             "control_type": "network", "description": "Protects the database.",
             "implementation_status": "partial", "bypass_difficulty": "low",
             "bypass_requirements": [], "detection_capability": "medium"},
        ],
        "attack_sequence": [
            {"event_id": "AE-0001",
             "name": "Exploit Public-Facing Application on Portal frontend",
             "description": "nginx frontend is internet-facing.",
             "sequence_order": 1, "target_asset": "Portal frontend",
             "attack_technique": "Exploit Public-Facing Application",
             "technique_id": "T1190", "tactic": "Initial Access",
             "evidence": "documented", "required_access": "none",
             "resulting_access": "user", "blocking_controls": ["WAF"],
             "detecting_controls": ["WAF"]},
            {"event_id": "AE-0002",
             "name": "Data from Local System on Customer database",
             "description": "PII sits in the claims database.",
             "sequence_order": 2, "target_asset": "Customer database",
             "attack_technique": "Data from Local System",
             "technique_id": "T1005", "tactic": "Collection",
             "evidence": "via_software", "required_access": "user",
             "resulting_access": "data", "blocking_controls": [],
             "detecting_controls": []},
        ],
    }


def _write_doc(tmp_path, doc, name="seed.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def _write_seed(tmp_path, n_paths: int) -> str:
    return _write_doc(tmp_path, {
        "source_tool": "adversary_path_projector",
        "actor": "APT29 (G0016)",
        "application": "Customer Portal",
        "scenarios": [_seed_scenario(f"path-{i}") for i in range(1, n_paths + 1)],
    })


def _import(plugin, **payload):
    return plugin.execute({"action": "import_scenario", **payload}, FakeContext())


class TestPhase3Validation:
    def test_import_needs_a_source(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "import_scenario"})
        assert not result.ok

    def test_import_accepts_artifact_id(self, plugin_instance):
        result = plugin_instance.validate_inputs(
            {"action": "import_scenario", "artifact_id": "art_1"})
        assert result.ok

    @pytest.mark.parametrize("value", [0, 11, True, "6"])
    def test_max_paths_bounds(self, plugin_instance, value):
        result = plugin_instance.validate_inputs(
            {"action": "import_scenario", "file_path": "x.json", "max_paths": value})
        assert not result.ok

    def test_export_scenario_needs_no_id(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "export_scenario"})
        assert result.ok


class TestSchemaMatchesCode:
    """The schema is what the router and the shell see; the code is what runs."""

    @pytest.fixture
    def input_schema(self):
        with open(PLUGIN_DIR / "schemas" / "input.schema.json") as f:
            return json.load(f)

    def test_actions(self, input_schema):
        assert input_schema["properties"]["action"]["enum"] == list(_tool_mod.ACTIONS)

    def test_source_types_include_actor_projection(self, input_schema):
        enum = input_schema["properties"]["source_type"]["enum"]
        assert enum == list(_tool_mod.SOURCE_TYPES)
        assert "actor_projection" in enum

    def test_max_paths_default(self, input_schema):
        prop = input_schema["properties"]["max_paths"]
        assert prop["default"] == _tool_mod.DEFAULT_IMPORT_MAX_PATHS == 6
        assert prop["maximum"] == _tool_mod.MAX_IMPORT_PATHS

    def test_manifest_chains_from_projector(self, manifest):
        assert "adversary_path_projector" in manifest["chains_from"]


class TestExportScenario:
    def test_full_scenario(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute(
            {"action": "export_scenario", "scenario_id": scenario_with_data}, None)
        assert result.ok
        scenario = result.result["scenarios"][0]
        assert len(scenario["security_controls"]) == 3
        assert len(scenario["attack_sequence"]) == 3
        assert scenario["security_controls"][0]["name"] == "Email Gateway"
        assert scenario["attack_sequence"][0]["technique_id"] == "T1566"

    def test_export_all(self, plugin_instance, scenario_with_data):
        plugin_instance.execute(
            {"action": "create_scenario", "name": "S2", "description": "D"}, None)
        result = plugin_instance.execute({"action": "export_scenario"}, None)
        assert result.result["scenario_count"] == 2

    def test_nothing_to_export(self, plugin_instance):
        result = plugin_instance.execute({"action": "export_scenario"}, None)
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"

    def test_unknown_scenario(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "export_scenario", "scenario_id": "TS-9999"}, None)
        assert not result.ok

    def test_round_trip_into_a_fresh_tracker(self, plugin_instance,
                                             scenario_with_data, tmp_path):
        """What the shell persists is exactly what import_scenario reads back."""
        exported = plugin_instance.execute(
            {"action": "export_scenario", "scenario_id": scenario_with_data}, None)
        path = _write_doc(tmp_path, exported.result)

        fresh = _tool_mod.ThreatModelAnalyzer()
        imported = _import(fresh, file_path=path)
        assert imported.ok, imported.message
        again = fresh.execute({"action": "export_scenario"}, None)

        def _strip(s):
            return {k: v for k, v in s.items()
                    if k not in ("scenario_id", "created_at", "source_document")}
        assert _strip(again.result["scenarios"][0]) == _strip(
            exported.result["scenarios"][0])

    def test_summary(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({"action": "export_scenario"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert scenario_with_data in summary
        assert "import_scenario" in summary


class TestImportScenario:
    def test_imports_each_path(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 3))
        assert result.ok, result.message
        imported = result.result["imported"]
        assert [s["path_id"] for s in imported] == ["path-1", "path-2", "path-3"]
        assert {s["source_type"] for s in imported} == {"actor_projection"}
        assert result.result["skipped_path_ids"] == []

    def test_default_cap_is_six(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 8))
        assert result.result["imported_count"] == 6
        assert result.result["skipped_path_ids"] == ["path-7", "path-8"]
        listed = plugin_instance.execute({"action": "list_scenarios"}, None)
        assert len(listed.result["scenarios"]) == 6

    def test_max_paths_overrides_the_cap(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 4),
                         max_paths=2)
        assert result.result["imported_count"] == 2
        assert result.result["skipped_path_ids"] == ["path-3", "path-4"]

    def test_path_id_selects_one(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 3),
                         path_id="path-2")
        assert [s["path_id"] for s in result.result["imported"]] == ["path-2"]

    def test_unknown_path_id_lists_what_exists(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 2),
                         path_id="nope")
        assert not result.ok
        assert "path-1" in result.message and "path-2" in result.message
        listed = plugin_instance.execute({"action": "list_scenarios"}, None)
        assert listed.result["scenarios"] == []

    def test_tactic_and_evidence_are_carried(self, plugin_instance, tmp_path):
        _import(plugin_instance, file_path=_write_seed(tmp_path, 1))
        exported = plugin_instance.execute({"action": "export_scenario"}, None)
        events = exported.result["scenarios"][0]["attack_sequence"]
        assert [(e["tactic"], e["evidence"]) for e in events] == [
            ("Initial Access", "documented"), ("Collection", "via_software")]

    def test_ids_are_reissued_and_references_follow(
            self, plugin_instance, scenario_with_data, tmp_path):
        """Importing into a tracker that already holds SC-0001 must not collide,
        and an event that pointed at the old control id must point at the new one."""
        exported = plugin_instance.execute(
            {"action": "export_scenario", "scenario_id": scenario_with_data}, None)
        result = _import(plugin_instance,
                         file_path=_write_doc(tmp_path, exported.result))
        new_id = result.result["imported"][0]["scenario_id"]
        assert new_id != scenario_with_data

        again = plugin_instance.execute(
            {"action": "export_scenario", "scenario_id": new_id}, None)
        scenario = again.result["scenarios"][0]
        gateway = scenario["security_controls"][0]
        assert gateway["name"] == "Email Gateway"
        assert gateway["control_id"] != "SC-0001"
        assert scenario["attack_sequence"][0]["blocking_controls"] == [
            gateway["control_id"]]

    def test_bad_document_imports_nothing(self, plugin_instance, tmp_path):
        doc = {"scenarios": [_seed_scenario("good"), _seed_scenario("bad")]}
        doc["scenarios"][1]["security_controls"][0]["control_type"] = "firewall"
        result = _import(plugin_instance, file_path=_write_doc(tmp_path, doc))
        assert not result.ok
        assert result.error_code == "INPUT_VALIDATION_FAILED"
        assert any("control_type" in p for p in result.details["problems"])
        listed = plugin_instance.execute({"action": "list_scenarios"}, None)
        assert listed.result["scenarios"] == []

    def test_bad_sequence_order_is_refused(self, plugin_instance, tmp_path):
        doc = {"scenarios": [_seed_scenario("p")]}
        doc["scenarios"][0]["attack_sequence"][0]["sequence_order"] = 0
        result = _import(plugin_instance, file_path=_write_doc(tmp_path, doc))
        assert not result.ok
        assert any("sequence_order" in p for p in result.details["problems"])

    def test_list_scenarios_result_is_refused(self, plugin_instance,
                                              scenario_with_data, tmp_path):
        """Counts only — importing it would create empty scenarios."""
        listed = plugin_instance.execute({"action": "list_scenarios"}, None)
        result = _import(plugin_instance,
                         file_path=_write_doc(tmp_path, listed.result))
        assert not result.ok
        assert any("export_scenario" in p for p in result.details["problems"])

    def test_projector_graph_artifact_is_refused(self, plugin_instance, tmp_path):
        doc = {"mitre_mappings": [], "attack_graph": {"paths": []}}
        result = _import(plugin_instance, file_path=_write_doc(tmp_path, doc))
        assert not result.ok
        assert "scenario seed" in result.message

    def test_reads_through_a_session_artifact(self, plugin_instance, tmp_path):
        ctx = FakeContext(artifacts=[
            FakeArtifact("art_seed", "json_events", _write_seed(tmp_path, 1))])
        result = plugin_instance.execute(
            {"action": "import_scenario", "artifact_id": "art_seed"}, ctx)
        assert result.ok, result.message
        assert result.result["source"] == "art_seed"

    def test_missing_artifact(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "import_scenario", "artifact_id": "art_gone"}, FakeContext())
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"

    def test_unreadable_file(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=str(tmp_path / "missing.json"))
        assert not result.ok
        assert result.error_code == "ARTIFACT_UNREADABLE"

    def test_gap_analysis_runs_on_an_imported_scenario(self, plugin_instance,
                                                      tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 1))
        scenario_id = result.result["imported"][0]["scenario_id"]
        gap = plugin_instance.execute(
            {"action": "gap_analysis", "scenario_id": scenario_id}, None)
        assert gap.ok
        analysis = gap.result["gap_analysis"]
        assert [e["sequence_order"] for e in analysis["unprotected_events"]] == [2]
        assert [c["name"] for c in analysis["weak_controls"]] == ["Database firewall"]
        assert [c["name"] for c in analysis["easy_bypass"]] == ["Database firewall"]

    def test_markdown_marks_a_projection(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 1))
        scenario_id = result.result["imported"][0]["scenario_id"]
        md = plugin_instance.execute(
            {"action": "export", "scenario_id": scenario_id}, None).result["markdown"]
        assert "**Source:** actor_projection" in md
        assert "**Projected Path:** path-1" in md
        assert "modelled, not observed" in md
        assert "**Tactic:** Initial Access" in md
        assert "**Evidence:** via_software" in md

    def test_analyst_markdown_has_no_projection_caveat(self, plugin_instance,
                                                      scenario_with_data):
        md = plugin_instance.execute(
            {"action": "export", "scenario_id": scenario_with_data},
            None).result["markdown"]
        assert "modelled, not observed" not in md
        assert "Projected Path" not in md

    def test_summary(self, plugin_instance, tmp_path):
        result = _import(plugin_instance, file_path=_write_seed(tmp_path, 8))
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "Imported 6 scenario(s)" in summary
        assert "path-7, path-8" in summary
        assert "modelled, not observed" in summary


class _PromptCapture:
    def __init__(self):
        self.prompts: list[str] = []

    def query_text(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return SimpleNamespace(ok=True, text="summary")


class TestAnalyzeDocumentIsNarrowed:
    def test_prompt_does_not_ask_for_attack_paths(self, plugin_instance):
        llm = _PromptCapture()
        plugin_instance.execute({
            "action": "analyze_document",
            "document_content": "The portal sits behind a WAF.",
        }, FakeContext(llm_query=llm))
        prompt = llm.prompts[0]
        assert "Attack Paths" not in prompt
        assert "Do not construct attack paths" in prompt
        assert "the document does not cite" in prompt

    def test_manifest_points_to_the_projector(self, manifest):
        assert "adversary_path_projector" in manifest["description_long"]
        assert "does not construct attack paths" in manifest["description_long"]
