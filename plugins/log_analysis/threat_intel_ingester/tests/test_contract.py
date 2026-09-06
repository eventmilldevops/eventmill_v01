"""
Contract tests for the Threat Intel Ingester plugin.

These tests verify the plugin meets the EventMillToolProtocol contract
as defined in tool_plugin_spec.md. They do NOT test analysis quality —
that is the domain of integration and acceptance tests.

Run: pytest tests/test_contract.py -v
"""

import importlib.util
import json
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure plugin module is importable
# ---------------------------------------------------------------------------

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "threat_intel_ingester_tool"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod

_tool_mod = _load_tool_module()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def manifest_path() -> Path:
    return PLUGIN_DIR / "manifest.json"


@pytest.fixture
def manifest(manifest_path: Path) -> dict:
    with open(manifest_path) as f:
        return json.load(f)


@pytest.fixture
def input_schema_path() -> Path:
    return PLUGIN_DIR / "schemas" / "input.schema.json"


@pytest.fixture
def output_schema_path() -> Path:
    return PLUGIN_DIR / "schemas" / "output.schema.json"


@pytest.fixture
def input_schema(input_schema_path: Path) -> dict:
    with open(input_schema_path) as f:
        return json.load(f)


@pytest.fixture
def output_schema(output_schema_path: Path) -> dict:
    with open(output_schema_path) as f:
        return json.load(f)


@pytest.fixture
def example_request() -> dict:
    path = PLUGIN_DIR / "examples" / "request.example.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def example_response() -> dict:
    path = PLUGIN_DIR / "examples" / "response.example.json"
    with open(path) as f:
        return json.load(f)


@dataclass
class MockToolResult:
    """Minimal ToolResult stand-in for summarize_for_llm tests."""
    ok: bool = True
    result: dict = field(default_factory=dict)
    message: str = ""
    output_artifacts: list = field(default_factory=list)


@pytest.fixture
def example_tool_result(example_response: dict) -> MockToolResult:
    return MockToolResult(
        ok=example_response.get("ok", True),
        result=example_response.get("result", {}),
    )


@pytest.fixture
def tool_class():
    return _tool_mod.ThreatIntelIngester


@pytest.fixture
def tool_instance(tool_class):
    return tool_class()


# ---------------------------------------------------------------------------
# Mock ExecutionContext for contract tests
# ---------------------------------------------------------------------------


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
    session_id: str = "test_session_001"
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


# ---------------------------------------------------------------------------
# Test 1: Manifest loads and is valid JSON
# ---------------------------------------------------------------------------


class TestManifestLoads:
    def test_manifest_is_valid_json(self, manifest: dict):
        assert isinstance(manifest, dict)

    def test_manifest_has_required_fields(self, manifest: dict):
        required = [
            "tool_name", "version", "pillar", "display_name",
            "description_short", "description_long", "author",
            "entry_point", "class_name", "artifacts_consumed",
            "artifacts_produced", "capabilities", "input_schema",
            "output_schema", "timeout_class", "safe_for_auto_invoke",
            "stability", "tags",
        ]
        for field_name in required:
            assert field_name in manifest, f"Missing required field: {field_name}"

    def test_tool_name_format(self, manifest: dict):
        import re
        assert re.match(r"^[a-z0-9_]+$", manifest["tool_name"])

    def test_pillar_is_valid(self, manifest: dict):
        valid_pillars = [
            "network_forensics", "cloud_investigation",
            "log_analysis", "risk_assessment", "threat_modeling",
        ]
        assert manifest["pillar"] in valid_pillars

    def test_stability_is_valid(self, manifest: dict):
        valid = ["experimental", "verified", "core", "deprecated"]
        assert manifest["stability"] in valid

    def test_timeout_class_is_valid(self, manifest: dict):
        valid = ["fast", "short", "medium", "slow", "long"]
        assert manifest["timeout_class"] in valid

    def test_capabilities_format(self, manifest: dict):
        import re
        pattern = re.compile(r"^[a-z]+:[A-Za-z0-9_.-]+$")
        for cap in manifest["capabilities"]:
            assert pattern.match(cap), f"Invalid capability format: {cap}"

    def test_artifacts_consumed_valid(self, manifest: dict):
        valid_types = {
            "pcap", "json_events", "log_stream", "risk_model",
            "cloud_audit_log", "pdf_report", "html_report",
            "image", "text", "none",
        }
        for art in manifest["artifacts_consumed"]:
            assert art in valid_types, f"Invalid artifact type: {art}"

    def test_artifacts_produced_valid(self, manifest: dict):
        valid_types = {
            "pcap", "json_events", "log_stream", "risk_model",
            "cloud_audit_log", "pdf_report", "html_report",
            "image", "text", "none",
        }
        for art in manifest["artifacts_produced"]:
            assert art in valid_types, f"Invalid artifact type: {art}"

    def test_version_is_semver(self, manifest: dict):
        import re
        pattern = r"^\d+\.\d+\.\d+([-+][A-Za-z0-9.\-]+)?$"
        assert re.match(pattern, manifest["version"])


# ---------------------------------------------------------------------------
# Test 2: Schemas load and are valid JSON Schema
# ---------------------------------------------------------------------------


class TestSchemasLoad:
    def test_input_schema_loads(self, input_schema: dict):
        assert isinstance(input_schema, dict)
        assert "$schema" in input_schema

    def test_output_schema_loads(self, output_schema: dict):
        assert isinstance(output_schema, dict)
        assert "$schema" in output_schema

    def test_input_schema_has_required(self, input_schema: dict):
        assert "required" in input_schema
        assert "artifact_id" in input_schema["required"]

    def test_output_schema_has_ok(self, output_schema: dict):
        assert "ok" in output_schema.get("properties", {})


# ---------------------------------------------------------------------------
# Test 3: Entry point imports without errors
# ---------------------------------------------------------------------------


class TestEntryPointImports:
    def test_tool_module_imports(self):
        assert _tool_mod is not None

    def test_tool_class_exists(self, tool_class):
        assert tool_class is not None
        assert tool_class.__name__ == "ThreatIntelIngester"


# ---------------------------------------------------------------------------
# Test 4: Tool class can be instantiated
# ---------------------------------------------------------------------------


class TestToolInstantiation:
    def test_instantiation(self, tool_instance):
        assert tool_instance is not None


# ---------------------------------------------------------------------------
# Test 5: validate_inputs accepts the example request
# ---------------------------------------------------------------------------


class TestValidateInputs:
    def test_accepts_valid_example(self, tool_instance, example_request: dict):
        result = tool_instance.validate_inputs(example_request)
        assert result.ok is True
        assert len(result.errors or []) == 0

    def test_rejects_missing_artifact_id(self, tool_instance):
        result = tool_instance.validate_inputs({})
        assert result.ok is False
        assert any("artifact_id" in e for e in result.errors)

    def test_rejects_invalid_ioc_type(self, tool_instance):
        result = tool_instance.validate_inputs({
            "artifact_id": "art_0001",
            "ioc_types": ["ip", "invalid_type"],
        })
        assert result.ok is False
        assert any("invalid_type" in e for e in result.errors)

    def test_rejects_invalid_confidence(self, tool_instance):
        result = tool_instance.validate_inputs({
            "artifact_id": "art_0001",
            "confidence_threshold": "extreme",
        })
        assert result.ok is False

    def test_rejects_max_pages_out_of_range(self, tool_instance):
        result = tool_instance.validate_inputs({
            "artifact_id": "art_0001",
            "max_pages": 500,
        })
        assert result.ok is False

    def test_accepts_minimal_payload(self, tool_instance):
        result = tool_instance.validate_inputs({"artifact_id": "art_0001"})
        assert result.ok is True


# ---------------------------------------------------------------------------
# Test 6: Example request validates against input schema
# ---------------------------------------------------------------------------


class TestExampleValidation:
    def test_example_request_matches_input_schema(
        self, example_request: dict, input_schema: dict
    ):
        """Validate example request against input schema using jsonschema."""
        try:
            import jsonschema
            jsonschema.validate(example_request, input_schema)
        except ImportError:
            # jsonschema not available — do basic structural check
            assert "artifact_id" in example_request

    def test_example_response_matches_output_schema(
        self, example_response: dict, output_schema: dict
    ):
        """Validate example response against output schema using jsonschema."""
        try:
            import jsonschema
            jsonschema.validate(example_response, output_schema)
        except ImportError:
            # Basic structural check
            assert "ok" in example_response
            assert example_response["ok"] is True
            assert "result" in example_response


# ---------------------------------------------------------------------------
# Test 7: summarize_for_llm produces valid output
# ---------------------------------------------------------------------------


class TestSummarizeForLLM:
    def test_returns_non_empty_string(
        self, tool_instance, example_tool_result
    ):
        summary = tool_instance.summarize_for_llm(example_tool_result)
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_under_2000_characters(
        self, tool_instance, example_tool_result
    ):
        summary = tool_instance.summarize_for_llm(example_tool_result)
        assert len(summary) <= 2000, (
            f"Summary is {len(summary)} chars, exceeds 2000 limit"
        )

    def test_contains_ioc_count(
        self, tool_instance, example_tool_result
    ):
        summary = tool_instance.summarize_for_llm(example_tool_result)
        # Should mention the total IOC count from the example
        assert "9" in summary or "IOC" in summary

    def test_contains_mitre_reference(
        self, tool_instance, example_tool_result
    ):
        summary = tool_instance.summarize_for_llm(example_tool_result)
        assert "MITRE" in summary or "T1" in summary

    def test_handles_error_result(self, tool_instance):
        error_result = MockToolResult(
            ok=False,
            message="Artifact art_9999 not found in session.",
        )
        summary = tool_instance.summarize_for_llm(error_result)
        assert isinstance(summary, str)
        assert "failed" in summary.lower()

    def test_no_raw_json_in_summary(
        self, tool_instance, example_tool_result
    ):
        summary = tool_instance.summarize_for_llm(example_tool_result)
        # Summary should be plain text, not JSON
        assert not summary.strip().startswith("{")
        assert not summary.strip().startswith("[")


# ---------------------------------------------------------------------------
# Test 8: metadata returns expected fields
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_returns_dict(self, tool_instance):
        meta = tool_instance.metadata()
        assert isinstance(meta, dict)

    def test_contains_tool_name(self, tool_instance):
        meta = tool_instance.metadata()
        assert "tool_name" in meta
        assert meta["tool_name"] == "threat_intel_ingester"

    def test_contains_version(self, tool_instance):
        meta = tool_instance.metadata()
        assert "version" in meta


# ---------------------------------------------------------------------------
# Test 9: execute returns structured error for missing artifact
# ---------------------------------------------------------------------------


class TestExecuteErrorHandling:
    def test_returns_error_for_missing_artifact(self, tool_instance):
        context = MockExecutionContext(
            artifacts=[],  # No artifacts loaded
        )
        result = tool_instance.execute(
            {"artifact_id": "art_nonexistent"}, context
        )
        assert result.ok is False
        assert result.error_code == "ARTIFACT_NOT_FOUND"

    def test_returns_error_for_wrong_artifact_type(self, tool_instance):
        context = MockExecutionContext(
            artifacts=[
                MockArtifactRef(
                    artifact_id="art_0001",
                    artifact_type="pcap",
                    file_path="/tmp/test.pcap",
                )
            ],
        )
        result = tool_instance.execute(
            {"artifact_id": "art_0001"}, context
        )
        assert result.ok is False
        assert result.error_code == "INPUT_VALIDATION_FAILED"


# ---------------------------------------------------------------------------
# Test 10: Regex extraction utility
# ---------------------------------------------------------------------------


class TestRegexExtraction:
    def test_extracts_ipv4(self):
        text = "The C2 server at 198.51.100.47 was observed."
        iocs = _tool_mod.extract_iocs_regex(text, ["ip"])
        values = [i.value for i in iocs]
        assert "198.51.100.47" in values

    def test_extracts_defanged_ip(self):
        text = "Connect to 198[.]51[.]100[.]47 for updates."
        iocs = _tool_mod.extract_iocs_regex(text, ["ip"])
        values = [i.value for i in iocs]
        assert "198.51.100.47" in values
        defanged = [i.defanged for i in iocs if i.value == "198.51.100.47"]
        assert defanged[0] is True

    def test_extracts_cve(self):
        text = "Exploited CVE-2025-21345 in the management platform."
        iocs = _tool_mod.extract_iocs_regex(text, ["cve"])
        values = [i.value for i in iocs]
        assert "CVE-2025-21345" in values

    def test_extracts_mitre_technique(self):
        text = "Technique T1566.001 was used for initial access."
        iocs = _tool_mod.extract_iocs_regex(text, ["mitre_technique"])
        values = [i.value for i in iocs]
        assert "T1566.001" in values

    def test_extracts_sha256(self):
        text = (
            "Hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
            "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        iocs = _tool_mod.extract_iocs_regex(text, ["hash_sha256"])
        assert len(iocs) == 1

    def test_deduplicates_same_ioc(self):
        text = (
            "IP 198.51.100.47 appeared again at 198.51.100.47 "
            "and once more 198.51.100.47."
        )
        iocs = _tool_mod.extract_iocs_regex(text, ["ip"])
        ip_values = [i.value for i in iocs if i.value == "198.51.100.47"]
        assert len(ip_values) == 1

    def test_empty_text_returns_empty(self):
        iocs = _tool_mod.extract_iocs_regex("", ["ip", "domain", "cve"])
        assert len(iocs) == 0


# ---------------------------------------------------------------------------
# Test 11: Multi-role merge deduplication
# ---------------------------------------------------------------------------


class TestMergeMultiRole:
    """Verify _merge_llm_chunk_results deduplicates by (technique_id, tactic)."""

    def test_same_tid_different_tactics_preserved(self):
        chunks = [
            {
                "refined_iocs": [],
                "additional_mitre_techniques": [
                    {"technique_id": "T1078", "tactic": "Initial Access",
                     "technique_name": "Valid Accounts", "confidence": "inferred",
                     "report_context": "cred harvesting"},
                ],
                "report_metadata": {},
                "attack_graph": {"paths": []},
            },
            {
                "refined_iocs": [],
                "additional_mitre_techniques": [
                    {"technique_id": "T1078", "tactic": "Persistence",
                     "technique_name": "Valid Accounts", "confidence": "inferred",
                     "report_context": "long-term access"},
                ],
                "report_metadata": {},
                "attack_graph": {"paths": []},
            },
        ]
        merged = _tool_mod._merge_llm_chunk_results(chunks)
        mitre = merged["additional_mitre_techniques"]
        assert len(mitre) == 2
        tactics = {m["tactic"] for m in mitre}
        assert tactics == {"Initial Access", "Persistence"}

    def test_exact_duplicate_tid_tactic_deduplicated(self):
        chunks = [
            {
                "refined_iocs": [],
                "additional_mitre_techniques": [
                    {"technique_id": "T1078", "tactic": "Initial Access",
                     "technique_name": "Valid Accounts", "confidence": "inferred",
                     "report_context": "first chunk"},
                ],
                "report_metadata": {},
                "attack_graph": {"paths": []},
            },
            {
                "refined_iocs": [],
                "additional_mitre_techniques": [
                    {"technique_id": "T1078", "tactic": "Initial Access",
                     "technique_name": "Valid Accounts", "confidence": "explicit",
                     "report_context": "second chunk duplicate"},
                ],
                "report_metadata": {},
                "attack_graph": {"paths": []},
            },
        ]
        merged = _tool_mod._merge_llm_chunk_results(chunks)
        mitre = merged["additional_mitre_techniques"]
        assert len(mitre) == 1


# ---------------------------------------------------------------------------
# Test 12: Multi-role reconcile with context_paths
# ---------------------------------------------------------------------------


class TestReconcileMultiRole:
    """Verify _reconcile_mitre_mappings handles (tid, tactic) identity."""

    def test_context_paths_populated_from_graph(self):
        all_mitre = [
            {"technique_id": "T1078", "tactic": "Initial Access",
             "technique_name": "Valid Accounts", "confidence": "inferred",
             "report_context": "from LLM"},
        ]
        attack_graph = {
            "paths": [
                {
                    "path_id": "path-A",
                    "steps": [
                        {"technique_id": "T1078", "tactic": "Initial Access",
                         "leads_to": []},
                    ],
                },
            ],
        }
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, attack_graph)
        entry = result[0]
        assert "context_paths" in entry
        assert "path-A" in entry["context_paths"]

    def test_new_tactic_role_backfilled_from_graph(self):
        all_mitre = [
            {"technique_id": "T1078", "tactic": "Initial Access",
             "technique_name": "Valid Accounts", "confidence": "inferred",
             "report_context": "from LLM"},
        ]
        attack_graph = {
            "paths": [
                {
                    "path_id": "path-A",
                    "steps": [
                        {"technique_id": "T1078", "tactic": "Initial Access",
                         "leads_to": []},
                    ],
                },
                {
                    "path_id": "path-B",
                    "steps": [
                        {"technique_id": "T1078", "tactic": "Persistence",
                         "leads_to": []},
                    ],
                },
            ],
        }
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, attack_graph)
        tactics = {m["tactic"] for m in result if m["technique_id"] == "T1078"}
        assert "Initial Access" in tactics
        assert "Persistence" in tactics
        assert len(result) == 2

    def test_empty_tactic_promoted_from_graph(self):
        all_mitre = [
            {"technique_id": "T1059", "tactic": "",
             "technique_name": "", "confidence": "inferred",
             "report_context": "from IOC"},
        ]
        attack_graph = {
            "paths": [
                {
                    "path_id": "path-X",
                    "steps": [
                        {"technique_id": "T1059", "tactic": "Execution",
                         "leads_to": []},
                    ],
                },
            ],
        }
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, attack_graph)
        assert len(result) == 1
        assert result[0]["tactic"] == "Execution"

    def test_leads_to_orphan_backfilled(self):
        all_mitre = []
        attack_graph = {
            "paths": [
                {
                    "path_id": "path-1",
                    "steps": [
                        {"technique_id": "T1566", "tactic": "Initial Access",
                         "leads_to": ["T9999"]},
                    ],
                },
            ],
        }
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, attack_graph)
        tids = {m["technique_id"] for m in result}
        assert "T1566" in tids
        assert "T9999" in tids


# ---------------------------------------------------------------------------
# Test 13: summarize_for_llm with multi-role counts
# ---------------------------------------------------------------------------


class TestSummarizeMultiRole:
    """Verify summarize_for_llm shows unique vs total when they differ."""

    def test_multi_role_summary_shows_both_counts(self, tool_instance):
        result = MockToolResult(
            ok=True,
            result={
                "report_metadata": {
                    "title": "Test Report",
                    "page_count": 5,
                    "artifact_type": "pdf_report",
                },
                "iocs": [
                    {"ioc_type": "ip", "value": "1.2.3.4", "confidence": "high"},
                ],
                "mitre_mappings": [
                    {"technique_id": "T1078", "tactic": "Initial Access",
                     "technique_name": "Valid Accounts"},
                    {"technique_id": "T1078", "tactic": "Persistence",
                     "technique_name": "Valid Accounts"},
                    {"technique_id": "T1566", "tactic": "Initial Access",
                     "technique_name": "Phishing"},
                ],
                "summary": {
                    "total_iocs": 1,
                    "ioc_breakdown": {"ip": 1},
                    "high_priority_count": 0,
                    "mitre_technique_count": 3,
                    "unique_technique_count": 2,
                    "confidence_distribution": {"low": 0, "medium": 0, "high": 1},
                },
            },
        )
        summary = tool_instance.summarize_for_llm(result)
        assert "2 unique techniques" in summary
        assert "3 tactical roles" in summary

    def test_single_role_summary_shows_standard_format(self, tool_instance):
        result = MockToolResult(
            ok=True,
            result={
                "report_metadata": {
                    "title": "Test Report",
                    "page_count": 3,
                    "artifact_type": "pdf_report",
                },
                "iocs": [],
                "mitre_mappings": [
                    {"technique_id": "T1078", "tactic": "Initial Access",
                     "technique_name": "Valid Accounts"},
                    {"technique_id": "T1566", "tactic": "Initial Access",
                     "technique_name": "Phishing"},
                ],
                "summary": {
                    "total_iocs": 0,
                    "ioc_breakdown": {},
                    "high_priority_count": 0,
                    "mitre_technique_count": 2,
                    "unique_technique_count": 2,
                    "confidence_distribution": {"low": 0, "medium": 0, "high": 0},
                },
            },
        )
        summary = tool_instance.summarize_for_llm(result)
        assert "2 MITRE techniques" in summary
        assert "unique" not in summary

    def test_quick_chart_command_in_summary(self, tool_instance):
        """Summary should include a copy-paste run command for attack_path_visualizer."""
        result = MockToolResult(
            ok=True,
            result={
                "report_metadata": {
                    "title": "Test", "page_count": 1,
                    "artifact_type": "pdf_report",
                },
                "iocs": [],
                "mitre_mappings": [],
                "summary": {
                    "total_iocs": 0, "ioc_breakdown": {},
                    "high_priority_count": 0,
                    "mitre_technique_count": 0,
                    "unique_technique_count": 0,
                    "confidence_distribution": {},
                },
            },
            output_artifacts=[
                {"artifact_id": "art_abc123", "artifact_type": "json_events"},
            ],
        )
        summary = tool_instance.summarize_for_llm(result)
        assert "Quick chart:" in summary
        assert "attack_path_visualizer" in summary
        assert "art_abc123" in summary
        assert "--format mermaid" in summary


# ---------------------------------------------------------------------------
# Test 14: Tactic progression fix
# ---------------------------------------------------------------------------


class TestTacticProgression:
    """Verify _fix_tactic_progression reassigns entry-only tactics on non-first steps."""

    def test_reassigns_initial_access_at_step2(self):
        """T1078.004 at step 2 with 'Initial Access' should be reassigned."""
        mitre_db = {
            "T1566.004": {
                "name": "Spearphishing Voice",
                "tactics": ["Initial Access"],
            },
            "T1078.004": {
                "name": "Cloud Accounts",
                "tactics": [
                    "Stealth", "Persistence",
                    "Privilege Escalation", "Initial Access",
                ],
            },
        }
        attack_graph = {
            "paths": [
                {
                    "path_id": "test-path",
                    "steps": [
                        {"technique_id": "T1566.004", "tactic": "Initial Access",
                         "leads_to": ["T1078.004"]},
                        {"technique_id": "T1078.004", "tactic": "Initial Access",
                         "leads_to": []},
                    ],
                },
            ],
        }
        _, count = _tool_mod._fix_tactic_progression(attack_graph, mitre_db)
        assert count == 1
        step2 = attack_graph["paths"][0]["steps"][1]
        assert step2["tactic"] != "Initial Access"
        # Should pick highest ordinal non-entry tactic = Stealth (7)
        assert step2["tactic"] == "Stealth"

    def test_preserves_first_step_initial_access(self):
        """Initial Access at step 0 should NOT be reassigned."""
        mitre_db = {
            "T1078": {
                "name": "Valid Accounts",
                "tactics": [
                    "Stealth", "Persistence",
                    "Privilege Escalation", "Initial Access",
                ],
            },
        }
        attack_graph = {
            "paths": [
                {
                    "path_id": "first-step",
                    "steps": [
                        {"technique_id": "T1078", "tactic": "Initial Access",
                         "leads_to": []},
                    ],
                },
            ],
        }
        _, count = _tool_mod._fix_tactic_progression(attack_graph, mitre_db)
        assert count == 0
        assert attack_graph["paths"][0]["steps"][0]["tactic"] == "Initial Access"

    def test_leaves_non_entry_tactic_untouched(self):
        """Persistence at step 2 should not be reassigned."""
        mitre_db = {
            "T1078": {
                "name": "Valid Accounts",
                "tactics": [
                    "Stealth", "Persistence",
                    "Privilege Escalation", "Initial Access",
                ],
            },
        }
        attack_graph = {
            "paths": [
                {
                    "path_id": "ok-path",
                    "steps": [
                        {"technique_id": "T1566", "tactic": "Initial Access",
                         "leads_to": ["T1078"]},
                        {"technique_id": "T1078", "tactic": "Persistence",
                         "leads_to": []},
                    ],
                },
            ],
        }
        _, count = _tool_mod._fix_tactic_progression(attack_graph, mitre_db)
        assert count == 0
        assert attack_graph["paths"][0]["steps"][1]["tactic"] == "Persistence"

    def test_keeps_entry_tactic_when_no_alternatives(self):
        """If all valid tactics are entry-only, keep the original."""
        mitre_db = {
            "T1595": {
                "name": "Active Scanning",
                "tactics": ["Reconnaissance"],
            },
        }
        attack_graph = {
            "paths": [
                {
                    "path_id": "recon-path",
                    "steps": [
                        {"technique_id": "T1566", "tactic": "Initial Access",
                         "leads_to": ["T1595"]},
                        {"technique_id": "T1595", "tactic": "Reconnaissance",
                         "leads_to": []},
                    ],
                },
            ],
        }
        _, count = _tool_mod._fix_tactic_progression(attack_graph, mitre_db)
        assert count == 0
        assert attack_graph["paths"][0]["steps"][1]["tactic"] == "Reconnaissance"

    def test_end_to_end_reconcile_splits_multi_role(self):
        """Full reconcile: T1078.004 in 2 paths, same LLM tactic, should split after fix."""
        all_mitre = [
            {"technique_id": "T1078.004", "tactic": "Initial Access",
             "technique_name": "Cloud Accounts", "confidence": "inferred",
             "report_context": "from LLM"},
        ]
        attack_graph = {
            "paths": [
                {
                    "path_id": "path-A",
                    "steps": [
                        {"technique_id": "T1078.004", "tactic": "Initial Access",
                         "leads_to": []},
                    ],
                },
                {
                    "path_id": "path-B",
                    "steps": [
                        {"technique_id": "T1566", "tactic": "Initial Access",
                         "leads_to": ["T1078.004"]},
                        {"technique_id": "T1078.004", "tactic": "Initial Access",
                         "leads_to": []},
                    ],
                },
            ],
        }
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, attack_graph)
        t1078_entries = [m for m in result if m["technique_id"] == "T1078.004"]
        # Should now have 2 entries — one with Initial Access (path-A),
        # one with the reassigned tactic (path-B)
        tactics = {m["tactic"] for m in t1078_entries}
        assert "Initial Access" in tactics
        assert len(tactics) == 2  # two distinct tactics


# ---------------------------------------------------------------------------
# Test 15: Tactic case-sensitivity and mismatch flagging
# ---------------------------------------------------------------------------


class TestTacticValidation:
    """Verify case-insensitive tactic comparison and tactic_mismatch flag."""

    def test_auto_corrects_tactic_casing(self):
        """'Command And Control' should be auto-corrected to the DB's 'Command and Control'."""
        all_mitre = [
            {"technique_id": "T1219", "technique_name": "Remote Access Software",
             "tactic": "Command And Control", "confidence": "inferred",
             "report_context": "test"},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        entry = result[0]
        assert entry["tactic"] == "Command and Control"
        assert entry.get("mitre_validated") is True
        assert "tactic_mismatch" not in entry

    def test_exact_match_no_flag(self):
        """Exact tactic match should not add tactic_mismatch."""
        all_mitre = [
            {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
             "tactic": "Initial Access", "confidence": "inferred",
             "report_context": "test"},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        entry = result[0]
        assert entry["tactic"] == "Initial Access"
        assert entry.get("mitre_validated") is True
        assert "tactic_mismatch" not in entry

    def test_genuine_mismatch_flagged(self):
        """T1078 with 'Lateral Movement' should get tactic_mismatch=True."""
        all_mitre = [
            {"technique_id": "T1078", "technique_name": "Valid Accounts",
             "tactic": "Lateral Movement", "confidence": "inferred",
             "report_context": "test"},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        entry = result[0]
        assert entry["tactic"] == "Lateral Movement"  # kept as-is
        assert entry.get("mitre_validated") is True
        assert entry.get("tactic_mismatch") is True
        assert "Persistence" in entry["allowed_tactics"]
        assert "tactic_corrected_from" not in entry

    def test_mismatch_absent_when_no_db(self):
        """When MITRE DB is empty, tactic_mismatch should not be set."""
        import unittest.mock as mock
        all_mitre = [
            {"technique_id": "T1078", "technique_name": "Valid Accounts",
             "tactic": "Lateral Movement", "confidence": "inferred",
             "report_context": "test"},
        ]
        with mock.patch.object(_tool_mod, "_get_mitre_db", return_value={}):
            result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        entry = result[0]
        assert "tactic_mismatch" not in entry
        assert "mitre_validated" not in entry


# ---------------------------------------------------------------------------
# Test 16: Legacy tactic migration (ATT&CK v19 retired "Defense Evasion")
# ---------------------------------------------------------------------------


class TestLegacyTacticMigration:
    """Verify retired tactics are mapped onto their v19 successors."""

    def test_tactic_order_uses_v19_vocabulary(self):
        assert "Defense Evasion" not in _tool_mod.TACTIC_ORDER
        assert "Stealth" in _tool_mod.TACTIC_ORDER
        assert "Defense Impairment" in _tool_mod.TACTIC_ORDER
        assert (
            _tool_mod.TACTIC_ORDER["Privilege Escalation"]
            < _tool_mod.TACTIC_ORDER["Stealth"]
            < _tool_mod.TACTIC_ORDER["Defense Impairment"]
            < _tool_mod.TACTIC_ORDER["Credential Access"]
        )

    def test_prompt_uses_v19_vocabulary(self):
        prompt = _tool_mod.LLM_REFINEMENT_PROMPT
        assert "Stealth, Defense Impairment" in prompt
        assert "Never output \"Defense Evasion\"" in prompt

    def test_mapping_migrates_to_stealth(self):
        """T1027 only lists Stealth, so 'Defense Evasion' resolves to it."""
        all_mitre = [
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
             "tactic": "Defense Evasion", "confidence": "inferred",
             "report_context": "test"},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        entry = result[0]
        assert entry["tactic"] == "Stealth"
        assert entry.get("mitre_validated") is True
        assert "tactic_mismatch" not in entry

    def test_mapping_migrates_to_defense_impairment(self):
        """T1553 only lists Defense Impairment."""
        all_mitre = [
            {"technique_id": "T1553", "technique_name": "Subvert Trust Controls",
             "tactic": "Defense Evasion", "confidence": "inferred",
             "report_context": "test"},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        assert result[0]["tactic"] == "Defense Impairment"
        assert "tactic_mismatch" not in result[0]

    def test_graph_steps_migrate_and_backfill_under_successor(self):
        """Attack-graph steps are rewritten before backfill, so the backfilled
        mapping entry carries the successor tactic and no mismatch."""
        attack_graph = {
            "paths": [
                {
                    "path_id": "obf-path",
                    "steps": [
                        {"technique_id": "T1566", "tactic": "Initial Access",
                         "leads_to": ["T1027"]},
                        {"technique_id": "T1027", "tactic": "Defense Evasion",
                         "leads_to": []},
                    ],
                },
            ],
        }
        result = _tool_mod._reconcile_mitre_mappings([], attack_graph)
        assert attack_graph["paths"][0]["steps"][1]["tactic"] == "Stealth"
        t1027 = next(e for e in result if e["technique_id"] == "T1027")
        assert t1027["tactic"] == "Stealth"
        assert t1027["context_paths"] == ["obf-path"]
        assert "tactic_mismatch" not in t1027

    def test_migrated_entry_merges_with_existing_successor_entry(self):
        all_mitre = [
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
             "tactic": "Stealth", "confidence": "explicit",
             "report_context": "a", "context_paths": ["p1"]},
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
             "tactic": "Defense Evasion", "confidence": "inferred",
             "report_context": "b", "context_paths": ["p2"]},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        t1027 = [e for e in result if e["technique_id"] == "T1027"]
        assert len(t1027) == 1
        assert t1027[0]["tactic"] == "Stealth"
        assert sorted(t1027[0]["context_paths"]) == ["p1", "p2"]

    def test_unknown_technique_keeps_legacy_tactic(self):
        """A non-ATT&CK ID cannot be resolved, so the value is left alone."""
        all_mitre = [
            {"technique_id": "T9999", "technique_name": "Made Up",
             "tactic": "Defense Evasion", "confidence": "inferred",
             "report_context": "test"},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        assert result[0]["tactic"] == "Defense Evasion"
        assert result[0].get("mitre_validated") is False

    def test_no_db_leaves_everything_untouched(self):
        import unittest.mock as mock
        all_mitre = [
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
             "tactic": "Defense Evasion", "confidence": "inferred",
             "report_context": "test"},
        ]
        with mock.patch.object(_tool_mod, "_get_mitre_db", return_value={}):
            result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        assert result[0]["tactic"] == "Defense Evasion"


# ---------------------------------------------------------------------------
# Test 17: Deterministic tactic correction (sibling swap, single-tactic)
# ---------------------------------------------------------------------------


class TestTacticCorrection:
    """Labels that are unambiguously wrong are fixed; ambiguous ones are
    flagged with the allowed options and surfaced in the summary."""

    def _entry(self, tid, name, tactic):
        return {"technique_id": tid, "technique_name": name, "tactic": tactic,
                "confidence": "inferred", "report_context": "test"}

    def test_sibling_swap_when_only_other_sibling_allowed(self):
        """T1578.002 allows only Defense Impairment; LLM said Stealth."""
        result = _tool_mod._reconcile_mitre_mappings(
            [self._entry("T1578.002", "Create Cloud Instance", "Stealth")],
            {"paths": []},
        )
        e = result[0]
        assert e["tactic"] == "Defense Impairment"
        assert e["tactic_corrected_from"] == "Stealth"
        assert "tactic_mismatch" not in e

    def test_sibling_swap_with_multi_tactic_technique(self):
        """T1556 allows Defense Impairment / Persistence / Credential Access;
        Stealth is the wrong sibling and there is exactly one right one."""
        result = _tool_mod._reconcile_mitre_mappings(
            [self._entry("T1556", "Modify Authentication Process", "Stealth")],
            {"paths": []},
        )
        assert result[0]["tactic"] == "Defense Impairment"
        assert result[0]["tactic_corrected_from"] == "Stealth"

    def test_single_tactic_technique_corrected(self):
        """T1490 only allows Impact; any other label is replaced."""
        result = _tool_mod._reconcile_mitre_mappings(
            [self._entry("T1490", "Inhibit System Recovery", "Defense Impairment")],
            {"paths": []},
        )
        assert result[0]["tactic"] == "Impact"
        assert result[0]["tactic_corrected_from"] == "Defense Impairment"
        assert "tactic_mismatch" not in result[0]

    def test_graph_steps_corrected_to_match(self):
        graph = {"paths": [{"path_id": "p", "steps": [
            {"technique_id": "T1566", "tactic": "Initial Access", "leads_to": ["T1490"]},
            {"technique_id": "T1490", "tactic": "Defense Impairment", "leads_to": []},
        ]}]}
        result = _tool_mod._reconcile_mitre_mappings([], graph)
        assert graph["paths"][0]["steps"][1]["tactic"] == "Impact"
        t1490 = next(e for e in result if e["technique_id"] == "T1490")
        assert t1490["tactic"] == "Impact"
        assert "tactic_mismatch" not in t1490

    def test_ambiguous_label_is_flagged_not_corrected(self):
        """T1078 allows four tactics; 'Execution' is none of them and no
        sibling rule applies, so the analyst has to decide."""
        result = _tool_mod._reconcile_mitre_mappings(
            [self._entry("T1078", "Valid Accounts", "Execution")],
            {"paths": []},
        )
        e = result[0]
        assert e["tactic"] == "Execution"
        assert e["tactic_mismatch"] is True
        assert set(e["allowed_tactics"]) == {
            "Stealth", "Persistence", "Privilege Escalation", "Initial Access",
        }

    def test_valid_label_untouched(self):
        result = _tool_mod._reconcile_mitre_mappings(
            [self._entry("T1556", "Modify Authentication Process", "Credential Access")],
            {"paths": []},
        )
        assert result[0]["tactic"] == "Credential Access"
        assert "tactic_corrected_from" not in result[0]

    def test_summary_reports_corrections_and_action(self, tool_instance):
        mappings = [
            {"technique_id": "T1490", "technique_name": "Inhibit System Recovery",
             "tactic": "Impact", "tactic_corrected_from": "Defense Impairment"},
            {"technique_id": "T1078", "technique_name": "Valid Accounts",
             "tactic": "Execution", "tactic_mismatch": True,
             "allowed_tactics": ["Stealth", "Persistence"]},
        ]
        result = MockToolResult(
            ok=True,
            result={
                "report_metadata": {"artifact_type": "text", "page_count": 1},
                "iocs": [],
                "mitre_mappings": mappings,
                "attack_graph": {},
                "summary": {
                    "total_iocs": 0, "ioc_breakdown": {},
                    "high_priority_count": 0,
                    "mitre_technique_count": 2, "unique_technique_count": 2,
                    "tactic_corrected_count": 1, "tactic_mismatch_count": 1,
                },
            },
        )
        text = tool_instance.summarize_for_llm(result)
        assert "1 tactic label(s) corrected automatically" in text
        assert "ACTION: 1 tactic label(s) need analyst confirmation" in text
        assert "T1078 labelled 'Execution', ATT&CK allows Stealth / Persistence" in text


# ---------------------------------------------------------------------------
# Test 18: Document profile (pre-flight, no LLM)
# ---------------------------------------------------------------------------


class TestDocumentProfile:
    def _pdf_text(self, pages: list[str]) -> str:
        return "\n\n".join(pages)

    def test_narrative_document(self):
        text = self._pdf_text([
            "The actor used spearphishing (T1566.001) to gain access.",
            "They then moved laterally and encrypted files (T1486).",
            "Contact was made with 203.0.113.5 for C2.",
        ])
        iocs = _tool_mod.extract_iocs_regex(text, ["ip", "mitre_technique"])
        prof = _tool_mod._profile_document(text, iocs, "pdf_report", 3)
        assert prof["pages"] == 3
        assert prof["candidates"] == 3
        assert prof["candidates_by_type"] == {"ip": 1, "mitre_technique": 2}
        assert prof["profile"] == "narrative"
        assert prof["candidates_per_page"] == 1.0
        assert prof["max_candidates_on_a_page"] == 1
        assert prof["estimated_output_tokens"] == (
            _tool_mod._OUTPUT_TOKENS_BASE + 3 * _tool_mod._OUTPUT_TOKENS_PER_IOC
        )

    def test_ioc_dense_document(self):
        page1 = "\n".join(f"198.51.100.{i} scanning" for i in range(1, 41))
        page2 = "\n".join(f"198.51.101.{i} scanning" for i in range(1, 41))
        text = self._pdf_text([page1, page2])
        iocs = _tool_mod.extract_iocs_regex(text, ["ip"])
        prof = _tool_mod._profile_document(text, iocs, "pdf_report", 2)
        assert prof["candidates"] == 80
        assert prof["candidates_per_page"] == 40.0
        assert prof["max_candidates_on_a_page"] == 40
        assert prof["profile"] == "ioc_dense"

    def test_non_pdf_is_one_page(self):
        text = "203.0.113.9 and 203.0.113.10"
        iocs = _tool_mod.extract_iocs_regex(text, ["ip"])
        prof = _tool_mod._profile_document(text, iocs, "text", 2)
        assert prof["pages"] == 1
        assert prof["max_candidates_on_a_page"] == 2
        assert prof["candidates_per_page"] == 2.0

    def test_dense_text_dump_exceeds_single_call(self):
        text = "\n".join(f"198.51.{i // 250}.{i % 250} node" for i in range(1, 400))
        iocs = _tool_mod.extract_iocs_regex(text, ["ip"])
        prof = _tool_mod._profile_document(text, iocs, "text", 399)
        assert prof["profile"] == "ioc_dense"
        # 399 records fit the tier's real reply budget; only latency splits them
        assert prof["exceeds_single_call_output"] is False

        bigger = "\n".join(f"198.51.{i // 250}.{i % 250} node" for i in range(1, 1200))
        prof = _tool_mod._profile_document(
            bigger, _tool_mod.extract_iocs_regex(bigger, ["ip"]), "text", 1199,
        )
        assert prof["exceeds_single_call_output"] is True

    def test_no_candidates(self):
        prof = _tool_mod._profile_document("nothing here", [], "text", 1)
        assert prof["candidates"] == 0
        assert prof["profile"] == "narrative"
        assert prof["estimated_output_tokens"] == _tool_mod._OUTPUT_TOKENS_BASE


class TestTruncatedRepairLogging:
    def test_repair_is_a_warning_with_counts(self, caplog):
        import logging
        truncated = (
            '{"refined_iocs": [{"value": "1.2.3.4", "ioc_type": "ip"}, '
            '{"value": "5.6.7.8", "ioc_type": "ip"}], '
            '"additional_mitre_techniques": [{"technique_id": "T1566"}], '
            '"report_metadata": {"title": "cut off he'
        )
        with caplog.at_level(logging.WARNING, logger="eventmill.plugin.threat_intel_ingester"):
            parsed = _tool_mod._parse_llm_json(truncated)
        assert parsed is not None
        assert len(parsed["refined_iocs"]) == 2
        msgs = [r.getMessage() for r in caplog.records if "[TRUNCATED]" in r.getMessage()]
        assert msgs, "repair outcome must be logged at WARNING"
        assert "2 refined_iocs and 1 techniques kept" in msgs[0]


# ---------------------------------------------------------------------------
# Test 19: Page-range batched native ingestion
# ---------------------------------------------------------------------------


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
    model_used: str | None = "mock-heavy"
    transport_path: str | None = "inline_bytes"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


class _NativeLLM:
    """Records every document / text call and answers with JSON that echoes
    the first two candidates it was given, so merged results are checkable."""

    def __init__(
        self,
        fail_labels: set[str] | None = None,
        truncate_over: int | None = None,
    ):
        self.doc_calls: list[dict] = []
        self.text_calls: list[dict] = []
        self.fail_labels = fail_labels or set()
        # A call carrying more than this many candidates comes back cut off at
        # the output cap, the way a real over-large batch does.
        self.truncate_over = truncate_over

    def supports_native_document(self, mime_type: str) -> bool:
        return mime_type == "application/pdf"

    @staticmethod
    def _candidates_from_prompt(prompt: str) -> list[str]:
        vals = []
        for line in prompt.splitlines():
            if line.startswith("- [ip] "):
                vals.append(line.split("- [ip] ", 1)[1].split(" |", 1)[0])
        return vals

    def _reply(self, values: list[str], label: str) -> str:
        return json.dumps({
            "refined_iocs": [
                {"value": v, "ioc_type": "ip", "confidence": "high", "priority": "medium",
                 "context": f"seen in {label}", "related_mitre": [], "is_false_positive": False}
                for v in values[:2]
            ],
            "additional_mitre_techniques": [
                {"technique_id": "T1595.001", "technique_name": "Scanning IP Blocks",
                 "tactic": "Reconnaissance", "confidence": "inferred", "report_context": label},
            ],
            "report_metadata": {"title": "Batched Report", "attributed_actor": "Unattributed"},
            "attack_graph": {"paths": [], "convergence_points": [], "branch_points": []},
        })

    def query_with_document(self, prompt, artifact, system_context=None, max_tokens=8192,
                            grounding_data=None, hints=None):
        label = (artifact.metadata or {}).get("page_range", "whole")
        self.doc_calls.append({
            "artifact_id": artifact.artifact_id,
            "file_path": artifact.file_path,
            "page_range": label,
            "candidates": self._candidates_from_prompt(prompt),
            "prompt": prompt,
        })
        if str(label) in self.fail_labels:
            return _Resp(ok=False, text=None, error="504 DEADLINE_EXCEEDED")
        values = self._candidates_from_prompt(prompt)
        if self.truncate_over is not None and len(values) > self.truncate_over:
            body = self._reply(values, str(label))
            return _Resp(
                text=body[: len(body) // 2],
                finish_reason="MAX_TOKENS",
                truncated=True,
            )
        return _Resp(text=self._reply(values, str(label)))

    def query_text(self, prompt, system_context=None, max_tokens=4096, grounding_data=None,
                   hints=None):
        vals = self._candidates_from_prompt(prompt)
        self.text_calls.append({"candidates": vals})
        return _Resp(text=self._reply(vals, "chunk"))


def _dense_pages(n_pages: int, per_page: int) -> list[str]:
    pages = []
    for pg in range(n_pages):
        pages.append("\n".join(
            f"198.{pg + 1}.{i // 250}.{i % 250} scanner" for i in range(per_page)
        ))
    return pages


@pytest.fixture
def batched_run(tmp_path, monkeypatch):
    """Wire the ingester for a 12-page, 30-candidates-per-page PDF without
    touching pdfplumber or pypdf."""
    pages = _dense_pages(12, 30)
    monkeypatch.setattr(_tool_mod, "extract_pdf_page_texts", lambda path, max_pages=50: pages[:max_pages])

    written: list[list[tuple[int, int]]] = []

    def fake_split(path, ranges, out_dir, stem=None):
        written.append(list(ranges))
        out = []
        for a, b in ranges:
            f = Path(out_dir) / f"{stem}_p{a}-{b}.pdf"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b"%PDF-fake")
            out.append(f)
        return out

    monkeypatch.setattr(_tool_mod, "split_pdf", fake_split)
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))

    pdf = tmp_path / "dense.pdf"
    pdf.write_bytes(b"%PDF-fake")
    artifact = MockArtifactRef(artifact_id="art_dense", artifact_type="pdf_report", file_path=str(pdf))
    registered: list[dict] = []

    def register(artifact_type, file_path, source_tool, metadata):
        registered.append({"artifact_type": artifact_type, "file_path": file_path})
        return MockArtifactRef(artifact_id="art_out", artifact_type=artifact_type, file_path=file_path)

    def make_context(llm):
        return MockExecutionContext(
            artifacts=[artifact], llm_enabled=True, llm_query=llm, register_artifact=register,
        )

    return {"pages": pages, "written": written, "make_context": make_context, "tmp": tmp_path}


class TestBatchedNativeIngestion:
    def test_dense_pdf_is_split_and_every_batch_sent_natively(self, tool_instance, batched_run):
        llm = _NativeLLM()
        result = tool_instance.execute({"artifact_id": "art_dense"}, batched_run["make_context"](llm))
        assert result.ok, result.message
        summary = result.result["summary"]
        plan = summary["ingestion_plan"]
        assert plan["strategy"] == "native_batched"
        assert plan["batch_count"] > 1
        # one document call per batch, each with its own sub-PDF and page range
        assert len(llm.doc_calls) == plan["batch_count"]
        # each range is cut only when its call is about to run
        cut = [rng for call in batched_run["written"] for rng in call]
        assert cut == [(b["start"], b["end"]) for b in plan["batches"]]
        for call, batch in zip(llm.doc_calls, plan["batches"]):
            assert call["page_range"] == [batch["start"], batch["end"]]
            assert call["file_path"].endswith(f"_p{batch['start']}-{batch['end']}.pdf")
            assert f"pages {batch['start']}-{batch['end']} of 12" in call["prompt"]
            # only that batch's candidates were sent
            assert len(call["candidates"]) == batch["candidates"]
        # every page covered exactly once
        covered = [pg for b in plan["batches"] for pg in range(b["start"], b["end"] + 1)]
        assert covered == list(range(1, 13))
        # results merged across batches; no chunked text calls were needed
        assert llm.text_calls == []
        assert summary["ingestion_mode"] == "llm"
        assert len(result.result["iocs"]) == 2 * plan["batch_count"]
        assert "native_s" in summary["timings"] and "chunks_s" not in summary["timings"]
        # temp sub-PDFs are cleaned up
        assert not list((batched_run["tmp"] / "artifacts").glob("*_batches_*"))

    def test_failed_batch_falls_back_to_chunked_text_for_its_pages_only(self, tool_instance, batched_run):
        probe = _NativeLLM()
        tool_instance.execute({"artifact_id": "art_dense"}, batched_run["make_context"](probe))
        second = probe.doc_calls[1]["page_range"]
        llm = _NativeLLM(fail_labels={str(second)})
        result = tool_instance.execute({"artifact_id": "art_dense"}, batched_run["make_context"](llm))
        assert result.ok
        summary = result.result["summary"]
        # chunked path ran, and only over the failed batch's candidates
        failed_candidates = set(probe.doc_calls[1]["candidates"])
        sent = {c for call in llm.text_calls for c in call["candidates"]}
        assert sent == failed_candidates
        assert "chunks_s" in summary["timings"]
        # native results from the surviving batches plus the chunked results
        # for the failed pages are all in the merge (2 records per call)
        surviving_native = len(llm.doc_calls) - 1
        assert len(result.result["iocs"]) == 2 * (surviving_native + len(llm.text_calls))
        assert any("seen in chunk" in i.get("context", "") for i in result.result["iocs"])
        assert summary["ingestion_mode"] == "llm"

    def test_small_pdf_still_single_native_call(self, tool_instance, batched_run, monkeypatch):
        monkeypatch.setattr(_tool_mod, "extract_pdf_page_texts", lambda path, max_pages=50: _dense_pages(2, 3))
        llm = _NativeLLM()
        result = tool_instance.execute({"artifact_id": "art_dense"}, batched_run["make_context"](llm))
        assert result.ok
        assert result.result["summary"]["ingestion_plan"]["strategy"] == "native"
        assert len(llm.doc_calls) == 1
        assert llm.doc_calls[0]["artifact_id"] == "art_dense"  # original artifact, no split
        assert batched_run["written"] == []

    def test_split_failure_falls_back_to_chunked_text_not_one_giant_call(
        self, tool_instance, batched_run, monkeypatch,
    ):
        """Sending the whole dense document in one call is what truncates it —
        when the pages cannot be cut, the small-chunk text path takes over."""
        def boom(*a, **k):
            raise _tool_mod.PdfSplitError("pypdf missing")
        monkeypatch.setattr(_tool_mod, "split_pdf", boom)
        llm = _NativeLLM()
        result = tool_instance.execute({"artifact_id": "art_dense"}, batched_run["make_context"](llm))
        assert result.ok
        assert llm.doc_calls == []
        assert llm.text_calls
        for call in llm.text_calls:
            assert len(call["candidates"]) <= _tool_mod._MAX_IOC_PER_CHUNK

    def test_truncated_batch_is_halved_and_rerun(self, tool_instance, batched_run):
        """A reply cut off at the output cap is a partial answer: the range is
        split and re-sent, not accepted with the missing indicators dropped."""
        llm = _NativeLLM(truncate_over=20)
        result = tool_instance.execute({"artifact_id": "art_dense"}, batched_run["make_context"](llm))
        assert result.ok
        summary = result.result["summary"]
        plan = summary["ingestion_plan"]
        # more calls than the plan asked for, and the extra ones are narrower
        assert len(llm.doc_calls) > plan["batch_count"]
        assert summary["native_calls"] == len(llm.doc_calls)
        first_over = next(c for c in llm.doc_calls if len(c["candidates"]) > 20)
        halves = [
            c for c in llm.doc_calls
            if c["page_range"] != first_over["page_range"]
            and first_over["page_range"][0] <= c["page_range"][0]
            and c["page_range"][1] <= first_over["page_range"][1]
        ]
        assert halves, "the truncated range was never re-run in smaller pieces"
        assert sum(len(h["candidates"]) for h in halves) >= len(first_over["candidates"])

    def test_truncated_single_page_falls_back_to_chunked_text(
        self, tool_instance, batched_run, monkeypatch,
    ):
        """A page that truncates on its own cannot be split further, so its
        candidates go to the text path rather than being lost."""
        monkeypatch.setattr(
            _tool_mod, "extract_pdf_page_texts",
            lambda path, max_pages=50: _dense_pages(1, 40),
        )
        llm = _NativeLLM(truncate_over=1)
        result = tool_instance.execute({"artifact_id": "art_dense"}, batched_run["make_context"](llm))
        assert result.ok
        assert llm.text_calls
        assert result.result["summary"]["ingestion_mode"] == "llm"

    def test_manifest_budget_covers_batched_runs(self, manifest):
        assert manifest["timeout_class"] == "long"
