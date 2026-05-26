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
            "description_short", "description_llm", "author",
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
        assert '"format": "mermaid"' in summary


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
                    "Defense Evasion", "Persistence",
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
        # Should pick highest ordinal non-entry tactic = Defense Evasion (7)
        assert step2["tactic"] == "Defense Evasion"

    def test_preserves_first_step_initial_access(self):
        """Initial Access at step 0 should NOT be reassigned."""
        mitre_db = {
            "T1078": {
                "name": "Valid Accounts",
                "tactics": [
                    "Defense Evasion", "Persistence",
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
                    "Defense Evasion", "Persistence",
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
        """'Command and Control' should be auto-corrected to 'Command And Control'."""
        all_mitre = [
            {"technique_id": "T1219", "technique_name": "Remote Access Software",
             "tactic": "Command and Control", "confidence": "inferred",
             "report_context": "test"},
        ]
        result = _tool_mod._reconcile_mitre_mappings(all_mitre, {"paths": []})
        entry = result[0]
        assert entry["tactic"] == "Command And Control"
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
