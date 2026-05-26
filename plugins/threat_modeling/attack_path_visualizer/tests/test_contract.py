"""Contract compliance tests for attack_path_visualizer."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "attack_path_visualizer_tool"
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
    return _tool_mod.AttackPathVisualizer()


@pytest.fixture
def sample_stages():
    """Ransomware attack path with controls and gaps."""
    return [
        {
            "name": "Initial Access",
            "technique_claimed": "Spear phishing with malicious attachment",
            "mitre_technique_id": "T1566.001",
            "stage_present": True,
            "relevance": "required",
            "controls": [
                {
                    "control_name": "Email Gateway Filter",
                    "control_type": "preventive",
                    "effectiveness_rating": "moderate",
                },
                {
                    "control_name": "Security Awareness Training",
                    "control_type": "preventive",
                    "effectiveness_rating": "weak",
                },
            ],
            "gaps_detected": [],
        },
        {
            "name": "Execution",
            "technique_claimed": "User opens malicious macro",
            "mitre_technique_id": "T1204.002",
            "stage_present": True,
            "relevance": "required",
            "controls": [
                {
                    "control_name": "EDR Agent",
                    "control_type": "detective",
                    "effectiveness_rating": "strong",
                },
            ],
            "gaps_detected": [],
        },
        {
            "name": "Privilege Escalation",
            "technique_claimed": "Exploiting unpatched service",
            "mitre_technique_id": "T1068",
            "stage_present": True,
            "relevance": "required",
            "controls": [
                {
                    "control_name": "EDR Agent",
                    "control_type": "detective",
                    "effectiveness_rating": "strong",
                },
            ],
            "gaps_detected": ["Patching cadence is 30+ days behind schedule"],
        },
        {
            "name": "Impact/Action on Objective",
            "technique_claimed": "Data encryption for ransom",
            "mitre_technique_id": "T1486",
            "stage_present": True,
            "relevance": "required",
            "controls": [],
            "gaps_detected": ["No ransomware-specific controls"],
        },
        {
            "name": "Exfiltration",
            "stage_present": False,
            "relevance": "not_applicable",
            "controls": [],
            "gaps_detected": [],
        },
    ]


@pytest.fixture
def stages_with_missing(sample_stages):
    """Stages with a missing required stage."""
    return sample_stages + [
        {
            "name": "Lateral Movement",
            "stage_present": False,
            "relevance": "required",
            "controls": [],
            "gaps_detected": [],
        },
    ]


class TestManifest:
    def test_required_fields(self, manifest):
        for field in ["tool_name", "version", "pillar", "entry_point", "class_name"]:
            assert field in manifest

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "attack_path_visualizer"

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()

    def test_safe_for_auto_invoke(self, manifest):
        assert manifest["safe_for_auto_invoke"] is True

    def test_no_llm_required(self, manifest):
        assert manifest["requires_llm"] is False


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "attack_path_visualizer"

    def test_validate_valid(self, plugin_instance, sample_stages):
        result = plugin_instance.validate_inputs({"stages": sample_stages})
        assert result.ok

    def test_validate_missing_stages(self, plugin_instance):
        result = plugin_instance.validate_inputs({})
        assert not result.ok

    def test_validate_invalid_format(self, plugin_instance, sample_stages):
        result = plugin_instance.validate_inputs({"stages": sample_stages, "format": "html"})
        assert not result.ok

    def test_validate_all_formats(self, plugin_instance, sample_stages):
        for fmt in ("ascii", "mermaid", "compact", "both"):
            result = plugin_instance.validate_inputs({"stages": sample_stages, "format": fmt})
            assert result.ok, f"Failed for format={fmt}"


class TestAsciiRendering:
    def test_ascii_output(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "ascii",
            "attack_type": "ransomware",
            "attack_narrative": "APT group deploys ransomware via spear phishing",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        assert "RANSOMWARE" in viz
        assert "Initial Access" in viz
        assert "T1566.001" in viz
        assert "Email Gateway Filter" in viz
        assert "Patching cadence" in viz

    def test_ascii_stages_counted(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({"stages": sample_stages, "format": "ascii"}, None)
        assert result.ok
        assert result.result["stages_rendered"] == 4  # 4 present, 1 N/A

    def test_ascii_missing_required(self, plugin_instance, stages_with_missing):
        result = plugin_instance.execute({"stages": stages_with_missing, "format": "ascii"}, None)
        assert result.ok
        assert result.result["missing_required"] == 1
        assert "MISSING REQUIRED" in result.result["visualization"]
        assert "Lateral Movement" in result.result["visualization"]

    def test_ascii_empty_stages(self, plugin_instance):
        result = plugin_instance.execute({"stages": [], "format": "ascii"}, None)
        assert result.ok
        assert "No attack stages" in result.result["visualization"]


class TestCompactRendering:
    def test_compact_output(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "compact",
            "attack_type": "ransomware",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        assert "RANSOMWARE" in viz
        assert "-->" in viz
        assert "Stages: 4" in viz

    def test_compact_truncates_long_names(self, plugin_instance):
        stages = [{
            "name": "Very Long Stage Name That Exceeds Limit",
            "stage_present": True,
            "controls": [],
        }]
        result = plugin_instance.execute({"stages": stages, "format": "compact"}, None)
        assert result.ok
        # Name should be truncated to 15 chars
        viz = result.result["visualization"]
        assert "..." in viz


class TestMermaidRendering:
    def test_mermaid_output(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "mermaid",
            "attack_type": "ransomware",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        assert "```mermaid" in viz
        assert "flowchart TB" in viz
        assert "RANSOMWARE" in viz
        assert "S0 --> S1" in viz

    def test_mermaid_gap_styling(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({"stages": sample_stages, "format": "mermaid"}, None)
        viz = result.result["visualization"]
        # Privilege Escalation has gaps -> red styling
        assert "fill:#ffcccc" in viz

    def test_mermaid_unprotected_styling(self, plugin_instance):
        stages = [{"name": "No Controls", "stage_present": True, "controls": [], "gaps_detected": []}]
        result = plugin_instance.execute({"stages": stages, "format": "mermaid"}, None)
        viz = result.result["visualization"]
        assert "fill:#ffffcc" in viz  # yellow for unprotected

    def test_mermaid_control_matrix(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "mermaid",
            "include_controls": True,
        }, None)
        viz = result.result["visualization"]
        assert "Control Coverage Matrix" in viz
        assert "EDR Agent" in viz

    def test_mermaid_no_control_matrix(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "mermaid",
            "include_controls": False,
        }, None)
        viz = result.result["visualization"]
        assert "Control Coverage Matrix" not in viz


class TestBothFormat:
    def test_both_includes_ascii_and_mermaid(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "both",
            "attack_type": "ransomware",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        # Should contain ASCII elements
        assert "ATTACK PATH" in viz
        # Should contain Mermaid elements
        assert "```mermaid" in viz


class TestSummarize:
    def test_summarize_success(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({"stages": sample_stages, "format": "compact"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "4 attack stages" in summary
        assert len(summary) <= 2000

    def test_summarize_with_missing(self, plugin_instance, stages_with_missing):
        result = plugin_instance.execute({"stages": stages_with_missing, "format": "compact"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "missing" in summary.lower()

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="Bad data")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()

    def test_summarize_truncation(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "both",
            "attack_type": "ransomware",
        }, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000


# ---------------------------------------------------------------------------
# Multi-role DAG tests
# ---------------------------------------------------------------------------


@pytest.fixture
def multi_role_mitre_mappings():
    """Mitre mappings with T1078 appearing in two tactical roles."""
    return [
        {"technique_id": "T1566", "technique_name": "Phishing",
         "tactic": "Initial Access"},
        {"technique_id": "T1078", "technique_name": "Valid Accounts",
         "tactic": "Initial Access"},
        {"technique_id": "T1078", "technique_name": "Valid Accounts",
         "tactic": "Persistence"},
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
         "tactic": "Execution"},
    ]


@pytest.fixture
def multi_role_attack_graph():
    """Attack graph where T1078 serves different roles in two paths."""
    return {
        "paths": [
            {
                "path_id": "phishing-path",
                "description": "Phishing to execution via harvested creds",
                "steps": [
                    {"technique_id": "T1566", "tactic": "Initial Access",
                     "leads_to": ["T1078"]},
                    {"technique_id": "T1078", "tactic": "Initial Access",
                     "leads_to": ["T1059"]},
                    {"technique_id": "T1059", "tactic": "Execution",
                     "leads_to": []},
                ],
            },
            {
                "path_id": "persistence-path",
                "description": "Valid accounts reused for persistence",
                "steps": [
                    {"technique_id": "T1078", "tactic": "Persistence",
                     "leads_to": ["T1059"]},
                    {"technique_id": "T1059", "tactic": "Execution",
                     "leads_to": []},
                ],
            },
        ],
        "convergence_points": ["T1059"],
        "branch_points": [],
    }


class TestMultiRoleDAG:
    """Verify multi-role technique mapping produces distinct DAG nodes."""

    def test_dag_builder_creates_distinct_nodes(
        self, multi_role_attack_graph, multi_role_mitre_mappings
    ):
        dag = _tool_mod._build_dag_from_attack_graph(
            multi_role_attack_graph, multi_role_mitre_mappings
        )
        assert dag is not None
        # T1078 should produce 2 nodes (Initial Access + Persistence)
        t1078_nodes = [
            n for n in dag.nodes.values()
            if n.technique_id == "T1078"
        ]
        assert len(t1078_nodes) == 2
        tactics = {n.tactic for n in t1078_nodes}
        assert tactics == {"Initial Access", "Persistence"}

    def test_dag_total_node_count(
        self, multi_role_attack_graph, multi_role_mitre_mappings
    ):
        dag = _tool_mod._build_dag_from_attack_graph(
            multi_role_attack_graph, multi_role_mitre_mappings
        )
        # T1566, T1078|initial-access, T1078|persistence, T1059 = 4 nodes
        assert len(dag.nodes) == 4

    def test_mermaid_contains_both_tactic_labels(
        self, multi_role_attack_graph, multi_role_mitre_mappings
    ):
        dag = _tool_mod._build_dag_from_attack_graph(
            multi_role_attack_graph, multi_role_mitre_mappings
        )
        _raw, mermaid = _tool_mod._render_mermaid_dag(dag, "multi-role test")
        assert "Initial Access" in mermaid
        assert "Persistence" in mermaid
        assert "T1078" in mermaid
        # No em-dash should appear in raw or markdown
        assert "\u2014" not in _raw

    def test_ascii_contains_both_tactic_labels(
        self, multi_role_attack_graph, multi_role_mitre_mappings
    ):
        dag = _tool_mod._build_dag_from_attack_graph(
            multi_role_attack_graph, multi_role_mitre_mappings
        )
        ascii_out = _tool_mod._render_ascii_dag(dag, "multi-role test")
        assert "Initial Access" in ascii_out
        assert "Persistence" in ascii_out
        assert "T1078" in ascii_out
        # No em-dash should appear in header/legend
        assert "\u2014" not in ascii_out

    def test_convergence_styling_uses_technique_id(
        self, multi_role_attack_graph, multi_role_mitre_mappings
    ):
        dag = _tool_mod._build_dag_from_attack_graph(
            multi_role_attack_graph, multi_role_mitre_mappings
        )
        _raw, mermaid = _tool_mod._render_mermaid_dag(dag, "test")
        # T1059 is convergence point — should get orange styling
        assert "fill:#ffe0b2" in mermaid

    def test_entry_nodes_labeled_with_path_names(
        self, multi_role_attack_graph, multi_role_mitre_mappings
    ):
        dag = _tool_mod._build_dag_from_attack_graph(
            multi_role_attack_graph, multi_role_mitre_mappings
        )
        _raw, mermaid = _tool_mod._render_mermaid_dag(dag, "test")
        # Entry nodes should have bold path name tags
        assert "phishing-path" in mermaid
        assert "persistence-path" in mermaid

    def test_color_legend_subgraph_present(
        self, multi_role_attack_graph, multi_role_mitre_mappings
    ):
        dag = _tool_mod._build_dag_from_attack_graph(
            multi_role_attack_graph, multi_role_mitre_mappings
        )
        raw, mermaid = _tool_mod._render_mermaid_dag(dag, "test")
        assert "Entry Point" in mermaid
        assert "Mid-chain" in mermaid
        assert "Exit / Terminal" in mermaid
        assert "Convergence" in mermaid
        assert "style LE fill:#bbdefb" in mermaid
        assert "style legend fill:#f5f5f5" in mermaid
        # raw_mermaid should NOT have fences
        assert "```mermaid" not in raw
        # markdown form should have fences
        assert "```mermaid" in mermaid

    def test_node_key_helper(self):
        key = _tool_mod._node_key("T1078", "Initial Access")
        assert key == "T1078|initial-access"
        key2 = _tool_mod._node_key("T1078", "Persistence")
        assert key2 == "T1078|persistence"
        assert key != key2
