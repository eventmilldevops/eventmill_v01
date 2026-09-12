"""Contract compliance tests for risk_assessment_analyzer."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "risk_assessment_analyzer_tool"
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
    return _tool_mod.RiskAssessmentAnalyzer()


@pytest.fixture
def sample_stages():
    """Stages for a ransomware attack path."""
    return [
        {
            "name": "Initial Access",
            "technique_claimed": "Spear phishing attachment",
            "mitre_technique_id": "T1566.001",
            "stage_present": True,
            "controls": [
                {
                    "control_name": "Email Gateway Filter",
                    "control_type": "preventive",
                    "effectiveness_rating": "moderate",
                    "evidence_basis": "tested",
                    "independence_flag": False,
                },
                {
                    "control_name": "Security Awareness Training",
                    "control_type": "preventive",
                    "effectiveness_rating": "weak",
                    "evidence_basis": "assumption",
                    "independence_flag": False,
                },
            ],
            "assumptions": ["Users complete annual training"],
            "gaps_detected": [],
        },
        {
            "name": "Execution",
            "technique_claimed": "Malicious macro execution",
            "mitre_technique_id": "T1204.002",
            "stage_present": True,
            "controls": [
                {
                    "control_name": "EDR Agent",
                    "control_type": "detective",
                    "effectiveness_rating": "strong",
                    "evidence_basis": "benchmark",
                    "independence_flag": False,
                },
            ],
            "assumptions": [],
            "gaps_detected": [],
        },
        {
            "name": "Privilege Escalation",
            "technique_claimed": "Exploiting unpatched service",
            "mitre_technique_id": "T1068",
            "stage_present": True,
            "controls": [
                {
                    "control_name": "EDR Agent",
                    "control_type": "detective",
                    "effectiveness_rating": "strong",
                    "evidence_basis": "benchmark",
                    "independence_flag": False,
                },
            ],
            "assumptions": [],
            "gaps_detected": ["Patching cadence is 30+ days"],
        },
        {
            "name": "Impact/Action on Objective",
            "technique_claimed": "Data encryption for ransom",
            "mitre_technique_id": "T1486",
            "stage_present": True,
            "controls": [
                {
                    "control_name": "Backup System",
                    "control_type": "responsive",
                    "effectiveness_rating": "moderate",
                    "evidence_basis": "vendor_claim",
                    "independence_flag": True,
                },
            ],
            "assumptions": ["Backups are tested quarterly"],
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
        assert manifest["tool_name"] == "risk_assessment_analyzer"

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "risk_assessment_analyzer"

    def test_validate_analyze_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "analyze", "document_content": "Test report content"
        })
        assert result.ok

    def test_validate_analyze_missing_content(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "analyze"})
        assert not result.ok

    def test_validate_list_attack_types(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "list_attack_types"})
        assert result.ok

    def test_validate_stages_valid(self, plugin_instance, sample_stages):
        result = plugin_instance.validate_inputs({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": sample_stages,
        })
        assert result.ok

    def test_validate_stages_missing_stages(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "validate_stages", "attack_type": "ransomware"
        })
        assert not result.ok

    def test_validate_invalid_attack_type(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "analyze", "document_content": "x", "attack_type": "unknown"
        })
        assert not result.ok

    def test_validate_invalid_action(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "destroy"})
        assert not result.ok


class TestListAttackTypes:
    def test_list(self, plugin_instance):
        result = plugin_instance.execute({"action": "list_attack_types"}, None)
        assert result.ok
        types = result.result["attack_types"]
        assert len(types) == 7  # ddos, ransomware, data_theft, apt, insider_threat, web_attack, generic
        names = [t["name"] for t in types]
        assert "ransomware" in names
        assert "apt" in names

    def test_ransomware_stages(self, plugin_instance):
        result = plugin_instance.execute({"action": "list_attack_types"}, None)
        ransomware = next(t for t in result.result["attack_types"] if t["name"] == "ransomware")
        assert "Initial Access" in ransomware["required_stages"]
        assert "Impact/Action on Objective" in ransomware["required_stages"]
        assert "Exfiltration" in ransomware["not_applicable_stages"]

    def test_stage_vocabulary_is_attack_v19(self, plugin_instance):
        """Defense Evasion was split into Stealth and Defense Impairment in v19."""
        result = plugin_instance.execute({"action": "list_attack_types"}, None)
        for entry in result.result["attack_types"]:
            every = (
                entry["required_stages"]
                + entry["optional_stages"]
                + entry["not_applicable_stages"]
            )
            assert "Defense Evasion" not in every
        ransomware = next(t for t in result.result["attack_types"] if t["name"] == "ransomware")
        assert "Stealth" in ransomware["optional_stages"]
        assert "Defense Impairment" in ransomware["optional_stages"]


class TestValidateStages:
    def test_legacy_defense_evasion_stage_inherits_relevance(self, plugin_instance):
        """A pre-v19 'Defense Evasion' stage name is treated like Stealth."""
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": [
                {"name": "Defense Evasion", "mitre_technique_id": "T1027",
                 "stage_present": True, "controls": []},
            ],
        }, None)
        assert result.ok
        assert result.result["stages"][0]["relevance"] == "optional"

    def test_full_ransomware(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": sample_stages,
        }, None)
        assert result.ok
        data = result.result
        assert data["attack_type"] == "ransomware"
        assert len(data["stages"]) == 4
        assert data["missing_required_stages"] == []
        assert data["confidence_assessment"]["structural_completeness"] == 1.0

    def test_missing_stages(self, plugin_instance):
        # Only Initial Access provided, missing Execution, PrivEsc, Impact
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": [{
                "name": "Initial Access",
                "stage_present": True,
                "controls": [],
            }],
        }, None)
        assert result.ok
        missing = result.result["missing_required_stages"]
        assert "Execution" in missing
        assert "Privilege Escalation" in missing
        assert "Impact/Action on Objective" in missing
        assert result.result["confidence_assessment"]["structural_completeness"] == 0.25

    def test_duplicate_controls_detected(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": sample_stages,
        }, None)
        assert result.ok
        dups = result.result["cross_stage_flags"]["duplicate_controls"]
        # EDR Agent appears in Execution and Privilege Escalation
        assert any("EDR Agent" in d for d in dups)

    def test_independence_violations_detected(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": sample_stages,
        }, None)
        assert result.ok
        violations = result.result["cross_stage_flags"]["independence_violations"]
        # Backup System has independence_flag=True
        assert any("Backup System" in v for v in violations)

    def test_evidence_strength(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": sample_stages,
        }, None)
        assert result.ok
        es = result.result["confidence_assessment"]["evidence_strength"]
        # 3 tested/benchmark out of 5 total controls = 0.6
        assert es == 0.6

    def test_assumption_density(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": sample_stages,
        }, None)
        assert result.ok
        ad = result.result["confidence_assessment"]["assumption_density"]
        # 2 assumptions out of 5 controls + 2 assumptions = 7 items
        assert 0.2 < ad < 0.4

    def test_stage_relevance_mapping(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ddos",
            "stages": [
                {"name": "Initial Access", "stage_present": True, "controls": []},
                {"name": "Impact/Action on Objective", "stage_present": True, "controls": []},
                {"name": "Persistence", "stage_present": False, "controls": []},
            ],
        }, None)
        assert result.ok
        stages = result.result["stages"]
        persistence = next(s for s in stages if s["name"] == "Persistence")
        assert persistence["relevance"] == "not_applicable"


class TestAnalyzeDocument:
    def test_analyze_without_llm(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "analyze",
            "document_content": "This is a sample risk assessment report.",
            "attack_type": "ransomware",
        }, None)
        assert result.ok
        data = result.result
        assert data["ai_analysis"] is None
        # Without LLM, all required stages are flagged missing
        assert len(data["missing_required_stages"]) > 0


class TestSummarize:
    def test_summarize_validate(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "action": "validate_stages",
            "attack_type": "ransomware",
            "stages": sample_stages,
        }, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "ransomware" in summary

    def test_summarize_list(self, plugin_instance):
        result = plugin_instance.execute({"action": "list_attack_types"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "7 attack types" in summary

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="Missing content")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()
