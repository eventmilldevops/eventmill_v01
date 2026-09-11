"""Contract compliance tests for adversary_path_projector."""

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "adversary_path_projector_tool"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@dataclass
class FakeArtifact:
    artifact_id: str
    artifact_type: str
    file_path: str


@dataclass
class FakeContext:
    artifacts: list = field(default_factory=list)


@pytest.fixture
def manifest():
    with open(PLUGIN_DIR / "manifest.json") as f:
        return json.load(f)


@pytest.fixture
def plugin_instance():
    return _tool_mod.AdversaryPathProjector()


@pytest.fixture
def sample_flow_map() -> dict[str, Any]:
    """A three-tier portal: internet edge, app tier, data tier."""
    return {
        "application": "Customer Portal",
        "zones": [
            {"id": "dmz", "name": "DMZ", "trust_level": "untrusted"},
            {"id": "app", "name": "Application tier", "trust_level": "semi_trusted"},
            {"id": "data", "name": "Data tier", "trust_level": "restricted"},
        ],
        "components": [
            {
                "id": "web",
                "name": "Portal frontend",
                "type": "web_app",
                "zone": "dmz",
                "exposure": "internet",
                "technologies": ["nginx"],
                "authentication": "none",
                "controls": [
                    {
                        "name": "WAF",
                        "control_type": "perimeter",
                        "implementation_status": "implemented",
                        "bypass_difficulty": "medium",
                        "detection_capability": "high",
                    }
                ],
            },
            {
                "id": "api",
                "name": "Portal API",
                "type": "api",
                "zone": "app",
                "exposure": "internal",
                "authentication": "oauth2",
                "controls": [],
            },
            {
                "id": "customer_db",
                "name": "Customer database",
                "type": "database",
                "zone": "data",
                "exposure": "internal",
                "authentication": "mtls",
                "data_classification": "pii",
                "controls": [
                    {
                        "name": "Database firewall",
                        "control_type": "network",
                        "implementation_status": "implemented",
                        "bypass_difficulty": "high",
                    }
                ],
            },
        ],
        "flows": [
            {"id": "f1", "from": "web", "to": "api", "protocol": "https",
             "authenticated": True},
            {"id": "f2", "from": "api", "to": "customer_db", "protocol": "postgres",
             "authenticated": True},
        ],
        "crown_jewels": ["customer_db"],
    }


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

class TestManifest:
    def test_required_fields(self, manifest):
        for field_name in (
            "tool_name", "version", "pillar", "display_name", "description_short",
            "description_long", "author", "entry_point", "class_name",
            "artifacts_consumed", "artifacts_produced", "capabilities",
            "input_schema", "output_schema", "timeout_class",
            "safe_for_auto_invoke", "stability", "tags",
        ):
            assert field_name in manifest, f"missing {field_name}"

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "adversary_path_projector"

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_class_name_matches_implementation(self, manifest):
        assert hasattr(_tool_mod, manifest["class_name"])

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()
        assert (PLUGIN_DIR / "schemas" / "flow_map.schema.json").exists()

    def test_schemas_are_valid_json(self, manifest):
        for name in ("input.schema.json", "output.schema.json", "flow_map.schema.json"):
            with open(PLUGIN_DIR / "schemas" / name) as f:
                json.load(f)

    def test_stability_is_in_the_documented_enum(self, manifest):
        """A new plugin must not repeat the invalid 'stable' the others declare."""
        assert manifest["stability"] in (
            "experimental", "verified", "core", "deprecated"
        )

    def test_model_tier_is_known_to_the_framework(self, manifest):
        assert manifest["model_tier"] in ("light", "heavy", "none")

    def test_manifest_matches_the_llm_it_actually_uses(self, manifest):
        """project_paths is a heavy-tier call, and the manifest must say so.

        The tier drives what TierScopedLLMClient hands the plugin, so a
        mismatch here silently downgrades the projection to the light model.
        """
        assert manifest["requires_llm"] is True
        assert manifest["model_tier"] == "heavy"
        assert manifest["safe_for_auto_invoke"] is False
        assert manifest["timeout_class"] == "long"

    def test_input_schema_actions_match_implementation(self, manifest):
        with open(PLUGIN_DIR / manifest["input_schema"]) as f:
            schema = json.load(f)
        assert set(schema["properties"]["action"]["enum"]) == set(_tool_mod.ACTIONS)

    def test_chains_to_the_visualizer_and_analyzer(self, manifest):
        assert "attack_path_visualizer" in manifest["chains_to"]
        assert "threat_model_analyzer" in manifest["chains_to"]

    def test_manifest_validates_against_the_schema(self, manifest):
        """The new plugin must not add an error to validate_manifests.py.

        15 of the 16 older manifests fail on stability and, behind that first
        error, on the capability namespace pattern too. threat_intel_ingester
        is the one that validates; this plugin follows it.
        """
        jsonschema = pytest.importorskip("jsonschema")
        schema_path = PLUGIN_DIR.parents[2] / "docs" / "specs" / "manifest_schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        errors = list(jsonschema.Draft202012Validator(schema).iter_errors(manifest))
        assert not errors, [
            f"{list(e.path)}: {e.message}" for e in errors
        ]


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "adversary_path_projector"
        assert meta["pillar"] == "threat_modeling"

    def test_implements_protocol_methods(self, plugin_instance):
        for name in ("metadata", "validate_inputs", "execute", "summarize_for_llm"):
            assert callable(getattr(plugin_instance, name))

    def test_missing_action(self, plugin_instance):
        assert not plugin_instance.validate_inputs({}).ok

    def test_unknown_action(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "nope"})
        assert not result.ok
        assert "Invalid action" in result.errors[0]

    def test_planned_action_says_so(self, plugin_instance):
        """A planned action must not read as a typo."""
        result = plugin_instance.validate_inputs({"action": "normalize_flow_map"})
        assert not result.ok
        assert "not implemented yet" in result.errors[0]

    def test_profile_actor_requires_threat_actor(self, plugin_instance):
        assert not plugin_instance.validate_inputs({"action": "profile_actor"}).ok

    def test_profile_actor_valid(self, plugin_instance):
        assert plugin_instance.validate_inputs(
            {"action": "profile_actor", "threat_actor": "APT29"}
        ).ok

    def test_max_procedures_bounds(self, plugin_instance):
        base = {"action": "profile_actor", "threat_actor": "APT29"}
        assert not plugin_instance.validate_inputs({**base, "max_procedures": -1}).ok
        assert not plugin_instance.validate_inputs({**base, "max_procedures": 99}).ok
        assert not plugin_instance.validate_inputs({**base, "max_procedures": "5"}).ok
        assert plugin_instance.validate_inputs({**base, "max_procedures": 0}).ok

    def test_validate_flow_map_needs_a_source(self, plugin_instance):
        assert not plugin_instance.validate_inputs({"action": "validate_flow_map"}).ok

    def test_validate_flow_map_accepts_each_source(
        self, plugin_instance, sample_flow_map
    ):
        for payload in (
            {"flow_map": sample_flow_map},
            {"flow_map_artifact_id": "art_001"},
            {"file_path": "flow.json"},
        ):
            result = plugin_instance.validate_inputs(
                {"action": "validate_flow_map", **payload}
            )
            assert result.ok, result.errors

    def test_flow_map_must_be_an_object(self, plugin_instance):
        result = plugin_instance.validate_inputs(
            {"action": "validate_flow_map", "flow_map": "not an object"}
        )
        assert not result.ok

    def test_execute_returns_structured_error_for_unknown_action(self, plugin_instance):
        result = plugin_instance.execute({"action": "nope"}, None)
        assert not result.ok
        assert result.error_code == "INPUT_VALIDATION_FAILED"


# ---------------------------------------------------------------------------
# profile_actor
# ---------------------------------------------------------------------------

class TestProfileActor:
    def test_resolves_an_alias(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "Cozy Bear"}, None
        )
        assert result.ok
        actor = result.result["actor"]
        assert actor["resolved"] is True
        assert actor["attck_id"] == "G0016"
        assert actor["entity_type"] == "group"

    def test_resolves_an_id(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "G0016"}, None
        )
        assert result.ok
        assert result.result["actor"]["attck_id"] == "G0016"

    def test_unknown_actor_is_a_structured_error(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "Fluffy Kitten Collective"},
            None,
        )
        assert not result.ok
        assert result.error_code == "ACTOR_NOT_FOUND"
        assert "intel_artifact_id" in result.message

    def test_technique_set_is_non_empty_and_sorted(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        assert result.ok
        techniques = result.result["techniques"]
        assert techniques
        ids = [t["technique_id"] for t in techniques]
        assert ids == sorted(ids)
        assert result.result["technique_count"] == len(techniques)

    def test_every_technique_carries_provenance(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        allowed = {"attck_group", "attck_campaign", "attck_software", "intel_report"}
        for technique in result.result["techniques"]:
            assert technique["provenance"], technique["technique_id"]
            assert set(technique["provenance"]) <= allowed
            assert technique["sources"]

    def test_core_set_is_direct_attribution_only(self, plugin_instance):
        """Software-derived techniques must not leak into the actor's own set."""
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29",
             "software_scope": "all"}, None
        )
        for technique in result.result["techniques"]:
            assert "attck_software" not in technique["provenance"]

    def test_software_block_is_separate_and_disjoint(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29",
             "software_scope": "all"}, None
        )
        core = {t["technique_id"] for t in result.result["techniques"]}
        software = {t["technique_id"] for t in result.result["software_techniques"]}
        assert software
        assert not (core & software)
        assert result.result["software_technique_count"] == len(software)

    def test_allowed_ids_are_the_union(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29",
             "software_scope": "all"}, None
        )
        core = {t["technique_id"] for t in result.result["techniques"]}
        software = {t["technique_id"] for t in result.result["software_techniques"]}
        assert set(result.result["allowed_technique_ids"]) == core | software

    def test_default_scope_is_delivery(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        assert result.result["software_scope"] == "delivery"

    def test_delivery_scope_keeps_only_delivery_band(self, plugin_instance):
        """Post-compromise software techniques are noise: an actor uses what is
        on the host, so only the dropper-stage mapping carries signal."""
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        bands = {t["band"] for t in result.result["software_techniques"]}
        assert bands == {"delivery"}

    def test_delivery_scope_is_a_strict_subset_of_all(self, plugin_instance):
        delivery = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        ).result
        every = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29",
             "software_scope": "all"}, None
        ).result
        assert (
            delivery["software_technique_count"] < every["software_technique_count"]
        )
        assert {t["technique_id"] for t in delivery["software_techniques"]} <= {
            t["technique_id"] for t in every["software_techniques"]
        }

    def test_scope_none_drops_the_software_block(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29",
             "software_scope": "none"}, None
        )
        assert result.result["software_techniques"] == []
        assert set(result.result["allowed_technique_ids"]) == {
            t["technique_id"] for t in result.result["techniques"]
        }

    def test_core_set_is_unchanged_by_scope(self, plugin_instance):
        """Scope must only ever move the software block, never the core set."""
        counts = {
            scope: plugin_instance.execute(
                {"action": "profile_actor", "threat_actor": "APT29",
                 "software_scope": scope}, None
            ).result["technique_count"]
            for scope in ("none", "delivery", "all")
        }
        assert len(set(counts.values())) == 1

    def test_software_entries_name_their_source_and_tooling(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        for technique in result.result["software_techniques"]:
            assert technique["source"] == "attck_lookup"
            assert technique["software"]
            assert all(s["id"].startswith("S") for s in technique["software"])
        assert result.result["software_source"] == "attck_lookup"

    def test_invalid_scope_is_rejected(self, plugin_instance):
        result = plugin_instance.validate_inputs(
            {"action": "profile_actor", "threat_actor": "APT29",
             "software_scope": "everything"}
        )
        assert not result.ok
        assert "software_scope" in result.errors[0]

    def test_profiling_software_directly_puts_it_in_the_core_set(self, plugin_instance):
        """A malware family profiled by name is the subject, not the tooling."""
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "Cobalt Strike"}, None
        )
        assert result.result["technique_count"] > 0
        assert result.result["software_techniques"] == []

    def test_tactic_coverage_is_in_kill_chain_order(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        ordinals = [c["ordinal"] for c in result.result["tactic_coverage"]]
        assert ordinals == sorted(ordinals)

    def test_coverage_never_names_a_retired_tactic(self, plugin_instance):
        """ATT&CK v19 retired Defense Evasion; nothing here may resurrect it."""
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        tactics = {c["tactic"] for c in result.result["tactic_coverage"]}
        tactics |= set(result.result["uncovered_tactics"])
        assert "Defense Evasion" not in tactics

    def test_enterprise_actor_has_no_ics_tactics_in_uncovered(self, plugin_instance):
        """ICS tactics are not gaps for an enterprise-only actor."""
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        uncovered = set(result.result["uncovered_tactics"])
        assert not uncovered & {
            "Inhibit Response Function", "Impair Process Control", "Evasion"
        }

    def test_procedures_are_capped(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29", "max_procedures": 3},
            None,
        )
        assert len(result.result["procedures"]) <= 3

    def test_max_procedures_zero_returns_none(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29", "max_procedures": 0},
            None,
        )
        assert result.result["procedures"] == []

    def test_software_can_be_profiled_directly(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "Cobalt Strike"}, None
        )
        assert result.ok
        assert result.result["actor"]["entity_type"] == "software"

    def test_intel_artifact_unions_into_the_set(self, plugin_instance, tmp_path):
        intel = tmp_path / "intel.json"
        intel.write_text(json.dumps({
            "mitre_mappings": [{"technique_id": "T1595", "tactic": "Reconnaissance"}]
        }), encoding="utf-8")
        context = FakeContext(
            artifacts=[FakeArtifact("art_intel", "json_events", str(intel))]
        )
        result = plugin_instance.execute(
            {
                "action": "profile_actor",
                "threat_actor": "APT29",
                "software_scope": "none",
                "intel_artifact_id": "art_intel",
            },
            context,
        )
        assert result.ok
        by_id = {t["technique_id"]: t for t in result.result["techniques"]}
        assert "T1595" in by_id
        assert "intel_report" in by_id["T1595"]["provenance"]
        assert "art_intel" in by_id["T1595"]["sources"]

    def test_intel_lets_an_unknown_actor_be_profiled(self, plugin_instance, tmp_path):
        intel = tmp_path / "intel.json"
        intel.write_text(json.dumps({
            "mitre_mappings": [{"technique_id": "T1566", "tactic": "Initial Access"}]
        }), encoding="utf-8")
        context = FakeContext(
            artifacts=[FakeArtifact("art_intel", "json_events", str(intel))]
        )
        result = plugin_instance.execute(
            {
                "action": "profile_actor",
                "threat_actor": "Fluffy Kitten Collective",
                "intel_artifact_id": "art_intel",
            },
            context,
        )
        assert result.ok
        assert result.result["actor"]["resolved"] is False
        assert result.result["technique_count"] == 1

    def test_missing_intel_artifact_is_a_structured_error(self, plugin_instance):
        result = plugin_instance.execute(
            {
                "action": "profile_actor",
                "threat_actor": "APT29",
                "intel_artifact_id": "art_nope",
            },
            FakeContext(),
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"


# ---------------------------------------------------------------------------
# validate_flow_map — linting
# ---------------------------------------------------------------------------

class TestFlowMapLinting:
    def test_clean_map_is_valid(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.ok
        assert result.result["valid"] is True
        assert result.result["errors"] == []

    def test_counts(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        counts = result.result["counts"]
        assert counts["components"] == 3
        assert counts["zones"] == 3
        assert counts["flows"] == 2
        assert counts["crown_jewels"] == 1
        assert counts["controls"] == 2

    def _codes(self, result, key="errors"):
        return {issue["code"] for issue in result.result[key]}

    def test_dangling_flow_endpoint(self, plugin_instance, sample_flow_map):
        sample_flow_map["flows"].append({"from": "api", "to": "ghost"})
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["valid"] is False
        assert "DANGLING_FLOW_ENDPOINT" in self._codes(result)

    def test_duplicate_component_id(self, plugin_instance, sample_flow_map):
        sample_flow_map["components"].append({"id": "web", "name": "Copy"})
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert "DUPLICATE_COMPONENT_ID" in self._codes(result)

    def test_unknown_crown_jewel(self, plugin_instance, sample_flow_map):
        sample_flow_map["crown_jewels"].append("vault")
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert "UNKNOWN_CROWN_JEWEL" in self._codes(result)

    def test_missing_application_name(self, plugin_instance, sample_flow_map):
        del sample_flow_map["application"]
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert "MISSING_APPLICATION" in self._codes(result)

    def test_no_components(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": {"application": "Empty"}}, None
        )
        assert result.ok
        assert result.result["valid"] is False
        assert "NO_COMPONENTS" in self._codes(result)

    def test_empty_object(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": {}}, None
        )
        assert result.ok
        assert result.result["valid"] is False

    def test_json_array_is_rejected_as_not_an_object(self, plugin_instance, tmp_path):
        """A file holding a JSON array reaches normalization past validate_inputs."""
        path = tmp_path / "flow.json"
        path.write_text(json.dumps([{"id": "web"}]), encoding="utf-8")
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "file_path": str(path)}, None
        )
        assert result.ok
        assert result.result["valid"] is False
        assert "FLOW_MAP_NOT_OBJECT" in self._codes(result)

    def test_unknown_zone_is_a_warning_not_an_error(
        self, plugin_instance, sample_flow_map
    ):
        sample_flow_map["components"][1]["zone"] = "nowhere"
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["valid"] is True
        assert "UNKNOWN_ZONE" in self._codes(result, "warnings")

    def test_bad_enum_falls_back_and_warns(self, plugin_instance, sample_flow_map):
        sample_flow_map["components"][1]["exposure"] = "extranet"
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["valid"] is True
        assert "INVALID_ENUM" in self._codes(result, "warnings")
        api = next(
            e for e in result.result["entry_surface"] if e["component_id"] == "api"
        )
        assert api["exposure"] == "internal"

    def test_isolated_component_is_reported(self, plugin_instance, sample_flow_map):
        sample_flow_map["components"].append({"id": "orphan", "name": "Orphan"})
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert "orphan" in result.result["isolated_components"]
        assert "ISOLATED_COMPONENT" in self._codes(result, "warnings")

    def test_self_flow_is_dropped(self, plugin_instance, sample_flow_map):
        sample_flow_map["flows"].append({"from": "api", "to": "api"})
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["counts"]["flows"] == 2
        assert "SELF_FLOW" in self._codes(result, "warnings")

    def test_no_external_exposure_warns(self, plugin_instance, sample_flow_map):
        sample_flow_map["components"][0]["exposure"] = "internal"
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert "NO_EXTERNAL_EXPOSURE" in self._codes(result, "warnings")

    def test_unknown_mitigation_id_warns(self, plugin_instance, sample_flow_map):
        sample_flow_map["components"][0]["controls"][0]["mitre_mitigation_id"] = "M9999"
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert "UNKNOWN_MITIGATION" in self._codes(result, "warnings")

    def test_real_mitigation_id_does_not_warn(self, plugin_instance, sample_flow_map):
        sample_flow_map["components"][0]["controls"][0]["mitre_mitigation_id"] = "M1050"
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert "UNKNOWN_MITIGATION" not in self._codes(result, "warnings")


# ---------------------------------------------------------------------------
# validate_flow_map — entry surface and reachability
# ---------------------------------------------------------------------------

class TestEntrySurface:
    def test_ranked_highest_first(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        surface = result.result["entry_surface"]
        scores = [entry["score"] for entry in surface]
        assert scores == sorted(scores, reverse=True)
        assert surface[0]["component_id"] == "web"

    def test_every_component_is_ranked(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert len(result.result["entry_surface"]) == 3

    def test_scores_are_explained(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        for entry in result.result["entry_surface"]:
            assert entry["reasons"]

    def test_unauthenticated_component_scores_higher(
        self, plugin_instance, sample_flow_map
    ):
        authed = json.loads(json.dumps(sample_flow_map))
        authed["components"][0]["authentication"] = "saml_sso"
        open_score = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        ).result["entry_surface"][0]["score"]
        authed_score = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": authed}, None
        ).result["entry_surface"][0]["score"]
        assert open_score > authed_score

    def test_hardened_component_scores_lower(self, plugin_instance, sample_flow_map):
        hardened = json.loads(json.dumps(sample_flow_map))
        hardened["components"][0]["controls"][0]["bypass_difficulty"] = "very_high"
        base = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        ).result["entry_surface"][0]["score"]
        tough = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": hardened}, None
        ).result["entry_surface"][0]["score"]
        assert tough < base

    def test_unimplemented_control_does_not_harden(
        self, plugin_instance, sample_flow_map
    ):
        """A planned control protects nothing today."""
        planned = json.loads(json.dumps(sample_flow_map))
        planned["components"][0]["controls"][0]["implementation_status"] = "planned"
        base = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        ).result["entry_surface"][0]["score"]
        weaker = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": planned}, None
        ).result["entry_surface"][0]["score"]
        assert weaker > base

    def test_score_never_negative(self, plugin_instance, sample_flow_map):
        armoured = json.loads(json.dumps(sample_flow_map))
        armoured["components"][2]["controls"] = [
            {
                "name": f"Control {i}",
                "control_type": "network",
                "implementation_status": "implemented",
                "bypass_difficulty": "very_high",
            }
            for i in range(5)
        ]
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": armoured}, None
        )
        assert all(e["score"] >= 0 for e in result.result["entry_surface"])


class TestReachability:
    def test_finds_the_route_to_the_crown_jewel(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        routes = result.result["crown_jewel_routes"]
        assert len(routes) == 1
        assert routes[0]["route"] == ["web", "api", "customer_db"]
        assert routes[0]["hops"] == 2
        assert routes[0]["entry"] == "web"
        assert routes[0]["target"] == "customer_db"

    def test_counts_boundary_crossings(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["crown_jewel_routes"][0]["boundary_crossings"] == 2

    def test_counts_unauthenticated_hops(self, plugin_instance, sample_flow_map):
        sample_flow_map["flows"][1]["authenticated"] = False
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["crown_jewel_routes"][0]["unauthenticated_hops"] == 1

    def test_unreachable_crown_jewel_is_reported(
        self, plugin_instance, sample_flow_map
    ):
        sample_flow_map["flows"] = [sample_flow_map["flows"][0]]
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["unreachable_crown_jewels"] == ["customer_db"]
        assert result.result["crown_jewel_routes"] == []

    def test_direction_matters(self, plugin_instance, sample_flow_map):
        """A flow pointing away from the database is not a route to it."""
        sample_flow_map["flows"][1] = {
            "from": "customer_db", "to": "api", "authenticated": True
        }
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["unreachable_crown_jewels"] == ["customer_db"]

    def test_bidirectional_flow_is_traversable_both_ways(
        self, plugin_instance, sample_flow_map
    ):
        sample_flow_map["flows"][1] = {
            "from": "customer_db", "to": "api",
            "authenticated": True, "bidirectional": True,
        }
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["crown_jewel_routes"][0]["route"] == [
            "web", "api", "customer_db"
        ]

    def test_shortest_route_wins(self, plugin_instance, sample_flow_map):
        sample_flow_map["flows"].append(
            {"from": "web", "to": "customer_db", "authenticated": False}
        )
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["crown_jewel_routes"][0]["route"] == ["web", "customer_db"]

    def test_no_crown_jewels_yields_no_routes(self, plugin_instance, sample_flow_map):
        sample_flow_map["crown_jewels"] = []
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["crown_jewel_routes"] == []
        assert "NO_CROWN_JEWELS" in {
            w["code"] for w in result.result["warnings"]
        }

    def test_internal_only_map_falls_back_to_top_component(
        self, plugin_instance, sample_flow_map
    ):
        sample_flow_map["components"][0]["exposure"] = "internal"
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        assert result.result["crown_jewel_routes"]


# ---------------------------------------------------------------------------
# Artifact and file input
# ---------------------------------------------------------------------------

class TestFlowMapSources:
    def test_reads_from_file_path(self, plugin_instance, sample_flow_map, tmp_path):
        path = tmp_path / "flow.json"
        path.write_text(json.dumps(sample_flow_map), encoding="utf-8")
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "file_path": str(path)}, None
        )
        assert result.ok
        assert result.result["application"] == "Customer Portal"

    def test_reads_from_artifact(self, plugin_instance, sample_flow_map, tmp_path):
        path = tmp_path / "flow.json"
        path.write_text(json.dumps(sample_flow_map), encoding="utf-8")
        context = FakeContext(
            artifacts=[FakeArtifact("art_flow", "json_events", str(path))]
        )
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map_artifact_id": "art_flow"}, context
        )
        assert result.ok
        assert result.result["counts"]["components"] == 3

    def test_missing_artifact(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map_artifact_id": "art_nope"},
            FakeContext(),
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"

    def test_unreadable_file(self, plugin_instance, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "file_path": str(path)}, None
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_UNREADABLE"


# ---------------------------------------------------------------------------
# summarize_for_llm
# ---------------------------------------------------------------------------

class TestSummarize:
    def test_actor_summary_under_cap(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "APT29"}, None
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert 0 < len(summary) <= 2000
        assert "APT29" in summary
        assert "attributed to the actor directly" in summary
        assert "via associated software" in summary

    def test_flow_map_summary_under_cap(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert 0 < len(summary) <= 2000
        assert "Customer Portal" in summary
        assert "web -> api -> customer_db" in summary

    def test_failure_summary(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "profile_actor", "threat_actor": "Fluffy Kitten Collective"},
            None,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert summary.startswith("adversary_path_projector failed")

    def test_invalid_map_summary_names_errors(self, plugin_instance, sample_flow_map):
        sample_flow_map["flows"].append({"from": "api", "to": "ghost"})
        result = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map}, None
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert "INVALID" in summary
        assert "DANGLING_FLOW_ENDPOINT" in summary


# ---------------------------------------------------------------------------
# project_paths — Phase B/C
# ---------------------------------------------------------------------------

@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
    model_used: str | None = "mock-heavy"
    transport_path: str | None = None
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


class _ScriptedLLM:
    """Answers query_text with a canned reply and records the prompt."""

    def __init__(self, reply: Any = None, **resp_kwargs):
        self.prompts: list[str] = []
        self.hints: list[Any] = []
        self._reply = reply
        self._resp_kwargs = resp_kwargs

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.prompts.append(prompt)
        self.hints.append(hints)
        if self._resp_kwargs.get("ok") is False:
            return _Resp(ok=False, error=self._resp_kwargs.get("error", "boom"))
        text = (
            self._reply if isinstance(self._reply, str)
            else json.dumps(self._reply)
        )
        kwargs = {k: v for k, v in self._resp_kwargs.items() if k != "error"}
        return _Resp(text=text, **kwargs)

    def supports_native_document(self, mime_type):
        return False


def _good_projection() -> dict[str, Any]:
    """A well-formed reply: real APT29 techniques on real sample components."""
    return {
        "paths": [{
            "path_id": "portal-to-db",
            "description": "Exploit the portal, pivot through the API to the database.",
            "objective": "Read customer records.",
            "steps": [
                {"technique_id": "T1190", "tactic": "Initial Access",
                 "component_id": "web",
                 "rationale": "nginx frontend is internet-facing with a partial WAF.",
                 "leads_to": ["T1078"]},
                {"technique_id": "T1078", "tactic": "Persistence",
                 "component_id": "api",
                 "rationale": "OAuth2 tokens reused to hold access to the API.",
                 "leads_to": ["T1005"]},
                {"technique_id": "T1005", "tactic": "Collection",
                 "component_id": "customer_db",
                 "rationale": "PII sits in the claims database.",
                 "leads_to": []},
            ],
        }],
        "convergence_points": [],
        "branch_points": [],
    }


def _project(plugin, flow_map, reply, **resp_kwargs):
    llm = _ScriptedLLM(reply, **resp_kwargs)
    context = FakeContext()
    context.llm_query = llm
    result = plugin.execute(
        {"action": "project_paths", "threat_actor": "APT29", "flow_map": flow_map},
        context,
    )
    return result, llm


class TestProjectPathsValidation:
    def test_project_paths_is_a_real_action_now(self, plugin_instance, sample_flow_map):
        result = plugin_instance.validate_inputs({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map,
        })
        assert result.ok

    def test_requires_actor_and_map(self, plugin_instance, sample_flow_map):
        assert not plugin_instance.validate_inputs(
            {"action": "project_paths", "flow_map": sample_flow_map}).ok
        assert not plugin_instance.validate_inputs(
            {"action": "project_paths", "threat_actor": "APT29"}).ok

    def test_max_paths_bounds(self, plugin_instance, sample_flow_map):
        base = {"action": "project_paths", "threat_actor": "APT29",
                "flow_map": sample_flow_map}
        assert not plugin_instance.validate_inputs({**base, "max_paths": 0}).ok
        assert not plugin_instance.validate_inputs({**base, "max_paths": 11}).ok
        assert plugin_instance.validate_inputs({**base, "max_paths": 1}).ok

    def test_no_llm_is_a_structured_error(self, plugin_instance, sample_flow_map):
        result = plugin_instance.execute(
            {"action": "project_paths", "threat_actor": "APT29",
             "flow_map": sample_flow_map},
            FakeContext(),
        )
        assert not result.ok
        assert result.error_code == "LLM_UNAVAILABLE"
        assert "GEMINI_PRO_API_KEY" in result.message

    def test_invalid_flow_map_blocks_before_the_llm(self, plugin_instance,
                                                   sample_flow_map):
        """A broken topology must not cost an LLM call."""
        sample_flow_map["flows"].append({"from": "api", "to": "ghost"})
        result, llm = _project(plugin_instance, sample_flow_map, _good_projection())
        assert not result.ok
        assert result.error_code == "INPUT_VALIDATION_FAILED"
        assert llm.prompts == []


class TestProjectPathsHappyPath:
    def test_produces_paths(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        assert result.ok, result.message
        assert result.result["path_count"] == 1
        assert result.result["step_count"] == 3

    def test_uses_heavy_tier_with_reasoning(self, plugin_instance, sample_flow_map):
        _, llm = _project(plugin_instance, sample_flow_map, _good_projection())
        hints = llm.hints[0]
        assert hints.tier == "heavy"
        assert hints.needs_reasoning is True

    def test_prompt_carries_the_closed_set_and_the_map(self, plugin_instance,
                                                       sample_flow_map):
        _, llm = _project(plugin_instance, sample_flow_map, _good_projection())
        prompt = llm.prompts[0]
        assert "T1190" in prompt
        assert "customer_db" in prompt
        assert "web -> api -> customer_db" in prompt
        assert "Defense Evasion" in prompt  # named only to forbid it
        assert "Stealth" in prompt

    def test_steps_bind_to_components(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        steps = result.result["attack_graph"]["paths"][0]["steps"]
        assert [s["component_id"] for s in steps] == ["web", "api", "customer_db"]
        assert steps[0]["asset"] == "Portal frontend"

    def test_evidence_is_derived_not_taken_from_the_model(self, plugin_instance,
                                                          sample_flow_map):
        reply = _good_projection()
        for step in reply["paths"][0]["steps"]:
            step["evidence"] = "documented"  # model claims; must be ignored
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        for step in result.result["attack_graph"]["paths"][0]["steps"]:
            assert step["evidence"] in ("documented", "via_software")
        counts = result.result["evidence_counts"]
        assert counts["documented"] + counts["via_software"] == 3

    def test_mitigation_gaps_are_computed(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        steps = result.result["attack_graph"]["paths"][0]["steps"]
        assert any(s["mitigations"] for s in steps)
        assert any(s["uncovered_mitigations"] for s in steps)

    def test_mitre_mappings_emitted_for_the_visualizer(self, plugin_instance,
                                                      sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        mappings = result.result["mitre_mappings"]
        assert {m["technique_id"] for m in mappings} == {"T1190", "T1078", "T1005"}
        assert all(m["tactic"] and m["technique_name"] for m in mappings)

    def test_graph_renders_in_attack_path_visualizer(self, plugin_instance,
                                                    sample_flow_map, tmp_path):
        """The whole point of the artifact shape: it chains with no translation."""
        viz_dir = PLUGIN_DIR.parent / "attack_path_visualizer"
        spec = importlib.util.spec_from_file_location(
            "apv_tool", viz_dir / "tool.py")
        viz = importlib.util.module_from_spec(spec)
        sys.modules["apv_tool"] = viz
        spec.loader.exec_module(viz)

        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        graph_file = tmp_path / "graph.json"
        graph_file.write_text(json.dumps({
            "mitre_mappings": result.result["mitre_mappings"],
            "attack_graph": result.result["attack_graph"],
        }), encoding="utf-8")

        ctx = FakeContext(
            artifacts=[FakeArtifact("art_graph", "json_events", str(graph_file))])
        rendered = viz.AttackPathVisualizer().execute(
            {"artifact_id": "art_graph", "format": "mermaid"}, ctx)
        assert rendered.ok, rendered.message
        assert "T1190" in rendered.result["visualization"]


class TestPhaseCRejection:
    def test_technique_outside_the_closed_set_is_rejected(self, plugin_instance,
                                                          sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["technique_id"] = "T0800"  # ICS, not APT29
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.ok
        codes = {r["code"] for r in result.result["rejections"]}
        assert "TECHNIQUE_NOT_IN_SET" in codes
        kept = {s["technique_id"]
                for s in result.result["attack_graph"]["paths"][0]["steps"]}
        assert "T0800" not in kept

    def test_component_outside_the_map_is_rejected(self, plugin_instance,
                                                   sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["component_id"] = "mainframe"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        codes = {r["code"] for r in result.result["rejections"]}
        assert "COMPONENT_NOT_IN_FLOW_MAP" in codes

    def test_everything_rejected_is_an_error_not_an_empty_success(
            self, plugin_instance, sample_flow_map):
        reply = _good_projection()
        for step in reply["paths"][0]["steps"]:
            step["technique_id"] = "T0800"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert not result.ok
        assert result.error_code == "PROJECTION_REJECTED"

    def test_retired_tactic_is_repaired(self, plugin_instance, sample_flow_map):
        """v19 killed Defense Evasion; a step using it must not carry it through."""
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["tactic"] = "Defense Evasion"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.ok
        tactics = {s["tactic"]
                   for s in result.result["attack_graph"]["paths"][0]["steps"]}
        assert "Defense Evasion" not in tactics

    def test_mismatched_tactic_is_flagged_not_dropped(self, plugin_instance,
                                                     sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][0]["tactic"] = "Impact"  # T1190 is not Impact
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.ok
        step = result.result["attack_graph"]["paths"][0]["steps"][0]
        assert step["notes"]
        assert "TACTIC_CORRECTED" in {
            w["code"] for w in result.result["warnings"]}

    def test_undeclared_hop_is_flagged(self, plugin_instance, sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["component_id"] = "customer_db"
        reply["paths"][0]["steps"][2]["component_id"] = "web"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.ok
        assert "HOP_NOT_DECLARED" in {w["code"] for w in result.result["warnings"]}

    def test_non_exposed_entry_is_flagged(self, plugin_instance, sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][0]["component_id"] = "customer_db"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert "ENTRY_NOT_EXPOSED" in {w["code"] for w in result.result["warnings"]}

    def test_dangling_leads_to_is_dropped(self, plugin_instance, sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][0]["leads_to"] = ["T1078", "T9999"]
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        step = result.result["attack_graph"]["paths"][0]["steps"][0]
        assert step["leads_to"] == ["T1078"]

    def test_convergence_points_are_filtered_to_kept_steps(self, plugin_instance,
                                                          sample_flow_map):
        reply = _good_projection()
        reply["convergence_points"] = ["T1078", "T9999"]
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.result["attack_graph"]["convergence_points"] == ["T1078"]


class TestProjectPathsFailureModes:
    def test_llm_failure(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, None,
                             ok=False, error="429 RESOURCE_EXHAUSTED")
        assert not result.ok
        assert result.error_code == "LLM_QUERY_FAILED"
        assert "429" in result.message

    def test_truncated_reply_is_refused(self, plugin_instance, sample_flow_map):
        """A cut-off projection is a path with steps missing; never accept it."""
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection(),
                             truncated=True, finish_reason="MAX_TOKENS")
        assert not result.ok
        assert result.error_code == "LLM_QUERY_FAILED"
        assert "max_paths" in result.message

    def test_unparseable_reply(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, "not json at all")
        assert not result.ok
        assert result.error_code == "LLM_QUERY_FAILED"

    def test_fenced_json_is_accepted(self, plugin_instance, sample_flow_map):
        fenced = "```json\n" + json.dumps(_good_projection()) + "\n```"
        result, _ = _project(plugin_instance, sample_flow_map, fenced)
        assert result.ok

    def test_unknown_actor_before_the_llm(self, plugin_instance, sample_flow_map):
        llm = _ScriptedLLM(_good_projection())
        context = FakeContext()
        context.llm_query = llm
        result = plugin_instance.execute(
            {"action": "project_paths", "threat_actor": "Fluffy Kitten Collective",
             "flow_map": sample_flow_map},
            context,
        )
        assert not result.ok
        assert result.error_code == "ACTOR_NOT_FOUND"
        assert llm.prompts == []


class TestScenarioSeed:
    def test_one_scenario_per_path(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        seeds = result.result["scenario_seeds"]
        assert len(seeds) == result.result["path_count"]
        assert seeds[0]["source_type"] == "actor_projection"

    def test_events_match_threat_model_analyzer_fields(self, plugin_instance,
                                                      sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        event = result.result["scenario_seeds"][0]["attack_sequence"][0]
        for key in ("event_id", "name", "description", "sequence_order",
                    "target_asset", "attack_technique", "technique_id",
                    "required_access", "resulting_access",
                    "blocking_controls", "detecting_controls"):
            assert key in event, key
        assert event["sequence_order"] == 1

    def test_controls_match_threat_model_analyzer_fields(self, plugin_instance,
                                                        sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        control = result.result["scenario_seeds"][0]["security_controls"][0]
        for key in ("control_id", "name", "control_type", "description",
                    "implementation_status", "bypass_difficulty",
                    "bypass_requirements", "detection_capability"):
            assert key in control, key

    def test_sequence_order_is_contiguous(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        orders = [e["sequence_order"]
                  for e in result.result["scenario_seeds"][0]["attack_sequence"]]
        assert orders == list(range(1, len(orders) + 1))

    def test_only_implemented_controls_block(self, plugin_instance, sample_flow_map):
        """A partial WAF must not appear as a blocking control."""
        sample_flow_map["components"][0]["controls"][0][
            "implementation_status"] = "partial"
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        first = result.result["scenario_seeds"][0]["attack_sequence"][0]
        assert "WAF" not in first["blocking_controls"]

    def test_events_carry_tactic_and_evidence(self, plugin_instance, sample_flow_map):
        """Without these a seed cannot be audited on its own — that is how a
        bad tactic went unnoticed for four events."""
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        steps = result.result["attack_graph"]["paths"][0]["steps"]
        events = result.result["scenario_seeds"][0]["attack_sequence"]
        assert [e["tactic"] for e in events] == [s["tactic"] for s in steps]
        assert [e["evidence"] for e in events] == [s["evidence"] for s in steps]
        assert all(e["evidence"] in ("documented", "via_software") for e in events)

    def test_every_declared_control_is_in_the_seed(self, plugin_instance,
                                                   sample_flow_map):
        """Estate-wide and flow controls used to be dropped, so gap analysis
        reported them as absent."""
        sample_flow_map["controls"] = [{
            "name": "Central SIEM", "control_type": "monitoring",
            "implementation_status": "implemented",
        }]
        sample_flow_map["flows"][1]["controls"] = [{
            "name": "mTLS on the DB link", "control_type": "network",
            "implementation_status": "planned",
        }]
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        controls = result.result["scenario_seeds"][0]["security_controls"]
        by_name = {c["name"]: c for c in controls}
        assert {"WAF", "Database firewall", "Central SIEM",
                "mTLS on the DB link"} <= set(by_name)
        assert "Estate-wide" in by_name["Central SIEM"]["description"]
        assert "f2" in by_name["mTLS on the DB link"]["description"]
        ids = [c["control_id"] for c in controls]
        assert ids == [f"SC-{i:04d}" for i in range(1, len(ids) + 1)]

    def test_seed_imports_into_threat_model_analyzer(self, plugin_instance,
                                                     sample_flow_map, tmp_path):
        """The seed exists for this hand-off; prove it lands without translation."""
        tma_dir = PLUGIN_DIR.parent / "threat_model_analyzer"
        spec = importlib.util.spec_from_file_location("tma_tool", tma_dir / "tool.py")
        tma = importlib.util.module_from_spec(spec)
        sys.modules["tma_tool"] = tma
        spec.loader.exec_module(tma)

        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        seed_file = tmp_path / "seed.json"
        seed_file.write_text(json.dumps({
            "source_tool": "adversary_path_projector",
            "scenarios": result.result["scenario_seeds"],
        }), encoding="utf-8")

        analyzer = tma.ThreatModelAnalyzer()
        ctx = FakeContext(
            artifacts=[FakeArtifact("art_seed", "json_events", str(seed_file))])
        imported = analyzer.execute(
            {"action": "import_scenario", "artifact_id": "art_seed"}, ctx)
        assert imported.ok, imported.message
        scenario = imported.result["imported"][0]
        assert scenario["source_type"] == "actor_projection"
        assert scenario["path_id"] == "portal-to-db"

        gap = analyzer.execute(
            {"action": "gap_analysis", "scenario_id": scenario["scenario_id"]}, None)
        assert gap.ok, gap.message
        md = analyzer.execute(
            {"action": "export", "scenario_id": scenario["scenario_id"]},
            None).result["markdown"]
        assert "**Tactic:** Initial Access" in md


class TestProjectionSummary:
    def test_summary_under_cap_and_honest(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        summary = plugin_instance.summarize_for_llm(result)
        assert 0 < len(summary) <= 2000
        assert "modelled, not observed" in summary
        assert "web:T1190" in summary

    def test_summary_reports_rejections(self, plugin_instance, sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["technique_id"] = "T0800"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        summary = plugin_instance.summarize_for_llm(result)
        assert "TECHNIQUE_NOT_IN_SET" in summary


class TestAccessLevels:
    def test_every_tactic_has_an_access_mapping(self):
        """A missing tactic reports 'none' access mid-chain, which reads as an
        unauthenticated step. Stealth and Defense Impairment were both missing."""
        from framework.reference_data.mitre_attack import TACTIC_ORDER
        missing = [t for t in TACTIC_ORDER if t not in _tool_mod._ACCESS_BY_TACTIC]
        assert not missing, f"no access mapping for: {missing}"

    def test_fallback_is_not_none_access(self):
        """An unrecognised tactic is more likely mid-chain than at entry."""
        assert _tool_mod._ACCESS_FALLBACK != ("none", "none")

    def test_stealth_step_does_not_claim_no_access(self, plugin_instance,
                                                   sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["tactic"] = "Stealth"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.ok
        event = result.result["scenario_seeds"][0]["attack_sequence"][1]
        assert event["required_access"] != "none"

    def test_only_entry_tactics_require_no_access(self, plugin_instance,
                                                  sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        events = result.result["scenario_seeds"][0]["attack_sequence"]
        for event in events[1:]:
            assert event["required_access"] != "none", event["name"]


# ---------------------------------------------------------------------------
# Tactic correction and kill-chain sequence checks
# ---------------------------------------------------------------------------

class TestTacticCorrection:
    def test_single_tactic_technique_is_corrected_not_kept(self, plugin_instance,
                                                           sample_flow_map):
        """T1190 carries only Initial Access, so 'Impact' has one right answer."""
        reply = _good_projection()
        reply["paths"][0]["steps"][0]["tactic"] = "Impact"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.ok
        step = result.result["attack_graph"]["paths"][0]["steps"][0]
        assert step["tactic"] == "Initial Access"
        assert any("corrected" in n for n in step["notes"])

    def test_correction_is_not_a_rejection(self, plugin_instance, sample_flow_map):
        """A mislabelled tactic must not cost the step or split the graph."""
        reply = _good_projection()
        reply["paths"][0]["steps"][0]["tactic"] = "Impact"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.result["step_count"] == 3
        assert not result.result["rejections"]

    def test_multi_tactic_technique_picks_one_it_carries(self, plugin_instance,
                                                        sample_flow_map):
        """T1078 carries four tactics; a bogus label resolves to one of them."""
        from framework.reference_data.mitre_attack import get_mitre_db
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["tactic"] = "Exfiltration"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        step = result.result["attack_graph"]["paths"][0]["steps"][1]
        assert step["tactic"] in get_mitre_db()["T1078"]["tactics"]

    def test_correction_does_not_introduce_a_second_entry(self, plugin_instance,
                                                          sample_flow_map):
        """T1078 carries Initial Access, but step 2 must not become an entry."""
        reply = _good_projection()
        reply["paths"][0]["steps"][1]["tactic"] = "Exfiltration"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        step = result.result["attack_graph"]["paths"][0]["steps"][1]
        assert step["tactic"] != "Initial Access"

    def test_correction_feeds_the_access_table(self, plugin_instance,
                                               sample_flow_map):
        """The corrected tactic, not the model's label, drives access levels."""
        reply = _good_projection()
        reply["paths"][0]["steps"][0]["tactic"] = "Impact"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        event = result.result["scenario_seeds"][0]["attack_sequence"][0]
        # Initial Access -> none->user, not Impact's admin->admin
        assert (event["required_access"], event["resulting_access"]) == ("none", "user")

    def test_correct_label_produces_no_note(self, plugin_instance, sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        first = result.result["attack_graph"]["paths"][0]["steps"][0]
        assert first["tactic"] == "Initial Access"
        assert not first["notes"]

    def test_closest_tactic_prefers_forward_progress(self):
        pick = _tool_mod._closest_tactic
        # Persistence(5), Privilege Escalation(6), Stealth(7), Initial Access(3)
        candidates = ["Stealth", "Persistence", "Privilege Escalation",
                      "Initial Access"]
        assert pick(candidates, 0) == "Initial Access"       # first step
        assert pick(candidates, 3) == "Persistence"          # forward, no re-entry
        assert pick(candidates, 7) == "Stealth"              # same position ok

    def test_closest_tactic_falls_back_when_nothing_is_forward(self):
        pick = _tool_mod._closest_tactic
        assert pick(["Discovery"], 18) == "Discovery"


class TestKillChainSequence:
    def test_large_regression_is_flagged(self, plugin_instance, sample_flow_map):
        """Collection(13) then Reconnaissance-era work is out of sequence."""
        reply = _good_projection()
        reply["paths"][0]["steps"] = [
            {"technique_id": "T1005", "tactic": "Collection",
             "component_id": "web", "rationale": "collect first",
             "leads_to": ["T1190"]},
            {"technique_id": "T1190", "tactic": "Initial Access",
             "component_id": "web", "rationale": "then break in", "leads_to": []},
        ]
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.ok
        codes = {w["code"] for w in result.result["warnings"]}
        assert "KILL_CHAIN_REGRESSION" in codes

    def test_regression_is_flagged_not_rejected(self, plugin_instance,
                                                sample_flow_map):
        """A step in the wrong position still keeps its edges."""
        reply = _good_projection()
        reply["paths"][0]["steps"] = [
            {"technique_id": "T1005", "tactic": "Collection",
             "component_id": "web", "rationale": "collect first",
             "leads_to": ["T1190"]},
            {"technique_id": "T1190", "tactic": "Initial Access",
             "component_id": "web", "rationale": "then break in", "leads_to": []},
        ]
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        assert result.result["step_count"] == 2
        assert not result.result["rejections"]

    def test_normal_loop_is_not_flagged(self, plugin_instance, sample_flow_map):
        """Lateral Movement back to Discovery is ordinary tradecraft."""
        reply = _good_projection()
        reply["paths"][0]["steps"] = [
            {"technique_id": "T1190", "tactic": "Initial Access",
             "component_id": "web", "rationale": "entry", "leads_to": ["T1550.003"]},
            {"technique_id": "T1550.003", "tactic": "Lateral Movement",
             "component_id": "api", "rationale": "pivot",
             "leads_to": ["T1003.004"]},
            {"technique_id": "T1003.004", "tactic": "Credential Access",
             "component_id": "api", "rationale": "harvest secrets",
             "leads_to": []},
        ]
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        codes = {w["code"] for w in result.result["warnings"]}
        assert "KILL_CHAIN_REGRESSION" not in codes

    def test_clean_path_has_no_sequence_warnings(self, plugin_instance,
                                                 sample_flow_map):
        result, _ = _project(plugin_instance, sample_flow_map, _good_projection())
        codes = {w["code"] for w in result.result["warnings"]}
        assert "KILL_CHAIN_REGRESSION" not in codes
        assert "LATE_INITIAL_ACCESS" not in codes

    def test_late_initial_access_is_flagged(self, plugin_instance, sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"] = [
            {"technique_id": "T1190", "tactic": "Initial Access",
             "component_id": "web", "rationale": "entry", "leads_to": ["T1133"]},
            {"technique_id": "T1133", "tactic": "Initial Access",
             "component_id": "api", "rationale": "second entry", "leads_to": []},
        ]
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        codes = {w["code"] for w in result.result["warnings"]}
        assert "LATE_INITIAL_ACCESS" in codes

    def test_sequence_problems_reach_the_summary(self, plugin_instance,
                                                 sample_flow_map):
        """A warning nobody reads is not a warning."""
        reply = _good_projection()
        reply["paths"][0]["steps"] = [
            {"technique_id": "T1005", "tactic": "Collection",
             "component_id": "web", "rationale": "collect first",
             "leads_to": ["T1190"]},
            {"technique_id": "T1190", "tactic": "Initial Access",
             "component_id": "web", "rationale": "then break in", "leads_to": []},
        ]
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        summary = plugin_instance.summarize_for_llm(result)
        assert "out of kill-chain sequence" in summary
        assert len(summary) <= 2000

    def test_corrections_reach_the_summary(self, plugin_instance, sample_flow_map):
        reply = _good_projection()
        reply["paths"][0]["steps"][0]["tactic"] = "Impact"
        result, _ = _project(plugin_instance, sample_flow_map, reply)
        summary = plugin_instance.summarize_for_llm(result)
        assert "tactic label(s) corrected" in summary


class TestThinkingLevel:
    def test_default_is_medium(self, plugin_instance, sample_flow_map):
        result, llm = _project(plugin_instance, sample_flow_map,
                               _good_projection())
        assert llm.hints[0].thinking_level == "medium"
        assert result.result["thinking_level"] == "medium"

    def test_default_is_stated_not_left_to_the_dispatcher(self):
        """An unset level plus needs_reasoning resolves to 'high' in
        client.py:_build_config. The plugin must state its own floor."""
        assert _tool_mod.DEFAULT_THINKING_LEVEL in _tool_mod.THINKING_LEVELS
        assert _tool_mod.DEFAULT_THINKING_LEVEL is not None

    def test_level_is_overridable(self, plugin_instance, sample_flow_map):
        llm = _ScriptedLLM(_good_projection())
        context = FakeContext()
        context.llm_query = llm
        result = plugin_instance.execute({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map, "thinking_level": "low",
        }, context)
        assert result.ok
        assert llm.hints[0].thinking_level == "low"
        assert result.result["thinking_level"] == "low"

    def test_invalid_level_is_rejected(self, plugin_instance, sample_flow_map):
        result = plugin_instance.validate_inputs({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map, "thinking_level": "ludicrous",
        })
        assert not result.ok
        assert "thinking_level" in result.errors[0]

    def test_every_level_validates(self, plugin_instance, sample_flow_map):
        for level in _tool_mod.THINKING_LEVELS:
            result = plugin_instance.validate_inputs({
                "action": "project_paths", "threat_actor": "APT29",
                "flow_map": sample_flow_map, "thinking_level": level,
            })
            assert result.ok, level

    def test_reasoning_flag_still_set(self, plugin_instance, sample_flow_map):
        """Explicit level must not displace the heavy tier or the reasoning hint."""
        _, llm = _project(plugin_instance, sample_flow_map, _good_projection())
        hints = llm.hints[0]
        assert hints.tier == "heavy"
        assert hints.needs_reasoning is True
        assert hints.needs_structured_output is True


class TestThinkingLevelEnvOverride:
    ENV = "EVENTMILL_PROJECTION_THINKING"

    def test_unset_falls_back_to_the_plugin_default(self, monkeypatch):
        monkeypatch.delenv(self.ENV, raising=False)
        assert _tool_mod._default_thinking_level() == "medium"

    def test_env_raises_the_default(self, monkeypatch, plugin_instance,
                                    sample_flow_map):
        monkeypatch.setenv(self.ENV, "high")
        result, llm = _project(plugin_instance, sample_flow_map,
                               _good_projection())
        assert llm.hints[0].thinking_level == "high"
        assert result.result["thinking_level"] == "high"

    def test_env_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv(self.ENV, "  HIGH  ")
        assert _tool_mod._default_thinking_level() == "high"

    def test_every_level_is_accepted(self, monkeypatch):
        for level in _tool_mod.THINKING_LEVELS:
            monkeypatch.setenv(self.ENV, level)
            assert _tool_mod._default_thinking_level() == level

    def test_bad_value_warns_and_falls_back(self, monkeypatch, caplog):
        """An operator typo must not cost a projection."""
        monkeypatch.setenv(self.ENV, "ludicrous")
        with caplog.at_level("WARNING"):
            assert _tool_mod._default_thinking_level() == "medium"
        assert any(
            self.ENV in r.getMessage() and "ludicrous" in r.getMessage()
            for r in caplog.records
        )

    def test_empty_value_is_ignored(self, monkeypatch):
        monkeypatch.setenv(self.ENV, "")
        assert _tool_mod._default_thinking_level() == "medium"

    def test_per_call_flag_beats_the_env(self, monkeypatch, plugin_instance,
                                        sample_flow_map):
        """Precedence: payload > env > default."""
        monkeypatch.setenv(self.ENV, "high")
        llm = _ScriptedLLM(_good_projection())
        context = FakeContext()
        context.llm_query = llm
        result = plugin_instance.execute({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map, "thinking_level": "low",
        }, context)
        assert result.ok
        assert llm.hints[0].thinking_level == "low"

    def test_env_read_at_call_time_not_import_time(self, monkeypatch):
        """A .env loaded after import must still apply."""
        monkeypatch.setenv(self.ENV, "minimal")
        assert _tool_mod._default_thinking_level() == "minimal"
        monkeypatch.setenv(self.ENV, "high")
        assert _tool_mod._default_thinking_level() == "high"

    def test_bad_env_still_validates_inputs(self, monkeypatch, plugin_instance,
                                            sample_flow_map):
        """A bad env value must not make every payload fail validation."""
        monkeypatch.setenv(self.ENV, "ludicrous")
        result = plugin_instance.validate_inputs({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map,
        })
        assert result.ok


# ---------------------------------------------------------------------------
# Run records
# ---------------------------------------------------------------------------

RUN_SCHEMA = json.loads(
    (PLUGIN_DIR / "schemas" / "projection_run.schema.json").read_text(
        encoding="utf-8"
    )
)


class _SequencedLLM:
    """Answers each call from a list, so a loop can be scripted run by run."""

    def __init__(self, replies: list):
        self.prompts: list[str] = []
        self.hints: list[Any] = []
        self._replies = list(replies)
        self._index = 0

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.prompts.append(prompt)
        self.hints.append(hints)
        reply = self._replies[min(self._index, len(self._replies) - 1)]
        self._index += 1
        if isinstance(reply, _Resp):
            return reply
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return _Resp(text=text)

    def supports_native_document(self, mime_type):
        return False


def _records_in(workspace) -> list[dict]:
    art_dir = Path(workspace) / "artifacts"
    if not art_dir.exists():
        return []
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(art_dir.glob("adversary_projection_run_*.json"))
    ]


def _project_exporting(plugin, flow_map, replies, workspace, monkeypatch,
                       **payload):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(workspace))
    llm = _SequencedLLM(replies if isinstance(replies, list) else [replies])
    context = FakeContext()
    context.llm_query = llm
    result = plugin.execute({
        "action": "project_paths", "threat_actor": "APT29",
        "flow_map": flow_map, **payload,
    }, context)
    return result, llm


class TestCanonicalFlowMapHash:
    def test_reformatting_does_not_change_the_hash(self):
        a = {"application": "X", "components": [{"id": "w", "zone": "z"}]}
        b = {"components": [{"zone": "z", "id": "w"}], "application": "X"}
        assert (
            _tool_mod._canonical_flow_map_hash(a)
            == _tool_mod._canonical_flow_map_hash(b)
        )

    def test_any_value_change_changes_the_hash(self):
        a = {"application": "X", "components": [{"id": "w", "exposure": "internal"}]}
        b = {"application": "X", "components": [{"id": "w", "exposure": "internet"}]}
        assert (
            _tool_mod._canonical_flow_map_hash(a)
            != _tool_mod._canonical_flow_map_hash(b)
        )

    def test_hashing_the_normalized_map_would_be_wrong(self, sample_flow_map):
        """Normalization fills defaults, so it collapses genuine differences.

        Two maps that differ only in an omitted-vs-explicit default normalize
        to the same thing. Hashing post-normalization would call them the same
        estate; hashing as supplied does not.
        """
        bare = json.loads(json.dumps(sample_flow_map))
        explicit = json.loads(json.dumps(sample_flow_map))
        for component in explicit["components"]:
            component.setdefault("technologies", [])
            component.setdefault("controls", [])

        raw_differs = (
            _tool_mod._canonical_flow_map_hash(bare)
            != _tool_mod._canonical_flow_map_hash(explicit)
        )
        norm_a, _, _ = _tool_mod._normalize_flow_map(bare)
        norm_b, _, _ = _tool_mod._normalize_flow_map(explicit)
        normalized_same = (
            _tool_mod._canonical_flow_map_hash(norm_a)
            == _tool_mod._canonical_flow_map_hash(norm_b)
        )
        assert raw_differs and normalized_same

    def test_hash_is_a_sha256_hex_digest(self, sample_flow_map):
        digest = _tool_mod._canonical_flow_map_hash(sample_flow_map)
        assert len(digest) == 64 and set(digest) <= set("0123456789abcdef")


class TestExportOptIn:
    def test_absent_export_writes_no_record(self, plugin_instance,
                                            sample_flow_map, tmp_path,
                                            monkeypatch):
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch,
        )
        assert result.ok
        assert _records_in(tmp_path) == []

    def test_absent_export_leaves_the_result_unchanged(self, plugin_instance,
                                                      sample_flow_map, tmp_path,
                                                      monkeypatch):
        """The one-run result keeps the shape it had before export existed."""
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch,
        )
        assert result.result["path_count"] == 1
        assert result.result["step_count"] == 3
        assert "attack_graph" in result.result
        assert "run_record" not in result.result
        assert "runs" not in result.result

    def test_export_writes_exactly_one_record(self, plugin_instance,
                                              sample_flow_map, tmp_path,
                                              monkeypatch):
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True,
        )
        assert result.ok
        assert len(_records_in(tmp_path)) == 1
        assert result.result["run_record"].startswith("adversary_projection_run_")


class TestRunRecordSchema:
    def test_successful_record_validates(self, plugin_instance, sample_flow_map,
                                         tmp_path, monkeypatch):
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True, run_group="apt29-portal",
        )
        record = _records_in(tmp_path)[0]
        jsonschema = pytest.importorskip("jsonschema")
        jsonschema.validate(record, RUN_SCHEMA)

    def test_record_carries_both_version_identifiers(self, plugin_instance,
                                                     sample_flow_map, tmp_path,
                                                     monkeypatch):
        """The manifest version alone cannot separate two builds of the code."""
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True,
        )
        version = _records_in(tmp_path)[0]["run"]["tool_version"]
        assert set(version) == {"manifest_version", "git_sha"}

    def test_run_group_is_slugged(self, plugin_instance, sample_flow_map,
                                  tmp_path, monkeypatch):
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True, run_group="APT29 / telemetry 2026-09!",
        )
        assert _records_in(tmp_path)[0]["run"]["run_group"] == (
            "APT29-telemetry-2026-09"
        )

    def test_run_group_defaults(self, plugin_instance, sample_flow_map,
                                tmp_path, monkeypatch):
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True,
        )
        assert _records_in(tmp_path)[0]["run"]["run_group"] == "ungrouped"

    def test_model_block_records_resolved_thinking_level(self, plugin_instance,
                                                         sample_flow_map,
                                                         tmp_path, monkeypatch):
        """The level that ran, not the one requested."""
        monkeypatch.setenv("EVENTMILL_PROJECTION_THINKING", "high")
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True,
        )
        assert _records_in(tmp_path)[0]["model"]["thinking_level"] == "high"

    def test_outcome_carries_provider_stop_signal_and_usage(self,
                                                            plugin_instance,
                                                            sample_flow_map,
                                                            tmp_path,
                                                            monkeypatch):
        monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
        reply = _Resp(
            text=json.dumps(_good_projection()),
            finish_reason="STOP",
            token_usage={"prompt_tokens": 11, "completion_tokens": 22,
                         "thinking_tokens": 33, "total_tokens": 66},
        )
        context = FakeContext()
        context.llm_query = _SequencedLLM([reply])
        plugin_instance.execute({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map, "export": True,
        }, context)
        outcome = _records_in(tmp_path)[0]["outcome"]
        assert outcome["finish_reason"] == "STOP"
        assert outcome["usage"]["thinking_tokens"] == 33
        assert outcome["wall_time_ms"] >= 0

    def test_sampled_keeps_technique_id_first_class(self, plugin_instance,
                                                    sample_flow_map, tmp_path,
                                                    monkeypatch):
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True,
        )
        steps = _records_in(tmp_path)[0]["sampled"]["paths"][0]["steps"]
        assert [s["technique_id"] for s in steps] == ["T1190", "T1078", "T1005"]
        assert all(s["technique_name"] for s in steps)

    def test_raw_reply_is_retained_beside_the_record(self, plugin_instance,
                                                     sample_flow_map, tmp_path,
                                                     monkeypatch):
        """When two runs disagree, only the raw reply shows why."""
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True,
        )
        record = _records_in(tmp_path)[0]
        raw = tmp_path / "artifacts" / record["run"]["raw_response_file"]
        assert raw.exists()
        assert json.loads(raw.read_text(encoding="utf-8"))["paths"]


class TestFailedRunsExport:
    def test_parse_failure_records_an_error(self, plugin_instance,
                                            sample_flow_map, tmp_path,
                                            monkeypatch):
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, "not json at all", tmp_path,
            monkeypatch, export=True,
        )
        assert not result.ok
        record = _records_in(tmp_path)[0]
        assert record["outcome"]["status"] == "error"
        assert record["outcome"]["error_code"] == "LLM_QUERY_FAILED"
        assert "sampled" not in record

    def test_truncation_records_an_error(self, plugin_instance, sample_flow_map,
                                         tmp_path, monkeypatch):
        """A reply cut off at the token cap is a finding about the map."""
        monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
        reply = _Resp(text=json.dumps(_good_projection()),
                      finish_reason="MAX_TOKENS", truncated=True)
        context = FakeContext()
        context.llm_query = _SequencedLLM([reply])
        result = plugin_instance.execute({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map, "export": True,
        }, context)
        assert not result.ok
        record = _records_in(tmp_path)[0]
        assert record["outcome"]["truncated"] is True
        assert record["outcome"]["finish_reason"] == "MAX_TOKENS"
        assert "sampled" not in record

    def test_query_failure_records_an_error(self, plugin_instance,
                                            sample_flow_map, tmp_path,
                                            monkeypatch):
        monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
        context = FakeContext()
        context.llm_query = _SequencedLLM([_Resp(ok=False, error="504 boom")])
        result = plugin_instance.execute({
            "action": "project_paths", "threat_actor": "APT29",
            "flow_map": sample_flow_map, "export": True,
        }, context)
        assert not result.ok
        record = _records_in(tmp_path)[0]
        assert record["outcome"]["status"] == "error"
        assert "504" in record["outcome"]["message"]

    def test_failed_record_still_validates(self, plugin_instance,
                                           sample_flow_map, tmp_path,
                                           monkeypatch):
        _project_exporting(
            plugin_instance, sample_flow_map, "not json at all", tmp_path,
            monkeypatch, export=True,
        )
        jsonschema = pytest.importorskip("jsonschema")
        jsonschema.validate(_records_in(tmp_path)[0], RUN_SCHEMA)

    def test_failed_record_keeps_the_deterministic_block(self, plugin_instance,
                                                         sample_flow_map,
                                                         tmp_path, monkeypatch):
        """A map that reliably fails is still a statement about the map."""
        _project_exporting(
            plugin_instance, sample_flow_map, "not json at all", tmp_path,
            monkeypatch, export=True,
        )
        record = _records_in(tmp_path)[0]
        assert record["deterministic"]["entry_ranking"]
        assert record["deterministic"]["routes"]


class TestDeterministicBlockIsStable:
    def test_identical_across_separate_invocations(self, plugin_instance,
                                                   sample_flow_map):
        """The cheapest correctness check the corpus has.

        Built without an LLM: validate_flow_map is the deterministic layer on
        its own, so the comparison needs no model and no mocking around one.
        """
        payload = {"action": "validate_flow_map", "flow_map": sample_flow_map}
        first = plugin_instance.execute(payload, FakeContext()).result
        second = plugin_instance.execute(payload, FakeContext()).result

        def _block(data):
            return json.dumps({
                "entry_ranking": data["entry_surface"],
                "routes": data["crown_jewel_routes"],
                "unreachable_crown_jewels": data["unreachable_crown_jewels"],
                "validation": data["warnings"],
            }, sort_keys=True)

        assert _block(first) == _block(second)

    def test_matches_what_the_record_stores(self, plugin_instance,
                                            sample_flow_map, tmp_path,
                                            monkeypatch):
        """The record's deterministic block is that same layer, not a copy."""
        linted = plugin_instance.execute(
            {"action": "validate_flow_map", "flow_map": sample_flow_map},
            FakeContext(),
        ).result
        _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), tmp_path,
            monkeypatch, export=True,
        )
        block = _records_in(tmp_path)[0]["deterministic"]
        assert json.dumps(block["entry_ranking"], sort_keys=True) == json.dumps(
            linted["entry_surface"], sort_keys=True
        )
        assert json.dumps(block["routes"], sort_keys=True) == json.dumps(
            linted["crown_jewel_routes"], sort_keys=True
        )

    def test_identical_across_runs_in_one_loop(self, plugin_instance,
                                               sample_flow_map, tmp_path,
                                               monkeypatch):
        _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=3,
        )
        blocks = {
            json.dumps(r["deterministic"], sort_keys=True)
            for r in _records_in(tmp_path)
        }
        assert len(blocks) == 1


class TestMultipleRuns:
    def test_runs_writes_one_record_each(self, plugin_instance, sample_flow_map,
                                         tmp_path, monkeypatch):
        result, llm = _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=3, run_group="stability",
        )
        assert result.ok
        assert len(llm.prompts) == 3
        records = _records_in(tmp_path)
        assert len(records) == 3
        assert {r["run"]["run_index"] for r in records} == {1, 2, 3}
        assert {r["run"]["run_group"] for r in records} == {"stability"}
        assert len({r["run"]["run_id"] for r in records}) == 3
        assert {r["run"]["run_count"] for r in records} == {3}

    def test_runs_implies_export(self, plugin_instance, sample_flow_map,
                                 tmp_path, monkeypatch):
        """A loop that leaves no record cannot be compared, so it is not one."""
        _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=2,
        )
        assert len(_records_in(tmp_path)) == 2

    def test_no_record_is_modified_by_a_later_run(self, plugin_instance,
                                                  sample_flow_map, tmp_path,
                                                  monkeypatch):
        _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=2, run_group="first",
        )
        art_dir = tmp_path / "artifacts"
        before = {
            p.name: p.read_bytes()
            for p in art_dir.glob("adversary_projection_run_*.json")
        }
        _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=2, run_group="first",
        )
        after = {
            p.name: p.read_bytes()
            for p in art_dir.glob("adversary_projection_run_*.json")
        }
        assert len(after) == 4
        for name, value in before.items():
            assert after[name] == value

    def test_a_failing_run_does_not_stop_the_rest(self, plugin_instance,
                                                  sample_flow_map, tmp_path,
                                                  monkeypatch):
        """At 'high' a run can hit the gateway deadline; the loop must survive."""
        replies = [
            _good_projection(),
            _Resp(ok=False, error="504 DEADLINE_EXCEEDED"),
            _good_projection(),
        ]
        result, llm = _project_exporting(
            plugin_instance, sample_flow_map, replies, tmp_path, monkeypatch,
            runs=3,
        )
        assert len(llm.prompts) == 3
        assert result.ok
        assert result.result["succeeded"] == 2
        assert result.result["failed"] == 1

        records = _records_in(tmp_path)
        assert len(records) == 3
        statuses = {r["run"]["run_index"]: r["outcome"]["status"] for r in records}
        assert statuses == {1: "ok", 2: "error", 3: "ok"}

    def test_all_runs_failing_is_a_failed_result(self, plugin_instance,
                                                 sample_flow_map, tmp_path,
                                                 monkeypatch):
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, ["nonsense"], tmp_path,
            monkeypatch, runs=2,
        )
        assert not result.ok
        assert len(_records_in(tmp_path)) == 2

    def test_graph_artifact_written_once_per_loop(self, plugin_instance,
                                                  sample_flow_map, tmp_path,
                                                  monkeypatch):
        """A twenty-run experiment must not bury the listing in graphs."""
        _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=3,
        )
        art_dir = tmp_path / "artifacts"
        assert len(list(art_dir.glob("adversary_path_graph_*.json"))) == 1
        assert len(list(art_dir.glob("adversary_scenario_seed_*.json"))) == 1

    def test_multi_run_result_has_no_graph(self, plugin_instance,
                                           sample_flow_map, tmp_path,
                                           monkeypatch):
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=2,
        )
        assert "attack_graph" not in result.result
        assert len(result.result["runs"]) == 2

    def test_runs_bounds(self, plugin_instance, sample_flow_map):
        base = {"action": "project_paths", "threat_actor": "APT29",
                "flow_map": sample_flow_map}
        assert not plugin_instance.validate_inputs({**base, "runs": 0}).ok
        assert not plugin_instance.validate_inputs(
            {**base, "runs": _tool_mod.MAX_RUNS + 1}).ok
        assert plugin_instance.validate_inputs({**base, "runs": 1}).ok
        assert plugin_instance.validate_inputs(
            {**base, "runs": _tool_mod.MAX_RUNS}).ok

    def test_runs_must_be_an_integer(self, plugin_instance, sample_flow_map):
        base = {"action": "project_paths", "threat_actor": "APT29",
                "flow_map": sample_flow_map}
        assert not plugin_instance.validate_inputs({**base, "runs": "3"}).ok
        assert not plugin_instance.validate_inputs({**base, "runs": True}).ok


class TestRunSummary:
    def test_multi_run_summary_stays_under_the_cap(self, plugin_instance,
                                                   sample_flow_map, tmp_path,
                                                   monkeypatch):
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, [_good_projection()], tmp_path,
            monkeypatch, runs=_tool_mod.MAX_RUNS,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) < 2000

    def test_summary_reports_failures_by_code(self, plugin_instance,
                                              sample_flow_map, tmp_path,
                                              monkeypatch):
        replies = [_good_projection(), "nonsense", "nonsense"]
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, replies, tmp_path, monkeypatch,
            runs=3,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert "3 run(s)" in summary and "1 ok" in summary
        assert "LLM_QUERY_FAILED x2" in summary


class TestExportFailureIsNotFatal:
    def test_unwritable_workspace_keeps_the_projection(self, plugin_instance,
                                                       sample_flow_map,
                                                       tmp_path, monkeypatch):
        """Losing the record must not also lose the projection."""
        blocker = tmp_path / "blocked"
        blocker.write_text("not a directory", encoding="utf-8")
        result, _ = _project_exporting(
            plugin_instance, sample_flow_map, _good_projection(), blocker,
            monkeypatch, export=True,
        )
        assert result.ok
        assert result.result["path_count"] == 1
        assert result.result["export_errors"]
