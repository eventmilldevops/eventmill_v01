"""Tests for the ATT&CK relationships lookup (groups, campaigns, software, mitigations).

Two layers:

* Extractor tests run ``scripts/build_mitre_lookup.py`` functions against a
  small synthetic STIX bundle — no network, no built file needed.
* Consistency tests load the built ``mitre_relationships.json`` and check it
  agrees with ``mitre_techniques.json`` and the helper API.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from framework.reference_data import mitre_attack

ROOT = Path(__file__).resolve().parent.parent.parent


def _load_build_script():
    spec = importlib.util.spec_from_file_location(
        "build_mitre_lookup", ROOT / "scripts" / "build_mitre_lookup.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build = _load_build_script()


# ---------------------------------------------------------------------------
# Synthetic bundle
# ---------------------------------------------------------------------------


def _ref(ext_id: str, kind: str) -> dict:
    return {
        "source_name": "mitre-attack",
        "external_id": ext_id,
        "url": f"https://attack.mitre.org/{kind}/{ext_id}",
    }


def _rel(rel_type: str, src: str, tgt: str, **extra) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{src}-{rel_type}-{tgt}",
        "relationship_type": rel_type,
        "source_ref": src,
        "target_ref": tgt,
        **extra,
    }


@pytest.fixture
def bundle() -> dict:
    objects = [
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--ia",
         "x_mitre_shortname": "initial-access", "name": "Initial Access"},
        {"type": "attack-pattern", "id": "attack-pattern--t1566", "name": "Phishing",
         "external_references": [_ref("T1566", "techniques")],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]},
        {"type": "attack-pattern", "id": "attack-pattern--t1059", "name": "Command and Scripting Interpreter",
         "external_references": [_ref("T1059", "techniques")],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]},
        {"type": "attack-pattern", "id": "attack-pattern--t1078", "name": "Valid Accounts",
         "external_references": [_ref("T1078", "techniques")],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]},
        {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Retired",
         "revoked": True,
         "external_references": [_ref("T1999", "techniques")]},
        {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "APT Test",
         "aliases": ["APT Test", "Fuzzy Bear"],
         "description": "[APT Test](https://attack.mitre.org/groups/G0001) is a group.(Citation: Vendor 2024)",
         "external_references": [_ref("G0001", "groups")]},
        {"type": "intrusion-set", "id": "intrusion-set--g2", "name": "Old Group",
         "revoked": True, "external_references": [_ref("G0002", "groups")]},
        {"type": "campaign", "id": "campaign--c1", "name": "Operation Test",
         "aliases": ["Operation Test"], "first_seen": "2023-01-15T00:00:00.000Z",
         "last_seen": "2023-06-01T00:00:00.000Z",
         "external_references": [_ref("C0001", "campaigns")]},
        {"type": "malware", "id": "malware--s1", "name": "TestRAT",
         "x_mitre_aliases": ["TestRAT", "TRat"], "x_mitre_platforms": ["Windows"],
         "external_references": [_ref("S0001", "software")]},
        {"type": "tool", "id": "tool--s2", "name": "TestTool",
         "external_references": [_ref("S0002", "software")]},
        {"type": "course-of-action", "id": "course-of-action--m1", "name": "User Training",
         "external_references": [_ref("M1017", "mitigations")]},
        {"type": "course-of-action", "id": "course-of-action--legacy", "name": "Legacy Mitigation",
         "x_mitre_deprecated": True,
         "external_references": [_ref("T1566", "mitigations")]},
        _rel("uses", "intrusion-set--g1", "attack-pattern--t1566",
             description="[APT Test](https://attack.mitre.org/groups/G0001) sent phishing emails.(Citation: X)"),
        _rel("uses", "intrusion-set--g1", "malware--s1"),
        _rel("uses", "malware--s1", "attack-pattern--t1059"),
        _rel("uses", "tool--s2", "attack-pattern--t1059"),
        _rel("uses", "campaign--c1", "attack-pattern--t1078"),
        _rel("uses", "campaign--c1", "tool--s2"),
        _rel("attributed-to", "campaign--c1", "intrusion-set--g1"),
        _rel("mitigates", "course-of-action--m1", "attack-pattern--t1566"),
        _rel("mitigates", "course-of-action--legacy", "attack-pattern--t1566"),
        # Edges that must be dropped
        _rel("uses", "intrusion-set--g2", "attack-pattern--t1566"),
        _rel("uses", "intrusion-set--g1", "attack-pattern--old"),
        _rel("uses", "intrusion-set--g1", "attack-pattern--t1078", revoked=True),
    ]
    return {"objects": objects}


class TestExtractor:
    def test_entities_and_edges(self, bundle):
        out = build._extract_relationships(bundle, "enterprise")
        out = build._finalize_relationships(out, "19.2", include_procedures=True)

        assert set(out["groups"]) == {"G0001"}
        g = out["groups"]["G0001"]
        assert g["techniques"] == ["T1566"]
        assert g["software"] == ["S0001"]
        assert g["campaigns"] == ["C0001"]
        assert g["aliases"] == ["Fuzzy Bear"]
        assert g["matrices"] == ["enterprise"]
        assert g["description"] == "APT Test is a group."

        c = out["campaigns"]["C0001"]
        assert c["groups"] == ["G0001"]
        assert c["techniques"] == ["T1078"]
        assert c["software"] == ["S0002"]
        assert (c["first_seen"], c["last_seen"]) == ("2023-01-15", "2023-06-01")

        assert out["software"]["S0001"]["type"] == "malware"
        assert out["software"]["S0001"]["techniques"] == ["T1059"]
        assert out["software"]["S0001"]["groups"] == ["G0001"]
        assert out["software"]["S0001"]["aliases"] == ["TRat"]
        assert out["software"]["S0002"]["type"] == "tool"
        assert out["software"]["S0002"]["campaigns"] == ["C0001"]

        assert set(out["mitigations"]) == {"M1017"}
        assert out["mitigations"]["M1017"]["techniques"] == ["T1566"]

    def test_procedures_are_cleaned(self, bundle):
        out = build._extract_relationships(bundle, "enterprise")
        assert out["procedures"] == [
            {"source": "G0001", "technique": "T1566", "text": "APT Test sent phishing emails."}
        ]

    def test_skip_procedures(self, bundle):
        out = build._extract_relationships(bundle, "enterprise")
        out = build._finalize_relationships(out, "19.2", include_procedures=False)
        assert out["procedures"] == []
        assert out["attack_version"] == "19.2"

    def test_merge_unions_across_matrices(self, bundle):
        ent = build._extract_relationships(bundle, "enterprise")
        ics = build._extract_relationships(bundle, "ics")
        ics["groups"]["G0001"]["techniques"].add("T0800")
        merged = build._merge_relationships(
            {"groups": {}, "campaigns": {}, "software": {}, "mitigations": {}, "procedures": []},
            ent,
        )
        merged = build._merge_relationships(merged, ics)
        g = merged["groups"]["G0001"]
        assert g["matrices"] == {"enterprise", "ics"}
        assert g["techniques"] == {"T1566", "T0800"}
        assert len(merged["procedures"]) == 1  # identical procedure not duplicated

    def test_clean_text_caps_on_word_boundary(self):
        text = "word " * 200
        cleaned = build._clean_text(text, 50)
        assert cleaned.endswith(" ...")
        assert len(cleaned) <= 54


# ---------------------------------------------------------------------------
# Built file consistency and helper API
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rel() -> dict:
    data = mitre_attack.get_mitre_relationships()
    assert data.get("groups"), (
        "mitre_relationships.json missing — run scripts/build_mitre_lookup.py"
    )
    return data


class TestBuiltFile:
    def test_version_matches_build_script(self, rel):
        assert rel["attack_version"] == build.ATTACK_VERSION

    def test_ids_are_well_formed(self, rel):
        patterns = {
            "groups": r"^G\d{4}$", "campaigns": r"^C\d{4}$",
            "software": r"^S\d{4}$", "mitigations": r"^M\d{4}$",
        }
        for section, pattern in patterns.items():
            bad = [k for k in rel[section] if not re.match(pattern, k)]
            assert bad == [], f"{section}: {bad[:5]}"

    def test_every_referenced_technique_exists(self, rel):
        db = mitre_attack.get_mitre_db()
        missing = set()
        for section in ("groups", "campaigns", "software", "mitigations"):
            for record in rel[section].values():
                missing.update(t for t in record["techniques"] if t not in db)
        missing.update(p["technique"] for p in rel["procedures"] if p["technique"] not in db)
        assert missing == set()

    def test_cross_references_are_symmetric(self, rel):
        for gid, g in rel["groups"].items():
            for sid in g["software"]:
                assert gid in rel["software"][sid]["groups"]
            for cid in g["campaigns"]:
                assert gid in rel["campaigns"][cid]["groups"]
        for cid, c in rel["campaigns"].items():
            for sid in c["software"]:
                assert cid in rel["software"][sid]["campaigns"]

    def test_both_matrices_present(self, rel):
        assert any(k.startswith("M0") for k in rel["mitigations"])  # ICS
        assert any(k.startswith("M1") for k in rel["mitigations"])  # Enterprise
        assert any(len(g["matrices"]) > 1 for g in rel["groups"].values())


class TestHelperApi:
    def test_find_group_by_alias_and_id(self, rel):
        gid = mitre_attack.find_group("Cozy Bear")
        assert gid == "G0016"
        assert mitre_attack.find_group("g0016") == "G0016"
        assert mitre_attack.find_group("APT29") == "G0016"
        assert mitre_attack.find_group("no such actor") is None

    def test_group_to_techniques_and_back(self, rel):
        techniques = mitre_attack.techniques_for_group("G0016")
        assert "T1566.001" in techniques
        assert "G0016" in mitre_attack.groups_for_technique("T1566.001")

    def test_mitigations_for_technique(self, rel):
        mitigations = mitre_attack.mitigations_for_technique("T1566.001")
        assert mitigations
        assert all(m.startswith("M") for m in mitigations)
        for mid in mitigations:
            assert "T1566.001" in mitre_attack.techniques_for_mitigation(mid)

    def test_software_lookup(self, rel):
        sid = mitre_attack.find_software("Cobalt Strike")
        assert sid is not None
        assert mitre_attack.techniques_for_software(sid)
        assert sid in mitre_attack.software_for_technique(
            mitre_attack.techniques_for_software(sid)[0]
        )

    def test_procedures_for_technique_filtered_by_source(self, rel):
        procs = mitre_attack.procedures_for_technique("T1566.001", "G0016")
        assert procs
        assert all(p["source"] == "G0016" and p["technique"] == "T1566.001" for p in procs)
        assert "(Citation:" not in procs[0]["text"]

    def test_unknown_ids_return_empty(self, rel):
        assert mitre_attack.techniques_for_group("G9999") == []
        assert mitre_attack.mitigations_for_technique("T9999") == []
        assert mitre_attack.procedures_for_technique("T9999") == []


class TestMissingFile:
    def test_empty_structure_when_file_absent(self, monkeypatch, tmp_path):
        monkeypatch.setattr(mitre_attack, "_RELATIONSHIPS_FILE", tmp_path / "nope.json")
        mitre_attack._reset()
        try:
            data = mitre_attack.get_mitre_relationships()
            assert data["groups"] == {}
            assert mitre_attack.find_group("APT29") is None
            assert mitre_attack.mitigations_for_technique("T1566.001") == []
        finally:
            mitre_attack._reset()
