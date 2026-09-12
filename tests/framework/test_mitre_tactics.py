"""Tests for the shared ATT&CK tactic vocabulary in framework.reference_data.mitre_attack."""

from framework.reference_data.mitre_attack import (
    LEGACY_TACTIC_ALIASES,
    TACTIC_ORDER,
    canonical_tactic,
    get_mitre_db,
    is_legacy_tactic,
    resolve_legacy_tactic,
    tactic_ordinal,
)


class TestVocabulary:
    def test_v19_enterprise_tactics_present(self):
        assert "Stealth" in TACTIC_ORDER
        assert "Defense Impairment" in TACTIC_ORDER
        assert "Defense Evasion" not in TACTIC_ORDER

    def test_kill_chain_order(self):
        assert tactic_ordinal("Initial Access") < tactic_ordinal("Execution")
        assert tactic_ordinal("Privilege Escalation") < tactic_ordinal("Stealth")
        assert tactic_ordinal("Stealth") < tactic_ordinal("Defense Impairment")
        assert tactic_ordinal("Defense Impairment") < tactic_ordinal("Credential Access")
        assert tactic_ordinal("Exfiltration") < tactic_ordinal("Impact")

    def test_ordinal_is_one_based_and_unknown_sorts_last(self):
        assert tactic_ordinal("Reconnaissance") == 1
        assert tactic_ordinal("Cyber Magic") == len(TACTIC_ORDER) + 1

    def test_legacy_ordinal_matches_first_successor(self):
        assert tactic_ordinal("Defense Evasion") == tactic_ordinal("Stealth")


class TestCanonicalTactic:
    def test_case_insensitive(self):
        assert canonical_tactic("command And control") == "Command and Control"
        assert canonical_tactic("  stealth ") == "Stealth"

    def test_unknown_and_legacy_return_none(self):
        assert canonical_tactic("Defense Evasion") is None
        assert canonical_tactic("") is None
        assert canonical_tactic("nope") is None


class TestLegacyResolution:
    def test_is_legacy(self):
        assert is_legacy_tactic("Defense Evasion")
        assert is_legacy_tactic("defense evasion")
        assert not is_legacy_tactic("Stealth")

    def test_resolves_single_allowed_successor(self):
        assert resolve_legacy_tactic("Defense Evasion", ["Stealth", "Persistence"]) == "Stealth"
        assert resolve_legacy_tactic("Defense Evasion", ["defense impairment"]) == "Defense Impairment"

    def test_ambiguous_or_missing_returns_none(self):
        assert resolve_legacy_tactic("Defense Evasion", ["Stealth", "Defense Impairment"]) is None
        assert resolve_legacy_tactic("Defense Evasion", ["Persistence"]) is None
        assert resolve_legacy_tactic("Stealth", ["Stealth"]) is None

    def test_every_alias_maps_to_current_tactics(self):
        for successors in LEGACY_TACTIC_ALIASES.values():
            for tactic in successors:
                assert tactic in TACTIC_ORDER


class TestDatabaseConsistency:
    """The built database and the tactic table must describe the same release."""

    def test_every_db_tactic_is_in_tactic_order(self):
        db = get_mitre_db()
        assert db, "mitre_techniques.json missing — run scripts/build_mitre_lookup.py"
        unknown = sorted({t for entry in db.values() for t in entry["tactics"]} - set(TACTIC_ORDER))
        assert unknown == [], f"tactics in DB but not in TACTIC_ORDER: {unknown}"

    def test_no_legacy_tactics_in_db(self):
        db = get_mitre_db()
        legacy = sorted(
            tid for tid, entry in db.items()
            if any(is_legacy_tactic(t) for t in entry["tactics"])
        )
        assert legacy == []

    def test_db_uses_official_casing(self):
        db = get_mitre_db()
        assert "Command and Control" in db["T1219"]["tactics"]
