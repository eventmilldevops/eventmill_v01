"""Retired ATT&CK technique ids resolve to their current equivalent.

ATT&CK v19 renumbered techniques the models still emit, because the old
numbering is what their training data and most published reporting use.
Without resolution a correct finding is demoted to "non-ATT&CK": dropped from
every ATT&CK-keyed view and shown to an analyst as though it were not real.
"""

from framework.reference_data.mitre_attack import (
    get_mitre_db,
    resolve_retired_technique,
    retirement_note,
)


class TestCuratedMap:
    def test_impair_defenses_disable_tools_maps_to_t1685(self):
        assert resolve_retired_technique(
            "T1562.001", "Impair Defenses: Disable or Modify Tools",
        ) == ("T1685", "curated")

    def test_impersonation_maps_to_t1684_001(self):
        assert resolve_retired_technique("T1656", "Impersonation") == (
            "T1684.001", "curated",
        )

    def test_a_split_technique_is_not_remapped(self):
        """T1562 became six techniques. Choosing one would be a guess, and the
        entry is more useful flagged than silently attached to the wrong id."""
        assert resolve_retired_technique("T1562", "Impair Defenses") is None

    def test_split_technique_still_explains_itself(self):
        note = retirement_note("T1562")
        assert "T1685" in note and "T1690" in note
        assert "retired" in note.lower()

    def test_every_curated_target_exists_in_the_database(self):
        """A map entry pointing at a nonexistent id would silently do nothing."""
        import json
        from pathlib import Path
        import framework.reference_data.mitre_attack as m
        path = Path(m.__file__).parent / "mitre_retired_techniques.json"
        retired = json.loads(path.read_text(encoding="utf-8"))["retired"]
        db = get_mitre_db()
        for old_id, entry in retired.items():
            target = entry.get("replaced_by")
            if target is not None:
                assert target in db, f"{old_id} -> {target} is not in ATT&CK"
            for succ in entry.get("successors") or []:
                assert succ in db, f"{old_id} successor {succ} is not in ATT&CK"

    def test_no_curated_entry_shadows_a_live_id(self):
        """If a retired id is somehow still in the database, it is not retired."""
        import json
        from pathlib import Path
        import framework.reference_data.mitre_attack as m
        path = Path(m.__file__).parent / "mitre_retired_techniques.json"
        retired = json.loads(path.read_text(encoding="utf-8"))["retired"]
        db = get_mitre_db()
        assert not (set(retired) & set(db)), "a listed id is still current"


class TestNameResolution:
    """The general case, so every v19 renumber does not need curating."""

    def test_uncurated_renumber_resolves_by_name(self):
        """T1562.004 is not in the curated map; its name is unchanged."""
        assert resolve_retired_technique(
            "T1562.004", "Impair Defenses: Disable or Modify System Firewall",
        ) == ("T1686", "name")

    def test_old_parent_prefix_is_stripped(self):
        """19.2 calls it just "Disable or Modify Tools"; the model sends the
        old "Parent: Sub" form."""
        new_id, basis = resolve_retired_technique(
            "T9998", "Impair Defenses: Disable or Modify Tools",
        )
        assert (new_id, basis) == ("T1685", "name")

    def test_ambiguous_leaf_is_disambiguated_by_parent(self):
        """"Botnet" is both T1583.005 and T1584.005."""
        assert resolve_retired_technique(
            "T9998", "Acquire Infrastructure: Botnet",
        ) == ("T1583.005", "name")

    def test_ambiguous_leaf_with_no_matching_parent_is_refused(self):
        assert resolve_retired_technique("T9998", "Nonsense: Botnet") is None

    def test_bare_ambiguous_name_is_refused(self):
        """Guessing between two real techniques is worse than flagging."""
        assert resolve_retired_technique("T9998", "Botnet") is None

    def test_unknown_id_with_no_name_is_refused(self):
        assert resolve_retired_technique("T9998", "") is None

    def test_unknown_id_with_unknown_name_is_refused(self):
        assert resolve_retired_technique("T9998", "Totally Made Up") is None


class TestCurrentIdsAreLeftAlone:
    def test_a_live_id_is_never_remapped(self):
        assert resolve_retired_technique("T1595", "Active Scanning") is None

    def test_a_live_id_is_not_remapped_even_with_a_wrong_name(self):
        """The id is authoritative when it is current; the name is not."""
        assert resolve_retired_technique("T1595", "Impersonation") is None

    def test_blank_id_is_refused(self):
        assert resolve_retired_technique("", "Impersonation") is None
