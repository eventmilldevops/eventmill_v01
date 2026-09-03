# Change Log — MITRE ATT&CK lookup moved to attack-stix-data, pinned to v19.2

**Date:** 2026-09-02
**Primary File Modified:** `scripts/build_mitre_lookup.py`
**Supporting Files:** `framework/reference_data/mitre_techniques.json` (regenerated),
`framework/reference_data/README.md`, `plugins/log_analysis/threat_intel_ingester/README.md`,
`plugins/log_analysis/threat_intel_ingester/tool.py` (log message only)

---

## Changes

- `build_mitre_lookup.py` now downloads from `mitre-attack/attack-stix-data`
  (STIX 2.1, one versioned bundle per release) instead of the legacy
  `mitre/cti` mirror. The release is a single `ATTACK_VERSION` constant;
  the URLs are derived from it.
- Pinned to **ATT&CK v19.2**. `mitre_techniques.json` regenerated:
  774 → 794 techniques (697 Enterprise + 97 ICS; 46 added, 26 removed).
- Version strings in the two READMEs and the ingester's unvalidated-technique
  warning updated from v18.1 to v19.2.

## v19 tactic restructure and plugin alignment

ATT&CK v19 removed the Enterprise **Defense Evasion** tactic and replaced it
with **Stealth** (148 techniques) and **Defense Impairment** (56). ICS keeps
**Evasion**. T1562 (Impair Defenses) and its sub-techniques were retired.
198 techniques changed their tactic list between v18.1 and v19.2.

Changes made so the plugins work against the v19 vocabulary:

- `scripts/build_mitre_lookup.py` now resolves kill-chain phase slugs to the
  official tactic names carried by the bundle's `x-mitre-tactic` objects
  instead of title-casing the slug. The database therefore says
  "Command and Control" (official) rather than "Command And Control", which
  had silently excluded C2 from `_fix_tactic_progression` because the
  ordering table used the official spelling.
- `framework/reference_data/mitre_attack.py` now owns the tactic
  vocabulary: `TACTIC_ORDER` (Enterprise v19 order with ICS-only tactics
  interleaved), `LEGACY_TACTIC_ALIASES`, and the helpers
  `canonical_tactic`, `tactic_ordinal`, `is_legacy_tactic`,
  `resolve_legacy_tactic`.
- `threat_intel_ingester` derives its `TACTIC_ORDER` from the shared
  sequence, and the LLM prompt lists the v19 tactics with an explicit
  instruction never to emit "Defense Evasion". A new
  `_migrate_legacy_tactics` pass runs first in `_reconcile_mitre_mappings`:
  every "Defense Evasion" in attack-graph steps and mapping entries is
  rewritten to the single successor the technique lists in the database;
  entries that collide with an existing successor entry are merged
  (`context_paths` unioned). Unresolvable cases (non-ATT&CK ID, or both
  successors allowed) are left for validation to flag.
- `attack_path_visualizer` derives `TACTIC_ORDER` / `TACTIC_DISPLAY` from
  the shared sequence. Legacy "defense-evasion" nodes from older artifacts
  keep their label but sort at Stealth's position instead of after Impact.
  ICS tactics (Evasion, Inhibit Response Function, Impair Process Control)
  are now ordered rather than appended.
- `risk_assessment_analyzer` replaces the `DEFENSE_EVASION` stage with
  `STEALTH` and `DEFENSE_IMPAIRMENT` in every attack-type template that
  listed it; a "Defense Evasion" stage name in input inherits Stealth's
  relevance.
- Tests: ingester tactic-progression fixtures moved to v19; new
  `TestLegacyTacticMigration` (ingester), `TestTacticOrdering`
  (visualizer), v19 vocabulary tests (risk assessment), and
  `tests/framework/test_mitre_tactics.py`, which asserts that every tactic
  in the built database appears in `TACTIC_ORDER` — the guard that would
  have caught this restructure at build time.
