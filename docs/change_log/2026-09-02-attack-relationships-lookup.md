# Change Log — ATT&CK relationships lookup (groups, campaigns, software, mitigations)

**Date:** 2026-09-02
**Primary Files Modified:** `scripts/build_mitre_lookup.py`,
`framework/reference_data/mitre_attack.py`
**Supporting Files:** `framework/reference_data/mitre_relationships.json` (new,
generated), `framework/cli/shell.py`, `framework/reference_data/README.md`,
`tests/framework/test_mitre_relationships.py` (new)

---

## Overview

The technique lookup answered "is T1566.001 real and what tactic is it?" but
nothing in the framework could answer "which actors use it, what software
implements it, and what mitigates it?" without asking the LLM. Those maps are
the deterministic backbone of any threat-modelling scenario, and the ATT&CK
STIX bundles already contain them as `relationship` objects. This change
extracts them into a second reference file.

## Changes

### `scripts/build_mitre_lookup.py`

- Emits `framework/reference_data/mitre_relationships.json` alongside the
  technique file. Sections: `groups` (intrusion-set), `campaigns`,
  `software` (malware and tool), `mitigations` (course-of-action), each
  keyed by ATT&CK id with name, aliases, description, url, matrices and the
  technique ids it `uses` / `mitigates`; cross-references from `uses`
  (group/campaign → software) and `attributed-to` (campaign → group) in
  both directions; and a `procedures` list of the free-text procedure
  examples attached to `uses` edges, keyed by source id and technique.
- Only active objects are emitted. Revoked and deprecated groups, software
  and mitigations are dropped, as are the 224 legacy Enterprise
  course-of-action objects that carry technique-style ids. An edge is kept
  only when both endpoints are active and known, so every technique
  referenced exists in `mitre_techniques.json`.
- Procedure and description text is cleaned (markdown links and
  `(Citation: ...)` markers removed, whitespace collapsed) and capped at 600
  characters on a word boundary. Enterprise and ICS results are merged;
  groups present in both matrices get the union of their techniques.
- New CLI: `--version`, `--bundle-dir DIR` (offline rebuild from cached
  bundles) and `--skip-procedures` (omit procedure text for a small file).
  `requests` is now imported only when downloading.
- v19.2 result: 178 groups, 58 campaigns, 831 software, 96 mitigations,
  17,407 procedures, 3.9 MB. `mitre_techniques.json` is unchanged.

### `framework/reference_data/mitre_attack.py`

- `get_mitre_relationships()` loads the file once per process and returns an
  empty structure with a warning if it is missing.
- Lookup helpers with lazily built reverse indexes: `find_group`,
  `find_software`, `find_campaign` (id, name or alias, case-insensitive);
  `techniques_for_group` / `_software` / `_campaign` / `_mitigation`;
  `groups_for_technique`, `software_for_technique`,
  `campaigns_for_technique`, `mitigations_for_technique`;
  `procedures_for_technique(tid, source_id=None)`.
- `_reset()` now clears the relationships cache too.

### `framework/cli/shell.py`

- The plugin `ExecutionContext` now exposes the raw structure as
  `context.reference_data.get("mitre_relationships")` next to
  `mitre_techniques`.

### Tests

`tests/framework/test_mitre_relationships.py` runs the extractor against a
synthetic STIX bundle (revoked group, revoked technique, revoked
relationship and legacy mitigation are all excluded; text cleaning; merge
across matrices), then checks the built file for well-formed ids,
referential integrity against the technique database, symmetric
cross-references, and the helper API against known facts (APT29 alias
resolution, T1566.001 mitigations, Cobalt Strike).
