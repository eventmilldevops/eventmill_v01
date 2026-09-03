# Event Mill Reference Data

This directory contains shared reference data available to all plugins.
Data is loaded once per process and made available via the `ReferenceDataView` interface.

## Contents

- **`mitre_techniques.json`** — Combined MITRE ATT&CK technique database
  (Enterprise + ICS), built by `scripts/build_mitre_lookup.py` from official
  STIX bundles (currently pinned to **ATT&CK v19.2**).
  See [One-time setup](#one-time-setup) below.
- **`mitre_attack.py`** — Python module providing `get_mitre_db()`,
  `validate_technique_id()`, and `enrich_technique()` for direct import by
  any plugin or framework code. It also owns the tactic vocabulary:
  `TACTIC_ORDER` (kill-chain sequence, Enterprise v19 with the ICS-only
  tactics interleaved), `LEGACY_TACTIC_ALIASES` (retired tactics such as
  "Defense Evasion" → Stealth / Defense Impairment), and the helpers
  `canonical_tactic()`, `tactic_ordinal()`, `is_legacy_tactic()` and
  `resolve_legacy_tactic()`. Plugins that order or validate tactics must
  derive their tables from here rather than hardcoding names.
- **`mitre_relationships.json`** — Groups (intrusion-set), campaigns,
  software (malware / tool) and mitigations (course-of-action) from the same
  bundles, each keyed by ATT&CK id with the techniques it uses or mitigates,
  cross-references between them (group ↔ software ↔ campaign), and the
  procedure examples attached to `uses` relationships. Built by the same
  script. ~4 MB with procedures; pass `--skip-procedures` for a much smaller
  file. See [Relationships](#relationships) below.
- `vetted_sources.json` — Curated URLs for threat intel, research, regulatory bodies

## Usage

### Via `context.reference_data` (from within a plugin's `execute()`)

```python
mitre_db = context.reference_data.get("mitre_techniques")  # dict[tid, metadata]
entry = mitre_db.get("T1190")  # {'name': '...', 'tactics': [...], 'url': '...'}
```

### Via direct import (from any Python code)

```python
from framework.reference_data.mitre_attack import get_mitre_db, validate_technique_id

db = get_mitre_db()
is_real = validate_technique_id("T1655")  # False — LLM hallucination
```

## Relationships

`mitre_relationships.json` gives actor→technique and mitigation→technique
maps with no LLM involvement — the deterministic backbone for scenario
building. Shape:

```json
{
  "attack_version": "19.2",
  "matrices": ["enterprise", "ics"],
  "groups":      {"G0016": {"name": "APT29", "aliases": [...], "description": "...", "url": "...",
                            "matrices": ["enterprise"], "techniques": ["T1003.006", ...],
                            "software": ["S0154", ...], "campaigns": ["C0024"]}},
  "campaigns":   {"C0024": {"name": "SolarWinds Compromise", "first_seen": "2019-08-01",
                            "last_seen": "2021-01-01", "groups": ["G0016"],
                            "techniques": [...], "software": [...]}},
  "software":    {"S0154": {"name": "Cobalt Strike", "type": "tool", "aliases": [...],
                            "platforms": [...], "techniques": [...], "groups": [...], "campaigns": [...]}},
  "mitigations": {"M1049": {"name": "Antivirus/Antimalware", "techniques": [...]}},
  "procedures":  [{"source": "G0016", "technique": "T1566.001", "text": "APT29 has used ..."}]
}
```

Only active objects are included (revoked and deprecated groups, software
and the legacy technique-style Enterprise mitigations are dropped), and an
edge is kept only when both ends are active. Procedure text has markdown
links and `(Citation: ...)` markers stripped and is capped at 600 characters.

Helper API in `mitre_attack.py` (reverse indexes are built lazily):

```python
from framework.reference_data.mitre_attack import (
    get_mitre_relationships, find_group, find_software, find_campaign,
    techniques_for_group, techniques_for_software, techniques_for_campaign,
    techniques_for_mitigation, groups_for_technique, software_for_technique,
    campaigns_for_technique, mitigations_for_technique, procedures_for_technique,
)

gid = find_group("Cozy Bear")                  # "G0016" — id, name or alias, case-insensitive
techniques_for_group(gid)                      # ["T1003.006", "T1021.006", ...]
mitigations_for_technique("T1566.001")         # ["M1017", "M1018", "M1021", ...]
procedures_for_technique("T1566.001", gid)     # [{"source": "G0016", "technique": ..., "text": ...}]
```

Inside a plugin the raw structure is also available as
`context.reference_data.get("mitre_relationships")`.

## One-time setup

Build the MITRE technique database (requires `requests`):

```bash
python scripts/build_mitre_lookup.py
```

This writes both `mitre_techniques.json` and `mitre_relationships.json`.
Change `ATTACK_VERSION` in the script (or pass `--version`) after a new
ATT&CK release. `--bundle-dir DIR` rebuilds from already-downloaded
`<matrix>-attack-<version>.json` files without network access.
Plugins degrade gracefully if either file is missing — a warning is logged,
LLM-provided data is used without validation, and group / mitigation
lookups return empty results.

## Adding new reference data

Plugin-specific reference data in a plugin's `data/` directory can extend
or override these entries when that plugin is active.
