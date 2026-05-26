# Event Mill Reference Data

This directory contains shared reference data available to all plugins.
Data is loaded once per process and made available via the `ReferenceDataView` interface.

## Contents

- **`mitre_techniques.json`** — Combined MITRE ATT&CK technique database
  (Enterprise + ICS), built by `scripts/build_mitre_lookup.py` from official
  STIX bundles (currently pinned to **ATT&CK v18.1**, ~774 techniques).
  See [One-time setup](#one-time-setup) below.
- **`mitre_attack.py`** — Python module providing `get_mitre_db()`,
  `validate_technique_id()`, and `enrich_technique()` for direct import by
  any plugin or framework code.
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

## One-time setup

Build the MITRE technique database (requires `requests`):

```bash
python scripts/build_mitre_lookup.py
```

Re-run after a new ATT&CK version is released to pick up new techniques.
Plugins degrade gracefully if the file is missing — a warning is logged and
LLM-provided data is used without validation.

## Adding new reference data

Plugin-specific reference data in a plugin's `data/` directory can extend
or override these entries when that plugin is active.
