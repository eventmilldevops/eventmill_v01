# Change Log — MITRE ATT&CK Local Lookup, LLM Diagnostic Logging & Ingester Hardening

**Date:** 2026-04-18
**Primary Files Modified:** `plugins/log_analysis/threat_intel_ingester/tool.py`, `framework/reference_data/mitre_attack.py` (new), `framework/cli/shell.py`, `framework/logging/structured.py`
**Supporting Files:** `scripts/build_mitre_lookup.py`, `scripts/verify_mitre_lookup.py`, `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json`, `plugins/log_analysis/threat_intel_ingester/README.md`, `framework/reference_data/__init__.py` (new), `framework/reference_data/README.md`

---

## Overview

Four areas of work across this session, driven by a production run where the
`threat_intel_ingester` silently fell back to regex-only IOC extraction and
produced output missing MITRE mappings and attack graph data, with no clear
indication in the CLI or GCP activity logs of what went wrong:

1. **Local MITRE ATT&CK technique database** — Built a compact lookup of all
   Enterprise + ICS ATT&CK techniques (v18.1, 774 entries) from official MITRE
   STIX bundles. Used to enrich, backfill, and validate LLM-generated technique
   data without relying on the LLM for reference accuracy.

2. **LLM-hallucinated technique ID marking** — Technique IDs not found in the
   official ATT&CK matrix are now marked with `"mitre_validated": false` and a
   visible `(non-ATT&CK ID)` suffix so frontline analysts can see at a glance
   which technique IDs were LLM-generated, without needing access to tool logs.

3. **LLM diagnostic logging fixes** — Fixed a pre-truncation bug where
   `response_text[:500]` was passed to `log_llm_interaction` before the function
   could measure the actual response length, making `response_length` always
   report ≤500 regardless of the real value. Added activity-level logging for
   JSON parse failures so they appear in GCP Cloud Logging alongside the
   original LLM call.

4. **ToolResult completeness & fallback visibility** — Added `attack_graph` to
   the `ToolResult.result` dict (previously only in the artifact file) and added
   `ingestion_mode` to the summary so the CLI clearly shows when the tool fell
   back to regex-only extraction.

5. **Shared MITRE module** — Extracted the MITRE lookup from the plugin into
   `framework/reference_data/mitre_attack.py` so all plugins can use it.
   Moved `mitre_techniques.json` to `framework/reference_data/`. Wired the
   database into `ReferenceDataView` for protocol-based access.

---

## Changes

### `scripts/build_mitre_lookup.py` — MITRE STIX Download & Extraction

**Purpose:** One-time setup script that downloads the Enterprise and ICS
ATT&CK STIX bundles from the official MITRE CTI GitHub repository and writes
a compact JSON lookup file.

**Changes:**
- Created the script with `_extract_techniques()` to parse STIX 2.x bundles
  and extract technique ID, name, tactics list, URL, matrix tag, and
  deprecation status.
- Initially pinned to ATT&CK v16.1; updated to **ATT&CK v18.1** after
  discovering the prior version was missing recent techniques.
- Output path updated from
  `plugins/log_analysis/threat_intel_ingester/data/mitre_techniques.json` to
  `framework/reference_data/mitre_techniques.json` when the lookup was
  promoted to a shared framework module.
- Produces 774 techniques (691 Enterprise + 83 ICS).

---

### `framework/reference_data/mitre_attack.py` — Shared MITRE Module (New)

**Purpose:** Central Python module providing MITRE ATT&CK technique data to
all Event Mill plugins and framework code.

**Public API:**
- `get_mitre_db() → dict[str, dict]` — Loads the compact technique lookup from
  `mitre_techniques.json`. Cached after first call (module-level singleton).
  Returns empty dict with a warning if the data file hasn't been built yet.
- `validate_technique_id(tid) → bool` — Returns True if the technique ID
  exists in the official ATT&CK matrix.
- `enrich_technique(tid) → dict` — Returns metadata (name, tactics, URL) for
  a technique ID, or empty dict if not found.
- `technique_count() → int` — Returns the number of loaded techniques.
- `_reset()` — Test-only function to clear the cached database.

**Design decisions:**
- Lazy-loaded singleton avoids startup cost when MITRE data isn't needed.
- Logger: `eventmill.reference_data.mitre` (distinct from plugin loggers).
- Graceful degradation: missing data file → empty dict + warning, not an error.

---

### `framework/reference_data/__init__.py` — Package Init (New)

- Exports `get_mitre_db`, `validate_technique_id`, `enrich_technique` for
  convenient imports: `from framework.reference_data import get_mitre_db`.

---

### `framework/reference_data/README.md` — Updated Documentation

- Replaced placeholder content listing files that didn't exist yet
  (`mitre_attack_enterprise.json`, `attack_chain_patterns.json`) with accurate
  descriptions of the current contents.
- Added two usage patterns: `context.reference_data.get("mitre_techniques")`
  for plugin protocol access, and direct import for any Python code.
- Added one-time setup instructions for `build_mitre_lookup.py`.

---

### `framework/cli/shell.py` — ReferenceDataView Wiring

**Problem:** `ReferenceDataView` was created empty (`ReferenceDataView()`) for
every tool execution, making `context.reference_data` useless.

**Fix:**
- Added import: `from ..reference_data.mitre_attack import get_mitre_db`.
- Changed `ReferenceDataView()` to
  `ReferenceDataView({"mitre_techniques": get_mitre_db()})` so all plugins
  can access the MITRE database via `context.reference_data.get("mitre_techniques")`.

---

### `plugins/log_analysis/threat_intel_ingester/tool.py` — Reconciliation, Validation & Diagnostics

This file received the most changes, organized into four functional areas:

#### A. MITRE Reconciliation (`_reconcile_mitre_mappings`)

**Purpose:** Post-process LLM-generated MITRE mappings using the local ATT&CK
database to fix gaps the LLM commonly leaves.

**Three-step process:**

1. **Backfill** (Step 1) — Technique IDs referenced in `attack_graph`
   paths/`leads_to` but missing from `mitre_mappings` are added with metadata
   from the local lookup. Each backfill is logged:
   ```
   [RECONCILE] Backfilled technique T1003.006 (DCSync, tactic=Credential Access)
   from attack_graph path 'ecrime-ransomware' | local_lookup=hit
   ```

2. **Enrich** (Step 2) — Entries with empty `technique_name` or `tactic` are
   filled from the local lookup. Common when the LLM returns IOC-derived entries
   with a technique ID but no metadata. Each enrichment is logged:
   ```
   [RECONCILE] Enriched T1190: name='Exploit Public-Facing Application',
   tactic='Initial Access' | from local MITRE lookup
   ```

3. **Validate** (Step 3) — Every technique ID is checked against the local
   ATT&CK database:
   - Found → `"mitre_validated": true`
   - Not found → `"mitre_validated": false`, technique name annotated with
     `(non-ATT&CK ID)`, warning logged:
     ```
     [RECONCILE] Unvalidated technique T1655 (Help-Desk Fraud (non-ATT&CK ID))
     — not found in ATT&CK v18.1 (DB has 774 techniques).
     Keeping entry but marking as non-ATT&CK.
     ```

**Reconciliation summary logged at end:**
```
[RECONCILE] Summary: 2 backfilled, 3 enriched, 1 unvalidated,
21 total mitre_mappings (local DB has 774 techniques)
```

**Design decision — why mark instead of remove:** LLM-hallucinated technique
IDs (e.g., T1655 "Help-Desk Fraud" from the CrowdStrike Scattered Spider
report) often describe real adversary behaviors that ATT&CK hasn't catalogued.
Removing them loses that intelligence. Marking them lets analysts see both the
inferred behavior and the fact that the ID is non-standard.

#### B. Local MITRE Loader Extraction

- Removed the 40-line `_get_mitre_db()` function, `_MITRE_DATA_FILE` constant,
  and `_MITRE_TECHNIQUE_DB` module-level variable.
- Replaced with a single import:
  `from framework.reference_data.mitre_attack import get_mitre_db as _get_mitre_db`
- All call sites (`_reconcile_mitre_mappings`, enrichment steps) unchanged.

#### C. LLM Activity Logging Fixes

**Problem 1 — Pre-truncation hid actual response length:**

Both `log_llm_interaction` calls (native PDF at line 884, chunked at line 1045)
were passing `response_text[:500]` instead of the full response. Since
`log_llm_interaction` computes `response_length = len(response_text)`, the GCP
activity log always showed `response_length: 500` (or less) regardless of
whether the LLM returned 500 chars or 50,000 chars. This made it impossible
to diagnose truncated responses from the activity log alone.

**Fix:** Removed `[:500]` from both calls. `log_llm_interaction` already
truncates the preview internally (line 326-328 of `structured.py`), so the
preview field is still bounded at 500 chars, but `response_length` now reports
the true response size.

**Problem 2 — JSON parse failures invisible in GCP activity log:**

When `_parse_llm_json` returned `None` (unparseable response), the diagnostic
warning went to logger `eventmill.plugin.threat_intel_ingester` — a different
log stream than the `eventmill.activity` log visible in GCP Cloud Logging.
Operators filtering on `logName: eventmill-activity` saw the LLM call succeed
but had no record of the subsequent parse failure.

**Fix:** Added a second `log_llm_interaction` call in the native PDF parse
failure path with:
- `prompt="[ti_ingester native_pdf] JSON_PARSE_FAILED"`
- `error=f"JSON parse failed on {len(response)}-char response. first_100=..."`
- Full response text passed for accurate `response_length`

This creates a second activity log entry that's clearly marked as a failure,
making the parse failure visible without checking the plugin log.

#### D. ToolResult Completeness

**Problem 1 — `attack_graph` missing from ToolResult:**

The `attack_graph` was written to the artifact file (line 1218) but was not
included in the `ToolResult.result` dict returned to the CLI. This meant:
- `summarize_for_llm` could never display attack graph info (line 1332-1339
  always got `{}` from `r.get("attack_graph", {})`)
- `_auto_persist_result` would lose the attack graph if it triggered
- Downstream consumers of the ToolResult had no access to attack graph data

**Fix:** Added `"attack_graph": attack_graph` to the ToolResult's `result`
dict alongside `iocs` and `mitre_mappings`.

**Problem 2 — No indication of regex-only fallback:**

When the LLM failed and the tool fell back to regex-only IOC extraction, the
CLI showed `✓ Completed successfully` with a generic summary. There was no
visible indication that the results were degraded.

**Fix:**
- Added `ingestion_mode` variable: set to `"llm"` by default, changed to
  `"regex_only"` when entering the fallback path.
- Added `"ingestion_mode"` to the `summary` dict in ToolResult.
- Added a check in `summarize_for_llm`: when `ingestion_mode == "regex_only"`,
  appends a warning:
  ```
  WARNING: LLM analysis failed — results are regex-only
  (low confidence, no MITRE mapping, no attack graph).
  Check logs for LLM failure details.
  ```

---

### `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json` — Schema Update

- Added `mitre_validated` boolean field to the `mitre_mappings` item schema
  with description explaining that `false` indicates an LLM-generated ID not
  found in the official ATT&CK matrix.

---

### `plugins/log_analysis/threat_intel_ingester/README.md` — Documentation Updates

- **Prerequisites section:** Added step 3 documenting the one-time
  `build_mitre_lookup.py` setup, what it downloads, where it writes, and what
  the plugin uses it for (enrich, backfill, validate).
- **Reference Data Overrides:** Updated to point to
  `framework/reference_data/mitre_techniques.json` and the shared module.
- **Chunked text extraction:** Corrected stale chunk size reference from
  ~3500 to ~6000 characters.

---

### `scripts/verify_mitre_lookup.py` — Verification Script (New)

- Quick-check script that validates a list of technique IDs from a CrowdStrike
  report against the local MITRE database.
- Used during development to confirm T1655 ("Help-Desk Fraud") was not in
  ATT&CK v18.1 (confirmed as LLM hallucination).
- Updated DB path from plugin `data/` to `framework/reference_data/`.

---

## Root Cause Analysis — Missing MITRE Mappings in v2 Output

The investigation that prompted these changes centered on why
`crowdstrikegeminiv2.json` contained only regex-extracted IOCs with no MITRE
mappings or attack graph, while `crowdstrikegemini.json` (same PDF) had full
LLM-enriched output.

**Finding:** The code changes (MITRE lookup + reconciliation) were **not** the
cause. All reconciliation logic runs downstream of the LLM calls and cannot
affect whether the LLM succeeds. The v2 run's LLM either timed out, hit a
rate limit, or returned an unparseable response, triggering the regex-only
fallback.

**Contributing factor — logging gap:** The pre-truncation bug
(`response_text[:500]`) made the GCP activity log report `response_length: 500`
for every run, masking whether the response was genuinely truncated or full-size.
After fixing this, the subsequent run showed `response_length: 18060` — a
healthy full response confirming the v2 failure was transient.

**Verified:** A third test run (`crowdstrikegeminiv3.json`) produced complete
output with 16 CVE IOCs, 21 MITRE mappings (all `mitre_validated: true`), and
4 attack graph paths with convergence at T1078 (Valid Accounts).

---

## File Movement

| From | To | Reason |
|------|----|--------|
| `plugins/log_analysis/threat_intel_ingester/data/mitre_techniques.json` | `framework/reference_data/mitre_techniques.json` | Shared across plugins |

---

## Session 2 — Multi-Role Tactic Mapping Refactor

**Date:** 2026-04-18 (continued)
**Primary Files Modified:** `plugins/log_analysis/threat_intel_ingester/tool.py`, `plugins/threat_modeling/attack_path_visualizer/tool.py`
**Supporting Files:** `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json`, `plugins/log_analysis/threat_intel_ingester/README.md`, `plugins/log_analysis/threat_intel_ingester/examples/response.example.json`, both plugin `tests/test_contract.py` files

### Problem

The `mitre_mappings` array used `technique_id` as an implicit identity key —
each technique could appear at most once. When an LLM reported the same
technique serving different tactical roles in different attack paths (e.g.,
T1078 "Valid Accounts" as both "Initial Access" and "Persistence"), the
reconciler flattened to `tactics[0]` and discarded the per-path context.
The visualizer then rendered a single node, losing the multi-role insight.

### Changes

#### A. `_merge_llm_chunk_results()` — Dedup Key Change

- Changed dedup key from `technique_id` alone to `(technique_id, tactic)`.
- Two chunks can now each contribute a T1078 entry with different tactics and
  both survive the merge.

#### B. `_reconcile_mitre_mappings()` — Full Rewrite

Identity key changed to `(technique_id, tactic)`. Three-step process updated:

1. **Backfill** — Scans all `(tid, tactic)` pairs from attack graph steps.
   Existing exact matches get `context_paths` populated. Empty-tactic entries
   are promoted when a graph step provides the tactic. New `(tid, tactic)`
   pairs are created as backfill entries.
2. **Enrich** — Same as before, but logs a warning when a technique has
   multiple valid tactics and no graph context to disambiguate.
3. **Validate** — Now also checks the assigned tactic against the technique's
   allowed tactics list, logging warnings for mismatches that may indicate
   LLM hallucinations. Summary line includes tactic mismatch count.

New fields on mapping entries:
- `context_paths: list[str]` — attack graph path IDs where this `(tid, tactic)`
  pair appears.

#### C. LLM Prompt Update (Section 4)

- Added explicit instruction that the same technique ID can appear multiple
  times in `additional_mitre_techniques` with different tactics when it serves
  different roles — "This is expected, not a duplication error."
- Updated JSON response format example with T1078 appearing twice (Initial
  Access + Persistence) to demonstrate the expected pattern.

#### D. `execute()` Summary — `unique_technique_count`

- Added `unique_technique_count` (count of distinct `technique_id` values)
  alongside the existing `mitre_technique_count` (total role entries).

#### E. `summarize_for_llm()` — Multi-Role Display

- When `unique_technique_count != mitre_technique_count`, the summary reads:
  `"Mapped to 5 unique techniques across 7 tactical roles: T1078 (Initial Access, Persistence), ..."`
- When counts match, the standard format is preserved:
  `"Mapped to 5 MITRE techniques: T1078 (Valid Accounts), ..."`

#### F. `attack_path_visualizer/tool.py` — Composite Node Keys

- New helper `_node_key(tid, tactic) -> str` produces composite keys like
  `T1078|initial-access` so the same technique with different tactics becomes
  distinct DAG nodes.
- `_build_dag_from_attack_graph()` rewritten to:
  - Build metadata lookup keyed by `(technique_id, tactic)` with fallback by
    `technique_id` alone.
  - Build per-path step mapping for `leads_to` edge resolution.
  - Create nodes keyed by composite `tid|tactic-slug`.
  - Resolve `leads_to` targets within per-path context to connect to the
    correct tactic-specific node.
- `_render_mermaid_dag()` updated:
  - Node labels use `node.technique_id` instead of composite key.
  - Convergence/branch matching uses `node.technique_id` (plain IDs from LLM);
    entry/exit matching uses composite keys (computed by builder).
  - Convergence legend searches by `node.technique_id`.
- `_render_ascii_dag()` updated with same fixes.

#### G. Em-Dash Encoding Fix

- Replaced Unicode em-dash (`\u2014`) with ASCII ` - ` in Mermaid labels,
  ASCII header, and path legend lines. Prevents mojibake (`â€"`) when output
  is decoded as CP1252 on Windows terminals.

#### H. Schema & Documentation

- `output.schema.json`:
  - `mitre_mappings` description updated to document `(technique_id, tactic)` identity key.
  - Added `context_paths` property definition.
  - Added `unique_technique_count` to summary properties.
- `README.md`:
  - Added "Multi-Role Tactic Mappings" subsection under Prerequisites.
  - Added tactic validation bullet point.
  - Updated `summarize_for_llm()` example output.
- `response.example.json`:
  - Added `context_paths` to two entries.
  - Added `unique_technique_count` to summary.

#### I. New Contract Tests

**threat_intel_ingester** (9 new tests):
- `TestMergeMultiRole` — same tid with different tactics preserved; exact
  duplicates deduplicated.
- `TestReconcileMultiRole` — context_paths populated; new tactic backfilled;
  empty tactic promoted; leads_to orphan backfilled.
- `TestSummarizeMultiRole` — multi-role shows both counts; single-role shows
  standard format.

**attack_path_visualizer** (6 new tests):
- `TestMultiRoleDAG` — distinct nodes for same technique; total node count;
  both tactic labels in Mermaid output; both in ASCII; convergence styling
  by technique_id; `_node_key` helper correctness.

---

## Session 3 — Kill-Chain Tactic Progression Fix

**Date:** 2026-04-18 (continued)
**Primary File Modified:** `plugins/log_analysis/threat_intel_ingester/tool.py`
**Supporting File:** `plugins/log_analysis/threat_intel_ingester/tests/test_contract.py`

### Problem

Despite the multi-role refactor (Session 2), T1078.004 still appeared with
tactic "Initial Access" in all attack paths. Root cause: the **LLM itself**
assigned "Initial Access" for T1078.004 in every attack_graph step, even
when the technique appeared at step 3 after credential theft. The reconciler
correctly preserved the LLM's (wrong) tactic, resulting in a single merged
entry instead of the expected multi-role split.

### Fix: Two-Layer Defense

#### A. `TACTIC_ORDER` + `ENTRY_ONLY_TACTICS` Constants

- Added 14-entry `TACTIC_ORDER` dict mapping each MITRE tactic to its
  kill-chain ordinal (Reconnaissance=1 through Impact=14).
- Added `ENTRY_ONLY_TACTICS` set: `{Reconnaissance, Resource Development,
  Initial Access}` — tactics that should only appear at the first step of
  a path.

#### B. `_fix_tactic_progression()` — Reconciler Step 0

New function called at the start of `_reconcile_mitre_mappings`, before
building the `(tid, tactic)` index. For each attack path:

1. Skips step 0 (first step is allowed any tactic).
2. For steps 1+, if the assigned tactic is in `ENTRY_ONLY_TACTICS`:
   - Looks up the technique's valid tactics from the MITRE database.
   - Filters out entry-only tactics, keeping alternatives.
   - Picks the alternative with the highest kill-chain ordinal.
   - Reassigns the step's tactic and logs the change.
3. If no alternatives exist (all valid tactics are entry-only), keeps the
   original tactic unchanged.

For T1078.004 at step 2 of aitm-cloud-compromise:
- "Initial Access" is entry-only → filter it out.
- Remaining: Defense Evasion (7), Privilege Escalation (6), Persistence (5).
- Highest ordinal: **Defense Evasion** (7).
- The subsequent backfill creates two distinct `(T1078.004, Initial Access)`
  and `(T1078.004, Defense Evasion)` entries with separate `context_paths`.

#### C. Multi-Shot LLM Prompt Enhancement (Section 5)

Added a `CRITICAL — TACTIC ASSIGNMENT IN ATTACK PATHS` block with:
- Explicit rule: "Initial Access should only appear at the FIRST step."
- List of common multi-tactic techniques with their valid tactics.
- Three concrete examples showing T1078 reuse across paths with different
  tactical roles:
  - As entry point → Initial Access
  - After credential theft → Persistence
  - At two stages in one path → Initial Access then Privilege Escalation

#### D. New Contract Tests (5 tests)

- `TestTacticProgression`:
  - Reassigns "Initial Access" at step 2 → Defense Evasion
  - Preserves "Initial Access" at step 0
  - Leaves non-entry tactic (Persistence) untouched
  - Keeps entry tactic when no alternatives exist
  - End-to-end reconcile splits T1078.004 into two distinct role entries

---

## Test Results

304 tests passing (237 plugin + 67 framework), 0 failures.

---

## What's Next

- Re-run the CrowdStrike report to verify T1078.004 now splits into
  multi-role entries with the code-level fix active.
- Monitor production runs for tactic mismatch warnings.
- Consider adding `context_paths` filtering to `attack_path_visualizer`
  to render per-path subgraphs on demand.

---

## Session 4 — Artifact Persistence, Export Pipeline & ASCII Rewrite

**Date:** 2026-04-18 (continued)
**Primary Files Modified:** `plugins/threat_modeling/attack_path_visualizer/tool.py`, `framework/cli/shell.py`
**Supporting Files:** `plugins/threat_modeling/attack_path_visualizer/tests/test_contract.py`

### Problem 1 — Visualizer output not written to disk

The `attack_path_visualizer` rendered Mermaid and ASCII output as in-memory
strings returned inside `ToolResult.result["visualization"]`.  The only way
to get the Mermaid code into a file was to copy-paste from the CLI summary.
This was a significant usability gap:

- Analysts couldn't open `.mmd` files directly in VS Code Mermaid Preview
  or paste into mermaid.live without manual extraction.
- The `artifacts` shell command never listed visualizer output because no
  artifact was registered.
- The `export` command couldn't upload visualizer files to the common
  storage bucket because there was nothing to export.

### Fix A — `_render_mermaid_dag()` return type split

Refactored `_render_mermaid_dag()` to return a `(raw_mermaid, markdown)` tuple:

- **`raw_mermaid`** — Pure Mermaid code with no fences.  Path descriptions
  embedded as `%%` comments.  Directly consumable by Mermaid CLI, VS Code
  Mermaid Preview, or `mermaid.live`.  Written to `.mmd` files.
- **`markdown`** — Fenced `` ```mermaid `` block plus a human-readable path
  legend.  Renders in GitHub and VS Code markdown preview.  Written to `.md`
  files.

Replaced em-dash (`—`) with regular dash (` - `) in Mermaid `%%` comment
lines to avoid encoding issues when `.mmd` files are opened on Windows
terminals with CP1252 default encoding.

### Fix B — `execute()` writes files and declares `output_artifacts`

Updated the DAG rendering branch in `execute()` to write each format to
`workspace/artifacts/` with timestamped filenames and declare them in the
`ToolResult.output_artifacts` list:

| Format   | File                                      | Extension |
|----------|-------------------------------------------|-----------|
| ASCII    | `attack_path_ascii_<ts>.txt`              | `.txt`    |
| Mermaid  | `attack_path_mermaid_<ts>.mmd`            | `.mmd`    |
| Mermaid  | `attack_path_mermaid_<ts>.md`             | `.md`     |
| Compact  | `attack_path_compact_<ts>.txt`            | `.txt`    |
| Both     | ASCII `.txt` + Mermaid `.mmd` + `.md`     | all three |

Each entry carries `artifact_id`, `artifact_type` ("text"), and `file_path`.

### Fix C — `summarize_for_llm()` lists output files

Updated the summary to append the file paths from `output_artifacts` so the
CLI shows where files were saved:

```
Output files: workspace/artifacts/attack_path_mermaid_20260418_211840.mmd,
workspace/artifacts/attack_path_mermaid_20260418_211840.md.
```

### Problem 2 — Plugin `output_artifacts` not registered in session

Even after Fix B, the files wouldn't appear in the `artifacts` command.
Root cause: `do_run()` in `shell.py` had two artifact registration paths,
and neither handled `ToolResult.output_artifacts`:

1. **`context.register_artifact()`** — a callback tools can call during
   execution.  The visualizer doesn't use this (it writes its own files).
2. **`_auto_persist_result()`** — fallback that creates a single `.md` or
   `.json` artifact when **no** artifacts were registered during execution.
   This produced one combined file, losing the individual `.mmd`/`.md`
   separation.

Neither path iterated `result.output_artifacts` to register the files the
plugin explicitly declared.

### Fix D — `do_run()` output_artifacts registration

Added a loop in `do_run()` (lines 1069-1078) that runs immediately after a
successful tool execution and **before** the `_auto_persist_result` fallback
check:

```python
for oa in (result.output_artifacts or []):
    oa_path = Path(oa.get("file_path", ""))
    if oa_path.exists():
        self.session_manager.register_artifact(
            artifact_type=oa.get("artifact_type", "text"),
            file_path=str(oa_path),
            source_tool=tool_name,
            metadata={"plugin_artifact_id": oa.get("artifact_id", "")},
        )
```

Because these artifacts are now registered before the
`_artifacts_after - _artifacts_before` diff check, the auto-persist fallback
correctly sees that artifacts already exist and does not create a duplicate
combined file.

**Result:** `artifacts` command now lists each visualizer file individually.
`export <artifact_id>` works for any of them.

### Problem 3 — ASCII DAG unreadable and mis-ordered

The ASCII renderer (`_render_ascii_dag`) used `_toposort_layers()` to flatten
all paths into a single topological ordering, then packed unrelated nodes
from different paths side-by-side on the same row.  For a 4-path graph:

- Layer 2 showed T1059.007 (dprk), T1078 (scattered-spider), T1557
  (cozy-bear), T1574.002 (china-nexus) in four adjacent boxes.
- Connector arrows (`│ ▼`) only connected visually to the first column.
- No way to trace which chain belonged to which path.
- Ordering didn't match the Mermaid view, which separated paths visually.

### Fix E — Per-path vertical chain ASCII renderer

Rewrote `_render_ascii_dag()` to render each path as its own vertical chain:

- **Path header** — double-line `═` separator with path name and description.
- **BFS walk** — starts from each path's entry node and follows `leads_to`
  edges only within nodes belonging to that path.  This preserves the
  kill-chain ordering per path.
- **Node boxes** — 64-char fixed width, showing `[technique_id] tactic`,
  technique name, and role tags (`▷ ENTRY`, `■ EXIT`, `◆ CONVERGE`).
- **Cross-references** — nodes appearing in multiple paths show
  `also in: <other-path-id>` so analysts can trace convergence without
  the visual confusion of the merged layout.
- **Connectors** — clean `│ ▼` between consecutive nodes in each chain.

Removed the side-by-side multi-column layout, the fork/merge arrow drawing
code, and the branch annotation logic that was producing misleading visuals.

### Test Updates

- `_render_mermaid_dag` call sites in `test_contract.py` updated to unpack
  the `(raw_mermaid, markdown)` tuple.
- New assertions: no em-dash in raw Mermaid output; raw form has no fences;
  markdown form has fences.
- ASCII tests still pass against the new per-path layout (same content, new
  structure).
- **311 tests passing** (244 plugin + 67 framework), 0 failures.

---

## Lessons Learned — Incomplete Design / Dead Ends

### 1. Diagrams were never written to the workspace

The original visualizer design treated Mermaid and ASCII output purely as
CLI display text — it lived only in `ToolResult.result["visualization"]`.
There was no file persistence, no artifact registration, and no export path.
This meant:

- An analyst running a 30-minute ingestion + visualization pipeline had to
  copy-paste the Mermaid code from the terminal to use it anywhere else.
- The `artifacts` and `export` shell commands — which were explicitly designed
  for this purpose — couldn't see visualizer output at all.
- The `_auto_persist_result` fallback did write *something*, but it was a
  single combined `.md` file containing whichever text field it found first,
  losing the `.mmd` / `.md` separation and the ASCII `.txt` entirely.

**Takeaway:** Any tool that produces files analysts need outside the CLI
should write them to `workspace/artifacts/` and declare them in
`output_artifacts`.  The `_auto_persist_result` fallback is a safety net for
tools that return structured data, not a substitute for intentional file
output.

### 2. `output_artifacts` on `ToolResult` was a dead letter

The `ToolResult` dataclass had an `output_artifacts` field, and the protocol
documentation described it as the way plugins declare produced files.  But
`do_run()` in the shell never read it.  The field existed on the object,
was populated by the plugin, and was silently ignored.  The only artifact
registration paths were:

- `context.register_artifact()` — a callback, not used by most plugins.
- `_auto_persist_result()` — a fallback that creates one file, ignoring
  `output_artifacts` entirely.

This is a classic case of designing an API surface (`output_artifacts`) but
never wiring it into the consumer (`do_run`).  The fix was 8 lines of code.

**Takeaway:** When adding a field to a protocol/result type, trace the
complete data flow from producer to consumer.  If nothing reads the field,
it doesn't exist from the user's perspective.

### 3. ASCII side-by-side layout was the wrong abstraction

The original ASCII renderer tried to mirror a general-purpose DAG layout:
topological layering with side-by-side nodes at each depth.  This works for
small graphs with clear fork/merge structure, but attack graphs typically
have 3-5 mostly independent paths that only share 1-2 convergence nodes.

The side-by-side layout made the graph *harder* to read, not easier:

- Unrelated nodes from different paths appeared adjacent, implying a
  relationship that didn't exist.
- Connector arrows only worked for the leftmost column; other columns had
  no visual connection to their predecessors.
- The Mermaid view rendered the same data clearly because its layout engine
  naturally separated disconnected subgraphs — the ASCII code tried to
  replicate this manually and failed.

**Takeaway:** Match the visualization to the data shape.  Attack paths are
essentially independent chains with occasional shared nodes.  Rendering them
as independent chains with cross-reference annotations is simpler to
implement and far easier to read than a unified topology grid.

### 4. Em-dash encoding breaks were silent

Mermaid `%%` comment lines used em-dash (`—`) from path descriptions
produced by the LLM.  These displayed correctly in the terminal and in
Markdown preview, but caused mojibake (`â€"`) when `.mmd` files were opened
in editors defaulting to CP1252.  This was only caught when inspecting the
raw `.mmd` file output — a scenario that didn't exist until files were
written to disk (see lesson 1).

**Takeaway:** Once output goes to files, encoding assumptions change.
Stick to ASCII-safe characters in machine-readable formats like `.mmd`.
