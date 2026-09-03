# Change Log — Deterministic tactic correction and analyst guidance

**Date:** 2026-09-03
**Primary File Modified:** `plugins/log_analysis/threat_intel_ingester/tool.py`
**Supporting Files:** `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json`,
`plugins/log_analysis/threat_intel_ingester/README.md`,
`plugins/threat_modeling/attack_path_visualizer/tool.py`,
`plugins/threat_modeling/attack_path_visualizer/README.md`, tests for both plugins

---

## Problem

Ingesting the 2026 CrowdStrike Global Threat Report produced three
`[RECONCILE] Tactic mismatch` warnings, each listing the tactics ATT&CK
allows and saying "keeping LLM assignment, flagged in output". Nothing told
the user whether they had to act, or how. The three cases were in fact
different:

- T1578.002 labelled Stealth, ATT&CK allows only Defense Impairment.
- T1556 labelled Stealth, ATT&CK allows Defense Impairment / Persistence /
  Credential Access.
- T1490 labelled Defense Impairment, ATT&CK allows only Impact.

The first two are the LLM confusing the two v19 replacement tactics; the
third is a single-tactic technique. None of them needs a human decision.

## Changes

### Reconciler: `_normalize_tactics` replaces `_migrate_legacy_tactics`

Runs first, over attack-graph steps and mapping entries alike, and applies
three deterministic fixes in order (`_resolve_tactic`):

1. **legacy** — retired tactic resolved to the single successor the
   technique lists (unchanged behaviour).
2. **sibling** — the label is one of a replacement pair (Stealth / Defense
   Impairment, derived from `LEGACY_TACTIC_ALIASES`) and the technique
   allows exactly the other one.
3. **single** — the technique has exactly one valid tactic (633 of 794).

Corrected mapping entries record the original label in
`tactic_corrected_from`. Entries that collide after correction are merged.

### Validation: genuine mismatches carry the options

What remains flagged is only the case where a technique has several valid
tactics and the LLM chose none. The entry now also carries
`allowed_tactics`, and the warning reads "Tactic needs analyst review ...
confirm the role from the report or pick one of the allowed tactics".

### Summary and artifact

`summary.tactic_corrected_count` and `summary.tactic_mismatch_count` are
added to the result. `summarize_for_llm` prints a "Tactic review: N
corrected automatically" line and, when anything is unresolved, an
`ACTION:` line listing up to three entries with their allowed tactics and
pointing at the artifact fields and the visualizer marker.

### Visualizer

`DAGNode.tactic_mismatch` is populated from the mapping entry. Mermaid
labels gain a "tactic unconfirmed" line and ASCII boxes a `? TACTIC` tag,
with the legend updated. This replaces a README claim that was not backed
by code.

### Tests

Ingester: sibling swap (single- and multi-tactic technique), single-tactic
correction, graph steps corrected to match, ambiguous label flagged with
`allowed_tactics`, valid label untouched, summary wording. Visualizer:
unconfirmed marker in both renderers.
