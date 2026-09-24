# N3c and N3d: the mitigation focus cut, and taxonomy against v19.2

**Date:** 2026-09-20
**Branch:** `llm_5`
**Scope:** code and spec. `plugins/threat_modeling/attack_path_detection_designer/`
— `normalization.py` (mitigation resolution, focus cut, tag caveat, taxonomy
reconciliation), `tool.py` (two summary lines, two result keys),
`schemas/output.schema.json`, 16 tests. Spec §4.4 (four new codes).
**Status:** built. Suite **1652 → 1668**. **N3 is complete**; N4, the context
pack artifact, is next. No shell run for this slice.

## N3c — mitigations

Four derived fields per node, and the export's own lists left untouched:

- **`mitigation_names`** — M-ID to name from `mitre_relationships.json`. A
  local lookup, recorded with origin `reference_data` so a name can never be
  mistaken for something a model supplied.
- **`mitigations_covered[]`** — `mitigations` minus `uncovered_mitigations`,
  each with its name and technique breadth. The smaller, more informative
  half: a tagged control exists on that component, so a draft is a tuning case
  rather than a gap case.
- **`mitigation_focus[]`** — the one or two **narrowest** uncovered
  mitigations by `len(techniques)`, ties broken by M-ID ascending. The spec's
  worked example reproduces exactly: on `022646` / `web-exploit-to-db` step 1
  (`T1190`) the cut is M1016 *Vulnerability Scanning* (5) then M1048
  *Application Isolation and Sandboxing* (14), and M1026 (112) — the broadest
  uncovered mitigation on that node — is excluded.
- **`mitigation_coverage`** — `{covered, total, unresolved, tag_caveat}`.
  Corpus-wide this reads **6 covered of 169**, the figure measured before the
  code existed.

**Why the export lists are not rewritten.** They are the provenance, they cost
nothing, and §1.4b's decision is to narrow the *audience* rather than the data:
generation reads the focus, the covered half and the ratio; the pack keeps
everything. Rewriting `mitigations[]` into named objects would also destroy the
graph-origin `provenance_by_field` pointer that makes the list auditable.

**`tag_caveat` (decision 11)** is recomputed from the supplied map exactly as
the projector computes it — controls on the targeted components, and how many
carry a `mitre_mitigation_id`. On `022646` with the telemetry map: 8 controls,
7 tagged, `ci_runner` declaring none. With no map it is `null` **and** carries
`tag_caveat_reason`, because a silent null would read as "every control is
tagged", which is the exact misreading §1.4b exists to prevent.

An M-ID the reference data does not carry is reported in
`mitigation_coverage.unresolved` with an advisory `MITIGATION_UNRESOLVED`, and
is excluded from the ranking rather than ranked at an assumed breadth.

## N3d — taxonomy

`technique_status` (`current` / `retired_remapped` / `unresolved`) and
`tactic_status` (`as_supplied` / `reconciled` / `unresolved`) per node, through
`framework/reference_data/mitre_attack.py` — the one framework import this
plugin makes, and the way every plugin reaches ATT&CK.

**Across the whole corpus every node is `technique:current` and
`tactic:as_supplied`.** That is the expected result and the point of §1.6: the
projector already reconciled against v19.2, and normalization must not hand a
later model an opportunity to restore `Defense Evasion`. `Stealth` survives
untouched, and a test asserts no node anywhere carries the retired name.

**Nothing rewrites a technique id.** A retired id gains `technique_id_current`
and `technique_remap_basis` *beside* the export value, the way the seed's raw
forms sit beside the graph's. A remap therefore stays auditable and reversible,
and the pack always shows what the projector actually said. A tactic is
different: a case difference or a retired tactic with exactly one successor the
technique uses is reconciled in place, with `tactic_as_supplied` retained. An
ambiguous or unknown tactic keeps the export value and warns.

Four advisory codes were added to §4.4: `MITIGATION_UNRESOLVED`,
`TACTIC_UNRESOLVED`, `TECHNIQUE_RETIRED`, `TECHNIQUE_UNRESOLVED`. The
catalogue test caught their absence from the spec before this entry was
written, which is what it is for.

## Verified, and not

- 145 plugin tests (129 → 145), full suite 1668 passing.
- The spec's two independent figures both reproduce from code: the M1016/M1048
  focus cut, and 6 of 169 covered.
- Synthetic cases, because the corpus cannot supply them: a retired tactic
  (`Defense Evasion` on `T1078` → `Stealth`), a retired technique
  (`T1562.001` → `T1685`, curated), an unknown technique, an unknown M-ID, a
  lower-case tactic, and an all-broad node yielding an empty focus with no
  warning.
- The summary gained two lines and is 448 characters on a joined pair, well
  inside the 4000 budget.
- **Not run in the shell.** The operator's live test of N2/N3a/N3b on
  2026-09-20 predates this slice; test steps 7-10 also remain unrun.
- `ruff`, `black` and `mypy` are not installed in this environment.
