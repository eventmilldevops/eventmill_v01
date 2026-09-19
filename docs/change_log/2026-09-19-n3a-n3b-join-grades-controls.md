# N3a and N3b: the flow-map join, the completeness grades, and controls

**Date:** 2026-09-19
**Branch:** `llm_5`
**Scope:** code and spec. `plugins/threat_modeling/attack_path_detection_designer/`
— `normalization.py` (enrichment, grading, control attachment), `tool.py`
(grade distribution in the result and the summary), `schemas/output.schema.json`,
16 tests. Spec `docs/specs/attack_path_detection_normalization.md` — §6 N3 row,
decisions 10 and 11, §9.
**Status:** built, following the 2026-09-19 N2 work in the same uncommitted
change. Suite **1635 → 1652**. No shell run and no LLM call; the operator will
test both N2 and this against real artifacts.

## What landed

**N3a — the join and the grades.** A node whose `component_id` resolves in the
supplied map gains `zone`, `exposure`, `technologies`, `authentication`,
`data_classification`, `crown_jewel` and `port`. `port` is on the map's flow,
never on a step's `transition`, so it is only reachable this way. Each field
carries origin `flow_map` and the map's lineage from N2, so an enriched field
always says which version of the estate it came from.

Every node then gets a `context_completeness` grade (§5) and, when something is
missing, `telemetry_requirements[]` naming it. The acceptance gate holds on the
whole corpus, and was computed from the fixtures independently before the code
was written:

| Inputs | Distribution |
|---|---|
| pair + map | **38 `component_bound`, 5 `component_bound_partial`** |
| pair, no map | 43 `asset_named` |
| seed only | 43 `asset_text_only` |

The five partial nodes are `users` (no technologies), `front_door`
(`authentication: none`), `claims_db` and `doc_store` (twice). `authentication:
"none"` counts as absent: it is a declared absence, not a product to name.

**N3b — controls (decision 10).** Each node gets a `control_catalogue[]` and a
derived `monitoring_claim` of `none` / `partial` / `claimed`.

## Decisions this forced (spec 10 and 11)

Two things §1.4 and §1.4b assume turned out not to exist in the documents.

**Decision 10 — the catalogue has no join key.** The seed's
`security_controls[]` entries carry `control_id`, `name`,
`detection_capability` and a description like `"Protects CDN (cdn)."` — no
component id. The graph's `controls_in_play` carries a name and no id. With a
map the join is structural and exact: the component owns its controls, with
`detection_capability` and `mitre_mitigation_id` on each. Without one, a
`controls_in_play` name is matched against catalogue entries whose description
names *that node's* component id, and the result is marked `evidence: "text"`.

Name matching alone was rejected and there is a test for why: `WAF` protects
two different components in the Claims Portal map, so a name-only match would
hang one component's `detection_capability` on another component's node. A
control that matches no entry is left unattached rather than guessed — the same
rule the projector follows for an untagged control.

**Decision 11 — `tag_caveat` is not in the exports.** §1.4b says it reproduces
the projector's `control_tagging` counts; those live in the tool result and the
run record, and one of the four pairs has no run record, so they can never be a
required input. It will be computed from the supplied map in N3c, exactly as
the projector computes it (`tool.py:1824`), and is `null` with a stated reason
when no map is supplied. Recorded now because it decides how N3c is written.

## Two shapes worth knowing about

**A derived field has no document to point at.** `monitoring_claim`,
`context_completeness` and `telemetry_requirements` are computed, so their
`provenance_by_field` entry carries `basis` — the field names they were
computed from — in place of a pointer. The N1 rule that every field answers
"where did this value come from" is intact; what changed is that for three
fields the answer is a derivation rather than a file. The invariant test now
runs with and without a map and checks the enriched fields too.

**An unenriched field is absent, not null.** A node whose component is missing
from the map carries no `zone` key at all, and its grade stays `asset_named`.
That follows the existing convention — a seed-only node has no `component_id`
key — and keeps "the map had nothing for this" distinguishable from "the map
said null".

## What the map may not do

Rule 4 is enforced, not assumed: the map fills only fields no export carried. A
component renamed in an analyst's copy produces an `input_conflicts[]` entry
with the export value kept, and — deliberately — does **not** stop the pair
join being reported `verified`, because a map disagreeing with an export is not
the two export documents disagreeing with each other.

## Still outstanding in N3

- **N3c** — mitigation names from `mitre_relationships.json`,
  `mitigations_covered[]` (6 of 169 in this corpus), `mitigation_focus[]` (1–2
  narrowest by technique breadth, ties by M-ID) and `mitigation_coverage` with
  the decision 11 caveat.
- **N3d** — taxonomy reconciliation through
  `framework/reference_data/mitre_attack.py`, `tactic_status` /
  `technique_status`, and the assertion that `Stealth` survives and the three
  existing `TACTIC_CORRECTED` relabels are not re-decided.

## Verified, and not

- 129 plugin tests (112 → 129), full suite 1652 passing.
- The grade gate, the five partial components and the 6-of-169 mitigation
  coverage were computed directly from the fixtures and the three repository
  maps before any of this was written; the gate test recomputes all three
  distributions.
- **Not run in the shell or on Cloud Run.** The operator will test N2 and
  N3a/N3b against uploaded artifacts.
- `ruff`, `black` and `mypy` are not installed in this environment and have not
  run.
