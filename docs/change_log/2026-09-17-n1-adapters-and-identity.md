# N1: adapters, three identities and the union merge

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** code. New plugin `plugins/threat_modeling/attack_path_detection_designer/`
— `normalization.py` (the N1 library), `tool.py`, `manifest.json`, two schemas,
a README, four export pairs copied under `tests/fixtures/`, and 66 tests.
**Status:** N1 complete against its acceptance gate. Suite **1523 → 1589**.

## The gate, and that it passes

> All four fixtures normalize graph-only and seed-only to identical ordered
> node keys (9, 11, 10, 13 — 43 in all).

It does, and `draft_id` agrees across all three call shapes as well, which is
the stronger property the determinism rule actually needs. Node keys are
`(projection_identity, path_id, node_index)`; `draft_id` is a digest of that
triple alone, so it cannot drift with which document supplied a node.

All four pairs join `verified` on `run_id` with **0 field conflicts** across 43
nodes. Every field on every node carries an origin (`graph`, `seed`,
`pair_agreed` or `derived`), the document it came from, and a JSON pointer into
that document — 1,419 provenance entries in total, of which 645 are
`pair_agreed`.

## Three decisions taken while building, all visible in the code

**1. The seed's `transition` cannot be trusted over the graph's, and its
difference is not a conflict.** This was already the plan (§4.3 rule 3a, added
earlier today), and implementation confirmed why it had to be: the prose form
`"flow f4: partner_api -> event_bus (kafka, authenticated)"` has nowhere to put
`crosses_boundary`, so an intra-zone flow and a boundary crossing render
identically. `canonical_transition` parses both forms into one shape, marks the
seed's `evidence: text`, leaves `crosses_boundary: None` rather than guessing
`False`, and `transitions_agree` compares only the fields the prose can carry.
Comparing the two forms naively yields a conflict on all 26 non-null
transitions.

**2. A content conflict blocks `verified` without rewriting the provenance
status.** §4.3 rule 3 says a mismatch "blocks the pair join from being reported
as verified". Provenance and content are different questions — the `run_id`
really did match — so the result carries both: `provenance_status` stays
`verified` and a separate `verified: false` plus a `PAIR_CONTENT_CONFLICT`
warning records that the content disagreed. Collapsing them would have lost the
distinction between "these documents are from different runs" and "these
documents are from one run and disagree".

**3. A refused pair is not an error.** It processes the primary source alone
and reports the refusal, because half a join is worse than none. Four
refusal cases are implemented and tested: differing `run_id`, one document with
provenance and one without, two documents of the same role, and derived
identities that differ.

## Where the code lives, and the import it forced

Decision 7 put the library inside the plugin. That collides with how plugins
load: `PluginLoader` imports `tool.py` under a flat module name
(`eventmill_plugin_<pillar>_<tool>`) with no package, so `from .normalization
import …` has no parent and `import normalization` is not on the path.

`tool.py` therefore loads its sibling by file location, through a small
`_load_sibling` helper — the same technique every plugin's tests already use to
load `tool.py` itself. It works identically under the loader and under pytest.
This is the concrete cost of keeping the library plugin-local; it is three
lines and it is documented where it happens.

## The plugin ships with one working action, not zero

`validate_input` — deterministic, writes nothing, reports the inventory,
identities, pair decision and conflicts. The designer plan already anticipated
it ("a deterministic `validate_input` action can share normalization and report
expected node count without calling an LLM").

The alternative was a manifest-less directory, which makes `discover_all()` log
a warning for it on every startup, or a manifest whose every action is planned,
which puts a tool in the catalog that cannot do anything. `normalize_paths` and
`generate_detections` are named in `PLANNED_ACTIONS` so `validate_inputs` can
say they are planned rather than unknown — the projector's own convention for
`normalize_flow_map`.

`safe_for_auto_invoke` is **false** per decision 7, `model_tier: none` and
`requires_llm: false` for now; the generation stage flips the latter two and
must leave the first alone.

## Fixtures are committed, and what they do not cover

The four export pairs are copied into `tests/fixtures/` (264 KB). Decision 6
permits this: every pair binds to a flow map already in the repository, so no
unconfirmed application name enters git. Copies, not builders.

Two properties have **no real subject** and are covered synthetically, with the
absence asserted so it cannot be forgotten:

- **A within-path `(technique, component)` repeat.** The test first asserts no
  fixture contains one, then derives a case from the Claims Portal fixture by
  relabelling step 4 to duplicate step 1, and requires both nodes to survive
  with distinct `node_index` and `draft_id` **and no warning** — a repeated
  pair is legitimate modelling.
- **A document with no `provenance`.** Built by deleting the key from a copy.
  Asserts the derived `projection_identity` is equal across graph and seed,
  that the join is refused without `accept_unverified_pair`, and that it is
  recorded `asserted_by_operator` rather than upgraded to `verified` when the
  flag is passed.

## Verified

`pytest plugins/threat_modeling/attack_path_detection_designer` — 66 passed.
Full suite `pytest -q` — **1589 passed**, up from 1523, nothing broken.
`scripts/validate_manifests.py` reports the new manifest **✓ valid**; the
pre-existing 15 `stability: stable` errors are unchanged and untouched.
The plugin was also loaded through the real `PluginLoader` and executed end to
end, to confirm the sibling import works outside pytest.

Not run: `ruff`, `black` and `mypy` are **not installed in this environment**,
so the code was written to the conventions and checked for line length by hand
(no line over 88 characters in any new file) rather than verified by the tools.

## Still open

N2's designer-side legacy handling, N3's enrichment and grading, N4's action
and artifact, N5's `normalize_flow_map`. Also unresolved and now visible in
code: the run record is not read at all, so `STATE_GAP`, `TACTIC_CORRECTED`,
`HOP_NOT_DECLARED` and `LATE_INITIAL_ACCESS` findings are not yet joined to
nodes — they key only on `<path_id>.steps[<n>]`, and one of the four pairs has
no run record, so it can never be a required input.
