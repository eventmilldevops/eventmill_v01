# Closing the N1 contract before N1 is written

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** planning only. `docs/specs/attack_path_detection_normalization.md`
— §0 dating preamble, §1.1 corrected, §1.2 marked resolved, §3 identity and
engagement blocks, §4.1 provenance names, new §4.2a, §4.2 legacy and mixed-pair
rows, §4.3 rule 3a, §5 grades, §6 N1/N3 gates, §7 tests, §8 decision 5, §9.
No code changed, no tests run, no LLM call made.
**Status:** decided and recorded; N1 implements against this.

## Why now

Six issues surfaced from re-reading the four fixtures against the spec. Each
would have been encoded into N1's first test file and then defended as
intended behaviour, so they were reconciled while the cost is a document edit.
Two were outright self-contradictions: the node identity could not satisfy the
gate the same document sets, and the merge rule would have rejected all 58
nodes.

## 1. The provenance block was described under the wrong names

The §4.1 shape was written before the block was built; the built version
differs, and the spec has been corrected to match the export.

| Spec said | Export carries |
|---|---|
| `actor_attck_id` | `actor_attack_id` |
| `provider: {provider_id, model}` | `model: {provider, vendor, model_configured, model_served}` |
| — | `run_index` |

The dangerous one is the second: **there is no `provider` key at all**. A
normalizer written from the draft reads `provenance.provider`, gets nothing,
and records "no provider attribution" on `192507` and `022646`, which carry
full attribution. That is silent-wrong in the same shape as an empty
`EVENTMILL_BUCKET_PREFIX`. Normalization reads `model`, and must distinguish
key-absent from value-null. `model_configured` and `model_served` stay
separate so a served substitution remains visible.

## 2. `source_identity` could not satisfy its own N1 gate

§4.2 synthesized one `source_identity` from the SHA-256 of the canonical
document plus its filename, and the node key was
`(source_identity, path_id, node_index)`. The graph and the seed are different
documents with different filenames, so they hash differently — while the N1
gate requires graph-only and seed-only input to produce **the same** ordered
node keys. The gate could never pass on a legacy pair, and passed on a
verified pair only because `run_id` happened to be equal.

New §4.2a separates three things that were conflated:

- **`artifact_identity`** — per document. Hash plus filename plus role.
  Differs between graph and seed by design; used for pointers and provenance.
- **`projection_identity`** — per projection run. `provenance.run_id` when
  present, otherwise a digest over run-invariant content (actor,
  `actor_attack_id`, application, ordered path IDs, per-path ordered technique
  IDs and assets) that deliberately excludes filenames, timestamps and role.
  Graph-only and seed-only of the same run agree.
- **node occurrence** — `(projection_identity, path_id, node_index)`.

`draft_id` derives from the occurrence key alone, so it cannot drift with
which document supplied a node — which is what the §7 determinism test needs.
A derived `projection_identity` still yields `provenance_status: derived` and
still requires `--accept_unverified_pair`; equality of a derived value means
the documents describe the same projection, not that one call wrote both.

A row was also added for the mixed case the table omitted: one document with
provenance and one without is refused, because the single `run_id` has nothing
to be checked against.

## 3. `state_check` equality would have rejected all 58 nodes

§4.3 rule 3 required equality on `state_check`, which the two exports
represent differently. The graph splits it into `state_check` (`ok` | `gap`)
and `state_note`; the seed carries one combined string. The relation is exact:

```text
seed.state_check == graph.state_check                         if note empty
seed.state_check == graph.state_check + " — " + graph.state_note   otherwise
```

Checked over all four pairs: **58 of 58 match byte-for-byte, 0 conflicts.**
The note branch is exercised by exactly the **6** `state_check: gap` nodes
(2 in `165537`, 3 in `204815`, 0 in `192507`, 1 in `022646`); the other 52 are
the empty-note case.

Comparing raw strings yields 58 spurious conflicts and blocks every pair join.
Comparing only the leading token silently discards the note, which on the six
gap nodes is the whole continuity finding. New rule 3a canonicalizes to the
graph's two-field form, retains the seed's combined string as the raw value,
and records `pair_agreed` — representation differences, not conflicts.

The separator is U+2014 with a single space either side. The rule is
encoding-fragile, which is why `2026-09-17-fox-kitten-fixture.md` checked the
GCS round trip for it. A transport that cannot carry the em dash raises an
encoding warning, never six content conflicts.

## 4. A hash is not a binding

§5 let `component_bound` rest on "verified or operator-asserted flow map". A
provenance hash records which map *would* bind, not that any binding happened.
The grade now requires all three independently: the map was **supplied**, its
hash matched or was explicitly asserted, **and** the node's `component_id`
resolved in it. An export carrying `flow_map_sha256` but normalized without
the map is `asset_named`. Scenario-only input stays `asset_text_only`
regardless of accompanying provenance, because it has no `component_id` to
join on.

Added `component_bound_partial` for a component that binds but declares no
`technologies` or no `authentication`. It is a real case:
`examples/telemetry_saas_flow_map.json` has two such components, `alb` (also
`authentication: none`) and `artifact_reg`. Neither appears in the verified
fixtures, so the grade is currently unexercised and needs its own fixture.
Folding it into `component_bound` would let a draft name a product for a
component that declares none; folding it into `asset_named` would throw away a
verified zone and boundary.

## 5. §1.1's headline assertion did not match the fixture

§1.1 claimed `(technique_id, component_id)` repeats three times inside
`helpdesk-oracle-onprem`, and §7 claimed `T1078` and `T1552.001` each occur
three times there. Re-read from the file: `T1078` occurs **twice** (plus
`T1078.004`, a distinct ID), `T1552.001` **twice**, and **no
`(technique_id, component_id)` pair repeats within any path in any of the four
fixtures.**

Pairs do repeat *across* paths in `204815` — `T1068@entry_api` and
`T1552.001@entry_api` in two paths — so the fixture catches a global dedupe
but not a within-path one. The within-path rule is the stronger claim and the
reason `node_index` exists, and it had no test that would fail if violated.

§7 now carries a synthetic case: derive from `helpdesk-oracle-onprem` in the
test module and relabel step 8 from `T1552.001@oracle_int` to
`T1078@oracle_int`, duplicating step 6 exactly. Assert both occurrences
survive with distinct `node_index` and `draft_id`, and that **no warning
fires** — a repeated pair is legitimate modelling, not a defect. Derived in
code rather than stored, to avoid a near-duplicate 24-node file.

## 6. Historical statements now carry dates

Several present-tense claims became false when §4.1 landed and when the third
and fourth fixtures arrived. §0 now states that §§1.1-1.6 were written on
2026-09-16 against the first two pairs and that undated "both fixtures" means
those two. §1.2 is retitled to the past tense and marked resolved, with the
note that the two legacy pairs will never be joinable on `run_id`, so §4.2
stays required. §2, §6, §7 and §8 were restated over all four fixtures and 58
nodes.

## Contract tests added

Provenance field names read from the export, including that
`provenance.provider` is absent rather than null and that the old names fail
detectably; the three identities distinct on a verified pair and
`projection_identity` equal across graph-only and seed-only on a legacy pair;
`state_check` canonicalization at 58 matches, 0 conflicts, with the em-dash
mutation raising an encoding warning; five completeness grades including
`component_bound_partial` and the hash-without-map case; the corrected
fixture-2 counts; and the synthetic within-path repeat.

## Still open

N1 remains unwritten. Two decisions outside this document's scope are still
outstanding and both belong before code: **where `normalize_paths` lives**, as
`safe_for_auto_invoke` is a whole-plugin manifest field with no per-action
form, so one plugin cannot mark normalization auto-invocable while leaving
generation gated; and **whether the four export pairs are committed**, since
they live outside the repository and the two legacy ones name an application
and actors that have not been confirmed synthetic.
