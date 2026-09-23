# Attack Path Detection Designer

Turns `adversary_path_projector` exports into a normalized, reviewable context
for every step of a projected attack path — one node per step, with a stable
identity, a JSON pointer and an origin for every field, and an explicit record
of anything the source documents disagree about.

Plan: `docs/specs/attack_path_detection_normalization.md`.
Producer shape it reads: `docs/specs/projector_export_shapes.md`.

**Stages N1, N2 and N3 are implemented.** Adapters, the three identities, the
node occurrence key, a deterministic `draft_id`, the union merge and
`provenance_by_field` (N1); flow-map lineage and fit, and a closed code
catalogue (N2); the flow-map join and the five completeness grades (N3a);
controls per node and `monitoring_claim` (N3b); mitigation names, the focus
cut and the coverage ratio (N3c); taxonomy status against ATT&CK v19.2 (N3d).
The context pack's own schema is N4. No LLM, no network.

## Actions

| Action | Status | What it does |
|---|---|---|
| `validate_input` | implemented | Normalizes the supplied sources and returns the node inventory, identities, pair decision and every field conflict. Writes nothing. |
| `digest` | implemented | The same run, three readable lines per node. A troubleshooting aid for a person; the pack itself is machine-facing. |
| `normalize_paths` | planned, stage N4 | The same normalization, persisted as a `detection_context_pack` artifact. |
| `generate_detections` | implemented, **costs a heavy-tier call per batch** | Drafts one detection per node, batched by path. Returns `ok: false` with `GENERATION_INCOMPLETE` and the partial output whenever fewer valid drafts exist than nodes. |

## Inputs: artifacts first

Registered artifacts are the route (spec decision 8). The projector registers
its two exports; this tool consumes them by id, and its own result is
registered in turn.

```bash
# the normal route — a graph and a seed of the same run
run attack_path_detection_designer --artifact_ids art_e2697614,art_2df55952

# a single document
run attack_path_detection_designer --artifact_id art_e2697614

# file paths, for a local export that was never registered
run attack_path_detection_designer --sources ./path_graph.json,./scenario_seed.json
```

A path is a local convenience. It is not the handle that works in the
container, where an export is auto-exported to the common bucket and only the
registry knows where it landed. `file_path` and `path` are also accepted
because `do_run` injects both when it resolves a singular `artifact_id`.

An artifact that is registered but whose bytes are not readable here comes back
as `ARTIFACT_UNAVAILABLE` naming its `storage_uri` — on Cloud Run that is a
real state, and it is not the same thing as a missing file.

## Flow maps: recorded, never refused

A flow map is a working document. An analyst is expected to copy a generated
map, correct it from inside knowledge and track it in git, so the export's
`flow_map_sha256` is **lineage**, not an integrity check (spec decision 9):

```bash
run attack_path_detection_designer --artifact_ids art_e2697614,art_2df55952 \
    --flow_map_artifact_id art_5c01ffee
# or locally: --flow_map_path ./telemetry_saas_flow_map.json
```

| Export hash vs supplied map | `flow_map.lineage` | Effect |
|---|---|---|
| equal | `same_map` | none |
| different | `edited_map` | advisory `FLOW_MAP_EDITED`; re-project if topology or controls changed |
| absent | `unhashed` | advisory `FLOW_MAP_UNHASHED`; no operator flag needed |

The hash cannot tell an edited map from the wrong one, so fit is checked
directly: `FLOW_MAP_APPLICATION_MISMATCH` when the map names another
application, and `FLOW_MAP_COMPONENT_UNRESOLVED` for each node component the
map lacks — the one flow-map condition that withholds anything, and only from
that component's nodes. Reordering or reformatting a map does not change its
hash; any content change does.

A map is refused only when it is not a JSON flow map at all:
`FLOW_MAP_UNREADABLE` (a prose or Mermaid map is stage N5's job) or
`FLOW_MAP_NOT_OBJECT`.

What the map then contributes to a node is below.

## What a supplied map adds, and what it may not do

With a map, a node whose `component_id` resolves gains `zone`, `exposure`,
`technologies`, `authentication`, `data_classification`, `crown_jewel` and
`port` — `port` lives on the map's flow, not on a step's `transition`, so this
is the only way to reach it. Each carries origin `flow_map` and the map's
lineage.

The map **fills only what no export carried**. A component renamed in an
analyst's copy produces an `input_conflicts[]` entry with the export's value
kept, and does not affect whether the graph/seed pair is `verified` — that is a
statement about the two exports, not about the map.

A field the map had nothing for is **absent, not null**, as `component_id` is
on a seed-only node.

## Grades

`context_completeness` per node, and a distribution on the result:

| Inputs | Distribution on the four fixtures |
|---|---|
| pair + map | 38 `component_bound`, 5 `component_bound_partial` |
| pair, no map | 43 `asset_named` |
| seed only | 43 `asset_text_only` |

`authentication: "none"` counts as absent — a declared absence is not a product
to name — so `front_door` grades partial despite carrying technologies. A
partial node names what is missing in `telemetry_requirements[]`. A node whose
component is not in the map stays `asset_named` while the rest of the map is
still used.

## Controls on a node

`control_catalogue[]` per node, plus a derived `monitoring_claim` of `none`,
`partial` or `claimed`:

- **With a map** the join is structural — the component owns its controls, with
  `detection_capability`, `bypass_difficulty` and `mitre_mitigation_id`.
  Marked `evidence: "structured"`.
- **Without one** a `controls_in_play` name is matched against catalogue
  entries whose description names that node's component (`"Protects CDN
  (cdn)."`), and marked `evidence: "text"`. Name alone is not a key: `WAF`
  protects two components in the Claims Portal map. A control matching nothing
  is left unattached, never guessed.

`monitoring_claim` is a claim about what is watched, never coverage. Every
draft still starts at `catalogue_status: new_unchecked`.

## Mitigations, and what generation will be allowed to read

The export's `mitigations[]` and `uncovered_mitigations[]` are kept exactly as
they arrived — they are the provenance. Four derived fields sit beside them:

- `mitigation_names` — M-ID to name, looked up locally. An id the reference
  data lacks is reported, never named or ranked.
- `mitigations_covered[]` — the covered half. A tagged control exists on that
  component, so a draft there is a **tuning** case, not a gap case.
- `mitigation_focus[]` — the 1–2 **narrowest** uncovered mitigations by
  technique breadth, ties by M-ID. Breadth is a proxy for specificity, not for
  detectability: the cut narrows what a model is asked to reason about and
  never argues that a detection should exist. An empty cut is ordinary.
- `mitigation_coverage` — `{covered, total, unresolved, tag_caveat}`. Across
  the fixture corpus that is 6 covered of 169.

`tag_caveat` is the control-tagging count recomputed from the supplied map
(decision 11), because no export carries the projector's own counts. **With no
map it is null and carries `tag_caveat_reason`** — a bare null would read as
"every control is tagged", which is the misreading the caveat exists to stop.

## Taxonomy

`technique_status` and `tactic_status` per node, against ATT&CK v19.2 through
`framework/reference_data/mitre_attack.py`. Every node of the current corpus
reads `current` / `as_supplied`: the projector already reconciled, and this
stage records that rather than re-deciding it. `Stealth` must survive;
`Defense Evasion` must never come back.

A retired **technique** id is never rewritten — `technique_id_current` and
`technique_remap_basis` sit beside it, so a remap stays auditable. A **tactic**
is reconciled in place when the case differs or a retired name has exactly one
successor the technique uses, with `tactic_as_supplied` retained; anything
ambiguous keeps the export value and warns.

## Reading a run: `digest`

```bash
run attack_path_detection_designer --action digest \
    --artifact_ids art_e2697614,art_2df55952 --flow_map_artifact_id art_5c01ffee
```

```text
9 nodes, pair verified, 0 conflict(s), flow map same_map. component_bound 9.
scm-to-vault  1  T1059 Command and Scripting Interpreter  ci_runner
  component_bound | ubuntu/docker/github-actions-runner | monitoring none | state gap | multistep_access=true ?
  focus: M1033 Limit Software Installation (17), M1045 Code Signing (22)
```

The pack is ~187k characters on a 13-node pair and **58% of it is
`provenance_by_field`** — the audit trail that makes a draft defensible and
that nobody reads in bulk. The digest is how a person checks a run; the pack is
what the next stage consumes. A long corpus is cut on a node boundary with the
remainder stated, never mid-node.

## Grounding: the assessment tuple

Every node carries `assessment` — a **named** mapping, so adding an element
later cannot shift the meaning of the existing ones — and up to three
`procedure_evidence[]` entries with source ids, content hashes, and an explicit
note that the ATT&CK link is an index reference, not a recovered report
citation.

| Element | true means | Today's distribution |
|---|---|---|
| `actor_evidence` | the local release documents this actor using this technique, directly or via associated software | 43 of 43 — **true by construction**, since the projector only builds paths from techniques already mapped to the actor |
| `multistep_access` | access depends on something no earlier step establishes | 10 of 43, from nine inherited state gaps and one undeclared transition |

`access_source: model` is a **qualifier, not a trigger**. It is set on every
node of every fixture, so triggering on it made `multistep_access` true 43 of
43 — a constant rather than an assessment. A test asserts the 10/33 split so it
cannot quietly become constant again.

`actor_evidence` establishes the floor, never the ceiling: the judgment that
bites is technique against *target class*, which the local corpus cannot
settle, and which generation may set false with its own basis. The export's own
`actor_support` is never rewritten by either element.

## Telemetry and drafting

```bash
run attack_path_detection_designer --action generate_detections \
    --artifact_ids art_graph,art_seed --flow_map_artifact_id art_map
```

Each node carries `telemetry_candidates[]` from the shared library and a
`telemetry_readiness` of `stream_available`, `periodic_only` or
`none_declared` — **a separate axis from `context_completeness`**. A node can
be bound to the estate with nothing to look at. A `protocol: physical` hop
draws badge, door-alarm and CCTV sources instead of network ones.

Generation refuses, rather than trusting the model: a telemetry source that was
not offered for that node, any `DS####` identifier, `logsource.product` below
`component_bound`, a changed technique id, and any `missing_data_behaviour`
other than `insufficient_telemetry`. Coverage is a set comparison by
`draft_id`, so a duplicate plus an omission is incomplete rather than "nine
drafts".

**Weak evidence is never a filter.** A node whose `actor_evidence` is false, or
whose telemetry readiness is `none_declared`, is still drafted with the
weakness stated — attackers change tactics, and a path the projector produced
is still a path.

## Codes

Warnings, review flags and errors are closed sets (spec §4.4): `WARNING_CODES`
and `REVIEW_FLAG_CODES` in `normalization.py`, `ERROR_CODES` in `tool.py`.
Every warning carries a `severity` — `blocking` if the output omits or
downgrades something because of it, `advisory` otherwise — and the summary
reports the two separately. Add a code to the catalogue and the spec table
together; the tests hold them to each other.

## Why this plugin is not auto-invocable

`safe_for_auto_invoke` is **false**, and that is deliberate. Normalization
itself is free, deterministic and provider-less — it would qualify on its own.
But the flag is a **whole-plugin** manifest field with no per-action form, and
`generate_detections` lands in this same plugin because it must be able to
normalize a raw export too. One plugin, one flag, and the expensive action sets
it. Recorded as decision 7 in the spec; `adversary_path_projector` has the same
shape for the same reason.

So: the action is safe and free to run. The manifest does not say so, and
should not be read as saying so.

## What normalization actually guarantees

- **Graph-only, seed-only and a joined pair produce the same ordered node keys
  and the same `draft_id`s.** That is the acceptance gate, and it holds on all
  four fixture pairs (9, 11, 10, 13 — 43 nodes).
- **Identity is positional and per projection.** The key is
  `(projection_identity, path_id, node_index)`. `projection_identity` is
  `provenance.run_id` when present, otherwise a digest over run-invariant
  content so the two documents still agree. `draft_id` derives from the
  occurrence key alone, never from which document supplied the node.
- **Nothing is deduplicated.** No `(technique_id, component_id)` pair repeats
  within a path anywhere in the corpus, but three repeat *across* paths in the
  Claims Portal fixture, and `event_id` restarts at `AE-0001` in every
  scenario. Both shortcuts lose real nodes.
- **A pair is never half-joined.** Two documents join on an equal
  `provenance.run_id`; a differing one, or one document carrying provenance
  while the other does not, is refused and the primary source is processed
  alone. Two documents with no provenance join only on
  `accept_unverified_pair`, and are recorded `asserted_by_operator` — never
  upgraded to `verified`.
- **Two fields are canonicalized, not compared raw.** `state_check` (the graph
  splits it, the seed joins it on a U+2014 em dash) and `transition` (the graph
  carries an object, the seed prose). In both the graph wins and the seed's form
  is retained as `state_check_raw` / `transition_raw`. These are representation
  differences; treating them as conflicts would block every pair join.
- **`transition` carries a movement discriminator.** `entry`, `declared_flow`,
  `in_place` and `undeclared`. The last two are the same `null` in the export,
  told apart by whether the component changed; `undeclared` raises a review
  flag, `in_place` is ordinary and must not read as missing data.

## What it deliberately does not do

- No context pack schema or `metadata.kind` — **stage N4**. The shell already
  persists and registers a result, so N4 is about the pack's format.
- No artifact, no CLI `show`/`export` — **stage N4**.
- No `DS####` data components: no local ATT&CK reference carries them, so any
  that appeared would be invented.
- No re-deciding of the projector's own work. A reconciled tactic, a
  `state_check: gap` and a `notes` entry survive normalization untouched.

## Reading the provenance block

`provenance.model`, never `provenance.provider` — there is no `provider` key at
that level, and a normalizer looking for one records "no attribution" on an
export that carries full attribution. `engagement.projection_model_present`
distinguishes *key absent* from *value null*. Similarly `actor_attack_id`, not
`actor_attck_id`.

It surfaces as **`engagement.projection_model`**: the model that produced the
attack path, not the one that drafts detections — that is
`generation_model`, summarised from `calls[].model_used`. Both models appear in
one generation export, and while the field was called `model_attribution` a
reader took the projector's model for the drafting one, which is the confusion
attribution exists to prevent. `model_attribution` and
`model_attribution_present` are kept as aliases so an existing consumer is not
broken.

## Fixtures

`tests/fixtures/` holds copies of four real export pairs, all on one code
revision, all projected against flow maps in this repository. Copies, not
builders: a builder re-derives the fixture from the same assumptions the
normalizer encodes, so it cannot catch a misreading of a real export.

`tests/fixtures/flow_maps/` holds copies of the three repository maps those
runs were projected against, frozen so that an edit to the projector's
examples cannot break the test that holds this plugin's hash to the
projector's.

Two properties no current fixture has, covered synthetically in the tests and
noted so nobody assumes they are covered by real data: a within-path
`(technique, component)` repeat, and a document with no `provenance` block.

## Layout note

`normalization.py` is loaded by file location from `tool.py`, not imported.
The loader imports a plugin under a flat module name with no package, so
neither a relative import nor a bare `import normalization` can find a sibling.
The tests load it the same way.
