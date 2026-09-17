# Attack Path Detection Designer

Turns `adversary_path_projector` exports into a normalized, reviewable context
for every step of a projected attack path — one node per step, with a stable
identity, a JSON pointer and an origin for every field, and an explicit record
of anything the source documents disagree about.

Plan: `docs/specs/attack_path_detection_normalization.md`.
Producer shape it reads: `docs/specs/projector_export_shapes.md`.

**Stage N1 is implemented.** Adapters, the three identities, the node
occurrence key, a deterministic `draft_id`, the union merge and
`provenance_by_field`. No LLM, no network, no flow map.

## Actions

| Action | Status | What it does |
|---|---|---|
| `validate_input` | implemented | Normalizes the supplied sources and returns the node inventory, identities, pair decision and every field conflict. Writes nothing. |
| `normalize_paths` | planned, stage N4 | The same normalization, persisted as a `detection_context_pack` artifact. |
| `generate_detections` | planned | Reasons over a pack to draft detection guidance. Heavy tier. |

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

- No flow-map join, no control catalogue resolution, no mitigation names, no
  completeness grade — **stage N3**.
- No artifact, no CLI `show`/`export` — **stage N4**.
- No `DS####` data components: no local ATT&CK reference carries them, so any
  that appeared would be invented.
- No re-deciding of the projector's own work. A reconciled tactic, a
  `state_check: gap` and a `notes` entry survive normalization untouched.

## Reading the provenance block

`provenance.model`, never `provenance.provider` — there is no `provider` key at
that level, and a normalizer looking for one records "no attribution" on an
export that carries full attribution. `engagement.model_attribution_present`
distinguishes *key absent* from *value null*. Similarly `actor_attack_id`, not
`actor_attck_id`.

## Fixtures

`tests/fixtures/` holds copies of four real export pairs, all on one code
revision, all projected against flow maps in this repository. Copies, not
builders: a builder re-derives the fixture from the same assumptions the
normalizer encodes, so it cannot catch a misreading of a real export.

Two properties no current fixture has, covered synthetically in the tests and
noted so nobody assumes they are covered by real data: a within-path
`(technique, component)` repeat, and a document with no `provenance` block.

## Layout note

`normalization.py` is loaded by file location from `tool.py`, not imported.
The loader imports a plugin under a flat module name with no package, so
neither a relative import nor a bare `import normalization` can find a sibling.
The tests load it the same way.
