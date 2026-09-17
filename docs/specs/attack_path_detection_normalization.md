# Attack path normalization — completing the seam the detection designer sits on

Status: proposed, with §4.1 (the projector export `provenance` block) built and
unit-tested on 2026-09-16. Revises section 3 of
`docs/specs/attack_path_detection_designer.md`.
Date: 2026-09-16.

## 0. Which "phase 3" this addresses, and why both readings converge

Two pieces of planned work are called normalization in this thread:

- **§3 of the detection designer plan**, *Normalize node identity without
  losing context* — building `DetectionNodeContext` from an exported path
  graph or scenario seed.
- **`normalize_flow_map`**, the projector's own outstanding action
  (`plugins/threat_modeling/adversary_path_projector/tool.py:56`,
  `PLANNED_ACTIONS`; projector spec Phase 4).

They are the same seam seen from two ends, and this plan treats them as one
work item. The designer's §3 declares `technologies`, `authentication` and
`zone` on every node context. **Neither export carries any of those three
fields.** They exist only in the flow map, and the flow map is only a
dependable input once `normalize_flow_map` exists to produce a canonical one.
So the designer's normalization cannot be completed on the designer side
alone; finishing it requires a small, additive change at the projector end
too. That is the gap this document closes.

Everything below was checked against the two export pairs in
`C:/projects/eventmill_v02/test_data/path_projector/`, the projector source,
and `framework/reference_data/`.

---

## 1. What the review found

### 1.1 The second export pair breaks the designer plan's stated assumptions

The designer plan was written against the `20260915_165537` pair only. The
directory holds a second pair, `20260915_204815`, and it is not a variant of
the first:

| | 165537 | 204815 |
|---|---|---|
| Actor | APT29 (G0016) | Scattered Spider (G1015) |
| Application | Fleet Telemetry Platform | Application B |
| Paths / nodes | 3 / 15 (5+5+5) | 3 / 24 (7+7+10) |

`helpdesk-oracle-onprem` in the second pair is
`T1598.004 → T1556.006 → T1078.004 → T1068 → T1552.001 → T1078 → T1068 →
T1552.001 → T1078 → T1486` across components
`users, okta, front_door, entry_api, entry_api, oracle_int ×3, oracle_db ×2`.

Three consequences:

1. **`(technique_id, component_id)` repeats inside a single path** — three
   times in that one path. The designer plan already forbids collapsing
   T1078 across paths; this fixture proves the stronger rule, that it cannot
   be collapsed *within* one either. `node_index` is the only identity.
2. **Node counts and path lengths are data, not constants.** Every "15 nodes"
   and "one call per five-step path, three calls" in the designer plan must
   be restated as a function of the input. A 10-step path with repeated
   techniques is the batching case that actually needs designing.
3. **Two files with identical top-level shape describe unrelated
   engagements.** The only thing distinguishing them is the filename stamp.

### 1.1b Fixture inventory

Three export pairs now exist in `test_data/path_projector/`. They are
deliberately unlike each other; normalization is expected to handle all three.

| Pair | Actor / application | Shape | Provenance | Grade without a flow map | Distinguishing feature |
|---|---|---|---|---|---|
| `20260915_165537` | APT29 (G0016) / Fleet Telemetry Platform | 3 paths, 15 nodes (5+5+5) | none (legacy) | `asset_named` | Two recorded `state_check: gap` steps; `via_software` support for T1195.002 |
| `20260915_204815` | Scattered Spider (G1015) / Application B | 3 paths, 24 nodes (7+7+10) | none (legacy) | `asset_named` | Techniques and components repeat *inside* one path; longest path is 10 steps |
| `20260916_192507` | APT29 (G0016) / Fleet Telemetry Platform | 2 paths, 10 nodes (5+5) | **verified** | `component_bound` | Built 2026-09-16 for §5; every node binds to a flow-map component; all `state_check: ok`; one kill-chain-order note |

The third pair is the `component_bound` fixture of decision 3, produced by a
real projection against
`plugins/threat_modeling/adversary_path_projector/examples/telemetry_saas_flow_map.json`
after §4.1 landed, so its `flow_map_sha256` verifiably binds it to that map.
All ten of its nodes resolve to a component carrying `technologies`,
`authentication` and `zone` — `scm` (git, github-actions, `sso_mfa`),
`ci_runner` (ubuntu, docker, runner, `oidc_federation`), `vault`
(hashicorp-vault, `mtls`), `web_console` (nodejs, react, `oidc`) and
`telemetry_db` (postgres, timescaledb, `mtls`).

Note what it does *not* provide. It has no state gaps, so
`multistep_access: true` has to be reached on this fixture through unresolved
credential acquisition rather than an inherited gap; `165537` remains the
fixture for the inherited-gap path. It carries one step whose `notes` record a
kill-chain-order concern — `T1195.002` (Initial Access) appearing second, after
access was already gained — which is a ready-made `needs_mapping_review` case.

### 1.2 The exports carry no verifiable identity

`_write_projection_artifacts`
(`plugins/threat_modeling/adversary_path_projector/tool.py:4250`) builds both
payloads from exactly seven keys: `source_tool`, `status`, `interpretation`,
`actor`, `application`, and then `mitre_mappings` + `attack_graph`, or
`scenarios`.

Absent from the body: `run_id`, `flow_map_sha256`, `attack_version`,
prompt/plugin version, provider attribution, created-at timestamp, and the
actor's ATT&CK ID as a field rather than as `"APT29 (G0016)"` prose. The run
record has `run_id` and `flow_map_sha256`
(`tool.py:3552`, `_canonical_flow_map_hash` at `tool.py:467`); **the exports
do not.**

The designer plan asks normalization to "establish an explicit common source
identity" for a graph/seed pair and to record flow-map provenance. With
today's exports there is nothing to key on but the filename stamp and the
application string — which the plan itself rules out: *"a matching
application name is not proof that a map produced a particular export."*
This is the one change that has to happen outside the designer plugin.

### 1.3 The seed is not strictly lossier than the graph

The designer plan says the scenario export "loses the component ID and turns
the transition and state check into text", implying a subset. Field-diffing
one step of the same node in both exports:

**Graph only:** `component_id`, `asset`, `technique_name`, `rationale`,
`result`, `leads_to`, `notes`, `state_note`, `access_before`, `access_after`,
`mitigations`, `uncovered_mitigations`, `controls_in_play`, and `transition`
as a structure (`flow`, `from`, `to`, `protocol`, `authenticated`,
`crosses_boundary`).

**Seed only:** `event_id`, `sequence_order`, `name`, `description`,
`target_asset`, `attack_technique`, `required_access`, `resulting_access`,
`access_source`, `blocking_controls`, **`detecting_controls`**,
`success_indicators` — plus, at scenario level, `security_controls[]` with
`control_id`, `bypass_difficulty`, `bypass_requirements` and
**`detection_capability`**, which the graph's per-step `controls_in_play`
does not carry.

So the two exports **intersect and diverge**. A merge that prefers the graph
throughout silently drops `access_source`, `detecting_controls`,
`success_indicators` and every control's `detection_capability` — the fields
most directly about detection. Normalization must be a declared union with a
per-field precedence table, not a preference for one document.

### 1.4 Detection-bearing fields the current context omits

`DetectionNodeContext` in designer §3 keeps `controls_in_play` and drops the
rest. For a tool whose output is detection guidance, these are the substrate:

| Field | Source | Why it matters to a detection draft |
|---|---|---|
| `uncovered_mitigations` | graph step | The M-IDs ATT&CK lists for the technique that this estate does **not** implement. Where prevention is absent, detection carries the weight — this is the node's argument for existing. |
| `mitigations` | graph step | The full candidate set, so "uncovered" can be read as a ratio rather than a bare list. |
| `detecting_controls` | seed event | What the model believed already observes this step. A claim to be checked, never coverage — it feeds `review_flags`, not `catalogue_status`. |
| `blocking_controls` | seed event | Distinguishes a step that is attempted-and-blocked from one that succeeds; changes whether the draft detects an attempt or an outcome. |
| `detection_capability` | scenario `security_controls[]` | A stated `none`/`low` on a control protecting this component is the strongest available signal of a telemetry gap. |
| `success_indicators` | seed event | Candidate observables, already phrased as outcomes. |
| `access_source` | seed event | Whether access state was modelled or derived — bears directly on `multistep_access`. |
| `flow` protocol/port/`authenticated`/`crosses_boundary` | graph `transition` | Selects the sensor. A `kafka` flow and an `https` flow at the same component are different log sources. |
| `exposure`, `data_classification`, `crown_jewel` | flow map | Severity and false-positive tolerance. |

`mitigations` and `uncovered_mitigations` resolve to names through
`framework/reference_data/mitre_relationships.json` (`mitigations` section,
e.g. `M1017 → User Training`). That is a local lookup, not a model claim.

### 1.5 There is no local ATT&CK detection or data-component reference

`framework/reference_data/mitre_techniques.json` records exactly four fields
per technique — `matrix`, `name`, `tactics`, `url`. No data sources, no data
components, no detection prose. `mitre_relationships.json` has
`attack_version`, `campaigns`, `groups`, `matrices`, `mitigations`,
`procedures` (17,407) and `software`, and likewise no data components.

Therefore the telemetry reference library the designer plan proposes is the
**only** source of sensor facts, and the generation prompt must forbid
`DS####` data-component identifiers outright. A model asked for ATT&CK
detection guidance will supply them from memory, and nothing in this
repository can check them — the same failure mode as the `v14` taxonomy
citation in `docs/change_log/2026-09-16-one-attack-taxonomy.md`.

### 1.6 Taxonomy: the exports are already correct, and that must be preserved

`T1078` in the local v19.2 lookup carries tactics
`['Stealth', 'Persistence', 'Privilege Escalation', 'Initial Access']`. The
export's `Stealth` agrees with the pinned release. Normalization reconciles
through `canonical_tactic` / `resolve_legacy_tactic` /
`resolve_retired_technique` and records the outcome; it must not hand a
downstream model an opportunity to restore `Defense Evasion`.

---

## 2. The deliverable: a normalized context pack, shipped before any guidance

Split the designer plan's Stage 1 into a standalone, LLM-free deliverable
with its own artifact. This is what "complete the normalization" means
concretely, and it is what lets detection guidance development start against
a stable input instead of against two raw JSON dialects.

**Action:** `normalize_paths` (deterministic, no LLM, `model_tier` irrelevant,
`safe_for_auto_invoke: true`). Accepts the same primary sources as
`generate_detections`: `attack_graph`, `scenario`, or a verified pair, plus
optional `flow_map_artifact_id` and `telemetry_profile_artifact_id`.

**Output artifact:** `detection_context_pack_<timestamp>_<run_id>.json`,
artifact type `json_events`, `metadata.kind:
attack_path_detection_context_pack`. Structure:

```text
pack_version: '1.0'
provenance: { ... §4 ... }
inventory:  { paths: [...], expected_node_keys: [...], counts }
nodes:      [ DetectionNodeContext, ... ]      # source order
reconciliation: { taxonomy: [...], pair_join: [...], flow_map_join: [...] }
completeness:   { per-node context grade, §5 }
warnings:       [ structured codes, never prose-only ]
```

`generate_detections` then takes either a primary source (normalizing
internally) **or** a context pack ID. Two benefits worth the extra action:

- The 24-node fixture and the 15-node fixture can both be normalized, diffed
  and reviewed today, with no provider configured and no cost.
- A guidance run that produced a bad draft can be re-examined against the
  exact pack it was given, rather than re-derived.

---

## 3. `DetectionNodeContext` v2

Additions to the designer §3 list are marked **+**. Fields keep their source
names where the source is unambiguous.

```text
# identity
pack_version, draft_id, source_identity, path_id, node_index
source_event_id, source_pointer

# engagement                                    + actor_attck_id split out
actor_label, actor_attck_id, application, attack_version

# placement
component_id (nullable), asset_name, zone, exposure,            + zone/exposure
data_classification, crown_jewel (bool), technologies,          + from flow map
authentication

# technique
technique_id, technique_name, tactic,
tactic_status: as_supplied | reconciled | unresolved,           +
technique_status: current | retired_remapped | unresolved       +

# behaviour
behavior, rationale, precondition, exploited_condition,
expected_result, success_indicators                             +

# access
access_before, access_after, access_source,                     + access_source
credential_type, credential_scope, state_check, state_note

# topology
transition: {flow_id, from, to, protocol, port,                 + structured
             authenticated, crosses_boundary, evidence: structured|text}
predecessors, successors

# control and coverage                                          + whole block
controls_in_play[]        # name, type, status, on
control_catalogue[]       # control_id, bypass_difficulty, detection_capability
blocking_controls[], detecting_controls[]
mitigations[], uncovered_mitigations[]      # with resolved names
monitoring_claim: none | partial | claimed   # derived, never treated as coverage

# grounding and bookkeeping
assumptions, evidence, actor_support, procedure_evidence[]
telemetry_requirements[], input_conflicts[], provenance_by_field
context_completeness                                            + §5
assessment: {version, tuple, details}
```

`transition` keeps an `evidence` discriminator so a seed-derived
`"flow f4: partner_api -> event_bus (kafka, authenticated)"` is parsed into
the same shape but marked `text`, with the original string retained. The
designer plan's rule stands — parsing does not promote text to a structured
flow — but the parsed form is what a sensor selector can read, so both are
kept rather than only the string.

`monitoring_claim` is derived from `detecting_controls` and the catalogue's
`detection_capability`, and exists so the phrase "a control is listed" can
never be confused with "the events exist". Every draft keeps
`catalogue_status: new_unchecked` regardless of its value.

---

## 4. Provenance and source identity

### 4.1 Additive change to the projector export (projector Phase 4 scope)

Add one `provenance` object to both export payloads in
`_write_projection_artifacts`. Purely additive: `attack_path_visualizer`
reads named keys and ignores the rest, which is why the extra per-step keys
already there are harmless.

```json
"provenance": {
  "run_id": "…",
  "run_group": "…",
  "created_at": "2026-09-15T16:55:37Z",
  "flow_map_sha256": "…",
  "flow_map_path": "…",
  "attack_version": "19.2",
  "actor_attck_id": "G0016",
  "plugin_version": "…",
  "prompt_sha256": "…",
  "provider": {"provider_id": "…", "model": "…"}
}
```

Every value already exists in `run_context` at `tool.py:3538-3562`; none is
newly computed. A graph and seed written by the same call share a `run_id`,
which is the pair-join key the designer plan needs and cannot currently have.

### 4.2 What the designer does with older exports

Both fixtures predate this, so normalization must work without it:

| Condition | `provenance_status` | Behaviour |
|---|---|---|
| `provenance` present in both, `run_id` equal | `verified` | Join the pair. |
| Present, `run_id` differs | `conflict` | Refuse the join; process the primary source alone and warn. |
| Absent (legacy) | `derived` | Synthesize a source identity from the SHA-256 of the canonical document plus its filename; join a pair **only** if the operator passes `--accept_unverified_pair` and actor, application, path IDs, order, techniques and assets all match. Record `pair_join: asserted_by_operator`. |
| Flow map supplied, `flow_map_sha256` present and equal | `verified` | Enrich freely. |
| Flow map supplied, hash present and different | `conflict` | Do not enrich. Report it as a blocking warning, as `summarize_run_group` already does at `tool.py:4180`. |
| Flow map supplied, no hash in export | `asserted_by_operator` | Enrich, and stamp every flow-map-derived field's `provenance_by_field` entry with that status so it cannot later read as sourced fact. |

Name-matching is never sufficient on its own and never silently upgrades a
status.

### 4.3 Field-level precedence

`provenance_by_field` records, for every populated field: origin document,
JSON pointer, and one of `graph | seed | pair_agreed | flow_map |
reference_data | derived`. Precedence when a pair is joined:

1. Graph wins for structure it alone carries — `component_id`, `transition`,
   `mitigations`, `uncovered_mitigations`, `access_before/after`, `notes`.
2. Seed wins for what it alone carries — `event_id`, `sequence_order`,
   `access_source`, `blocking_controls`, `detecting_controls`,
   `success_indicators`, `control_catalogue`.
3. Where both carry a value (`precondition`, `technique_id`, `tactic`,
   `evidence`, `actor_support`, `procedure_excerpt`, `state_check`), equality
   is required. A mismatch produces an `input_conflicts[]` entry with both
   values and both pointers, keeps the graph value, and **blocks** the pair
   join from being reported as `verified`.
4. Flow map fills only fields neither export carries. It never overwrites an
   export value; a disagreement (asset name vs component name) is a conflict
   record.

---

## 5. Context completeness, graded per node

The designer plan's Stage 1 gate — "each supplied input independently
produces the same 15 ordered node occurrences" — can pass while
`technologies`, `authentication`, `zone`, `exposure` and
`data_classification` are all `null`, because no export carries them. A
context pack that satisfies the gate can still be unable to support a single
product-specific detection. Grade it explicitly:

| Grade | Condition | What guidance may claim |
|---|---|---|
| `component_bound` | Verified or operator-asserted flow map, component matched by ID, technologies and authentication present | Product-named log sources; `logsource.product` may be set |
| `asset_named` | Component ID present, no flow map | Behaviour-level sources only; `logsource.definition` describes required collection, `product` stays unset |
| `asset_text_only` | Scenario-only input, asset name but no component ID | Conditional design; the plan's existing rule that a guessed ID must not become a join key |
| `unbound` | No component and no asset | Draft still produced, telemetry section is a declared gap |

`normalize_paths` reports the grade distribution. **Revised Stage 1 gate:**
graph-only and seed-only input produce the same node keys in the same order
*and* a completeness grade per node, with a declared field-level diff between
the two — not merely the same count. For the 165537 fixture without a flow
map, every node is `asset_named`; the 24-node fixture behaves the same way.
Neither reaches `component_bound` until a flow map is supplied.

This is also the honest answer to the designer plan's §1 note that neither
export embeds a technology inventory: the tool does not invent one, it
reports which grade it is working at and constrains the drafts accordingly.

---

## 6. Staging

Normalization first and separately; guidance builds on the pack.

| Stage | Deliverable | Acceptance gate |
|---|---|---|
| **N1. Adapters and identity** | Graph, seed and single-scenario adapters; `(source_identity, path_id, node_index)` keys; deterministic `draft_id`; union merge with the §4.3 precedence table | Both fixtures normalize graph-only and seed-only to identical ordered node keys (15 and 24). Repeated `(technique, component)` inside one path stays distinct. `AE-0001` recurring per path never collides. No pair joins without `verified` or an explicit operator assertion. |
| **N2. Provenance** | Projector `provenance` block (§4.1) — **built 2026-09-16**; designer-side legacy handling (§4.2); conflict codes | A graph from one run and a seed from another are refused as a pair. A flow map whose hash differs does not enrich. Every field carries an origin and pointer. |
| **N3. Enrichment and grading** | Flow-map join, control catalogue, mitigation-name resolution, taxonomy reconciliation, completeness grades | `Stealth` survives against v19.2. `uncovered_mitigations` resolve to names locally. Grades match §5 on both fixtures with and without the flow map. |
| **N4. Context pack artifact** | `normalize_paths` action, pack schema, registration, CLI `show`/`export`, bounded `summarize_for_llm` | Pack round-trips; re-normalizing the same inputs is byte-identical apart from run ID and timestamp; the summary states counts, grades and conflicts without pasting node bodies. |
| **N5. `normalize_flow_map`** | The projector's own Phase 4 action | Prose/Markdown/Mermaid → canonical flow map JSON with a stable `_canonical_flow_map_hash`. An unstated control status becomes `partial` and is flagged, never `implemented` — the rule already recorded in `docs/change_log/2026-09-11-adversary-path-projector-phase-3.md`. This is what makes `component_bound` routinely reachable. |
| **G1…** | Grounding, generation, workbook — designer plan stages 2–5, unchanged except that they consume a pack | As in the designer plan, with the node-count constants replaced by pack inventory. |

N1–N4 need no provider and no cost. N5 is projector work and can run in
parallel; the designer degrades to `asset_named` without it, which is a
documented state rather than a failure.

### Corrections the designer plan needs

- §1 table, §6 headings, §8 `expected_nodes: 15` and the §9 acceptance gates:
  restate every count as derived from the pack inventory.
- §8 step 4: "one call for each five-step path; three calls" becomes a
  batching rule sized against the provider's content budget, with the 10-step
  path as the worked example.
- §1: the claim that the scenario export is a lossy subset of the graph is
  wrong in both directions; replace with the §1.3 union.
- §3: add the §1.4 control-and-coverage block, `access_source`, and the
  structured-vs-text transition discriminator.
- §4: state that no local ATT&CK data-component reference exists and that
  `DS####` identifiers are rejected by the validator.

---

## 7. Contract tests for the normalization layer

Beyond the designer plan's list, and all runnable without a provider:

- **Fixture 2 as a first-class fixture.** 24 nodes, three path lengths,
  `T1078` three times and `T1552.001` three times inside one path, three
  consecutive steps on `oracle_int`. Any dedupe that touches it fails.
- **Cross-fixture contamination.** Normalizing the 165537 graph with the
  204815 seed must be refused, not merged — different actor, application and
  path IDs, and today nothing but those strings prevents it.
- **Union merge.** For a node present in both exports, assert every field in
  the §1.3 graph-only and seed-only lists survives, each with the right
  `provenance_by_field` origin.
- **Precedence conflict.** Mutate one shared field in the seed copy; assert a
  conflict record with both pointers, the graph value retained, and the pair
  join not reported `verified`.
- **Legacy provenance.** Both fixtures lack `provenance`; assert
  `provenance_status: derived`, and that a pair join requires the explicit
  operator flag.
- **Flow map hash mismatch** blocks enrichment; a flow map with no hash in the
  export marks every derived field `asserted_by_operator`.
- **Completeness grading** across all four grades, including a
  scenario-only run reaching `asset_text_only` with `component_id: null`.
- **Taxonomy.** `Stealth` unchanged against v19.2; a deliberately retired ID
  is remapped through `resolve_retired_technique` with the remap recorded,
  never guessed.
- **Mitigation resolution.** `uncovered_mitigations` names come from
  `mitre_relationships.json`; an unknown M-ID is reported, not invented.
- **`DS####` rejection** anywhere in a normalized or generated record.
- **Determinism.** Same inputs → identical pack apart from run ID and
  timestamp; `draft_id` stable across runs and unchanged by the presence of
  optional context.

---

## 8. Not in scope, and what is still open

Out of scope here: the assessment tuple's semantics (designer §5, unchanged
and adopted as-is), generation, rendering, any catalogue, and the deferred
visualizer control binding (projector spec, *Deferred: rendering the
component binding*) — though a context pack carrying `controls_in_play` and
`uncovered_mitigations` per node is exactly what that renderer would need.

Decisions taken, 2026-09-16 (operator):

1. **The projector export change is in scope and is built.** The export half
   of N2 landed the same day — see
   `docs/change_log/2026-09-16-projector-export-provenance.md`. Both exports
   now carry the `provenance` block of §4.1, sharing one `run_id` with the run
   record. The designer-side legacy handling of §4.2 remains N2 work, and
   remains necessary: both current fixtures predate the change.
2. **`generate_detections` accepts a raw export as well as a pack**, and
   always writes the pack as an artifact, so the input to any generation run
   stays recoverable even when the operator passed a file path.
3. **The `component_bound` fixture is an interim step and comes before the
   generation function is designed.** Confirmed. Its purpose is to keep
   behaviour-level telemetry from becoming the implicit norm: if every fixture
   is `asset_named`, the prompt, the draft schema and the reviewers all settle
   at "describe the collection you would need", and the `component_bound`
   path — where `logsource.product` may actually be set — gets designed later
   against no example. It is throwaway: once N5 (`normalize_flow_map`) lands,
   `component_bound` is the ordinary case and the hand-built fixture is
   replaced by a real one.

   **Built 2026-09-16** by a real projection against
   `plugins/threat_modeling/adversary_path_projector/examples/telemetry_saas_flow_map.json`,
   rather than by hand: now that exports carry `flow_map_sha256` that yields a
   verifiably bound pair instead of an asserted one, and it live-confirmed the
   §4.1 block at the same time. The result is the `20260916_192507` pair in
   §1.1b. Change log:
   `docs/change_log/2026-09-16-component-bound-fixture.md`.

## 9. Review status

Parsed both export pairs and diffed their per-node fields; read
`_write_projection_artifacts`, `run_context` and the flow-map hash handling in
the projector; confirmed the ATT&CK lookup's field set, `attack_version`
19.2, the `mitigations` section and the absence of any data-component data.
When this document was first written no code had been changed. §4.1 was then
built the same day (change log above); nothing else here is implemented, and no
LLM run has been performed. Node counts, path shapes,
field lists and the tactic check in this document come from reading the
fixtures and reference data, not from the earlier plan's prose.
