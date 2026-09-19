# Attack path normalization — completing the seam the detection designer sits on

Status: proposed, with §4.1 (the projector export `provenance` block) built and
unit-tested on 2026-09-16. Revises section 3 of
`docs/specs/attack_path_detection_designer.md`.
Date: 2026-09-16. Extended 2026-09-17 with §1.4b (mitigation focus),
§4.2a (three identities), §4.3 3a (`state_check` canonicalization), the
corrected §4.1 provenance names, the `component_bound_partial` grade, and
decisions 4 and 5. N1 is the next implementation step and its contract is
now settled.
**N1 is built** (`docs/change_log/2026-09-17-n1-adapters-and-identity.md`,
commit `bbd4384`), with artifact-id input added the same day per decision 8.
Corpus refreshed 2026-09-17 (later): three new projector runs replaced the
three pre-provenance pairs. §1.1b, §4.3 3a, §5, §6, §7a and decision 6 are
restated over the new 43-node corpus. Decision 7 then settled the plugin shape
— one plugin, `safe_for_auto_invoke: false`, §2 corrected — which was the last
thing blocking N1 code. The producer-side shape those counts
come from is described once, separately, in
`docs/specs/projector_export_shapes.md`.
**N2 is closed 2026-09-19** (decision 9): a flow map is an analyst-editable
working document, so its hash records lineage and never gates enrichment; the
§4.2 flow-map rows, §5 and the new §4.4 code catalogue are revised to match.

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

Sections 1.1-1.6 were written on 2026-09-16 against the **two** export pairs
then in `C:/projects/eventmill_v02/test_data/path_projector/`, the projector
source, and `framework/reference_data/`. Two further pairs were added on
2026-09-16 and 2026-09-17; §1.1b is the current inventory of all four, and any
statement below reading "both fixtures" without a date means those first two.
Statements about what the exports do or do not carry are **as of their stated
date** — §4.1 landed on 2026-09-16 and changed several of them.

**The fixture corpus was then replaced on 2026-09-17.** §§1.1–1.6 were
measured against pairs that no longer exist in the data store; they are kept
because the *findings* still hold and are the reason several rules exist, but
every **count** in them is historical. Current counts are §1.1b, §7a and
`docs/specs/projector_export_shapes.md`. Where the two disagree, the later
document is right and the older text is evidence of what was once observed.

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

1. **A technique repeats inside a single path.** In that path `T1078` occurs
   twice (steps 6 and 9, alongside `T1078.004` at step 3, which is a distinct
   ID) and `T1552.001` twice (steps 5 and 8); `oracle_int` carries three
   consecutive steps. So `(technique_id, path_id)` is not unique and
   `node_index` is the only identity.

   **Corrected 2026-09-17.** This passage previously claimed
   `(technique_id, component_id)` repeats three times inside that path. Re-read
   from the fixture, **no `(technique_id, component_id)` pair repeats within
   any path in any of the four fixtures.** Pairs do repeat *across* paths in
   `204815` — `T1068@entry_api` and `T1552.001@entry_api` appear in both
   `vish-token-entrydb` and `phish-link-blob` — so this fixture catches a
   global dedupe but **not** a within-path one. The within-path rule is the
   stronger claim and the one `node_index` exists to serve; it currently has
   no fixture that would fail if it were violated. §7 carries the synthetic
   case that closes this.
2. **Node counts and path lengths are data, not constants.** Every "15 nodes"
   and "one call per five-step path, three calls" in the designer plan must
   be restated as a function of the input. A 10-step path with repeated
   techniques is the batching case that actually needs designing.
3. **Two files with identical top-level shape describe unrelated
   engagements.** The only thing distinguishing them is the filename stamp.

### 1.1b Fixture inventory

**Replaced 2026-09-17 (second revision).** The corpus was rebuilt: three fresh
runs against the current code joined `20260917_022646`, and the three older
pairs — `20260915_165537`, `20260915_204815`, `20260916_192507` — are
**retired**. They were produced before the provenance block, before the v19.2
tactic reconciliation, or both, and two of them named applications that were
never confirmed synthetic. The inventory below is the one N1 builds against.
The producer-side description of these documents, measured field by field, is
`docs/specs/projector_export_shapes.md`; this section records only what the
fixtures are for.

Four export pairs in `C:/projects/eventmill_v02/test_data/path_projector/`,
**43 nodes over 8 paths**, all on `git_sha 1c2ba74` / manifest `0.2.0` / ATT&CK
19.2, all produced by `gcp_gemini` `gemini-3.1-pro-preview` at `heavy` tier.

| Pair | Actor / application | Shape | Provenance | Grade with the map | Distinguishing feature |
|---|---|---|---|---|---|
| `20260917_022646` | Fox Kitten (G0117) / Fleet Telemetry Platform | 2 paths, 9 nodes (5+4) | **verified** (`build_env`) | `component_bound` | Shortest graph; 1 `state_check: gap` at `component_bound` grade; a live tactic reconciliation to `Stealth`; the only pair with no run record |
| `20260917_122549` | Scattered Spider (G1015) / Fleet Telemetry Platform | 2 paths, 11 nodes (5+6) | **verified** (`build_env`) | `component_bound` | Same flow map and same hash as `022646`, different actor — the corpus's one controlled comparison; 3 gaps; 3 `STATE_GAP` warnings and nothing else |
| `20260917_123525` | APT29 (G0016) / Application B | 2 paths, 10 nodes (4+6) | **verified** (`build_env`) | `component_bound_partial` | The only `undeclared` transition (`okta` → `entry_api`) and its `HOP_NOT_DECLARED` warning; `LATE_INITIAL_ACCESS`; 4 flow-map `validation` findings; alias resolution `Midnight Blizzard` → APT29; 0 of 28 mitigations covered |
| `20260917_124121` | Volt Typhoon (G1017) / Claims Portal | 2 paths, 13 nodes (7+6) | **verified** (`build_env`) | `component_bound_partial` | Longest graph; the only `via_software` evidence; 3 convergence points and 1 branch point; cross-path `(technique, component)` repeats; two live `TACTIC_CORRECTED` relabels to `Stealth` |

What the new corpus gains, and what it costs:

- **Two new applications and two new flow maps.** `application_b_flow_map.json`
  and `claims_portal_flow_map.json` are both in the repository, as
  `telemetry_saas_flow_map.json` already was, so **all four pairs now bind to a
  map under version control**. This is what closes decision 6 (§8).
- **`component_bound_partial` is exercised for the first time** — 5 nodes on
  components declaring no `technologies` or `authentication: none`:
  `front_door` and `users` on Application B, `claims_db` and `doc_store` on
  Claims Portal. §5 recorded this grade as needing its own fixture; it now has
  two.
- **Every node resolves.** 43 of 43 `component_id` values are found in the
  supplied map, so `asset_named` is reachable only by withholding the map, and
  `asset_text_only` only through seed-only input.
- **Three run records** (`122549`, `123525`, `124121`), which the retired
  corpus did not include in the fixture set at all. `022646` has none, which is
  why the run record cannot be a required normalization input.
- **Lost:** the 10-step path, the three-path graph, the within-path technique
  repeats of `204815`, and the `git_worktree` code-identity branch — no current
  fixture exercises any of them. The §7 synthetic within-path case therefore
  becomes the *only* cover for the within-path identity rule, not a supplement
  to a fixture, and the longest real path is now 7 steps.

### 1.2 The exports carried no verifiable identity (before 2026-09-16)

**Resolved.** This section records the state that motivated §4.1, which
landed on 2026-09-16. Exports produced from that date carry `provenance` and
are joinable on `run_id`; the two legacy pairs never will be, so §4.2 remains
required. Read the rest of this section in the past tense.

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
| `mitigations` | graph step | The ATT&CK mitigation set for the technique. Supplies the denominator of the coverage ratio and the input to the §1.4b focus cut. |
| `uncovered_mitigations` | graph step | The subset carrying **no matching tag on a control declared on that component**. Retained for provenance and for the ratio — not as evidence that prevention is absent, and not as the node's argument for existing. See §1.4b. |
| *covered* (derived) | graph step | `mitigations` minus `uncovered_mitigations`. A tagged control exists on this component for that mitigation, so a draft here is a **tuning** case rather than a gap case. The smaller and more informative half. |
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

### 1.4b `uncovered_mitigations` is not a coverage finding

Measured across the four fixtures, the field carries almost no discriminating
signal, and the earlier wording of §1.4 overstated it in two directions at
once. What the projector computes
(`plugins/threat_modeling/adversary_path_projector/tool.py:2042-2063`) is
`mitigations_for_technique(t)` minus the M-IDs tagged on controls declared
**on that one component** — not an estate-wide implementation check, and
absence of a *tag* rather than absence of a *control*. The projector already
narrates that caveat at `tool.py:4593`: untagged controls cannot be matched,
and estate-wide and flow controls are not checked at all.

Three measurements decide how it should be consumed:

1. **It is ~95% identical to `mitigations`.** Across `165537`, `192507` and
   `022646`: 154 mitigations, 147 uncovered, **7 covered**. Mean 4.4 uncovered
   per node against 4.5 total. Carrying both lists is carrying one list twice.
2. **Its frequency profile is inverted.** The most-often-uncovered M-IDs are
   the broadest in ATT&CK — M1018 (119 techniques), M1026 (112), M1047 (110),
   M1017 (60), M1032 (48). The list is dominated by advice applying to a third
   of the matrix, and M1017 *User Training* yields no telemetry at all.
3. **It is component-blind.** `T1078` at `telemetry_db` and `T1078` at `scm`
   in `022646` carry byte-identical eight-item lists. The set derives from the
   technique, so it repeats verbatim wherever the technique repeats; it is not
   node-specific information.

Two filters that look available are not:

- **By telemetry source.** A mitigation entry in `mitre_relationships.json`
  has exactly `description`, `matrices`, `name`, `techniques`, `url` — no data
  sources and no data components, the same absence §1.5 records for
  techniques. Ranking mitigations by sensor relevance would be a model claim
  with nothing local to check it, which is the `DS####`-from-memory failure
  mode §1.5 already forbids.
- **By actor.** Mitigations attach to techniques, and the technique at a node
  was selected *because* the named actor uses it — the actor constraint is
  applied upstream, when the projector builds the path. Re-filtering at the
  node re-derives the same set, so "the mitigations most applicable to this
  actor" collapses to "the mitigations for this technique."

**Decision.** Keep the full lists in the pack; narrow what generation sees.

- The pack retains `mitigations[]` and `uncovered_mitigations[]` unchanged.
  They are already in the export, they cost nothing, and discarding them would
  make a later change to this rule unexplainable.
- Normalization derives `mitigation_focus[]` — the **one or two narrowest**
  uncovered mitigations ranked ascending by `len(mitigations[M].techniques)`,
  each carrying that breadth count so a reviewer can see the basis. The
  ranking is a local, deterministic lookup. On `022646` step 1 (`T1190`) it
  surfaces M1016 *Vulnerability Scanning* (5) and M1048 *Application Isolation
  and Sandboxing* (14) in place of M1026 (112).
- Normalization derives `mitigations_covered[]` and
  `mitigation_coverage: {covered, total, tag_caveat}`, where `tag_caveat`
  carries the projector's own `control_tagging` counts.
- **Generation consumes `mitigation_focus[]`, `mitigations_covered[]` and the
  ratio only** — never the full uncovered list. 255 near-generic M-IDs across
  58 nodes is not a pack-size problem; it is a problem with what the model is
  told to reason about.

Breadth is a proxy for specificity, **not** for detectability: M1015 *Active
Directory Configuration* is narrow (15 techniques) but is a configuration
posture, not a sensor. `mitigation_focus[]` therefore narrows the prompt; it
never argues that a detection should exist. The fields that do argue that are
already on the §1.4 list — `detecting_controls`, `detection_capability` and
`controls_in_play` — and they are per-component and per-flow rather than
per-technique. Mitigation data is a preventive-control taxonomy, and using it
to justify a detection is a category borrow.

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

**Action:** `normalize_paths` (deterministic, no LLM, `model_tier` irrelevant).
Accepts the same primary sources as `generate_detections`: `attack_graph`,
`scenario`, or a verified pair, plus optional `flow_map_artifact_id` and
`telemetry_profile_artifact_id`.

**Where it lives.** `normalize_paths` and `generate_detections` are **two
actions of one plugin**, and that plugin declares
`safe_for_auto_invoke: false`. *(Corrected 2026-09-17: this section previously
declared `normalize_paths` as `safe_for_auto_invoke: true`, which the manifest
cannot express — the field is whole-plugin and there is no per-action form.
Decision 7, §8.)*

The action is still free, deterministic and provider-less; what changes is only
that the **plugin** it sits in is not marked auto-invocable, because it also
holds a heavy-tier generation call. `adversary_path_projector` already has this
shape — `profile_actor` and `validate_flow_map` are free and deterministic
while `project_paths` is a heavy call, and the plugin is `false`. Any
documentation of `normalize_paths` should say it is safe and free to run, and
should not claim the manifest says so.

**Inputs are artifacts, and so are outputs.** Confirmed 2026-09-17 as the
shape of the first working version and implemented in N1 — decision 8, §8. The
registered artifact, not a file path, is how a projector export reaches this
plugin:

| Input | Meaning |
|---|---|
| `artifact_ids: [graph, seed]` | the normal route; one or two registered exports of the same run |
| `artifact_id` | a single export, because the shell's own `artifact_id` handling speaks the singular and injects `file_path`/`path` beside it |
| `sources: [path, path]` | file paths, for a local export that was never registered |

A path is a convenience for local work. It is not the route that works in the
container, where an export is auto-exported to a bucket and only the registry
knows where it landed; resolution therefore goes through `context.artifacts`
like every other plugin's. An artifact that is registered but whose bytes are
not readable on this disk is reported as `ARTIFACT_UNAVAILABLE` naming its
`storage_uri` — not as a missing file, and never as an empty result.

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
internally) **or** a context pack ID — in both cases by artifact id, per the
table above. Two benefits worth the extra action:

- All four fixtures — 43 nodes across 9, 11, 10 and 13 — can be normalized,
  diffed and reviewed today, with no provider configured and no cost.
- A guidance run that produced a bad draft can be re-examined against the
  exact pack it was given, rather than re-derived.

---

## 3. `DetectionNodeContext` v2

Additions to the designer §3 list are marked **+**. Fields keep their source
names where the source is unambiguous.

```text
# identity                                     + three identities, not one
pack_version, draft_id
artifact_identity[]       # one per contributing document; §4.2a
projection_identity       # the run both documents came from; §4.2a
path_id, node_index       # with projection_identity, the occurrence key
source_event_id, source_pointer

# engagement                                   + actor_attack_id split out
actor_label, actor_attack_id, application, attack_version
model_attribution: {provider, vendor,                            + §4.1
                    model_configured, model_served}

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

# topology                                          + movement discriminator
transition: {movement, flow_id, from, to, protocol,
             authenticated, crosses_boundary, exposure,
             evidence: structured|text, raw}
predecessors, successors

# control and coverage                                          + whole block
controls_in_play[]        # name, type, status, on
control_catalogue[]       # control_id, bypass_difficulty, detection_capability
blocking_controls[], detecting_controls[]
mitigations[], uncovered_mitigations[]      # with resolved names; pack only
mitigations_covered[]                       # mitigations - uncovered; tuning case
mitigation_focus[]        # 1-2 narrowest uncovered: m_id, name, technique_breadth
mitigation_coverage: {covered, total, tag_caveat}            # §1.4b
monitoring_claim: none | partial | claimed   # derived, never treated as coverage

# grounding and bookkeeping
assumptions, evidence, actor_support, procedure_evidence[]
telemetry_requirements[], input_conflicts[], provenance_by_field
context_completeness                                            + §5
assessment: {version, tuple, details}
```

The four mitigation fields are **not one block with one audience**.
`mitigations[]` and `uncovered_mitigations[]` are pack-only: retained whole for
provenance and never handed to generation. `mitigations_covered[]`,
`mitigation_focus[]` and `mitigation_coverage` are what the generation layer
reads, for the reasons measured in §1.4b. A node with an empty
`mitigation_focus[]` is ordinary — it means every uncovered mitigation for that
technique was broad — and must not be reported as missing data.

`transition` keeps an `evidence` discriminator so a seed-derived
`"flow f4: partner_api -> event_bus (kafka, authenticated)"` is parsed into
the same shape but marked `text`, with the original string retained. The
designer plan's rule stands — parsing does not promote text to a structured
flow — but the parsed form is what a sensor selector can read, so both are
kept rather than only the string.

**The graph's `transition` has three shapes, not one.** Counted across all
four fixtures (58 nodes):

| Source shape | Count | `movement` | Meaning |
|---|---:|---|---|
| `{entry: true, exposure: …}` | 8 | `entry` | The path's first step. There is no originating component; `exposure` is the surface it arrives on. |
| `{flow, from, to, protocol, authenticated, crosses_boundary, return?}` | 18 | `declared_flow` | Movement along a flow the map declares. `flow` is the flow map's flow id. 14 cross a boundary; one carries `return: true`. |
| `null` | 17 | `in_place` or `undeclared` | No transition object at all. |

*(Restated 2026-09-17 over the 43-node corpus; the retired corpus read 10 / 23
/ 25 and the proportions are unchanged. `return: true` is new to the counted
set.)*

The `null` case is not one case. In 16 of 17 occurrences the step's
`component_id` equals its predecessor's — the actor is acting *in place* on a
component it already holds, which is a different detection problem from lateral
movement and must not read as missing data. In the remaining occurrence
(`123525` / `phishing-to-blob` step 3, `okta` → `entry_api`, the step the run
record flags `HOP_NOT_DECLARED`) the component changes with no declared flow:
movement the flow map does not describe. Normalization sets `movement: in_place` for the first and
`movement: undeclared` for the second, and an `undeclared` transition is a
`review_flags` entry — an adversary crossing a boundary the model of the estate
does not contain is precisely what a reviewer should see.

Note also that `port` appears on flow-map flows but **not** on a step's
`transition`; it is available only through the flow-map join, at
`component_bound` grade.

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

This block is **built**. What follows is the shape as read from the two
verified fixtures on 2026-09-17, not the shape this document originally
proposed; where they differed the export is authoritative and the spec has
been corrected to match.

```json
"provenance": {
  "run_id": "…",
  "run_group": "…",
  "run_index": 1,
  "created_at": "2026-09-15T16:55:37Z",
  "flow_map_path": "…",
  "flow_map_sha256": "…",
  "prompt_sha256": "…",
  "attack_version": "19.2",
  "actor_attack_id": "G0016",
  "tool_version": {"manifest_version": "0.2.0", "git_sha": "1c2ba74",
                   "code_id_source": "git_worktree|build_env|unavailable"},
  "model": {"provider": "gcp_gemini", "vendor": "google",
            "model_configured": "gemini-3.1-pro-preview",
            "model_served": "gemini-3.1-pro-preview"}
}
```

Three naming corrections, each a silent-wrong risk for a normalizer written
from the earlier draft:

- **`actor_attack_id`**, not `actor_attck_id`.
- **`model`**, not `provider`, and its shape is four fields, not two. The
  operator's provider id is at `model.provider`; `model_configured` and
  `model_served` are kept apart deliberately, so a served substitution stays
  visible.
- **There is no `provider` key at all.** Reading `provenance.provider` returns
  nothing on a fixture that carries full attribution, and a normalizer that
  records "no provider attribution" from that is wrong in the same silent way
  as an empty `EVENTMILL_BUCKET_PREFIX`. Normalization must read `model`, and
  must distinguish *key absent* from *value null*.

`run_index` is also present and was missing from the earlier draft; it
disambiguates runs sharing a `run_group`.

Every value already exists in `run_context` at `tool.py:3538-3562`; none is
newly computed. `code_id_source` is required reading before trusting
`git_sha`: a container has no working tree, so an export produced on Cloud Run
before 2026-09-17 carries an empty SHA and no source field, and its code
identity is simply not recoverable. Normalization records that as a provenance
limitation rather than treating the empty string as a value. A graph and seed written by the same call share a `run_id`,
which is the pair-join key the designer plan needs and cannot currently have.

### 4.2a Three identities, because one cannot do the job

The earlier draft used a single `source_identity`, synthesized for legacy
exports from the SHA-256 of the canonical document plus its filename. That is
self-contradictory. The graph and the seed are different documents with
different filenames, so they produce different hashes — yet N1's gate requires
graph-only and seed-only input to yield **the same** ordered node keys, and the
key was `(source_identity, path_id, node_index)`. Under the old definition the
gate can never pass on a legacy pair, and on a verified pair it passes only
because `run_id` happens to be equal.

Separate the three things that were conflated:

| Identity | Scope | Derivation | Used for |
|---|---|---|---|
| `artifact_identity` | one **document** | SHA-256 of the canonical document plus its filename and role (`graph`/`seed`) | Provenance, `provenance_by_field` pointers, "which file said this". Differs between graph and seed **by design**. |
| `projection_identity` | one **projection run** | `provenance.run_id` when present; otherwise a digest over the run-invariant content — actor, `actor_attack_id`, application, ordered path IDs, per-path ordered technique IDs and assets — deliberately excluding filenames, timestamps and role | The pair-join key, and the stable prefix of every node key. Graph-only and seed-only input of the same run yield the **same** value. |
| node occurrence | one **step** | `(projection_identity, path_id, node_index)` | Node identity. `node_index` is the only discriminator within a path; see §1.1. |

`draft_id` derives from the node occurrence key alone, so it is stable across
runs and unchanged by the presence of optional context — the determinism rule
in §7 depends on it not incorporating `artifact_identity`.

For a legacy pair `projection_identity` is a *derived* value and the pair join
still requires `--accept_unverified_pair`: equal derived identities mean the
two documents describe the same projection, not that they were written by one
call. The status carried is `derived`, never `verified`, and equality of a
derived identity never silently upgrades it.

### 4.2 What the designer does with older exports

Both legacy fixtures predate the §4.1 block, so normalization must work
without it:

| Condition | `provenance_status` | Behaviour |
|---|---|---|
| `provenance` present in both, `run_id` equal | `verified` | Join the pair. |
| Present, `run_id` differs | `conflict` | Refuse the join; process the primary source alone and warn. |
| Absent (legacy) | `derived` | Derive `projection_identity` per §4.2a — over run-invariant content, **not** over the document hash or filename, so graph-only and seed-only agree. Join a pair **only** if the operator passes `--accept_unverified_pair` and the derived identities are equal. Record `pair_join: asserted_by_operator`. |
| Present in one document only | `conflict` | Refuse the join. A verified document and a legacy one are not comparable: the one `run_id` cannot be checked against anything. Process the primary source alone and warn. |
Name-matching is never sufficient on its own to join a pair and never silently
upgrades a pair status.

**Flow maps are recorded, not gated (decision 9, 2026-09-19).** A flow map is
not a forensic copy. An analyst with inside knowledge is expected to copy a
generated map and correct it, git is the recommended way to track those
edits, and a tampered map is not a meaningful threat in this workflow. The
export's `flow_map_sha256` therefore answers *is this the map the projection
ran against, or something else?* — lineage — and never decides whether the map
may be used:

| Flow map supplied, compared with the export's `flow_map_sha256` | `flow_map_lineage` | Behaviour |
|---|---|---|
| Hash present and equal | `same_map` | Enrich. |
| Hash present and different | `edited_map` | Enrich. Advisory `FLOW_MAP_EDITED`: the paths were reasoned against an earlier version of the estate; re-project if the edit changes topology or controls. |
| No hash in the export | `unhashed` | Enrich. Supplying the map is the operator's assertion; no flag is required. Advisory `FLOW_MAP_UNHASHED`. |

The hash cannot tell a descendant of the projected map from an unrelated one;
both read `edited_map`. Two direct checks stand in for the integrity reading
the hash used to be given, and both are advisory:

- **Application.** The map's `application` against the export's. A difference
  raises `FLOW_MAP_APPLICATION_MISMATCH` — the likeliest sign of the wrong
  map, not of an edit.
- **Component fit.** Every distinct `component_id` the nodes carry is looked up
  in the map. One that does not resolve raises `FLOW_MAP_COMPONENT_UNRESOLVED`
  and its nodes receive no flow-map enrichment in N3; they stay `asset_named`.
  A renamed or removed component therefore surfaces per node, not as a
  pass/fail on the whole map.

Substantive contradictions between an edited map and the projection are
already caught by §4.3 rule 4: the map only fills fields no export carries,
and a disagreement is a conflict record with the export value kept. An edited
map can add context; it cannot rewrite what the projection reasoned about.

The lineage is recorded once on the result and, from N3, on every
flow-map-derived field's `provenance_by_field` entry as `flow_map_lineage`, so
a draft can say it rests on an edited map. This does **not** relax the pair
rows above: the `run_id` join guards against merging two different runs into
one context, which is an error whatever the trust model.

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
   is required **after canonicalization**, per 3a. A mismatch produces an
   `input_conflicts[]` entry with both values and both pointers, keeps the
   graph value, and **blocks** the pair join from being reported as
   `verified`.

   **3a. `state_check` is represented differently in the two exports and must
   be canonicalized before comparison.** The graph splits it across two fields,
   `state_check` (`ok` | `gap`) and `state_note`; the seed carries one combined
   string. The relation is exact, not approximate:

   ```text
   seed.state_check == graph.state_check                 if state_note is empty
   seed.state_check == graph.state_check + " — " + graph.state_note   otherwise
   ```

   Verified over all **43** nodes of the current four fixtures: 43 of 43 match
   byte-for-byte under that rule, 0 conflicts. The separator is U+2014 EM DASH
   with a single space either side — not a hyphen, not an en dash. It differs
   on exactly the **9** nodes carrying `state_check: gap` (1 in `022646`, 3 in
   `122549`, 3 in `123525`, 2 in `124121`); the other 34 are the empty-note
   case where both sides read `ok`. *(The same rule held 58 of 58 with 6 gap
   nodes on the retired corpus, so it has now been confirmed across seven
   runs, three applications and five actors.)*

   **`transition` needs the same treatment and does not yet have a rule.** The
   graph carries an object; the seed carries prose
   (`"flow f5: claims_api -> doc_store (s3, unauthenticated)"`,
   `"entry point (internet-exposed)"`, `""`). The prose is derivable from the
   object but not the reverse — it omits `crosses_boundary` entirely, so an
   intra-zone flow and a boundary crossing render identically. Rule 1 already
   gives the graph precedence for `transition`; what is added here is that a
   seed/graph `transition` difference is a **representation difference, never
   an `input_conflicts[]` entry**, and the prose may be retained only as a
   display string. Without this, every non-null transition in every pair joins
   as a conflict.

   Comparing the raw strings produces 58 spurious conflicts and blocks every
   pair join. Comparing only the leading token silently discards the note,
   which on the 6 gap nodes is the entire continuity finding. Normalization
   therefore canonicalizes to the graph's two-field form, keeps the seed's
   combined string as the raw value per the retain-raw rule, and records
   `pair_agreed` — these are representation differences, **not** conflicts.

   The rule is encoding-fragile: a transport that mangles the em dash turns all
   six into conflicts. `2026-09-17-fox-kitten-fixture.md` records that the GCS
   round trip was checked for exactly this. A round-trip that cannot produce a
   U+2014 must raise an encoding warning rather than a content conflict.
4. Flow map fills only fields neither export carries. It never overwrites an
   export value; a disagreement (asset name vs component name) is a conflict
   record. Each field it fills is stamped origin `flow_map` plus the
   `flow_map_lineage` of §4.2.

### 4.4 Warning, review-flag and error codes

Closed sets, each code declared once in the plugin
(`WARNING_CODES` and `REVIEW_FLAG_CODES` in `normalization.py`, `ERROR_CODES`
in `tool.py`). Emitting an undeclared code is a programming error, not a new
code. Every warning carries its severity.

**Severity.** `blocking` means the output omits or downgrades something
because of the condition — a document dropped, a node not merged, a join not
reported verified, a component left unenriched. `advisory` means the output is
complete and the reader should know why it may need a second look.

| Warning | Severity | Raised when |
|---|---|---|
| `PAIR_REFUSED` | blocking | §4.2 refuses the pair; the primary document is processed alone. |
| `PAIR_CONTENT_CONFLICT` | blocking | A shared field disagrees after canonicalization; the join is not reported verified. |
| `NODE_ONLY_IN_SECONDARY` | blocking | A node the leading document lacks; it is not merged. |
| `PATH_NOT_IN_BOTH` | advisory | A path present in one document of a pair only. |
| `PATH_LENGTH_DIFFERS` | advisory | The two documents disagree on a path's length. |
| `STATE_NOTE_ENCODING` | advisory | The `state_check` separator is not U+2014; the transport damaged it (§4.3 3a). |
| `FLOW_MAP_EDITED` | advisory | The supplied map's hash differs from the export's (§4.2). |
| `FLOW_MAP_UNHASHED` | advisory | The export records no flow map hash (§4.2). |
| `FLOW_MAP_APPLICATION_MISMATCH` | advisory | The map names a different application from the export. |
| `FLOW_MAP_COMPONENT_UNRESOLVED` | blocking | A node's `component_id` is not in the supplied map; its nodes are not enriched. |

| Review flag (per node) | Raised when |
|---|---|
| `UNDECLARED_TRANSITION` | The component changes with no declared flow. |
| `TRANSITION_UNPARSED` | Transition prose matched no known form; kept verbatim. |

| Error (the call fails) | Raised when |
|---|---|
| `NO_INPUT` | No export supplied. |
| `ARTIFACT_NOT_FOUND` | An artifact id, export or flow map, is not registered in the session. |
| `ARTIFACT_UNAVAILABLE` | Registered, but its bytes are not readable here; names the `storage_uri`. |
| `INPUT_UNREADABLE` | An export is not readable JSON. |
| `INPUT_UNRECOGNIZED` | An export is not a graph, seed or scenario. |
| `FLOW_MAP_UNREADABLE` | The flow map is not readable JSON. Prose, Markdown and Mermaid maps are N5's job. |
| `FLOW_MAP_NOT_OBJECT` | The flow map is not an object with a `components` list. |
| `NORMALIZATION_FAILED` | Normalization raised on inputs that passed the checks above. |

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
| `component_bound` | Flow map **supplied and joined**, whatever its lineage; component matched by ID; technologies **and** authentication both non-empty | Product-named log sources; `logsource.product` may be set |
| `component_bound_partial` | Same, but the matched component has empty `technologies` or `authentication` | Zone, exposure and boundary facts may be used; `logsource.product` stays unset and the missing field is named in `telemetry_requirements[]` |
| `asset_named` | Component ID present, no flow map supplied | Behaviour-level sources only; `logsource.definition` describes required collection, `product` stays unset |
| `asset_text_only` | Scenario-only input, asset name but no component ID | Conditional design; the plan's existing rule that a guessed ID must not become a join key |
| `unbound` | No component and no asset | Draft still produced, telemetry section is a declared gap |

**The hash neither grants nor withholds a grade** (decision 9). Two conditions
must hold: the operator supplied a map, **and** the node's `component_id`
resolved to a component in it. An export carrying a `flow_map_sha256` but run
without the map is `asset_named` — the hash records which map the projection
used, not any binding that happened. A map whose hash differs grades exactly
as a matching one would; the difference is carried as `flow_map_lineage:
edited_map` so a draft can say what it rests on. Likewise a scenario-only
input stays `asset_text_only` no matter what provenance accompanies it, because
it carries no `component_id` to join on.

`component_bound_partial` is a real case, not a defensive placeholder. **As of
the 2026-09-17 corpus it is exercised by real exports** — 5 nodes across the
two new applications land on components declaring no `technologies` or
`authentication: none`: `front_door` and `users` on Application B,
`claims_db` and `doc_store` on Claims Portal. (The observation that first
motivated the grade still stands: in `examples/telemetry_saas_flow_map.json`
two of ten components declare no technologies — `alb`, also
`authentication: none`, and `artifact_reg` — and no fixture's nodes land on
either, so the telemetry pairs alone would still leave it untested.)
Collapsing it into
`component_bound` would let a draft name a product for a component that
declares none; collapsing it into `asset_named` would discard a verified zone
and boundary. It is its own grade because it permits a strict subset.

`normalize_paths` reports the grade distribution. **Revised Stage 1 gate:**
graph-only and seed-only input produce the same node keys in the same order
*and* a completeness grade per node, with a declared field-level diff between
the two — not merely the same count. **Restated over the 2026-09-17 corpus:**
with the map supplied, all 43 nodes grade `component_bound` or
`component_bound_partial` (38 / 5); with the map withheld, all 43 grade
`asset_named`; from seed-only input all 43 grade `asset_text_only`, because
the seed carries `target_asset` and no `component_id`. The grade is a property
of the inputs supplied, not of the export, and the same export must produce
three different distributions across those three calls.

This is also the honest answer to the designer plan's §1 note that neither
export embeds a technology inventory: the tool does not invent one, it
reports which grade it is working at and constrains the drafts accordingly.

---

## 6. Staging

Normalization first and separately; guidance builds on the pack.

| Stage | Deliverable | Acceptance gate |
|---|---|---|
| **N1. Adapters and identity** | Graph, seed and single-scenario adapters; the three identities of §4.2a; `(projection_identity, path_id, node_index)` keys; deterministic `draft_id`; union merge with the §4.3 precedence table including the 3a `state_check` **and `transition`** canonicalizations; `provenance_by_field` | All four fixtures normalize graph-only and seed-only to identical ordered node keys (9, 11, 10, 13 — **43** in all). All four carry provenance, so the `run_id` join is the normal path and §4.2's derived-identity path has no fixture — it is covered by the §7a synthetic pair. A repeated `(technique, component)` inside one path stays distinct on the §7 synthetic case; the three cross-path repeats in `124121` survive as distinct nodes. `AE-0001` recurring per path never collides. Every field carries an origin and pointer. No pair joins without `verified` or an explicit operator assertion. |
| **N2. Provenance** — **closed 2026-09-19** | Projector `provenance` block (§4.1) — built 2026-09-16; designer-side pair handling (§4.2) — built in N1; flow-map lineage, application and component-fit checks (§4.2, decision 9); the §4.4 code catalogue | A graph from one run and a seed from another are refused as a pair. A supplied flow map is recorded as `same_map`, `edited_map` or `unhashed` and **never refused**; the four fixture exports reproduce their recorded `flow_map_sha256` from the repository maps. Every field carries an origin and pointer. Every emitted code is in §4.4. |
| **N3. Enrichment and grading** — built in slices: **N3a** flow-map join and grades and **N3b** controls landed 2026-09-19; N3c mitigations and N3d taxonomy outstanding | Flow-map join, control catalogue, mitigation-name resolution, the §1.4b focus cut and coverage ratio, taxonomy reconciliation, completeness grades | `Stealth` survives against v19.2. `uncovered_mitigations` resolve to names locally. `mitigation_focus[]` is the 1–2 narrowest by technique breadth, deterministic and tie-broken by M-ID. Grades match §5 across all four fixtures with and without the flow map — 38 `component_bound`, 5 `component_bound_partial`, and 43 `asset_named` when the map is withheld. The two `TACTIC_CORRECTED` relabels in `124121` and the one in `022646` survive normalization. |
| **N4. Context pack artifact** | `normalize_paths` action, pack schema, registration, CLI `show`/`export`, bounded `summarize_for_llm` | Pack round-trips; re-normalizing the same inputs is byte-identical apart from run ID and timestamp; the summary states counts, grades and conflicts without pasting node bodies. Input by `artifact_ids` and output as a registered artifact are **done in N1** (decision 8); what N4 adds is the pack's own schema and `metadata.kind`, not persistence — the shell already auto-persists a result that registers nothing. |
| **N5. `normalize_flow_map`** | The projector's own Phase 4 action | Prose/Markdown/Mermaid → canonical flow map JSON with a stable `_canonical_flow_map_hash`. An unstated control status becomes `partial` and is flagged, never `implemented` — the rule already recorded in `docs/change_log/2026-09-11-adversary-path-projector-phase-3.md`. This is what makes `component_bound` routinely reachable. |
| **G1…** | Grounding, generation, workbook — designer plan stages 2–5, unchanged except that they consume a pack | As in the designer plan, with the node-count constants replaced by pack inventory. |

N1–N4 need no provider and no cost. N5 is projector work and can run in
parallel; the designer degrades to `asset_named` without it, which is a
documented state rather than a failure.

**Where N1's code lands.** One plugin directory under
`plugins/threat_modeling/`, holding both `normalize_paths` and the later
`generate_detections`, with `safe_for_auto_invoke: false` — decision 7, §8. The
normalization library is plugin-local, not a `framework/` module, and nothing
in it may be imported by another plugin. N1 may therefore create the plugin
directory and manifest up front even though the action itself is N4; the
adapters are ordinary modules beside `tool.py` until then.

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
  `T1078` twice and `T1552.001` twice inside `helpdesk-oracle-onprem`
  (`T1078.004` at step 3 is a distinct ID), and three consecutive steps on
  `oracle_int`. Assert 24 distinct node keys and that a dedupe on
  `(technique_id, path_id)` fails. Corrected 2026-09-17 from "three times
  each"; see §1.1.
- **A synthetic within-path `(technique, component)` repeat.** Required,
  because no real fixture exercises it: pairs repeat only *across* paths in
  `204815`, so a within-path dedupe passes every fixture today while violating
  §1.1's identity rule. Build it in-repo by deriving from
  `helpdesk-oracle-onprem` and relabelling step 8 from `T1552.001@oracle_int`
  to `T1078@oracle_int`, which duplicates step 6 exactly. Assert both
  occurrences survive with distinct `node_index` and distinct `draft_id`, and
  that no warning is raised — a repeated pair is legitimate modelling, not a
  defect. Derive it in the test module from the committed fixture rather than
  storing a near-duplicate 24-node file.
- **Cross-fixture contamination.** Normalizing the 165537 graph with the
  204815 seed must be refused, not merged — different actor, application and
  path IDs, and today nothing but those strings prevents it.
- **Union merge.** For a node present in both exports, assert every field in
  the §1.3 graph-only and seed-only lists survives, each with the right
  `provenance_by_field` origin.
- **Precedence conflict.** Mutate one shared field in the seed copy; assert a
  conflict record with both pointers, the graph value retained, and the pair
  join not reported `verified`.
- **Legacy provenance.** `165537` and `204815` lack `provenance`; assert
  `provenance_status: derived`, and that a pair join requires the explicit
  operator flag. `192507` and `022646` carry it; assert they join on `run_id`
  without the flag. Pairing one legacy document with one verified document is
  refused outright (§4.2).
- **Flow map lineage** (decision 9). The repository maps reproduce each
  fixture's `flow_map_sha256` and read `same_map`; an edited copy reads
  `edited_map` with an advisory warning and is **not** refused; an export
  stripped of its hash reads `unhashed` without any operator flag. A map for a
  different application raises `FLOW_MAP_APPLICATION_MISMATCH`, and a
  component missing from the map raises `FLOW_MAP_COMPONENT_UNRESOLVED`.
- **All three transition shapes**, including both readings of `null`: a
  same-component step becomes `movement: in_place`, and a component change with
  no declared flow becomes `movement: undeclared` and raises a review flag.
  Neither may be reported as absent data.
- **A gap at `component_bound` grade.** `20260917_022646` / `scm-to-vault`
  step 2 carries `state_check: gap` on a node with full component context.
  Assert the gap survives enrichment and forces `multistep_access: true` — a
  richer context must never read as a resolved access dependency.
- **A reconciled tactic survives.** The same pair's step 4 records `T1078`
  corrected from Initial Access to `Stealth`. Assert the correction and its
  note are preserved, and that normalization does not re-decide it.
- **Completeness grading** across all five grades, including a scenario-only
  run reaching `asset_text_only` with `component_id: null`, and a
  `component_bound_partial` case built against `alb` or `artifact_reg`, which
  declare no technologies. Assert that an export carrying `flow_map_sha256`
  but normalized **without** the map grades `asset_named`, not
  `component_bound` — the hash is not the binding.
- **Provenance field names, read from the export not the draft.** Assert
  `actor_attack_id` and `model.provider` populate, that `provenance.provider`
  is absent rather than null, and that a normalizer reading the old names
  yields a detectable failure rather than a silent "no attribution" on
  `192507` and `022646`. Assert `run_index` is carried.
- **The three identities are distinct.** On a verified pair assert
  `artifact_identity` differs between graph and seed while
  `projection_identity` is equal; on a legacy pair assert graph-only and
  seed-only input derive the **same** `projection_identity` and therefore the
  same ordered node keys, while `provenance_status` stays `derived` and the
  join still requires `--accept_unverified_pair`. Assert `draft_id` is
  unchanged by which document supplied it.
- **`state_check` canonicalization.** Over all 58 nodes assert 58 matches and
  0 conflicts under the §4.3 3a rule, that the 6 gap nodes are the only ones
  exercising the note branch, that the seed's combined string is retained raw,
  and that the outcome is `pair_agreed`. Assert a hyphen-for-em-dash mutation
  raises an encoding warning, not 6 content conflicts.
- **Taxonomy.** `Stealth` unchanged against v19.2; a deliberately retired ID
  is remapped through `resolve_retired_technique` with the remap recorded,
  never guessed.
- **Mitigation resolution.** `uncovered_mitigations` names come from
  `mitre_relationships.json`; an unknown M-ID is reported, not invented.
- **The focus cut is deterministic and correctly ordered.** On `022646`
  `web-exploit-to-db` step 1 (`T1190`), `mitigation_focus[]` is M1016 (breadth
  5) then M1048 (14), and excludes M1026 (112). Ties on breadth break by M-ID
  ascending, so re-running yields a byte-identical list. An M-ID absent from
  the reference data is excluded from the ranking and reported, never ranked
  at an assumed breadth.
- **Focus never becomes a coverage claim.** Assert `mitigation_focus[]` is
  absent from any rendered detection rationale, and that a node whose
  uncovered mitigations are all broad yields an empty focus list with no
  warning — an empty cut is a normal outcome, not missing data.
- **Generation is not given the full list.** Assert the generation input
  contains `mitigation_focus[]`, `mitigations_covered[]` and
  `mitigation_coverage`, and contains neither `uncovered_mitigations[]` nor
  `mitigations[]`, while the persisted pack contains all five.
- **The covered half is carried.** Across `165537`, `192507` and `022646`
  exactly 7 of 154 mitigations are covered; assert each lands in
  `mitigations_covered[]` on its node and that `mitigation_coverage.tag_caveat`
  reproduces the projector's `control_tagging` counts, so "uncovered" can never
  be read as "no control exists".
- **`DS####` rejection** anywhere in a normalized or generated record.
- **Determinism.** Same inputs → identical pack apart from run ID and
  timestamp; `draft_id` stable across runs and unchanged by the presence of
  optional context.

### 7a. Re-targeting after the 2026-09-17 corpus change

The list above names retired fixtures in several places. Each such test keeps
its intent; only its subject moves. Where the new corpus cannot supply a
subject, the test becomes synthetic rather than being dropped — the properties
were chosen because they are dangerous, not because a file happened to have
them.

| Test as written | Subject now |
|---|---|
| "Fixture 2 as a first-class fixture" — 24 nodes, three path lengths, within-path technique repeats | **No equivalent exists.** Longest real path is 7 (`124121`), all graphs have 2 paths, and no pair repeats a technique within a path. Replaced by `124121` as the largest fixture (13 nodes) plus the synthetic within-path case below, which is now the *only* cover for the rule. |
| Synthetic within-path `(technique, component)` repeat | Unchanged in intent; derive it from `124121` / `portal-api-docstore` instead of `helpdesk-oracle-onprem`. Still required, and now load-bearing. |
| Cross-fixture contamination (`165537` graph + `204815` seed) | `123525` graph + `124121` seed — different actor, application, flow map hash and `run_id`. A stronger case than the original, which differed on no hash at all. |
| Legacy provenance: `165537` / `204815` lack `provenance` | **No fixture lacks provenance any more.** Build the legacy case synthetically by deleting the `provenance` key from a copy of `122549`, and assert both that it refuses to join without `--accept_unverified_pair` and that graph-only and seed-only derive an equal `projection_identity`. §4.2 stays required for exports already in the wild. |
| The mixed pair (one document with provenance, one without) | Same construction, deleting the key from one side only. |
| Cross-run pair refusal on `run_id` | `022646` graph + `122549` seed: same flow map, same hash, same application, different actor and `run_id`. The hash matching makes this the case a naive check passes. |
| `state_check` canonicalization at 58 / 6 gap nodes | 43 / 9 gap nodes (§4.3 3a). |
| Covered mitigations: 7 of 154 across three pairs | **6 of 169** across the four current pairs, 163 uncovered, 3.9 per node. |
| Gap at `component_bound` grade: `022646` / `scm-to-vault` | Unchanged, and now joined by 8 more gap nodes, including 3 at `component_bound_partial` grade. |
| `run_index` carried, `192507` and `022646` | All four pairs; all read `run_group: ungrouped`, `run_index: 1`, so the grouped case is still untested by any fixture. |

Two tests the new corpus makes possible that the old one did not:

- **`component_bound_partial` from real data.** 5 nodes (§1.1b). Assert they
  grade partial with the map supplied, that `logsource.product` stays unset,
  and that the missing field is named in `telemetry_requirements[]`.
- **Actor is the only variable.** `022646` and `122549` share the flow map,
  its hash, the application and the code. Assert their node keys do not
  collide and that `projection_identity` differs, i.e. that identity derives
  from the projection and not from the estate.

One test the new corpus removes the subject for, which must be recorded rather
than silently lost: **`git_worktree` code identity** is no longer present in
any fixture — all four read `code_id_source: build_env`. With `unavailable`
also unobserved, two of the three branches of the code-identity change now
have unit coverage only.

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
   record. The designer-side legacy handling of §4.2 was N2 work — it shipped
   with N1's pair gating, and N2 closed 2026-09-19 under decision 9 — and
   remains necessary: the two fixtures existing at that date, `165537` and
   `204815`, predate the change and always will. The two added since carry the
   block.
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

Decision taken, 2026-09-17 (operator):

4. **`uncovered_mitigations` stops being treated as a coverage finding.**
   Raised on the ground that defenders never implement every mitigation, so a
   full uncovered list is a distraction. Measurement agreed and went further —
   the field is ~95% identical to `mitigations`, its most frequent members are
   ATT&CK's broadest, and it is component-blind. Neither of the two narrowing
   filters that were asked about is available locally: mitigations carry no
   data-source link, and the actor constraint is already applied upstream when
   the path is built. Resolved by splitting the audience rather than the data —
   the pack keeps everything, generation reads only `mitigation_focus[]`,
   `mitigations_covered[]` and the ratio. Recorded in §1.4b; change log
   `docs/change_log/2026-09-17-mitigation-focus.md`.

5. **The N1 contract is closed before N1 is written.** Six issues found by
   re-reading the fixtures against this document were reconciled rather than
   left for implementation to discover, because each one would have been
   encoded into the first test file and then defended. Two were
   self-contradictions in the spec (`source_identity` could not satisfy its own
   N1 gate; `state_check` equality would have failed on all 58 nodes), two were
   drift from the exports (`actor_attck_id`, `provider`), one was a grade that
   a hash alone could wrongly confer, and one was a fixture assertion that did
   not match the fixture. Change log
   `docs/change_log/2026-09-17-n1-contract-fixes.md`.

Decision taken, 2026-09-17 (operator), later the same day:

6. **The fixture corpus is replaced, and the retired pairs may be deleted from
   the data store.** Three runs were made against the current code — Scattered
   Spider on the telemetry map, APT29 on Application B, Volt Typhoon on Claims
   Portal — joining `20260917_022646` to give four pairs on one code revision.
   `20260915_165537`, `20260915_204815` and `20260916_192507` are retired.

   **This resolves the second of the two decisions that gated N1.** That
   blocker was provenance of the *content*: two legacy pairs named
   applications and actors not confirmed synthetic, and CLAUDE.md forbids
   committing tenant identifiers. Every pair in the new corpus was projected
   against a flow map already in the repository —
   `telemetry_saas_flow_map.json`, `application_b_flow_map.json`,
   `claims_portal_flow_map.json` — so the applications are the repository's own
   examples and the question does not arise. Copies of the four pairs may be
   committed under repository tests, and the path-presence skip the earlier
   decision contemplated is no longer needed.

   The other decision is resolved separately, as decision 7 below.

   The cost of the refresh is recorded in §7a — the 10-step path, the
   three-path graph, the within-path repeats, the no-provenance case and the
   `git_worktree` code-identity branch all lose their real subject and become
   synthetic constructions — and the producer-side shape the new counts come
   from is `docs/specs/projector_export_shapes.md`.

7. **`normalize_paths` and `generate_detections` are one plugin, declared
   `safe_for_auto_invoke: false`.** This was the last decision blocking N1, and
   it decides where the normalization library physically lives: inside a single
   plugin directory, not in `framework/` and not duplicated across two plugins.
   §2 is corrected accordingly.

   **The constraint.** `safe_for_auto_invoke` is one boolean per plugin.
   `docs/specs/manifest_schema.json` has no `actions` property and sets
   `additionalProperties: false`; `framework/plugins/loader.py:67` reads a
   single boolean. §2's original `safe_for_auto_invoke: true` for a single
   action was therefore unimplementable as written.

   **Why one plugin rather than two.** Decision 2 says `generate_detections`
   accepts a raw export as well as a pack, so **both** actions need the
   normalization library. No plugin in this repository imports another — the
   loader imports each under a flat module name
   (`eventmill_plugin_<pillar>_<tool>`) specifically to avoid parent-package
   lookups, and plugins share code only through `framework.*`. A two-plugin
   split would therefore force one of: moving detection-specific normalization
   into `framework/` (which holds cross-cutting infrastructure — reference
   data, LLM, documents — not one feature's logic), duplicating it, or
   reversing decision 2 so generation only ever accepts a pack. None is worth
   the flag.

   **What it costs, stated plainly.** A free, deterministic, provider-less
   action sits in a plugin the manifest does not mark auto-invocable, and the
   router surfaces one catalog entry rather than two — so normalization is not
   independently discoverable. **Today that cost is unobservable**: nothing in
   the framework reads `safe_for_auto_invoke`. The only non-test reference in
   the tree is the assignment in `loader.py`; routing scores on `capabilities`,
   `tags`, `artifacts_consumed`, `chains_to` and `also_useful_in`. The field is
   declarative intent, not a live gate.

   **What was rejected, and what would reopen it.** Widening the manifest
   schema for a per-action flag was rejected *for now*, not on principle: it is
   a change to visibility and invoke policy, `additionalProperties: false`
   means an unregistered field fails validation for every plugin at once, and
   no caller reads the field yet, so there is no evidence to design it against
   — the same reasoning that forbids widening the `stability` enum to silence
   the validator. If `safe_for_auto_invoke` becomes a live gate and this action
   is the case that proves per-action granularity is needed, that is when to
   make the change, with a real caller to test it.

   Precedent: `adversary_path_projector` already mixes free deterministic
   actions (`profile_actor`, `validate_flow_map`) with a heavy-tier
   `project_paths` under a single `safe_for_auto_invoke: false`.

Decision taken, 2026-09-17 (operator), after N1 was built:

8. **Artifacts are the input and output route for the first working version of
   detection generation, through this plugin.** Registered artifacts, resolved
   through `context.artifacts`, rather than file paths passed by hand.
   Implemented in N1 and confirmed end to end in the running shell:

   ```text
   run attack_path_detection_designer --artifact_ids art_e2697614,art_2df55952
     ✓ Completed successfully
     Normalized 10 nodes across 2 paths.
     Pair: run_id (provenance verified, verified=True).
   ```

   **Why this and not file paths.** In the container an export is auto-exported
   to the common bucket and only the registry knows where it landed, so a path
   is not a usable handle there. The artifact route is also what lets the chain
   run without an operator in the middle: the projector registers its two
   exports, the designer consumes them by id, and its own result is registered
   in turn. `chains_from: adversary_path_projector` states that relationship
   where the router can read it.

   **What follows from it.** Three things are settled rather than open. File
   paths stay supported but are a local convenience, not the contract. An
   artifact that is registered but whose bytes are unreadable here is its own
   reported condition — `ARTIFACT_UNAVAILABLE`, naming the `storage_uri` —
   because on Cloud Run that is a real state and must not read as a missing
   file or as an empty result. And the shell already auto-persists a result
   that registers no artifact of its own, so a result is an artifact before N4
   exists; N4's remaining work is the pack's schema and `metadata.kind`, not
   persistence. Adding the tool to `DEFAULT_AUTO_EXPORT_TOOLS` (currently only
   `attack_path_visualizer`) is what makes a container run's output leave the
   container.

   **Untested:** whether `artifact.file_path` points at readable bytes on Cloud
   Run. If it does not, the condition is reported precisely, but fetching from
   the bucket would need the storage resolver, which plugins do not receive.
   Change log `docs/change_log/2026-09-17-artifact-input-route.md`.

Decision taken, 2026-09-19 (operator):

9. **A flow map's hash is lineage, not an integrity gate.** The map is not a
   forensic copy. An analyst with inside information is expected to copy a
   generated map and correct it; git is the recommended way to track those
   edits; and a tampered map passed around is not a meaningful risk in this
   workflow. The 2026-09-16 rows of §4.2 — a mismatched hash refuses
   enrichment, a missing hash needs an operator assertion — would have
   penalised exactly that workflow, and §5 made a hash match a condition of
   `component_bound`.

   **What replaced them.** The lineage (`same_map` / `edited_map` /
   `unhashed`) is recorded and warned on, never refused. The check the hash
   had been standing in for — does this map fit this projection — is made
   directly: the map's application against the export's, and every node's
   `component_id` against the map's components. Both are advisory at the level
   of the whole map; an unresolved component withholds enrichment from its own
   nodes only. §4.3 rule 4 already keeps an edited map from overwriting an
   export value.

   **What it does not change.** The pair rows of §4.2. The `run_id` join
   protects against merging two runs into one context, not against tampering,
   and stays strict.

   **Deliberately left out.** Recording the map's git commit or blob id when it
   lives in a working tree would say *which* edit a draft rests on, not only
   that it was edited. Not built; reopen when a reviewer needs to trace a draft
   to a specific revision of the map.

   Change log `docs/change_log/2026-09-19-n2-flow-map-lineage.md`.

Decisions taken, 2026-09-19 (operator), when N3 was planned:

10. **A control catalogue entry attaches to a node by component, and by name
    plus component id when there is no map.** §1.4 assumes the seed's
    `security_controls[]` can be read per node; nothing in the documents
    supports that directly. A catalogue entry carries `control_id`, `name`,
    `detection_capability` and a *description* — `"Protects CDN (cdn)."` — and
    the graph's `controls_in_play` carries a name and no id. So:

    - **With a flow map**, the join is structural and needs no matching: the
      map's component owns its controls, with `detection_capability`,
      `bypass_difficulty` and `mitre_mitigation_id` on each. Origin
      `flow_map`, carrying the lineage of §4.2.
    - **Without one**, a `controls_in_play` name is matched against catalogue
      entries whose description names that node's `component_id` in
      parentheses. The match is recorded `evidence: text` and may never
      outrank the map — the same treatment §3 gives the seed's transition
      prose. A name that matches no entry, or matches one written for another
      component, is left unattached rather than guessed.

    Name matching alone was rejected: control names repeat across components
    (`WAF` protects two in Claims Portal), so it would attach one component's
    `detection_capability` to another's node.

11. **`mitigation_coverage.tag_caveat` is computed from the supplied flow map,
    or is null.** §1.4b says it reproduces the projector's `control_tagging`
    counts. **Neither export carries them** — they exist in the tool result and
    the run record only, and one of the four pairs has no run record, so it can
    never be a required input. The projector derives them from the map
    (`tool.py:1824`), which the designer can do identically: controls on the
    targeted components, and how many carry a `mitre_mitigation_id`. With no
    map, `tag_caveat` is `null` with a stated reason; a null caveat must never
    read as "every control is tagged". The counts are stamped with the map's
    lineage, so an edited map yields the caveat for the estate the analyst
    corrected.

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

Extended 2026-09-17 for §1.4b. The mitigation counts, the covered/uncovered
ratio, the technique-breadth figures and the `T1190` worked example were
computed from the four export pairs and
`framework/reference_data/mitre_relationships.json` at that date; the
component-scoped derivation was read at
`plugins/threat_modeling/adversary_path_projector/tool.py:2042-2063` and its
caveat at `tool.py:4593`. Still no code changed and no LLM run performed.

Six contract issues raised in the same review were applied later the same day:
the `actor_attack_id` / `model` provenance names (§4.1), the three identities
replacing `source_identity` (§4.2a), the `state_check` split/join (§4.3 3a),
control meaning (§1.4b), `component_bound` completeness and the new
`component_bound_partial` grade (§5), and the corrected repeat-count
assertions with the synthetic within-path case (§1.1, §7). Each was checked
against the fixtures before being written: the provenance key set and the
absence of a `provenance` key, the 58-of-58 `state_check` canonicalization and
its six gap nodes, the zero within-path `(technique, component)` repeats, and
the two technology-less components in the example flow map. Still no code
changed and no LLM run performed.

**Corpus refresh, 2026-09-17 (later).** Three new projector runs were made by
the operator against the current code; this document was revised, not
re-derived. Both exports of all four current pairs and the three run records
were parsed with `encoding="utf-8"` and diffed field by field; every
`component_id` was resolved against the three flow maps in
`plugins/threat_modeling/adversary_path_projector/examples/`; mitigation
breadth was recomputed from `mitre_relationships.json`. Restated here: §1.1b,
the §4.3 3a counts and the new `transition` canonicalization rule, the §5
grade distributions and the `component_bound_partial` evidence, the §6 N1 and
N3 gates, the new §7a, and decision 6. §§1.1–1.6 were **not** rewritten — they
are dated to the retired corpus by §0, and their findings still stand even
where their counts no longer do. Everything measured is set out once in
`docs/specs/projector_export_shapes.md`. No code changed, no test run, no LLM
call made in this revision.

**After N1, 2026-09-17.** The claims in decision 8 were checked in the code
before being written: `do_run`'s `artifact_id` handling and its injection of
`file_path`/`path` (`framework/cli/shell.py:2925-2932`), the auto-persistence
of a result that registers nothing (`shell.py:3105-3110`), the auto-export
gate and its `DEFAULT_AUTO_EXPORT_TOOLS` default of `attack_path_visualizer`
(`shell.py:932`, `1061-1072`), and `context.artifacts` as the only artifact
handle a plugin receives (`framework/plugins/protocol.py:256-287`). The shell
transcript quoted there is a real run against two registered fixtures. Suite
1597 passing.

**Decision 7, 2026-09-17 (later still).** Before recommending a plugin shape,
four things were read rather than recalled: `manifest_schema.json` (38
top-level properties, no `actions`, `additionalProperties: false`);
`framework/plugins/loader.py:67`; a tree-wide search for `auto_invoke`, which
returns only that assignment outside tests and the `build/` copy; and the
routing modules' manifest field usage (`capabilities`, `tags`,
`artifacts_consumed`, `chains_to`, `also_useful_in` — the flag is not among
them). Cross-plugin imports were checked for and do not exist: plugins import
shared code only from `framework.*`. The projector's own manifest was read for
the precedent. §2 and §6 were then corrected and decision 7 recorded. **N1 is
now unblocked.** Still no code changed, no test run, no LLM call made.

**N2, 2026-09-19.** Decision 9 came from the operator; everything built on it
was checked first. The projector's `_canonical_flow_map_hash`
(`adversary_path_projector/tool.py:467`) was read and its serialisation
compared with the designer's `canonical_json`; the three repository maps were
then hashed and matched the `flow_map_sha256` recorded in all eight fixture
documents, which is now a test. The application names and component ids of
the three maps were read against the four exports before the fit checks were
written. The §4.4 catalogue was taken from every code the module actually
emitted, not written first. `framework/cli/shell.py` `_plugin_input_schema`
was read to confirm the shell takes its flags from the input schema. Suite
1597 → 1635. No shell run and no LLM call.

**N3a and N3b, 2026-09-19.** The §5 gate was recomputed from the four fixtures
and the three repository maps before the grading code existed — 38 / 5 with the
map, 43 `asset_named` without, 43 `asset_text_only` seed-only — and the five
partial components identified (`users`, `front_door`, `claims_db`,
`doc_store`). Decisions 10 and 11 came from reading the documents rather than
the spec: the seed's `security_controls[]` entries were checked for a component
key and have none but the parenthesised id in their description, the graph's
`controls_in_play` for an id and has none, the Claims Portal map for a repeated
control name (`WAF`, on two components), and both exports for `control_tagging`,
which is absent from each. `mitre_attack.py` was checked for the taxonomy
helpers N3d will use, and the corpus's mitigation coverage recomputed at 6 of
169 with no unresolvable M-ID. Suite 1635 → 1652. No shell run and no LLM
call; the operator will test N2 and N3a/N3b against uploaded artifacts.
