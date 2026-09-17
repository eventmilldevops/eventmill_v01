# Adversary path projector output shapes — the three-document contract

Status: descriptive. This document states what the projector **emits today**,
measured field by field against a live corpus; it proposes nothing.
Date: 2026-09-17.
Code under measurement: `git_sha 1c2ba74`, projector manifest `0.2.0`, run
record `schema_version 5`, ATT&CK lookup `19.2`.
Purpose: give the normalization work (`attack_path_detection_normalization.md`)
and any later schema change one place that describes the producer, so a
consumer-side plan never has to re-derive the shape from a single fixture
again. Every count below is computed from the corpus in §1, not quoted from an
earlier plan.

---

## 1. The corpus this describes

Four projection runs, all on the same code, all against flow maps that live in
the repository under
`plugins/threat_modeling/adversary_path_projector/examples/`. The three earlier
runs (`20260915_165537`, `20260915_204815`, `20260916_192507`) are retired and
are **not** described here; they were produced before the provenance block, the
v19.2 tactic reconciliation, or both, and their shape is no longer the
producer's shape.

| Run | Actor | Application / flow map | Paths | Nodes | Gaps | Documents |
|---|---|---|---:|---:|---:|---|
| `20260917_022646` | Fox Kitten (G0117) | Fleet Telemetry Platform / `telemetry_saas_flow_map.json` | 2 (5+4) | 9 | 1 | graph, seed |
| `20260917_122549` | Scattered Spider (G1015) | Fleet Telemetry Platform / `telemetry_saas_flow_map.json` | 2 (5+6) | 11 | 3 | graph, seed, run record |
| `20260917_123525` | APT29 (G0016) | Application B / `application_b_flow_map.json` | 2 (4+6) | 10 | 3 | graph, seed, run record |
| `20260917_124121` | Volt Typhoon (G1017) | Claims Portal / `claims_portal_flow_map.json` | 2 (7+6) | 13 | 2 | graph, seed, run record |

**43 nodes over 8 paths.** Two applications are new to the corpus; the two
telemetry runs differ only in actor, which is the one controlled comparison the
set contains.

Three properties of the set matter more than its size:

- **Every run resolved every `component_id` in the supplied flow map.** 43 of
  43. The `asset_named` degradation is now unexercised by any current export,
  and only reachable by normalizing without the map.
- **All four carry `tool_version.code_id_source: build_env`** with the same
  `git_sha`. The `git_worktree` branch of the code-identity change is no longer
  exercised by any fixture, and `unavailable` never has been.
- **Each of the three runs with a run record returned 2 paths against
  `max_paths: 3`.** Path count is a model outcome, not a configured constant,
  and nothing downstream may assume it.

---

## 2. Three documents per run, one identity

A projection emits up to three JSON documents, which are separate artifacts
with separate names and no containing envelope:

| Document | File stem | Emitted | Carries |
|---|---|---|---|
| **Path graph** | `adversary_path_graph_<ts>` | always | the projection as a graph of steps bound to components |
| **Scenario seed** | `adversary_scenario_seed_<ts>` | always | the same projection restated as importable scenarios with a control catalogue |
| **Run record** | `adversary_projection_run_<ts>_<run8>` | per run | inputs, deterministic pre-analysis, model call outcome, warnings |

The graph and the seed are **two renderings of one projection**, not a document
and its summary. They share `path_id`, step order and step count exactly, and
each carries fields the other does not (§7). The run record is the only one
naming the raw response file, the token spend and the deterministic analysis
the model never saw the output of.

`<ts>` is a UTC run stamp, so re-runs accumulate rather than overwrite. The run
record's file name additionally carries the first 8 characters of `run_id`; the
graph and seed do not, so a directory holding two runs of the same second would
collide — unobserved, but the naming permits it.

---

## 3. The common envelope

Graph and seed share five top-level keys before their payload:

```text
source_tool    "adversary_path_projector"
status         "projected"
interpretation a fixed paragraph stating what is sourced and what is projected
actor          "<Name> (<Gxxxx>)"     resolved, not the operator's input string
application    the flow map's application name
provenance     { … }                  §3.1
```

`interpretation` is byte-identical across all four runs and is the tool's own
disclaimer — technique ids, names and controls are sourced; route, rationale
and access states are the model's projection; access is checked for continuity
only. It contains a **U+2014 em dash**, which makes the envelope itself an
encoding canary for any transport (see §7.2).

### 3.1 `provenance`

Eleven keys, identical in graph and seed, minted once per projection:

```text
run_id            uuid4, shared by graph, seed and run record
run_group         "ungrouped" unless the operator grouped the run
run_index         1-based position within the group
created_at        ISO-8601 UTC with offset
flow_map_path     repo-relative path as supplied
flow_map_sha256   hash of the canonicalized map, not of the file on disk
prompt_sha256     hash of the rendered prompt
attack_version    "19.2"
actor_attack_id   "G1015"          — note: not actor_attck_id
tool_version      { manifest_version, git_sha, code_id_source }
model             { provider, vendor, model_configured, model_served }
```

There is **no `provider` key at this level**; vendor attribution lives inside
`model`, with `model_configured` and `model_served` kept apart so a served
substitution stays visible. `flow_map_sha256` is stable across runs against the
same map (`5de20d4b…` on both telemetry runs) and differs per map, but it does
**not** equal the SHA-256 of the file's bytes — it is computed over the
canonicalized content, so a consumer verifying a binding must canonicalize the
same way rather than hashing the file.

---

## 4. Path graph

```text
attack_graph
  paths[]              path_id, description, objective, steps[]
  convergence_points[] technique ids reached by more than one path
  branch_points[]      technique ids from which paths diverge
mitre_mappings[]       technique_id, technique_name, tactic, confidence
```

`mitre_mappings` is the de-duplicated technique set of the paths, restated with
a confidence grade. Across all four runs it is **exactly** the set of technique
ids used in the steps — no extra, none missing — so it is a projection of the
steps, not an independent field, and a consumer must not treat a discrepancy as
data. Convergence and branch points are populated only where paths actually
meet: 0/0 on both telemetry runs, 2/0 on Application B, 3/1 on Claims Portal.

### 4.1 The step

25 fields, in five groups. Nothing is optional in the key sense — every step in
the corpus carries all 25 — but several are routinely empty.

| Group | Fields | Notes |
|---|---|---|
| **Technique** | `technique_id`, `technique_name`, `tactic`, `evidence` | `tactic` is reconciled against the v19.2 lookup after the model answers (§8.1) |
| **Placement** | `component_id`, `asset` | `component_id` joins the flow map; `asset` is the human name |
| **Narrative** | `rationale`, `notes[]`, `assumptions[]`, `control_note`, `procedure_excerpt` | `procedure_excerpt` is sourced from ATT&CK; the rest are the model's |
| **State** | `precondition`, `access_before`, `exploited_condition`, `result`, `access_after`, `state_check`, `state_note` | the continuity model; `state_check` ∈ `ok` \| `gap` |
| **Topology and coverage** | `transition`, `leads_to[]`, `controls_in_play[]`, `mitigations[]`, `uncovered_mitigations[]`, `actor_support` | |

Measured over the 43 nodes:

- `evidence` / `actor_support`: 42 `documented` / `procedure_documented`,
  1 `via_software`. The two fields moved together on every node in the corpus.
- `procedure_excerpt` is non-empty on all 43.
- `notes[]` non-empty on 13; `state_check: gap` on 9.
- `leads_to` holds 35 edges and **0 of them dangle** — every target technique
  id appears in the same run's paths.
- `controls_in_play`: 65 entries over 34 nodes; 9 nodes carry none.
  Status distribution `implemented` 43, `partial` 15, `missing` 4, `planned` 3.
  **`on` is `component` on all 65** — the flow-scoped form the field allows has
  never been produced.

### 4.2 `transition` has three shapes and four meanings

| Shape | Count | Meaning |
|---|---:|---|
| `{entry: true, exposure: …}` | 8 | the path's first step; no originating component |
| `{flow, from, to, protocol, authenticated, crosses_boundary, return?}` | 18 | movement along a declared flow (14 cross a boundary; 1 is a `return`) |
| `null`, same `component_id` as predecessor | 16 | the actor acting **in place** on a component it already holds |
| `null`, different `component_id` | 1 | movement the flow map does not declare |

The last two are the same JSON value with opposite meanings, and only the
predecessor's `component_id` separates them. The single undeclared case
(`123525` / `phishing-to-blob` step 3, `okta` → `entry_api`) is the one the run
record reports as `HOP_NOT_DECLARED`. `port` exists on flow-map flows but never
on a step's `transition`; it is reachable only through the map join.

### 4.3 Mitigations

169 entries over 43 nodes, of which **163 are also in
`uncovered_mitigations` — 6 covered, 3.9 mitigations per node**. The two lists
are 96.4% the same list. The most frequently uncovered are ATT&CK's broadest
(M1026 at 112 techniques, 16 times; M1018 at 119, 11 times; M1017 at 60, 11
times), which reproduces on fresh data the measurement recorded in
`docs/change_log/2026-09-17-mitigation-focus.md`. The set derives from the
technique, so it repeats byte-identically wherever a technique repeats, and it
is component-blind by construction.

---

## 5. Scenario seed

```text
scenarios[]
  path_id, name, description, source_type: "actor_projection"
  threat_actor_profile, attack_objective
  target_assets[], entry_vectors[]
  security_controls[]   the control catalogue for this scenario
  attack_sequence[]     one event per graph step, same order
```

`security_controls[]` is the seed's own contribution and has no counterpart in
the graph: `control_id` (`SC-000n`), `name`, `control_type`, `description`,
`implementation_status`, `bypass_difficulty`, `bypass_requirements[]`,
`detection_capability`. It is scenario-scoped and sized by the estate, not by
the path — 17 controls on the telemetry runs, 25 on Application B, 4 on Claims
Portal.

An `attack_sequence` event carries 23 fields. 15 of them restate the graph
step; 8 exist only here:

```text
event_id           "AE-0001", restarting per scenario — not globally unique
sequence_order     1-based
name, description  prose forms of the step
target_asset       the asset name — there is no component_id in the seed
required_access    == graph access_before
resulting_access   == graph access_after
access_source      "model" | (fallback) — "model" on 43 of 43
blocking_controls[]   control names, not control_ids
detecting_controls[]  control names, not control_ids
success_indicators[]
```

Two cautions a schema change has to absorb:

- **`blocking_controls` and `detecting_controls` are names, not ids**, so
  joining them to `security_controls[]` is a string match, and a renamed
  control breaks it silently.
- **They are largely the same list.** 22 of 43 events carry at least one
  control; on 18 of those the two lists are identical and on 4 they differ.
  `detecting_controls` is therefore closer to "controls present on this
  component" than to "controls that would detect this step"; the discriminating
  signal is the catalogue's `detection_capability`, not membership.

---

## 6. Run record

Five blocks, `schema_version 5`.

- **`run`** — `run_id`, `run_group`, `run_index`, `run_count`, `created_at`,
  `tool_version`, `flow_map_path`, `flow_map_sha256`, `prompt_sha256`,
  `application`, `actor_input`, `actor_resolved`, `record_file`,
  `raw_response_file`. `actor_resolved` is the only place the corpus records
  alias resolution and actor breadth: `Midnight Blizzard` → `APT29 (G0016)`,
  14 aliases, 110 techniques; Scattered Spider 81; Volt Typhoon 97.
- **`model`** — the provenance `model` block plus `tier`, `thinking_level`,
  `max_tokens`, `max_paths`, `software_scope`. All three: `gcp_gemini` /
  `gemini-3.1-pro-preview`, `heavy`, `medium`, 49152, 3, `delivery`.
- **`deterministic`** — `entry_ranking[]` (scored components with reasons),
  `routes[]` (entry → crown jewel, with `hops`, `boundary_crossings`,
  `unauthenticated_hops`), `unreachable_crown_jewels[]`, `validation[]`. This
  is the pre-LLM analysis. Sizes: 10/7, 14/10, 7/4 entries/routes; no
  unreachable crown jewels in any run.
- **`outcome`** — `status`, `finish_reason`, `truncated`, `error_code`,
  `message`, `usage`, `wall_time_ms`. All three `ok` / `STOP` / not truncated.
  Prompt 4.0k–6.3k, completion 2.7k–3.0k, **thinking 4.1k–8.1k**, wall
  57–82 s. Thinking exceeded completion on two of three runs.
- **`sampled`** — `paths[]`, `rejections[]`, `warnings[]`,
  `raw_response_path`. No rejections in any run.

Warning codes observed, 12 in total: `STATE_GAP` 8, `TACTIC_CORRECTED` 2,
`HOP_NOT_DECLARED` 1, `LATE_INITIAL_ACCESS` 1. Validation codes (flow-map
defects, not model defects) appear only on Application B: `INVALID_ENUM` 2
(`private_link` exposure coerced to `internal`), `DUPLICATE_FLOW` 2.

**Every warning carries a `location` of the form `<path_id>.steps[<n>]`**, a
zero-based index into the graph's steps. That string is the only join between
the run record and a node, and it is the only per-node field in the corpus that
is positional rather than keyed.

---

## 7. What holds between the documents

Verified over all four pairs, 43 nodes.

### 7.1 Structure

Path ids and step counts agree exactly, and `technique_id` agrees on 43 of 43.
The graph and the seed are a **union, not a subset relation** — 13 step fields
are graph-only (`component_id`, `access_before/after`, `mitigations`,
`uncovered_mitigations`, `controls_in_play`, `leads_to`, `notes`, `rationale`,
`result`, `asset`, `technique_name`, `state_note`) and 12 are seed-only
(`event_id`, `sequence_order`, `access_source`, `blocking_controls`,
`detecting_controls`, `success_indicators`, `target_asset`, `attack_technique`,
`description`, `name`, `required_access`, `resulting_access`).

### 7.2 Two fields are represented differently and must be canonicalized

**`state_check`.** The graph splits it (`state_check` + `state_note`); the seed
combines it. `seed == graph.state_check` when the note is empty, otherwise
`graph.state_check + " — " + graph.state_note`, separator U+2014 with one space
either side. **43 of 43 match byte-for-byte, 0 conflicts**, with the note
branch exercised by the 9 gap nodes. Comparing raw strings yields 43 spurious
conflicts; comparing the leading token discards the whole continuity finding on
the 9 nodes where it exists.

**`transition`.** The graph carries an object; the seed carries prose —
`"flow f5: claims_api -> doc_store (s3, unauthenticated)"`,
`"entry point (internet-exposed)"`, `""` for the null case. The prose is
derivable from the object but **not the reverse**: it omits
`crosses_boundary` entirely, so an intra-zone flow and a boundary crossing
render identically. Any merge must take the graph's object as authoritative and
may keep the prose only as a display string.

### 7.3 Node identity

No `(technique_id, component_id)` pair repeats **within** a path in any of the
four runs. Pairs do repeat **across** paths — three of them in the Claims
Portal run (`T1190@portal`, `T1552@portal`, `T1078@claims_api`), which is what
its convergence points describe. So a global dedupe on the pair loses real
nodes today, while a within-path dedupe passes the whole corpus and would still
be wrong: `event_id` restarts at `AE-0001` per scenario, and the only safe key
is positional within a path.

---

## 8. Vocabularies as observed

### 8.1 Tactics — v19.2, and the restructure is live

12 distinct tactics over 43 nodes: Initial Access 8, Collection 6, Credential
Access 5, Execution 5, Discovery 5, **Stealth 3**, Lateral Movement 3,
Persistence 2, **Defense Impairment 2**, Command and Control 2, Exfiltration 1,
Reconnaissance 1. `Defense Evasion` does not appear. `Stealth` and
`Defense Impairment` are the v19 successors, and the Claims Portal run shows
the reconciliation happening in flight: two `TACTIC_CORRECTED` warnings
relabel a model-supplied `Initial Access` to `Stealth` on the grounds that
ATT&CK documents it for that technique and the entry point is earlier in the
path. Any consumer holding a hardcoded tactic list will silently drop these.

### 8.2 Access states

5 of the 7-state vocabulary appear, across `access_before` and `access_after`
(86 slots): `code_execution` 31, `network_reach` 20, `service_credential` 15,
`data_access` 15, `user_credential` 5.

### 8.3 Everything else

`evidence` / `actor_support`: `documented` / `procedure_documented`,
`via_software`. `control_type`: `network`, `application`, `identity`,
`perimeter`, `data`, `monitoring`. Control `status`: `implemented`, `partial`,
`missing`, `planned`. `implementation_status` (seed catalogue) and
`bypass_difficulty` / `detection_capability` (`high` | `medium` | `low`).

---

## 9. What the output does not carry

Stated positively so a schema plan does not budget for it:

1. **No ATT&CK data sources or data components.** Not in the export and not in
   `framework/reference_data/mitre_relationships.json`, whose mitigation
   entries hold exactly `description`, `matrices`, `name`, `techniques`, `url`.
   A `DS####` in any downstream artifact is a model invention.
2. **No `component_id` in the seed.** Scenario-only input can reach `asset`
   text and nothing that joins to an estate.
3. **No flow-scoped controls.** `controls_in_play[].on` is `component` on all
   65 entries; estate-wide and flow-level controls are not evaluated per step.
4. **No `port`** on a transition, and no protocol detail beyond the flow's own.
5. **No non-`model` `access_source`.** The tactic-default fallback is declared
   but unexercised — 43 of 43 are `model`.
6. **No stable id per node.** Identity is positional: `path_id` + index, in
   both the steps array and the warning `location` strings.
7. **No coverage claim.** `uncovered_mitigations` means "no *tagged* control on
   *that one component* carries this M-ID" — not that the estate lacks the
   control (`tool.py:2042-2063`, caveat narrated at `tool.py:4593`).

---

## 10. What this implies for schema work

Each item is a consequence of a measurement above, not a proposal adopted here.
They are the inputs to `attack_path_detection_normalization.md` §6.

1. **Canonicalize two fields, not one.** `state_check` already has a rule
   (normalization §4.3 3a); `transition` needs the same treatment and the
   graph's object must win, because the seed's prose loses `crosses_boundary`.
2. **Node identity stays positional.** Nothing in the output supplies a stable
   node id, and the corpus rules out both dedupe shortcuts (§7.3).
3. **`component_bound` is now the normal grade, and `asset_named` is the
   degraded one.** 43 of 43 nodes resolve. Conversely,
   `component_bound_partial` finally has real instances: 5 nodes across the two
   new maps sit on components declaring no `technologies` or
   `authentication: none` (`front_door`, `users` on Application B;
   `claims_db`, `doc_store` on Claims Portal).
4. **Warning join is positional and lossy.** `STATE_GAP` and
   `TACTIC_CORRECTED` carry findings no other document holds, keyed only by
   `<path_id>.steps[<n>]`. Either normalization parses that string or the
   findings are dropped — and the run record is emitted for only 3 of the 4
   pairs, so it cannot be a required input.
5. **The mitigation split holds on fresh data.** 163/169 uncovered on a corpus
   that shares no run with the one that produced the original 147/154.
6. **Control-name joins are string joins.** The seed's `blocking_controls` and
   `detecting_controls` reference catalogue entries by name; ids exist and are
   unused.
7. **Encoding is load-bearing in three places now** — `interpretation`, the
   `state_check` separator and the flow-map prose — so a transport check
   belongs at the document level, not per field.
8. **Two producer-side gaps are worth their own decision**, both outside
   normalization: `on: flow` controls are never emitted, and `event_id`
   restarts per scenario despite looking global.

---

## 11. How this was measured

Both exports of all four pairs and all three run records were parsed with
`encoding="utf-8"` and diffed field by field; the flow maps were read from
`plugins/threat_modeling/adversary_path_projector/examples/` and every
`component_id` resolved against them; mitigation breadth came from
`framework/reference_data/mitre_relationships.json` (96 mitigations,
`attack_version` 19.2). No code was changed, no test was run and no LLM call
was made in producing this document. Counts supersede those in
`attack_path_detection_normalization.md` §§1.1–1.6, which were measured against
the retired corpus and are dated there.
