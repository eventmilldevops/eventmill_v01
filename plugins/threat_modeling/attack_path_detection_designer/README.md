# Attack Path Detection Designer

Turns `adversary_path_projector` exports into a normalized, reviewable context
for every step of a projected attack path — one node per step, with a stable
identity, a JSON pointer and an origin for every field, and an explicit record
of anything the source documents disagree about — and then drafts a detection
for each of those steps against the telemetry that component actually has.

The drafts are **starting points for a detection engineer**, not rules to
deploy. Every one carries `validation_status: draft_unvalidated`, the
collection it would need, what it cannot see, and the questions a tester should
answer first. See *Keeping a generated record honest* for the measures that
make that claim checkable, and *Descriptors* for how to read the output.

Plan: `docs/specs/attack_path_detection_normalization.md`.
Producer shape it reads: `docs/specs/projector_export_shapes.md`.

**Stages N1, N2 and N3 are implemented.** Adapters, the three identities, the
node occurrence key, a deterministic `draft_id`, the union merge and
`provenance_by_field` (N1); flow-map lineage and fit, and a closed code
catalogue (N2); the flow-map join and the five completeness grades (N3a);
controls per node and `monitoring_claim` (N3b); mitigation names, the focus
cut and the coverage ratio (N3c); taxonomy status against ATT&CK v19.2 (N3d).
The context pack's own schema is N4. Normalization uses no LLM and no network.

**Stages G1a and G1b are implemented and live-run on four vendors.** The
telemetry library joins to each node (G1a); `generate_detections` drafts one
detection per node, batched per path with the full path outline (G1b). G1c
(repair) and G1d (the rendered workbook) are outstanding — drafts are returned
as JSON today.

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

## Keeping a generated record honest

Everything below exists because a live run produced something wrong, and
almost none of it was the model's fault. Across seven runs on four vendors the
tally is consistent: the drafts' *reasoning* has been sound, and the defects
have been in the contract we handed the model or in the checks we wrote to
inspect it. That shapes the whole design.

The governing rule is that **pseudocode is a hypothesis that will be generated
and then tested.** Every draft carries `validation_status: draft_unvalidated`
and means it. So this stage never tries to decide whether a detection is
*good*. It has three jobs, and they are kept strictly apart because each can
support a different kind of claim.

| Mechanism | What it can check | On failure |
|---|---|---|
| **Rejection** | A comparison of two values, both present in the record | The draft is refused and named in `rejected` |
| **Derivation** | Something the record's own shape determines better than its label does | The record is corrected to describe itself |
| **Flag** | A question a human should answer | Recorded in `review_flags`; nothing is blocked |

### Rejections: checkable facts

A rejection needs a fact, not a judgement. Each of these is a comparison
against something the prompt actually supplied:

- **A telemetry source that was not offered** for that node.
- **A `required_fields` entry the cited candidate does not list.** Fields are
  offered exactly as sources are, one level down. The refusal names what the
  source *does* offer, because a rejection the author cannot act on costs the
  draft and teaches nothing. A candidate carrying no field list is not
  second-guessed — there is nothing to check against, and inventing a
  complaint is worse.
- **A changed `technique_id`**, or a `draft_id`, `path_id` or `node_index`
  that does not match the node it claims to be.
- **Any `DS####` data component identifier**: no local reference defines them.
- **`logsource.product` below `component_bound`**, or holding a `source_id`
  rather than a vendor name.
- **`missing_data_behaviour` other than `insufficient_telemetry`.** Absent data
  may never evaluate as benign.

Why field-level rejection had to wait: the candidate projection passed
`prerequisites` and `absent_without_enrichment` while withholding `native` and
`derived`, so the model was told what each source *lacked* and never what it
*had*. One run invented all fourteen of its field names while copying
`prerequisites` verbatim — it used what it was given and fabricated the rest.
Rejecting on fields before offering them would have failed every draft with no
route to compliance. Offering them fixed the behaviour outright: **0 invented
names across 13 citations** in the next run, with all five of the library's
purpose-built indicators in use.

### Derivations: making the record describe itself

Some fields the model fills in are better read off the logic than taken on
trust.

- **`detection_logic.kind`** is derived from the shape: a numeric threshold
  makes it `threshold`; more than one source over a window makes it
  `correlation` whether or not a key is named; join keys alone make it
  `correlation`; a window alone makes it `threshold`; otherwise
  `single_event`. A draft declaring `baseline_deviation` or `reconciliation`
  keeps it — those are claims about *method* that no structural rule can infer.
  Where a threshold and a grouping are both present the shape genuinely
  supports either reading, and a draft that declared one of them keeps its
  answer.
- **`window`** is canonicalised to `value_timeunit` — `60_sec`, `10_min`,
  `24_hour` — so a consumer splits on the underscore instead of parsing prose.
  A bare number is seconds. A window that cannot be read is kept verbatim and
  flagged, because discarding a parameter an engineer proposed is worse than
  carrying one that needs a human.

Two lessons are built into these. First, **`single_event` was once the literal
placeholder in the prompt skeleton**, and every draft in one run declared it —
including two carrying windows and thresholds. A model that reasons about the
logic still copies a fixed example, so placeholders are enumerations now.
Second, **only a numeric threshold counts**: one run's single wrong correction
came from a `thresholds` entry reading *"proposed starting point: alert on the
first event"*, prose saying the opposite of a threshold, which nonetheless made
the mapping non-empty and rewrote a correct `single_event`.

### Flags: questions, never verdicts

`review_flags` is a closed catalogue in `generation.py`, and **no code in it
can reject a draft**. An empty array asserts there are none.

| Code | Meaning |
|---|---|
| `FIELD_DECLARED_UNUSED` | A `required_fields` entry the logic never reads. Often deliberate analyst context — and also what a rule looks like when its discriminator went missing. |
| `FIELD_UNDECLARED_IN_LOGIC` | The logic reads a field of a cited source that is not in `required_fields`, so the rule would ship uncollectable. |
| `FIELD_FROM_UNCITED_SOURCE` | The logic reads a field the library attributes only to sources this draft does not cite. Either the source list or the logic is wrong. |
| `LOGIC_KIND_CORRECTED` | `kind` disagreed with the shape and was replaced. |
| `LOGIC_NULL_AS_MATCH` | The condition fires on an absent value. If the field is not collected, every record matches. |
| `WINDOW_UNPARSED` | A window that is not a number and a time unit. |
| `ANNOTATION_FAILED` | Annotation raised. The draft passed validation and is kept. |

`FIELD_DECLARED_UNUSED` is the one that matters most and reads most like
noise. It was written after a T1210 draft filtered a database session on source
address alone while the `username` that separates the service from its stolen
credentials sat declared and unread. One mechanical check — do the fields
collected and the fields read agree — caught it with no understanding of
Postgres, the path, or the attack, and handed the question to whoever tests the
rule.

Three things keep the field checks quiet enough to be worth reading. They are
**grounded in the telemetry library**, so only names it knows to be fields of
some source are ever reported and pseudocode placeholders never become
findings. They report only **distinctive** names — containing `_` or `.` —
because the contract permits prose pseudocode, and a draft reading *"executing
command patterns"* means English, not the `command` that happens to be a field
somewhere. And a draft's own **normalized-field aliases are subtracted**, but
only when the alias differs from the native name it maps: an identity mapping
`{"name": "actor", "from": "actor"}` declares the field is read, and
subtracting it once took the native reference with it.

`LOGIC_NULL_AS_MATCH` is where the rejection/flag line is clearest. The spec
forbids null-as-match outright and `missing_data_behaviour` is enforced as a
rejection, because that is a declared value. The null test is read out of prose
pseudocode, where the same words express the defect (`auth_identity IS NULL`
meaning "unauthenticated") and the handling the contract asks for (`IF
principal IS NULL THEN insufficient_telemetry`). A pattern that cannot tell
those apart with certainty states the concern and leaves the judgement.
`IS NOT NULL` and `!= NULL` are excluded: requiring presence is the opposite
failure and a legitimate condition.

Flags reach `summarize_for_llm` by code and count, above the closing caveat
because the summary truncates from the end. A flag that exists only in the
artefact is a flag nobody acts on.

### Relocation: give the prose a home

The most persistent pattern has nothing to do with correctness. **A model with
something worth saying says it in whichever field is nearest, and that field
stops being parseable.** It has happened four times:

| Field | What arrived | Where it goes now |
|---|---|---|
| `grounding.limitations` | Copies of `absent_without_enrichment` field names | Prose for a reader (prompt rule) |
| `review_flags` | Bare strings — `authentication_not_directly_observed` | `caveats` |
| `thresholds` | *"proposed starting point: alert on the first event"* | `threshold_notes`, keyed by the same parameter |
| `join_keys` | *"approximate temporal join only; no shared identifier exists"* | `join_notes` |

In every case the content was **good** — "no shared identifier exists between
these two sources" is a real and valuable answer about a join, and
`post_exploitation_outcome_only` is exactly the caveat a tester wants. So
nothing is discarded. Each machine-readable field now has a prose sibling, the
prompt asks for the right one by name, and anything left in the wrong place is
moved.

One rule governs the move: **relocating an explanation must never change what
the record claims.** Stripping a sentence out of `join_keys` once left a
genuine two-source temporal correlation looking like a threshold, because the
prose *was* the evidence of the join. That is why multiple sources over a
window now derive as `correlation` regardless of keys.

### What this record has cost, and why flags over rejections

The honest summary: the checks themselves have needed correcting four times —
a foreign-alias false positive, an identity-mapping regression, prose tokens in
a field-reference scan, and a kind derivation that overrode an answer the model
had reasoned its way to. Twenty-odd lines of mechanical comparison, wrong four
times, each time caught by live output rather than by review or tests.

That is the case for the design. A rejection is a strong claim and is reserved
for facts. Everything requiring inference is a flag, phrased as a question,
that a person resolves while testing the rule. A validator that starts
reviewing the detection rather than describing the record will be wrong in its
own turn — and the record above is what that looks like when it happens.

## Descriptors: a language, not a vocabulary

Read any draft and the same shape appears everywhere:
`token_file_read_by_unexpected_process`, `first_time_route_for_principal`,
`attempt_only_not_code_execution`, `distinct_new_routes_per_group`,
`credential_theft_indistinguishable_from_service_defect`. Long, lowercase,
underscore-joined. They are not variable names that grew out of control. They
are the working notation of this pillar, and understanding how they are built
is most of what it takes to read the output.

**A descriptor compresses a complete proposition into a single token.** Not a
category and not a label — a statement that can be true or false of one record,
or a question that has an answer. `actor_approver_same_person` is not the topic
"approval"; it is the claim *the person who created this adjustment is the
person who approved it*. `allowed_after_rule_match` is *the WAF matched a rule
and let the request through anyway*. Read each one as a sentence with the
articles and the verb "to be" removed, and it resolves immediately.

They are deliberately long. A descriptor is read by someone deciding what to
collect, what to test, or whether an alert means anything, and at that moment
precision is worth far more than brevity. `token_file_read_by_unexpected_process`
survives being quoted in a ticket, pasted into a query, and argued about in a
review. `unusual_file_access` does not.

### The two halves are governed differently

**The library half is authored and stable.** In telemetry library v0.3.0 there
are 36 sources carrying 160 distinct native fields, **38 distinct derived
indicators** and **59 distinct `absent_without_enrichment` descriptors**. The
derived ones are the library's purpose-built observations — 26 sources carry
exactly one, five carry none — and they are the single highest-value thing the
library offers, because each encodes an analytic somebody already thought
through. The `absent_without_enrichment` names are the mirror image: they state
precisely what a source *cannot* tell you, which is how a draft knows to say so
in `grounding.limitations` rather than quietly assume it.

These are versioned, reviewed, and change only when the library does.

**The generated half is coined per run and cannot be enumerated.** Normalized
field aliases (`source_address`, `route_is_new_for_actor`, `sql_text`),
threshold parameter names (`distinct_new_routes_per_group`,
`single_statement_rows_estimate`), and `caveats`
(`temporal_correlation_only_no_shared_join_key`,
`end_user_principal_not_available_in_database_records`) are minted by the
drafting model, for that node, in that run. A different model, or the same
model tomorrow, will coin different ones for the same node.

That is not a defect to be closed. It is the point. Asking a model to name the
thing it just reasoned about, in a notation dense enough to be a key and
explicit enough to be read cold, is how a detection concept travels from the
draft into a ticket, a query and a test plan without a paragraph of
explanation attached. The prompt asks for the *form* — short snake_case labels,
one proposition each — and leaves the content open, because the content is
the analysis.

### The glossary

[`framework/reference_data/telemetry_descriptor_glossary.md`](../../../framework/reference_data/telemetry_descriptor_glossary.md)
exists for someone meeting this output for the first time. It covers the
library's full fixed half — all 38 derived indicators and all 59 enrichment
descriptors, with a plain-language reading of each — and then walks one
recorded run draft by draft, explaining every alias, threshold name and caveat
it coined.

**It is far from complete, and it can never be complete.** The library half
will track the library. The generated half is a snapshot of one run and will
not match the next one. The glossary is not a controlled vocabulary and must
not be read as one: it is a reading primer for a language whose grammar is
fixed and whose lexicon is open.

Two cautions carried in the glossary itself are worth repeating. A derived
indicator's meaning there is a plain-language interpretation of its name and
source context, **not a calculation specification** — `derived` means an
indicator to compute or enrich, never that an implementation exists. And every
library source reports `collection_status: unknown`, so a descriptor appearing
in a draft says what *would* be observable, not what is being collected today.

## Codes

Warnings, review flags and errors are closed sets (spec §4.4): `WARNING_CODES`
and `REVIEW_FLAG_CODES` in `normalization.py` for the normalization stage,
a separate `REVIEW_FLAG_CODES` in `generation.py` for the draft stage (see
*Keeping a generated record honest* above), and `ERROR_CODES` in `tool.py`.
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
