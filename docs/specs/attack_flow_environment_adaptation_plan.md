# Attack Flow import and environment adaptation — Claude implementation plan

Date: 2026-09-23  
Status: implementation handoff; the interfaces below are proposed, not available commands.  
Revised: 2026-09-23 after a review against the code (fixtures, shell, loader,
designer, telemetry library, ATT&CK reference). Five choices are left open and
are collected under *Open decisions*; do not settle them in code without the
operator.  
Audience: Claude coding agent implementing the extension, and the operator installing and testing it.

## Objective

Enable an analyst to import a third-party Attack Flow STIX bundle, inspect its
source-described actions, and generate detection-design inputs adapted to the
analyst's own environment. A one-to-one match between source and local assets
must not be required. Preserve the source attack and clearly distinguish local
mapping decisions and model-generated hypotheses from reported behavior.

Complete the working vertical slice: import -> inspect -> adapt to a local flow
map -> visualize -> validate/digest -> generate detection drafts -> export.
Implement in the repository; do not deploy, call paid providers, change secrets,
or commit/push as part of this handoff. The operator will install and conduct
live tests. Offline tests and mock-provider tests are part of implementation.

## Read before editing

Read the current AGENTS.md, relevant change logs, and these files. Current code
wins over historical status paragraphs in specifications. Preserve unrelated
working-tree changes; this checkout has active work in the same plugins.

- `plugins/threat_modeling/adversary_path_projector/{README.md,tool.py,manifest.json}`
- Its input, flow-map, and export schemas, and `docs/specs/projector_export_shapes.md`.
- `plugins/threat_modeling/attack_path_visualizer/{README.md,tool.py}` and its tests.
- `plugins/threat_modeling/attack_path_detection_designer/{README.md,tool.py,normalization.py,generation.py,telemetry.py}` and schemas/tests.
- `docs/specs/attack_path_detection_normalization.md` and `docs/specs/attack_path_detection_designer.md`.
- `docs/change_log/2026-09-23-n4-retired.md`.
- `framework/cli/shell.py`, artifact registration, storage resolution, and export tests.
- `framework/reference_data/{telemetry_library.py,telemetry_library.json,mitre_attack.py}`.
- `docs/specs/reserved_vocabulary.md` (every enum and reserved spelling) and
  `docs/specs/telemetry_reference_library.md` (the rules for adding sources).
- `plugins/threat_modeling/adversary_path_projector/examples/README.md`
  (flow-map authoring, including mitigation-id guidance this work affects).
- `docs/specs/manifest_schema.json` and CLAUDE.md's note on the known
  validator failures.

Fixture outside the repository directory, relative to its root:

`../test_data/attack_examples/Berserk Bear Attack on Polish GCPs.json`

The adjacent `.afb`, `.eventmill_input.txt`, and `.eventmill_output.md` are
comparison material. Do not overwrite them or silently correct their content.

A second real bundle sits beside it and should be the generality check:

`../test_data/attack_examples/TwoNet Hacktivist Attack.json`

Attack Flow 2.0.0, 7 actions, 3 assets, one threat actor, and 14 connections:
7 `asset_refs`, 6 `related-to` relationships and 1 asset `object_ref`. No
`effect_refs`, operators or conditions. It
shares no technique with Berserk Bear (T0815, T0831, T0837, T1078, T1136.001,
T1213.006, T1491), so an importer tuned to one fixture will show it here.

### Verified constraints in this checkout

- `project_paths` currently uses actor-grounded technique sets and a structured
  local flow map. `normalize_flow_map` is not implemented.
- The visualizer accepts inline linear stages or an Event Mill graph. Its graph
  node identity and `leads_to` resolution currently use technique/tactic, so
  repeated techniques on separate components can merge.
- The detection designer currently accepts projector exports and re-derives its
  context. Use `validate_input`, `digest`, and `generate_detections`. Do not
  resurrect retired `normalize_paths` or make stored context packs a new input.
- `export --all <folder>` exports registered tool outputs under
  `exports/<source_tool>/<folder>/` in the common bucket.
- The sample has 12 actions, 7 assets, one threat actor, and 24 corresponding
  connections across JSON and AFB: 12 action `asset_refs`, 10 `related-to`
  relationships and 2 asset `object_ref`s. Connections include asset/context
  references; 24 connections does not mean 24 temporal attack transitions.
- **Neither real bundle has a single `effect_refs` entry**, and neither has an
  operator or condition. The Berserk Bear flow has one `start_refs` entry. In
  practice ordering will usually be unspecified, so any local ordering is a
  model hypothesis, and effects, AND/OR, conditions and cycles are exercised
  only by the synthetic fixtures.
- **Most of the sample is ATT&CK for ICS.** Seven of twelve actions carry `T08xx`
  or ICS tactics (`TA0100`, `TA0106`, `TA0107`, `TA0109`); the rest are
  enterprise. The local reference handles both: `validate_technique_id`
  accepts every technique in both bundles including `T0892` and `T1693.001`,
  `TACTIC_ORDER` includes `Inhibit Response Function` and `Impair Process
  Control`, and `mitre_relationships.json`'s 96 mitigations include the ICS
  `M08xx`/`M09xx` ids.
- **Tactics arrive as ids only.** Actions carry `tactic_id` (e.g. `TA0107`)
  and the bundle contains no tactic objects; `T1133` has no tactic at all. No
  local reference maps a `TA` id to a tactic name. See open decision D3.
- **"Berserk Bear" resolves locally to G0035 Dragonfly**, which has 58
  techniques, two of them ICS (T0817, T0862) and neither in the fixture. Local
  ATT&CK actor evidence would therefore be false for nearly every imported
  action; that is why source-report evidence must stay a separate field.
- **Telemetry for OT is thin.** The telemetry library holds 36 sources, 6 for
  the `plant_ot` estate: Windows security events, historian tag changes, HMI
  operator actions, remote-access sessions, the asset register and a collector
  heartbeat. None observes RTU or serial-server firmware, device credential
  changes, or Modbus/DNP3 traffic. See open decision D4.
- **The estate is read from the flow map's filename** (`<estate>_flow_map.json`,
  `telemetry.estate_key`); `estate_specific` sources attach only to their own
  estate. Name synthetic maps deliberately.
- **The designer does not check which tool produced its input.** Any document
  with an `attack_graph` key goes through the projector-graph adapter, and
  grounding then computes `actor_evidence` from the local catalogue. A
  source-informed graph in the same shape would be silently read as an actor
  projection unless producer detection is added first (Phase 5).
- **Only the singular `artifact_id` is resolved by the shell**, which injects
  `file_path` and `path` beside it. Every other `*_artifact_id` argument is
  resolved by the plugin itself from `context.artifacts`, as the projector's
  `flow_map_artifact_id` and the designer's `artifact_ids` already are. No
  shell change is required for the new arguments.
- **The plugin loader imports each plugin under a flat module name with no
  package.** Relative imports and `import sibling` fail. A plugin split into
  modules loads them by file location, as the designer's `_load_sibling` does.
- **No plugin imports another** (normalization spec decision 7). Code that two
  plugins both need goes into `framework/` or is not shared.
- `jsonschema` (4.23) is a base dependency and installed. `stix2` is declared
  only in the `plugins-log-analysis` extra, is not installed here, and nothing
  in the repository imports it.
- Flags are split with POSIX `shlex`: quoted paths with spaces work, and
  backslashes are escapes, so Windows paths need forward slashes.
- The sample's inline input/output misspell T0892 as T08921. The original JSON
  and AFB use T0892. Use the JSON as the conversion fixture.
- The environment the plan was first written in had no Python; the one it was
  revised in runs Python 3.12 with a suite of 1844 passing. Discover the
  implementation environment afresh and report actual test execution rather
  than copying either figure.

## Architecture and command contract

Use a small deterministic `attack_flow_importer` plugin for source ingestion and
the mapping template. Extend `adversary_path_projector` with `project_from_attack`
for the LLM-assisted local adaptation. Where mapping validation lives is open
decision D1: the projector must enforce the same mapping rules when it
projects, and no plugin may import another. Keep SDK calls in the existing LLM seam.
Do not overload existing `project_paths` behavior or require an actor resolved
in the local ATT&CK group catalogue to import a third-party attack.

Proposed shell interfaces:

```text
run attack_flow_importer --action import --artifact_id <stix-artifact-id>
run attack_flow_importer --action import --file_path <local-stix-path>
run <importer or projector, per D1> --action validate_mapping --source_graph_artifact_id <import-id> --flow_map_artifact_id <map-id> --mapping_artifact_id <mapping-id>
run adversary_path_projector --action project_from_attack --source_graph_artifact_id <import-id> --flow_map_artifact_id <map-id> --mapping_artifact_id <mapping-id> --export true
```

`mapping_artifact_id` is optional for projection: without it the LLM proposes
bindings, all marked model-proposed. With it, honor analyst decisions as hard
constraints; contradictory choices produce explicit errors, not quiet changes.
Support equivalent explicit local file-path inputs for scripting, with mutually
exclusive source validation. Do not overload one `file_path` to mean both attack
bundle and local environment. Custom `*_artifact_id` arguments are resolved
by the plugin from `ExecutionContext.artifacts`, not by the shell (see
*Verified constraints*); they must work that way, not merely appear in schemas.
An artifact registered but unreadable on this disk is reported with its
`storage_uri`, as the designer's `ARTIFACT_UNAVAILABLE` does.

Manifest conventions for the new plugin: `stability: experimental` (the value
`stable` is one of the 15 known validator failures), capability names that
satisfy the schema's namespace pattern (it rejects underscores), a
`summary_budget`, `safe_for_auto_invoke` reflecting its most expensive action,
and every new field registered in both `PluginManifest` and
`docs/specs/manifest_schema.json`. Split code into sibling modules loaded by
file location.

No generic shell parser rewrite is expected. Add only the artifact-resolution
support that is actually required, with regression tests.

## Phase 1 — deterministic, versioned Attack Flow import

Create the importer plugin, schemas, tests, README, and small parser/adapter
modules. Keep parsing independent of shell, storage, and model execution.

1. Accept STIX 2.1 JSON bundles declaring the supported Attack Flow extension.
   Initially support the fixture's Attack Flow 2.0.0 contract. Vendor a pinned
   official schema and its necessary dependencies/license, or use an existing
   local equivalent after demonstrating compatibility. The 2.0.0 schema refers
   to the STIX 2.1 common schemas, so vendor those too and resolve every
   reference through a local registry. Validate with `jsonschema`, a base
   dependency; do not add `stix2`. Runtime validation must not fetch URLs. Do
   not apply a newer Attack Flow schema silently.
2. Validate JSON structure, object identities, reference types and targets,
   duplicate/conflicting objects, and exactly one selected attack flow. For
   multiple flows require explicit `flow_id` selection. Record unsupported
   versions as unsupported, not corrupt JSON. Bound input size/object counts.
3. Preserve original bytes as an immutable registered source artifact or retain
   a durable byte-identical copy with SHA-256. Carry markings, references,
   creator, timestamps, and supplied confidence without asserting their truth.
4. Emit a versioned canonical source graph, an import report, and an editable
   mapping-template JSON. All must be registered artifacts for show/export.
5. Give every source action its own stable identity derived from source object
   ID within the import identity. Repeated techniques never collapse actions.
   Preserve source JSON pointers/object IDs on extracted fields and edges.
6. Resolve technique IDs against the bundled ATT&CK release for annotation.
   Preserve original IDs and record any resolved aliases separately. Missing,
   unfamiliar, revoked, or malformed IDs remain visible with explicit status;
   never invent a replacement or drop the action. Preserve behavior without a
   technique ID and render it using its action identity/name.
7. Resolve `technique_ref`/`tactic_ref` from bundled objects when possible. Missing
   external objects are recorded as unresolved; do not fetch them implicitly.
   Neither real bundle carries tactic objects: tactics arrive as `tactic_id`
   alone, or not at all. How a `TA` id becomes a tactic name is open decision
   D3. Whatever is chosen, keep the supplied id, record how the name was
   obtained, and never guess between several candidate tactics.

### Edge semantics are a release requirement

Use typed edges. Distinguish flow starts, effects, condition branches, operator
operands/effects, action-to-asset associations, asset object references, and STIX
relationships. Preserve original relationship types and direction.

`asset_refs`, an asset's `object_ref`, and generic `related-to` are not temporal
dependencies. Do not convert every reference into a `leads_to` edge. In the
Berserk Bear fixture, several visible connections pass through assets and the
actions do not supply a complete `effect_refs` sequence. Preserve that context
and report ordering as unspecified. Do not recreate the old twelve-step chain.
Both real bundles have no `effect_refs` at all, so "ordering unspecified" is
the expected result for them, not an edge case.

Support conditions and AND/OR operators in the canonical graph and source
visualization. A path-list projection must not turn AND prerequisites into OR
alternatives. Where the adaptation/detection path cannot preserve a construct,
return an explicit unsupported-semantics result for the affected portion while
retaining the source graph. Never advertise a silently flattened result as full
support. Detect cycles; render them, but bound traversal and explicitly report
any path-enumeration limits. No silent truncation of branches or isolated nodes.

The official language reference is at
[Attack Flow language](https://center-for-threat-informed-defense.github.io/attack-flow/language/).
It currently presents newer documentation; locate and pin the 2.0.0 schema and
versioned semantics for this implementation rather than trusting the latest
page to define the fixture's version.

## Phase 2 — explicit source-to-environment mapping

Define a versioned mapping schema referencing source-graph and local-map hashes.
A record must support multiple source action/asset IDs and multiple local
component IDs. Asset correspondence and action applicability are separate:
matching an appliance role does not establish exploit applicability.

Suggested record shape; finalize exact names consistently in schema and code:

```json
{
  "mapping_id": "map_...",
  "source_action_ids": ["attack-action--..."],
  "source_asset_ids": ["attack-asset--..."],
  "local_component_ids": ["remote_access_gateway"],
  "relationship": "role_equivalent",
  "applicability": "unknown",
  "origin": "analyst",
  "rationale": "Same access role; product and exploit prerequisites differ.",
  "prerequisites": [
    {"description": "Applicable vulnerability exists", "status": "unknown"}
  ],
  "evidence_refs": []
}
```

Define closed enums for structural states, with documented semantics, and
register every one in `docs/specs/reserved_vocabulary.md`; check it first so a
value is not invented twice. At
minimum distinguish exact versus role-equivalent correspondence; applicable,
conditional, inapplicable, and unknown behavior; analyst versus model origin;
and satisfied, unsatisfied, and unknown prerequisites. Cardinality comes from
the arrays, not a requirement that source and destination lengths match.

Validation checks IDs, hashes/lineage, contradictory decisions, and references.
Edited-map hash differences should be reported as lineage changes following the
existing designer policy, not rejected solely for differing bytes. Removed
component references are substantive errors. The deterministic importer must
not declare a behavior applicable merely because component names resemble one
another. The template starts unresolved, not pre-approved.

## Phase 3 — source-attack-informed projection

Implement `project_from_attack` using the selected provider and existing
TierScopedLLMClient/LLMQueryInterface. No vendor SDK imports or cross-provider
fallback. Without a connected provider return the normal actionable LLM error.

Prompt inputs: canonical source actions and typed relationships; local components,
flows, identities, controls and objective; analyst mapping constraints; supported
technique candidates; unresolved prerequisites and importer warnings. Treat source
descriptions as data, not instructions. Do not include secrets or follow embedded
links/commands. Use bounded batches with full graph identity and boundary context.

Require the model to return:

- A disposition for every source action: retained, adapted, inapplicable, or
  unresolved, with reason and local bindings where supported.
- Local paths with explicit node identities, component IDs, preconditions,
  transitions, source-action references, assumptions, and behavioral rationale.
- Separately identified local connector actions where the local architecture
  requires additional steps, such as access through a jump host.
- A source-edge accounting report: preserved, changed as hypothesis, inapplicable,
  unresolved, or unsupported. No disappearance of inconvenient branches.

Technique policy: source techniques that resolve in the local catalogue form the
default set. Optional extra candidates for local connector steps must be supplied
explicitly through existing actor/intel grounding or an analyst allowlist checked
against the local catalogue. The model cannot invent IDs or silently borrow the
whole ATT&CK database. Source-reported actor association is separate from local
ATT&CK actor evidence; absence from the actor's catalogue is not a reason to erase
the report's action. Unknown-technique source actions remain inspectable and can
receive behavioral proposals with explicit limitations, without fabricated IDs.

Deterministically validate returned component IDs, technique candidates, source
references, node identity, mapping constraints, and transitions. Every asserted
local network transition must cite an allowed flow and any relevant access
prerequisites. Co-located actions need not invent a network hop. Physical/manual
transitions use the local flow-map semantics. Unknown access remains unknown;
declared controls are not proof that a path is blocked or a detection works.
Reuse the projector's existing transition rules rather than defining new ones:
a step may return over the flow it arrived on (`return: true`), a hop with no
declared flow is `HOP_NOT_DECLARED`, physical movement is `protocol: physical`,
and the continuity check's `STATE_GAP` applies unchanged.

Budget the time. The shell enforces the projector's `long` timeout class, 600 s
per invocation, and each provider client times out at 180 s per request.
Batches must fit inside one invocation, or the action must say how to continue
across invocations without losing source-action accounting.

Mitigations for ICS techniques are ICS ids (`M08xx`/`M09xx`). A local control
covers one only if it is tagged with that id. Actor projections keep their
current enterprise-only guidance; a source-informed projection of ICS
behaviour does not.

Preserve partial outcomes. If no actions are applicable, emit a valid disposition
report with no projected paths and an explicit empty-result status. Never force
a path to satisfy a count. Complete source accounting and successful generation
are different measures.

## Phase 4 — output contracts and provenance

Write a source-informed graph and a projection run record. Whether a matching
scenario seed is also written is open decision D5; the designer does not need
one. Reuse existing export
builders after factoring out shared logic; avoid duplicating a large tool module.
Use a distinct producer/mode and versioned schemas. Never fabricate a historical
projector run or pretend the importer made an LLM call.

Record on outputs:

- Original bundle hash, selected flow ID, source object IDs, markings/references,
  supported source schema version, importer version and source graph hash.
- Actual local flow-map hash, mapping hash, and mapping revision/lineage.
- Adaptation run ID, code identity, prompt hash/version, model/provider/vendor,
  actual served model when available, and complete/partial/error status.
- Per-node origin: source-described, local adaptation, or added connector;
  source-action references; analyst/model binding origin; assumptions and gaps.
- Per-edge relation type, source references, and whether ordering was supplied
  by the source, asserted by an analyst, or hypothesized during adaptation.

Identity must be stable for identical deterministic inputs; generated runs have
distinct run IDs. Distinguish semantic action identity, local occurrence identity,
and path occurrence. An action mapped to two local components creates distinct
local occurrences. Repeated occurrences within one path remain distinct too.
Use explicit node references for new edges; do not use technique IDs as unique
destinations. State schema migration rules and retain legacy input support.

## Phase 5 — visualizer and detection-designer integration

### Visualizer

Add an explicit adapter for the canonical imported source graph and the adapted
graph. For new-format inputs use node/occurrence IDs, not technique+tactic, in
both ASCII and Mermaid. Preserve the current behavior for legacy graphs unless
an independently tested compatibility migration is necessary.

Label actions with technique, behavior, and asset/component. Differentiate
context associations from supported flow edges and hypothetical transitions;
include a legend. Preserve conditions, operators, disconnected actions, and
uncertain order rather than drawing unsupported arrows. The source graph should
be viewable before any local mapping or provider call. Escape imported labels so
they cannot alter Mermaid syntax or inject active HTML.

### Detection designer

**Detect the producer before adapting.** Today any document with an
`attack_graph` key is read as a projector export, and its actor evidence is
computed from the local catalogue. Branch on an explicit producer/mode field
first, so a source-informed graph can never be read as an actor projection,
and so an actor projection keeps exactly today's behaviour. Refuse the raw
imported source graph with a named error: it carries no local components. Add
every new error, warning and review-flag code to the closed catalogues in
`tool.py`, `normalization.py` or `generation.py` and to the normalization
spec's §4.4 table together; the tests hold them to each other.

Add a producer/version-aware input adapter in the normalization layer. Feed the
existing node-context (the spec's `DetectionNodeContext`, which is a spec name
rather than a class) and telemetry-selection seam, retaining new
provenance and applicability fields in validation output, digest, generation
prompts, and drafts. Re-derive context from the immutable source-informed exports
plus the current flow map. Do not add a stored context-pack dependency.

The existing actor-evidence boolean must continue to mean what it means today;
add separate source-report evidence rather than setting local ATT&CK evidence
true just because a third party named an actor. Prompt wording must distinguish
reported source behavior from local hypothesized placement.

Applicable and conditional local nodes can receive drafts; unresolved bindings
receive explicit telemetry/applicability gaps and appropriately limited behavior
guidance. Draft validation compares each draft's `technique_id` with its node's,
and titles lead with the technique id, so a node without one needs a decision
before it can be drafted (open decision D2). Every action in both real bundles
has an id, so this arises only in synthetic fixtures today.

Expect thin telemetry. With the current library most Berserk Bear steps will be
`none_declared` (see *Verified constraints*). Whether the library is extended
first is open decision D4. Either way `none_declared` is a legitimate outcome,
recorded as a collection gap, and never a reason to drop a node or invent a
source. Inapplicable source actions remain in the disposition report, not
silently counted as missing generated detections. Define expected draft coverage
from eligible local occurrences, then separately report source-action accounting.
Never equate either count with operational detection coverage.

Sequence detections require supported ordering, joinable identities, timestamps,
and a justified window. Contextual associations alone permit action-level
detection work, not a proven correlated attack sequence. Collection status stays
unknown unless supplied evidence supports another state. The telemetry library
declares fields; it does not calculate its derived indicators. New drafts must
not claim those indicators are already implemented.

## Tests and acceptance gates

Add independent synthetic fixtures with small, manually specified expected
graphs. Do not rely only on snapshots produced by the converter itself.

| Gate | Required evidence |
|---|---|
| Import without provider | Import succeeds with no LLM, network calls, or vendor keys. |
| Berserk Bear inventory | 12 actions, 7 assets, actor/flow metadata and original IDs retained; T0892 preserved. |
| Berserk Bear semantics | 24 source connections accounted for with typed semantics; no twelve-step temporal chain invented. Assets and related-to links are not promoted to effects. |
| Determinism | Reordering bundle objects changes byte hash but not semantic action identities; identical bytes give identical canonical content apart from explicitly excluded runtime metadata. |
| Repeated techniques | Two same-technique actions on different assets remain separate through import, visualization, adaptation, normalization, and drafts. |
| Structural variety | Effects, condition branches, AND/OR, cycles, disconnected actions, missing IDs, and unresolved external refs have explicit tested outcomes. |
| Mapping cardinality | Exact, role-equivalent, one-to-many, many-to-one, no-match, and unresolved examples retain correct identities and dispositions. |
| No forced applicability | No local RTU yields an inapplicable/unresolved RTU branch; it never becomes a database action by renaming. |
| Access validation | A proposed hop missing from the local map is rejected or retained solely as an explicit gap, never a valid transition. |
| LLM failure handling | Mock invalid IDs, omitted actions, unsupported connectors, truncation, malformed replies, and a failed batch. Preserve accounting and useful successful batches with honest status. |
| Provenance | Source evidence, analyst bindings, imported actor attribution, and model hypotheses remain separable in every exported artifact. |
| Shell/storage | Local-file and registered-artifact inputs work; outputs appear in artifacts/show/export; custom artifact arguments resolve correctly. |
| Second fixture | TwoNet imports with 7 actions, 3 assets and its 14 connections typed, with no change to importer code made for it. |
| Tactic ids | Every `TA` id in both bundles is resolved or reported per D3; `T1133`'s missing tactic is reported, not guessed. |
| Producer detection | An actor projection normalizes byte-identically to before the change; a source-informed graph is never graded with local actor evidence; the raw source graph is refused with its named code. |
| Code catalogues | Every new error, warning and review-flag code is in its catalogue and in the spec table. |
| Manifest | `validate_manifests.py` reports no new failure beyond the 15 known `stability` errors. |
| Regression | Existing actor-driven projection, legacy visualization, designer validation/digest/generation, and export behavior remain compatible. |

Run the affected suites, schema checks, and then the normal repository test suite
where available. Separate pre-existing failures from new failures with evidence.
Do not fix unrelated manifest vocabulary problems to make checks green. Record
commands, results, environment limitations, and unexecuted live checks.

## Operator installation and live-test handoff

Provide a README walkthrough with real implemented flags and artifact examples.
All syntax below is the target workflow; adjust it to final validated interfaces.

```text
load "Berserk Bear Attack on Polish GCPs.json"
artifacts
run attack_flow_importer --action import --artifact_id <loaded-stix-id>
run attack_path_visualizer --artifact_id <imported-source-graph-id> --format both
```

Show how to create/load a local structured flow map, edit/load the generated
mapping template, and inspect `validate_mapping` before invoking a model. Supply
a clearly synthetic OT example map with an applicable subset and an absent
component, plus an edited variant introducing a jump host. Do not portray either
example as the user's actual environment. Name the map `<estate>_flow_map.json`
on purpose, because the estate filter reads the filename. Tag its controls with
ICS mitigation ids where the behaviour is ICS. Use forward slashes in every
Windows path shown.

```text
connect
run adversary_path_projector --action project_from_attack --source_graph_artifact_id <source-id> --flow_map_artifact_id <map-id> --mapping_artifact_id <mapping-id> --export true
run attack_path_visualizer --artifact_id <adapted-graph-id> --format both
run attack_path_detection_designer --action validate_input --artifact_id <adapted-graph-id> --flow_map_artifact_id <map-id>
run attack_path_detection_designer --action digest --artifact_id <adapted-graph-id> --flow_map_artifact_id <map-id>
run attack_path_detection_designer --action generate_detections --artifact_id <adapted-graph-id> --flow_map_artifact_id <map-id>
export --all berserk-bear-local
```

The commands above use the designer's graph-only route. If D5 produces a seed
and a pair is used, give the exact `--artifact_ids <graph>,<seed>` command
instead of leaving it implicit.
Mark adaptation and draft generation as paid provider calls; import, mapping
validation, visualization, validate_input, and digest are deterministic.

Operator checks: imported actions remain distinct; associations are not shown as
proven sequence; mapping gaps are visible; the jump-host variant produces only
supported local transitions; source action dispositions account for everything;
drafts name actual offered telemetry fields; all provenance survives export.
Document install/build instructions using existing repo deployment mechanisms,
including new dependencies if any, and how to revert the extension's code/schema
changes without deleting user artifacts.

## Open decisions

These affect structure or scope and are the operator's to settle. Each lists
the options and a recommendation; none is decided. Implementation that depends
on one should stop at that point and ask, not choose.

**D1 — Where mapping validation lives.** The importer's `validate_mapping` and
the projector's enforcement of analyst mappings apply the same rules, and no
plugin may import another.

- (a) `validate_mapping` becomes a free projector action beside
  `validate_flow_map`; the importer only imports and writes the template.
  *Recommended:* a mapping relates a source graph to a flow map, and the
  projector already owns flow maps and projection.
- (b) Move the mapping rules into a `framework/` module both plugins call.
  Keeps the command where this plan first put it, and adds a framework
  surface.
- (c) Duplicate the rules in both plugins. Contrary to the convention; listed
  for completeness.

**D2 — Source actions with no technique id.** The draft contract is keyed on
technique id.

- (a) Keep them out of draft eligibility: they appear in the disposition
  report and the digest with behaviour-only guidance, and receive no draft.
  *Recommended* until a real bundle needs more.
- (b) Define a draft contract with no technique id: a title rule, a validation
  rule in place of the technique comparison, and taxonomy status
  `not_applicable`.

**D3 — Resolving `TA` ids to tactic names.**

- (a) Vendor a pinned v19.2 table of enterprise and ICS tactic ids and names
  in `framework/reference_data/`, with its release recorded. *Recommended:*
  exact, and the id is the only tactic data the bundles carry.
- (b) Derive the name from the technique's tactics when there is exactly one;
  otherwise report it unresolved. No new data, but `T1693.001` carries three
  tactics and stays unresolved.
- (c) Both: the table, cross-checked against the technique's tactics, with a
  disagreement reported rather than resolved.

**D4 — Telemetry for OT.**

- (a) Extend the telemetry library first with ICS device-level sources (RTU
  and serial-server firmware and configuration, device authentication, ICS
  protocol monitoring), following the library's own rules:
  `collection_status: unknown`, no invented ATT&CK ids, `EM-OT-` ids for
  unmapped behaviour.
- (b) Build without extending it, and record `none_declared` as the expected
  outcome for most OT steps.
- (c) (b) now, with (a) as a separate dated change once the operator has
  decided which OT sources are representative. *Recommended:* it keeps this
  plan's scope bounded and makes the gap visible in the first run's output.

**D5 — A scenario seed for source-informed projections.**

- (a) Graph only. The designer supports graph-only input fully, and a pair
  join adds provenance matching for no gain here. *Recommended.*
- (b) Write a seed too, for `threat_model_analyzer import_scenario`, which
  needs one and has uses outside this workflow.

## Completion deliverables

1. Implemented importer and projection action with registered artifacts.
2. Versioned source/mapping/adapted-graph contracts with runtime validation.
3. Working visualizer and designer adapters, including identity/provenance tests.
4. Fixture-based offline demonstration and synthetic local-map examples.
5. Updated plugin READMEs, relevant specifications, and dated change log. This
   includes the projector's `examples/README.md` mitigation-id guidance, which
   currently tells analysts to use enterprise ids only, and
   `docs/specs/reserved_vocabulary.md`.
6. Test report and operator install/live-test runbook naming unsupported cases.

Do not stop at an import-only converter: the acceptance target includes local
adaptation and detection drafting. Keep unsupported semantics explicit instead
of claiming general Attack Flow compatibility from one successful fixture.
