# 2026-09-23 — Attack Flow import plan reviewed against the code

**Planning only. No code changed; suite unchanged at 1844.**
Subject: `docs/specs/attack_flow_environment_adaptation_plan.md`, committed at
`66445c1` with this review applied.

## What the plan is

A new input route for the three path tools. It imports a third-party Attack
Flow STIX 2.1 bundle, adapts its actions to a local flow map with an LLM, and
drafts detections from the result. A new deterministic `attack_flow_importer`
plugin does the import; a new `project_from_attack` action in
`adversary_path_projector` does the adaptation; the visualizer and designer
gain adapters. The worked fixture is *Berserk Bear Attack on Polish GCPs*, held
outside the repository in `../test_data/attack_examples/`.

## Why it was reviewed before any code

The plan was written in an environment without Python. Its structure was
sound, and most of its factual claims held when checked. But four points would
have led an implementer to build the wrong thing, and several others would
have had to be rediscovered at implementation time.

## What was checked, and held

The fixture's 12 actions, 7 assets and 24 connections (12 `asset_refs`, 10
`related-to`, 2 asset `object_ref`s); Attack Flow 2.0.0; `T0892` correct in
the JSON and misspelled `T08921` only in the `.eventmill_input.txt`; the
`export --all` folder layout; `--export true` parsing; the visualizer's
node-merging limitation; and the instruction not to revive N4.

## What the review changed in the plan

**The four that would have gone wrong:**

1. **Mapping validation in two plugins.** The importer validated mappings and
   the projector enforced the same rules, which means shared code across
   plugins, and no plugin may import another. Now open decision D1.
2. **The designer does not check which tool produced its input.** Any document
   with an `attack_graph` key is read as a projector export, and
   `actor_evidence` is then computed from the local catalogue. "Berserk Bear"
   resolves to G0035 Dragonfly, whose two ICS techniques include none of the
   fixture's, so a source-informed graph would be silently misgraded. The plan
   now requires producer detection before adapting, and a named refusal of the
   raw source graph.
3. **Tactic ids cannot be resolved as written.** The bundles carry tactics only
   as `TA` ids, contain no tactic objects, and `T1133` has none. No local table
   maps `TA` ids to names. Now open decision D3.
4. **Telemetry for OT is thin.** Six `plant_ot` sources, none observing RTU or
   serial-server firmware, device credentials, or Modbus/DNP3. Most steps would
   be `none_declared`. Now open decision D4.

**Facts added** to *Verified constraints*: neither real bundle has any
`effect_refs`, operators or conditions, so ordering is usually unspecified;
most of the sample is ATT&CK for ICS, which the local reference supports
(techniques, ICS tactics in `TACTIC_ORDER`, and the ICS mitigations among the
96); the estate comes from the flow map's filename; only the singular
`artifact_id` is resolved by the shell; sibling modules must be loaded by file
location; use `jsonschema` (base dependency) and not `stix2` (declared in the
log-analysis extra only, not installed, unused); forward slashes in Windows
paths.

**Also added:** the second real fixture, *TwoNet Hacktivist Attack* (7
actions, 3 assets, 14 connections, no technique shared with Berserk Bear);
manifest conventions for the new plugin; reuse of the projector's existing hop
rules; the 600 s / 180 s time budget; ICS mitigation ids, which contradict the
projector's current enterprise-only guidance for this case; registering new
enums in `reserved_vocabulary.md`; five new test gates; and the corrected class
name `ExecutionContext` (the plan had `ToolContext`).

## Left open for the operator

Each is written into the plan's *Open decisions* section with options and a
recommendation, and the plan tells an implementer to stop and ask rather than
choose.

| | Decision | Recommended |
|---|---|---|
| D1 | Where mapping validation lives | a free projector action beside `validate_flow_map` |
| D2 | Source actions with no technique id | out of draft eligibility |
| D3 | `TA` id to tactic name | a pinned v19.2 table in `framework/reference_data/` |
| D4 | Telemetry for OT | build without extending the library now; extend it as a separate change |
| D5 | A scenario seed | graph only; the designer needs none |

## How it was verified

The two bundles were parsed and counted directly. `validate_technique_id`,
`enrich_technique`, `mitigations_for_technique`, `canonical_tactic` and
`find_group` were run against the fixture's ids. The telemetry library's
sources were listed by estate. The shell's flag parsing, artifact injection,
`load` type inference and export paths, and the designer's adapter and
grounding, were read in the code. No implementation was started.
