# Change Log — `adversary_path_projector` Phase 3: the `threat_model_analyzer` handoff

**Date:** 2026-09-11
**Primary Files Modified:**
`plugins/threat_modeling/threat_model_analyzer/tool.py`,
`plugins/threat_modeling/threat_model_analyzer/manifest.json`,
`plugins/threat_modeling/threat_model_analyzer/schemas/input.schema.json`,
`plugins/threat_modeling/threat_model_analyzer/schemas/output.schema.json`,
`plugins/threat_modeling/threat_model_analyzer/tests/test_contract.py`,
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`
**Supporting Files:**
`plugins/threat_modeling/threat_model_analyzer/README.md`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`docs/specs/adversary_path_projector.md`

Follows `2026-09-10-projection-run-records.md`.

---

## Scope, as agreed

The projector is a **first-step triage** tool, not a security platform. It
answers two questions:

1. Is there a control at all where the actor's path lands?
2. Is there a credible path we have not considered?

It does not assess how good a control is, and it does not say whether an
application is "safe" — the management conversation about risk is held by
people. Control quality is an explicit later step. That scope decided several
things below.

## Problem

Since Phase 2 the projector has written a scenario seed shaped for
`threat_model_analyzer`, and nothing read it. The analyzer's gap analysis —
steps with no implemented control, incomplete controls, easy bypasses,
defense-in-depth coverage — is the answer to triage question 1, and the seed
could not reach it.

The analyzer also had no way to save a scenario. `list_scenarios` returns
counts and `export` returns markdown, so a half-built threat model died with
the process.

## Changes

### `threat_model_analyzer` — `import_scenario` (new)

`import_scenario --artifact_id <seed>` loads a projector seed, or an
`export_scenario` result, into the tracker.

- **Each path becomes its own scenario, up to `max_paths` (default 6, 1–10).**
  The spec said to default to "the highest-ranked path", but the projection
  prompt never ranks paths — seed order is only reply order, so that default
  had nothing behind it. Importing each path keeps every candidate in view,
  which is what triage wants; the cap exists because every imported path is a
  scenario an analyst has to read. Paths over the cap are listed by id in
  `skipped_path_ids`, not silently dropped. `--path_id` imports one.
- **The document is validated in full before anything is created.** An invalid
  `control_type` used to raise inside `DefenseLayerType(...)` and surface as
  `INTERNAL_ERROR`; now every problem is listed and nothing is imported, so a
  bad document cannot leave half a scenario in the tracker.
- **Ids are reissued.** A seed numbers its controls from `SC-0001`, which would
  collide with scenarios already loaded. Event references to the old control ids
  follow the reissue; references by name (what the seed uses) pass through.
- **Wrong documents are refused with a reason.** The projector's attack graph
  artifact ("not its attack graph") and a `list_scenarios` result (counts only —
  importing it would create empty scenarios) both fail with a message that
  names the right artifact.
- Reads through `context.artifacts` like the other plugins, falling back to the
  `file_path` the shell injects from `artifact_id`.

### `threat_model_analyzer` — `export_scenario` (new)

Returns scenarios in full — controls and events included — as `result.result`,
so the shell's auto-persist writes an artifact that `import_scenario` reads back
unchanged. A round-trip test asserts it. Omitting `--scenario_id` exports every
scenario in the tracker, which is the useful form for saving a session's work
before a restart.

### `threat_model_analyzer` — model and report changes

- `AttackEvent` gained optional `tactic` and `evidence`; `add_event` accepts
  both. This closes the question left open in Phase 2: without the tactic a
  seed could not be audited on its own, which is how a bad tactic hid for four
  events. `evidence` carries `documented` vs `via_software`, which is half of
  what makes a projected path credible (question 2).
- `AttackEvent.to_dict()` now includes `success_indicators`, which it always
  omitted — required for a lossless round trip.
- `ThreatScenario` gained `path_id` and `to_full_dict()`.
- The markdown report shows tactic, evidence and projected path per step, and
  for `actor_projection` scenarios states that placement is modelled, not
  observed. Analyst-built scenarios render as before.
- `"actor_projection"` added to the `source_type` enum.

### `threat_model_analyzer` — `analyze_document` narrowed

`THREAT_MODEL_PROMPT` asked for "Attack Paths: step-by-step attack sequences with
MITRE ATT&CK mapping", and the code never parsed or validated any of it. The
prompt now summarises what the document itself states — scope, threats named,
controls documented, gaps stated, recommendations — and forbids constructing
attack paths or assigning technique ids the document does not cite.
`description_long` says the same and points to `adversary_path_projector` for
actor projection, so the router can tell the two apart. `TABLETOP_PROMPT` is
unchanged. `content[:8000]` still truncates without saying so; noted, not
touched.

Manifest version 1.0.0 → 1.1.0; `chains_from` gained `adversary_path_projector`.
The legacy `threat_modeling:` capability names were left as they are — they are
part of the pre-existing schema failure, and adding new ones in that form would
extend it.

### `adversary_path_projector` — seed fixes

- **Every declared control is in the seed.** `_build_scenario_seeds` read only
  per-component controls, so estate-wide controls (1 in the OT example, 2 in
  the SaaS example) and flow-level controls never reached gap analysis — which
  would answer question 1 with "no control" where there is one.
- Events carry `tactic` (the corrected value Phase C settled on) and `evidence`.
- The unused `control_ids` map was removed with the loop it lived in.

## Deliberately not changed

**`blocking_controls` stays per component.** Any implemented preventive control
on the component a step lands on counts as blocking, whether or not it
addresses that technique — a WAF "blocks" T1078. That is the right test for
"is there a control at all" and an overstatement for "is it good enough". The
second question belongs to the control-quality step, not here. Documented in
the analyzer README and the spec so a reader does not take "blocking" as an
effectiveness claim.

The markdown label for such a step changed from **PROTECTED** to
**CONTROL_PRESENT**. The check underneath is unchanged; the label now says what
was actually checked, and so starts the conversation with a reader about
whether the control is good enough rather than implying it has been answered.
`DETECT ONLY` and `UNPROTECTED` are unchanged. Cosmetic, so not retested.

`ScenarioTracker` is still process-scoped, not session-scoped. `export_scenario`
gives persistence a manual path, which is what blocked work; the README now
says scenarios live in memory until exported.

## Tests

`threat_model_analyzer` 69 (was 32); `adversary_path_projector` 195 (was 192);
`threat_modeling` pillar 332 (was 292); full suite **883 passed** (was 843).

New coverage: import of each path, the default cap of 6 with skipped ids
reported, `max_paths` and `path_id`, unknown `path_id` listing what exists,
tactic and evidence carried, id reissue with references following, a bad
document importing nothing, `sequence_order` 0 refused, `list_scenarios` and
attack-graph documents refused, artifact and file sources, gap analysis on an
imported scenario, the projection caveat present on imported and absent on
analyst scenarios, export/import round trip into a fresh tracker, schema enums
asserted equal to the code's constants so they cannot drift, the narrowed
prompt, and an end-to-end test that a real projector seed imports, analyses
and renders.

`validate_manifests.py` still reports exactly the 15 pre-existing `stability`
errors and nothing else. `ruff` and `black` are not installed here; style was
matched by hand.

## Not verified

No live run. Everything here is deterministic — the hand-off involves no LLM
call — and the end-to-end test drives the real projector code path against a
scripted reply. The narrowed `analyze_document` prompt has not been run against
a model.

## Next

- **Phase 3b** — run-group summary: count how often each path recurs across a
  `run_group` and show one representative variant per recurring path rather
  than every near-duplicate. Recurring = present in at least half the runs, in a
  group of three or more.
- **Phase 4** — `normalize_flow_map`. Agreed rule: a control whose status the
  source does not state is set to `partial` and flagged as a potential
  weakness, never defaulted to `implemented`. Plus the plugin README, a
  deliberately malformed example map, and a first live run on the OT map.
