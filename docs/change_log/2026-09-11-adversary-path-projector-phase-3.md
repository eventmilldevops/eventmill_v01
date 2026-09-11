# Change Log — `adversary_path_projector` Phase 3: the `threat_model_analyzer` handoff, and triage-report wording

**Date:** 2026-09-11
**Primary Files Modified:**
`plugins/threat_modeling/threat_model_analyzer/tool.py`,
`plugins/threat_modeling/threat_model_analyzer/manifest.json`,
`plugins/threat_modeling/threat_model_analyzer/schemas/input.schema.json`,
`plugins/threat_modeling/threat_model_analyzer/schemas/output.schema.json`,
`plugins/threat_modeling/threat_model_analyzer/tests/test_contract.py`,
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`
**Supporting Files:**
`plugins/threat_modeling/threat_model_analyzer/README.md`,
`plugins/threat_modeling/adversary_path_projector/examples/README.md`,
`docs/specs/adversary_path_projector.md`

Follows `2026-09-10-projection-run-records.md`.

---

## Summary of the session

1. Reviewed the 2026-09-09 and 2026-09-10 change logs and the spec, and
   re-planned the remaining phases against the question the tool exists to
   serve (below).
2. Agreed the tool's scope: **first-step triage**, not a security platform and
   not a safety verdict.
3. Built Phase 3 — `import_scenario` and `export_scenario` on
   `threat_model_analyzer`, `actor_projection` source type, narrowed
   `analyze_document`, and fixes to the projector's scenario seed.
4. Reviewed a live Volt Typhoon projection and its import (verified below).
5. Made the projector's mitigation summary say exactly what it checked.
6. Relabelled every projected output so no reader can take it for a confirmed
   attack or a likelihood assessment: "Projected from threat intelligence, not
   a confirmed attack path."
7. Stopped the test suite writing fixture output into the real
   `workspace/artifacts`, and fixed the `attack_path_visualizer` bug that made
   one of those leaks impossible to redirect.
8. Proposed Phase 3c — step state — in response to a review criticism that
   paths lack the attack state connecting their steps. Design only; awaiting
   approval.

## Scope, as agreed

The management question behind the tool is "is application X safe from threat
actor Y, given current threat intelligence about Y?" The tool does not answer
that yes or no, and should not claim to: the model is asked for attack paths and
will always produce some, so the absence of a path can never mean "safe". The
risk conversation with management is held by people.

What the tool does is first-step triage, answering two questions:

1. **Is there a control at all** where the actor's projected path lands?
2. **Is there a credible path we have not considered?** Credible means the
   technique is sourced (ATT&CK attributes it to the actor) and the path
   recurs — across runs, or across actors.

**How good a control is** — whether a WAF actually addresses Valid Accounts —
is an explicit later step, not this one.

The framing readers should take away: the report combines the organization's
inside knowledge of its own architecture and controls with a current LLM
generating attack paths the way an adversary would have to. Both sides can
speculate with LLMs; the insider has the better vantage point.

## Decisions taken

| Question | Decision |
|---|---|
| Carry tactic and evidence on imported events? | Yes — both, as optional `AttackEvent` fields |
| What `import_scenario` does without `--path_id` | Imports each path, up to `max_paths`, default **6** — a cap to guard tokens and analyst time |
| `normalize_flow_map` (Phase 4): a control whose status the source does not state | Set to `partial` and flagged as a potential weakness — never defaulted to `implemented` |
| Run-group summary (Phase 3b) | Count recurring paths and show **one** representative variant per path — triage needs the distinct choices, not near-duplicates. Recurring = in at least half the runs of a group of three or more |
| Per-component `blocking_controls` overstates protection | Accepted for triage; per-technique effectiveness belongs to the control-quality step |
| Wording for projected output | "Projected", not "estimated" — see below |

## Problem

Since Phase 2 the projector has written a scenario seed shaped for
`threat_model_analyzer`, and nothing read it. The analyzer's gap analysis —
steps with no implemented control, incomplete controls, easy bypasses,
defense-in-depth coverage — answers triage question 1, and the seed could not
reach it.

The analyzer also had no way to save a scenario. `list_scenarios` returns
counts and `export` returns markdown, so a half-built threat model died with
the process.

## Changes — Phase 3

### `threat_model_analyzer` — `import_scenario` (new)

`import_scenario --artifact_id <seed>` loads a projector seed, or an
`export_scenario` result, into the tracker.

- **Each path becomes its own scenario, up to `max_paths` (default 6, 1–10).**
  The spec said to default to "the highest-ranked path", but the projection
  prompt never ranks paths — seed order is only reply order, so that default
  had nothing behind it. Paths over the cap are listed by id in
  `skipped_path_ids`, not silently dropped. `--path_id` imports one.
- **The document is validated in full before anything is created.** An invalid
  `control_type` used to raise inside `DefenseLayerType(...)` and surface as
  `INTERNAL_ERROR`; now every problem is listed and nothing is imported, so a
  bad document cannot leave half a scenario in the tracker.
- **Ids are reissued.** A seed numbers its controls from `SC-0001`, which would
  collide with scenarios already loaded. Event references to the old control ids
  follow the reissue; references by name (what the seed uses) pass through.
- **Wrong documents are refused with a reason.** The projector's attack graph
  artifact and a `list_scenarios` result (counts only — importing it would
  create empty scenarios) both fail with a message naming the right artifact.
- Reads through `context.artifacts` like the other plugins, falling back to the
  `file_path` the shell injects from `artifact_id`.

### `threat_model_analyzer` — `export_scenario` (new)

Returns scenarios in full — controls and events included — as `result.result`,
so the shell's auto-persist writes an artifact that `import_scenario` reads back
unchanged; a round-trip test asserts it. Omitting `--scenario_id` exports every
scenario in the tracker, which is the useful form for saving a session's work
before a restart.

### `threat_model_analyzer` — model changes

- `AttackEvent` gained optional `tactic` and `evidence`; `add_event` accepts
  both. Without the tactic a seed could not be audited on its own, which is how
  a bad tactic hid for four events in Phase 2. `evidence` (`documented` /
  `via_software`) is half of what makes a projected path credible.
- `AttackEvent.to_dict()` now includes `success_indicators`, which it always
  omitted — required for a lossless round trip.
- `ThreatScenario` gained `path_id` and `to_full_dict()`.
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
- Events carry `tactic` (the value Phase C settled on) and `evidence`.
- The unused `control_ids` map was removed with the loop it lived in.

## Verified against a live run

`Volt Typhoon` against `claims_portal_flow_map.json`, `--max_paths 4`, Gemini at
`medium`, ~60–70s. Two paths, 14 steps, all `documented`, no rejections, no
tactic corrections, no kill-chain warnings. Two paths rather than four is the
map's ceiling, not a failure: the portal is the only internet-facing component
with onward flows, and there are two crown jewels.

```
[volt-portal-webshell-docstore]  portal:T1190 -> portal:T1505.003 -> portal:T1059.004
                                 -> portal:T1552 -> claims_api:T1078
                                 -> claims_api:T1090.001 -> doc_store:T1083 -> doc_store:T1005
[volt-portal-mtls-claimsdb]      portal:T1190 -> portal:T1059.004 -> claims_api:T1570
                                 -> claims_api:T1552.004 -> claims_db:T1078 -> claims_db:T1005
```

`import_scenario` on the seed produced exactly what the flow map predicts:
TS-0003 with 8 of 8 steps having no implemented preventive control (the portal
WAF is `partial`; the API and document store have no controls), and TS-0004 with
4 of 6 (the two claims-database steps carry the implemented database firewall).

What the run showed, recorded for readers of later reports:

- **Two actors, the same two routes.** Scattered Spider on 2026-09-09 took the
  same component routes through this map — through the unauthenticated
  `claims_api → doc_store` flow `f5`, and through the API's mTLS private key to
  the database. When different actors converge, the weakness is architectural.
- **The strongest control was walked around, not defeated.** The IdP's
  conditional access (implemented, high bypass difficulty) sits on neither
  path: the first takes OAuth tokens from the portal's own configuration and
  presents them to the API directly. "The attacker went around the thing that
  was expected to stop them" is the management message.
- **`CONTROL_PRESENT` is not "stopped".** The two database steps show the
  firewall, and the path's premise is presenting stolen mTLS keys that the
  firewall lets through — the control-quality question, deferred by design.
- **Technique labels at data stores are the nearest documented fit.** The
  document store (S3) and database (Postgres) steps use T1005 and T1083, which
  describe host-local files. Better fits — T1530 Data from Cloud Storage, T1213
  Data from Information Repositories — are not in Volt Typhoon's ATT&CK set, so
  the closed set forced the nearest documented technique. That is the grounding
  rule working, but the mitigation list for those steps is T1005's, not T1530's.
- **Model prose is not validated.** The path description calls the document
  store "unauthenticated"; the store requires IAM and it is flow `f5` that is
  unauthenticated. The objective calls the same store "restricted". FRP, named
  in a rationale, is genuinely Volt Typhoon's S1144 — correct by luck, not by
  check.
- **Access levels do not chain.** AE-0004 ends at `credentials` and AE-0005
  starts at `user`: `required_access` / `resulting_access` come from a fixed
  table keyed on each step's tactic (`_ACCESS_BY_TACTIC`), not from the model
  and not threaded between steps. Each event is atomic — one technique on one
  component — and nothing records how it was carried out beyond the model's
  rationale.

## Changes — the mitigation line in the projection summary

The live run's summary ended:

```
ATT&CK mitigations not declared anywhere: M1013, M1015, M1016, M1017, M1018, M1022, +16 more.
```

That reads as 22 missing controls. It was not:

- **Untagged controls cannot match.** Only one of that map's controls — the
  `partial` WAF, `M1050` — declares a `mitre_mitigation_id`. Conditional access,
  the database firewall and DDoS protection declare none.
- **"Anywhere" was false.** `uncovered_mitigations` is diffed against the
  controls on the step's own component only. Estate-wide and flow controls are
  never consulted.

The summary now says exactly what was checked:

```
No controls declared at all on: claims_api, doc_store.
ATT&CK mitigations for these techniques that no control on the targeted component declares: M1013, ... +16 more.
Caution: 1 of 2 control(s) on the targeted components carry no ATT&CK mitigation id and cannot be matched, so some listed mitigations may already be in place. Estate-wide and flow controls are not checked against this list.
```

The first line is the unambiguous triage answer and comes first. The caution
appears only when an untagged control exists. Backed by a new `control_tagging`
block on the `project_paths` result (targeted components, control count, tagged
count, components with no controls), computed in `_validate_projection` from the
kept paths. The comparison itself is unchanged.

## Changes — wording: projected, not confirmed, not a likelihood

The people reading these reports struggle with ambiguity, and several labels
claimed more than was checked. "Placement is modelled, not observed" was
accurate and too technical. "Estimated" was tried and dropped: it implies a
likelihood assessment, which the tool does not make, and invites "estimated how
likely?". "Projected" says what happened and matches the tool's name.

One sentence now appears in every projected output, identical in both plugins
(`PROJECTION_NOTICE`; a test asserts the two copies match):

> Projected from threat intelligence, not a confirmed attack path.

| Output | Change |
|---|---|
| Projector summary, single run and `--runs` | The sentence replaces "Placement is modelled, not observed" |
| Attack graph and scenario seed files | New top-level `status: "projected"` and an `interpretation` paragraph — people open these files directly |
| Analyzer report, projected scenarios | Title *Projected Threat Scenario*; source line *(projected from threat intelligence)*; the sentence plus how the path was made and that it is not a likelihood assessment; *Projected Attack Sequence* |
| Analyzer report, each projected step | Path description prefixed *Path summary written by the LLM (projection)*; step prose prefixed *LLM rationale (projection, not verified)*; access relabelled *Typical access for this tactic (not tracked step to step)* |
| Analyzer report, every scenario | Step label **PROTECTED → CONTROL_PRESENT**; "Blocking Controls" → *Preventive Controls Present*; evidence value explained in words; "Unprotected Steps" in the gap summary → *Steps With No Implemented Preventive Control*, which is what it counts (a detect-only step was included under "unprotected") |
| `import_scenario` summary | The sentence; "no implemented control" → "no implemented preventive control" |
| `gap_analysis` | Result carries `source_type`; summary breaks `total_issues` into steps, incomplete controls and easy-bypass controls, says one control can count twice (the claims portal WAF is both `partial` and `low` bypass), and ends with the sentence for a projected scenario |

`CONTROL_PRESENT` and *Preventive Controls Present* both replace wording that
read as a claim the control stops the technique. What was checked is that an
implemented preventive control sits on the component; saying so starts the
control-quality conversation instead of implying it is settled. The JSON field
keeps its name, `blocking_controls`. `DETECT ONLY`, `UNPROTECTED` and
*Detecting Controls* are unchanged.

## Changes — test output no longer leaks into the real workspace

A review criticism cited `workspace/artifacts/adversary_path_graph_20260911_125838.json`
as "the latest artifact". It was not model output: its steps are the projector
test suite's scripted `_good_projection()` reply, word for word. The tests had
been writing into the operator's real artifact directory, where fixture output
is indistinguishable from a genuine projection by filename.

At the time of the fix, of the files in `workspace/artifacts`:

| Kind | Test output | Real |
|---|---|---|
| `adversary_path_graph_*` | 37 | 7 |
| `adversary_scenario_seed_*` | 37 | 7 |
| `attack_path_mermaid_*` (`.md` + `.mmd`) | 66 | 2 |

Two more diagrams were written by the first verification run, below — 142 test
files in all. The folder is gitignored, so none of it reached the repository.
All 142 were deleted, selected by filename pattern **and** fixture content
(the `portal-to-db` path or its scripted rationale). The 18 files left are the
genuine 2026-09-09 runs — Scattered Spider, Fox Kitten and APT29 graphs and
seeds, two auto-persisted `adversary_path_projector_*` results, one Mermaid
pair — plus nothing else from the tools.

Two causes:

- **No workspace isolation.** Plugins and the shell resolve
  `$EVENTMILL_WORKSPACE`, falling back to `./workspace`. Only a handful of tests
  redirected it; the rest wrote to the real directory. A new repo-root
  `conftest.py` gives every test — in `tests/` and `plugins/` alike — a throwaway
  workspace through an autouse fixture. A test that sets its own still wins.
  The existing `tests/conftest.py` could not do this: it only applies beneath
  `tests/`. Every workspace read in the codebase happens at call time, not at
  import, so the fixture reaches all of them.
- **`attack_path_visualizer` ignored `EVENTMILL_WORKSPACE` entirely.** It wrote
  to a hardcoded `Path("workspace") / "artifacts"`, relative to wherever the
  process started. After the fixture landed, one run still wrote two diagrams —
  from the projector's end-to-end test that renders through the visualizer. This
  is a production bug, not only a test one: the visualizer's output landed in
  the right place on the container only because `/app` happens to be the
  working directory. It now resolves the workspace the same way as every other
  plugin. The end-to-end test asserts the rendered files land in the test
  workspace, so the regression cannot return silently.

Verified: a full run (888 passed) wrote **zero** files to `workspace/artifacts`,
checked by timestamp against a marker taken before the run.

## Proposed — Phase 3c: step state

A review of the output criticised the path format as **under-specified, not
excessively speculative**: it records technique → component → technique →
component, but not the attack state connecting the steps, so a path can jump
from exploiting a frontend to reusing an API token without saying how the token
was obtained. The criticism is correct in principle — the live Volt Typhoon run
did supply the bridging step (`portal:T1552`), but nothing asks for it, requires
it or checks it.

The design is in `docs/specs/adversary_path_projector_step_state.md`. In short:

- The model supplies what cannot be computed: `precondition`,
  `exploited_condition`, `result`, 1–3 `assumptions` (the test plan), and
  `access_before` / `access_after` from a **fixed seven-state vocabulary**.
- The tool computes what it already holds: the `transition` flow, the
  `controls_in_play`, and `actor_support` — refined to procedure level from
  ATT&CK's procedure examples, with a `procedure_excerpt`. The review's own
  proposal had the model supply these; they moved to the tool side for the same
  reason `evidence` is never read from the reply.
- A deterministic continuity check flags **`STATE_GAP`** when a step needs
  access no earlier step provided — as a warning, like the kill-chain checks.
- Path mapping — closed set, component and hop checks, tactic correction — is
  unchanged.

The procedure excerpt was checked against the lookup: ATT&CK's G1017/T1552
example reads "obtained credentials insecurely stored on targeted network
appliances", while the projection placed T1552 on a Django host — the kind of
documented-versus-adapted gap the excerpt makes visible at a glance. Six
decisions are listed at the end of the design for approval.

## Deliberately not changed

- **`blocking_controls` stays per component.** Any implemented preventive
  control on the component a step lands on counts, whether or not it addresses
  that technique. Right for "is there a control at all", an overstatement for
  "is it good enough" — which is the control-quality step.
- **Whether estate-wide and flow controls should count toward covering a step's
  mitigations** is a semantics decision, not a wording one, and was not taken.
- **`ScenarioTracker` is still process-scoped.** `export_scenario` gives
  persistence a manual path; the README now says scenarios live in memory until
  exported.

## Tests

`threat_model_analyzer` 71 (was 32); `adversary_path_projector` 198 (was 192);
full suite **888 passed** (was 843).

Coverage added: import of each path, the default cap of 6 with skipped ids
reported, `max_paths` and `path_id`, unknown `path_id` listing what exists,
tactic and evidence carried, id reissue with references following, a bad
document importing nothing, `sequence_order` 0 refused, `list_scenarios` and
attack-graph documents refused, artifact and file sources, gap analysis on an
imported scenario, export/import round trip into a fresh tracker, schema enums
asserted equal to the code's constants, the narrowed prompt, an end-to-end test
that a real projector seed imports, analyses and renders, the seed carrying
every declared control, the mitigation summary's three lines, artifact files
marked `projected`, the gap summary breaking down `total_issues`, every
relabelled line present on a projected report and absent from an analyst one,
and the notice identical in both plugins.

`validate_manifests.py` still reports exactly the 15 pre-existing `stability`
errors and nothing else. `ruff` and `black` are not installed here; style was
matched by hand.

## Not verified

The narrowed `analyze_document` prompt has not been run against a model. The
relabelled report was rendered locally and checked by eye, not against a live
import.

## Open, not fixed

- `attack_path_visualizer`'s diagram of a projection carries no notice; it
  ignores `status` and `interpretation`. Belongs with the deferred renderer
  change.
- `entry_vectors` in the seed holds a component id (`portal`) while
  `target_assets` holds names.
- The projection summary's control lines are not indented to match the path
  lines above them.
- The Google SDK's "automatic function calling (AFC)" notice still reaches the
  console, past the 2026-08-24 change that routed dependency warnings to the log
  file.

## Next

- **Phase 3b** — run-group summary: count how often each path recurs across a
  `run_group` and show one representative variant per recurring path rather
  than every near-duplicate. Recurring = present in at least half the runs, in a
  group of three or more.
- **Phase 4** — `normalize_flow_map`. A control whose status the source does not
  state is set to `partial` and flagged as a potential weakness, never
  defaulted to `implemented`; the model marks every inferred field and the tool
  lists them for review. Plus the plugin README, a deliberately malformed
  example map, and a first live run on the OT map.
