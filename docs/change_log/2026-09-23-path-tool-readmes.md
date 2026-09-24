# 2026-09-23 — One narrative across the three path tools

**Documentation, plus two small code fixes and three manifests found while
writing it. Suite 1840 → 1844.**

Files: `plugins/threat_modeling/adversary_path_projector/README.md` (new),
`plugins/threat_modeling/attack_path_visualizer/README.md` (rewritten),
`plugins/threat_modeling/attack_path_detection_designer/README.md` (one
section added), `plugins/threat_modeling/adversary_path_projector/examples/README.md`
(Application B added). Code: `attack_path_detection_designer/tool.py` and its
`tests/test_generation.py`; the three plugins' `manifest.json`.

## Why

The designer's README (rewritten at `cc2da9c`) describes that tool well, but
nothing described how the three tools are meant to be used together. The
projector had no plugin-level README, only the flow-map authoring guide in
`examples/`. The visualizer's README still described it as an ingester
companion, and was silent about what it does with a projector graph.

The target reader is a detection engineer handed a common request: *"I am very
concerned about Scattered Spider. How well protected is Application B, and what
can we do to make it better?"* The walkthrough now lives in the projector's
README, as the first tool in the chain. The other two link to it and carry a
"Where this sits" table.

## What the narrative commits to

- **Scope first.** The tools cannot grade "how well protected". They can say
  where the actor's documented techniques plausibly land, whether a control is
  there at all, and what is and is not observable at each step. The README
  tells the engineer to set that expectation with the leader before running
  anything, and gives an example of an answer the output can support and one
  it cannot.
- **Check the map against the actor.** Scattered Spider's closed set (64
  direct techniques, measured with `profile_actor` for this entry) is heavily
  identity-centred: `T1621`, `T1556.006`, `T1556.009`, `T1598.004`,
  `T1684.001`. Application B's map models Okta as one component, with no help
  desk, admin plane or deploy pipeline. The projector routes only over declared
  flows, so the README presents "project as documented" and "project an amended
  copy" as the two legitimate choices. The designer's `edited_map` lineage
  already supports the second.
- **Two model axes, kept apart.** The projection model decides which paths. The
  generation model decides which detections. Recurrence (within a provider) and
  agreement (across providers) identify common patterns and outliers. Drafting
  the same pair under two generation models gives identical `draft_id`s, which
  is the cleanest step-by-step comparison.
- **Carried cautions.** Agreement may reflect how constraining the prompt is
  (2026-09-14 Stage E). `generation_model` must be checked before grading
  anything cross-vendor (the unresolved 09-23 attribution question). Every draft
  is `draft_unvalidated`.

## Found while writing

Each of these was checked in the code. Items 3, 4 and 5 are fixed in this
entry (see *Fixed* below); 1, 2 and 6 are documented only.

1. **The visualizer's ASCII output on a projector graph ends with
   `⚠ Unprotected stages:` listing every non-exit technique.**
   `_build_dag_from_attack_graph` never fills `DAGNode.controls`, so the line
   fires regardless of the flow map. The Mermaid "Has Controls" colour never
   appears on that route, and `--include_controls` is inert there. The
   visualizer README now says the line is not a finding. The projector spec
   already records the fix as deferred ("rendering the component binding").
2. **The visualizer merges nodes by `(technique_id, tactic)` across paths and
   components.** The designer spec's *Downstream diagram styling* says a
   renderer must not do this. Documented as a limitation.
3. **A partial `generate_detections` result is not persisted.** It returns
   `ok: false` with the partial result attached, and the shell's failure branch
   (`framework/cli/shell.py`, after `if result.ok:`) prints the message and
   saves nothing. The drafts that passed, already paid for, were lost.
4. **`LLM_UNAVAILABLE` in the designer suggests `use threat_modeling
   <provider>`.** The shell's syntax is `use <provider> [for <tool>]`, so the
   suggested command would be rejected as an unknown argument.
5. **Stale manifests.** The designer's `description_long` still says
   `generate_detections` "lands later". The visualizer's `chains_from` omits
   the projector and the ingester, which are its two real sources. Its
   `stability: stable` is one of the known schema failures and is left alone.
6. **Only the visualizer auto-exports on Cloud Run by default**
   (`DEFAULT_AUTO_EXPORT_TOOLS`). The walkthrough says to run `export --all`,
   or to widen `EVENTMILL_AUTO_EXPORT_TOOLS`, before the session ends.

## What was verified

`validate_flow_map` on `application_b_flow_map.json` and `profile_actor` for
Scattered Spider were run locally with no LLM, and their summaries are quoted
verbatim. Every command, argument, default, file name and field path in the
walkthrough was checked against the code: the input schemas, `do_use`,
`providers probe`, `_group_confounds`, `_agreement_grade`,
`_auto_persist_result`, `detection_draft.schema.json` and the timeout classes.
**No projection or generation was run for this entry.** The walkthrough
describes the workflow and does not report results from it. The Scattered
Spider / Application B pairing in particular has no export on the current code
revision. The retired `20260915_204815` pair is the only projection of it.

## Fixed

**3 — a partial generation result is saved.** The fix is in the plugin, not
the shell. Changing the shell's failure branch to persist `result.result`
would change it for every tool. `_persist_partial` writes the incomplete
result to `$EVENTMILL_WORKSPACE/artifacts/attack_path_detection_designer_partial_<UTC stamp>.json`,
registers it through `context.register_artifact` as `json_events` with
`kind: detection_drafts_partial`, and records where it went as
`result.partial_file`. The message prints the artifact id and path, because on
failure the message is all the shell prints. A write or registration failure
is reported in the message and never replaces `GENERATION_INCOMPLETE`. A
complete run writes nothing extra, since the shell's auto-persist handles it
as before.

**4 — the `LLM_UNAVAILABLE` message** now says
`use <provider> for attack_path_detection_designer`.

**5 — manifests aligned with what the tools do today.**

- **Designer:** `description_short` / `description_long` describe the three
  implemented actions, heavy-tier drafting, `draft_unvalidated`, and the
  partial save. They no longer say generation "lands later". Adds the
  `operation:generate` capability and the `detection_engineering` and
  `telemetry` tags.
- **Projector:** `chains_to` gains `attack_path_detection_designer`, which
  consumes the `json_events` it produces, so the chain is executable under the
  rule `threat_report_analyzer`'s contract test enforces. The description names
  the designer, says the group summary counts recurrence per provider and
  agreement across providers, and says `normalize_flow_map` is not
  implemented.
- **Visualizer:** `chains_from` adds `adversary_path_projector` and
  `threat_intel_ingester`, its two real artifact sources. The two analyzers are
  kept, because they can still feed it inline `stages`. The description states
  that the graph route is component-blind.

Unchanged on purpose: version fields (no behaviour change in the projector or
visualizer, and the designer's version tracks its stages), and the
visualizer's `stability: stable`, which is one of the 15 known validator
failures that CLAUDE.md says not to remap in passing. The designer's module
docstring still lists `generate_detections` as planned. It is a comment, and
it was left alone under the repository's comment convention.

**Verified:** four new tests. A partial run writes and registers its file with
the drafts that passed. Without a registry, the file is still written. A failed
write is reported and does not raise. A complete run writes nothing extra. The
`LLM_UNAVAILABLE` test now asserts the command text. An autouse fixture points
`EVENTMILL_WORKSPACE` at `tmp_path`, so these tests never write into the
repository. Full suite 1844 passed. `validate_manifests.py` still reports
exactly the 15 known `stability` errors, and the projector and designer
manifests pass. `ruff` is not installed in this environment and was not run.
