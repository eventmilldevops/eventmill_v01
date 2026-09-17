# A fourth fixture: component-bound with a real access gap

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** no repository files changed. Two export files added to
`C:/projects/eventmill_v02/test_data/path_projector/`; fixture inventory and
transition counts updated in
`docs/specs/attack_path_detection_normalization.md`.
**Status:** characterized and recorded.

The Fox Kitten run of 2026-09-17T02:26:46Z — the one that live-confirmed
`code_id_source` — is now the fourth fixture. It was retrieved from
`gs://evtm-v011-common/exports/adversary_path_projector/` and saved as
`exports_adversary_path_projector_adversary_{path_graph,scenario_seed}_20260917_022646.json`.

## What it adds

`20260916_192507` was built to give normalization a `component_bound` example,
and it did — but every one of its steps came back `state_check: ok`. That left
the inherited-access-gap route to `multistep_access: true` exercisable only on
`165537`, which is `asset_named`. The two properties that matter most to the
assessment tuple could not be tested together.

This pair has both. All nine nodes bind to a flow-map component carrying
technologies, and `scm-to-vault` step 2 carries a `state_check: gap` — the
projector's own continuity check firing because `T1059` on `ci_runner` needs
`network_reach` there while the declared flow comes from `scm`, which no earlier
step takes control of. The path depends on the build system acting for the
attacker, which is the same shape as the crown-jewel finding in
`docs/change_log/` for the earlier projection runs.

Two more properties are unique to it:

- **A live tactic reconciliation.** Step 4's `notes` record `T1078` labelled
  Initial Access after the first step and corrected to `Stealth`, which the
  v19.2 lookup also documents for that technique. Section 1.6 of the
  normalization plan asserts this behaviour; this is it happening in
  production, and the reconciliation has to survive normalization rather than
  be re-decided downstream.
- **Cloud Run provenance.** `tool_version` reads `git_sha: 1c2ba74,
  code_id_source: build_env`. It is the only fixture exercising the
  deployed-build identity path; `192507` exercises `git_worktree`.

## Shape

Fox Kitten (G0117) against Fleet Telemetry Platform, 2 paths, 9 nodes:

```
web-exploit-to-db  web_console:T1190 -> web_console:T1505.003 ->
                   web_console:T1552.001 -> telemetry_db:T1078 ->
                   telemetry_db:T1005
scm-to-vault       scm:T1078 -> ci_runner:T1059 -> ci_runner:T1046 ->
                   vault:T1210
```

Unequal path lengths (5 and 4) and the shortest graph of the four. Evidence is
9 of 9 `documented` / `procedure_documented` — the only fixture with no
`via_software` support anywhere, which makes it the control case for the
designer's rule that `actor_support: procedure_documented` and
`actor_evidence: false` can coexist. Transitions are 2 `entry`, 4 `in_place`,
3 `declared_flow`, no `undeclared`.

Across all four fixtures the transition counts are now 58 nodes: 10 `entry`,
23 `declared_flow`, 24 `in_place`, 1 `undeclared`. The single `undeclared`
remains `204815` / `helpdesk-oracle-onprem` step 3.

## Verified

Graph and seed share one `run_id` (`4f0b54a0`); `flow_map_sha256` is identical
to the other three runs against the same map; `actor_attack_id` is `G0117` and
`attack_version` 19.2. Both files are clean UTF-8 with no BOM and no
replacement characters, so the GCS round trip did not damage the em dashes in
the reconciliation note. Node counts, path shapes, evidence mix, state checks,
transition shapes and component binding were all read from the files rather
than taken from the run summary.

Nothing in the repository changed except the two documentation edits, so no
tests were run; the suite stands at 1523 from the code-identity change.
