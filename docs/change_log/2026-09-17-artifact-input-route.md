# Artifacts are the route, not file paths

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** code. `plugins/threat_modeling/attack_path_detection_designer/` —
`tool.py` input resolution, `schemas/input.schema.json`, 8 tests. Spec
`docs/specs/attack_path_detection_normalization.md` §2, §6 N4 row, decision 8,
§9.
**Status:** decided and built. Suite **1589 → 1597**. Confirmed end to end in
the running shell.

## The decision

Registered artifacts are the input and output route for the first working
version of detection generation. `normalize_paths` and, later,
`generate_detections` take `artifact_ids`; file paths stay supported as a local
convenience and are not the contract.

## What prompted it

N1 shipped taking `sources` — a list of file paths. Asked whether it could be
tested in the container, the honest answer was: only by hand-typing paths
inside the container, which is exactly what the artifact registry exists to
avoid. On Cloud Run a projector export is auto-exported to the common bucket
and only the registry knows where it landed. A tool that can only be reached by
path is a tool that cannot participate in a chain.

## What was built

`artifact_ids` (a list, because a pair is two documents) resolved against
`context.artifacts`, the same handle every other plugin uses and the only
artifact access an `ExecutionContext` carries.

Three details that are not obvious and each of which would have been a bug:

- **`artifact_id`, singular, is also accepted.** `do_run` resolves a singular
  `artifact_id` and injects `file_path` **and** `path` beside it
  (`shell.py:2925-2932`). A plugin that only understood `artifact_ids` would
  have failed with "no input" on a payload the shell believed it had filled in.
- **The injected path is not read twice.** With `artifact_id` present the
  injected `file_path`/`path` are ignored rather than appended, or a single
  document would arrive as a phantom pair of itself — which normalization would
  then refuse as two documents of the same role. There is a test for exactly
  this.
- **A registered artifact whose bytes are not readable here is its own
  condition.** `ARTIFACT_UNAVAILABLE`, naming the `storage_uri`. On Cloud Run
  that is a real state, and reporting it as a missing file would send whoever
  hit it looking for the wrong problem.

Not-found keeps the projector's own code and wording (`ARTIFACT_NOT_FOUND`,
"Use 'artifacts' to list loaded artifacts"), so the two tools in this chain
fail the same way.

## Verified in the running shell, not only in tests

```text
load …/path_graph_20260917_123525.json json_events     → art_e2697614
load …/scenario_seed_20260917_123525.json json_events  → art_2df55952
run attack_path_detection_designer --artifact_ids art_e2697614,art_2df55952

  ✓ Completed successfully
  Normalized 10 nodes across 2 paths.
  Pair: run_id (provenance verified, verified=True).
  Field conflicts: 0.
  Actor APT29 (G0016) against Application B, ATT&CK 19.2.
  1 node(s) carry a review flag.
  Output files: art_fa1b9b88 json_events …
```

The review flag is the `okta` → `entry_api` step, the corpus's only undeclared
transition. No shell change was needed: the flag parser coerces `a,b` into an
array straight from the plugin's input schema.

## A correction this run produced

Earlier the same day it was stated that a container run would leave no trace,
because the plugin registers no artifact. **That was wrong.** `do_run`
auto-persists any tool result that did not register one itself
(`shell.py:3105-3110`), which is where `art_fa1b9b88` above came from.

So persistence is not what N4 adds. What N4 adds is the pack's own schema and
`metadata.kind`. What is still missing for a container run to be *useful* is
adding this tool to `DEFAULT_AUTO_EXPORT_TOOLS` — currently only
`attack_path_visualizer` (`shell.py:932`) — so the output leaves the container.

## Verified

74 tests in the plugin, full suite **1597 passed**, up from 1589, nothing
broken. Manifest still validates. The shell transcript above is a real run.

Not run: `ruff`, `black`, `mypy` — not installed in this environment. New code
was kept under 88 characters per line by hand.

## Still open

Whether `artifact.file_path` points at readable bytes on Cloud Run. If it does
not, `ARTIFACT_UNAVAILABLE` says so precisely, but fetching from the bucket
would need the storage resolver, which plugins do not receive — that would be a
framework change, not a plugin one.
