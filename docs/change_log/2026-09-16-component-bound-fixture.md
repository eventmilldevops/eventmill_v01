# A component-bound fixture, and the first live run of export provenance

**Date:** 2026-09-16
**Branch:** `llm_5`
**Scope:** no repository files changed. One live projection run; two export
files added to `C:/projects/eventmill_v02/test_data/path_projector/`.
**Status:** run complete, provenance live-confirmed.
**Plan:** `docs/specs/attack_path_detection_normalization.md` §5 and operator
decision 3; follows `2026-09-16-projector-export-provenance.md`.

## Why a run rather than a hand-built file

Every export pair in the test data was `asset_named` — a component ID and an
asset name, and nothing that could name a product. The normalization plan's
grades only matter if something exercises the other end of them, and a
generation prompt designed against `asset_named` fixtures alone will settle at
"describe the collection you would need" and never design the path where
`logsource.product` is actually set.

Hand-assembling one would have produced an `asserted_by_operator` binding — the
§4.2 legacy path — and exercised the wrong half of the plan. Once the exports
carried `flow_map_sha256`, a real run was both cheaper and strictly better: it
yields a verifiable binding and it is the first live test of the provenance
block written earlier the same day.

## The run

`adversary_path_projector --action project_paths --threat_actor APT29
--file_path .../examples/telemetry_saas_flow_map.json --export`, default
`thinking_level: medium`, `max_paths: 3`, through the shell so the wiring is
the real one. Gemini 3.1 Pro on `gcp_gemini`, heavy tier per the manifest.
Completed in roughly 60 seconds, well inside the envelope
`docs/change_log/2026-09-12-light-tier-gemini-3-8-flash.md` and the latency
notes would predict for `medium`.

The model returned **two** paths, not the three it was allowed:
`supply-chain-vault` (scm → scm → ci_runner → vault → vault) and
`web-console-telemetry` (web_console ×3 → telemetry_db ×2). Ten nodes.

## What it confirms

The provenance block written this morning works on a real call:

```
run_id            aed1f374-4bac-43b7-b280-14ebb305e6d5   (graph == seed == run record)
created_at        2026-09-17T01:25:07.449586+00:00       (== run record)
flow_map_sha256   5de20d4b…5eaf9                         (== recomputed from the file)
attack_version    19.2        actor_attack_id  G0016
tool_version      0.2.0 / 0ff0849
model             gcp_gemini / google / gemini-3.1-pro-preview (configured == served)
```

`model` had only ever been observed as the test double's nulls; it now carries
real attribution. The graph, the seed and the run record share one `run_id`,
which is what the designer's pair join needs and could not previously have.

All ten nodes bind to a flow-map component carrying `technologies`,
`authentication` and `zone` — `scm` (git, github-actions, `sso_mfa`),
`ci_runner` (ubuntu, docker, github-actions-runner, `oidc_federation`),
`vault` (hashicorp-vault, `mtls`), `web_console` (nodejs, react, `oidc`),
`telemetry_db` (postgres, timescaledb, `mtls`). That is the `component_bound`
grade, and it is the first fixture to reach it.

## What it does not cover

Every step came back `state_check: ok`, so this fixture cannot exercise the
inherited-access-gap route to `multistep_access: true` — `20260915_165537`,
with its two recorded gaps, stays the fixture for that. Evidence is 9
`documented` to 1 `via_software`.

One step carries a note worth keeping: `supply-chain-vault` step 2 is
`T1195.002`, an Initial Access technique, appearing after access was already
gained upstream, and the projector's own kill-chain check flagged it. That is a
ready-made `needs_mapping_review` case for the designer rather than a defect in
the run.

## A correction worth recording

The first hash comparison appeared to fail. The cause was the check, not the
tool: `json.load(open(path))` on Windows decodes as cp1252, and the flow map's
description contains a UTF-8 em dash, so the recomputed hash covered mojibake.
Read with `encoding="utf-8"` — as `_load_flow_map_source` does — it matches
exactly. Worth knowing before anyone verifies one of these hashes by hand on
this platform.

## Verified

Pair `run_id` equality, `created_at` and `flow_map_sha256` equality against the
run record, `flow_map_sha256` recomputed from the source file with
`_canonical_flow_map_hash`, component binding for all ten nodes, and the node
and path counts. No repository code or test changed, so no suite was re-run
beyond the 1519 already green from the provenance change.
