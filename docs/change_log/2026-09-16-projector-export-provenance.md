# The projector's exports can now be joined to the run that produced them

**Date:** 2026-09-16
**Branch:** `llm_5`
**Scope:** `plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`
**Status:** built and unit-tested. Suite **1513 → 1519**. Not yet exercised on
a live projection run.
**Plan:** `docs/specs/attack_path_detection_normalization.md` §4.1, operator
decision 1.

`_write_projection_artifacts` wrote seven top-level keys — `source_tool`,
`status`, `interpretation`, `actor`, `application`, and then `mitre_mappings`
plus `attack_graph`, or `scenarios`. Nothing else. The run record written a few
lines later carried `run_id`, `flow_map_sha256`, `prompt_sha256`, the resolved
actor, the tool version and the provider attribution; the exports carried none
of it, and are written even when `--export` is off, so for those runs the
identity existed nowhere at all.

That mattered as soon as anything downstream tried to consume a pair. A graph
and a seed could only be paired by filename stamp, and a flow map could only be
matched to an export by application name. The test data shows why neither is
adequate: `20260915_165537` and `20260915_204815` have identical top-level
shape and describe different actors against different estates. A pairing rule
of "same stamp, same application" is a rule that works until the day two
projections run close together.

## What changed

Both export payloads gained a `provenance` block:

```json
"provenance": {
  "run_id": "...", "run_group": "...", "run_index": 1, "created_at": "...",
  "flow_map_path": "...", "flow_map_sha256": "...", "prompt_sha256": "...",
  "attack_version": "19.2", "actor_attack_id": "G0016",
  "tool_version": {"manifest_version": "...", "git_sha": "..."},
  "model": {"provider": ..., "vendor": ..., "model_configured": ...,
            "model_served": ...}
}
```

No value in it is newly computed — every one already existed in `run_context`
or on the response. The only real change is **where `run_id` is minted**. It
was created inside `_build_run_record`, which runs *after* the exports and only
when `export` is on. It is now minted in the projection loop and read by both,
so a graph, a seed and a run record from the same projection carry the same id
and a consumer can verify the pair instead of assuming it. `created_at` moved
with it for the same reason.

`model` is read off the response with `getattr`, matching the run record's
existing rule: with several providers bound at once, a derived vendor name is a
guess that reads as evidence. Null means no response, not "probably Gemini".

## Why additive is safe here

`attack_path_visualizer` reads named keys off the export — `mitre_mappings`,
`attack_graph`, and the per-step fields inside it — and ignores the rest, which
is why the extra per-step keys the projector already writes are harmless. The
export shape has no `additionalProperties: false` schema anywhere. A test
asserts every key the visualizer reads is still present.

The manifest version was deliberately **not** bumped. The repo's own note on
`_manifest_version` says it has read 0.2.0 since the projection action landed
while several behaviour changes shipped under it, and that the git SHA is the
field that can actually separate two runs of different code. Bumping it here
would weaken that convention for no gain — both fields are in the block.

## Verified

Six new contract tests in `TestExportProvenance`: both exports share one
`run_id`; that id and `created_at` match the run record's; `flow_map_sha256`
equals `_canonical_flow_map_hash` of the map actually passed; the ATT&CK
release, actor ATT&CK id, prompt hash, tool version and model block are
present; two separate projections do not share an id, so a graph from one run
cannot pair with a seed from another; and every key the visualizer reads
survives.

Full suite 1519 passed. `scripts/validate_schemas.py` clean at 34 schemas.

**Not done:** no live projection run, so the block has never been written with
a real provider attached — `model` has only been observed as the test double's
nulls. The two fixtures in `test_data/path_projector/` predate this change and
still have no `provenance`, which is why the designer-side legacy handling in
§4.2 of the plan is still required rather than optional. `normalize_flow_map`,
the rest of the projector's Phase 4, is untouched.
