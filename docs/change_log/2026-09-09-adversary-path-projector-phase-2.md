# Change Log — `adversary_path_projector` Phase 2: projection

**Date:** 2026-09-09
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/manifest.json`,
`plugins/threat_modeling/adversary_path_projector/schemas/input.schema.json`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`
**Supporting Files:** `framework/cli/shell.py`, `.env.example`, `.gitignore`,
`docs/specs/adversary_path_projector.md`

---

## Problem

Phase 1 built the two halves that constrain projection — the closed technique
set and the flow map's reachable routes — but nothing joined them. Nothing in
the repo emitted an `attack_graph`, so `attack_path_visualizer` had nothing to
render from an actor and an architecture.

## Changes

### `project_paths` (new action)

Three phases, only the middle one using a model:

**Phase A (deterministic).** Reuses Phase 1 wholesale: `_load_actor_profile`
builds the closed set, `_normalize_flow_map` + `_entry_surface` +
`_crown_jewel_routes` build the topology. A flow map with blocking errors
returns before any LLM call is made — a broken topology must not cost a
heavy-tier request.

**Phase B (heavy tier).** One `query_text` with
`QueryHints(tier="heavy", needs_reasoning=True, needs_structured_output=True)`.
The prompt carries the closed set grouped by tactic with provenance inline, the
component table with exposure/technology/authentication/controls, the reachable
routes, and the declared flows. Five hard rules state that technique ids and
component ids must be copied from those lists, that consecutive steps must
follow a declared flow, and that a path must start on an externally exposed
component. The v19 tactic list is given explicitly, with "Defense Evasion"
named only to forbid it.

**Phase C (deterministic).** `_validate_projection` splits failures by kind:

- *Rejections* discard the step — a technique outside the closed set is exactly
  what the set exists to prevent, and a component outside the map cannot be
  reasoned about. If nothing survives, the action fails with
  `PROJECTION_REJECTED` rather than returning an empty success.
- *Warnings* annotate the step and keep it — a retired tactic is mapped to the
  successor the technique actually carries, a tactic the technique does not
  carry is flagged, an undeclared hop is flagged, a non-exposed entry is
  flagged. The placement may be sound even when the label is not.

`evidence` is **derived, never read from the reply**: `documented` if the
technique is in the core set, `via_software` if it came from the tooling block.
A model cannot be trusted to label the strength of its own source, and a test
asserts that an `evidence` key in the reply is ignored.

A truncated reply is refused outright. Unlike IOC extraction, a cut-off
projection is an attack path with steps missing, and closing brackets to make
it parse would hand back a graph that looks complete and is not.

### Outputs

Two artifacts. The graph file carries exactly the keys
`attack_path_visualizer._load_stages_from_artifact` reads, so it chains with no
translation; the extra per-step keys (`component_id`, `asset`, `evidence`,
`rationale`, `mitigations`, `uncovered_mitigations`, `notes`) are ignored by
the renderer. The scenario seed carries `SecurityControl` and `AttackEvent`
structures matching `threat_model_analyzer`'s dataclasses field for field, one
scenario per path — `sequence_order` is a linear integer and a projection is a
graph, so flattening every path into one scenario would misrepresent it.

Mitigation gaps are computed per step: `mitigations_for_technique()` diffed
against the `mitre_mitigation_id` values the component's controls declare.

### `framework/cli/shell.py`

`main()` now loads `.env` via `python-dotenv`, which was already a base
dependency but was never imported, so the file the repo shipped a template for
was never read. Guarded by the existing `K_SERVICE` check so it never runs on
Cloud Run, and `override=False` so an already-set variable always wins.
`.gitignore` gained `.env.*` with `!.env.example`.

### Manifest

`model_tier` heavy, `requires_llm` true, `timeout_class` long, `cost_hint`
moderate, `safe_for_auto_invoke` false, version 0.2.0. A live run took ~95s, so
`long` (600s) is the right class and `fast` would have failed.

## Verified against the live API

`Scattered Spider` against the example claims portal, `max_paths 2`, Gemini 3.1
Pro. Two paths, nine steps, all nine `documented`, zero rejections:

```
[s3-session-exfil]    portal:T1078 -> portal:T1539 -> claims_api:T1580
                      -> doc_store:T1530 -> doc_store:T1567.002
[db-mtls-ransomware]  portal:T1078 -> claims_api:T1059.004
                      -> claims_api:T1552.004 -> claims_db:T1486
```

The rationales read the architecture rather than restating the technique —
"bypass the partial WAF" (reads `implementation_status`), "the API's
unauthenticated flow to the internal file store" (reads flow `f5`), "to
circumvent the implemented database firewall and satisfy the Postgres MTLS
authentication requirement, the attacker searches the API server to steal
private keys" (reads both the control and the component's `authentication`).

The resulting artifact rendered in `attack_path_visualizer` unchanged, with
T1078 correctly resolved as the branch point shared by both paths.

## Tests

123 contract tests for the plugin (44 new), against a scripted LLM stub in the
style of `threat_intel_ingester`'s `_NativeLLM`. Coverage includes every Phase C
rejection and warning path, evidence derivation ignoring the model's own claim,
truncation refusal, fenced JSON, unparseable JSON, LLM failure, no-LLM, and an
end-to-end assertion that the emitted graph renders in
`attack_path_visualizer`. Two Phase 1 tests were updated: the manifest test now
asserts the heavy-tier reality, and the planned-action test moved to
`normalize_flow_map`.

Full suite: 767 passed. `validate_manifests.py` still reports exactly the 15
pre-existing `stability` errors.

## Not in this phase

- `export_scenario` / `import_scenario` on `threat_model_analyzer`, and
  narrowing its `analyze_document` description — Phase 3. Until then the
  scenario seed is emitted but nothing consumes it.
- `normalize_flow_map` and the README — Phase 4.
- Teaching `attack_path_visualizer` to render `component_id` and
  `uncovered_mitigations`, which its `DAGNode` already has empty fields for.
  Still deferred; the diagram is technique-level until then.
