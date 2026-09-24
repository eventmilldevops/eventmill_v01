# N2 closed: a flow map's hash is lineage, not a gate

**Date:** 2026-09-19
**Branch:** `llm_5`
**Scope:** code and spec. `plugins/threat_modeling/attack_path_detection_designer/`
— `normalization.py` (code catalogue, flow-map lineage), `tool.py` (flow-map
input, `ERROR_CODES`, summary), both schemas, three flow-map fixtures, 38
tests, README, manifest description. Spec
`docs/specs/attack_path_detection_normalization.md` — header, §4.2, §4.3 rule 4,
new §4.4, §5, §6 N2 row, §7, decision 1 note, new decision 9, §9.
**Status:** decided and built. Suite **1597 → 1635**. No shell run and no LLM
call.

## The decision (spec decision 9)

A flow map is not a forensic copy. An analyst with inside information is
expected to copy a generated map and correct it; git is the recommended way to
track those edits; a tampered map passed around is not a meaningful risk here.

The spec as written on 2026-09-16 treated the map as evidence: a
`flow_map_sha256` mismatch refused enrichment with a blocking warning, a missing
hash required an operator assertion, and §5 made a hash match one of the
conditions for `component_bound`. Every one of those would have penalised the
workflow the operator described — correcting a map after projection — while
protecting against a threat nobody has.

So the hash now answers only *is this the map the projection ran against?*

| Export hash vs supplied map | `lineage` | Effect |
|---|---|---|
| equal | `same_map` | none |
| different | `edited_map` | advisory `FLOW_MAP_EDITED`, map used as given |
| absent | `unhashed` | advisory `FLOW_MAP_UNHASHED`, no operator flag |

## Why the hash had to be replaced, not just relaxed

The hash cannot tell an analyst's descendant of the projected map from an
unrelated map — both read `edited_map`. What the hash had really been standing
in for is *does this map fit this projection*, and that can be asked directly:

- **Application** — the map's `application` against the export's.
  `FLOW_MAP_APPLICATION_MISMATCH` (advisory) is the likeliest sign of the
  wrong map rather than an edit.
- **Component fit** — every distinct node `component_id` looked up in the
  map. `FLOW_MAP_COMPONENT_UNRESOLVED` is raised once per missing component,
  naming how many nodes it affects, and is **blocking** in the §4.4 sense:
  those nodes will receive no flow-map enrichment in N3 and stay
  `asset_named`. The rest of the map is still used.

A test demonstrates the difference: the Claims Portal map supplied against the
telemetry export reads `edited_map` on hash, but the application mismatch and
all seven of the nodes' components unresolved say what actually happened:

```text
Flow map: edited_map (claims_portal_flow_map.json), 0 of 7 node components resolve, application 'Claims Portal' differs.
Warnings (blocking): FLOW_MAP_COMPONENT_UNRESOLVED x7
Warnings (advisory): FLOW_MAP_APPLICATION_MISMATCH x1, FLOW_MAP_EDITED x1
```

Substantive contradictions between an edited map and the projection were
already covered by §4.3 rule 4 — the map fills only fields no export carries,
and a disagreement is a conflict record with the export value kept.

**Not changed:** the pair rows of §4.2. The `run_id` join prevents two runs
being merged into one context, which is wrong under any trust model.

## What was built

**Flow-map input.** `flow_map_artifact_id` (the contract, per decision 8) or
`flow_map_path` (local convenience); supplying both is a validation error. JSON
only — a prose, Markdown or Mermaid map fails `FLOW_MAP_UNREADABLE` with a
pointer to N5, and a JSON document with no `components` list (an export passed
by mistake, say) fails `FLOW_MAP_NOT_OBJECT`. Those are the only two ways a map
is refused, and neither concerns lineage.

**The hash, reproduced.** Plugins cannot import one another, so
`flow_map_hash` is a second implementation of the projector's
`_canonical_flow_map_hash`. It reuses the plugin's existing `canonical_json`,
whose serialisation already matched (sorted keys, compact separators,
`ensure_ascii=False`; the projector's extra `default=str` never fires on
JSON-parsed data). Drift is caught by evidence, not by reading both functions:
a parametrized test recomputes the hash of each repository map and compares it
with the `flow_map_sha256` all eight fixture documents recorded. The three maps
are copied into `tests/fixtures/flow_maps/` so that an edit to the projector's
examples cannot silently break this plugin's tests.

**The result.** A `flow_map` record on every result — `supplied`,
`export_sha256` and `export_flow_map_path` always, so a run with no map still
says which map *would* bind; plus `filename`, `sha256`, `lineage`,
`application`, `application_matches`, `components_resolved` and
`components_unresolved` when one was supplied. `flow_map_lineage` at the top
level for the result summary.

**The code catalogue (§4.4).** The warning codes were free strings scattered
through the module. They are now closed sets: `WARNING_CODES` (code →
severity) and `REVIEW_FLAG_CODES` in `normalization.py`, `ERROR_CODES` in
`tool.py`. Every warning is built through `_warning()`, which looks the
severity up and raises `KeyError` on an undeclared code; review flags go
through `_review_flag()` the same way. Each warning now carries `severity`.
Tests hold the spec table and the code to each other in both directions, and
check that every `error_code=` in `tool.py` is declared.

Severity has one meaning: **blocking** if the output omits or downgrades
something because of the condition, **advisory** if the output is complete but
needs a second look. On that definition `PAIR_REFUSED`,
`PAIR_CONTENT_CONFLICT`, `NODE_ONLY_IN_SECONDARY` and
`FLOW_MAP_COMPONENT_UNRESOLVED` are blocking; the rest advisory.

**The summary** gains a flow-map line directly under the pair line — lineage,
filename, "N of M node components resolve", and the application when it
differs — and splits warnings into a blocking line and an advisory line, so the
condition that removed something is read before the one that merely flags it.

## What N2 did not need

The designer-side pair handling of §4.2 — refuse different runs, refuse a mixed
pair, join legacy documents only on `accept_unverified_pair` — shipped with
N1's `decide_pair` and its synthetic no-provenance test. N2 added nothing
there. Spec §6 and decision 1 now say so.

## Deliberately left out

- **The map's git revision.** Recording the commit or blob id of a map in a
  working tree would say *which* edit a draft rests on, not only that it was
  edited. Raised with the operator and not built; decision 9 records when to
  reopen it.
- **Enrichment.** Nothing is copied from the map onto a node. That, the
  `flow_map_lineage` stamp on each enriched field's `provenance_by_field`
  entry, and the completeness grades are N3.

## Verified, and not

- 112 plugin tests (74 → 112), full suite 1635 passing.
- **Not run in the shell.** The flow-map artifact route is exercised with a
  fake context only. The export artifact route it copies was confirmed in a
  real shell run on 2026-09-17, and the map uses the same `_resolve_artifact`.
  The shell accepts `--flow_map_artifact_id` / `--flow_map_path` because it
  reads a tool's flags from its input schema's `properties`
  (`framework/cli/shell.py`, `_plugin_input_schema`), where both are declared.
- `ruff`, `black` and `mypy` are not installed in this environment and have
  not run.
