# 2026-10-27 — Name the projector document that was passed in the wrong slot

## Why

Two failures in one operator session had the same cause. A real projector
output was passed where a different projector document belonged, and the error
described only what was missing:

- `attack_path_detection_designer` was given two **projection run records**
  (`adversary_projection_run_*.json`) instead of the path graph and scenario
  seed. It said `INPUT_UNRECOGNIZED — expected attack_graph, scenarios or
  attack_sequence`.
- `adversary_path_projector project_paths` was given the **validate_flow_map
  result** that the shell saves after `validate_flow_map` as
  `--flow_map_artifact_id`. It said `NO_COMPONENTS — Flow map declares no
  components`, which reads as a broken map.

The validate result, the run record, the path graph and the scenario seed are
all `json_events` artifacts from `adversary_path_projector`, so the `artifacts`
listing gives no cue which is which.

## What changed

Documents are recognised by **shape**, using keys each producer is required to
write. Anything not recognised keeps its previous message. **No error code
changed.**

| Document | Recognised by |
|---|---|
| Projection run record | `run`, `outcome` and `deterministic` (required by `projection_run.schema.json`) |
| validate_flow_map result | `action == "validate_flow_map"` and no `components` |
| Path graph / scenario seed | `attack_graph` object / `scenarios` list |

**`attack_path_detection_designer/tool.py`**
- A run record in `artifact_ids` gets `INPUT_UNRECOGNIZED` with a message naming
  it, and the most recent path graph and scenario seed registered in the session
  (by the `kind` metadata the projector registers them under). If neither is
  registered, it says so. It also notes that a multi-run loop writes the graph and
  seed for the first successful run only. `details` gains `recognized_as` and
  `suggested_artifact_ids`.
- A validate result in the flow-map slot gets `FLOW_MAP_NOT_OBJECT` with a message
  naming it.
- `normalization.py` is unchanged; the helpers are local to `tool.py`, so the
  normalization library stays plugin-local.

**`adversary_path_projector/tool.py`**
- `_load_flow_map_source` checks an artifact or file before linting it. A validate
  result, run record, path graph or scenario seed gets `INPUT_VALIDATION_FAILED`
  naming it, with the fix: load the map file and pass that id, or use
  `--file_path`. This covers `validate_flow_map` and `project_paths`.
- **`summarize_run_group` degrades instead of failing.** Its map is optional, and a
  map with blocking errors already only adds a warning there. A misplaced
  document now does the same: the summary is written without control context and
  `report_warnings` names the document. This is a small departure from the plan,
  which had the summary fail too.
- Inline `flow_map` payloads are not checked.

## Tests

- Designer `test_contract.py`: run record names itself and lists the graph and
  seed ids; no exports registered says so; the newest export of each kind is
  suggested; an unrelated document keeps the original message; a validate result
  as the flow map names itself.
- Projector `test_contract.py`: a validate result as `flow_map_artifact_id` and a
  run record as `file_path` both name themselves; the shipped
  `plant_ot_flow_map.json` still validates; `summarize_run_group` with a validate
  result as its map still writes the report with a warning.

## Verification

- Both plugins: 574 passed.
- Full suite `pytest -q tests/ plugins/`: 2185 passed, 4 skipped.
- `ruff check` on the four touched files: the same counts as `HEAD`, so no new
  findings.
- Not run in the live shell; the session that produced the original errors is in
  the container.
