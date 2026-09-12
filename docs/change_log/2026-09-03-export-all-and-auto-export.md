# Change Log — `export --all` and auto-export on Cloud Run

**Date:** 2026-09-03
**Primary File Modified:** `framework/cli/shell.py`
**Supporting Files:** `plugins/threat_modeling/attack_path_visualizer/README.md`,
`cloud_install/README.md`, `tests/framework/test_cli_export.py` (new)

---

## Problem

On Cloud Run `workspace/artifacts` lives on the container filesystem and is
lost when the instance is recycled. `export` moved one artifact at a time
and nothing exported automatically, so an expensive ingest-and-graph run
that the user forgot to export was simply gone.

## Changes

- `export --all [subfolder]` exports every tool-produced artifact in the
  session (artifacts with a `source_tool`); loaded inputs are skipped since
  they came from a bucket. Prints a per-artifact result and a final count.
- `do_export` is refactored around `_export_artifact(artifact, subfolder)`,
  which both the single and `--all` forms and the auto-export use.
- Auto-export after `run`: when the shell is on Cloud Run (`K_SERVICE`) or
  `EVENTMILL_AUTO_EXPORT=1`, the artifacts a run just produced are exported
  for tools listed in `EVENTMILL_AUTO_EXPORT_TOOLS` (default
  `attack_path_visualizer`; `*` = all, empty = off). Failures are printed
  but never fail the run; the files remain on disk for a manual `export`.
- Docs: visualizer README ("Keeping the files on Cloud Run") and the
  cloud_install README configuration reference.

## Tests

`tests/framework/test_cli_export.py` uses the local storage resolver:
`export --all` uploads only tool-produced artifacts into
`<prefix>-common/exports/<tool>/[subfolder]/`, single export still works,
auto-export fires for the visualizer under `EVENTMILL_AUTO_EXPORT=1`, is
silent for tools not listed, honours `*`, and is off by default locally.
