# Change Log — Full rendering after `run`, and the `show` command

**Date:** 2026-09-03
**Primary Files Modified:** `framework/cli/shell.py`,
`plugins/threat_modeling/attack_path_visualizer/tool.py`
**Supporting Files:** `plugins/threat_modeling/attack_path_visualizer/README.md`,
`tests/framework/test_cli_show.py` (new)

---

## Problem

After an expensive ingest-and-graph run, `run attack_path_visualizer`
appeared to truncate its output. The shell printed only
`summarize_for_llm()`, which the plugin spec caps at 2000 characters because
it feeds the LLM context, and the visualizer's summary embedded the first 20
lines of the drawing followed by "... (truncated)". The full rendering was
being written to files, but for inline-`stages` runs the user was never told
where, and the shell had no command to print an artifact. `--format both`
made it worse because ASCII and Mermaid share the same cap.

## Changes

### `framework/cli/shell.py`

- After the summary, `run` now calls `_print_run_output`, which prints any
  `visualization` string in the result **in full** under "Rendered output:",
  then lists every artifact the run registered (ID, type, path) under
  "Output files", so the user always knows where the complete result is.
  This applies to any tool that returns a `visualization` field.
- New `show <artifact_id> [max_lines]` command prints an artifact's file:
  text, markdown and Mermaid as-is, JSON pretty-printed, binary artifacts
  refused. With a limit it says how many lines remain and how to see them.

### `attack_path_visualizer`

- `summarize_for_llm()` no longer embeds a chopped drawing. It reports
  counts, convergence points, missing required stages by name, where the
  full rendering was saved, nodes whose tactic is unconfirmed, and either
  one line per attack path (id, step count, description) or the linear
  stage flow. Still within the 2000-character cap.
- The result dict gains `paths` (DAG runs), `stage_names` /
  `missing_stage_names` (linear runs) and `unconfirmed_tactics` to support
  that summary without re-parsing the drawing.

### Tests

`tests/framework/test_cli_show.py` drives the real shell: a 14-stage
`--format ascii` run must print the last stage box with no "(truncated)"
marker and list output files; `--format both` must print both the ASCII and
the Mermaid block; `show` prints whole files, honours a line limit, pretty-
prints JSON, and refuses binaries.
