# Change Log — `history` split into `tool_history` and `llm_history`

**Date:** 2026-09-05
**Primary Files Modified:** `framework/cli/shell.py`
**Supporting Files:** `tests/framework/test_cli_history.py` (new),
`docs/specs/framework_architecture.md`,
`docs/guides/linux_auth_log_analysis.md`

---

## Problem

`do_history` was defined twice in `EventMillShell`. The first definition
listed tool executions from session state; the second listed LLM
conversation turns. Python keeps the last binding, so the tool-execution
listing was unreachable and `history` only ever showed LLM turns — the
behaviour the `2026-08-23` change log recorded under "Not addressed",
where the open question was which of the two `history` should mean.

The answer is both, under names that say which is which. A single
`history` could not carry the detail either stream deserves: tool
executions have durations, artifact lineage and stored summaries that the
old four-column table dropped, and LLM turns have timestamps that were
never recorded at all.

## Changes

### `framework/cli/shell.py`

- The first definition becomes **`tool_history`**, and gains the flag
  grammar the `files` command already uses (`shlex.split` +
  `_split_flags`): `--tool`, `--status`, `--limit`, `--detail`. A bare
  execution id — `tool_history exec_a1b2c3d4` — prints that one execution
  in full. Rows gained a Duration column; `--detail` and the single-id
  form print `started_at`/`completed_at`, the input → output artifact
  pair, and the stored `summary`. Those fields were already on
  `ToolExecution`; nothing new is persisted.
- The second becomes **`llm_history`**, with `--last <n>` and `--full`
  (untruncated answers) alongside the existing `clear`. Previews now
  collapse newlines so a multi-line answer stays one row.
- **`history`** is now a merged timeline over both streams, oldest first,
  one row per event, ending in a count and a pointer to the two detail
  commands. `history clear` says only LLM turns can be cleared and
  forwards to `llm_history clear`; tool history is session state and is
  not deletable from the shell.
- `_query_llm` now stamps each recorded turn with a `timestamp`, which is
  what lets the two streams interleave. Turns recorded without one sort
  last and render their time as `-`.
- `do_new` and `do_load_session` clear `_conversation_history`. It is
  in-memory and was not scoped to a session, so turns from a previous
  investigation used to persist across a session switch — visible in the
  old listing, and incoherent in a timeline whose other half is
  session-scoped.

New helpers: `_print_execution_detail`, `_execution_duration`,
`_turn_time`. New module constant `HISTORY_DEFAULT_LIMIT = 40` caps the
merged timeline.

## Not done

LLM turns are still in-memory only, not persisted to SQLite next to
`tool_executions`. Both tool calls and LLM calls already reach the
platform through the structured log (`log_user_activity`,
`log_llm_interaction`), which is the durable audit trail; a second
in-database record would duplicate it. `llm_history` is deliberately a
this-shell-session view, and the command docstring and guide say so.

## Tests

`tests/framework/test_cli_history.py` — 33 tests over the three commands:
filters, limits, detail, error paths, timeline ordering, `clear`
routing, and session scoping. One test parses `shell.py` with `ast` and
asserts no `do_*` name is defined twice in `EventMillShell`, so a
re-shadowed command fails the suite rather than silently disappearing.
