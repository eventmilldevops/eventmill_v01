# Change Log — `expansion_mode` is reachable from configuration

**Date:** 2026-09-07
**Primary Files Modified:** `framework/routing/router.py`,
`framework/routing/config/adjacency.json`
**Supporting Files:** `tests/framework/test_routing.py`,
`docs/specs/router_design.md`

---

## Problem

`RouterConfig.expansion_mode` defaulted to `"strict"` and
`load_from_directory` never read it from anywhere, so no configuration
could change it. Adjacency expansion (`router.py:209`) and the
`pillar_match = 0.5` adjacent tier were unreachable in the running
product: the shell builds its router through `load_from_directory`
(`shell.py:342`), and `adjacency.json` was loaded only for its map.

The spec describes `strict` and `adjacent` as shipping modes, and
`adjacency.json` carries a hand-written note explaining the map's
design. Both described a feature that could not be switched on.

## Changes

### `framework/routing/router.py`

- `load_from_directory` reads `expansion_mode` from `adjacency.json`,
  the file holding the map it governs.
- Absent key keeps `"strict"`, so an existing deployment behaves exactly
  as before.
- A value outside `EXPANSION_MODES` (a new module constant:
  `"strict"`, `"adjacent"`) logs a warning naming the file and the valid
  modes, then falls back to `"strict"`. The spec's future `"broad"` mode
  is not implemented, so it is treated as unknown rather than silently
  widening the candidate set.

### `framework/routing/config/adjacency.json`

Declares `"expansion_mode": "strict"` explicitly — the shipped default is
unchanged, but the knob is now visible in the file rather than buried in
a dataclass default. The note explains what the two modes do and that a
plugin's `also_useful_in` applies in either.

## Behaviour

Nothing changes until someone edits the file. With
`"expansion_mode": "adjacent"`, a `threat_modeling` session starts
scoring the `network_forensics` and `log_analysis` tools its adjacency
row names, at `pillar_match = 0.5`. `also_useful_in` keeps its 0.75 in
both modes, so a declared tool still outranks one that is merely
adjacent, and the phase 2 dedupe added with that change keeps a tool that
is both from being scored twice.

## Not done

`max_candidate_tools` and the scoring `weights` are still dataclass
defaults with no config path. They are genuinely tunable knobs and the
same argument applies, but changing them changes ranking for every query,
which is a separate decision from making a documented mode reachable.

## Tests

`tests/framework/test_routing.py::TestExpansionMode` — six tests: the
mode is read from config, defaults to strict when absent, falls back to
strict on an unknown value, the shipped config declares a valid mode,
adjacent mode actually reaches adjacent-pillar tools where strict does
not, and a declared tool keeps 0.75 and one candidate slot under adjacent
mode.

626 tests pass.
