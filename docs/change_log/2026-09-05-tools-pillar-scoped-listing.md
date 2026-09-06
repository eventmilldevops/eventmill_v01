# Change Log — `tools` is scoped to the active pillar

**Date:** 2026-09-05
**Primary Files Modified:** `framework/cli/shell.py`
**Supporting Files:** `tests/framework/test_cli_tools.py` (new),
`docs/specs/framework_architecture.md`,
`docs/guides/linux_auth_log_analysis.md`

---

## Problem

`do_tools` called `plugin_loader.list_all()` whenever no pillar argument
was given, so a bare `tools` printed all 16 plugins regardless of the
active pillar. In `threat_modeling` that is four relevant rows buried
under twelve PCAP and log-analysis rows. `framework_architecture.md`
already described the command as "List available tools for the current
pillar", so the implementation had drifted from the spec rather than the
spec being unwritten.

This is not a context problem — the shell is not an MCP server and the
list never enters a prompt — it is a reading problem for the analyst.

## Changes

### `framework/cli/shell.py`

- A bare `tools` with an active pillar now lists that pillar's tools,
  without the redundant Pillar column, under a `<pillar> tools` heading.
- Below it, a **Related** section lists tools from other pillars whose
  manifest `artifacts_consumed` intersects the artifact types loaded in
  the session. Loading a PCAP into a `threat_modeling` session surfaces
  the six `pcap_*` tools; with nothing loaded, the section is absent.
- A footer names how many tools are hidden and which pillars still hold
  them, with the two ways to see them.
- `tools --all` restores the full listing; `tools <pillar>` is unchanged
  except that an unknown pillar now lists the loaded ones instead of
  saying "No tools available." With no active pillar, the listing stays
  complete and suggests `pillar <name>`.

New helpers: `_related_tools`, `_print_tool_rows` (the pillar column is
printed only for listings that can span pillars).

## Why artifacts, not adjacency

`framework/routing/config/adjacency.json` looks like the natural source
for "which other pillars make sense", but it does not narrow anything
here: `threat_modeling` is adjacent to `risk_assessment`,
`log_analysis` and `network_forensics`, which is every pillar that has
plugins loaded. Adjacency exists to widen the router's candidate set,
not to rank a menu. What actually makes another pillar's tool useful
right now is whether it can consume something the analyst has in the
session, which is exactly what `artifacts_consumed` declares — and the
router already scores the same signal in phase 3.

The listing stays deterministic and makes no LLM call.

## Tests

`tests/framework/test_cli_tools.py` — 16 tests: pillar scoping, `--all`,
a named pillar, no active pillar, the related-section behaviour with and
without a loaded PCAP, no double-counting between the two sections, and
the argument grammar.
