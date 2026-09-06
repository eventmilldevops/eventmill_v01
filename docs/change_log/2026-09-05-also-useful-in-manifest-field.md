# Change Log — `also_useful_in`: offering a tool in a pillar it does not belong to

**Date:** 2026-09-05
**Primary Files Modified:** `docs/specs/manifest_schema.json`,
`framework/plugins/loader.py`, `framework/cli/shell.py`,
`plugins/log_analysis/threat_intel_ingester/manifest.json`
**Supporting Files:** `tests/framework/test_cli_tools.py`,
`tests/framework/test_plugins.py`, `docs/specs/tool_plugin_spec.md`,
`docs/guides/plugin_development.md`

---

## Problem

`threat_intel_ingester` lives in `log_analysis` but is frequently the
first action in threat-modeling work. Nothing in the manifest could say
so: `pillar` is a single-valued enum that `PluginLoader._load_plugin`
requires to equal the plugin's directory, the schema is
`additionalProperties: false`, and the routing adjacency map is
pillar-level rather than per tool.

The pillar-scoped `tools` listing landed earlier the same day surfaces
cross-pillar tools by intersecting loaded artifact types with
`artifacts_consumed`. That answers "what next" and cannot answer this
case: an entry-point tool runs before any artifact exists.

## Changes

### `docs/specs/manifest_schema.json`

New optional `also_useful_in`: an array over the same pillar enum, unique
items, documented as advisory and as MUST NOT containing the tool's own
pillar. `validate_manifests.py` still reports exactly the 15 pre-existing
`stability` errors and nothing new; `threat_intel_ingester`, the one
manifest that passes, passes with the field present.

### `framework/plugins/loader.py`

- `PluginManifest.also_useful_in` filters out the tool's own pillar, so a
  manifest that lists it is harmless rather than producing a duplicate
  row.
- New `get_for_pillar(pillar)` returns the pillar's own plugins followed
  by those that declare it, sorted by `(pillar, tool_name)`. `_by_pillar`
  and `get_by_pillar` are untouched — they mirror the directory layout
  and the router and executor read them, so nothing existing changes
  meaning.

### `framework/cli/shell.py`

`tools` uses `get_for_pillar`, for both the active pillar and a named
one. The Pillar column, dropped for single-pillar listings, comes back
when a borrowed tool makes it vary, and a footnote says why the row is
there. The hidden-tools footer counts what is actually offered, so a
borrowed tool is no longer double-counted as hidden.

### `plugins/log_analysis/threat_intel_ingester/manifest.json`

`"also_useful_in": ["threat_modeling"]`. It now appears in a
`threat_modeling` listing on an empty session, labelled `log_analysis`,
and still appears under `tools log_analysis` unchanged.

## Not done

The router is untouched. Phase 2 expands candidates by adjacency and
phase 3 scores own-pillar 1.0 / adjacent 0.5; giving `also_useful_in` a
tier between them is a reasonable follow-up, but it changes what the LLM
may see at any point, which is the bound the routing layer exists to
keep. A CLI listing is contained; candidate expansion is not.

Unrelated but adjacent: `threat_intel_ingester` declares
`chains_to: ["context_enriched_analyzer"]`, a plugin specified in
`framework_architecture.md`, `tool_plugin_spec.md` and
`router_design.md` but never built. The edge points at nothing and is
left as found.

## Tests

- `tests/framework/test_plugins.py` — `also_useful_in` defaults to empty,
  drops the tool's own pillar, and `get_for_pillar` both includes
  borrowed tools (without moving them) and matches `get_by_pillar` for a
  pillar nobody declares.
- `tests/framework/test_cli_tools.py` — the borrowed tool is listed,
  shows its real pillar, carries the footnote, is not counted as hidden,
  and still lists under its own pillar without the footnote.

614 tests pass.
