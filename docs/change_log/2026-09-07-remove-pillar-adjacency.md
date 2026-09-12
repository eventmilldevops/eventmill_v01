# Change Log — pillar adjacency removed; strict is the routing model

**Date:** 2026-09-07
**Primary Files Modified:** `framework/routing/router.py`,
`framework/routing/config/adjacency.json` (deleted)
**Supporting Files:** `tests/framework/test_routing.py`, `tests/conftest.py`,
`docs/specs/router_design.md`, `docs/specs/eventmill_v1_1.md`,
`docs/specs/framework_architecture.md`, `framework/cli/shell.py`

---

## Decision

Pillar-level adjacency is gone. One pillar at a time is the routing model,
and a tool reaches another pillar only by naming it in its manifest's
`also_useful_in`.

Adjacency was specified as three expansion modes over a curated map, and
made reachable from configuration earlier the same day. Turning it on was
never going to be a good idea: `threat_modeling` is adjacent to every
pillar that has plugins, so `adjacent` mode admits all 16 tools to
compete for the 5 candidate slots — the opposite of the router's stated
purpose of exposing 3-5 relevant tools. A mechanism whose only setting
worth using is "off" is better deleted than carried.

`also_useful_in` covers the same need with better properties: one
declaration at a time, written by the plugin author, visible in the
manifest, reviewable per plugin, and testable.

## Changes

### `framework/routing/router.py`

- `RouterConfig` loses `adjacency_map` and `expansion_mode`;
  `load_from_directory` no longer opens `adjacency.json`. Remaining
  config: pillars, keywords, artifact rules.
- Phase 2 is one line: `get_for_pillar(selected_pillar)`. The expansion
  branch and the dedupe that existed only to protect against it are gone.
- `_score_tools` scores `pillar_match` in two tiers: `1.0` own pillar,
  `0.75` declared via `also_useful_in`. The `0.5` adjacent tier is
  removed.
- `EXPANSION_MODES` removed.

### `framework/routing/config/adjacency.json`

Deleted. The router now reads three config files.

### Docs

`router_design.md` replaces the Expansion Modes and Adjacency Map
sections with the declaration model, and records why adjacency was
removed rather than silently dropping it. The weight table, the routing
output contract, the configuration list and the MVP implementation order
are updated. `eventmill_v1_1.md`'s "Single active pillar" constraint and
the config tree in `framework_architecture.md` follow.

`_related_tools` in `shell.py` had a docstring justifying itself against
adjacency; it now describes the two halves of cross-pillar relevance
without referring to removed machinery.

## Behaviour

Unchanged. The shipped configuration was `strict`, and strict is what the
code now does unconditionally. Routing a threat-intel question inside
`threat_modeling` still gives:

```
Selected pillar: threat_modeling
Candidate tools (5):
  - threat_intel_ingester:    1.94 (pillar=0.8, artifact=0.3, keyword=0.8)
  - threat_report_analyzer:   1.84 (pillar=1.0, artifact=0.0, keyword=0.6)
  - threat_model_analyzer:    1.68 (pillar=1.0, artifact=0.0, keyword=0.2)
  - attack_path_visualizer:   1.60 (pillar=1.0, artifact=0.0, keyword=0.0)
  - risk_assessment_analyzer: 1.60 (pillar=1.0, artifact=0.0, keyword=0.0)
```

## Tests

`TestExpansionMode` is deleted along with the feature. `TestAlsoUsefulIn`
keeps the cross-pillar coverage, including that a tool from a pillar that
neither matches nor is declared stays out of the candidate set - which
under strict-only routing is now a property of the model rather than of a
mode. `tests/conftest.py` no longer writes `adjacency.json`, and
`test_load_from_directory` no longer asserts an adjacency map.

620 tests pass.
