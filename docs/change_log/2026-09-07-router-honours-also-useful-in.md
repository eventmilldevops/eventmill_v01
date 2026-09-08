# Change Log — the router honours `also_useful_in`

**Date:** 2026-09-07
**Primary Files Modified:** `framework/routing/router.py`
**Supporting Files:** `tests/framework/test_routing.py`,
`docs/specs/router_design.md`

---

## Problem

`also_useful_in` landed on 2026-09-05 with one consumer, the `tools`
listing. The router still built its candidate set from
`get_by_pillar(selected_pillar)`, so a tool that declared another pillar
was offered in that pillar's menu but could never be routed there.

`RouterConfig.expansion_mode` defaults to `"strict"` and
`load_from_directory` does not read it from any config file, so the shell
always routes in strict mode: adjacency expansion (`router.py:209-212`)
and the `pillar_match = 0.5` adjacent tier never fire in the running
product. In a `threat_modeling` session the router could only ever see
the four native tools.

## Changes

### `framework/routing/router.py`

- **Phase 2** builds candidates with `get_for_pillar`, so a declaring
  tool is in the set. Adjacency expansion is unchanged and still gated on
  `expansion_mode`, but now dedupes by tool name: a borrowed tool from an
  adjacent pillar would otherwise be added twice.
- **Phase 3** scores `pillar_match` in three tiers: `1.0` own pillar,
  `0.75` declared via `also_useful_in`, `0.5` adjacent. A declaration is
  an author naming one pillar deliberately, so it outranks the blanket
  adjacency relation; a native tool still wins when both are otherwise
  equal. The 0.25 gap is deliberately smaller than an artifact match
  (weight 0.8) can close, so a declared tool that consumes what is loaded
  can still come first.
- `get_tools_for_pillar` uses `get_for_pillar`, matching what the CLI
  now lists.

`also_useful_in` is deliberately not gated on `expansion_mode`. Adjacency
is a blanket relation an operator may switch off; this is one plugin
naming one pillar on purpose, and gating it would let the field silently
do nothing — which is how adjacency expansion came to be unreachable.

Phase 1 is untouched. A declared tool never changes which pillar is
selected; it only competes for a candidate slot inside one.

## Observed effect

In `threat_modeling` with a `pdf_report` loaded:

```
"ingest this threat intelligence report"
  threat_intel_ingester    total=1.94  pillar=0.75  artifact=0.33  kw=0.80
  threat_report_analyzer   total=1.84  pillar=1.00  artifact=0.00  kw=0.60

"map these findings to attack paths"
  threat_model_analyzer    total=1.26  pillar=1.00
  attack_path_visualizer   total=1.08  pillar=1.00
  threat_intel_ingester    total=1.02  pillar=0.75  artifact=0.33
```

The ingester leads when the question is about ingesting intel, and falls
behind both native tools that match the wording when it is not — while
still sitting above the natives that match nothing, on the strength of
the loaded report.

## Not done

`expansion_mode` is still unreachable from configuration. Either
`load_from_directory` should read it or the adjacency code should go;
that is a decision about whether adjacent-pillar expansion is wanted at
all, not something to settle here.

## Tests

`tests/framework/test_routing.py::TestAlsoUsefulIn` — six tests over the
shipped plugins and shipped routing config: the declared tool is scored
and reaches `candidate_tools`, it scores 0.75 against a native 1.0, it
scores 1.0 in its own pillar, undeclared pillars stay out under strict
mode, pillar selection is unaffected, and `get_tools_for_pillar` includes
it while excluding undeclared tools.

620 tests pass.
