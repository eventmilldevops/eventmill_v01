# The summary budget belongs to the tool, not the framework

**Date:** 2026-09-16
**Branch:** `llm_5`
**Scope:** `framework/plugins/{loader,executor,protocol}.py`,
`docs/specs/manifest_schema.json`, both report plugins' manifests, the docs that
stated the old number
**Status:** built and mutation-checked. Suite **1471 → 1475**.

`summarize_for_llm()` was capped at a hardcoded 2000 characters. That number
predates the current providers, where 2000 characters is roughly 500 tokens
against context windows measured in hundreds of thousands. A tool that reads a
154-page report has more to say than one that lists files, and the ceiling now
travels with the tool.

*(Operator decision, 2026-09-16.)*

---

## What changed

| Where | Change |
|---|---|
| `loader.py` | `DEFAULT_SUMMARY_BUDGET = 4000`; `PluginManifest.summary_budget` reads `summary_budget`, clamped at 0 |
| `docs/specs/manifest_schema.json` | `summary_budget` declared — required, because `additionalProperties: false` fails **every** plugin at once on an unregistered field |
| `executor.py` | truncates at `plugin.manifest.summary_budget` instead of the constant, and names the tool in the warning |
| `ti/manifest.json`, `tra/manifest.json` | `summary_budget: 8000` |
| `ti/tool.py` | `_summary_cap()` reads the plugin's own manifest, the same way `_native_tier()` reads `model_tier` |

**Default doubled, 2000 → 4000. Both report tools set 8000.**

### Two things done deliberately

**The budget is read outside the `try`.** It was briefly inside, and a manifest
without the attribute surfaced as `summarize_for_llm failed` in the log — which
sends whoever reads it to the wrong file. `getattr` with the default now, and
the lookup cannot be mistaken for a plugin fault. A test covers it.

**The plugin reads its own budget too.** The executor's truncation is a last
resort that loses whatever the plugin put last. A plugin that can run long is
expected to budget its own summary and never arrive at the cut. The manifest
stays the single place the number is set; both sides read it.

## What did **not** change

**The bounded attribution narration stays.** *(Operator decision,
2026-09-16.)* A larger ceiling is not a reason to narrate thirty proper nouns.
The live 154-page run named ~30 actors and ~20 campaigns; listing them all
produces something that is mostly names and no longer a summary. Bounding holds
at any budget, and the analyst has the artifact, the export and the source
document. This is meant to be a meaningful summary, not a line-by-line copy.

Concretely: `_SUMMARY_LIST_BUDGET` is still 180 characters per narrated list,
and `_attribution_narration` still sizes itself against the room left. With the
cap at 8000 the ingester's summary for that report lands near 1,400 — the extra
budget is headroom, not something to fill.

## Correcting the record

The previous entry said the oversized summary was cutting the findings off the
live run. **It was not.** The cap lives in `PluginExecutor`, and the shell does
not use `PluginExecutor` — `do_run` calls `instance.execute()` directly and
stores and prints the summary whole. `PluginExecutor` is in fact instantiated
nowhere in the live code today; it is the declared contract, enforced by its own
tests and by nothing else at runtime.

So the 3,712-character summary reached the operator intact, and the real problem
was narrower: a plugin 85% over the contract it is written against, storing that
string in the session database, and sitting on a cut that would take the IOC
counts and the analyst-action line the moment the contract is enforced.
`2026-09-16-stage-2-live-run-154-page.md` carries the correction inline.

That the enforcement point is currently dead code is worth its own decision
later — either the shell should route through `PluginExecutor` or the contract
should stop claiming to be enforced. Not changed here.

## Verification

Suite 1471 → 1475. `validate_schemas.py` 34 valid, exit 0.
`validate_manifests.py` reports the same **15 pre-existing** `'stable' is not
one of [...]` errors and nothing new, so `additionalProperties: false` accepts
the new field on both manifests.

New tests in `tests/framework/test_executor.py`:

- the budget comes from the manifest (8000 gives 8000, not the default)
- a manifest without the field falls back to the default **and does not report
  it as `summarize_for_llm` failing**
- a summary inside the budget is untouched
- the existing truncation test asserts against `DEFAULT_SUMMARY_BUDGET` rather
  than a literal

The ingester's budget tests now read `_summary_cap()` rather than a literal
2000, plus a test that it equals the manifest's own number — so the two cannot
drift apart silently. The pressure sweep was rescaled to walk the new 8000
ceiling.

## Docs updated

`CLAUDE.md`, `docs/guides/plugin_development.md`,
`docs/specs/framework_architecture.md`, `docs/specs/tool_plugin_spec.md`,
`docs/specs/report_processing_integrity.md` (amended in place, with the reason
the original text still holds), and the READMEs for `threat_intel_ingester`,
`threat_report_analyzer` and `attack_path_visualizer`.

Historical change-log entries that state 2000 are left alone — they were
accurate when written, and rewriting them would make the record say the number
was never 2000.
