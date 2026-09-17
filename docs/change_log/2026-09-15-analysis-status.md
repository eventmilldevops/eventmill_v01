# Change Log — one status per run, stated first

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md`, **Stage 1.4**
**Scope:** `plugins/threat_modeling/threat_report_analyzer/` (`tra`) and
`plugins/log_analysis/threat_intel_ingester/` (`ti`).
**Status:** implemented. **No live model requests were made.**

---

## What was wrong

Stages 1.2 and 1.3 gave each failure mode its own field and its own sentence:
`INCOMPLETE COVERAGE`, `TRUNCATED OUTPUT`, `DEGRADED INPUT`. All three were
appended **after** the content in `summarize_for_llm`.

`PluginExecutor` caps `summarize_for_llm` at 2000 characters and truncates from
the end. So the warnings were precisely the part most likely to be cut — and a
caller had to read and combine three fields to answer the only question that
matters first: *is this the answer this tool normally produces?*

## What changed

### `analysis_status` and `analysis_notes` on both plugins

```
analysis_status: "complete" | "partial" | "degraded"
analysis_notes:  list[str]
```

- **complete** — nothing truncated, no pages dropped, no fallback.
- **partial** — content is missing, but every cause is known and named.
- **degraded** — the tool fell back to a materially worse input path.

**Precedence is degraded > partial > complete**, and the distinction is
deliberate: "partial" says the same analysis covered less of the report;
"degraded" says part of it was never analysed at all. Calling the regex
baseline "partial" would understate it — nothing classified those indicators or
ruled out false positives, which is a different kind of answer rather than less
of the same one.

Derived from what 1.2 and 1.3 already recorded, so this stage is mostly
assembly:

| Cause | Plugin | Status |
|---|---|---|
| Pages dropped | both | partial |
| Reply truncated at the output cap | both | partial |
| Section produced no summary; raw text stood in | `tra` | degraded |
| Synthesis did not produce a report | `tra` | degraded |
| PDF read as pypdf text instead of natively | `tra` | degraded |
| `ingestion_mode == "regex_only"` | `ti` | degraded |

### One input that did not exist yet

`tra` never recorded the **native → pypdf text** fallback, which the plan names
explicitly as a degradation. It does now, at the `if not native_pdf_succeeded:`
seam, distinguishing "the native attempt did not succeed" from "native document
ingestion was unavailable" via a new `native_attempted` flag. Both are
degradations — page images, layout and tables are absent from the input either
way — but the operator needs to know which.

### The status leads

`summarize_for_llm` now renders `PARTIAL — <notes>. ` or `DEGRADED — <notes>. `
before anything else, in `ti` ahead of even the report title. A `complete` run
says nothing about status, as before.

The separate trailing sentences are **removed**, not kept alongside: each cause
is now phrased as a note, and saying it twice wastes a capped budget. The
coverage and truncation wording survives inside the notes, so `INCOMPLETE
COVERAGE`, `TRUNCATED OUTPUT` and `DEGRADED INPUT` still appear — just in front.

### A duplicate removed

`ti`'s `summarize_for_llm` carried a separate trailing block:

```
WARNING: LLM analysis failed — results are regex-only (low confidence, no
MITRE mapping, no attack graph). Check logs for LLM failure details.
```

That is the same fact as the new `DEGRADED INPUT` note. Its detail — no MITRE
mapping, no attack graph, no false-positive assessment — was folded into the
note and the trailing block deleted. Nothing in the tests referenced it.

### Schemas

Additive on both: `analysis_status` (with the three-value `enum`) and
`analysis_notes`. A test in each plugin asserts the code's vocabulary and the
schema's `enum` are the same set, so they cannot drift.
`scripts/validate_schemas.py` — **34 schemas valid**.

## Two existing tests changed

Both asserted on `summarize_for_llm` using hand-built result dicts, and both
checked a warning that now arrives through `analysis_notes`:

- `tra` `test_contract.py::test_truncation_is_stated_in_the_llm_summary`
  (committed at `a83e74e`)
- `tra` `test_section_status.py::test_degradation_is_stated` (Stage 1.3)

Each now supplies `analysis_status` / `analysis_notes` and additionally asserts
**the status leads**. Neither was weakened: the derivation they no longer
exercise is covered directly by the new `test_analysis_status.py` in each
plugin, which is the stronger arrangement — rendering and derivation tested
separately rather than one test doing both loosely.

## Verified

- Full suite: **1268 passed** (baseline 1238; 30 new tests).
- **Mutation-checked.** Removing the lead and flattening the precedence to
  "partial" fails **15 of the 30**.
- The 2000-character cap is tested directly in both plugins: with a note long
  enough to overflow, `text[:2000]` still starts with the status.
- Each status is reachable from a synthetic scenario in both plugins, and the
  code vocabulary is asserted equal to the schema `enum`.

## Not verified

- **No live model requests.**
- `ruff` and `black` are still not installed in the active interpreter.
- `ti` chunk-level failures (`chunk_json_failures`, `chunk_llm_failures`,
  `chunk_exceptions`) are counted in logs but never reach the result, so they
  cannot contribute to `analysis_status`. A run where several chunks failed but
  some succeeded still reports `complete`. **This is a real remaining gap in
  Goal A** and belongs with 1.5, which is already in that code.

## The projector flake, now characterised

`adversary_path_projector`'s `TestRunGroupSummary::test_two_batches_build_one_group`
failed again during this work, with a **different** wrong value than before:
`[1, 2, 3, 4]` where `2026-09-15-truncation-is-recorded.md` recorded
`[1, 2, 3, 5]`. Expected is `[1, 2, 4, 5]`.

`[1, 2, 3, 4]` is exactly what ordering the six records by `run_index` alone
produces: each invocation numbers its own runs 1-3, so a run_index-major order
interleaves the batches as b1r1, b2r1, b1r2, b2r2, b1r3, b2r3 — DB, DB, DB, DB,
WEB, WEB.

The sort at `adversary_path_projector/tool.py:4137-4139` is:

```python
records.sort(key=lambda r: (
    r["run"].get("created_at", ""), r["run"].get("run_index", 0)
))
```

with the comment that it exists so batches "number in the order they happened
rather than interleaving on a per-invocation index". When `created_at` is
absent or equal across records the key collapses to `run_index`, and the sort
produces precisely the interleaving the comment says it prevents.

**Not established:** why `created_at` is absent or equal on some runs.
`_write_run_record` sets it from `datetime.now(timezone.utc).isoformat()`, which
is microsecond-precision and should not collide. So the mechanism is identified
but its trigger is not, and this is still a plugin outside this change's scope.
It is a defect in run-group numbering, not only a flaky test: the same
degenerate ordering would misnumber a real group.

## Next

Stage 1.5 — distinguish "classified, none accepted" from "classification
unavailable" at `ti:2111`. Today an all-false-positive assessment is
indistinguishable from a total refinement failure, and the recovery reinstates
the exact indicators the model rejected, at `confidence: "low"`. It is also
where `ti`'s per-chunk failure counts should start reaching the result, which
closes the gap named above.
