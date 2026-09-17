# Change Log — a truncated reply is no longer reported as complete work

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md`, **Stage 1.2**
**Scope:** `plugins/threat_modeling/threat_report_analyzer/` (`tra`) and
`plugins/log_analysis/threat_intel_ingester/` (`ti`).
**Status:** implemented. **No live model requests were made** — every test uses
synthetic responses.

---

## What was wrong

`LLMResponse.truncated` is populated correctly by all three clients
(`gemini.py:467,620`, `anthropic.py:429`, `openai.py:434`) and reaches the
plugin unchanged. Four call sites ignored it:

| Call site | What it read | What it missed |
|---|---|---|
| `tra` native whole-PDF | `ok and text` | a summary that stopped mid-report |
| `tra` section summary | `ok` | a section covering part of its page range |
| `tra` synthesis | `ok` | a final summary missing its later sections |
| `ti` chunked text path | `ok and text` | both the finish reason **and** the bracket-repair flag |

The `ti` text path had the sharper version: it called `_parse_llm_json`
(`ti:532`), the thin wrapper that **discards** the repair flag
`_parse_llm_json_result` returns, so a reply that only parsed after unmatched
brackets were closed was indistinguishable from a clean one.

Nothing here needed designing. The correct pattern already existed in this
repository at `ti:1797-1799`, on the native path of the same file. This change
applies it in four more places.

## What changed

### Both signals, everywhere

```python
truncated = bool(response.truncated)          # the transport's finish reason
parsed, repaired = _parse_llm_json_result(…)  # a reply repaired by closing brackets
truncated = truncated or repaired
```

Neither subsumes the other, which is why the `ti` text path now calls
`_parse_llm_json_result` and ORs both.

### `tra` — truncation travels with the result

- New per-run state `_truncations: list[str]`, reset in `_summarize_report`
  next to `_last_pdf_pages` and for the same reason: a value left from an
  earlier report would describe the wrong run.
- `_note_truncation()` records one human-readable line per cut-off call, naming
  *which* work was truncated — the whole-document pass, a specific page range,
  or the synthesis. "Something was truncated" is not actionable; "the summary
  of pages 40–60 stopped at the output cap" is.
- `_truncation_fields()` mirrors `_coverage_fields()` and adds `truncated` and
  `truncation_notes` to the result. Unlike coverage it is **always** stated:
  every LLM path now reads the finish reason, so `false` is a measurement
  rather than an absence of one.
- Each chunk summary dict carries its own `truncated` flag.

### `ti` — the affected chunk index is recorded

`chunk_truncations: list[int]` holds the 1-based indices of chunks cut off at
the cap. Declared at method level, not inside the LLM block, because the result
is built outside it. Surfaced as `truncated` and `truncated_chunks` in the
result `summary`.

### Both — the warning reaches `summarize_for_llm`

`summarize_for_llm` is what downstream reasoning actually sees, and it is
capped at 2000 characters by `PluginExecutor`. Both plugins now state
truncation there, immediately after the existing `INCOMPLETE COVERAGE` line and
for the same reason: a truncated summary reads exactly like a complete one.

Stage 1.4 will fold both of these into `analysis_status` / `analysis_notes` and
move the status ahead of everything else. Until then these fields are the
record, and they are shaped so 1.4 can absorb them without a schema break.

### Schemas

Additive only: `truncated` + `truncation_notes` on the analyzer's summary
items, `truncated` + `truncated_chunks` on the ingester's result summary.
`scripts/validate_schemas.py` — **34 schemas valid**.

## What this change deliberately does not do

**A truncated reply is not converted into a failure.** The text is kept and the
run still succeeds; the defect was the silence, not the content. A test pins
this: a truncated `ti` chunk must not downgrade the run to the regex baseline,
and the IOCs the model did return must survive.

**Recovery is not attempted.** Retrying at a larger budget or bisecting the
range is Stage 3.6. This change makes truncation *visible*, which is the
prerequisite for deciding whether recovery is worth it.

## Verified

- Full suite: **1210 passed** (baseline 1191; 19 new tests). See the caveat
  below.
- **Mutation-checked.** With only the truncation reads reverted, **9 of the 19
  new tests fail**. They fail on the defect rather than merely passing on the
  fix.
- Both signals covered independently: a test asserts that a reply the transport
  reported as `STOP`, but which only parsed after bracket repair, is still
  recorded as truncated.
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.

## Caveat — an intermittent failure elsewhere in the suite

`adversary_path_projector`'s `TestRunGroupSummary::test_two_batches_build_one_group`
failed once out of three full-suite runs on this tree, asserting
`db_route["runs"] == [1, 2, 4, 5]` and getting `[1, 2, 3, 5]`.

Established:

- It **passes in isolation** and passed on two subsequent identical full runs.
- It is **not caused by the source changes here**: the full suite with the two
  new test files excluded is **1191 passed**, matching the baseline exactly.
- `pytest-randomly`, `pytest-xdist` and `pytest-forked` are all absent, so
  collection order and execution are deterministic. The nondeterminism is
  inside that test or the plugin it exercises, not in the runner.

**Not established:** the mechanism. The projector makes no concurrent LLM calls
and `_SequencedLLM` hands out replies from a plain index, so the shifted
sequence is unexplained. It is a pre-existing flake in a plugin outside this
change's scope and was left alone rather than chased or papered over.

## Not verified

- **No live model requests.** How often real replies truncate now that Stage
  1.1 sizes budgets correctly is unmeasured.
- `ruff` and `black` are still not installed in the active interpreter, so
  neither was run.
- `_parse_llm_json` (`ti:532`) still exists and still discards the repair flag.
  It is kept because `test_contract.py:1302` exercises the repair logging
  through it. A new test asserts no production call site below its definition
  calls it, so the defect cannot be reintroduced silently — but the trap is
  still in the file.

## Next

Stage 1.3 — stop substituting raw pypdf text for a section summary without
saying so. It is the other half of the compound failure: a failed section still
produces a file named `.summary.md` holding 3,000 characters of raw extracted
text or nothing at all, unmarked, and `_synthesize_summaries` cannot tell that
block from a real summary. Stage 1.2 makes a *truncated* section visible; a
*failed* one is still silent.
