# Change Log — raw extracted text is no longer passed off as a summary

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md`, **Stage 1.3**
**Scope:** `plugins/threat_modeling/threat_report_analyzer/` only.
**Status:** implemented. **No live model requests were made** — every test uses
synthetic responses.

---

## What was wrong

This is the compound failure the parent review identified and the external
analysis described only in pieces.

`_summarize_chunk` initialised `summary_text` to `chunk.content[:3000]` — raw
pypdf output — and replaced it only inside `if response.ok`. So:

| Outcome | What ended up in `summary` |
|---|---|
| Call failed, or raised, or no LLM | 3,000 characters of **raw extracted text** |
| `ok=True` with empty text (budget starvation) | **empty string** |

Neither was marked. Both then travelled two ways, which is what made it
dangerous rather than merely untidy:

1. `_write_chunk_artifact` persisted the value to a file named
   `<report>.<stamp>.chunk_NNN.summary.md`. A file in the common bucket whose
   name says "summary" could hold raw PDF text, or nothing.
2. `_synthesize_summaries` concatenated it into the synthesis prompt under a
   `[Pages 40–60]` label, where the model had no way to tell it from a real
   section summary.

And if synthesis itself failed, the function returned `combined` — that same
concatenation, unsummarised blocks included — as the final report summary, with
`ok=True` and no marker.

## What changed

### A section now says what it is

Every chunk summary carries `status`:

| Status | Meaning | `summary` | `raw_excerpt` |
|---|---|---|---|
| `complete` | a real summary | the text | `None` |
| `partial` | real, cut off at the output cap | the text | `None` |
| `empty` | `ok=True`, no text — budget starvation | `None` | the excerpt |
| `failed` | call failed, raised, or no LLM | `None` | the excerpt |

`summary` is `None` until a genuine non-empty reply sets it. The excerpt is
still kept — it is the only content there is — but in its own key. That
separation is the whole fix: nothing downstream can now read raw pypdf output
out of a field called `summary`.

`empty` is deliberately distinct from `failed`. It is the Stage 1.1
starvation outcome, and a transport that reports no error at all is exactly the
case that used to be invisible.

### Substitutions are labelled wherever they go

Three small helpers — `_chunk_label`, `_chunk_notice`, `_chunk_text` — and two
composition points:

- **Synthesis prompt:** `[Pages 40–60 — SECTION SUMMARY FAILED; raw extracted
  text follows, treat as unsummarised source]`. A `complete` section is
  labelled exactly as before, so the normal prompt is unchanged.
- **Exported file:** `_chunk_export_text` prefixes a `>` blockquote notice to a
  substitution. A real summary, whole or truncated, is written verbatim as
  before — stamping provenance onto *every* export is Stage 1.6.

### The run reports that it was degraded

`_degradations` mirrors 1.2's `_truncations`: per-run state, reset in
`_summarize_report`, surfaced as `degraded` / `degradation_notes` and stated in
`summarize_for_llm`. Recorded when a section produced no summary, and when the
synthesis pass did not produce a report.

**Truncation is not a degradation.** A `partial` section holds real analysis
that was cut short; it is reported as truncated (1.2), not degraded. Conflating
them would make `degraded` fire so often it stopped meaning anything. A test
pins the distinction.

### Synthesis failure

Still returns `combined`, per the plan — it is the best available answer. But
the concatenation is now built from *labelled* blocks, and the run is marked
degraded, so it cannot read as though synthesis happened. An `ok=True` reply
with empty text is treated the same way as a failure here, which it previously
was not.

### Schema

Additive: `degraded` and `degradation_notes` on the analyzer's summary items.
`scripts/validate_schemas.py` — **34 schemas valid**.

## Open decision, resolved as the plan assumed

The plan's third open decision: *chunk artifacts for failed sections — write
them with a failure header, or not at all?*

**Implemented as written: they are written, with the header.** The plan's
reasoning holds — a missing file cannot distinguish a section that failed from
one that was never attempted, so silence is the more ambiguous outcome. A test
pins it. Say so if you want the opposite; it is a one-line change plus its
test.

## Verified

- Full suite: **1238 passed** (baseline 1210; 28 new tests in
  `tests/test_section_status.py`).
- **Mutation-checked.** Restoring the old initialiser — the excerpt as
  `summary`, status `complete` — fails **11 of the 28**, including every
  "raw text is never in the summary key" case.
- Every value in `CHUNK_STATUSES` is reachable from a synthetic scenario, and a
  test asserts the four observed statuses are exactly that vocabulary.
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.
- The `adversary_path_projector` flake recorded in
  `2026-09-15-truncation-is-recorded.md` did not recur in this change's runs.
  That is not evidence it is fixed — it was intermittent to begin with.

## Not verified

- **No live model requests.** How often sections actually come back empty now
  that Stage 1.1 sizes budgets correctly is unmeasured. The expectation is
  "much less often"; that is an expectation, not a measurement.
- `ruff` and `black` are still not installed in the active interpreter.
- The native whole-PDF path has no equivalent of this. It either succeeds, is
  refused by provider policy, or falls through to the chunked path — there is
  no substitution to mark. Worth re-checking if 3.5 adds native batching there.

## Next

Stage 1.4 — `analysis_status: complete | partial | degraded` plus
`analysis_notes`, surfaced **first** in `summarize_for_llm` so the 2000-character
cap cannot truncate the warning away. The inputs now all exist: 1.2's
`truncated` / `truncation_notes` and 1.3's `degraded` / `degradation_notes` on
the analyzer, and `truncated` / `truncated_chunks` on the ingester. 1.4 is
mostly folding them into one field and putting it at the front.
