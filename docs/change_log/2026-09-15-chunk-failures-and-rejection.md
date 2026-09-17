# Change Log — chunk failures are visible, and a rejection is not undone

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md`, **Stage 1.5**
**Scope:** `plugins/log_analysis/threat_intel_ingester/` only.
**Status:** implemented. **No live model requests were made.**

---

## Two defects with one shape

Both come from a single line answering two different questions at once, and
from failure counts that never left the log stream.

### 1. `if not refined_iocs:` reinstated what the model rejected

An empty `refined_iocs` meant either *"the model assessed every candidate as a
false positive"* or *"refinement never produced anything"*. Both fell through to
the regex baseline, so an all-false-positive assessment **returned the exact
indicators the model had just rejected**, at `confidence: "low"`, labelled
`ingestion_mode: "regex_only"`.

That is worse than returning nothing: a correct filtering result became a wrong
one, and the label said the filtering had not happened.

### 2. Chunk failures existed only in log lines

`chunk_json_failures`, `chunk_llm_failures` and `chunk_exceptions` were counted
and logged, then discarded. A run where four of ten chunks failed merged the six
survivors and produced a result **indistinguishable from a clean run** — the
candidates in the failed chunks were never assessed and nothing said so. After
Stage 1.4 this was worse than cosmetic: such a run reported
`analysis_status: "complete"`.

That gap was recorded in `2026-09-15-analysis-status.md` as a known Goal A
failure for 1.5 to close. It is closed.

## What changed

### `refinement_ran` is tracked separately from "anything survived"

Set when at least one chunk or native batch produced parseable JSON. The
fallback is now:

| Condition | Result |
|---|---|
| Refinement ran, accepted nothing | **zero IOCs**, `ingestion_mode: "llm"`, status `complete` |
| Refinement never ran, or wholly failed | regex baseline, `ingestion_mode: "regex_only"`, status `degraded` |

The regex fallback itself is untouched — it is still the right answer when
refinement was unavailable. Only the reinstatement of an *explicit rejection*
was wrong.

Unparseable JSON counts as a failure, not a rejection: the model answered and
the answer could not be read, which is not an assessment that every candidate
was benign. A test pins that distinction.

### Per-chunk outcomes reach the result

New on the result `summary`, all additive:

```
chunks_attempted, chunks_failed,
chunk_failure_breakdown: {json_parse, llm_call, exception},
candidates_rejected
```

The breakdown separates causes that mean different things: a `json_parse`
failure means the model answered and the answer was unusable; an `llm_call`
failure means it did not answer at all.

A non-zero `chunks_failed` now makes the run **partial**, with the note
`INCOMPLETE ANALYSIS: 4 of 10 chunk(s) produced no usable result, so their
candidates were never assessed`.

### "No indicators accepted" is complete, and says so

A rejection is a finished answer, so it does **not** make the run partial. But
an empty IOC list reads as a failure unless the reason is stated, so it carries
the note `NO INDICATORS ACCEPTED: all N candidate(s) were assessed as false
positives; the empty result is the assessment, not a failure to produce one`.

This exposed a gap in Stage 1.4's rendering: `summarize_for_llm` emitted
`analysis_notes` only when the status was *not* complete, so this note would
never have been seen. It now renders notes on a complete run too — without the
status prefix, since there is no warning to make. A clean run with no notes is
silent exactly as before.

### One subtlety worth recording

`accepted_none` is computed from `refined_iocs`, not `filtered_iocs`. An empty
result *after* the confidence threshold is the threshold's doing, not a
false-positive assessment, and claiming otherwise would be a new version of the
same conflation this stage removes.

## Open decision 2, resolved as the plan assumed

*Zero accepted IOCs — return an empty set, or the regex baseline labelled
`unrefined`?*

**Implemented as assumed: an empty set.** Reinstating indicators the model
explicitly rejected is worse than returning none, and the empty result is now
labelled well enough to not be mistaken for a failure. Reversible if you
disagree — it would mean keeping the baseline and adding an `unrefined` mode
rather than reusing `regex_only`, which would otherwise claim refinement never
happened.

## Verified

- Full suite: **1285 passed** (baseline 1268; 17 new tests in
  `tests/test_chunk_failures.py`).
- **Mutation-checked.** Restoring the conflation and dropping the chunk-failure
  note fails **6 of the 17**, including
  `test_zero_iocs_and_mode_stays_llm`.
- Every failure cause is exercised separately: a transport failure, an
  unparseable reply, and a raised exception each land in their own breakdown
  bucket.
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.

## Not verified

- **No live model requests.** Whether real reports produce all-false-positive
  assessments often enough to matter is unmeasured; the defect was reachable by
  construction, which is what this fixes.
- `ruff` and `black` are still not installed in the active interpreter.
- `chunks_attempted` is 0 when the native path covered the whole document. That
  is correct — no chunked calls were made — but it means `chunks_failed == 0`
  on a native run says nothing about native batch failures. Native batch
  outcomes are tracked separately and are **not** folded into
  `analysis_status`; that belongs with Stage 2.1, which is already about native
  batch bookkeeping.

## Stage 1 status

1.1-1.5 done. **1.6** (persist coverage and status with the exports) and
**1.7** (do not count an unreadable page as read) remain.

With 1.5 in, the ingester no longer reports work it did not do: dropped pages,
truncated chunks, failed chunks and an unavailable refinement each reach
`analysis_status`, and the one case that legitimately produces nothing says why.
