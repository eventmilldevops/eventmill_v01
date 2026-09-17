# Change Log — exports carry their own provenance; an unreadable page is not a read one

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md`, **Stages 1.6 and 1.7**
**Scope:** `plugins/threat_modeling/threat_report_analyzer/` (`tra`) and
`plugins/log_analysis/threat_intel_ingester/` (`ti`).
**Status:** implemented. **No live model requests were made.**
**This completes Stage 1.**

---

## 1.7 — an unreadable page is not a page that was read

`_split_pdf_into_chunks` appended `""` for a page whose `extract_text()` raised,
exactly as it did for a page that is genuinely blank. Both then counted toward
`pages_read`. A coverage number that cannot distinguish a blank page from a
scanned one is not evidence of coverage.

Page outcomes are now counted in three buckets:

| Bucket | Meaning | Effect on status |
|---|---|---|
| `pages_read` | yielded text | — |
| `pages_empty` | genuinely blank | **none** |
| `pages_extract_failed` | pypdf could not read it | **partial**, with a note |

A blank page is a legitimate outcome and is deliberately **not** a defect —
reporting it as one trains operators to ignore the field. An unreadable page
adds `UNREADABLE PAGES: N of M pages could not be read as text (scanned or
damaged), so their content is absent from this summary`.

`pages_dropped` keeps its meaning: **never attempted**, i.e. beyond the local
page ceiling. A page pypdf failed on *was* attempted, and calling it dropped
would hide that the file itself is the problem. The two counts are now
orthogonal rather than one absorbing the other.

Backwards compatible: `_last_pdf_page_outcomes` is `None` when no per-page
extraction ran — native ingestion reads the document whole — and
`_coverage_fields()` then reports exactly what it reported before.

## 1.6 — coverage and status travel with the export

An export outlives the session that produced it. Everything Stages 1.2-1.5
built lived only on the returned `ToolResult` and vanished the moment the
artifact was read back.

### `ti` — the persisted artifact

`output_data` gains `coverage`, `ingestion_mode`, `analysis_status` and
`analysis_notes` alongside the existing four keys. A file read from the bucket
now says whether its indicators were refined or are a regex baseline, which was
previously the first thing a later reader needed and the one thing not written
down.

The status is computed **once** and used in both the artifact and the result, so
the two cannot disagree. A test asserts they match.

### `tra` — a provenance block on every written file

Prepended to the final summary and to every chunk artifact, on both the local
and GCS paths:

```
<!-- Event Mill threat_report_analyzer -->
> **Source:** `vendor/r.pdf`
> **Run:** 20260915T120000Z
> **Answered by:** gcp_gemini/gemini-3.8-flash-002
> **Analysis status:** partial
> - TRUNCATED OUTPUT: the whole-document summary stopped at the output cap…
> **Pages:** 148 read of 154, 3 blank, 3 unreadable
```

`_note_model` records `provider_id` and prefers `model_version` — what the
provider reports having served — over `model_used`, which is only what was
asked for. Per the existing provider-attribution work, a summary with no
attribution cannot be compared against another vendor's or re-run against the
same one.

## One existing test changed

`test_section_status.py::test_the_chunk_file_is_still_written_for_a_failed_section`
(Stage 1.3) asserted the chunk file *starts with* the substitution notice. It
now starts with the provenance block. The assertion was **strengthened** rather
than relaxed: it checks the provenance header opens the file, the notice is
present, and the notice still precedes the raw text.

## Verified

- Full suite: **1308 passed** (baseline 1285; 23 new tests).
- **Mutation-checked.** Counting an unreadable page as blank again, and
  dropping both persistence paths, fails **12 of the 23**.
- The plan's 1.7 fixture is implemented exactly: one text page, one blank page,
  and one whose `extract_text()` raises reports
  `pages_read=1, pages_empty=1, pages_extract_failed=1` and status `partial`.
- The plan's 1.6 round-trip is implemented for both plugins: write the
  artifact, read it back, assert coverage and status survive.
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.

## Not verified

- **No live model requests.** No real scanned PDF was run through the new
  counting; the outcomes are exercised with a stubbed `pypdf`.
- `ruff` and `black` are still not installed in the active interpreter.
- The provenance block is **not** parsed back. It is written for a human
  reading the file, and nothing re-reads it as data. If a later stage wants to
  reconcile an export against a run record, that needs a machine-readable
  sidecar rather than parsing markdown.
- OCR is still out of scope. 1.7 makes the loss *visible*, which is the
  prerequisite for deciding whether OCR is worth a new dependency — that
  decision is unchanged and still open.

## Stage 1 is complete

| Step | What it removed |
|---|---|
| 1.1 | Every analyzer call sized below its own thinking reserve |
| 1.2 | Four call sites discarding `LLMResponse.truncated` |
| 1.3 | Raw pypdf text presented as a section summary |
| 1.4 | Three separate warnings, none of them stated first |
| 1.5 | A rejection reinstated as a regex baseline; invisible chunk failures |
| 1.6 | Coverage and status dying with the session |
| 1.7 | An unreadable page counted as read |

Goal A — *incomplete work is never reported as complete* — holds for both
plugins as far as deterministic control flow can establish it. Every failure
mode reachable in these two tools now reaches `analysis_status`, and
`analysis_status` leads `summarize_for_llm`.

**This is the plan's recommended stopping point.** Stage 2 (evidence the model
produced is never destroyed — the first-wins merge, the partial that beats its
own retry, `path_id` collisions) is independently valuable and does not depend
on Stage 3. Stage 3 remains hard-gated on the Appendix A fixture set.

Two things carried forward that Stage 1 could not close:

- **Native batch outcomes are outside `analysis_status`.** `chunks_attempted`
  is 0 on a native run, so `chunks_failed == 0` there says nothing about native
  batch failures. That bookkeeping is Stage 2.1's subject.
- **The `adversary_path_projector` run-group ordering defect**, diagnosed in
  `2026-09-15-analysis-status.md`. Unrelated to this plan, still open.
