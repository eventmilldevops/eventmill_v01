# Change Log — Document profiler and page-range batched native ingestion

**Date:** 2026-09-05
**Primary Files:** `framework/documents/` (new: `profile.py`, `pdf_split.py`),
`plugins/log_analysis/threat_intel_ingester/tool.py`
**Supporting Files:** ingester `manifest.json`, `schemas/output.schema.json`,
`README.md`; `tests/framework/test_document_profile.py` (new); ingester
contract tests; `CLAUDE.md`

---

## Problem

A 15–20 page IOC-dense PDF could not complete: the single native call
exceeded the 120 s request deadline (504), the plugin budget (also 120 s)
expired at the same moment, and the chunked fallback then truncated at
MAX_TOKENS. Retests showed the cost scales with indicator density, not
page count (5 pages / 14 candidates ≈ 80 s on the heavy tier). Text
chunking was the only way to split work, and it loses page layout — the
reason native PDF ingestion was chosen in the first place.

## Design

### `framework/documents/profile.py`

- `profile_document(artifact_type, page_chars, page_candidates, max_output_tokens)`
  → `DocumentProfile`: pages, text size, candidates (total, per page, max on
  a page), estimated output tokens (`1500 + 70 × candidates`),
  `narrative` / `ioc_dense` (≥ 8 per page), `exceeds_single_call_output`.
- `LatencyModel(base_seconds=10, seconds_per_page=12, seconds_per_candidate=0.2)`
  — seconds a native call takes; calibrated on observed heavy-tier runs.
- `plan_ingestion(profile, native_available, max_output_tokens,
  call_deadline_s, latency)` → `IngestionPlan` with strategy `native`,
  `native_batched` or `chunked_text`. Batching is greedy on page
  boundaries: a batch closes when the next page would push it past 75 % of
  the output cap or 80 % of the deadline. A page that alone exceeds a cap
  becomes its own batch flagged `oversized`. The plan carries per-batch
  candidate counts, token and time estimates, a total, and a one-line
  `describe()` for logs.

Pure arithmetic; no LLM, no IOC regexes, no client.

### `framework/documents/pdf_split.py`

`split_pdf(path, ranges, out_dir, stem)` writes one sub-PDF per 1-based
inclusive page range with pypdf (already a declared dependency), clipping
ranges past the last page and raising `PdfSplitError` on bad input. Page
images and tables survive, so each batch still goes through the native
document path.

### `threat_intel_ingester`

- PDF text is now extracted per page (`extract_pdf_page_texts`) and regex
  candidates are counted per page; the profile and plan are built from
  those before any model call and logged as `[PROFILE]` / `[PLAN]`.
- `native_batched`: the PDF is split into the planned ranges under
  `workspace/artifacts/<id>_batches_*/` (removed on exit), and each batch
  is sent with only its own de-duplicated candidates and a
  "pages a–b of N" note in the prompt. Results are merged by the existing
  chunk-merge and reconcile code.
- A failed batch (deadline, parse error, exception) sends only its pages
  and candidates to the chunked text path; successful batches' native
  results are kept. If splitting itself fails, the whole document is sent
  in one call as before.
- Latency model overridable via `EVENTMILL_NATIVE_BASE_S`,
  `EVENTMILL_NATIVE_S_PER_PAGE`, `EVENTMILL_NATIVE_S_PER_CANDIDATE`.
- `summary.ingestion_plan` added to the result; `timeout_class` raised
  from `medium` (120 s) to `long` (600 s) so batched runs have a budget.
- The plugin's `_profile_document` is now a thin wrapper over the
  framework profiler; the by-type candidate breakdown stays plugin-side.

## Tests

`tests/framework/test_document_profile.py` (16): profile measurements and
classification; plan chooses `native` for small documents,
`chunked_text` without native support, `native_batched` with contiguous
ordered page ranges each under both caps for dense and for long-narrative
documents, oversized single pages flagged, custom latency model changes the
decision; `split_pdf` page counts, clipping, and errors on a generated
blank PDF.

Ingester contract tests (5): a 12-page dense PDF is split into the planned
ranges and every batch is sent natively with only its candidates and page
note, results merged, no text calls, temp files cleaned; a failed batch
falls back to chunked text for its pages only while other batches' results
are kept; a small PDF still makes one whole-document call without
splitting; a split failure degrades to one whole-document call; manifest
budget is `long`.

## Follow-ups

- Per-call deadline hint on `QueryHints` so the client's request timeout
  can be raised for single large batches instead of relying on the 120 s
  client default.
- `threat_report_analyzer` uses page chunks through text extraction; it
  can adopt `plan_ingestion` + `split_pdf` to keep native ingestion on
  long reports.
- A `document_profiler` tool that prints the plan without running it.
