# Change Log — Ingester pre-flight profile, phase timings, duplicate artifact listing

**Date:** 2026-09-04
**Primary File Modified:** `plugins/log_analysis/threat_intel_ingester/tool.py`
**Supporting Files:** `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json`,
`plugins/log_analysis/threat_intel_ingester/README.md`, `framework/cli/shell.py`,
tests in both

---

## Background

A 15–20 page IOC-dense PDF timed out: the native PDF call hit the
120-second request deadline (504 DEADLINE_EXCEEDED), the plugin budget
(also 120 s) expired at the same moment, and the chunked fallback then hit
MAX_TOKENS on its densest chunk. Retesting with `--max_pages 5` (about 80 s
for 14 IOCs) and with a larger narrative PDF (completed) confirmed that the
cost scales with candidate density, not page count. The logs did not make
that visible: no timings, no candidate density, and the truncated-JSON
repair logged at INFO.

## Changes

### Pre-flight document profile (`_profile_document`)

Computed from the extracted text and the regex pre-scan before any LLM
call: pages, text size, candidate counts (total, by type, per page, max on
a page), an output-token estimate (`1500 + 70 × candidates`) and a
`narrative` / `ioc_dense` classification (≥ 8 candidates per page). Logged
as `[PROFILE]`, with a warning for dense documents, and stored in
`summary.document_profile`. This is the deterministic basis for choosing how
a document should be processed.

### Phase timings

`[NATIVE] start` / `[NATIVE] done` (elapsed, model, transport, response
size, token usage; on a 504 the deadline and observed seconds-per-page),
`[CHUNK] n/N done` per fallback call, a loop total with failure counts, and
a final `[TIMING]` line with `extract_s`, `native_s`, `chunks_s`,
`reconcile_s`, `total_s`. Stored in `summary.timings`.

### Truncated replies are a warning

`[TRUNCATED]` now logs at WARNING with the number of records recovered and
a note that anything after the cut is lost.

### Shell: duplicate output artifact

`threat_intel_ingester` registers its JSON through
`context.register_artifact` and also declares it in `output_artifacts`; the
shell registered it a second time, so "Output files" listed the same file
under two IDs. The shell now skips output artifacts whose path was already
registered during the run.

## Tests

Profile classification for narrative, dense, non-PDF and empty inputs;
repair outcome logged at WARNING with counts; a regex-only ingester run
through the shell registers exactly one output artifact.
