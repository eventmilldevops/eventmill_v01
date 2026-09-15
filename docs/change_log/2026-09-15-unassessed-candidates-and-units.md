# Change Log — unassessed candidates, coverage units, and native page counts

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** follow-up to `docs/specs/report_processing_integrity.md` Stage 1 —
three defects found by running the tools, not by reading them.
**Scope:** `plugins/log_analysis/threat_intel_ingester/` (`ti`) and
`plugins/threat_modeling/threat_report_analyzer/` (`tra`).
**Status:** implemented.

---

## How these were found

A live run against Anthropic's *Detecting and countering misuse of AI*
(154 pages) was accidentally pointed at the **analyzer's own summary** rather
than the source PDF. The ingester reported:

```
NO INDICATORS ACCEPTED: all 3 candidate(s) were assessed as false positives
Extracted 0 IOCs
"coverage": { "pages_total": 114, "pages_read": 114 }
"analysis_status": "complete"
```

The re-run against the actual PDF produced **147 IOCs** (74 domains, 55 IPs,
7 CVEs, 2 SHA256) across 154 pages, so the zero was entirely the input
artifact. But three things in that first output were wrong independently of the
operator error, and all three are Goal A failures — work reported as more
complete than it was.

## Defect 1 — the rejection note overclaimed

`candidates_rejected = len(all_refined) - len(non_fp)` counts verdicts the
model **returned**. The note then said *"all 3 candidate(s) were assessed"*.

Nothing reconciled that against what the model was **given**. The regex pass
over that summary produced far more than three candidates — `mitre_technique`
is in the default `ioc_types` and the summary carries 24 technique IDs, plus
the domains. So the model answered about three and said nothing about the
rest, and the run called itself `complete`.

**Rejecting three of three is an assessment. Rejecting three of forty is not,
and the two reported identically.**

Now reconciled by value, excluding `mitre_technique` matches — those are
requested as techniques rather than indicators, so their absence from
`refined_iocs` is correct rather than a gap. Comparison is on value alone,
because the model relabels `ioc_type` freely and a type disagreement is not a
missing verdict.

- New `candidates_unassessed` on the result and the persisted artifact.
- Non-zero makes the run **partial**, with `UNASSESSED CANDIDATES: N indicator
  candidate(s) received no verdict from the model, so they are neither accepted
  nor ruled out`.
- The rejection note now says *"the model assessed N candidate(s)"* rather than
  *"all N"*, which is what it was actually counting all along.

This defect was introduced by Stage 1.5, in the change that was otherwise
correct. It is the external review's "unresolved-candidate reporting" finding,
arriving by a different route.

## Defect 2 — coverage counted lines and called them pages

`page_count` is a line count for any non-PDF artifact —
`summarize_for_llm` already knew this (`size_label = "pages" if artifact_type
== "pdf_report" else "lines"`) — but the coverage fields hardcoded "pages".

In the `ToolResult` that was survivable, because `artifact_type` sits nearby.
In the artifact persisted by Stage 1.6 it was not: `report_metadata` there
carries only title, campaign and actor, so `"pages_total": 114` reads as a
114-page document with nothing to contradict it. That is precisely how a
summary gets mistaken for the report it summarises.

Keys stay `pages_total` / `pages_read` / `pages_dropped` so existing consumers
keep working; a new `unit` (persisted) / `coverage_unit` (result) says what
they count, and the `INCOMPLETE COVERAGE` note now names the unit.

## Defect 3 — the analyzer's export never stated the page count

Reported from the live run: the provenance block Stage 1.6 added carries the
model and timestamp but no pages.

Cause: the block emits page figures only `if coverage:`, and
`_coverage_fields()` is deliberately empty on a native run — no per-page
extraction ran, and Stage 1.7's reasoning was that inventing per-page outcomes
would be worse than silence. That reasoning still holds for *outcomes*. It does
not hold for the **size of the document**, which is knowable and which a reader
needs: without it the export cannot distinguish a 9-page advisory from a
154-page report.

`_pdf_page_count()` now counts the page tree when the PDF is resolved — cheap,
and extracts no text — and a native run's block reads:

```
> **Pages:** 154 of 154, read natively as a whole document (no text extraction)
```

Worded differently from the extracted case on purpose: it is a different
measurement, and it deliberately claims nothing about blank or unreadable
pages, because nothing measured those. The extracted path still wins when it
has real per-page counts, and an unreadable PDF reports no count rather than a
wrong one.

## The new check caught a real gap immediately

Three Stage 1.5 tests began failing the moment the reconciliation landed. Their
stub answered about one of the three candidates in the fixture report, so
`partial` is the correct status and their `complete` assertion had been wrong
since I wrote it. The fixtures now answer about every candidate, which is what
those tests meant to exercise.

That is the check working before it ever reached a real report.

## Verified

- Full suite: **1319 passed** (baseline 1308; 11 new tests).
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.
- Live confirmation of the diagnosis: the same report ingested as a PDF yields
  147 IOCs over 154 pages, `analysis_status: complete`.

## Not verified

- The reconciliation compares **values**, so a model that returns a verdict
  under a reformatted value (refanged differently, or with whitespace) will
  read as unassessed. Raw candidates are stored refanged and both sides are
  lowercased and stripped, which covers the cases seen; a systematic mismatch
  would show up as an implausibly high `candidates_unassessed` rather than
  silently.
- `ruff` and `black` are still not installed in the active interpreter.

## Calibration data point for Stage 3.1

The 154-page native run planned **16 batches, est. 2105s**, and completed in
**~260s** — 8.1x pessimistic, against the ~6.3x already recorded. Worth
capturing before the recalibration in Stage 3.1, which must not be attempted
until the Appendix A fixtures exist. The estimate also exceeded the 600s plugin
timeout, so a document only slightly larger would be refused work it can
comfortably do.
