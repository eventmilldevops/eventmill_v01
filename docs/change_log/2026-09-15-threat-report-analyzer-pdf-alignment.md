# Change Log — threat_report_analyzer: provider limits, refusals, coverage, stamped exports

**Date:** 2026-09-15
**Branch:** `llm_5`
**Primary Files Modified:**
`plugins/threat_modeling/threat_report_analyzer/tool.py`,
`plugins/threat_modeling/threat_report_analyzer/schemas/output.schema.json`,
`plugins/threat_modeling/threat_report_analyzer/tests/test_contract.py` (new)

**1177 tests pass** (was 1159; +18 — this plugin had **no tests at all** before).

Prompted by a review asking whether `threat_report_analyzer` shares
`threat_intel_ingester`'s PDF handling. It does not, and four of the
differences were defects.

---

## The two plugins do not share PDF handling, and still don't

`threat_intel_ingester` is the only plugin that imports `framework/documents/`.
The difference is deliberate in places and accidental in others:

| | `threat_intel_ingester` | `threat_report_analyzer` |
|---|---|---|
| Text library | `pdfplumber` | `pypdf` |
| Batching | `profile_document` + `plan_ingestion`, candidate-density driven | own `_split_pdf_into_chunks`, fixed 100-page ranges |
| What the model sees | **real sub-PDFs** cut by `split_pdf()` — page images, layout | **extracted text** |
| Native strategies | `native` / `native_batched` / `chunked` | one whole-file attempt, else text |
| Truncated reply | halve the range, retry | none |

Both call `context.llm_query.query_with_document`, so both get the
provider-aware PDF guard fixed on 2026-09-14. The guard can size this
plugin's request: it passes a local `file_path`, and `_pdf_page_count` falls
back to `pypdf` when metadata carries no `pages` key — which this plugin's
`ArtifactRef` does not set.

**Not unified here.** Sharing `framework/documents/` would be a large change
to a working tool, and the two have different jobs — per-page IOC extraction
against whole-report summarisation. The gap that remains is item 4 below.

## Fix 1 — the plugin restated provider limits, in Gemini's numbers

`MAX_PDF_SIZE_BYTES = 50 * 1024 * 1024` and `MAX_PDF_PAGES = 1000` were
Gemini's figures living in plugin code, applied whichever provider was routed
to. Anthropic and OpenAI accept 100 pages / 32 MB, so they were wrong for two
of three vendors, and the rejection message said *"PDF exceeds 50 MB limit"*
regardless of provider.

CLAUDE.md is explicit that `framework/llm/providers/<id>.json` is the single
source of truth per vendor and that these must not be hardcoded elsewhere.

**The fix is not to read the manifest here.** A plugin cannot reliably know
its provider — `TierScopedLLMClient.default_provider` is `None` whenever no
`use` override is set, and falling back to a guess is exactly how Gemini's
numbers got written down in the first place. The dispatcher's guard is the
only place that knows, because it runs after routing.

So the plugin stops deciding provider policy. What is left is an honest local
resource ceiling on what this process will read off disk with pypdf —
`MAX_LOCAL_PDF_BYTES` (200 MB) and `MAX_LOCAL_PDF_PAGES` (2000), deliberately
well above any vendor's limit so they cannot be mistaken for one, with a
message that quotes no vendor figure.

## Fix 2 — a provider's refusal was swallowed into a silent downgrade

This is the sharp one, and it contradicted the policy set for the ingester:
*limits are acceptable, the choice is Gemini or split*.

After the 2026-09-14 guard fix, a 150-page report on Anthropic fails the
native call with `fallback_reason="pdf_exceeds_provider_page_limit"`. The
plugin logged a warning and **fell through to the pypdf text path** — so the
operator got a successful-looking summary built from markedly worse input,
with the reason visible only in logs. The guard's "run it on Gemini or split
the document" message reached nobody.

Refusals are now split by kind, because the kind decides whether degrading is
reasonable:

- **`PROVIDER_LIMIT_REFUSALS`** — `pdf_exceeds_provider_page_limit`,
  `pdf_exceeds_provider_size_limit`, `pdf_exceeds_context_at_resolution`,
  `pdf_exceeds_context_at_all_resolutions`. The provider will not take this
  document. That is a decision for the operator, so the tool returns
  `ARTIFACT_TOO_LARGE` carrying the guard's own message plus both ways out.
- **Everything else** — transport failures, model errors, exceptions — still
  degrade to the text path, which is the right behaviour for a condition
  nobody chose.

## Fix 3 — page coverage never reached the output

`total_pages = min(len(reader.pages), MAX_PDF_PAGES)` truncated the read. Both
numbers were logged, but at INFO, and nothing propagated: the output schema
had no page fields and `summarize_for_llm` reported only `chunk_count`. Same
class as the ingester's 50-page defect, at a much higher ceiling.

Now `pages_total`, `pages_read` and `pages_dropped` are reported, the
truncation log is a WARNING naming the unexamined range, and
`summarize_for_llm` leads with `INCOMPLETE COVERAGE: only N of M pages were
read` — a topic's absence from a partial summary is not evidence of its
absence from the report.

**Coverage fields are omitted, not zeroed, when native ingestion succeeds.**
Nothing counted the pages on that path: the provider accepted the whole
document, so coverage is total by construction, and reporting a page count
the plugin never counted would be a worse answer than none.

## Fix 4 — exports are stamped, so re-runs no longer overwrite

Every run wrote `{source}.summary.md` to the same object in the shared common
bucket, so summarising one report twice destroyed the first result. Storage is
cheap and a replaced summary cannot be compared against what replaced it.

Exports are now `{source}.{YYYYMMDDTHHMMSSZ}.summary.md`:

```
generated/threat_report_analyzer/vendor_advisories/
    Anthropic-Detecting-and-countering-091026.pdf.20260915T031500Z.summary.md
```

Three details that matter:

- **The stamp goes before the suffix**, so anything globbing `*.summary.md`
  keeps matching — the convention this directory documents.
- **Basic ISO 8601 UTC**, which sorts lexicographically in the order it sorts
  chronologically. That is what a bucket listing gives you.
- **One stamp per run**, threaded into `_write_chunk_artifact` rather than
  regenerated there, so a run's summary and its chunk summaries group
  together instead of straddling a second boundary.

`_summary_output_path` answered "has this been summarised?" by testing for an
exact path, which a stamped name cannot do. It now returns the **newest**
`{source}.*.summary.md`, excluding chunk summaries (they share the prefix),
and still falls back to an unstamped `{source}.summary.md` so summaries
already in the bucket do not become invisible.

## Tests

The plugin had **no test directory**. Added 18 covering exactly the above:
that the provider-shaped constants are gone and the manifests hold those
numbers instead; that a policy refusal blocks while a transport failure does
not; that coverage is reported, omitted when unmeasured, and surfaced in the
LLM summary; and that two runs produce two objects, chunks share the run's
stamp, and discovery finds both stamped and pre-stamp summaries.

## Not done

- **Native page-range batching** (item 4 of the review). One whole-document
  native call, then straight to text — the ingester's middle ground does not
  exist here, so a report too large for a single native call loses native
  fidelity entirely rather than being split into native page ranges. This is
  the real quality gap: `_normalize_pdf_text` exists because pypdf's
  `extract_text()` mangles multi-column layouts, so the fallback is
  known-lossy for a tool whose job is reading reports full of diagrams and
  tables.
- **Sharing `framework/documents/`**, for the reason given above.
