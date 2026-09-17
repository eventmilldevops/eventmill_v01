# Change Log — PDF page limits come from the provider, and truncation is visible

**Date:** 2026-09-14
**Branch:** `llm_5`
**Primary Files Modified:** `framework/llm/dispatcher.py`,
`plugins/log_analysis/threat_intel_ingester/tool.py`,
`plugins/log_analysis/threat_intel_ingester/schemas/{input,output}.schema.json`,
`plugins/log_analysis/threat_intel_ingester/examples/*.json`,
`tests/framework/test_llm_dispatcher.py`,
`plugins/log_analysis/threat_intel_ingester/tests/test_contract.py`, `AGENTS.md`

**1137 tests pass** (was 1121; +16). Two defects, found from one operator
report: a 150-page / 11 MB PDF stopped at exactly 50 pages.

---

## What the operator saw, and why the first diagnosis was wrong

The reasonable reading was that a provider limit had been hit and that Gemini
— 1000 pages, 50 MB — should have taken the document whole. It never reached
a provider limit. **50 was `threat_intel_ingester`'s own default**, and the
run stopped in local `pdfplumber` text extraction before any model was
consulted:

```python
max_pages = payload.get("max_pages", 50)   # tool.py
...
if i >= max_pages:                          # extract_pdf_page_texts
    break
```

Two separate page limits existed. Only one of them was the provider's, and it
was not the one that fired.

## Defect 1 — the ingester's own limit, and how it hid

`max_pages` truncated the page list, and everything downstream measured the
document from that list:

| | Value for a 150-page PDF |
|---|---|
| `page_count` (`len(page_texts)`) | 50 |
| `doc_profile.pages` (`profile.py:135`) | 50 |
| `[PLAN]` log line, `ingestion_plan` | built over 50 pages |
| reported `page_count` | 50 |

Nothing recorded 150 anywhere. **A 150-page report ingested as 50 pages was
byte-for-byte indistinguishable from a 50-page report ingested whole** — the
same output shape, the same numbers, no warning. For a triage tool that is the
worst available failure: the analyst is not told that two-thirds of the
document was never examined, so "no indicator found" reads as "no indicator
present".

### The sharp part: the two paths disagreed

`_batch_document` short-circuited a whole-document range to the original file:

```python
if rng.start == 1 and rng.end == doc_profile.pages:
    return artifact          # the original — all 150 pages
```

After truncation `doc_profile.pages` is 50, so a single-batch `native` plan
satisfied that test and **attached the full 150-page file** while the profile,
the plan and the output all said 50. Under `native_batched` the planner cut
real sub-PDFs, but only over pages 1–50, so 51–150 were genuinely dropped.
Same input, opposite behaviour, identical-looking output — decided by which
strategy the planner picked. Confirmed by reverting the fix: the test sees
`page_range: 'whole'` where it expects `[1, 5]`.

### Fixed

- **`max_pages` defaults to `None`** — read the whole document. The page limit
  belongs to the provider manifest, and a second one here could only ever cap
  a document the provider would have taken.
- **Ceiling raised 200 → 1000**, matching the largest cap any provider
  declares, so anything the guard could accept is now expressible.
- **`pdf_page_total()`** reads the real count when — and only when — a cap was
  set, because a capped read cannot see past its own cap. No extra file open
  in the default path, where pages read *are* the total.
- **`pages_total` and `pages_dropped` are always reported**, a `[TRUNCATED]`
  warning names the unexamined range, and `summarize_for_llm` leads with
  `INCOMPLETE COVERAGE: only N of M pages were read` — that last one matters
  most, being what downstream reasoning actually sees.
- **The short-circuit tests the file, not the profile** (`and not
  pages_dropped`), so a truncated read can never send pages the plan did not
  count.

An explicit `max_pages` is still honoured. It is a deliberate cost ceiling;
what changed is that it is now reported as a truncation rather than as the
document's size.

## Defect 2 — the guard read Gemini's limits for every provider

`_pdf_context_overflow` called `pdf_handling()` and `tokens_per_pdf_page()`
with no argument, so both resolved to `DEFAULT_PROVIDER_ID` — `gcp_gemini` —
whatever provider had been routed to:

| | Gemini | Anthropic / OpenAI |
|---|---|---|
| `max_pages` | 1000 | 100 |
| `max_size_mb` | 50 | 32 |
| tokens per page @ medium | 560 | 1500 |

So a 150-page PDF on Anthropic **passed** the guard (150 < 1000) and was then
rejected by the vendor partway through the call — precisely the opaque failure
the guard exists to replace. The cost estimate was also understated ~2.7x, and
mixed one vendor's per-page rate with another's context window, since
`_context_cap(client)` correctly reads the routed client.

`anthropic.json` had said so all along:

> Tightest PDF limits of the three providers, and the reason the dispatcher's
> PDF guard must read the ACTIVE provider's limits rather than Gemini's 1000
> pages / 50 MB.

### Fixed

`provider = _provider_of(client)` — which already existed at `dispatcher.py:56`
— now feeds `pdf_handling`, `default_media_resolution` and every
`tokens_per_pdf_page` call in the guard. Refusals name the provider, its limit,
and both ways out: run it on Gemini, or split the document.

`media_resolution` defaulting also **moved to after `_route`**. It was being
resolved from Gemini's manifest before the provider was known, which is the
same bug one call earlier.

## The behaviour that was chosen, deliberately

Per the operator: this is a triage tool and limits are acceptable — what is
not acceptable is a limit that is invisible.

- **Large documents go to Gemini.** 1000 pages / 50 MB.
- **Anthropic and OpenAI block above 100 pages / 32 MB**, up front, with the
  alternatives named.
- **No automatic re-routing.** The refusal says Gemini would take it; it does
  not switch providers, for the same reason cross-provider fallback is
  forbidden everywhere else — deliberate selection is the requirement.

## Not done

- **`openai.json`'s PDF limits are still placeholders**, flagged in its own
  `_note`, and no OpenAI document path exists yet. The 100/32 figures are
  Anthropic's copied across. The guard now reads them correctly; whether they
  are *right* is Stage 3's question.
- **A >1000-page document** cannot be read whole by anything. `max_pages`
  caps at 1000, the largest provider cap, so such a file must be split. The
  refusal says so.
- **`pdf_page_total` opens the file a second time** when a cap is set. Cheap,
  and only on the capped path.
