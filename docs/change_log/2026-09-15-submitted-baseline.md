# Change Log — the reconciliation is measured against what was submitted

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md` **Stage 2.0**
**Scope:** `plugins/log_analysis/threat_intel_ingester/` (`ti`)
**Status:** implemented. **Changes no output on any run today** — read the next
section before deciding whether that was worth doing.

---

## The defect this step was written against does not exist

Stage 2.0 was added during the pre-flight review of Stage 2, on the following
reasoning: `raw_text` is `"\n\n".join(page_texts)` while `_page_iocs` runs the
regex per page, so the per-page candidate union should be a strict *subset* of
`raw_iocs` — a value straddling a page join would live in `raw_iocs` and in no
page, never be submitted to a model, and then be reported as
`candidates_unassessed`, which blames the model for our own coverage gap.

**Checked against the patterns instead of reasoned about, and it is not
reachable.** Every entry in `IOC_PATTERNS` is contiguous over non-whitespace,
so none can match across the join. Eight split fixtures — ip mid-octet, ip at a
dot, domain, sha256, url, cve, an empty page between two, and a clean pair —
all give `raw_keys - page_union == {}`.

The batching closes the other half of it. `plan_ingestion`
(`framework/documents/profile.py`) walks the pages contiguously and every page
lands in exactly one batch, while a batch that fails for *any* reason adds its
pages to `failed_pages`:

| Failure | Where |
|---|---|
| the page-range PDF could not be written | `ti:1807` |
| the call raised | `ti:1883` |
| truncated and unsplittable | `ti:1982` |
| the call budget ran out with batches pending | the `pending` drain |

and the chunked path then submits those pages' candidates from
`fallback_iocs`. So **no path leaves a candidate unsubmitted**, and the two
baselines are equivalent on every run.

I wrote the step on a plausible-sounding inference and did not test it first.
Recording that here rather than quietly deleting the step, because the same
inference will look reasonable again.

## What was kept, and why it is not just tidying

The code landed anyway, rescoped from a fix to a guard.

**1. The field now means what it says by construction.** The equivalence above
is a property of today's batching, not of `candidates_unassessed`'s definition.
Measuring against `raw_iocs` is correct by coincidence.

**2. Stage 2.5 rewrites prompt assembly into page units.** That is precisely
the change that could drop a candidate between extraction and batching, and
under the old baseline the drop would be reported as the model's silence. The
last test class in `test_submitted_reconciliation.py` asserts
`candidates_not_submitted == 0` across four run shapes — whole-document native,
page-batched native, native-with-partial-fallback, and pure chunked — so if 2.5
breaks page coverage, those four fail rather than the field quietly lying.

**3. Stage 2.1 needed one baseline to hold still.** 2.1 stops superseded
results from supplying canonical values, which moves the *verdict* side of the
reconciliation. Making the submitted side explicit first means that change
moves one baseline instead of two.

## What changed

- `_record_submitted()` records every candidate placed into a prompt, native
  (`ti:1826-1835`) and chunked (`ti:2059-2067`) alike, lowercased value to the
  value as extracted. `mitre_technique` matches are skipped, for the same
  reason the reconciliation already excluded them: they are asked for as
  techniques rather than indicators, so their absence from `refined_iocs` is
  correct rather than a gap.
- `candidates_unassessed` is now the submitted set minus the values that came
  back with a verdict.
- New `candidates_not_submitted`: what `raw_iocs` holds and no prompt carried.
- `_analysis_fields` gained a note, placed **before** the unassessed one:
  `CANDIDATES NOT SUBMITTED: N indicator candidate(s) found by the regex
  pre-scan were never placed in a prompt, so no model was asked about them`.
  Non-zero makes the run `partial`.

**Two counters rather than one**, which was the operator's call and is the
right one: "the model was asked and stayed silent" and "we never asked" have
different causes and different fixes, and one counter cannot say which
happened. It is the same distinction Stage 1.5 drew between rejecting three of
three and rejecting three of forty.

## Verified

- Full suite: **1332 passed** at this step (baseline 1319; 13 new tests).
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.
- **Mutation-checked.** Three mutations, each caught:

  | Mutation | Tests that failed |
  |---|---|
  | reconciliation reverted to the `raw_iocs` baseline | 1 |
  | the `CANDIDATES NOT SUBMITTED` note removed | 5 |
  | native-path recording removed | 4 |

- The case that *would* be a defect is exercised directly: `_page_iocs` is
  patched to drop one candidate on a batched native run, and the run reports
  `candidates_not_submitted == 1` with `candidates_unassessed == 0`. That test
  is only expressible on the batched native path — a whole-document batch is
  handed `raw_iocs` and the chunked path takes `fallback_iocs` from `raw_iocs`,
  so neither reads `page_iocs`.

## Not verified

- No live model requests. Every conclusion is about control flow.
- The invariant is asserted on four synthetic run shapes, not on a real
  document. A 154-page live run is budgeted once for the whole of Stage 2.

## A note on method

The first attempt at this step's test passed on the fix and also passed on the
defect, because it patched the wrong extraction pass. That is what the mutation
check is for, and it is worth more than the test count: a test that cannot fail
is a claim, not a check.
