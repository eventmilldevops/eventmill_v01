# Plan — report processing integrity

**Date:** 2026-09-15
**Status:** **Stage 1 is COMPLETE** (1.1-1.7), 2026-09-15. Change logs:
`2026-09-15-analyzer-output-budgets.md`,
`2026-09-15-truncation-is-recorded.md`,
`2026-09-15-section-status-and-substitution.md`,
`2026-09-15-analysis-status.md`,
`2026-09-15-chunk-failures-and-rejection.md`,
`2026-09-15-persisted-provenance-and-page-outcomes.md`,
`2026-09-15-unassessed-candidates-and-units.md` (post-Stage-1 repairs
found by running the tools).
**Stage 2 is IN PROGRESS.** 2.0 and 2.1+2.2 landed 2026-09-15 — change logs
`2026-09-15-submitted-baseline.md`,
`2026-09-15-retry-supersedes-partial.md`, and the live runs in
`2026-09-15-stage-2-live-runs.md`, which found and fixed two further defects in
that code. **2.3, 2.4, 2.5 and 2.6 are outstanding.** Stages 3 and 4 are still
proposed, nothing built.

**Live-run status:** the three landed steps ran against a real provider
(`gcp_gemini` light) across five shapes, and supersession fired by both routes
on real traffic. Two limits remain before Stage 2 can be called signed off: the
154-page report named in the acceptance has not been run, and only one of the
three keyed providers was exercised.

Stage 2's pre-flight review on 2026-09-15 added two steps and re-derived every
line number: **2.0** (measure the reconciliation against what was submitted —
a no-op today, kept as 2.5's tripwire, because the defect it was first written
against turned out to be unreachable, which the step records) and **2.6** (the
analyzer's silent caps). The three operator decisions it settled are recorded
in the step text.

Full suite **1380 passing** — 1177 before Stage 1, 1319 after it, 1380 with
Stage 2 so far. Committed on `llm_5` at `a83e74e` (1.1), `2d7eec2` (1.2-1.7)
and `2efb594` (the post-Stage-1 repairs); Stage 2's work is uncommitted at the
time of writing.
**Parent review:** `docs/change_log/2026-09-15-chunking-integrity-review.md` —
the eight findings, their verification, and the four corrections to the
external analysis are settled there and are not restated.
**Tree this plan was written against:** `e1dda3a` plus the uncommitted
`threat_report_analyzer` changes.

Scope: `plugins/log_analysis/threat_intel_ingester/tool.py` (`ti`),
`plugins/threat_modeling/threat_report_analyzer/tool.py` (`tra`),
`framework/documents/profile.py` (`profile`).

---

## The goal, stated so it can be failed

"Establish that all relevant report context survived processing" is not
achievable and must not be the goal — it makes every change unfalsifiable.
Three separable goals replace it, in the order they can be tested:

| Goal | Testable how | Stage |
|---|---|---|
| **A.** Incomplete work is never reported as complete | Synthetic responses, no model | 1 |
| **B.** Evidence the model produced is never destroyed deterministically | Synthetic responses, no model | 2 |
| **C.** Meaning is more likely to survive a chunk boundary | Analyst-labeled fixtures only | 3 |

A and B are defects with deterministic repros. C is an improvement in odds and
cannot be measured without the fixture set in **Appendix A**. Building C before
the fixtures exist means shipping a change nobody can evaluate, which is why it
is gated rather than sequenced.

## What is already in the tree and simply not used

Three mechanisms exist, are correct, and are consumed by one plugin but not the
other. Most of Stage 1 is applying them, not designing them.

| Mechanism | Defined at | Consumed by | Not consumed by |
|---|---|---|---|
| `LLMResponse.truncated` | `framework/plugins/protocol.py:83`, populated `gemini.py:467,620`, `anthropic.py:429`, `openai.py:434` | `ti:1797` (native path only) | `tra` entirely; `ti` text path |
| `_parse_llm_json_result` repair flag | `ti:538` | `ti:1798` | `ti:2011` (calls the flag-discarding wrapper `_parse_llm_json`, `ti:532`) |
| `thinking_reserve_tokens()` | `framework/llm/providers/__init__.py:261` | `ti:36`, `ti:369` | `tra` — imports neither it nor `max_output_tokens_for_tier` |

The reference pattern for the first two is `ti:1797-1799`:

```python
truncated = bool(native_response.truncated)
if native_response.ok and native_response.text:
    parsed, repaired = _parse_llm_json_result(native_response.text)
    truncated = truncated or repaired
```

Both signals are needed. `LLMResponse.truncated` is the transport's finish
reason; `repaired` catches a reply that parsed only after unmatched brackets
were closed. Neither subsumes the other.

## The finding that reorders the work

Not in the external review, and it changes which step goes first.

`framework/llm/providers/gcp_gemini.json` declares, under `output_budget`:

```json
"thinking_reserve_tokens": {
  "minimal": 1024, "low": 4096, "medium": 16384, "high": 32768
}
```

with the note that Gemini 3.x spends thinking tokens from the same budget as
the reply, so `max_output_tokens` is not all available for content.

**All three of the analyzer's LLM calls are sized below the reserve for the
thinking level they actually request:**

| Call | `tra` line | Thinking level | Reserve (gcp_gemini) | Budget passed | Content headroom |
|---|---|---|---|---|---|
| Native whole-PDF | `tra:441` | provider default `medium` (no level, no `needs_reasoning`) | 16,384 | `max(2048, min(8192, max_words × 8))` → **≤ 8,192** | **negative** |
| Section summary | `tra:1075` | explicit `low` | 4,096 | **3,072** | **negative** |
| Synthesis | `tra:1144` | none given, but `needs_reasoning=True` promotes to `high` at `gemini.py:71-72` | 32,768 | **4,096** | **negative** |

The tier cap is 65,536 output tokens on both Gemini tiers, so none of these
numbers is near a provider limit — they are arbitrary constants.

Stated precisely: the reserve is a **ceiling, not a charge**
(`providers/__init__.py:318-329`), so these calls do not fail every time. They
fail whenever thinking actually spends near the reserve, and that spend is not
deterministic between identical calls — the behaviour already recorded for
liveness pings, where the same model returned empty text on one run and text on
the next at the same cap.

This is the mechanical cause of the compound failure recorded in the parent
review: a starved section call returns `ok=True` with empty text, which becomes
`summary_text = ""`, which is persisted to a file named `.summary.md` and fed
to synthesis as though it were a section summary.

**Consequence for this plan:** step 1.1 is budget sizing, not truncation
marking. Marking a truncation that a correct budget would have avoided fixes
the report and leaves the cause. Do 1.1 first, then 1.2–1.4 catch what remains.

---

# Stage 1 — incomplete work is never reported as complete

**Goal A.** No schema breaks; every schema change is additive. Every step is
testable with synthetic `LLMResponse` objects and no network.

**Estimated size:** one change set, ~1 day. **This is the recommended next
piece of work, and the recommended stopping point before reassessing.**

**Progress:** all of Stage 1 done. **This is the recommended stopping
point before reassessing.**

### 1.1 — Size every analyzer LLM budget from the provider's declared reserve

**Status: DONE, 2026-09-15.** Landed as written except for step 4's native
level — see "Correction found in implementation" below. Full record in
`docs/change_log/2026-09-15-analyzer-output-budgets.md`.

**Where:** `tra:441` (native), `tra:1075` (section), `tra:1144` (synthesis).
**Currently:** three bare integer constants, no reserve subtracted, no import
of the budget helpers.

**Change:**
1. Add to `tra` imports: `from framework.llm.providers import
   max_output_tokens_for_tier, thinking_reserve_tokens`.
2. Add a module-level helper mirroring `ti:360-372`:

   ```python
   def _budget(tier: str, thinking_level: str, content_tokens: int) -> int:
       """Output budget that leaves room for both thinking and content.

       Gemini spends thinking from the reply budget, so a bare content
       figure is silently a thinking cap. Ask for the content plus the
       reserve the provider declares for the level actually requested,
       bounded by the tier cap.
       """
       cap = max_output_tokens_for_tier(tier)
       return min(cap, content_tokens + thinking_reserve_tokens(thinking_level))
   ```
3. Pass an **explicit** `thinking_level` on all three calls so the budget and
   the level cannot drift apart. In particular replace the bare
   `needs_reasoning=True` at `tra:1146` with an explicit level, because
   `gemini.py:71-72` silently promotes it to `high` and that promotion is
   invisible at the call site.
4. Apply: native `_budget("heavy", "medium", max_words * 8)`; section
   `_budget("light", "low", 3072)`; synthesis
   `_budget("heavy", "high", max_words * 8)`.

**Why:** the plugin must not restate provider figures — `CLAUDE.md` is explicit
that `framework/llm/providers/<id>.json` is the single source of truth. The
helper reads it rather than copying it, which is the same reason the ingester
calls it at `ti:369`.

**Do not:** hardcode 4096/16384/32768 in the plugin. That reintroduces exactly
the defect fixed on 2026-09-15 for PDF page limits.

**Test:** with a stub provider manifest, assert each call site requests at
least `content + reserve(level)` and never more than the tier cap; assert the
plugin declares an explicit `thinking_level` on every `QueryHints` it builds.

**Done when:** no analyzer call passes a `max_tokens` smaller than
`thinking_reserve_tokens()` for its own thinking level.

**Met.** Budgets now run 7,168-48,768 against a 65,536 tier cap; every one was
previously below the reserve for its own level. 14 tests in
`plugins/threat_modeling/threat_report_analyzer/tests/test_output_budget.py`;
full suite 1191 passing, up from the 1177 baseline. Mutation-checked: 7 of the
14 fail when the change is reverted.

#### Correction found in implementation

Two things in this step were wrong as written.

**There are four call sites, not three.** The single-pass branch of
`_summarize_chunk` carries its own copy of the same
`max(2048, min(8192, max_words * 8))` constant. It is now
`_budget("light", "low", max_words * 8)`.

**Step 4's native `"medium"` is `gcp_gemini`'s default applied to every
vendor.** The step justified it as preserving today's behaviour, but the
manifests disagree: `gcp_gemini`, `openai` and both daybreak ids declare
`medium`, and `anthropic` declares **`high`**. `anthropic.py:71-75` sends no
effort control when `thinking_level` is `None` and `needs_reasoning` is
`False`, so Anthropic's own default applies today. Pinning `"medium"` would
have silently demoted the native pass whenever the operator routed this plugin
to Anthropic — one vendor's figure applied to all of them, which is the defect
class this step's own **Do not** warns against.

The plugin cannot fix this by reading the routed provider: `shell.py:2982-2984`
makes the wrapper "the one place a plugin cannot reach either of them", and
`QueryHints` must not carry a provider. The plugin owns reasoning depth, the
operator owns the vendor, so the level is pinned and vendor-independent, with a
deployment override in the shape of `EVENTMILL_PROJECTION_THINKING`:

```
EVENTMILL_REPORT_NATIVE_THINKING=low|medium|high   # default: medium
```

resolved once per call into a local that feeds both the budget and the hint, so
they cannot drift. Only those three levels are offered — `minimal` is declared
solely by `gcp_gemini` and is a 400 on `gemini-3.8-flash` and both `gpt-5.6`
models.

**Carry this forward:** any later step that pins a `thinking_level`,
`media_resolution` or token figure must check it against every provider
manifest, not just the default one. Stage 3.1's recalibration and Stage 3.6's
retry budgets are both exposed to this.

### 1.2 — Read `truncated` at the four call sites that ignore it

**Status: DONE, 2026-09-15.** Landed as written. Full record in
`docs/change_log/2026-09-15-truncation-is-recorded.md`. Line numbers below are
as the plan was written; the sites are now `tra:511` (native), `tra:1151`
(section), `tra:1207` (synthesis) and `ti:2011` (text path, unmoved).

**Recorded where:** `tra` gains per-run `_truncations` plus `truncated` /
`truncation_notes` on the result (mirroring `_coverage_fields()`); `ti` gains
`truncated` / `truncated_chunks` carrying the affected 1-based chunk indices.
Both state it in `summarize_for_llm`. These are shaped so **1.4 can absorb them
into `analysis_status` / `analysis_notes` without a schema break** — 1.2's test
criterion refers to a status field that 1.4 introduces, so until then these
fields are the record.

**Amended 2026-09-15 by a live run.** The rejection note counted verdicts
the model *returned* and called them "all candidates", with nothing reconciling
that against what it was *given*. Rejecting three of three is an assessment;
rejecting three of forty is not, and both reported `complete`.
`candidates_unassessed` now closes it — see
`docs/change_log/2026-09-15-unassessed-candidates-and-units.md`. **Stage 2 work
on the merge must keep this reconciliation intact**, since 2.2's occurrence
records change what "returned a verdict" means.

**Note for 1.4:** `_parse_llm_json` (`ti:532`) still exists and still discards
the repair flag; it is retained only because `test_contract.py:1302` exercises
the repair logging through it. A test now asserts no production call site below
its definition calls it.

**Where:** `tra:457` (native), `tra:1098` (section), `tra:1154` (synthesis),
`ti:2011` (text path).

**Change:** apply the `ti:1797-1799` pattern at each.
- `tra`: `truncated = bool(response.truncated)`; keep the text (it is the best
  available answer) but record the truncation rather than discarding the fact.
- `ti:2011`: call `_parse_llm_json_result` instead of `_parse_llm_json` and OR
  the `repaired` flag with `llm_response.truncated`, exactly as the native path
  does. Record the affected chunk index.

**Why:** the signal is already plumbed to the plugin. Ignoring it is what lets
a three-word reply be reported as a complete summary.

**Do not:** convert a truncated reply into a failure. Truncated content is
usually better than the alternative; the defect is the silence, not the
content. Recovery (retry at a larger budget, or bisect) is **Stage 3**.

**Test:** an `LLMResponse(ok=True, text="short", truncated=True)` must not
produce a result whose status is `complete`.

### 1.3 — Stop substituting raw text for a summary without saying so

**Status: DONE, 2026-09-15.** Landed as written, including open decision 3
(failed-section chunk artifacts **are** written, with a failure header). Full
record in `docs/change_log/2026-09-15-section-status-and-substitution.md`.

**One distinction the step did not draw:** a `partial` section — real analysis
cut off at the output cap — is **not** a degradation. It is reported through
1.2's truncation fields instead. Folding truncation into `degraded` would make
that field fire so often it would stop carrying information. 1.4 must keep the
two separable when it maps them onto `analysis_status`: truncation alone is
`partial`, a substitution or a failed synthesis is `degraded`.

**Inputs now ready for 1.4:** `truncated` / `truncation_notes` and `degraded` /
`degradation_notes` on the analyzer; `truncated` / `truncated_chunks` on the
ingester. The ingester has no degradation record yet — its equivalent is the
regex-baseline fallback, which is step 1.5.

**Where:** `tra:1076` (`summary_text = chunk.content[:3000]`), `tra:1098`,
`tra:1157` (`return combined`).

**Change:**
1. Initialise `summary_text = None` and `status = "failed"`. Set both together
   only on a genuine reply. An `ok=True` reply whose stripped text is **empty**
   is `status = "empty"`, not `"complete"` — this is the budget-starvation
   outcome from 1.1 and it must be distinguishable.
2. Every chunk summary dict carries `status:
   complete | partial | empty | failed`.
3. Where the excerpt is still worth keeping, keep it in a **separate key**
   (`raw_excerpt`), never in `summary`.
4. In `_synthesize_summaries`, label non-`complete` blocks in the prompt
   explicitly, e.g. `[Pages 40-60 — SECTION SUMMARY FAILED; raw extracted text
   follows, treat as unsummarised source]`.
5. On synthesis failure (`tra:1157`), still return `combined`, but have the
   caller mark the run `degraded` — see 1.4.

**Why:** the parent review's compound failure. A file named `.summary.md` that
contains raw pypdf text, and a synthesis prompt that cannot tell that block
from a summary, are the two halves of one defect.

**Test:** a failing section call must produce a chunk dict whose `summary` is
`None` and whose `status` is `failed`; the synthesis prompt built from it must
contain the failure label; the run's status must not be `complete`.

### 1.4 — Add `analysis_status` to both plugins' outputs

**Status: DONE, 2026-09-15.** Landed as written. Full record in
`docs/change_log/2026-09-15-analysis-status.md`.

**One input the step assumed existed but did not:** `tra` never recorded the
native → pypdf text fallback, which this step names as a degradation. It is
recorded now, distinguishing "the native attempt did not succeed" from "native
ingestion was unavailable".

**Trailing warnings were removed, not kept.** Each cause is a note now, and the
status leads; `ti`'s separate "WARNING: LLM analysis failed — results are
regex-only" block was the same fact said twice and was folded into the note.

**Known gap left open, and it is a Goal A gap.** `ti`'s per-chunk failure
counts (`chunk_json_failures`, `chunk_llm_failures`, `chunk_exceptions`) are
logged but never reach the result, so a run where some chunks failed and others
succeeded still reports `analysis_status: complete`. **1.5 must close this** —
it is already editing that code, and until it does, `complete` on the ingester
means "no truncation, no dropped pages, LLM ran", not "no chunk failed".

**Where:** `tra` result dict (`tra:646`) and
`plugins/threat_modeling/threat_report_analyzer/schemas/output.schema.json`;
`ti` result dict (`ti:2244`) and its output schema.

**Change:** add one additive field:

```
analysis_status: "complete" | "partial" | "degraded"
```

- `complete` — every call returned untruncated; no page dropped; no chunk
  failed.
- `partial` — content is missing but every failure is known and named
  (truncation, dropped pages, a failed chunk).
- `degraded` — the tool fell back to a materially worse input path
  (native → pypdf text, or LLM → regex baseline).

Accompany it with `analysis_notes: list[str]`, one human-readable line per
cause, and surface the status **first** in `summarize_for_llm()` — ahead of the
existing `INCOMPLETE COVERAGE` line, which becomes one of the notes.

**Why:** `summarize_for_llm` is what downstream reasoning actually sees
(`CLAUDE.md`), and it is capped at 2000 characters by `PluginExecutor`. Status
must lead so truncation of the summary cannot remove the warning.

**Do not:** exceed the 2000-character cap. Keep `analysis_notes` to one short
line per cause.

**Test:** each status reachable from a synthetic scenario; `summarize_for_llm`
output starts with the status whenever it is not `complete`.

### 1.5 — Distinguish "classified, none accepted" from "classification unavailable"

**Status: DONE, 2026-09-15.** Landed as written, including open decision 2
(zero accepted IOCs returns an **empty set**, not a labelled baseline). Full
record in `docs/change_log/2026-09-15-chunk-failures-and-rejection.md`.

**It also closed the Goal A gap 1.4 left open.** Per-chunk failure counts now
reach the result as `chunks_attempted`, `chunks_failed` and
`chunk_failure_breakdown` (json_parse / llm_call / exception), and a non-zero
`chunks_failed` makes the run `partial`. Before this, a run where four of ten
chunks failed reported `complete`.

**Two distinctions the step did not name:**

- *Unparseable JSON is a failure, not a rejection.* The model answered and the
  answer could not be read; that is not an assessment that every candidate was
  benign. Only a parseable result sets `refinement_ran`.
- *`accepted_none` is computed from `refined_iocs`, not `filtered_iocs`.* An
  empty result after the confidence threshold is the threshold's doing, and
  treating it as a false-positive assessment would be a new version of the same
  conflation this step removes.

**A gap in 1.4's rendering this exposed:** `summarize_for_llm` emitted
`analysis_notes` only when the status was not `complete`, so the "no indicators
accepted" note would never have been seen. Notes now render on a complete run
too, without the status prefix. A clean run with no notes stays silent.

**Still outside `analysis_status`:** native batch failures. `chunks_attempted`
is 0 on a native run, so `chunks_failed == 0` there says nothing about native
batch outcomes. That bookkeeping is Stage 2.1's subject.

**Where:** `ti:2111` — `if not refined_iocs:`.

**Change:** track whether LLM refinement *ran and returned parseable results*
as a separate boolean from whether the accepted list is non-empty. Fall back to
the regex baseline only when refinement was unavailable or wholly failed. When
refinement ran and rejected everything, return zero IOCs with
`analysis_status: "complete"` and a note saying all candidates were assessed as
false positives.

**Why:** today an all-false-positive assessment is indistinguishable from a
total refinement failure, and the recovery **reinstates the exact indicators
the model rejected**, at `confidence: "low"`. That converts a correct
filtering result into a wrong one.

**Test:** every candidate marked `is_false_positive` must yield zero IOCs and
mode `llm`, not the regex baseline. A refinement that never ran must still
yield the baseline with mode `regex_only`.

### 1.6 — Persist coverage and status with the exports, not only in the result

**Status: DONE, 2026-09-15.** Full record in
`docs/change_log/2026-09-15-persisted-provenance-and-page-outcomes.md`.

`ti` persists `coverage`, `ingestion_mode`, `analysis_status` and
`analysis_notes` into `output_data`, computed **once** and shared with the
result so the two cannot disagree. `tra` prepends a provenance block to the
final summary and every chunk artifact, on both the local and GCS paths,
naming source, run stamp, provider/model, status, every note and the page
outcomes.

**Note for any later stage:** the provenance block is written for a human and
is never parsed back. Reconciling an export against a run record would need a
machine-readable sidecar, not markdown parsing.

**Where:** `ti:2186-2190` (the persisted artifact's `output_data`) and
`tra:603` / `tra:626` (the exported Markdown).

**Change:**
1. `ti`: add `pages_total`, `pages_read`, `pages_dropped`, `analysis_status`
   and `analysis_notes` to `output_data`. Today they exist only on the returned
   `ToolResult` and vanish the moment the artifact is read back.
2. `tra`: prepend a short provenance block to the written Markdown — report
   path, run stamp, provider and model used, `analysis_status`, and each
   `analysis_note`. Apply to the final summary **and** to chunk artifacts.

**Why:** an export outlives the session that produced it. A summary read from
the bucket months later currently carries no trace of having been built from
part of a report, or of having failed halfway.

**Test:** round-trip — write the artifact, read it back, assert coverage and
status survive.

### 1.7 — Do not count an unreadable page as read

**Status: DONE, 2026-09-15.** Landed as written, including the fixture.

`pages_read` counts only pages that yielded text; `pages_empty` and
`pages_extract_failed` are reported separately, and a non-zero
`pages_extract_failed` makes the run `partial`. A blank page is **not** a
failure, per the step's own "Do not".

**One distinction the step did not name:** `pages_dropped` keeps meaning
*never attempted*. A page pypdf failed on was attempted, so counting it as
dropped would hide that the file itself is the problem. The two counts are
orthogonal.

**Where:** `tra:970-974`.

**Change:** count per page: extracted / empty / extraction-failed. `pages_read`
counts only pages that yielded text. Report `pages_empty` and
`pages_extract_failed` separately, and treat a non-zero
`pages_extract_failed` as a `partial` status with a note.

**Why:** a genuinely blank page and a scanned page pypdf cannot read are
currently identical in the counters, and both report as read. Coverage numbers
that cannot distinguish them are not evidence of coverage.

**Do not:** treat empty pages as failures. A blank page is a legitimate outcome
and reporting it as a defect trains operators to ignore the field.

**Test:** a fixture with one text page, one blank page and one page whose
`extract_text()` raises must report `pages_read=1, pages_empty=1,
pages_extract_failed=1` and status `partial`.

### Stage 1 acceptance — **MET, 2026-09-15**

- Full suite green: **1308 passing**, from the 1177 baseline. ✔
- New tests in both plugins — `test_output_budget`, `test_truncation`,
  `test_section_status`, `test_analysis_status`,
  `test_page_outcomes_and_provenance` (`tra`); `test_truncation`,
  `test_analysis_status`, `test_chunk_failures`, `test_persisted_coverage`
  (`ti`, which already had a `tests/` directory). ✔
- No live model calls required by any new test. ✔
- A dated entry in `docs/change_log/` per step, indexed in its README. ✔

Beyond the stated bar, every step was **mutation-checked**: the change was
reverted and the new tests were confirmed to fail on the defect rather than
merely pass on the fix.

**Amended 2026-09-15.** Stage 1 was signed off on control flow alone, and
the first live run found three defects it could not have caught: a note that
overclaimed assessment, coverage counting lines while naming pages, and an
export that stated no page count on the native path. All three are Goal A
failures, and all three are now fixed. The lesson for Stage 2 is that a
deterministic review is necessary and not sufficient — **run the tools before
declaring a stage done.**

**Not covered by any of this:** no live model requests were made at any point
in Stage 1. Every conclusion is about control flow. How often these failures
fire against real reports, and whether Stage 1.1's budget sizing actually
removes the starvation in practice, are unmeasured.

---

# Stage 2 — evidence the model produced is never destroyed

**Status: in progress.** 2.0 and 2.1+2.2 landed 2026-09-15 (change logs
`2026-09-15-submitted-baseline.md`, `2026-09-15-retry-supersedes-partial.md`);
suite 1319 → 1372. **2.3, 2.4, 2.5 and 2.6 remain**, to be done as the third
change set. **Nothing in Stage 2 is signed off**: the single live run against
the 154-page report has not been made, and Stage 1's lesson was that control
flow alone is not sufficient.

Two corrections came out of implementing the first two steps, both recorded in
their steps below: **2.0's defect turned out to be unreachable** (it is kept as
2.5's tripwire and changes no output today), and **2.1 had a second path** the
original write-up missed — a truncated batch that cannot be bisected hands its
pages to the chunked text path while its partial stays in the merge.

Read the four notes below before continuing — they are what Stage 1 learned
that changes how Stage 2 should be done.

### Before starting 2.x

1. **Re-derive every line number.** Appendix B is stale — see the warning on
   it. Stage 1 added roughly 250 lines to `tra` and 200 to `ti`, and several
   referenced constructs changed shape. Grep for the construct, do not trust
   the table.

2. **Run the tools, not just the tests.** Stage 1 was signed off on control
   flow and a full green suite, and the first live run found three further
   Goal A defects — a note that overclaimed assessment, coverage counting lines
   while naming pages, and an export with no page count. A deterministic review
   is necessary and not sufficient. Budget a live run against the 154-page
   Anthropic report before calling any Stage 2 step done.

3. **Do not regress the reconciliation.** `candidates_unassessed`
   (`ti:2221-2231`) compares candidates submitted against verdicts returned,
   and **both sides move in Stage 2.**

   *The verdict side:* **2.2 changes what "returned a verdict" means** — once
   occurrences are recorded per entity, the assessed set has to be derived from
   every attempt's verdicts, **including superseded ones**, rather than from the
   post-merge `refined_iocs` alone. Otherwise a value a partial answered and its
   retry did not reads as unassessed on every run. This is the most likely way
   Stage 2 breaks Stage 1.

   *The submitted side:* it compares against `raw_iocs` (`ti:1617`), the
   whole-document regex pass, while what is actually submitted is `batch_iocs`
   built from `page_iocs` (`ti:1817-1820`) or `fallback_iocs` (`ti:2029`). The
   two are **equivalent today** — 2.0 records why — but 2.0 makes the submitted
   side explicit first, so that this change moves one baseline rather than two.

4. **`analysis_status` is now a consumer of the merge.** 2.2's `conflicts` and
   2.1's `superseded_by` both need to reach it: an unresolved conflict is
   `partial`, not silence. Stage 1 established the field; Stage 2 has to keep
   feeding it.

### What Stage 2 assumed — **re-checked against the code, 2026-09-15**

Every assumption below was verified in the tree at `2efb594`, not read off the
table. All three hold.

- `_merge_llm_chunk_results` is still first-wins on `(ioc_type, value.lower())`
  and `(technique_id, tactic)`. ✔
- The partial-before-retry ordering is unchanged. The partial is appended at
  `ti:1947`, the bisected halves are pushed at `ti:1971`, and `chunk_results`
  is seeded from `native_batch_results` at `ti:2048` — so the partial is ahead
  of its own retry in merge order. The truncation *reporting* added in 1.2 does
  not fix it: the log still reports the retry as a success. ✔
- Native batch outcomes remain outside `analysis_status` (`chunks_attempted =
  n_chunks` at `ti:2049` is 0 on a clean native run). **2.1 closes this**,
  since it is already adding per-attempt bookkeeping. ✔

### Line numbers, re-derived at `2efb594`

Appendix B is stale. These are the positions Stage 2 actually edits.

| Step | Construct | Stale ref | Actual |
|---|---|---|---|
| 2.1 | partial appended before retry | `ti:1829` | `ti:1946-1947` |
| 2.1 | bisect push / cannot-split fall-through | — | `ti:1960-1975` / `ti:1976-1982` |
| 2.1 | native results seeded into the merge | — | `ti:2048` |
| 2.1 | `batch_no` (the attempt counter) | — | `ti:1804` |
| 2.2 | `_merge_llm_chunk_results` | `ti:478-528` | `ti:478-527` |
| 2.3 | `path_id` union | `ti:519-521` | `ti:513-516` |
| 2.4 | `report_metadata` first-wins | `ti:523` | `ti:509-510` |
| 2.4 | attribution scalars on the result | `ti:2246-2258` | `ti:2459-2462` |
| 2.5 | `ioc_batches` / `text_chunks` / `n_chunks` | `ti:1910-1914` | `ti:2028-2033` |
| 2.5 | whole-document candidate order | `ti:1587` | `ti:1617`, type-major loop at `ti:270` |
| 2.5 | native-failure `fallback_text` / `fallback_iocs` | `ti:1894`, `ti:1891` | `ti:2009-2013` |
| 2.0 | the reconciliation Stage 1 added | — | `ti:2221-2231` |
| 2.0 | `_analysis_fields` | — | `ti:532-620` |
| 2.0 | `_page_iocs` | — | `ti:391-393` |
| 2.1 | `PageRange.label`, `bisect_range` | — | `profile.py:170`, `308-338` |
| 2.6 | `tra` finding and technique caps | — | `tra:1888`, `tra:1893` |

**`PageRange.label` is page-derived** (`f"p{start}-{end}"`), so a bisected
retry's halves never share their parent's label. Supersession is therefore
computed by page-range containment, not by label match, and `attempt_id` is
the monotonic `batch_no` at `ti:1804`.

**Goal B.** Additive schema changes; the existing key sets stay valid.
Depends on Stage 1's `analysis_status` for reporting conflicts.

**Estimated size:** revised 2026-09-15 to ~3 days across three change sets —
2.0 alone (small; a no-op plus a tripwire, see the step), then 2.1+2.2
together, then 2.3/2.4/2.5/2.6. The original estimate predated 2.0 and 2.6.

### 2.0 — Measure the reconciliation against what was submitted

**LANDED 2026-09-15.** `2026-09-15-submitted-baseline.md`.

**Added 2026-09-15, then corrected the same day.** It was written as a Goal A
defect fix and it is not one. Kept, rescoped, as the invariant guard 2.5 needs.

**Where:** `ti:2221-2231`, against `raw_iocs` at `ti:1617`.

**What was claimed, and why it was wrong.** The step was planned on the belief
that `raw_text` being `"\n\n".join(page_texts)` (`ti:1579`) while `_page_iocs`
(`ti:391-393`) runs the regex per page makes the per-page union a strict subset
of `raw_iocs` — a value straddling a page join living in `raw_iocs` and in no
page, never asked about, and charged to the model's silence.

**That case is not reachable.** Every pattern in `IOC_PATTERNS` is contiguous
over non-whitespace, so none can match across the `\n\n` join. Checked against
the real patterns, not reasoned about: eight split fixtures (ip mid-octet, ip at
a dot, domain, sha256, url, cve, an empty page between two, and a clean pair)
all give `raw_keys - page_union == {}`. And `plan_ingestion`
(`profile.py:216-300`) batches pages 1..N contiguously with no gaps, while every
batch that fails for any reason — `doc_ref is None` (`ti:1807`), an exception
(`ti:1883`), truncation that cannot be split (`ti:1982`), or an exhausted call
budget — adds its pages to `failed_pages`, which the chunked path then submits
from `fallback_iocs` (`ti:2009-2013`). **No path leaves a candidate
unsubmitted**, so `candidates_not_submitted` is 0 on every run today and the
reconciliation's two baselines are equivalent.

**What is still worth doing, and why.**

1. *Measuring against the submitted set makes the field mean what it says by
   construction rather than by coincidence.* The equivalence above is a property
   of today's batching, not of the field's definition. 2.5 rewrites prompt
   assembly into page units; if that rewrite drops a candidate, the current code
   would report it as the model's silence.
2. *2.1 needs this baseline.* Once superseded results are skipped, the assessed
   set can no longer be read off the post-merge `refined_iocs` alone — see note
   3 in "Before starting 2.x". Having the submitted side already explicit is
   what keeps that change from moving both baselines at once.

**Change:** record a `submitted` map of candidate values as they are placed into
a prompt — native (`ti:1826-1835`) and chunked (`ti:2059-2067`) alike — and
reconcile verdicts against that. Report what `raw_iocs` holds and no prompt
carried as a **separate** `candidates_not_submitted`, with its own note, and
feed both to `_analysis_fields` (`ti:532-620`). *(Operator decision,
2026-09-15: separate counter, kept for the reason above.)*

**Why separate rather than folded in:** "the model was asked and stayed silent"
and "we never asked" have different causes and different fixes, and one counter
cannot say which happened — the same distinction Stage 1.5 drew between
rejecting three of three and rejecting three of forty.

**Honest statement of effect:** this changes no output on any run today. It is
a no-op with a tripwire attached.

**Tests:**
- `_analysis_fields` reports `CANDIDATES NOT SUBMITTED` distinctly from
  `UNASSESSED CANDIDATES` and makes the run `partial` — the reporting contract,
  which is mutation-checkable.
- The reconciliation reads the submitted map: with a submitted set that is a
  strict subset of `raw_iocs`, the unassessed count follows the submitted set
  and the remainder is reported as not-submitted.
- **The invariant, as a regression tripwire for 2.5:** on a whole-document
  native run, a page-batched native run, a native run that partially falls back,
  and a pure chunked run, `candidates_not_submitted == 0`. If 2.5 breaks page
  coverage, these fail.

### 2.1 — A successful retry must supersede the partial it replaces

**LANDED 2026-09-15.** `2026-09-15-retry-supersedes-partial.md`. Live-verified
2026-09-15: four partials superseded on real traffic by both routes. The
machinery works; **no superseded sighting disagreed with the retry that
replaced it**, so the defect's output impact on that run was nil and its
real-world severity is still unmeasured.

**Where:** `ti:1829` — the partial parse is appended to `native_batch_results`
*before* the bisected retry runs, and `_merge_llm_chunk_results` is first-wins,
so the partial beats its own retry.

**Change:** tag every native result with `(batch_label, attempt_id,
superseded_by)`, `attempt_id` being the monotonic `batch_no` at `ti:1804`.
When a bisected retry succeeds, mark the parent partial superseded. The merge
skips superseded results **except** for entities that appear only there, which
are retained and flagged `recovered_from_partial: true`.

**Supersede by page-range containment, not by label.** `PageRange.label` is
derived from the page numbers (`profile.py:170`), so bisecting `p1-10` yields
`p1-5` and `p6-10` and no child shares the parent's label. A result is
superseded when later successful results cover every page it covered.

**The cannot-split fall-through needs it too** (`ti:1976-1982`, not in the
original write-up). When a truncated batch cannot be bisected, its pages are
added to `failed_pages` for the chunked path **while its partial stays in
`native_batch_results`** — so the partial beats the chunked re-read of the same
pages, by the same first-wins rule. Containment covers both paths uniformly,
which is the reason to prefer it over special-casing the bisect.

**Why:** this is the one finding whose behaviour is the opposite of what the
logs say — the retry logs success while its own earlier partial supplies the
merged answer.

**Test:** a partial batch asserting `confidence: "low"` followed by a
successful retry asserting `confidence: "high"` must merge to `high`.

### 2.2 — Separate canonical entities from evidence occurrences

**LANDED 2026-09-15.** `2026-09-15-retry-supersedes-partial.md`. **Two defects
found live 2026-09-15 and fixed** (`2026-09-15-stage-2-live-runs.md`): the
false-positive filter dropped a record and took its `conflicts` out of the
output with it, hiding the one disagreement an analyst most needs (now
`rejected_with_dissent` plus a note, with the rejection still standing); and
`technique_name` as a conflict field made a naming variant set whole runs to
`partial` (now `_MITRE_CONFLICT_FIELDS = ("confidence",)`).

**Where:** `ti:478-528`.

**Change:** keep the existing top-level shape (downstream consumers depend on
it) and make the merge additive:
- Each merged IOC and technique keeps `occurrences: [{page_start, page_end,
  batch_label, attempt_id, context, confidence, role}]`.
- First-wins still decides the **canonical** scalar fields, so no consumer
  breaks, but nothing is discarded.
- When occurrences disagree on a scalar (`confidence`, `is_false_positive`,
  attribution), record `conflicts: [...]` and set the run `partial` with a
  note. **Do not auto-resolve by highest confidence** — a later correction and
  a lower-confidence restatement are not distinguishable by value.

**Why:** `(ioc_type, value)` and `(technique_id, tactic)` are entity
identities, not evidence identities. Several procedures share one technique;
one indicator carries several roles.

**Do not:** redesign the output schema into an evidence graph. The external
review proposed source hashes, spans and image regions; that is Stage 4
territory and would break every downstream consumer at once.

**Test:** two chunks reporting the same technique with different procedures
must merge to one technique with two occurrences.

### 2.3 — Namespace `path_id` before deduplicating attack paths

**Where:** `ti:519-521`.

**Change:** prefix each path's id with its batch label before the union, so two
batches that independently coin `path_id: "initial_access_to_exfil"` produce
two paths. Reconcile on actual nodes and edges, not the slug.

**Why:** separate model calls choose slugs independently. Today the second
path is dropped entirely.

**Test:** two batches emitting the same `path_id` with different node sequences
must yield two paths.

### 2.4 — Support more than one actor and campaign

**Where:** `ti:523` (first non-empty `report_metadata` wins) and `ti:2246-2258`
(`campaign_name`, `attributed_actor`, `attribution_confidence` are scalars).

**Change:** merge metadata field-by-field rather than object-at-a-time; collect
`actors: []` and `campaigns: []` alongside the existing scalars, which keep the
first value for compatibility. A later chunk qualifying attribution is added,
not dropped.

**Test:** chunk 1 naming actor A and chunk 2 naming actor B must yield both.

### 2.5 — Align candidate batches with the text they came from

**Where:** `ti:2028-2033` (the two independent splits) and `ti:2048`.

**Change:** build text units first, then attach to each unit the candidates
extracted from that unit's pages. Split a unit whose candidate list exceeds
`_MAX_IOC_PER_CHUNK` **within the unit**, keeping its text. Preserve page
labels in `fallback_text` and mark gaps between non-adjacent page ranges
(`ti:2009-2013`).

**Note the scope correction from the parent review:** the misalignment is
severe on the whole-document path (`ti:1617`, type-major candidate order from
the `for ioc_type in ioc_types` loop at `ti:270`) and mild on the
native-failure path (`ti:2009-2013`, already page-ordered).

**Confirmed 2026-09-15:** there is no relationship at all between the two
splits. `ioc_batches` slices `fallback_iocs` by index and `text_chunks` splits
`fallback_text` by paragraph, then chunk `i` pairs `ioc_batches[i]` with
`text_chunks[i]`. On the whole-document path that pairs the first fifty
candidates — in practice all of one type, drawn from anywhere in the document
— with the document's first 6,000 characters. Both need the fix; only the first is likely to pair an appendix
indicator with an unrelated narrative section.

**Test:** every candidate in a chunk's prompt must have its source page inside
that chunk's page range.

### 2.6 — The analyzer's hard caps destroy evidence, one nondeterministically

**Added 2026-09-15.** Stage 2 was scoped to `ti`, but this is the same Goal B
failure in `tra`, and it is the one place in either tool where two identical
runs disagree about what the report said. *(Operator decision, 2026-09-15:
in scope for Stage 2.)*

**Where:** `tra:1888` and `tra:1893`.

```python
return findings[:10]                  # _extract_key_findings
return list(set(techniques))[:20]     # _extract_techniques
```

**The defect.** Both caps drop silently — nothing counts what was discarded and
no note reaches `analysis_status`. The technique cap is worse than lossy:
`set()` gives no ordering, so *which* twenty ids survive varies between
identical runs over identical text. And it applies twice — per chunk at
`tra:1484`, before the cross-chunk union at `tra:734-735` — so a 16-batch
report can lose techniques at both levels.

**Change:** make both order-stable (preserve first appearance), raise or drop
the limits, and when anything is dropped, record the count and feed a note to
`_analysis_fields` (`tra:1055`). A cap is defensible; a silent cap is not, and
a nondeterministic one is not defensible at all.

**Why it matters beyond tidiness:** `relevant_techniques` is what a reader takes
as "the techniques this report covers". A cap that silently keeps an arbitrary
twenty makes that list unreproducible, and the export carries it with no
indication anything was left out.

**Test:** a summary naming 25 techniques must yield a stable, documented
ordering across repeated calls, and the result must state that five were
dropped.

### Stage 2 acceptance

Same as Stage 1, plus: no change to the top-level keys any existing consumer
reads. Verify by grepping the projector and any other consumer of
`threat_intel_ingester` output before merging.

**Schema headroom confirmed 2026-09-15:** neither plugin's
`schemas/output.schema.json` sets `additionalProperties: false` on the objects
Stage 2 touches, so `occurrences`, `conflicts`, `superseded_by`, `actors`,
`campaigns` and the two new counters are all additive. Declare them anyway —
an undeclared field is valid and undocumented.

**Consumers to grep before merging** (checked 2026-09-15): the only readers of
`threat_intel_ingester` output are `attack_path_visualizer` (`tool.py:60`,
`880`, `915`, `945`, on the `json_events` artifact) and
`adversary_path_projector` (`tool.py:3249`). Re-grep at merge time.

**Live-run sign-off** *(operator decision, 2026-09-15)*: build and
mutation-check every step against synthetic responses, then **one** live run
against the 154-page Anthropic report covering the whole stage before any
change log claims completion. Per-step live runs were considered and declined
on cost; the change logs must say which steps the single run exercised.

**Order of work**, from the code review rather than the numbering: 2.0 first
(it protects Stage 1 before the merge moves), then **2.1 and 2.2 as one change
set** — both rewrite `_merge_llm_chunk_results`'s contract, and splitting them
means writing the merge twice — then 2.3 and 2.4, which are small and
independent, then 2.5, which changes what the prompts contain and wants a
trustworthy merge underneath it. 2.6 is independent of all of them.

---

# Stage 3 — meaning is more likely to survive a boundary (GATED)

**Goal C.** **Do not start this stage until the Appendix A fixture set exists
and Stages 1 and 2 have landed.** Every change here is an improvement in odds,
and without labeled fixtures there is no way to tell an improvement from a
regression. Shipping it ungated produces a change set nobody can evaluate or
safely revert.

### 3.0 — The gate

Build Appendix A. Record, for the current code, a baseline result per fixture.
Only then proceed.

### 3.1 — Recalibrate the latency model before changing boundaries

**Calibration data, 2026-09-15 (live).** A 154-page PDF planned 16 native
batches at **est. 2105s** and completed in **~260s** — **8.1x pessimistic**,
against the ~6.3x previously recorded. The estimate also exceeded the 600s
plugin timeout, so a slightly larger document would be refused work it can
comfortably do. One data point, not a calibration set.

**Where:** `profile:43-62`.

The model is already recorded as roughly 6.3x pessimistic, and the arithmetic
in the parent review shows it splitting a zero-candidate narrative at 11 pages.
Over-splitting is itself a cause of the boundary losses this stage is trying to
fix, so **recalibrate first** — otherwise every later measurement is taken
against an artificially fragmented baseline.

Calibrate from real runs per provider and tier. Do not add a budget guard
before the recalibration; a guard sized from a 6.3x-pessimistic model bakes the
error in.

### 3.2 — Separate the two workload estimators

`estimate_output_tokens = 1500 + 70 × candidates` (`profile:31-32`) prices
IOC extraction. It does not price a narrative-heavy, IOC-poor report with many
procedures. The analyzer's workload is different in kind. Share the profiling
and splitting machinery; give extraction and summarisation different
estimators.

### 3.3 — Prefer section boundaries, then add bounded overlap

Use document structure where it can be detected; fall back to page boundaries.
Add bounded overlap only at unavoidable mid-section breaks. Overlap helps a
continuation; it does nothing for a distant reference, so do not oversell it.

### 3.4 — Give every batch a compact report map

Source identity, section structure, aliases, campaign scope, stated
uncertainties. Currently each batch receives only its page range and
`source_context` (`ti:1710-1712`) and is asked independently for report
metadata and attack paths.

### 3.5 — Native page-range batching in the analyzer

The gap already named as "not done" in
`docs/change_log/2026-09-15-threat-report-analyzer-pdf-alignment.md`: one
whole-document native call, then straight to known-lossy pypdf text. The
ingester's middle ground does not exist here.

**Keep the provider-limit refusal policy from that change unless the product
adds an operator-selected split workflow.** Native batching is for
*processing* failures, not for overriding a provider's refusal.

### 3.6 — Truncation recovery, not just truncation reporting

Stage 1.2 reports truncation. Here, act on it: retry at a larger budget, or
bisect the range as the native ingester path already does at `ti:1841`.

---

# Stage 4 — analyst deliverables (product decision, deferred)

Not a defect fix. The external review proposes splitting the briefing from a
retained evidence packet: the briefing as an index into evidence, with detection
and hunting material carrying exact procedures, prerequisites, expected benign
use and page citations, and with source-stated facts distinguished from
model-inferred mappings and proposed logic.

This is a sound direction and it is a decision about what Event Mill delivers,
not a repair. It also depends on Stage 2's occurrence records existing. Revisit
after Stages 1–3.

One point from the review worth carrying forward verbatim: an ATT&CK ID passing
validation establishes vocabulary validity, not that the reported behaviour
occurred.

---

## Sequencing and stopping points

```
Stage 1 ──► reassess ──► Stage 2 ──► reassess ──► [Appendix A fixtures] ──► Stage 3 ──► Stage 4
   ~1 day                   ~2 days                   gate                    unscoped     product
```

- **Stage 1 alone removes every failure that currently misleads an operator.**
  It is the recommended next change set and a legitimate stopping point.
  1.1-1.5 have landed; 1.6 and 1.7 are what remain of it.
- Stage 2 is independently valuable and does not depend on Stage 3.
- Stage 3 without Appendix A is unmeasurable. Treat the gate as hard.

## Explicitly not in scope

- **Unifying the two PDF implementations.** The reasons recorded on 2026-09-15
  still hold: different jobs, a large change to a working tool. Stage 3.2
  shares the profiler while keeping the estimators separate; that is the
  intended extent.
- **OCR / layout reconstruction.** Named by the external review under finding
  5. Real, but a new dependency and a new failure surface. Stage 1.7 makes the
  loss *visible*, which is the prerequisite for deciding whether OCR is worth
  it.
- **Automatic cross-provider failover** to a vendor with larger limits. Still
  forbidden (`CLAUDE.md`, `_fallback_client`). "Run it on Gemini" stays an
  operator instruction, never an automatic action.
- **The `stability` enum and capability-namespace manifest validation errors.**
  Pre-existing, unrelated, and behaviour decisions rather than typos.

## Open decisions for the operator

1. **Truncated native analyzer summary** — mark `partial` and keep it
   (assumed by 1.2), or refuse and make the operator split the document, as the
   provider-limit refusal does? The assumed answer treats a short answer as
   better than a worse input path; the opposite is defensible.
2. ~~**Zero accepted IOCs** (1.5)~~ — **settled 2026-09-15**: an empty set,
   as assumed. The empty result is now labelled well enough not to read as a
   failure. Reversing it would mean an `unrefined` mode rather than reusing
   `regex_only`, which would claim refinement never happened.
3. ~~**Chunk artifacts for failed sections** (1.3)~~ — **settled
   2026-09-15**: written, with a failure header, as assumed. A missing file
   cannot distinguish a section that failed from one never attempted. Reversible
   in one line plus its test if the operator disagrees.

---

## Appendix A — the fixture set Stage 3 is gated on

Analyst-labeled report fixtures, each isolating one failure mode. Derived from
the external review's validation section and kept verbatim in substance:

| Fixture | What it tests |
|---|---|
| A procedure crossing a chunk boundary | Boundary loss |
| A table continued across a boundary | Structure loss |
| A screenshot-only command | Visual loss (finding 5) |
| A distant attribution correction | Merge first-wins (finding 1) |
| The same indicator in benign and malicious contexts | Occurrence roles (2.2) |
| Two campaigns using one technique | Entity vs evidence identity |
| Colliding path names across chunks | `path_id` namespacing (2.3) |
| A late critical qualifier | Cross-chunk reconciliation |
| A response that truncates | Findings 2, 1.2, 3.6 |
| One failed middle chunk | Compound failure, 1.3 |

For each: check retained evidence, relationship accuracy, unresolved-candidate
reporting, citation correctness, and whether the output is actually usable for
detection or hunting. Compare whole-document against chunked runs where the
document is small enough for both, **with the analyst labels as the reference —
not either model output as ground truth.**

## Appendix B — evidence index

Every line reference in this plan, so it can be re-verified after the code
moves. Tree: `e1dda3a` plus the uncommitted analyzer changes.

> **STALE AFTER STAGE 1 — do not trust these numbers.** Stage 1 added roughly
> 250 lines to `tra` and 120 to `ti`, so every `tra:` reference below is off by
> well over 100 lines and the `ti:` ones by tens. The *subjects* are still
> correct and are what this table is for. Re-derive the line by grepping for
> the construct before citing it — the Stage 1.2 work found the same drift and
> re-derived all four of its sites that way. Several referenced constructs have
> also changed shape: `ti:2011`'s `_parse_llm_json` call is now
> `_parse_llm_json_result`, and `tra`'s `summary_text` initialiser no longer
> holds the raw excerpt.

| Subject | Location |
|---|---|
| Merge, first-wins | `ti:478-528` |
| `_parse_llm_json` discards repair flag | `ti:532-536` |
| `_parse_llm_json_result` | `ti:538` |
| Budget helpers imported | `ti:36`, used `ti:369` |
| Native truncation pattern (reference) | `ti:1797-1799` |
| Partial appended before retry | `ti:1829` |
| Bisect on truncation | `ti:1841` |
| Failed-page fallback assembly | `ti:1891-1894` |
| Positional candidate/text pairing | `ti:1910-1914`, `ti:1938` |
| Text path ignores truncation | `ti:2011` |
| Regex reinstatement | `ti:2111` |
| Persisted artifact keys | `ti:2186-2190` |
| Native analyzer call | `tra:437-444` |
| Native success condition | `tra:457` |
| Final summary written | `tra:603`, GCS `tra:626` |
| PDF page extraction, empty substitution | `tra:970-974` |
| Section budget | `tra:1075` |
| Raw-excerpt initialiser | `tra:1076` |
| Section success condition | `tra:1098` |
| Synthesis budget | `tra:1144` |
| Synthesis fallback | `tra:1157` |
| Output/deadline headroom | `profile:38-39` |
| Output token estimator | `profile:31-32` |
| Latency model | `profile:43-62` |
| Greedy page batching | `profile:270-287` |
| `LLMResponse.truncated` declared | `framework/plugins/protocol.py:83` |
| `truncated` populated | `gemini.py:467,620`, `anthropic.py:429`, `openai.py:434` |
| `needs_reasoning` → `high` | `gemini.py:71-72` |
| Thinking spent from reply budget | `gemini.py:329` |
| `thinking_reserve_tokens()` | `framework/llm/providers/__init__.py:261` |
| Reserve is a ceiling, not a charge | `framework/llm/providers/__init__.py:318-329` |
| Gemini reserves and tier caps | `framework/llm/providers/gcp_gemini.json` |
