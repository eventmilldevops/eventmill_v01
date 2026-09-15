# Plan — report processing integrity

**Date:** 2026-09-15
**Status:** proposed, nothing built
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

### 1.1 — Size every analyzer LLM budget from the provider's declared reserve

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

### 1.2 — Read `truncated` at the four call sites that ignore it

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

### Stage 1 acceptance

- Full suite green (baseline: **1177 passing** as of 2026-09-15).
- New tests in `plugins/threat_modeling/threat_report_analyzer/tests/` and a
  new `tests/` directory under `threat_intel_ingester` if none exists.
- No live model calls required by any new test.
- A dated entry in `docs/change_log/`.

---

# Stage 2 — evidence the model produced is never destroyed

**Goal B.** Additive schema changes; the existing key sets stay valid.
Depends on Stage 1's `analysis_status` for reporting conflicts.

**Estimated size:** one change set, ~2 days.

### 2.1 — A successful retry must supersede the partial it replaces

**Where:** `ti:1829` — the partial parse is appended to `native_batch_results`
*before* the bisected retry runs, and `_merge_llm_chunk_results` is first-wins,
so the partial beats its own retry.

**Change:** tag every native result with `(batch_label, attempt_id,
superseded_by)`. When a bisected retry succeeds, mark the parent partial
superseded. The merge skips superseded results **except** for entities that
appear only there, which are retained and flagged
`recovered_from_partial: true`.

**Why:** this is the one finding whose behaviour is the opposite of what the
logs say — the retry logs success while its own earlier partial supplies the
merged answer.

**Test:** a partial batch asserting `confidence: "low"` followed by a
successful retry asserting `confidence: "high"` must merge to `high`.

### 2.2 — Separate canonical entities from evidence occurrences

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

**Where:** `ti:1910-1914` and `ti:1938`.

**Change:** build text units first, then attach to each unit the candidates
extracted from that unit's pages. Split a unit whose candidate list exceeds
`_MAX_IOC_PER_CHUNK` **within the unit**, keeping its text. Preserve page
labels in `fallback_text` and mark gaps between non-adjacent page ranges at
`ti:1891`.

**Note the scope correction from the parent review:** the misalignment is
severe on the whole-document path (`ti:1587`, type-major candidate order from
`extract_iocs_regex`) and mild on the native-failure path (`ti:1894`, already
page-ordered). Both need the fix; only the first is likely to pair an appendix
indicator with an unrelated narrative section.

**Test:** every candidate in a chunk's prompt must have its source page inside
that chunk's page range.

### Stage 2 acceptance

Same as Stage 1, plus: no change to the top-level keys any existing consumer
reads. Verify by grepping the projector and any other consumer of
`threat_intel_ingester` output before merging.

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
2. **Zero accepted IOCs** (1.5) — return an empty set, or return the regex
   baseline clearly labelled `unrefined`? The plan assumes empty, on the
   grounds that reinstating rejected indicators is worse than returning none.
3. **Chunk artifacts for failed sections** (1.3) — write them with a failure
   header, or do not write them at all? The plan assumes writing with a header,
   since a missing file is itself ambiguous.

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
