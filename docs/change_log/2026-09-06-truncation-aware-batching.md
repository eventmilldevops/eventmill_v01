# Change Log — Truncation-aware native batching

**Date:** 2026-09-06
**Primary Files:** `framework/llm/client.py`,
`framework/llm/providers/__init__.py`, `framework/llm/providers/gcp_gemini.json`,
`framework/documents/profile.py`,
`plugins/log_analysis/threat_intel_ingester/tool.py`
**Supporting Files:** `framework/plugins/protocol.py`,
`framework/documents/__init__.py`, `AGENTS.md`,
`tests/framework/test_document_profile.py`,
`tests/framework/test_llm_dispatcher.py`, ingester contract tests

---

## Problem

A 313-candidate PDF still lost most of its indicators. The page-range
batching added on 2026-09-05 did run — the document was split and each
sub-PDF was sent natively — but a batch came back as 20,891 characters of
JSON that stopped mid-record. `_parse_llm_json` repaired it by closing
brackets, returned a dict, and the batch was recorded as a **success**: 70
records kept, the rest silently dropped, and those pages never reached the
chunked fallback. The run looked like it was working and just taking 600 s.

Three separate faults produced that:

1. **Batches were sized against a budget that did not exist.** The plugin
   hardcoded `_NATIVE_MAX_OUTPUT_TOKENS = 16_384` and planned batches to fill
   75 % of it. Gemini 3.x spends thinking tokens from the same
   `max_output_tokens` budget as the reply, so on the heavy tier ~11k of that
   16,384 went to reasoning and only ~5k was left for JSON — a third of what
   the plan assumed. The hardcoded cap was also a quarter of the tier's real
   65,536, which the provider manifest already declares.
2. **Truncation was invisible.** `_execute_document_query` discarded
   `finish_reason` and `usage_metadata` and returned `ok=True`, so a reply cut
   off at the cap was indistinguishable from a complete one. The text path
   read `finish_reason` only to `print()` it.
3. **A repaired reply counted as a good one.** The one place that could tell
   (`_parse_llm_json`) logged a warning and returned the partial dict, and the
   caller treated any non-`None` parse as a finished batch.

## Design

### The reply budget is `cap − thinking reserve`

`gcp_gemini.json` gains an `output_budget` block declaring
`thinking_reserve_tokens` per level (minimal 1k / low 4k / medium 16k / high
32k) — the provider manifest stays the single source of truth. New accessors
`thinking_reserve_tokens(level)` and `max_output_tokens_for_tier(tier)`.

`plan_ingestion()` takes `output_reserve_tokens`, subtracted before the
existing `OUTPUT_HEADROOM` factor, so batches are sized against what can
actually hold JSON.

The ingester now asks for the tier's real cap (65,536) and passes
`thinking_level="low"` on native calls, matching what the chunked path
already does — refining regex hits into records is extraction, not reasoning,
and the reserve it needs is small.

### Truncation is reported, not inferred

`LLMResponse` gains `finish_reason` and `truncated`. Both the document and
text paths now fill them, plus `token_usage` including `thinking_tokens`, and
log a warning when a reply hits the cap. `_parse_llm_json_result()` returns
`(parsed, truncated)`; `_parse_llm_json()` remains for callers that only want
the dict.

### Batches are a queue, and a truncated batch is re-run

`bisect_range()` and `range_from_pages()` split one batch at the page
boundary nearest half its candidates. The ingester's native loop works from a
queue rather than a fixed list: a truncated reply pushes both halves back on
the front and re-runs them, bounded by `_NATIVE_MAX_EXTRA_CALLS = 8` extra
calls. A single page that truncates cannot be split, so its pages go to the
chunked text path at 50 candidates per call. Partial records are kept either
way — the merge deduplicates by `(type, value)`, so re-running a range costs
calls, never data.

This is the part that makes the estimate non-critical: if the cost model is
wrong for a document, the run corrects itself instead of losing indicators.

Sub-PDFs are now cut lazily, one range at a time, because the queue's
contents are not known up front. A cut that fails sends those pages to the
chunked path — previously the whole document was sent in one call instead,
which is the exact shape that truncates.

### Latency recalibration

`LatencyModel.seconds_per_candidate` 0.2 → 0.7. Writing the records dominates
a call: a 133-candidate batch estimated at 85 s was still generating past the
120 s deadline. At 0.7 a batch lands near 30–70 candidates — the size the
chunked path already sustains. Still overridable per deployment via
`EVENTMILL_NATIVE_S_PER_CANDIDATE`.

### Visibility

The console handler shows WARNING and above, so the old `[PROFILE]` dense
warning was the only thing a running ingest printed — a prediction of
trouble with no plan attached. That line drops to INFO (dense documents are
now handled, not warned about) and the `[PLAN]` line is logged at WARNING
whenever the document had to be split, so the operator sees the batch layout
instead of a silent countdown. `summary.native_calls` records how many
document calls actually ran, which is higher than `ingestion_plan.batch_count`
whenever a batch was re-split.

## Effect on the failing run

313 candidates over a dense PDF now plans 5–10 batches of 30–70 candidates
each (was 3–7 of up to 133, sized against a budget three times larger than
the real one). Each call asks for 65,536 tokens with low thinking, so ~2–5k
of JSON has room. Any batch that still truncates is halved and re-run rather
than accepted, and anything the native path cannot finish falls back to the
50-candidate chunked path. The 600 s plugin budget is unchanged — the point
was never more time, it was replies that fit.

## Tests

`tests/framework/test_document_profile.py` (+8): the reserve shrinks the
usable cap and forces batching; a reserve larger than the cap cannot drive it
negative; `bisect_range` splits near half the *candidates* not the pages,
handles two-page and single-page ranges, terminates when applied repeatedly,
and costs its halves with the caller's latency model.

`tests/framework/test_llm_dispatcher.py` (+6): tier cap and thinking-reserve
accessors; `finish_reason` read from an SDK enum or a string; `_usage`
reports thinking tokens; a `MAX_TOKENS` document reply comes back
`ok=True, truncated=True` with usage attached, and a `STOP` reply does not.

Ingester contract tests (+2, 2 reworked): a truncated batch is halved and
re-run over the same pages; a single page that truncates falls back to the
chunked path; a split failure now falls back to chunked text instead of one
whole-document call; the profile's `exceeds_single_call_output` is asserted
against the tier's real budget.

## Follow-ups

- The client's 120 s `http_options` timeout is still hardcoded in
  `MCPLLMClient.connect()` while the plugin declares
  `_NATIVE_CALL_DEADLINE_S` separately. A per-call deadline on `QueryHints`
  would let one large batch have longer without raising it globally.
- `thinking_reserve_tokens` values are allowances, not measured constants.
  The `thinking_tokens` now recorded in `token_usage` make them measurable —
  worth revisiting once a few dense runs are logged.
- `threat_report_analyzer` shares the parse-and-repair helper shape and has
  the same silent-partial risk on its own document calls.
