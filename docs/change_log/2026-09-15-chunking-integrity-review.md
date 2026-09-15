# Change Log — report chunking integrity review (no code changed)

**Date:** 2026-09-15
**Branch:** `llm_5`
**Tree reviewed:** `e1dda3a` plus the uncommitted `threat_report_analyzer`
changes from `2026-09-15-threat-report-analyzer-pdf-alignment.md`
**Status:** review only. **No application code was changed and no live model
requests were made.** The remediation plan is
`docs/specs/report_processing_integrity.md`.

---

## Why this entry exists

An external review (GPT-6, 15 September 2026) asserted that neither
`threat_intel_ingester` nor `threat_report_analyzer` establishes that report
content survives chunked processing, and listed eight defects. The concern
behind the request was context rot on large reports: whether a long report is
being read, chunked and merged in a way that quietly loses evidence.

This entry records **which of those claims were verified against the code**,
which were overstated, and one compound failure the external review described
only in pieces. It is written so the plan can be executed later by someone who
no longer has the review in front of them.

Every claim below was checked by reading the cited code. None was accepted on
the strength of the review's own probes.

## The bar this is measured against

The external review's framing — "neither tool establishes that all relevant
report context survived processing" — is not an achievable bar. No chunked
pipeline can establish semantic completeness, and adopting that as the goal
would make every improvement unfalsifiable.

Two things *are* achievable, and they are what the plan targets:

1. **Never present incomplete work as complete.** Deterministic, testable
   without a model.
2. **Never destroy evidence the model did produce.** Also deterministic, also
   testable without a model.

Improving the *odds* that meaning survives a chunk boundary — semantic
boundaries, overlap, a report map — is a third thing, and it cannot be
validated without analyst-labeled fixtures. That is why it is gated in the plan
rather than done first.

## Findings — all eight confirmed

Line numbers are against `e1dda3a` plus the uncommitted analyzer changes.
`ti` = `plugins/log_analysis/threat_intel_ingester/tool.py`,
`tra` = `plugins/threat_modeling/threat_report_analyzer/tool.py`,
`profile` = `framework/documents/profile.py`.

| # | Finding | Verified at | Mechanism |
|---|---|---|---|
| 1 | Merge discards later evidence and corrections | `ti:478-528` | First-wins on `(ioc_type, value.lower())`, `(technique_id, tactic)`, first non-empty `report_metadata`, first `path_id` |
| 2 | Incomplete processing can be reported as success | `tra:457`, `tra:1098`, `tra:1154`; `ti:532`, `ti:2011` | `LLMResponse.truncated` is never read at four of five call sites |
| 3 | No cross-chunk relationship preservation | `profile:270-287`, `ti:1695-1724` | Greedy page batching, no overlap, no section awareness; every batch gets the full prompt and is asked for report metadata and attack paths independently |
| 4 | Text fallback pairs candidates with unrelated text | `ti:1910-1914`, `ti:1938` | `ioc_batches[i]` paired positionally with `text_chunks[i]`; partitioned independently at 50 candidates vs 6,000 chars |
| 5 | PDF text fallback loses visual evidence unmeasured | `tra:970-974` | `except: texts.append("")` — the page is still counted as read |
| 6 | Limitations do not travel with exports | `ti:2186-2190`, `tra:603` | Persisted JSON carries four keys; coverage fields exist only in the returned `ToolResult`. The analyzer writes `final_summary` alone |
| 7 | Chunk sizing is a resource estimate, not a context policy | `profile:31-39`, `profile:43-62` | `10 + 12·pages + 0.7·candidates` against a 0.80 deadline headroom splits a zero-candidate narrative at 11 pages |
| 8 | Rejected false positives are reinstated by the regex baseline | `ti:2111` | `if not refined_iocs:` cannot distinguish "classified, none accepted" from "classification unavailable" |

### Detail on the sharp ones

**Finding 1** is about identity, not deduplication. `(ioc_type, value)` and
`(technique_id, tactic)` are *entity* identities; the same indicator can carry
several roles and several procedures can share one technique and tactic. A
later section qualifying or correcting an earlier one loses, because the
earlier one was merged first.

**Finding 1, second half.** A truncated native batch's partial parse is
appended to `native_batch_results` at `ti:1829` *before* the bisected retry
runs. Since the merge is first-wins, **the partial interpretation beats its own
successful retry.** This is the most counter-intuitive defect found and it is
not visible from the log line, which reports the retry as a success.

**Finding 2** is narrower and cheaper than the external review implies — see
the corrections below.

**Finding 7** restates a known issue; the latency model was already recorded as
roughly 6.3x pessimistic. Arithmetic confirms the consequence: deadline
`180 × 0.80 = 144 s`, estimate with zero candidates `10 + 12p`, so `p = 11`
fits and `p = 12` does not. A 154-page report becomes 14 batches.
Over-splitting is not only a cost problem; it is one of the drivers of
finding 3.

## Four corrections to the external review

### 1. Its test caveat is stale

It reported that pytest and jsonschema were unavailable, that the suite was not
run, and that historical passing totals in change logs should not be treated as
current validation.

**The suite was run for this review: 1177 passed in 74 s.** The caveat can be
dropped. This does not weaken any finding — every one of them sits in untested
behaviour, which is the more useful observation.

### 2. Finding 4 is overstated by half

The review states that "regex extraction iterates by IOC type, while text
chunks follow document order," implying type-major ordering everywhere. That is
true only on the **whole-document** path: `ti:1587` sets
`fallback_iocs = raw_iocs`, and `extract_iocs_regex` (`ti:258-299`) loops
`for ioc_type in ioc_types`, which is type-major.

On the **native-failure** path, `ti:1894` rebuilds `fallback_iocs` page by page
from `page_iocs`, so candidates there are already in document order.

The misalignment is real on both paths — 50-candidate batches and 6,000-char
text chunks partition independently, so boundary `i` never coincides — but the
severity differs substantially between them, and a fix should be scoped
accordingly.

### 3. Finding 2 needs far less work than implied

The review reads as though truncation detection has to be built. It does not.
**All three clients already populate `LLMResponse.truncated` correctly**:

| Client | Line | Condition |
|---|---|---|
| `framework/llm/clients/gemini.py` | 467, 620 | `reason == "MAX_TOKENS"` |
| `framework/llm/clients/anthropic.py` | 429 | `stop == "max_tokens"` |
| `framework/llm/clients/openai.py` | 434 | `reason == "max_output_tokens"` |

`LLMResponse.truncated` is declared at `framework/plugins/protocol.py:83` and
reaches the plugin unchanged. **The correct consumption pattern also already
exists in this repository**, at `ti:1797-1799`:

```python
truncated = bool(native_response.truncated)
if native_response.ok and native_response.text:
    parsed, repaired = _parse_llm_json_result(native_response.text)
    truncated = truncated or repaired
```

The signal is plumbed all the way to the plugin and four call sites ignore it.
Finding 2 is therefore *apply the existing pattern in four more places*, not
*design a mechanism*. That reclassification is why Stage 1 of the plan is a day
of work rather than a redesign.

Note the second half of that pattern: `_parse_llm_json_result` (`ti:538`)
detects truncation the transport cannot see — a reply that parses only after
unmatched brackets are closed. Both signals are needed; neither subsumes the
other. `_parse_llm_json` (`ti:532`) is a thin wrapper that **discards the
repair flag**, and the text path calls that wrapper at `ti:2011`.

### 4. Its remediation scope is a program, not a fix

The review's prescriptions include per-occurrence evidence spans with source
hashes, OCR and layout processing, retrieval of referenced evidence across
chunks, and separate detection/hunt evidence packets. These are sound
directions and several are genuinely product-level decisions about what
analysts consume, not defect repairs. Presented as one list they obscure that
roughly a day of deterministic work removes the failures that actually mislead
an operator today.

The plan splits them accordingly and recommends stopping after Stage 1 to
reassess.

## What the external review missed

The section-summary path has a **compound failure** that the review describes
only in pieces, and it is the most dangerous behaviour found.

`_summarize_chunk` (`tra:1038-1110`) runs at `tier="light"`,
`thinking_level="low"`, `max_tokens=3072` (`tra:1075`), against a prompt asking
for 800–1,500 words. Gemini spends thinking tokens from the reply's budget —
stated in `framework/llm/clients/gemini.py:329` and already recorded as a
failure mode in this project: a small `max_output_tokens` returns empty text
because thinking consumed the budget, and thinking spend is not deterministic.

`summary_text` is initialised at `tra:1076` to `chunk.content[:3000]` — **raw
pypdf text** — and is only replaced inside `if response.ok:` at `tra:1098`. So:

- **Budget starvation** → `response.ok` is `True`, `response.text` is empty →
  `summary_text = ""`.
- **Call failure or exception** → the initialiser survives → `summary_text` is
  3,000 characters of raw extracted PDF text.

Neither outcome is marked. Both then travel two ways:

1. `_write_chunk_artifact` persists the value to a file named
   `<report>.<stamp>.chunk_NNN.summary.md`. A file in the common bucket whose
   name says "summary" can contain raw PDF text, or nothing at all.
2. `_synthesize_summaries` (`tra:1112`) concatenates it into the synthesis
   prompt under a `[Pages 40–60]` label, where the model cannot distinguish it
   from a real section summary.

And if synthesis itself fails, `tra:1157` returns `combined` — the
concatenation, including any raw-text blocks — as the final report summary,
with `ok=True` and no degraded marker.

The external review identified the 3,000-character substitution and the
synthesis fallback separately. It did not connect them, and did not note that
the substituted text is **persisted as an artifact** and **consumed downstream
as though it were a summary**.

## Verified

- Full suite: **1177 passed** in 73.9 s (`pytest -q`, `PYTHONIOENCODING=utf-8`).
- Every file:line reference in this entry read directly in the tree.
- `LLMResponse.truncated` population confirmed in all three clients.
- The 11-page batching arithmetic confirmed by hand against `profile:31-39`
  and `profile:43-62`.

## Not verified

- **No live model requests were made.** Every conclusion is about control flow,
  not model accuracy on real reports.
- `ruff` and `black` are not installed in the active interpreter; neither was
  run. This review changed no code, so nothing new is unlinted.
- The external review's own probe results were not re-executed. Where a probe
  outcome is stated above, it was re-derived by reading the code instead.
- No claim is made about how often these failures fire in practice. They are
  reachable by construction; their frequency is unmeasured.

## Next

`docs/specs/report_processing_integrity.md` — four stages, with Stage 1 as the
recommended next change set.
