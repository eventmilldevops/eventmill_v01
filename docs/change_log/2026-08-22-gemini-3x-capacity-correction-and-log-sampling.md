# Change Log — Gemini 3.x Capacity Correction & Log Sampling

**Date:** 2026-08-22
**Scope:** `framework/llm/`, `framework/plugins/protocol.py`, `plugins/log_analysis/log_investigator/`, docs

---

## Summary

The codebase carried Gemini 2.5-era model assumptions, and every size limit in the plugins
had been chosen against them. Two consequences: light-tier responses were being clamped to
an output ceiling 8× lower than the real one, and `log_investigator` showed the model 50 raw
log lines regardless of how much evidence existed.

Verified against Google's model documentation:

| | Gemini 3.5 Flash (light) | Gemini 3.1 Pro (heavy) |
|---|---|---|
| Model ID | `gemini-3.5-flash` | `gemini-3.1-pro-preview` |
| Input limit | 1,048,576 | 1,048,576 |
| Output limit | 65,536 | 65,536 |

**The tiers are capacity-identical.** Tier now signals reasoning depth and cost only — never
how much fits. Any sizing decision made on tier grounds was meaningless.

---

## Corrected model facts

`framework/llm/providers/gcp_gemini.json` previously declared:

| Field | Was | Now |
|---|---|---|
| light `model_id` | `gemini-2.5-flash` | `gemini-3.5-flash` |
| heavy `model_id` | `gemini-2.5-pro` | `gemini-3.1-pro-preview` |
| light `max_output_tokens` | 8,192 | **65,536** |
| heavy `max_context_tokens` | 2,097,152 | **1,048,576** |
| `tokens_per_page` | 258 | **560** (default resolution) |
| PDF 1000 pages / 50 MB | ✅ | ✅ unchanged, still correct |

The light output cap mattered immediately: `_clamp_tokens()` (added 2026-08-22, earlier
session) clamps against these numbers, so every light-tier response was being truncated at
8,192 tokens.

`framework/llm/backends/gemini.py` duplicated the same stale values in
`_default_capabilities()`. It now reads `load_tier_specs()`, so the manifest is the single
source of truth.

### PDF page cost is no longer a constant

Under Gemini 3.x, per-page cost is set by `media_resolution`:

| Resolution | Tokens/page | 1000-page PDF | Fits 1M context? |
|---|---|---|---|
| `low` | 280 | 280,000 | ✅ 27% |
| `medium` (default) | 560 | 560,000 | ✅ 53% |
| `high` | 1120 | 1,120,000 | ❌ exceeds the window |

Native text extracted from a PDF is not billed — only the per-page image tokens.

---

## Changes

### `framework/llm/providers/__init__.py`

- `TierSpec` gains `fallback_model_id`.
- New `pdf_handling()`, `default_media_resolution()`, `tokens_per_pdf_page(resolution)`.
- Built-in fallback caps corrected to the 3.x values.

### `framework/plugins/protocol.py`

`QueryHints` gains `media_resolution` and `thinking_level`, both defaulting to `None`
("provider default"), so no existing call site changes behavior.

### `framework/llm/client.py`

- **New `_build_config()`** — one place that turns `max_tokens` + `system_context` + hints
  into a `GenerateContentConfig`, replacing three duplicated construction sites. Applies
  `thinking_level` and `media_resolution`; `needs_reasoning=True` implies `high` thinking
  unless the caller was explicit. Unknown values are logged and ignored rather than fatal.
- **Hints now reach the client.** The dispatcher previously routed on hints and then dropped
  them. That was harmless when hints only chose a tier; now that they carry generation
  controls, `query_text` / `query_multimodal` / `query_with_document` forward them — as does
  `MCPLLMClient`, which threads them into both execution paths.
- **New `_pdf_context_overflow()`** — estimates `pages × tokens_per_page` for the chosen
  resolution and refuses a PDF that cannot fit, naming the resolution that would work.
  Also enforces the 1000-page provider limit. Defers to the provider when the page count
  cannot be determined.
- **New `_is_model_not_found()` / `_retry_on_retired_model()`** — the heavy tier is a Preview
  endpoint that Google may retire with ~2 weeks' notice. On `NOT_FOUND` the dispatcher
  retries against the tier's `fallback_model_id`, reusing the live connection, and registers
  the substitute so later calls skip the dead id.
- PDFs default to the manifest's `media_resolution` explicitly rather than relying on an
  implicit provider choice.
- `MCPLLMClient` default model id updated to `gemini-3.5-flash`.

### Bulk call sites — `thinking_level="low"`

Default thinking moved to `medium` in 3.x, which adds latency and cost to high-volume work
that is pattern-matching rather than reasoning:

- `threat_intel_ingester/tool.py` — per-chunk IOC extraction
- `threat_report_analyzer/tool.py` — per-chunk summarization

Synthesis and reasoning call sites keep the default.

### `pyproject.toml`

`google-genai>=1.0.0` → `>=1.69.0`, the verified floor for `media_resolution` and
`thinking_level`.

---

## log_investigator — sample sizes

`log_investigator` is the only plugin that sends **raw log lines** to the model rather than
deterministic aggregates, so its sample size sets investigation fidelity. It sent
`matching_lines[:50]` — about 0.24% of the context window on a 150-char syslog.

Three defects compounded it:

1. **`context_lines` was inert.** The schema documented it as "Max matching lines to analyze"
   and `_investigate()` collected that many — then the LLM helper re-sliced to 50. Raising it
   changed nothing.
2. **The counts fed to the model were wrong.** The read loop broke out once the buffer filled,
   so `total_matches` and `lines_scanned` stopped counting there. The prompt interpolates
   both and asks the model for severity and *Timeline Analysis* off them — a 10,000-line file
   with 3,000 matches was reported as "100 occurrences in 2,347 lines". A correctness bug,
   not a sizing one.
3. **No budget guard.** Lines were retained untruncated; fifty 4 KB JSON lines is 200 KB.

### New sizing

| Knob | Was | Now |
|---|---|---|
| `context_lines` default | 100 (sliced to 50) | **500** |
| `context_lines` maximum | 500 (sliced to 50) | **5,000** |
| Total sample budget | none | **400,000 chars** (~130k tokens, ~13% of context) |
| Per-line cap | none | **1,000 chars** |

At ~3 chars/token, 500 lines is ~25k tokens for syslog, ~42k for combined access logs, ~84k
for verbose app logs. At the 5,000 maximum the char budget binds first for anything but short
lines — intended, so the cap self-adjusts to line width rather than trusting a line count.

### Representative sampling

First-N is the worst choice for security logs: an attack starting at line 8,000 is invisible.
`_select_sample()` now takes the first quarter, last quarter, and an evenly strided middle
half, binary-searching the largest selection that fits the char budget. On a synthetic log
where the final 20% carries the attack, the new sampler surfaces 324 of those lines; the old
`[:50]` surfaced **zero**.

The prompt now discloses partial coverage
(`SAMPLE LOG ENTRIES (showing 500 of 3,412 matches — first 125, last 125, every 9th …)`),
and a `sampling` block in the result records `total_matches`, `sampled`, `strategy`, and
`truncated_by`. `summarize_for_llm()` repeats it so downstream context does not read the
findings as full coverage.

`full_log` is now deprecated and ignored — the file is always scanned in full so the counts
are accurate. Reading is I/O-cheap; the LLM call is the expense.

---

## Tests

- `tests/framework/test_llm_dispatcher.py` — 25 → 47. New coverage for the 3.x generation
  controls, the PDF context guard, per-resolution page cost, and retired-model fallback.
  The `_specs()` fixture now mirrors real 3.x values; `_asymmetric_specs()` exercises
  per-tier clamping, which the real caps no longer demonstrate. Two regression guards added:
  tiers must stay capacity-identical, and the heavy tier must declare a fallback.
- `plugins/log_analysis/log_investigator/tests/test_sampling.py` — new, 16 tests covering
  complete match counting, sample selection, budget binding, prompt disclosure, and metadata.

Suite: 91 framework + 244 plugin → **376 passing**.

---

## Still Outstanding

`scripts/validate_manifests.py` reports 15 errors, all
`'stable' is not one of ['experimental', 'verified', 'core', 'deprecated']` — unchanged from
the previous session and unrelated to this work. Per `tool_plugin_spec.md`, `stability`
governs visibility and auto-invoke policy, so mapping `stable` to `verified` or `core`
changes runtime behavior for 15 plugins. Awaiting a decision rather than a silent enum widen.
