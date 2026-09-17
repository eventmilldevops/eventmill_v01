# Change Log — analyzer output budgets sized from the declared reserve

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md`, **Stage 1.1**
**Scope:** `plugins/threat_modeling/threat_report_analyzer/` only. Stage 1.2–1.7
are not in this change set.
**Status:** implemented. **No live model requests were made** — every test uses
synthetic responses.

---

## What was wrong

All of the analyzer's LLM calls passed a bare integer `max_tokens` with no
thinking reserve subtracted, and every one of them was sized **below** the
reserve the provider declares for the level it actually requested:

| Call | Thinking level | Reserve | Budget passed | Content headroom |
|---|---|---|---|---|
| Native whole-PDF | provider default (`medium`) | 16,384 | ≤ 8,192 | negative |
| Section summary | explicit `low` | 4,096 | 3,072 | negative |
| Synthesis | `needs_reasoning=True` → `high` | 32,768 | 4,096 | negative |

The reserve is a ceiling rather than a charge
(`framework/llm/providers/__init__.py:318-329`), so these did not fail every
time. They failed whenever thinking spent near the reserve, and that spend is
not deterministic between identical calls — the behaviour already recorded for
liveness pings, where the same model returned empty text on one run and text on
the next at the same cap.

This is the mechanical cause of the compound failure in
`2026-09-15-chunking-integrity-review.md`: a starved section call returns
`ok=True` with empty text, which becomes `summary_text = ""`, which is persisted
to a file named `.summary.md` and fed to synthesis as though it were a section
summary. **That downstream half is Stage 1.3 and is still present.** This change
removes the cause, not the symptom.

None of the numbers was near a provider limit — the tier cap is 65,536 output
tokens on both Gemini tiers. They were arbitrary constants.

## What changed

`plugins/threat_modeling/threat_report_analyzer/tool.py`:

1. Imports `max_output_tokens_for_tier` and `thinking_reserve_tokens` from
   `framework.llm.providers`, mirroring `threat_intel_ingester` (`ti:36`).
2. New module-level `_budget(tier, thinking_level, content_tokens)` — content
   plus the declared reserve, bounded by the tier cap. It **reads** the provider
   manifest rather than restating it, for the reason CLAUDE.md gives and the
   reason the PDF page limits were fixed on 2026-09-14.
3. All four call sites now use it, each naming its own level:

| Call | Level | Content | Budget (`max_words=2000`) |
|---|---|---|---|
| Native whole-PDF | `_native_thinking_level()` | `max_words × 8` | 32,384 at `medium` |
| Single-pass chunk | `low` | `max_words × 8` | 20,096 |
| Section summary | `low` | 3,072 | 7,168 |
| Synthesis | `high` | `max_words × 8` | 48,768 |

   There were **four** sites, not the three the plan names: the single-pass
   branch of `_summarize_chunk` carried its own copy of the same
   `max(2048, min(8192, max_words * 8))` constant.
4. The synthesis call's bare `needs_reasoning=True` is replaced with an explicit
   `thinking_level="high"`. `gemini.py:71-72` (and the matching lines in the
   Anthropic and OpenAI clients) promoted it to `high` invisibly, so the budget
   was sized against a level the call site never named.

### The correction to the plan's own recommendation

The plan specified `_budget("heavy", "medium", …)` for the native call, on the
grounds that this preserves today's behaviour — the call names no level and
falls through to the "provider default `medium`".

**That default is `gcp_gemini`'s.** Checking every manifest:

| Provider | `default_thinking_level` |
|---|---|
| `gcp_gemini` | medium |
| `anthropic` | **high** |
| `openai`, `openai_daybreak_red`, `openai_daybreak_blue` | medium |

`anthropic.py:71-75` returns no effort control when `thinking_level` is `None`
and `needs_reasoning` is `False`, so Anthropic's own default applies. Pinning
`"medium"` would therefore have **silently demoted the native pass from high to
medium whenever the operator routed this plugin to Anthropic** — one vendor's
figure applied to all of them, which is the defect class the 2026-09-14 PDF
limits change removed.

The plugin cannot resolve this by reading the routed provider:
`shell.py:2982-2984` states that the wrapper is deliberately "the one place a
plugin cannot reach either of them", and `QueryHints` must not carry a provider.
The architecture's position is that **the plugin owns reasoning depth and the
operator owns the vendor**, so the level has to be chosen on merit and be the
same on every vendor.

### The operator override

Depth is therefore pinned, with a deployment-level override — the same shape as
`EVENTMILL_PROJECTION_THINKING` in `adversary_path_projector`:

```
EVENTMILL_REPORT_NATIVE_THINKING=low|medium|high   # default: medium
```

- Default `medium`, because this pass runs against a whole document and
  thinking level dominates latency; the 180 s client deadline is the real
  ceiling here, not the token cap.
- Resolved **once** per call into a local, which feeds both the budget and the
  hint, so the two cannot drift.
- Read at call time, so a `.env` loaded after import still takes effect.
- Only `low|medium|high` are offered: `minimal` is declared solely by
  `gcp_gemini` and is a 400 on `gemini-3.8-flash` and both `gpt-5.6` models, so
  offering it would hand the operator a setting that breaks the run.
- An unrecognised value warns and falls back rather than failing the run.

Section summaries stay `low` and synthesis stays `high`. Both are vendor
independent already and are not exposed.

Documented in the plugin README under "LLM Integration".

## Verified

- Full suite: **1191 passed** in 65.3 s (`pytest -q`, `PYTHONIOENCODING=utf-8`).
  Baseline before this change was 1177; the 14 new tests are
  `plugins/threat_modeling/threat_report_analyzer/tests/test_output_budget.py`.
- **Mutation-checked.** With the three edits reverted, 7 of the 14 new tests
  fail, including the acceptance test, with
  `a 8192-token budget at level 'medium' sits entirely inside the thinking
  reserve`. The tests fail on the defect rather than merely passing on the fix.
- Every level used (`low`, `medium`, `high`) confirmed present in
  `accepted_thinking_levels("heavy", pid)` for all five provider manifests, so
  no call can now 400 on an unsupported level.
- Every budget (7,168–48,768) confirmed under the 65,536 tier cap.
- Dropping `needs_reasoning=True` from synthesis confirmed inert for routing:
  `tier="heavy"` is set, so `dispatcher.py:259-260` selects the same order and
  `dispatcher.py:982`'s `hints.tier is None` is `False` either way.

## Not verified

- **No live model requests.** Whether a `medium`-level whole-document pass
  actually stays inside the 180 s deadline on a large report is unmeasured; it
  is the reason the override exists.
- `ruff` and `black` are not installed in the active interpreter, so neither was
  run. Line lengths were checked by hand: no line added here exceeds 88, and the
  file's over-length lines (31, all in prompt templates and `focus_areas`
  joins) are pre-existing.
- The reserve figures are read from the **default** provider
  (`gcp_gemini`), as `threat_intel_ingester` does at `ti:369`. All five
  manifests declare identical reserves for `low`/`medium`/`high`, so the number
  is correct today for every vendor; the tier cap differs (65,536 Gemini vs
  128,000 Anthropic and OpenAI) but only ever makes the budget more
  conservative, so it cannot truncate. If a vendor ever declares different
  reserves, this becomes wrong and the sizing has to move into the framework
  where the routed provider is known.

## Noticed, not changed

`plugins/threat_modeling/threat_report_analyzer/README.md` still says "Large
files (up to 50 MB / ~1,000 pages)" under Notes. Those are the provider-shaped
constants the PDF-alignment change removed from the code
(`2026-09-15-threat-report-analyzer-pdf-alignment.md`). That is that change
set's line to correct, not this one's.

## Next

Stage 1.2 — read `truncated` at the four call sites that ignore it (`tra:457`,
`tra:1098`, `tra:1154`, `ti:2011`). Stage 1.1 makes starvation much less likely;
1.2 is what makes it visible when it still happens.
