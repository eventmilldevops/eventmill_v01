# Change Log — three-provider connectivity probe (Stage 2a, Step 1)

**Date:** 2026-09-13
**Primary Files Modified:** none — this is a measurement, not a change.

Step 1 of Stage 2a of `docs/specs/multi_provider_llm_clients.md`: before writing
`anthropic.json`, `openai.json` or either client, find out whether the three
keys actually authenticate and whether a completion comes back. Run locally with
the keys `.env` already carries, against all three vendors, in the same three
phases per provider — **key → auth → ping** — at the operator's request that
Gemini be probed the same way as the other two rather than exempted.

Throwaway scripts, run from the repo root so the local `framework` shadows the
editable install pointing at the sibling checkout.

---

## Result: 14/14 phases passed

| Provider | Tier | Model | Auth | Ping |
|---|---|---|---|---|
| `gcp_gemini` | light | `gemini-3.8-flash` | 562 ms, visible in 55-model listing | 1641 ms |
| `gcp_gemini` | heavy | `gemini-3.1-pro-preview` | 375 ms, visible | 1891 ms, `'OK'`, STOP |
| `anthropic` | heavy | `claude-opus-5` | 546 ms, 11 models | 1235 ms, `'OK'`, `end_turn` |
| `anthropic` | light | `claude-haiku-4-5-20251001` | (same key) | 609 ms, `'OK'`, `end_turn` |
| `openai` | heavy | `gpt-5.2` → `gpt-5.2-2025-12-11` | 1000 ms, 136 models | 2281 ms, `'OK'`, `stop` |
| `openai` | light | `gpt-5-mini` → `gpt-5-mini-2025-08-07` | (same key) | 1625 ms |

Key shapes only were reported, never a value or a prefix. Gemini tiers and model
ids came from `load_tier_specs("gcp_gemini")` — the real accessor — so the
Gemini rows exercise the manifest path rather than hardcoded ids. The Anthropic
and OpenAI model ids were **discovered from each vendor's `models.list`**, not
assumed, which is the other half of what this step was for.

`ANTHROPIC_API_KEY` and `OPENAI_API_KEY` are one key per provider serving both
tiers: neither vendor splits keys by tier, unlike the two Gemini keys that exist
to isolate Flash volume from Pro quota.

## The finding: a flat ping budget makes a healthy provider look broken

Two pings returned **empty text with a successful HTTP call**:
`gemini-3.8-flash` at `finish=MAX_TOKENS`, and `gpt-5-mini` at `finish=length`
with `reasoning_tokens=64` of a 64-token cap. Reasoning had consumed the entire
budget before any content was emitted. A follow-up run isolated it:

```
gemini-3.8-flash   cap=64    thoughts=57  total=66   text='OK'   STOP
gemini-3.8-flash   cap=256   thoughts=89  total=98   text='OK'   STOP
gpt-5-mini  cap=64  effort=None      reasoning=64  text=''    length
gpt-5-mini  cap=512 effort=None      reasoning=0   text='OK'   stop
gpt-5-mini  cap=64  effort=minimal   reasoning=0   text='OK'   stop
gpt-5-mini  cap=64  effort=low       reasoning=0   text='OK'   stop
```

Note the first row against the first run's failure at the *same* cap: thinking
spend varies between identical calls (57 tokens here, over 64 there), so a
64-token ping on Gemini light passes or fails depending on the run. **The probe
would have been flaky, not wrong.**

Three consequences for `probe()` in Step 4:

1. **The ping budget comes from the manifest, not a constant.**
   `thinking_reserve_tokens(level, provider_id)` in `providers/__init__.py`
   already computes exactly this reserve, and `threat_intel_ingester` already
   uses it for the same reason. The ping adds a small content allowance on top.
2. **Pinning reasoning down is a per-provider capability, not a general one.**
   `reasoning_effort="minimal"` fixes the OpenAI case at a 64-token cap, but
   `gemini-3.8-flash` rejects `thinking_level="minimal"` outright with `400
   INVALID_ARGUMENT`. For Gemini the answer is budget; for OpenAI either works.
   That asymmetry belongs in each provider manifest — which levels a tier
   accepts — and is the same gap already recorded for Stage 2.
3. **Budget starvation is its own diagnostic.** A finish reason of
   `MAX_TOKENS` / `length` with zero content tokens must report as *ping
   truncated — raise the budget*, never as an auth or connectivity failure.
   Conflating them would make `providers probe` cry wolf on a working key.

## Model ids now known, for Steps 2 and 4

Anthropic's listing (11 models): `claude-opus-5`, `claude-sonnet-5`,
`claude-fable-5-1`, `claude-fable-5`, `claude-opus-4-8`, `claude-opus-4-7`,
`claude-opus-4-6`, `claude-sonnet-4-6`, `claude-opus-4-5-20251101`,
`claude-haiku-4-5-20251001`, `claude-sonnet-4-5-20250929`. Proposed manifest
tiers: heavy `claude-opus-5`, light `claude-haiku-4-5-20251001`.

OpenAI exposes 136 models. Proposed: heavy `gpt-5.2`, light `gpt-5-mini`. Both
pinged clean; the alias resolved to a dated snapshot in the response
(`reported_model`), which is why normalised diagnostics report requested *and*
reported model.

## Confirmed on the way past

- `openai` is **1.58.1** and `client.responses` is **absent** — the Responses
  API the plan specifies needs `>=1.66`. `chat.completions` served the ping, so
  Step 1 did not need the upgrade; `OpenAIClient` will.
- `anthropic` 0.111.0 `messages.create` worked unchanged.
- Neither SDK is declared in `pyproject.toml`; both remain ambient in the dev
  venv. `llm-openai>=1.66` and `llm-anthropic` extras are still outstanding.

## Not done here

No application code changed and no manifest was added. `LLMDispatcher._clients`
is still keyed by tier alone and still holds Gemini only — Anthropic and OpenAI
are reachable, not bound, and no module routing changed. Steps 2–7 of Stage 2a
follow.
