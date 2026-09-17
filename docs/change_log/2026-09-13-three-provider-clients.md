# Change Log — three provider clients, auth + ping, heavy and light tiers wired

**Date:** 2026-09-13
**Primary Files Modified:**
`framework/llm/providers/anthropic.json` (new),
`framework/llm/providers/openai.json` (new),
`framework/llm/providers/gcp_gemini.json`,
`framework/llm/providers/__init__.py`,
`framework/llm/model_client.py`,
`framework/llm/clients/anthropic.py` (new),
`framework/llm/clients/openai.py` (new),
`framework/llm/clients/gemini.py`,
`framework/llm/factory.py` (new),
`framework/cli/shell.py`,
`tests/framework/test_provider_registry.py` (new),
`pyproject.toml`

**1033 tests pass** (was 974; +59). Stage 2a of
`docs/specs/multi_provider_llm_clients.md` — three providers configurable and
provably reachable, **Gemini still the only provider bound for tool execution**.

---

## What this delivers

`providers probe`, run against the keys `.env` already carries:

```
  gcp_gemini
    ✓ light  gemini-3.8-flash
        auth  55 models, this one visible
        ping  'OK' in 812 ms, 9 tokens, served by gemini-3.8-flash
    ✓ heavy  gemini-3.1-pro-preview
        auth  55 models, this one visible
        ping  'OK' in 2828 ms, 80 tokens, served by gemini-3.1-pro-preview
  anthropic
    ✓ light  claude-sonnet-5     auth 11 models, visible / ping 'OK' 1546 ms, 20 tok
    ✓ heavy  claude-opus-5       auth 11 models, visible / ping 'OK' 1343 ms, 30 tok
  openai
    ✓ light  gpt-5.6-terra       auth 136 models, visible / ping 'OK' 1906 ms, 17 tok
    ✓ heavy  gpt-5.6-sol         auth 136 models, visible / ping 'OK' 1610 ms, 17 tok
```

Tiers as the operator specified them: Opus 5 and Sonnet 5 against Gemini 3.1 Pro
and 3.8 Flash, Sol and Terra likewise.

## Why `connect` could not answer the question

`GeminiClient.connect()` builds a `genai.Client` handle and returns `True`
(`clients/gemini.py:192`). It makes no network call, so a garbage key connects
cleanly and fails later at `PERMISSION_DENIED`. Both new clients are the same by
construction. So "can we reach the provider" needed a second operation:
`probe()`, two phases, both cheap.

- **auth** — `models.list`. No tokens. Proves the key reaches the vendor, and
  reports whether the manifest's model id is in the listing.
- **ping** — a few-token completion. Proves the query path returns.

A key can pass the first and fail the second: an entitlement that does not cover
one model shows up only on the ping. `LLMProbeResult` reports them separately for
that reason, and `summary()` names which phase failed rather than saying
"unreachable".

**Added to Gemini too, at the operator's request** — "it technically isn't
necessary but it would be easier to follow in the code if all three models are
initialized the same way." That symmetry paid for itself immediately (below).
Nothing about Gemini's existing `connect`, `query_text`, `query_with_document` or
error classification changed; `probe()` is additive.

## The finding symmetry caught

The first probe (change log `…-connectivity-probe.md`) had two pings return empty
text at a flat 64-token cap. The follow-up found the worse version:

```
gemini-3.8-flash  cap=64  thoughts=64+  text=''    MAX_TOKENS   <- run 1
gemini-3.8-flash  cap=64  thoughts=57   text='OK'  STOP         <- run 2, same cap
gpt-5-mini  cap=64  effort=None     reasoning=64  text=''    length
gpt-5-mini  cap=64  effort=minimal  reasoning=0   text='OK'  stop
```

Same cap, same model, opposite outcome — **thinking spend varies between
identical calls**, so a flat small ping budget passes or fails by luck. Had
Gemini been exempted as "technically unnecessary", that would have shipped as an
intermittent failure on the one provider carrying every module.

Three consequences, all implemented:

1. **`ping_budget(tier, provider_id)`** returns the reserve the provider declares
   for its shallowest accepted level plus 64 content tokens. The budget is a
   ceiling, not a charge, so reserving generously costs nothing unless spent —
   the light-tier Gemini ping now costs **9 tokens instead of 66**, because
   pinning the level down is cheaper than letting the default run.
2. **`accepted_thinking_levels(tier, provider_id)`** reads a new per-tier
   `thinking_levels`. `"minimal"` is excluded on all three: `gemini-3.8-flash`
   rejects `thinking_level="minimal"` and **both `gpt-5.6` tiers reject
   `reasoning_effort="minimal"`** ("does not support 'minimal' with this
   model"), verified live. Anthropic has no such level. A level that is valid
   `QueryHints` vocabulary is not portable, and the manifest is where that is
   now stated. Nothing clamps a plugin query against it yet — that is Stage 2.
3. **Truncation is its own diagnostic.** `MAX_TOKENS`/`length` with zero content
   reports as "TRUNCATED, raise the budget", never as an auth failure.

## The bug the new manifests would have introduced

`TIER_MODEL_ENV_OVERRIDE` was global. `.env` pins
`EVENTMILL_MODEL_HEAVY=gemini-3.1-pro-preview`, so the moment `anthropic.json`
loaded, **Anthropic's heavy tier would have been retargeted at a Gemini model
id** — the same silent-failure class as the 09-12 pin that made a model swap
inert. Now:

- unqualified `EVENTMILL_MODEL_LIGHT` / `_HEAVY` and `EVENTMILL_MAX_OUTPUT_*`
  apply to the **default provider only**, so an existing `.env` keeps working;
- `EVENTMILL_MODEL_<PROVIDER>_<TIER>` (e.g. `EVENTMILL_MODEL_ANTHROPIC_HEAVY`)
  addresses any provider.

Four tests pin this, including one asserting a global pin does **not** reach the
other two providers.

## Manifest facts, measured rather than assumed

| | Anthropic | OpenAI |
|---|---|---|
| Output cap | **128,000** | **128,000** |
| Context | 1,000,000 | 400,000 |
| Source | `models.retrieve` + over-limit 400 | over-limit 400 only |
| `temperature` | rejected | rejected — "only the default (1)" |
| Thinking | `budget_tokens` **rejected**; adaptive + `effort` | `reasoning_effort`, no `minimal` |

Both caps are **double Gemini's 65,536**, so output clamping cannot be shared
between providers. `models.retrieve` gave Anthropic's numbers authoritatively
(`max_input_tokens`, `max_tokens`, plus a capability block reporting
`thinking.types.enabled: false`). OpenAI exposes no context window at all —
`models.retrieve` returns `id`/`created`/`owned_by` — so `max_context_tokens`
there is **documented, not probed, and marked as such in the manifest**. The
number that matters for clamping was probed; the unverified one is only read by
a PDF guard no OpenAI path reaches.

## Scope held deliberately

**`LLMDispatcher._clients` is still keyed by tier alone and still holds Gemini
only.** An `AnthropicClient` registered under `"heavy"` would evict Gemini Pro
and route every heavy plugin to a vendor nobody selected. So:

- `_discover_models` stays Gemini-only and keeps feeding `_available_models` /
  `do_connect`. Provider status is a **separate** structure — `do_connect` hands
  `_available_models` ids to `GeminiClient` (`shell.py:3453`), so an Anthropic
  row there would bind a client that fails on first use.
- `providers` and `providers probe` are read-only. A test asserts that probing
  another provider leaves `_clients` byte-identical.
- `TestOnlyGeminiIsBoundForToolExecution` runs `do_connect` offline against dummy
  keys and asserts every bound client's `provider_id == "gcp_gemini"`.

Both new clients implement `query_text` only. `query_multimodal` and
`query_with_document` return a declared `bad_request` naming the stage that will
implement them: nothing in the estate consumes multimodal, and both document
modules stay on Gemini because neither new provider can read a `gs://` URI and
the dispatcher does not yet materialise bytes.

`OpenAIClient` uses `chat.completions`, not the Responses API the plan specifies,
because the installed SDK is 1.58.1 and `client.responses` arrived in 1.66.
`store=False` is sent on every request either way — a no-retention posture for
incident data is a declared property of the client, not an incidental default.
The `llm-openai` extra pins `>=1.66` so the SDK is not the blocker twice.

## Verified

- **1033 passed** (974 before, +59 new). No existing test changed.
- Live: all six tier clients green through the real CLI — `providers`,
  `providers probe`, `providers probe <id>`, and `models` with its new provider
  column.
- Registry behaviour exercised directly: default, multi-provider, deduplication,
  unknown-id refusal, and a placeholder key correctly counting as missing.
- `ruff`, `black` and `mypy` are **not installed in this venv** (declared in the
  `dev` extra, absent from the interpreter), so neither was run. Every new file
  compiles, and none of the lines this change adds exceeds 88 characters —
  `shell.py`'s 68 over-length lines are all pre-existing.

## Verified on Cloud Run — 2026-09-14

The operator ran `providers probe` in the deployed container: all six tier
clients green, latencies matching the local runs. Keys arrive through Secret
Manager, all three SDKs are in the image, and each configured model returns a
completion. Detail: `2026-09-14-cloud-run-three-provider-verification.md`.

## Not done here

- **Stage 2's `(provider_id, tier)` rekey** — the next piece, and the one that
  makes a second provider bindable for tool execution.
- `_model_supports_native_doc` still reads the manifest rather than
  `client.supports()`, and `_tier_of` still reverse-looks-up. Both are routing
  behaviour; this change touched none.
- No per-tier `output_budget` override yet; `thinking_reserve_tokens` is still
  provider-global. Each new manifest declares its own block, which is what the
  ping needs.
- The remaining Stage 6 items: `cloudbuild.yaml:117/229/257`,
  `Dockerfile.cloudrun:26` (neither SDK is installed in the image — the new
  extras exist but nothing installs them there yet),
  `docker-compose.cloudrun.yml:21`, `setup-deploy-server.sh:108`.
- `EVENTMILL_LLM_PROVIDERS` is now read by the framework, but nothing writes it
  into `.env.example`.
