# Change Log — `connect` binds every configured provider

**Date:** 2026-09-14
**Primary Files Modified:** `framework/cli/shell.py`,
`tests/framework/test_provider_registry.py`

**1059 tests pass** (was 1056; +3 net). Stage A of
`docs/specs/projector_three_vendor_run.md`, which is the enabling half of
Stage 5 in `docs/specs/multi_provider_llm_clients.md`.

---

## What this makes possible

```
  ✓ Gemini 3.8 Flash (gemini-3.8-flash)
    Provider: gcp_gemini   Tier: light   Key: GEMINI_FLASH_API_KEY
  ✓ Gemini 3.1 Pro (gemini-3.1-pro-preview)
    Provider: gcp_gemini   Tier: heavy   Key: GEMINI_PRO_API_KEY
  ✓ Claude Sonnet 5 (claude-sonnet-5)
    Provider: anthropic   Tier: light   Key: ANTHROPIC_API_KEY
  ✓ Claude Opus 5 (claude-opus-5)
    Provider: anthropic   Tier: heavy   Key: ANTHROPIC_API_KEY
  ✓ GPT-5.6 Terra (gpt-5.6-terra)
    Provider: openai   Tier: light   Key: OPENAI_API_KEY
  ✓ GPT-5.6 Sol (gpt-5.6-sol)
    Provider: openai   Tier: heavy   Key: OPENAI_API_KEY

  Providers bound: gcp_gemini, anthropic, openai — 'gcp_gemini' serves tools
  by default.
```

Six clients bound for **tool execution**, not only for probing. The rekey
(`71df426`) made the dispatcher able to hold this; nothing in the shell could
produce it, because `do_connect` named `GeminiClient` directly in both of its
branches and `_discover_models` read Gemini's manifest alone. A mounted
`ANTHROPIC_API_KEY` was correct in source and inert in the environment — the
same failure class as the 3.8 model pin.

## The change

**`_load_provider_specs()` is new.** Tier specs per configured provider, read
once at startup. An unknown id in `EVENTMILL_LLM_PROVIDERS` is an operator
typo that must not stop the shell from starting, so it is recorded in
`_load_errors` and the session falls back to the default provider alone —
matching what `provider_status()` already did. `self._tier_specs` stays as
Gemini's specs, because the legacy single-key path is Gemini's alone.

**`_discover_models()` iterates providers, in configured order,** so the first
entry of `EVENTMILL_LLM_PROVIDERS` is the session default. Two things it now
does that it did not:

- **A placeholder key is skipped.** Every deployment mounts a secret for every
  vendor and the unadopted ones hold the literal `placeholder`. Binding one
  would produce a client that reports success at `connect` and fails at first
  use, which is precisely the state this project has already been burned by.
  Applied to Gemini too, including the legacy `GEMINI_API_KEY`.
- **The legacy `GEMINI_API_KEY` fallback is gated on Gemini being configured.**
  Without that gate, a session configured for Anthropic alone would have
  produced a Gemini row from a stale variable and bound a vendor nobody chose.

**`_build_client()` is new** and is the only place a client is constructed. The
class comes from `llm_factory.client_class(provider_id)` rather than being
named in the shell, so adding a vendor stays a registry entry plus a manifest.
A missing SDK names the extra to install; an absent or placeholder key says so
before anything is attempted.

**`_bound_tier_specs()` is new, and it prevents a silent mis-clamp.** The
dispatcher fans a *tier*-keyed spec map across every bound provider — correct
for one vendor, and with three it would price Anthropic's 128,000-token output
cap off Gemini's 65,536. The shell now hands it a `(provider_id, tier)`-keyed
map. Verified rather than assumed:

```
  anthropic   light/heavy  out=128,000  in=1,000,000
  gcp_gemini  light/heavy  out= 65,536  in=1,048,576
  openai      light/heavy  out=128,000  in=  400,000
```

**`connect <model_id>` stays single-provider.** Its silent "other tier for
quota fallback" bind is now scoped to the selected model's own provider.
Unscoped, with three vendors discovered, it would have bound another vendor's
other tier — and `_fallback_client` answers "the other connected tier of the
same provider", so that would have handed the forbidden cross-vendor hop a
route back in through the shell. `connect claude-opus-5` binds
`('anthropic','heavy')` and `('anthropic','light')` and nothing else.

## Two deviations from the plan, both deliberate

**The plan said `do_connect` would call `build_clients(provider_id)`. It does
not.** `build_clients` reads each tier's `api_key_env` from the manifest, which
means it cannot see a legacy single `GEMINI_API_KEY` — using it would have
silently dropped support for that variable. The shell instead builds from its
own discovered rows, which carry the env var that was actually found, and takes
only the *class* from the registry. `build_clients` remains what
`providers probe` uses, where no legacy path applies.

**`EVENTMILL_MCP_TRANSPORT` no longer reaches the client.** `transport` is a
vestige of the abandoned MCP framing: `GeminiClient` stores it and propagates
it through `with_model()`, and no request path reads it. `build_clients` has
never passed it, so every probed client already defaulted to `"stdio"`.
`tests/framework/test_provider_seam.py:52` names a client that needs
`transport` as a seam violation, so dropping it from the connect path moves
with that work rather than against it. The env var is still documented in
`.env.example` and `docker-compose.yml`; a separate pass should remove it,
along with the other MCP-era names an earlier spec review already flagged.

## The guard test was rewritten, not deleted

`TestOnlyGeminiIsBoundForToolExecution` asserted that exactly one provider
could be bound. That was correct while `_clients` was keyed by tier alone — a
second vendor under `"heavy"` evicted Gemini Pro — and the rekey removed the
hazard, so the *premise* is now stale. The *subject* is not, and it protects an
operator rather than a data structure. It becomes
`TestOnlyConfiguredProvidersAreBound`, and the assertions that matter are:

| Test | What it holds |
|---|---|
| `test_a_mounted_key_is_not_a_bound_provider` | all four keys present, only Gemini configured, only Gemini bound — the Cloud Run steady state exactly |
| `test_every_configured_provider_binds_its_own_tiers` | six clients, each `provider_id` matching its key, each `model_id` matching its manifest |
| `test_each_provider_is_clamped_by_its_own_manifest` | no vendor's output cap is read off another's |
| `test_the_first_configured_provider_serves_by_default` | order in the env var is the operator's statement of which vendor serves a tool that names none |
| `test_a_placeholder_key_binds_nothing` | the unadopted-vendor steady state binds nothing |
| `test_probing_another_provider_does_not_bind_it` | unchanged — `providers` stays read-only |

## Also

Three CLI footers said things that had become false: `providers` and `models`
both claimed only one provider is bound for tool execution, and the "no models
configured" hint named Gemini's two key variables as though they were the only
ones. The hint now points at `providers`, which already renders exactly that
per-vendor table.

## Verified

- **1059 passed**, none skipped, none xfailed.
- Offline, against dummy keys: six bindings, correct per-provider caps,
  `connect claude-opus-5` scoped to Anthropic, an unknown provider id logged
  without stopping startup, a `placeholder` key binding nothing.
- No network call was made. `connect` cannot answer reachability on any
  provider — that is `providers probe`, unchanged here.
- `ruff` / `black` / `mypy` are not installed in this venv, so none was run.
  No added line exceeds the 88-column limit.

## Not done — the rest of the plan

Stage B (`use <provider> [for <tool>]`, and `shell.py:2786` passing
`default_provider`) is what makes a *module* reachable by a second vendor.
Until it lands, every tool still runs on the default provider — now the first
entry of `EVENTMILL_LLM_PROVIDERS` rather than Gemini by construction. Stage C
(run record `provider` is still the hardcoded `"gcp_gemini"`) and Stage D (the
group summary's provider dimension) are untouched.
