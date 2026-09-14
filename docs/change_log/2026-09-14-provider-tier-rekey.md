# Change Log — the (provider_id, tier) rekey

**Date:** 2026-09-14
**Primary Files Modified:** `framework/llm/dispatcher.py`,
`framework/cli/shell.py`,
`tests/framework/test_provider_routing.py` (new),
`tests/framework/test_llm_dispatcher.py`, `tests/framework/test_provider_seam.py`,
`tests/framework/test_provider_registry.py`

**1056 tests pass** (was 1036; +20). Stage 2 of
`docs/specs/multi_provider_llm_clients.md` — the half the plan says must land
first. Several providers can now be bound and selected concurrently.

---

## What this makes possible

Six clients bound at once, one prompt, three vendors, each answer attributed:

```
bound providers: ('gcp_gemini', 'anthropic', 'openai')
   gcp_gemini  light  gemini-3.8-flash      heavy  gemini-3.1-pro-preview
   anthropic   light  claude-sonnet-5       heavy  claude-opus-5
   openai      light  gpt-5.6-terra         heavy  gpt-5.6-sol

-- same prompt, each vendor, heavy tier, through the scoping wrapper --
  gcp_gemini  gemini-3.1-pro-preview  ok=True  tok=556
  anthropic   claude-opus-5           ok=True  tok=123
  openai      gpt-5.6-sol             ok=True  tok=41
```

That is the recorded requirement working: *"running the projector across three
vendors on the same flow map for a diversity of opinion."* The prompt is
byte-identical across the swap, which is the precondition for the comparison
meaning anything.

## The change

`LLMDispatcher._clients` is keyed by `(provider_id, tier)`. Keyed by tier it
could not express the state at all — a second vendor's client registered under
`"heavy"` **evicted** the first vendor's heavy model and silently rerouted every
heavy plugin. That is why Stage 2a refused to bind anything but Gemini, and why
this had to land before anything else in Stage 2.

- `_route()` resolves **provider first, then tier**, and never falls through to
  another vendor.
- `_tier_of` becomes `_locate() -> (provider_id, tier)`; `_tier_of` remains as a
  thin wrapper. New `_spec_of(client)` looks a tier spec up by the client's own
  provider — reading it by tier alone would price Anthropic's 128k output cap
  off Gemini's 65,536.
- `connected_models()` reports `provider_id` alongside tier.
- `bound_providers()`, `default_provider` and `client_at(tier, provider)` are new.
- `_prefer_native_capable` is scoped to one provider: Gemini reading PDFs
  natively says nothing about another vendor's tier.

### Backward compatibility was the design constraint

A tier-keyed dict is still accepted and normalised, because **each client
already knows its own `provider_id`**. That is what kept the change inside
`dispatcher.py` instead of rippling through the shell, both deploy paths and a
thousand-test suite. Every existing caller — including `do_connect` — passes the
old shape and is unaffected.

`TestSingleProviderBehaviourIsUnchanged` pins that: a one-vendor session must
not be able to tell this happened.

## The data-handling boundary

`_fallback_client` now answers *"the other connected tier **of the same
provider**"*. This is the one place the boundary lives, and it is a three-line
constraint rather than a policy spanning the design:

| | Who chose | Recorded on the output | Verdict |
|---|---|---|---|
| Automatic fallback on quota | nobody | no | **forbidden** |
| Deliberate provider selection | the operator | yes, `provider_id` | **the requirement** |

Four tests hold it, the sharpest being
`test_a_provider_with_no_healthy_tier_fails_rather_than_hopping`: both tiers of
one provider exhausted, another bound and healthy, and the call **must still
fail**. Answering from the healthy vendor is precisely the silent failover this
forbids — investigation data would reach a provider nobody selected and the
result would be unattributable afterwards.

## Provider scope rides the wrapper, never QueryHints

`TierScopedLLMClient` gains `default_provider`. A `provider` field on
`QueryHints` would be wrong twice: it would put vendor selection in plugin code,
breaking "the analysis tools do not change", and it would let a plugin override
an operator's A/B choice. `test_a_plugin_cannot_reach_the_provider_argument`
asserts the wrapper's signature exposes no `provider` at all.

The dispatcher's query methods take `provider: str | None = None`, supplied by
the wrapper and duck-typed on `accepts_provider_scope` so the same wrapper still
works around a bare client or a test fake that takes no such argument.

## Two bugs found while building it

**A spec map keyed by the wrong provider fails silently.** A tier-keyed
`tier_specs` dict took its provider from the spec objects while a tier-keyed
client dict took it from the clients. When those disagree — a caller building
`TierSpec` values by hand gets the default `provider_id` while its clients
declare their own — every lookup missed. Nothing raised: clamping fell back to
defaults and the retired-model retry quietly stopped happening. A tier-keyed
spec map now attaches to the providers actually bound, which is what it meant.
Caught by an existing seam test, not by a new one.

**A response with no `provider_id` is unattributable.** Every real client stamps
its own, but a client that simply forgot would produce output nobody could trace
to a vendor — the exact failure the requirement exists to prevent. The
dispatcher now stamps it as a backstop when absent, never overriding a client's
own. Attributing to the routed client stays correct after a tier change or a
retired-model substitution, since both are same-provider by construction.

## Also

`shell.py`'s `models` command read `_clients.get(tier)` directly; it now uses
`client_at(tier, provider)`. Seven test call sites did the same and moved to the
same accessor — they were asserting on a private key shape, which is exactly
what changed.

## Verified

- **1056 passed**, none skipped, none xfailed.
- Live: three providers bound concurrently, both tiers each, one prompt routed
  to each vendor's heavy tier through `TierScopedLLMClient`, every response
  carrying the `provider_id` that served it.
- `ruff` / `black` / `mypy` are not installed in this venv, so none was run.

## Not done — the rest of Stage 2

The rekey was the separable half. Still outstanding:

- **Accessor threading.** `pdf_handling()` and `tokens_per_pdf_page()` are still
  called with no `provider_id` in the PDF guard, so it reads Gemini's 1000-page
  / 50 MB limits whatever provider is selected. Anthropic's are 100 / 32 MB.
- `LLMQueryInterface.output_budget()` / `.max_output_tokens()`, and cutting
  `threat_intel_ingester` over — it imports the provider helpers directly and
  calls them with no provider argument (`tool.py:320`, `:334`).
- Per-tier `output_budget` override; `thinking_reserve_tokens` is still global.
- `remote_uri_gs` capability plus dispatcher-side byte materialisation, which is
  what gates the document path for the two non-Gemini providers.
- `_model_supports_native_doc` reads the manifest rather than `client.supports()`.
- The CLI half: `use <provider> [for <tool>]`, and `shell.py:2786` does not yet
  pass `default_provider` — so the plumbing is in place and nothing selects a
  provider per module yet.
