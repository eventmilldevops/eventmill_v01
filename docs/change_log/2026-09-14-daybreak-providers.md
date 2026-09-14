# Change Log — two Daybreak providers, and the vendor/provider split they forced

**Date:** 2026-09-14
**Branch:** `llm_5`
**Primary Files Modified:**
`framework/llm/providers/openai_daybreak_red.json` (new),
`framework/llm/providers/openai_daybreak_blue.json` (new),
`framework/llm/providers/__init__.py`, `framework/llm/factory.py`,
`framework/llm/dispatcher.py`, `framework/llm/clients/{openai,anthropic,gemini}.py`,
`framework/plugins/protocol.py`, `framework/cli/shell.py`,
`plugins/threat_modeling/adversary_path_projector/tool.py` and its
`schemas/projection_run.schema.json` and `tests/test_contract.py`,
`tests/framework/test_provider_vendor_identity.py` (new),
`tests/framework/test_provider_registry.py`,
the six `cloud_install/` deploy surfaces, `.env.example`, `docker-compose.yml`

**1121 tests pass** (was 1095; +26). `RUN_RECORD_SCHEMA_VERSION` 4 → 5.
34 schemas validate; every `cloud_install/` script passes `bash -n`. The 15
pre-existing `validate_manifests.py` stability errors are unchanged — nothing
here touches plugin manifests.

---

## What landed

Two new providers, `openai_daybreak_red` and `openai_daybreak_blue`, each
declaring its own model under **both** tiers and reading a single shared
credential in `OPENAI_DAYBREAK_API_KEY`. They are ordinary providers: the
three-state registry (known / configured / available), `use <provider> for
<tool>`, `providers probe`, and the placeholder-seeded deploy shape all apply
unchanged.

```
gcp_gemini             vendor=google     gemini-3.8-flash / gemini-3.1-pro-preview
anthropic              vendor=anthropic  claude-sonnet-5  / claude-opus-5
openai                 vendor=openai     gpt-5.6-terra    / gpt-5.6-sol
openai_daybreak_red    vendor=openai     gpt-daybreak-red-latest   (both tiers)
openai_daybreak_blue   vendor=openai     gpt-daybreak-blue-latest  (both tiers)
```

## Why both tiers name the same model

This was the design question, and the alternative was worse in three separate
ways.

Declaring one tier would have left every `for tier in ("light", "heavy")` loop
in the framework handling a case that no other provider produces. It would have
left a light-tier plugin reaching Daybreak only through `_route`'s
take-any-connected-tier fallback — which works, by accident rather than by
intent. And it would have made `_fallback_client` a hazard: that function
returns *the other tier of the same provider* on a quota or access error, so
with one model per tier a Red run could have been silently served by something
else, inside the exact comparison the providers exist to make.

With both tiers on one model, the fallback is a wasted retry against the
identical model on the identical key, and then an honest failure. Neither
colour declares a `fallback_model_id`: the only correct substitute for this
model is this model.

The rejected alternative — Red as `heavy` and Blue as `light` of one provider —
fails immediately. The projector hardcodes `tier="heavy"`, so Red would always
win, and `_fallback_client` would swap in Blue on a 429 without saying so.

## The part that was forced

`OpenAIClient.provider_id` was a class attribute. Reusing that class for a
second provider id breaks four things at once, none of them cosmetic:

- **Attribution.** The client stamps `provider_id` on every response and
  `_attributed` deliberately preserves an existing stamp. Every Daybreak run
  would have been recorded as `provider: "openai"`.
- **Capabilities.** `supports()` calls `load_tier_specs(self.provider_id)` —
  it would read `openai.json` while talking to a Daybreak model.
- **Reasoning clamp.** `_effort()` read the module-level `PROVIDER_ID`, so
  `thinking_levels` came off the wrong manifest.
- **Probe budget.** `ping_budget()` sized the ping from the wrong reserve.

So `provider_id` is now a constructor argument on all three clients, defaulting
to each one's existing class attribute, and both construction paths —
`factory.build_clients` and `shell._build_client` — pass it. The dispatcher
needed no change: the shell already keys the client map by explicit
`(provider_id, tier)` tuples, and `_spec_of` looks up by identity.

Six clients across three OpenAI-backed providers now bind concurrently with
none evicting another.

## Vendor is now a separate question from provider

Three provider ids reach one lab. `vendor` is a new manifest field on all five
providers, read through `vendor_of()`, filled onto `LLMResponse.vendor` by the
dispatcher's `_attributed` — derived once, centrally, rather than asked of
every client, because asking each client to remember which lab it speaks for is
how attribution drifts. That is the mistake the class-level `provider_id` had
already made.

The projector records it (`model.vendor`, schema v5).

**`_agreement_grade` still counts provider ids, deliberately.** It grades how
far a route's support extends, and whether two models from one lab count as one
opinion or two is an empirical question: shared training lineage argues they
correlate, while a deliberately adversarial Red/Blue pair argues the opposite.
The field is captured now so the grading can be decided on evidence later. A v4
record carries no vendor and must not be given one by guesswork at read time.

## Also fixed in passing

- The SDK install hint was derived from the provider id, so it told operators
  to `pip install 'eventmill[llm-gcp_gemini]'` — an extra that does not exist,
  since `google-genai` is a base dependency. It would have said
  `eventmill[llm-openai_daybreak_red]` next. Now a `PROVIDER_SDK_INSTALL` map,
  with a test that every target it names is an extra `pyproject.toml` defines.
- `project_paths`' `LLM_UNAVAILABLE` message still told operators to set
  `GEMINI_PRO_API_KEY`. It now points at `providers`.
- `load_provider_manifest`'s LRU cache went from 8 to 16 entries.

## Unverified, and deliberately marked so

Both manifests carry `"_verified": "UNVERIFIED"`. The model aliases, token
limits, accepted reasoning levels and capability list are **documented or
inherited, not probed** — unlike `openai.json`, whose every number came from a
live 400 or a live ping. `capabilities` is deliberately short: `multimodal_image`,
`function_calling` and every document capability are omitted rather than
assumed, because an unverified capability token is a promise the router acts
on.

Two things need confirming before a live run:

1. **The secret name.** `eventmill-anthropic-daybreak` — carried from the
   originating assessment, not present anywhere in this repo before today. Its
   `anthropic` substring is a storage label; the value is an OpenAI key wired
   to the OpenAI transport. Overridable via `EVENTMILL_SECRET_OPENAI_DAYBREAK`
   so correcting it is config, not code.
2. **The model aliases.** `providers probe openai_daybreak_red` against
   `models.list` settles them.

`connect` proves only that an SDK handle was built. `providers probe` is what
proves the key reaches the vendor.
