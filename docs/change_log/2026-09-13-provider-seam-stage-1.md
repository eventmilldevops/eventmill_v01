# Change Log — Stage 1, extracting `GeminiClient`

**Date:** 2026-09-13
**Primary Files Added:**
`framework/llm/model_client.py`,
`framework/llm/clients/__init__.py`,
`framework/llm/clients/gemini.py`

**Primary Files Modified:**
`framework/llm/client.py` → `framework/llm/dispatcher.py` (renamed),
`framework/llm/__init__.py`,
`framework/llm/backends/base.py`,
`framework/plugins/protocol.py`,
`framework/cli/shell.py`,
`tests/framework/test_provider_seam.py`,
`tests/framework/test_llm_dispatcher.py`

Plan: `docs/specs/multi_provider_llm_clients.md`.

**974 passed, 0 xfailed** (was 965 passed, 7 xfailed).

Stage 1 is a refactor: the Google SDK left the dispatcher, and the dispatcher
now talks to whatever it holds through one interface. Behaviour is unchanged,
and that claim is checked live rather than asserted — see *Verified against the
API* below.

---

## Definition of done, met

Stage 0 wrote this stage's acceptance criterion as seven `xfail(strict=True)`
tests. All seven pass, the markers are gone, and
`test_the_current_dispatcher_module_does_import_one` — the test that asserted the
defect rather than the requirement, and said so in its own docstring — is
deleted.

The run that confirmed it, before any marker was touched:

```
16 passed, 1 failed    (--runxfail)
FAILED ...::test_the_current_dispatcher_module_does_import_one
```

That is exactly the right shape: every requirement test passing, and the only
failure the one whose whole purpose was to stop being true.

## What moved, and what deliberately did not

`clients/gemini.py` took `_build_config`, the three response readers
(`_finish_reason`, `_model_version`, `_usage`), both error classifiers,
`_build_prompt`'s job, both `_execute_mcp_*` methods, and
`LLMDispatcher._execute_document_query` — which was a `@staticmethod` on the
dispatcher operating entirely on another object's privates, and is now
`GeminiClient.query_with_document`, a real method on the object that owns the
SDK handle.

`dispatcher.py` kept what is genuinely policy: routing, tier preference, output
clamping, the PDF size and context guards, artifact → `DocumentPart` resolution,
and the retired-model retry. `grep` for `genai`, `google`, `_genai_client` or
`_build_prompt` in it returns nothing, and `test_the_dispatcher_imports_no_vendor_sdk`
keeps it that way with an `ast` walk over its imports.

Three things stayed put on purpose:

- **`_model_supports_native_doc` still reads the provider manifest**, not the
  new `client.supports()`. Group A's
  `test_native_capability_comes_from_the_manifest_not_the_sdk` pins the manifest
  as the capability authority, and rewiring routing is a behaviour change, which
  this stage does not make. `supports()` exists on the client because the
  protocol declares it; Stage 2's registry is its first caller.
- **`_tier_of` still reverse-looks-up the tier** from `self._clients` rather than
  reading the new `client.tier`. Same reason.
- **`pdf_handling()` and `tokens_per_pdf_page()` are still called with no
  provider argument.** That is decision 5 in the plan and it belongs to Stage 2;
  it is harmless while one provider exists and wrong the moment two do.

## `grounding_data` does not cross the document seam

The one design question the extraction actually forced. `PublicOnlyClient.query_with_document`
takes no `grounding_data` parameter, and the Stage 0 test that asserts grounding
data reaches the client on the document path only asserts that the call
*succeeds* — so a dispatcher passing `grounding_data=` as a keyword would have
failed against the fake with a `TypeError`.

That is the fake stating the contract: composing grounding context into a prompt
is string assembly, not a request shape, and no provider needs a say in it. So
`compose_prompt()` lives in `model_client.py`, the dispatcher calls it and hands
the client a composed prompt, and `query_with_document` stays about the
document. The text path is unchanged — `query_text` still takes `grounding_data`
and each client composes it, because the protocol declares it there.

## `error_kind` — landed here, not deferred

The plan allowed Stage 1 or Stage 2. Landing it now means Stage 3 plugs OpenAI
into a socket instead of doing a refactor under pressure.

`LLMResponse` gained two fields, both additive and both defaulting to `None`:
`error_kind` (from the closed vocabulary in `model_client.py`) and `provider_id`.
`GeminiClient.classify_error` is the only place Google's wire vocabulary is read.
Order matters inside it, and the comment says why: a retired preview returns
NOT_FOUND *alongside* a 404, and quota exhaustion carries RESOURCE_EXHAUSTED
*alongside* a 429, so the specific classification has to be tested first.

The dispatcher's `_kind_of(result)` prefers what the client decided and falls
back to the old string matching when a client classified nothing. `_should_try_other_tier`
and `_retry_on_retired_model` now take the `LLMResponse` rather than a bare
string, and route on the enum. Two new tests cover both directions: a failure
whose *text* says nothing about a retired model but whose `error_kind` does
still substitutes, and an unclassified failure still falls back to the text.

Keeping the string classifiers is not politeness to old code. `LLMDispatcher._is_model_not_found`
has three tests pinning a false-positive class that costs a whole session — a
"404" in a request id or a byte offset must not rewrite the tier's model — and
the fallback is what any provider client that has not classified a failure lands
on.

## `with_model()` replaces the four-attribute clone

`_retry_on_retired_model` used to construct `MCPLLMClient` by name and copy
`_genai_client`, `_api_key_env_var`, `_connected` and `_total_tokens_used` across.
It now calls `client.with_model(spec.fallback_model_id)` and lets the provider
decide what carrying a live session forward means. `GeminiClient.with_model`
reuses the SDK handle and carries the spend, because `total_tokens_used` sums
over the live clients and a substitute starting at zero would undercount the
session — the property Stage 0 wrote a test for and this stage now satisfies
without a monkeypatch.

`test_document_query_retries_on_a_retired_model` was rewritten as a consequence:
it used to monkeypatch both `_retry_on_retired_model` and `_execute_document_query`,
and now runs the whole path unmocked, from the heavy client's 404 through
`with_model()` to the substitute serving the retry and the tier staying rebound.

## `MCPLLMClient` is gone, with no alias

Per plan decision 7. The name described an MCP bridge that was deferred and
never arrived, while the class talked to Gemini directly. Six call sites outside
the module, all in `shell.py` and `framework/llm/__init__.py`.

`shell.py` also stopped assigning `client._api_key_env_var` after construction:
the tier and the key env var are both known at the call site, so they are
constructor arguments now. Annotations there name `LLMModelClient`; only the
three construction sites name `GeminiClient`, which is where a provider registry
replaces them in Stage 2.

## Verified against the API

The 09-12 lesson was that a live check is cheap and was available all along, and
that a change can be correct in source and inert in the environment. Both tiers
bound from the repo `.env` and ran:

| Path | Result |
|---|---|
| `query_text` (light) | `ok`, `model_version=gemini-3.8-flash`, `provider_id=gcp_gemini`, `finish=STOP` |
| `query_text` + `grounding_data` | grounding reached the model — it answered from context only |
| `TierScopedLLMClient` | manifest tier applied, routed, served |
| 400 `INVALID_ARGUMENT` | `error_kind='bad_request'`, and correctly **not** a tier change |
| `query_with_document` | `ok`, `transport_path=inline_bytes`, 2,553 tokens, `finish=STOP` |

The document run scored **82/82 non-technique recall** against
`scripts/make_probe_pdf.py`'s exact inventory. That is the 09-12 baseline
reproduced through the moved code, and it also answers the open question Stage 0
left: the rebuilt corpus does reproduce 82/82, so the RFC 5737 / RFC 2606
reserved-name concern is not depressing recall on this model. The regenerated
PDF was 8,021 bytes over 3 pages, byte-identical to the Stage 0 record.

One finding, unrelated to the refactor: **`gemini-3.8-flash` rejects
`thinking_level="minimal"`** with `400 INVALID_ARGUMENT — Thinking level MINIMAL
is not supported for this model`. `_THINKING_LEVELS` in the client accepts it and
`QueryHints` documents it as valid, so a plugin asking for `minimal` on the light
tier fails the call outright rather than being clamped. No plugin currently does.
Not fixed here — it is a provider-manifest question (which levels a tier
actually supports), which is Stage 2's territory.

## Confirmed on Cloud Run — 2026-09-13

The operator deployed and exercised the refactored layer on the container and
reported it working: **Gemini runs unchanged through the extracted client, and
the dispatcher's decoupling from the vendor holds in the deployed environment**,
not only in the test suite and the local live run.

That closes the gap this change log opened. The local verification could only
reach the `inline_bytes` ingestion branch, because a local artifact has no
`gs://` URI; the container is the only place the `gs_uri` branch runs. Stage 1
moved that code off the dispatcher, so a deployed run was the last untested
piece of the move.

## Not done here

- **No behaviour change.** No routing, clamping or guard logic was altered.
- **No provider registry, no `EVENTMILL_LLM_PROVIDER`, no second client.** Stage 2
  and Stage 3.
- **`ruff`, `black` and `mypy` are not installed in this environment**, as on
  2026-09-12 and in Stage 0. Style matched by hand; the 88-character limit was
  checked directly. All over-long lines in the touched files are pre-existing —
  `shell.py` had 82 before this change and has 82 after — and three that were
  over 88 in `client.py` are now wrapped.
- **`validate_manifests.py` is untouched** and still reports its pre-existing
  errors.
- **`openai` 1.58.1 is installed and has no `.responses`.** The Responses API
  that Stage 3 specifies landed in 1.66, so the `llm-openai` extra needs
  `openai>=1.66` and this environment needs an upgrade before Stage 3. Neither
  `openai` nor `anthropic` is declared in `pyproject.toml` today — both are
  ambient in this venv. `anthropic` 0.111.0 is current. Both keys authenticate
  against their `models.list`.
