# Plan — a second and third model provider

**Date:** 2026-09-13
**Branch:** `llm-tiering-gemini-3x` (this work should get its own branch)
**Status:** not started. Written after the Gemini 3.8 Flash swap landed
(`9b43aa5`, `docs/change_log/2026-09-12-light-tier-gemini-3-8-flash.md`).

This plan responds to the GPT 5.6 architecture assessment. **Its shape is
adopted**: per-provider clients, a thin dispatcher, a small internal model-client
protocol, an explicit registry keyed by `EVENTMILL_LLM_PROVIDER`, per-provider
JSON manifests, no cross-provider fallback, and no universal client that
understands every vendor. That is the right decomposition and nothing below
argues with it.

What the assessment could not see is how much Gemini-specific code lives
**outside** `MCPLLMClient`. Its sequence opens with "move the Google SDK code out
of `MCPLLMClient` without changing runtime behavior" — but roughly half of that
code is in `LLMDispatcher`, some of it reaching into the client's private
attributes, and one plugin reaches past both into the provider manifest. The
stages below are the same journey with the real starting position.

---

## The seam audit — where Gemini actually lives today

| Location | What is Gemini-specific |
|---|---|
| `framework/llm/client.py:52` `_build_config` | `GenerateContentConfig`, `ThinkingLevel`, `MediaResolution` enums |
| `client.py:99/115/127` `_finish_reason` / `_model_version` / `_usage` | Google response shape (`candidates[0].finish_reason`, `usage_metadata.thoughts_token_count`) |
| `client.py:144` `MCPLLMClient` | `genai.Client`, `models.generate_content`, `Part.from_bytes`, 180 s http option |
| `client.py:382/391` `_is_quota_exhausted` / `_is_retriable` | string-matches Google's error text (`RESOURCE_EXHAUSTED`, `free_tier`, `503/429/504`) |
| **`client.py:1167` `_execute_document_query`** | **on `LLMDispatcher`, not the client** — `Part.from_uri`, `gs://`, `client._genai_client`, `client._build_prompt`, `client._is_retriable`, `client._total_tokens_used` |
| `client.py:759` `_retry_on_retired_model` | constructs `MCPLLMClient` and copies four private attributes to reuse the live connection |
| `client.py:721/726/745` error classifiers | string-matches Google's `PERMISSION_DENIED` / `NOT_FOUND` / HTTP 404 |
| `client.py:949/1022/1053` | calls `default_media_resolution()`, `pdf_handling()`, `tokens_per_pdf_page()` with **no provider argument** |
| `framework/llm/providers/__init__.py:22` | `DEFAULT_PROVIDER_ID = "gcp_gemini"`, the implicit argument to all six accessors |
| `framework/cli/shell.py:399/3426/3838` | two-tier discovery loop, legacy `GEMINI_API_KEY` binding, `isinstance(..., MCPLLMClient)`, "Set GEMINI_FLASH_API_KEY" copy |
| `plugins/log_analysis/threat_intel_ingester/tool.py:36` | imports `max_output_tokens_for_tier` and `thinking_reserve_tokens` directly from `framework.llm.providers` |

`tests/framework/test_llm_dispatcher.py:36` is corroborating evidence: `FakeClient`
has to implement `_build_prompt` because the dispatcher calls it on the client.
A fake that satisfies only the public interface does not work today.

---

## Seven decisions the assessment leaves open

### 1. The document path moves into the provider client, not out of `MCPLLMClient`

`_execute_document_query` is a `@staticmethod` on the dispatcher that operates
entirely on another object's privates. It is the single largest piece of vendor
code in the tree and it is on the wrong class.

After the split, `LLMModelClient.query_with_document(prompt, doc, ...)` is a real
method on each provider client, and the dispatcher keeps only what is genuinely
common: resolve `ArtifactRef` → `DocumentPart`, run the PDF guard, clamp tokens,
call the client, apply the retired-model retry. `_build_prompt` (grounding-data
prefixing) is provider-neutral and moves to a module function the dispatcher owns.

### 2. Rebinding a model needs a protocol operation, not a factory

`_retry_on_retired_model` does not just build a client — it clones
`_genai_client`, `_api_key_env_var`, `_connected` and `_total_tokens_used` so the
substitute reuses the live session and the token count is not lost. A factory
returning a fresh, unconnected client loses all four.

Put it on the protocol instead:

```python
def with_model(self, model_id: str) -> "LLMModelClient": ...
```

Each provider decides what carrying a connection forward means for its SDK. The
dispatcher asks for a rebound client and stays out of it.

### 3. Error classification must return a typed reason, not a string

The dispatcher's *policy* — quota or access error → try the other tier;
NOT_FOUND → try the tier's fallback model — is decided by grepping Google's error
text. Three providers means three error vocabularies, and putting all three in
the dispatcher is exactly the monolith this refactor exists to avoid.

Add `LLMResponse.error_kind: str | None` with a closed vocabulary:

```
quota | access | model_not_found | transient | context_overflow |
content_filtered | bad_request | other
```

The client classifies; the dispatcher routes on the enum. `error` keeps the raw
provider text for the operator.

**This lands in Stage 2, not Stage 4.** The assessment sequences diagnostics
after the OpenAI client; but without it, adding OpenAI *forces* OpenAI exception
handling into the dispatcher, and Stage 3 cannot be done cleanly.

### 4. Plugins already reach into provider facts — that has to be fixed here

`threat_intel_ingester` imports `max_output_tokens_for_tier` and
`thinking_reserve_tokens` at module scope and calls them with no provider
argument (`tool.py:320`, `tool.py:334`). It uses them to size how much JSON one
native call may emit. Under `EVENTMILL_LLM_PROVIDER=openai` those calls silently
return Gemini's numbers and the batching plan is wrong — the same *class* of
silent failure as the `EVENTMILL_MODEL_LIGHT` pin that made the 3.8 swap inert.

The assessment's claim that Stage 5 needs "no plugin changes" is therefore not
achievable as written. The fix is small and belongs on the interface the plugin
already holds:

```python
class LLMQueryInterface(Protocol):
    def output_budget(self, thinking_level: str | None = None) -> int: ...
    def max_output_tokens(self) -> int: ...
```

`TierScopedLLMClient` answers both for the tier the plugin will actually run on,
against the active provider. The plugin stops importing from
`framework.llm.providers` entirely. Two call sites change in one plugin.

### 5. Non-Gemini providers cannot read `gs://`, and on Cloud Run that is the whole document path

Gemini reads a GCS URI zero-copy. OpenAI and Anthropic cannot; they need bytes.
On Cloud Run `ArtifactRef.storage_uri` is a `gs://` URI and `file_path` may not
exist locally, so for those providers **the bytes have to be fetched first** —
egress, latency, and memory the Gemini path never pays.

Fetching from GCS is a framework concern (`framework/cloud/resolver.py`), not an
SDK concern. So:

- add a capability token `remote_uri_gs` to the manifest `capabilities` list;
- when the selected client does not declare it, the dispatcher materialises the
  artifact to bytes before building the `DocumentPart`;
- `DocumentPart` gains a lazy `read_bytes()` so the fetch happens once, and only
  when a client actually needs it.

This also makes `_pdf_context_overflow` (`client.py:1009`) more load-bearing, not
less: Anthropic's per-request PDF page and size limits are far below Gemini's
1000 pages / 50 MB, so the guard must read the **active** provider's
`file_handling` block. It currently reads Gemini's unconditionally.

### 6. `output_budget` becomes per-tier when the second provider lands

The 2026-09-12 change log recorded a deliberate decision to keep `output_budget`
and `file_handling` provider-global, on the evidence that 3.8 Flash and 3.1 Pro
agree. That holds within one Gemini generation. It is much less likely to hold
where a provider's light tier is a non-reasoning model and its heavy tier is a
reasoning model — the reasoning reserve is then structurally different per tier,
not incidentally different.

So: keep the global block as the default, and let a tier entry override it. That
is a loader change plus a `tier` argument on the accessors in
`framework/llm/providers/__init__.py`, and it should land with Stage 2 rather
than waiting for evidence that arrives as a truncated reply.

The concept itself is portable — all three families spend reasoning tokens from
the same budget as the reply — so the table survives the move. Only the numbers
and the knob name change.

### 7. `MCPLLMClient` gets renamed, with no compatibility alias

The name has been wrong since the MCP transport was deferred; its own docstrings
say "until full MCP transport is integrated". It becomes `GeminiClient`. Nothing
outside this repo imports it, the 945-test suite catches the six call sites
(`framework/llm/__init__.py`, `shell.py` ×4, the dispatcher), and keeping an
alias preserves a name that lies about what the class does.

`framework/llm/client.py` becomes `framework/llm/dispatcher.py` in the same move
— once the Gemini code leaves, `client.py` names a file that contains no client.

---

## Target layout

```
framework/llm/
  dispatcher.py            LLMDispatcher, TierScopedLLMClient, ContextBuilder
  model_client.py          LLMModelClient Protocol, error-kind vocabulary
  factory.py               PROVIDER_CLIENTS registry, build_clients()
  clients/
    gemini.py              GeminiClient    — google.genai
    openai.py              OpenAIClient    — Responses API
    anthropic.py           AnthropicClient — Messages API
  providers/
    __init__.py            provider-aware manifest loading
    gcp_gemini.json
    openai.json
    anthropic.json
  backends/base.py         DocumentPart (+ lazy read_bytes)
```

---

## Stages

### Stage 0 — lock the seam before moving anything — **DONE 2026-09-13**

No production code changes. `tests/framework/test_provider_seam.py` pins the
behaviour the refactor must preserve against `PublicOnlyClient`, a fake
implementing **only** the public model-client interface — no `_build_prompt`, no
`_genai_client`, no `transport`. Ten of those pass today (routing, clamping, tier
fallback, the PDF guard, capability checks): that is the part of the dispatcher
already provider-neutral. Seven are `xfail(strict=True)` and are Stage 1's
definition of done.

The SDK invariant is checked by parsing the dispatcher module's import
statements with `ast` rather than by blocking `sys.modules`. The latter does not
work: `client.py` wraps its `google.genai` import in `try/except ImportError`, so
a blocked SDK leaves the module importing cleanly and the test would pass while
the coupling was still there. Import-tree inspection also tolerates a comment
mentioning Google Cloud Storage, which the dispatcher legitimately keeps.

`scripts/make_probe_pdf.py` is rebuilt and committed, with
`tests/framework/test_probe_corpus.py` holding it to the 09-12 inventory.

**Done:** 965 passed, 7 xfailed (was 945). Each xfail fails at exactly the
coupling its `reason` names — `client.py:981` (`_build_prompt`), `client.py:789`
(`transport`), and the absent `framework/llm/dispatcher.py` — enforced by
`raises=`, so none of them can pass for the wrong reason or fail for an
unrelated one.

### Stage 1 — extract `GeminiClient`, behaviour unchanged

Move `_build_config`, the three response readers, both error classifiers, and
`_execute_document_query` into `clients/gemini.py`. Rename the class. Rename
`client.py` → `dispatcher.py`. Add `with_model()`. Add `error_kind` to
`LLMResponse` and populate it from the Gemini classifiers. The dispatcher's
`_should_try_other_tier` / `_is_model_not_found` start reading `error_kind`,
keeping the string matchers only as a fallback for a client that reports none.

**Done when:** Stage 0's tests pass, the SDK-blocked import test passes, and the
full suite is green with no behavioural diff. No manifest, no new provider.

### Stage 2 — generalise construction

`LLMModelClient` protocol. `PROVIDER_CLIENTS` registry in `factory.py`.
`EVENTMILL_LLM_PROVIDER` (default `gcp_gemini`). Thread `provider_id` through
every accessor in `providers/__init__.py` and through the dispatcher's four
unqualified calls. Per-tier override of `output_budget` / `file_handling`.
`LLMQueryInterface.output_budget()` / `.max_output_tokens()`, and cut
`threat_intel_ingester` over to them. Add the `remote_uri_gs` capability and
dispatcher-side byte materialisation. Rework `_discover_models` and `do_connect`
to be provider-driven, and make `connect` print **provider, tier, model, and key
env var** — the 3.8 swap's most expensive lesson was a silently inert change, and
a provider switch has strictly more ways to be half-applied.

**Done when:** with `EVENTMILL_LLM_PROVIDER=gcp_gemini` the suite is green and
live behaviour is unchanged; with the variable set to an unknown id the shell
refuses to start with a named error rather than falling back to Gemini.

### Stage 3 — `OpenAIClient`

`openai.json` plus the SDK in a new `llm-openai` extra. Implement in order: text
→ structured output → images → documents. Own the Responses API construction,
`reasoning.effort`, `text.format`, `input_image` / `input_file`, status and usage
parsing, exception → `error_kind` classification, and **`store=False`** — this
platform handles incident data, and the no-retention posture is a declared
property of the client, recorded in the manifest, not an incidental default.

Map the portable hints: `thinking_level` → `reasoning.effort` where there is a
defensible equivalent, `media_resolution` → detail where one exists, and log a
diagnostic where there is not. Neither mapping appears in the dispatcher.

**Done when:** the provider probe below passes.

### Stage 4 — normalise response diagnostics

Every provider returns provider id, requested model, reported model, normalised
usage (prompt / completion / reasoning / total), finish reason, truncation, and
`error_kind`. Add `provider_id` to `LLMResponse` and to the projector's run
record (`model` block, `RUN_RECORD_SCHEMA_VERSION` 3 → 4) — a cross-provider
comparison is unreadable without it.

Most of the mechanism lands in Stages 1–3; this stage is where the vocabulary is
proven consistent across two real providers and the record format is fixed.

### Stage 5 — `AnthropicClient`

New client, manifest, registry entry, `llm-anthropic` extra, tests. **If this
stage touches `dispatcher.py`, `TierScopedLLMClient`, any plugin, or any prompt,
the abstraction is in the wrong place and that is the finding.** Anthropic is the
honest test precisely because it is third — its API differs from both.

Watch the PDF limits: they are the tightest of the three and will exercise
`_pdf_context_overflow` in a way Gemini never has.

### Stage 6 — deployment

Parameterise the secret wiring, which currently names Gemini in five places
(`cloud_install/deploy-cloudrun-secrets.sh:129`, `deploy-cloudrun.sh:96`,
`provision-secrets.sh:207`, `setup-deploy-server.sh:108`, and the README env
table). The selected provider's key secret, and only that one, gets mounted. The
container build installs the selected provider's extra.

---

## The acceptance instrument exists as a method, but not as code — fix that first

The 3.8 swap built exactly the right tool: `make_probe_pdf.py`, which emits a
3-page synthetic report with an **exact** 94-indicator ground truth (24 IP, 20
domain, 16 sha256, 12 URL, 10 CVE, 12 technique), turning "did the two agree"
into "how much did each one find".

**It was never committed.** `git log --all -- "*probe*"` is empty; the script
lived in a scratch directory and only its output survives, in the 09-12 change
log. The same is true of the `stepstate-medium-2` run artifacts — the numbers are
recorded in `docs/change_log/2026-09-11-live-run-findings.md:158`, the artifacts
are not in the tree.

**Rebuilt and committed in Stage 0** as `scripts/make_probe_pdf.py`, reproducing
the 94 / 82 inventory. Two things about it are choices rather than
reconstructions, because the original is gone and only its counts were recorded:

- **Reserved names throughout** — RFC 5737 addresses, RFC 2606 TLDs. Right for a
  fixture in a security repository, but a model may rank a `.invalid` host as
  obvious test data and decline to report it. That would depress absolute recall
  equally for every provider, so comparisons still hold; if a baseline run cannot
  reproduce 82/82 non-technique recall, this is the first knob to turn.
- **The document is generated, not stored.** No PDF dependency: `fpdf2` is in the
  network-forensics extra and `reportlab` is not a dependency at all, and a
  fixture generator that only runs under one optional extra stops being run. It
  writes uncompressed Helvetica text directly, which is what the extraction path
  reads anyway.

The run artifacts are still not in the tree and this plan does not put them
there; `stepstate-medium-2` remains a table in a change log.

Run it against each new provider on the light tier at equal reasoning effort and
report the same table the 09-12 entry used: wall time, plan chosen, IOC records,
ground-truth recall, documented techniques recalled, techniques inferred beyond
the document, `tactic_mismatch`, `finish_reason`, truncation. A provider that
cannot reach 82/82 on the non-technique indicators is not interchangeable for the
ingester's work, whatever else it does well.

For the heavy tier, the projector's `stepstate-medium-2` baseline is the
comparison, and **rejections is the number that matters**.

## Stage 0 facts to confirm per provider, before writing a line of client code

The 3.8 swap's Stage 0 pattern, applied to a provider instead of a model. For
each candidate, against the live API: model ids for both tiers; GA or preview;
context and output limits per tier; whether reasoning tokens are drawn from the
output budget and what the reserve is per effort level; native PDF support, page
limit, size limit and per-page token cost; whether a remote object-store URI can
be referenced or bytes are mandatory; the structured-output mechanism; whether
the served model id is reported back; and the data-retention default and how to
disable it.

Every one of those is a manifest field. None of them belongs in Python.

---

## Out of scope, deliberately

- **Cross-provider fallback.** A process started on OpenAI must not send
  investigation data to Google or Anthropic because a quota ran out. Fallback
  stays within the active provider's two tiers. This is a data-handling
  boundary, not a routing convenience.
- **Mixing providers across tiers** (light on one vendor, heavy on another).
  Same reason, plus it makes every comparison unattributable.
- **Retiring `thinking_level` / `media_resolution` from `QueryHints`.** They stay
  for compatibility; `GeminiClient` consumes them, others map or ignore with a
  diagnostic. A portable-intent vocabulary can come later, with evidence.
- **Prompt changes.** Prompts must stay byte-identical across a provider swap or
  the comparison means nothing — the same rule the 3.8 swap held to.
- **Adopting `structured_output`.** Still declared and unused, for the reasons
  recorded on 2026-09-12. If a provider produces *parse failures*, the narrow fix
  is a JSON mime type, not a schema.
- **The heavy-tier Gemini swap (Stage B of the 3.8 plan)** and **projector Phase
  4**. Both still outstanding; neither blocks nor is blocked by this work.

## Rollback

Stages 1–2 are a pure refactor: revert the commit. From Stage 3 on, the rollback
is `EVENTMILL_LLM_PROVIDER=gcp_gemini`, which is the default — a broken new
provider client cannot affect the Gemini path, because it shares no code with it.
That property is the point of the design and should be stated in `AGENTS.md`.
