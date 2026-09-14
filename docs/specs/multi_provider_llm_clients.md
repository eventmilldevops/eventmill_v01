# Plan — a second and third model provider

**Date:** 2026-09-13
**Branch:** `llm_multi`
**Status:** Stage 0 (`1d31b54`), Stage 1 (`3464b69`) and the secret-wiring half
of Stage 6 (`52e3a10`) all done 2026-09-13 and verified on Cloud Run. **Part 1
Stage 2 next** — the `(provider_id, tier)` rekey is the piece that must land
first.

**Revised 2026-09-13** after the operator corrected a premise: concurrent
multi-vendor operation and per-module provider override were requirements from
the start, not deferrable extensions. Decisions 8 and 9 are new, Stages 2, 5 and
6 are rewritten, and two items move out of "out of scope" into "in scope,
corrected". Stages 0 and 1 are unaffected — `provider_id` on both the client and
the response, landed in Stage 1, is exactly the attribution this needs.

Event Mill has to run on OpenAI or Anthropic without the analysis tools
changing — and, where the operator asks for it, **on more than one at the same
time**. This plan gets there in two parts, and the split matters:

> **Part 1 builds the plumbing. Part 2 finds out what it's worth.**
>
> Part 1 ends when every configured provider can be bound concurrently and every
> module still runs. That proves nothing about output quality — it proves the
> platform is no longer wired to one vendor. Part 2 is where each module is
> assessed against each provider, one module at a time, because there is no
> single answer to "which provider is better" and a plan that produces one is
> lying.

## The concurrency requirement, stated plainly

Event Mill was never meant to be tied to one vendor. The settled decision is
**one heavy and one light model per tool module**, taken from the module's
manifest — and **overridable at runtime so the same module can be run across
vendors and the outputs compared.**

Two things follow, and they shape every stage below:

1. **Several providers may be bound at once.** An operator can run Gemini Flash
   for the light-tier work and Anthropic for `adversary_path_projector` in the
   same session, or run the projector three times across three vendors for a
   diversity of opinion on the same flow map.
2. **Provider choice is an operator decision, not a plugin decision.** It
   arrives through the per-execution scoping wrapper, never through plugin code
   or `QueryHints`. That is what keeps "the analysis tools do not change" true,
   and it is what keeps prompts byte-identical across a swap — the precondition
   for any comparison meaning anything.

**What is still forbidden is automatic cross-provider *fallback*.** A quota
exhaustion must not silently move a session to another vendor: nobody chose it,
and the output is unattributable afterwards. Deliberate selection is the
requirement; silent failover is the hazard. Fallback stays inside the active
provider's two tiers. Earlier revisions of this plan collapsed the two and ruled
out both — that was wrong, and the stages below are rewritten accordingly.

The architecture is otherwise adopted wholesale from the GPT 5.6 assessment:
per-provider clients each owning their SDK, a thin dispatcher, a small internal
model-client protocol, an explicit provider registry, per-provider JSON
manifests, and no cross-provider fallback. There is no universal client that
understands every vendor.

What the assessment could not see is how much Gemini-specific code lives
**outside** `MCPLLMClient`, how unevenly the provider differences actually land
across the plugin estate, and that the dispatcher's client map is keyed by tier
alone. All three change the sequence.

---

## The seam audit — where Gemini actually lives today

| Location | What is Gemini-specific |
|---|---|
| `framework/llm/client.py:52` `_build_config` | `GenerateContentConfig`, `ThinkingLevel`, `MediaResolution` enums |
| `client.py:99/115/127` response readers | Google response shape (`candidates[0].finish_reason`, `usage_metadata.thoughts_token_count`) |
| `client.py:144` `MCPLLMClient` | `genai.Client`, `models.generate_content`, `Part.from_bytes` |
| `client.py:382/391` error classifiers | string-matches Google's error text (`RESOURCE_EXHAUSTED`, `free_tier`, `503/429/504`) |
| **`client.py:1167` `_execute_document_query`** | **on `LLMDispatcher`, not the client** — `Part.from_uri`, `gs://`, `client._genai_client`, `client._build_prompt`, `client._is_retriable` |
| `client.py:787` `_retry_on_retired_model` | constructs `MCPLLMClient` by name, clones four private attributes |
| `client.py:1022/1053` | `pdf_handling()`, `tokens_per_pdf_page()` called with **no provider argument** |
| `framework/cli/shell.py:399/3426/3838` | two-tier discovery loop, legacy `GEMINI_API_KEY`, `isinstance(..., MCPLLMClient)` |
| `plugins/log_analysis/threat_intel_ingester/tool.py:36` | imports provider budgeting helpers directly |

Stage 0 pinned all of this. `tests/framework/test_provider_seam.py` held seven
`xfail(strict=True)` tests naming each coupling. **Stage 1 removed every row
above except the last two**, and the markers came off with them; the table stays
as the record of what the audit found. The two `provider_id`-less accessor calls
and the `shell.py` discovery loop are Stage 2 and Stage 5.

---

## Where the provider differences actually land

Nine plugins use the LLM. Before deciding an order, it is worth knowing which
call paths they use, because that is what determines how hard a provider swap is
for each of them:

| Module | Pillar | Tier | `query_text` | `query_with_document` | `query_multimodal` |
|---|---|---|---|---|---|
| `adversary_path_projector` | threat_modeling | heavy | ✓ | — | — |
| `threat_model_analyzer` | threat_modeling | heavy | ✓ | — | — |
| `risk_assessment_analyzer` | threat_modeling | heavy | ✓ | — | — |
| `threat_report_analyzer` | threat_modeling | heavy | ✓ | **✓** | — |
| `log_investigator` | log_analysis | heavy | ✓ | — | — |
| `log_pattern_analyzer` | log_analysis | light | ✓ | — | — |
| `threat_intel_ingester` | log_analysis | light | ✓ | **✓** | — |
| `pcap_ai_analyzer` | network_forensics | heavy | ✓ | — | — |
| `pcap_report_correlator` | network_forensics | light | ✓ | — | — |

Three things follow, and they set the whole shape of Part 2:

1. **Seven of nine modules are text-only.** The document path — which carries the
   ugliest provider difference, `gs://` versus uploaded bytes versus inline data,
   with three different page-cost models — gates only two modules. Everything
   else can be assessed the moment the text path works.
2. **Nothing uses `query_multimodal`.** Not one plugin. The clients still
   implement it because the interface declares it, but no acceptance criterion
   hangs off it and it moves to the back of every implementation order.
3. **The two document modules are the two that matter least to move.**
   `threat_intel_ingester` is running well on Gemini 3.8 Flash and was signed off
   on 2026-09-12. `threat_report_analyzer` falls back to text extraction by
   design. Neither needs to be first.

---

## Nine decisions the assessment leaves open

### 1. The document path moves into the provider client, not out of `MCPLLMClient`

`_execute_document_query` is a `@staticmethod` on the dispatcher that operates
entirely on another object's privates. It is the largest single piece of vendor
code in the tree and it is on the wrong class. After the split,
`LLMModelClient.query_with_document(prompt, doc, ...)` is a real method on each
provider client; the dispatcher keeps only artifact → `DocumentPart` resolution,
the PDF guard, token clamping, and the retired-model retry.

### 2. Rebinding a model needs a protocol operation, not a factory

`_retry_on_retired_model` clones `_genai_client`, `_api_key_env_var`,
`_connected` and `_total_tokens_used` so the substitute reuses the live session
and the token count survives. A factory returning a fresh client loses all four.
Put `with_model(model_id) -> LLMModelClient` on the protocol and let each
provider decide what carrying a connection forward means.

### 3. Error classification must return a typed reason, not a string

The dispatcher's policy — quota or access → other tier; NOT_FOUND → fallback
model — is decided by grepping Google's error text. Add
`LLMResponse.error_kind` with a closed vocabulary:

```
quota | access | model_not_found | transient | context_overflow |
content_filtered | bad_request | other
```

The client classifies; the dispatcher routes on the enum; `error` keeps the raw
text for the operator. **This lands in Stage 1–2, not after the second provider.**
Without it, adding OpenAI forces OpenAI exception handling into the dispatcher.

### 4. Plugins already reach into provider facts

`threat_intel_ingester` imports `max_output_tokens_for_tier` and
`thinking_reserve_tokens` and calls them with no provider argument
(`tool.py:320`, `:334`), using them to size how much JSON one native call may
emit. Under another provider those return Gemini's numbers and the batching plan
is wrong — the same silent-failure class as the `EVENTMILL_MODEL_LIGHT` pin that
made the 3.8 swap inert.

Fix it on the interface the plugin already holds:

```python
class LLMQueryInterface(Protocol):
    def output_budget(self, thinking_level: str | None = None) -> int: ...
    def max_output_tokens(self) -> int: ...
```

`TierScopedLLMClient` answers both for the tier that will actually run, against
the active provider. Two call sites in one plugin.

### 5. Non-Gemini providers cannot read `gs://`

Gemini reads a GCS URI zero-copy. The others need bytes, and on Cloud Run
`file_path` may not exist — so the framework must fetch first. Fetching from GCS
is a `framework/cloud/resolver.py` concern, not an SDK concern: add a
`remote_uri_gs` capability token, have the dispatcher materialise bytes when the
selected client does not declare it, and give `DocumentPart` a lazy
`read_bytes()`. This also makes `_pdf_context_overflow` read the **active**
provider's limits — Anthropic's are far below Gemini's 1000 pages / 50 MB, and it
currently reads Gemini's unconditionally.

Per the census above, this gates two modules, not nine.

### 6. `output_budget` becomes per-tier

Keeping it provider-global was a recorded 09-12 decision resting on two Gemini
models agreeing. It is much less likely to hold where a provider's light tier is
a non-reasoning model and its heavy tier is a reasoning model. Keep the global
block as the default; let a tier entry override it.

### 7. `MCPLLMClient` gets renamed, with no compatibility alias

The name has been wrong since the MCP transport was deferred. It becomes
`GeminiClient`; `framework/llm/client.py` becomes `framework/llm/dispatcher.py`.
Nothing outside this repo imports it and the suite catches the six call sites.

### 8. The dispatcher's client map is keyed by tier, and must be keyed by both

`LLMDispatcher._clients` is `dict[str, LLMModelClient]` keyed by `"light"` /
`"heavy"`. With one vendor that is complete; with two bound at once it cannot
express the state. Eight call sites read it (`dispatcher.py:80` through `:679`),
and `_tier_of` reverse-looks-up a client by scanning it.

It becomes keyed by **`(provider_id, tier)`**. `_route()` resolves the provider
first — from the execution scope, else the session default — and the tier within
it. `connected_models()` reports both.

**`_fallback_client` is the one method that must stay provider-scoped.** It
answers "the other connected tier" today; it has to answer "the other connected
tier *of the same provider*". This is where the data-handling boundary actually
lives, and it is a three-line constraint rather than a policy spanning the
design. A test asserting that a quota failure on one vendor never routes to
another belongs with it.

### 9. Runtime provider override rides the scoping wrapper, not `QueryHints`

`shell.py:2782` already wraps every plugin execution in
`TierScopedLLMClient(self.llm_client, default_tier=plugin.manifest.model_tier)`.
That is the single place a manifest default is turned into a per-execution
decision, and it is the right place for the provider too:

```python
TierScopedLLMClient(dispatcher, default_tier=..., default_provider=...)
```

The alternative — a `provider` field on `QueryHints` — is wrong twice. It would
put vendor selection in plugin code, breaking "the analysis tools do not
change"; and it would let a plugin's own hints override an operator's A/B
choice, making a comparison silently unattributable.

The manifest may later declare a per-module provider preference through the same
channel, which is the mechanism Part 2 would use to record a per-module
decision. Neither the plugin nor its prompts change either way.

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
    gcp_gemini.json  openai.json  anthropic.json
  backends/base.py         DocumentPart (+ lazy read_bytes)
```

---

# Part 1 — three providers, selectable at the CLI

The deliverable is an operator being able to choose a provider and have every
module still run. Output quality is explicitly **not** in scope here.

### Stage 0 — lock the seam — **DONE 2026-09-13** (`1d31b54`)

`tests/framework/test_provider_seam.py` pins the dispatcher's behaviour against
`PublicOnlyClient`, a fake implementing only the public model-client interface.
Ten tests pass today — routing, clamping, quota fallback, the PDF guard,
capability checks — and are the genuinely provider-neutral core. Seven are
`xfail(strict=True)`, each with `raises=` so it cannot fail for an unrelated
reason, and each naming the coupling it waits on.

The SDK invariant is an `ast` walk over the dispatcher's imports, not the
`sys.modules` block originally specified: `client.py` wraps its `google.genai`
import in `try/except ImportError`, so a blocked SDK leaves the module importing
cleanly and that test would have passed against the coupling it was meant to
catch.

`scripts/make_probe_pdf.py` rebuilt and committed with
`tests/framework/test_probe_corpus.py`. **965 passed, 7 xfailed** (was 945).

### Stage 1 — extract `GeminiClient`, behaviour unchanged — **DONE 2026-09-13**

`_build_config`, the response readers, both error classifiers and
`_execute_document_query` moved into `clients/gemini.py`; `MCPLLMClient` became
`GeminiClient` and `client.py` became `dispatcher.py`, which now imports no
vendor SDK. `with_model()` replaced the four-attribute clone. `error_kind` and
`provider_id` were added to `LLMResponse`, the Gemini classifier populates them,
and the dispatcher routes on the enum with string matching as the fallback.

Stage 0's seven xfail markers are gone because the tests pass. **974 passed, 0
xfailed** (was 965 passed, 7 xfailed). Verified live against both tiers: text,
grounding, the 400 classification path, and a native document query that
reproduced 82/82 non-technique recall on the probe corpus.

Change log: `docs/change_log/2026-09-13-provider-seam-stage-1.md`.

### Stage 2a — three providers reachable, one bound — **DONE 2026-09-13/14**

Inserted after Stage 1 from the operator's framing: *"only gemini light and
heavy need to work with the other modules; the first goal is to confirm the
keys load and we can make client connections."* That splits cleanly from the
rekey and was worth having first, because it makes Stage 2 land against
providers already known to be reachable rather than against assumptions.

The deliverable is **configurable and provably reachable, not bindable**.
`LLMDispatcher._clients` is untouched and still holds Gemini alone — while it
is keyed by tier, an `AnthropicClient` under `"heavy"` would evict Gemini Pro
and route every heavy plugin to a vendor nobody chose. A test enforces it.

Landed: `anthropic.json` / `openai.json` with both tiers
(`claude-sonnet-5`/`claude-opus-5`, `gpt-5.6-terra`/`gpt-5.6-sol`);
`factory.py` with `PROVIDER_CLIENTS` and the first Python reader of
`EVENTMILL_LLM_PROVIDERS`; `AnthropicClient` and `OpenAIClient` (text path);
`probe()` on the protocol and all three clients; the `providers` and
`providers probe` commands; provider-qualified `EVENTMILL_MODEL_*` overrides.

Two findings worth carrying forward into Stage 2:

- **`connect()` proves nothing.** Every client builds an SDK handle without a
  network call, so a wrong key connects cleanly and fails at first use. That is
  why `probe()` exists and why the CLI never reports reachability from `connect`.
- **A ping budget must come from the manifest's thinking reserve.** Reasoning is
  spent from the output budget and the spend varies between identical calls, so
  a flat small budget makes a healthy model report as broken on some runs only.

Change logs: `2026-09-13-three-provider-connectivity-probe.md`,
`2026-09-13-three-provider-clients.md`,
`2026-09-14-llm-sdks-to-current-stable.md`.

This absorbs the text-path half of Stages 3 and 4; what remains there is the
document and multimodal work, which no module needs yet.

#### Sequencing decision, 2026-09-14: google-genai stays on 1.x until after Stage 2

The Anthropic and OpenAI SDKs were moved to current stable
(`anthropic>=1.5.0,<2.0.0`, `openai>=3.13.0,<4.0.0`) on the operator's
principle that net-new code should not start on a deprecated major.
**`google-genai` is deliberately excluded and stays `>=1.69.0,<2.0.0`.**

It is the one component that is not net-new: `GeminiClient` carries every
module, and its 1.x controls — `media_resolution`, `thinking_level`, the
response readers, the error classifiers, the native document path — are what
the whole suite and both live verification sessions were run against. Moving to
2.x is a migration with a real blast radius, not a specifier edit.

Doing it *after* the rekey is the cheaper order: once `_clients` is keyed by
`(provider_id, tier)` and another provider can be bound, a Gemini regression is
visible against a working comparison rather than being the only thing running.

Note that the deployed container has been running google-genai 2.x *by
accident* — the requirement was unbounded until 2026-09-14 — so "Gemini is on
1.x" became true of the image only at the next build after that pin.

### Stage 2 — generalise construction, and make the client map two-dimensional

The largest stage, and the one the concurrency requirement reshapes.
**Stage 2a landed the construction half** (`factory.py`, both manifests, both
clients, `EVENTMILL_LLM_PROVIDERS`); what remains below is the rekey, the
scoping wrapper's `default_provider`, and the accessor threading.

**Construction.** `PROVIDER_CLIENTS` registry in `factory.py`.
`EVENTMILL_LLM_PROVIDERS` — **plural, space-separated, default `gcp_gemini`** —
names which providers a session may bind. A provider is *available* when it is
listed and its key env var is set; listing one whose key is absent is a named
warning at startup, not a failure, because a placeholder-seeded deployment is
the expected steady state (see Stage 6).

**Keying.** `LLMDispatcher._clients` moves to `(provider_id, tier)` per decision
8. `_route()` resolves provider then tier; `_tier_of` becomes
`_locate(client) -> (provider_id, tier)`; `connected_models()` reports both.
`_fallback_client` is constrained to the same provider, with a test asserting a
quota failure never crosses vendors.

**Scoping.** `TierScopedLLMClient` gains `default_provider`, set from the
execution scope in `shell.py:2782` per decision 9. With one provider bound this
is a no-op and behaviour is identical.

**Provider-qualified accessors.** Thread `provider_id` through every accessor in
`providers/__init__.py` and the dispatcher's four unqualified calls
(`pdf_handling()`, `tokens_per_pdf_page()`, and the two in the PDF guard).
Per-tier `output_budget` / `file_handling` override.
`LLMQueryInterface.output_budget()` and `.max_output_tokens()`, with
`threat_intel_ingester` cut over. Add `remote_uri_gs` and dispatcher-side byte
materialisation.

**Done when:** with only `gcp_gemini` configured the suite is green and live
behaviour is unchanged; two providers can be bound simultaneously and each
response carries the `provider_id` that served it; a quota failure on one
provider never routes to another; and an unknown provider id is refused with a
named error rather than a silent fall back to Gemini.

This is large enough to split if it gets unwieldy — the `(provider_id, tier)`
rekey is separable from the accessor threading, and the rekey is the half that
must land first.

### Stage 3 — `OpenAIClient` — **text path DONE in Stage 2a**

`openai.json`, the client, the `llm-openai` extra and the Responses API
construction all landed with Stage 2a; both tiers are verified live. The SDK
went straight to current stable (`>=3.13.0,<4.0.0`), so the "1.58.1 has no
`client.responses`" constraint that shaped the original plan no longer applies.

**Outstanding:** structured output (`text.format`), documents (`input_file`
plus the dispatcher-side byte materialisation below), and images. Nothing
consumes `query_multimodal`, so it stays last and nothing is gated on it. Both
unimplemented methods currently return a declared `bad_request` naming this
stage rather than a wrong answer.

Implementation order follows the census: **text first, then structured output,
then documents, and images last**.

The client owns Responses API construction, `reasoning.effort`, `text.format`,
`input_file`, status and usage parsing, exception → `error_kind`, and
**`store=False`**. This platform handles incident data; a no-retention posture is
a declared property of the client recorded in the manifest, not an incidental
default.

Portable hints map inside the client: `thinking_level` → `reasoning.effort` where
there is a defensible equivalent, and a logged diagnostic where there is not.
Neither mapping appears in the dispatcher.

### Stage 4 — `AnthropicClient` — **text path DONE in Stage 2a**

Client, manifest, registry entry, `llm-anthropic` extra and tests landed with
Stage 2a; both tiers verified live on `anthropic>=1.5.0,<2.0.0`.

**The abstraction held.** This stage's own test was: *if it touches
`dispatcher.py`, `TierScopedLLMClient`, any plugin, or any prompt, the
abstraction is in the wrong place.* It touched none of them. The only framework
files that changed were additive — `probe()` on the protocol, and the provider
accessors gaining the per-tier `thinking_levels` every provider turned out to
need. That is the honest result, and it is worth more than it looks, because
Anthropic was written third against an interface shaped by the first two.

**Outstanding:** the document path. Its PDF limits are the tightest of the three
(100 pages / 32 MB against Gemini's 1000 / 50 MB, already recorded in
`anthropic.json`) and will exercise `_pdf_context_overflow` in a way Gemini
never has — but only once the guard reads the *active* provider's limits rather
than Gemini's, which is Stage 2 accessor work.

### Stage 5 — CLI selection, runtime override, and normalised diagnostics

Rework `_discover_models` and `do_connect` to be provider-driven.
`_discover_models` currently gates on `spec.api_key_env` from the Gemini
manifest alone (`shell.py:418`), so until this lands a mounted
`ANTHROPIC_API_KEY` is invisible — correct in source, inert in the environment,
which is the 09-12 failure mode exactly.

- `models` lists every **bound** provider's tiers, provider-qualified.
- `connect` binds all available providers and prints **provider, tier, model and
  key env var** for each.
- `providers` shows what is configured, what is bound, and what is missing a key
  — naming the env var for each gap.
- **`use <provider> [for <tool>]`** sets the session default, or a per-module
  override. This is the runtime A/B control, and the only supported way to
  choose a vendor for a module.

The 3.8 swap's most expensive lesson was a change that was correct in the source
and inert in the environment. Several vendors bound at once has strictly more
ways to be half-applied, so every bind and every override announces itself.

Every provider returns provider id, requested model, reported model, normalised
usage (prompt / completion / reasoning / total), finish reason, truncation and
`error_kind`. `provider_id` is already on `LLMResponse` as of Stage 1; add it to
the projector's run record (`RUN_RECORD_SCHEMA_VERSION` 3 → 4). **With vendors
running concurrently this stops being a convenience and becomes the only thing
that makes a run interpretable** — two records from one session may now come
from two vendors.

**Part 1 is done when** `EVENTMILL_LLM_PROVIDERS` binds any combination of the
three concurrently, the CLI shows and overrides them per module, every response
and run record names the provider that served it, and all nine modules execute
without plugin changes.

### Stage 6 — deployment — **secret wiring DONE 2026-09-13** (`52e3a10`)

**Decision: provision all three secrets always, seeded with placeholders.**

Brought forward ahead of Stages 2–5 deliberately, and verified on Cloud Run: the
four LLM keys reach the container through Secret Manager for providers that have
no code behind them yet. When the registry lands, the only untested variable is
the code. **Done:** `provision-gcp-project.sh`, `provision-secrets.sh`,
`deploy-cloudrun-secrets.sh`, `deploy-cloudrun.sh`. **Still open:**
`cloudbuild.yaml`, the `pyproject` extras and `Dockerfile.cloudrun`,
`docker-compose.cloudrun.yml`, `setup-deploy-server.sh`.
Change log: `docs/change_log/2026-09-13-three-vendor-secret-wiring.md`.

The infrastructure provisions a fixed set of secrets — Gemini Flash, Gemini Pro,
Anthropic, OpenAI — regardless of which vendors an operator actually uses.
OpenAI and Anthropic are seeded with the literal `placeholder` that
`provision-gcp-project.sh` already writes, and stay that way until someone
adopts them.

This separates infrastructure from development, and it is the right call for
three reasons:

1. **The build is identical for every deployment.** No provider-conditional
   branching in `deploy-cloudrun-secrets.sh` or `cloudbuild.yaml`; `ALL_SECRETS`
   stays a static list and the `--set-secrets` string stays fixed. The
   alternative — computing the secret set from `EVENTMILL_LLM_PROVIDERS` —
   duplicates that logic across the shell script and the CI YAML, where it will
   drift.
2. **It stays GCP-first.** Gemini remains the default and the only provider with
   real keys out of the box. Nothing about a stock deployment changes.
3. **Adoption becomes a one-module decision.** Extending to another vendor is
   `gcloud secrets versions add` plus a `use` override — no redeploy, no
   infrastructure change, no re-provisioning. That is what makes Part 2's
   module-at-a-time sequence practical rather than theoretical.

The work:

- **`provision-gcp-project.sh:94`** — add `eventmill-anthropic-api` and
  `eventmill-openai-api` to `SECRET_NAMES`, so they are created and
  secretAccessor-bound at bootstrap like every other secret. Existing projects
  pick them up by re-running provisioning, which is idempotent.
- **`provision-secrets.sh`** — these keys are externally issued, so
  `create_restricted_gemini_key` (which calls `gcloud services api-keys create`,
  a Google-only mechanism) does not apply. Use the existing `add_secret_version`
  helper, already used for ttyd and the GCS SA. **One secret per provider, not
  two**: Section 1's per-tier quota-isolation rationale is specific to Gemini —
  neither OpenAI nor Anthropic splits keys by tier, so one key serves both tiers
  of that provider.
- **`deploy-cloudrun-secrets.sh`** — add the two secret-name variables
  (`:129`), append to `ALL_SECRETS` (`:202`), mount both in `--set-secrets`
  (`:724`), and pass `EVENTMILL_LLM_PROVIDERS` through `--set-env-vars`.
  **Step 4's placeholder check needs care**: it currently warns and prompts to
  abort on any `placeholder` value, which would fire on every Gemini-only deploy
  once the new secrets exist. A placeholder in an *unadopted* provider is the
  expected state and must be informational; a placeholder in a provider named by
  `EVENTMILL_LLM_PROVIDERS` stays blocking.
- **`cloudbuild.yaml:117/229/257`** — the CI path duplicates the preflight loop,
  the `--set-secrets` string and the secret-name substitutions. Easy to miss,
  and it would keep deploying Gemini-only in silence.
- **`Dockerfile.cloudrun:26`** — installs `[gcp,plugins-*]` only. Add
  `llm-openai` and `llm-anthropic` extras to `pyproject.toml` and install all
  three, so the image is consistent and adopting a vendor never needs a rebuild.
  Neither SDK is declared anywhere today. **`openai` must be `>=1.66`** — the
  Responses API this plan specifies landed there, and the 1.58.1 currently in
  the dev venv has no `.responses` attribute at all.
- Documentation follow-on: `Dockerfile.cloudrun:76`, `setup-deploy-server.sh:108`,
  `deploy-cloudrun.sh:96`, and the `cloud_install/README.md` env tables.

**Sequencing:** the `pyproject` extras and the Dockerfile can land any time —
they only make SDKs present. The script changes should land **with or after
Stage 5**, because until `_discover_models` is provider-driven a mounted
Anthropic key binds nothing and the deploy would look correct while doing
nothing.

---

# Part 2 — module-by-module assessment

## Why module by module

A provider that projects attack paths well may extract indicators poorly. The
nine modules ask for different things — closed-set obedience under a long prompt,
indicator recall from prose, correlation across flow records — and a model is
good at those independently. Reporting one verdict per provider would average
away exactly the information the assessment exists to produce.

So each module gets its own comparison, its own acceptance number, and its own
decision. The end state is not "we moved to provider X". It is a per-module
record of which providers are acceptable for that module and what each one costs.

This is also why `model_tier` lives in the plugin manifest. That mechanism
already lets one module run on a different model from another, and Stage 5
extends the same channel to the provider — so by the time Part 2 starts, running
one module on a different vendor from the rest is a `use` override, not a code
change. Part 2 records which vendors are acceptable per module; the mechanism to
act on that answer already exists.

## What is not being assessed, and why

**`threat_intel_ingester` stays on Gemini 3.8 Flash.** It was compared, measured
and signed off on 2026-09-12 — 94/94 indicators, 82/82 non-technique recall, 12/12
documented techniques, ~30% faster than 3.5 — and the operator's verdict was that
outputs are as good or better. It is also one of only two modules needing
document-path parity. Moving the module that works, and that is hardest to move,
first would be the wrong order twice over.

It gets re-run under other providers eventually, as a late item, to record what
the alternative costs. It is not a Part 2 target.

## First target: `adversary_path_projector`

Six reasons, in the order they matter:

1. **It is text-only.** `tool.py:3384` is its single LLM call — `query_text`, no
   document, no multimodal. It can be compared across providers as soon as Stage
   3 lands, with none of the `gs://`-versus-bytes work resolved.
2. **Its input is structured records, not a document.** Session state is SQLite
   (`framework/session/database.py` — sessions, artifacts, tool executions) and
   the threat intel the projector reasons over arrives as registered artifacts
   indexed there. Presenting identical input to three providers is reading the
   same rows and assembling the same prompt — not re-ingesting a PDF through
   three different file APIs. **Prompt tokens are byte-identical across
   providers**, which is the precondition for any comparison meaning anything.
3. **It already scores itself.** `_validate_projection` is deterministic and
   produces rejections by code. `TECHNIQUE_NOT_IN_SET` and
   `COMPONENT_NOT_IN_FLOW_MAP` are pure closed-set obedience: no ground truth is
   needed, only the flow map and the actor's technique set. That is a rare thing
   to have — an objective, model-agnostic number that requires no human scoring.
4. **It exercises the knobs that differ most.** Heavy tier, `needs_reasoning`,
   `needs_structured_output`, an explicit `thinking_level`, a ~3,900-token system
   context and a 49,152-token output budget. If a provider abstraction is going
   to break anywhere, it breaks here.
5. **It has a recorded baseline.** `stepstate-medium-2`, in
   `docs/change_log/2026-09-11-live-run-findings.md:158`.
6. **It supports multiple runs per invocation** (`max_paths`, `runs`), so
   variance can be measured rather than assumed. A single sample from a reasoning
   model is noise, and a comparison built on one run per provider would be
   worthless.

### The metrics

**Primary — obedience.** Rejections by code, summed over n runs:
`TECHNIQUE_NOT_IN_SET`, `COMPONENT_NOT_IN_FLOW_MAP`, `PATH_NOT_OBJECT`,
`STEP_NOT_OBJECT`. **This is the number that matters.** A path built on a
technique the actor does not have is not a weaker answer, it is a wrong one.

**Secondary — reasoning quality.** Warnings by code: `HOP_NOT_DECLARED`,
`KILL_CHAIN_REGRESSION`, `LATE_INITIAL_ACCESS`, `STATE_GAP`, `MISSING_STEP_STATE`,
`TACTIC_CORRECTED`. These are judgement calls the validator records rather than
refuses, and they are where a model's understanding of the map shows.
`HOP_NOT_DECLARED` deserves particular attention: a path may never skip a hop
point, and a model that quietly teleports is failing at the thing the projector
exists to do.

**Envelope — did it survive the round trip.** Parse failures, `truncated`,
`finish_reason`, wall time, reasoning tokens, and `model_served` versus
`model_configured`.

**Judgement — is it useful.** Paths produced against `max_paths`, and whether the
crown-jewel routes surfaced are ones an analyst would act on. This is the only
part needing a human, and it is read last, after the deterministic numbers have
already narrowed the field.

### Run design

Same flow map, same actor, same `max_paths`, same `thinking_level` where it maps,
**prompt byte-identical**. n ≥ 5 runs per provider per configuration, reported as
a distribution and not a single figure. Every run records `provider_id` and
`model_served`, so a comparison rests on what actually ran rather than what was
configured — the gap `model_version` was added to close on 2026-09-12.

**Concurrent binding makes this one invocation rather than three sessions.** The
projector already supports multiple runs per invocation (`runs`, `max_paths`),
and with several providers bound the same mechanism spreads those runs across
vendors. That removes the largest confound in the original design: three
sequentially-configured sessions differ in more than the vendor — session state,
artifact set, and any environment drift between them all move too. One
invocation over one flow map with one actor holds every one of those fixed.

It also raises the stakes on attribution. Two run records from one session may
now come from two vendors, so `provider_id` on the record
(`RUN_RECORD_SCHEMA_VERSION` 4, Stage 5) stops being a convenience and becomes
the only thing that makes the output interpretable. A run record without it is
not a weaker measurement — it is an unreadable one.

A provider is **acceptable for this module** when its rejection count is at or
below the `stepstate-medium-2` baseline and no run produces a parse failure or a
truncated reply. Everything else is a cost discussion.

## Order after the projector

Each becomes its own comparison, reusing the pattern above:

| Order | Module | Why here | Instrument |
|---|---|---|---|
| 2 | `threat_model_analyzer` | heavy, text-only, same pillar and closed-set discipline | deterministic schema validation |
| 3 | `risk_assessment_analyzer` | heavy, text-only, consumes the projector's output | consistency against a fixed input |
| 4 | `log_investigator` | heavy, text-only, different pillar — tests whether the projector result generalises | analyst review against known-answer logs |
| 5 | `pcap_ai_analyzer` | heavy, text-only, third pillar | analyst review |
| 6 | `log_pattern_analyzer`, `pcap_report_correlator` | light tier, text-only, cheap to run | existing plugin tests plus spot review |
| 7 | `threat_report_analyzer` | **needs document parity**; has a text fallback, so it can be assessed on the text path first | recall against a known report |
| 8 | `threat_intel_ingester` | **needs document parity**; already settled on Gemini — run last, to price the alternative | `scripts/make_probe_pdf.py`, 82/82 non-technique recall |

Items 7 and 8 are the only two that wait on Stage 2's byte-materialisation work.
Everything above them needs nothing but a working text path.

## The probe corpus

`scripts/make_probe_pdf.py` is the instrument for item 8, and the reason it was
rebuilt in Stage 0: the version behind the 09-12 numbers was never committed.
It emits a 3-page report with an exact 94-indicator ground truth (24 IPv4, 20
domain, 16 sha256, 12 URL, 10 CVE, 12 technique; 82 non-technique), with 12 URL
hostnames outside the domain set so refinement has real discrimination to do.

Two properties of it are choices, not reconstructions — only the counts survived:
it writes the PDF itself rather than depending on `fpdf2` from an optional extra,
and every name in it is RFC 5737 or RFC 2606 reserved. The second is right for a
fixture in this repository and costs something worth recording: a model may rank
a `.invalid` host as obvious test data and decline to report it. If a baseline run
cannot reproduce 82/82 non-technique recall, that is the first knob to turn, not
the model.

---

## In scope, corrected 2026-09-13

Two items previously listed as out of scope were **requirements all along**, and
ruling them out was this plan's own error rather than a design decision:

- **Several providers bound at once, and mixed across modules.** Gemini Flash for
  light-tier work while `adversary_path_projector` runs on Anthropic is a
  supported configuration, not a violation. Decision 8 makes the dispatcher able
  to express it.
- **Per-module provider selection at runtime.** The point of the work, not a
  Part 2 recommendation to be deferred. Decision 9 gives it a channel that does
  not touch plugin code. The earlier justification — "speculative until the
  assessment says it is needed" — inverted the requirement and the evidence for
  it.

Both are about *deliberate* selection. The distinction from the bullet below is
the whole of it: an operator choosing a vendor and having it recorded, versus a
session moving vendors on its own.

## Out of scope, deliberately

- **Automatic cross-provider fallback.** A quota exhaustion must not move a
  session to another vendor. Nobody chose it, investigation data reaches a
  provider the operator did not select, and the output is unattributable
  afterwards. Fallback stays within the active provider's two tiers —
  `_fallback_client`, and nowhere else. This is a data-handling boundary, not a
  routing convenience, and it is narrower than it looks: it constrains one
  method, not the shape of the design.
- **Retiring `thinking_level` / `media_resolution` from `QueryHints`.** They stay;
  `GeminiClient` consumes them, others map or ignore with a diagnostic.
- **Prompt changes.** Prompts stay byte-identical across a provider swap or the
  comparison means nothing — the rule the 3.8 swap held to. This is also why the
  provider override rides the scoping wrapper: a channel that reached plugin
  code could not make this guarantee.
- **A `provider` field on `QueryHints`.** Decision 9. It would put vendor choice
  in plugin code and let a plugin override an operator's A/B selection.
- **Adopting `structured_output`.** Still declared and unused, for the reasons
  recorded on 2026-09-12. If a provider produces *parse failures*, the narrow fix
  is a JSON mime type, not a schema. Part 2 may revisit this per provider.
- **`query_multimodal` parity.** No plugin uses it. Implemented, not assessed.
- **The heavy-tier Gemini swap (Stage B of the 3.8 plan)** and **projector Phase
  4**. Both outstanding; neither blocks nor is blocked by this work.

## Rollback

Part 1 Stages 1–2 are a pure refactor: revert the commit. From Stage 3 on, the
rollback is `EVENTMILL_LLM_PROVIDERS=gcp_gemini`, which is the default — a broken
new provider client cannot affect the Gemini path, because it shares no code with
it. That property is the point of the design and belongs in `AGENTS.md`.

Stage 6's placeholder seeding gives the same property in the infrastructure: a
deployment carrying all three secrets but real keys only for Gemini behaves
exactly as a Gemini-only deployment does, and reverting an adoption is removing
a `use` override — not a redeploy.

Part 2 changes no code by default. A module moves to a different provider only by
an explicit decision recorded in a change log, and moves back by reverting that
decision.
