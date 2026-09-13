# Plan — a second and third model provider

**Date:** 2026-09-13
**Branch:** `llm_multi`
**Status:** Stage 0 done (`1d31b54`), Stage 1 done 2026-09-13. Part 1 Stage 2 next.

Event Mill has to run on OpenAI or Anthropic without the analysis tools
changing. This plan gets there in two parts, and the split matters:

> **Part 1 builds the plumbing. Part 2 finds out what it's worth.**
>
> Part 1 ends when all three providers are selectable at the CLI and every
> module still runs. That proves nothing about output quality — it proves the
> platform is no longer wired to one vendor. Part 2 is where each module is
> assessed against each provider, one module at a time, because there is no
> single answer to "which provider is better" and a plan that produces one is
> lying.

The architecture is adopted wholesale from the GPT 5.6 assessment: per-provider
clients each owning their SDK, a thin dispatcher, a small internal model-client
protocol, an explicit registry keyed by `EVENTMILL_LLM_PROVIDER`, per-provider
JSON manifests, and no cross-provider fallback. There is no universal client that
understands every vendor. Nothing below argues with that.

What the assessment could not see is how much Gemini-specific code lives
**outside** `MCPLLMClient`, and how unevenly the provider differences actually
land across the plugin estate. Both change the sequence.

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

## Seven decisions the assessment leaves open

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

### Stage 2 — generalise construction

`LLMModelClient` protocol, `PROVIDER_CLIENTS` registry, `EVENTMILL_LLM_PROVIDER`
(default `gcp_gemini`). Thread `provider_id` through every accessor in
`providers/__init__.py` and the dispatcher's four unqualified calls. Per-tier
`output_budget` / `file_handling` override. `LLMQueryInterface.output_budget()`
and `.max_output_tokens()`, with `threat_intel_ingester` cut over. Add
`remote_uri_gs` and dispatcher-side byte materialisation.

**Done when:** with the default provider the suite is green and live behaviour is
unchanged; with an unknown provider id the shell refuses to start with a named
error rather than silently falling back to Gemini.

### Stage 3 — `OpenAIClient`

`openai.json`, plus the SDK in a new `llm-openai` extra. Implementation order
follows the census: **text first, then structured output, then documents, and
images last** — nothing consumes `query_multimodal`, so it is implemented for
interface completeness and nothing is gated on it.

The client owns Responses API construction, `reasoning.effort`, `text.format`,
`input_file`, status and usage parsing, exception → `error_kind`, and
**`store=False`**. This platform handles incident data; a no-retention posture is
a declared property of the client recorded in the manifest, not an incidental
default.

Portable hints map inside the client: `thinking_level` → `reasoning.effort` where
there is a defensible equivalent, and a logged diagnostic where there is not.
Neither mapping appears in the dispatcher.

### Stage 4 — `AnthropicClient`

New client, manifest, registry entry, `llm-anthropic` extra, tests. **If this
stage touches `dispatcher.py`, `TierScopedLLMClient`, any plugin, or any prompt,
the abstraction is in the wrong place and that is the finding.** Anthropic is the
honest test precisely because it is third.

Its PDF limits are the tightest of the three and will exercise
`_pdf_context_overflow` in a way Gemini never has.

### Stage 5 — CLI selection and normalised diagnostics

Rework `_discover_models` and `do_connect` to be provider-driven. `models` lists
the active provider's tiers; `connect` prints **provider, tier, model, and key
env var** on every bind. A `provider` command shows what is selected and what is
available, and refuses an unconfigured one with the missing env var named.

The 3.8 swap's most expensive lesson was a change that was correct in the source
and inert in the environment. A provider switch has strictly more ways to be
half-applied, so it has to announce itself.

Every provider now returns provider id, requested model, reported model,
normalised usage (prompt / completion / reasoning / total), finish reason,
truncation and `error_kind`. Add `provider_id` to `LLMResponse` and to the
projector's run record (`RUN_RECORD_SCHEMA_VERSION` 3 → 4) — Part 2's comparisons
are unreadable without it.

**Part 1 is done when** `EVENTMILL_LLM_PROVIDER` selects any of the three, the
CLI shows and binds it, and all nine modules execute without plugin changes.

### Stage 6 — deployment

Parameterise the secret wiring, which names Gemini in five places
(`cloud_install/deploy-cloudrun-secrets.sh:129`, `deploy-cloudrun.sh:96`,
`provision-secrets.sh:207`, `setup-deploy-server.sh:108`, and the README env
table). The selected provider's key secret, and only that one, gets mounted; the
container build installs the selected provider's extra.

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
already lets one module run on a different model from another; the same mechanism
is what a per-module provider choice would eventually need.

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

## Out of scope, deliberately

- **Cross-provider fallback.** A process started on OpenAI must not send
  investigation data to Google or Anthropic because a quota ran out. Fallback
  stays within the active provider's two tiers. This is a data-handling boundary,
  not a routing convenience.
- **Mixing providers across tiers.** Same reason, plus it makes every Part 2
  comparison unattributable.
- **Per-module provider selection at runtime.** The manifest mechanism could
  support it and Part 2 may recommend it, but building it before the assessment
  says it is needed is speculative.
- **Retiring `thinking_level` / `media_resolution` from `QueryHints`.** They stay;
  `GeminiClient` consumes them, others map or ignore with a diagnostic.
- **Prompt changes.** Prompts stay byte-identical across a provider swap or the
  comparison means nothing — the rule the 3.8 swap held to.
- **Adopting `structured_output`.** Still declared and unused, for the reasons
  recorded on 2026-09-12. If a provider produces *parse failures*, the narrow fix
  is a JSON mime type, not a schema. Part 2 may revisit this per provider.
- **`query_multimodal` parity.** No plugin uses it. Implemented, not assessed.
- **The heavy-tier Gemini swap (Stage B of the 3.8 plan)** and **projector Phase
  4**. Both outstanding; neither blocks nor is blocked by this work.

## Rollback

Part 1 Stages 1–2 are a pure refactor: revert the commit. From Stage 3 on, the
rollback is `EVENTMILL_LLM_PROVIDER=gcp_gemini`, which is the default — a broken
new provider client cannot affect the Gemini path, because it shares no code with
it. That property is the point of the design and belongs in `AGENTS.md`.

Part 2 changes no code by default. A module moves to a different provider only by
an explicit decision recorded in a change log, and moves back by reverting that
decision.
