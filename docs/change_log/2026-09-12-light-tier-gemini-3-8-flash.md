# Change Log — the light tier moves to Gemini 3.8 Flash

**Date:** 2026-09-12
**Primary Files Modified:**
`framework/llm/providers/gcp_gemini.json`,
`framework/llm/providers/__init__.py`,
`framework/llm/client.py`,
`framework/plugins/protocol.py`,
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/projection_run.schema.json`,
`tests/framework/test_llm_dispatcher.py`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`
**Supporting Files:**
`AGENTS.md`, `README.md`, `cloud_install/README.md`,
`docs/specs/eventmill_v1_1.md`, `docs/specs/model_interchange_gemini_3_8_flash.md`,
`docs/guides/network_forensics_analysis.md`, `framework/cli/shell.py`,
`docker-compose.yml`

Plan: `docs/specs/model_interchange_gemini_3_8_flash.md`.

---

## Problem

Event Mill has claimed model interchangeability since the MCP-era spec. Nothing
had ever tested it. Moving the light tier from `gemini-3.5-flash` to
`gemini-3.8-flash` is the cheapest available test: three plugins, a single
source-of-truth manifest, and an existing per-tier override path that should make
the whole thing a configuration change.

It mostly was. What it surfaced is one structural gap and one measurement gap —
both pre-existing, neither visible until two models had to be compared.

## Scope

**The light tier only. The heavy tier is untouched** — `model_id` stays
`gemini-3.1-pro-preview`. A swap of both at once means a regression cannot be
attributed to a tier, and the heavy tier is where the interesting behaviour is
(closed-set obedience, a ~3,900-token prompt, a 48K output budget).

One consequence, recorded rather than fixed: the heavy tier's `fallback_model_id`
is still `gemini-3.5-flash`, which no tier now runs as its primary. That is a
loose end, not a fault — 3.5 Flash is a live GA endpoint, so a retired Pro still
lands somewhere that works. It gets retargeted when the heavy tier moves.

## Changes

### The tier swap

`gcp_gemini.json`, light tier: `model_id` and `display_name` to 3.8 Flash.
Capabilities are unchanged — `deep_reasoning` is deliberately **not** declared on
light, so the tier distinction still means something and
`test_ships_light_and_heavy_tiers` still holds.

`fallback_model_id` stays `""`. It was briefly set to `gemini-3.5-flash` as a
hedge while the 3.8 id was unverified; the live check below confirmed 3.8 Flash
is a GA endpoint, so the hedge came back out. A fallback there would only have
masked a mistyped model id.

### `model_version` — what ran, not what was asked for

`LLMResponse.model_used` is the id the client was *constructed* with.
`projection_run.schema.json` said so explicitly, and said closing the gap was its
own task. Comparing two models over one corpus is exactly the case where the gap
bites: an alias resolving to a different dated build is a confound that cannot be
seen.

- `LLMResponse.model_version` — new field, `None` when the provider reports
  nothing. `model_used`'s comment said "which model actually ran", which was
  never true; corrected.
- `_model_version(response)` in `client.py`, applied on all three paths that hold
  a provider response: `_execute_mcp_query` and `_execute_mcp_multimodal_query`
  (both return it alongside their existing values) and `_query_document_native`
  (inline). The error and guard paths leave it `None`, which is correct — there is
  no response to read.
- The projector's run record gains `model.model_served`;
  `RUN_RECORD_SCHEMA_VERSION` 2 → 3. The schema's long "this is impossible"
  description on `model_configured` is replaced by a short one plus a real
  `model_served` field.

### Stale model names

Three places named 3.5 Flash outside the manifest, none of them a source of
truth, all of them misleading to read: `MCPLLMClient.__init__`'s default
`model_id`, one comment in `LLMDispatcher.__init__`, and `shell.py`'s legacy
no-tier-specs fallback (unreachable whenever the manifest loads).

`docker-compose.yml` set `EVENTMILL_MODEL_ID=gemini-2.5-flash` in both services.
**Nothing reads that variable** — grep confirms no consumer anywhere in the tree.
Removed from both, with a comment naming `EVENTMILL_MODEL_LIGHT` /
`EVENTMILL_MODEL_HEAVY` as the real overrides rather than leaving a dead,
two-generations-stale id that reads as configuration.

### Documentation

Tier tables in `AGENTS.md`, `README.md` and `cloud_install/README.md`; the
env-var default in `docs/specs/eventmill_v1_1.md`; the sample `connect` output in
the network forensics guide. Two new `AGENTS.md` bullets: why the light tier has
a fallback, and the `model_used` / `model_version` distinction.
`cloud_install/README.md` also gains `EVENTMILL_MAX_OUTPUT_LIGHT` /
`_HEAVY` in the env-var table — the model override and the cap override have to
be set together, and only the model one was documented.

## Decisions

- **`structured_output` stays declared and unused.** Discussed at length and
  deliberately not adopted; the reasoning is in the plan's Stage 6. The short
  version: a schema could enforce the envelope (valid JSON, required keys, the
  seven access states as an `enum`) but not the reasoning checks that matter, and
  during a model comparison the tolerant paths are the instrument —
  `ACCESS_STATE_UNKNOWN` is evidence about how well a model follows the contract,
  and an `enum` would force a legal value and erase the tell. Enumerating
  `technique_id` or `component_id` would be worse still: it drives
  `TECHNIQUE_NOT_IN_SET` to zero by steering the model rather than catching it.
  If a swap ever produces *parse failures*, the narrow fix is
  `response_mime_type="application/json"` alone, no schema.
- **`output_budget` and `file_handling` stay provider-global.** They are not
  per-tier, and `thinking_reserve_tokens()` / `tokens_per_pdf_page()` take no
  tier argument, so a mixed-model state cannot express two different thinking
  reserves or PDF page costs. Kept shared on the assumption the two models agree;
  moving them under each tier is a loader plus accessor change and waits for
  evidence that they differ.
- **`deep_reasoning` not declared on light.** No runtime consumer exists for it,
  so this is a labelling choice; keeping it off preserves the tier distinction.

## Tests

**945 passed**, was 937. Added:

- `TestServedModelIsRecorded` — the helper reads a reported version and yields
  `None` for an absent or empty one; the document path records configured and
  served ids separately; the text path carries the served version; a provider
  that reports nothing leaves it `None`.
- `test_ga_light_tier_needs_no_fallback` — a GA tier declares none, so a
  mistyped model id fails loudly instead of being masked.
- `test_a_redundant_model_pin_is_not_treated_as_a_substitution` — an env pin
  naming the manifest's own model must not warn about a cap that was never
  wrong.
- The projector's run record keeps `model_configured` and `model_served` apart.

`_FakeSDKResponse` gained an optional `model_version`, set only when supplied, so
the existing tests still exercise the provider-reports-nothing path. The
projector's `_Resp` fake carries `model_version="mock-heavy-001"` against
`model_used="mock-heavy"`, so a test asserting they are separate fails if the two
are ever wired to the same source.

`validate_manifests.py` still reports exactly the 15 pre-existing `stability`
errors. `ruff`/`black` are not installed here; style matched by hand.

## Verified live

The repo `.env` holds two Gemini keys, both model-agnostic, so everything the
first pass recorded as an assumption was checked against the API on 2026-09-12.
Every assumption held.

| Fact | Result |
|---|---|
| model id | `models/gemini-3.8-flash` exists, `display_name` "Gemini 3.8 Flash" |
| context / output | 1,048,576 / 65,536 — identical to 3.5 Flash and to heavy, so the capacity-identical invariant survives untouched |
| GA or Preview | **GA**, no `-preview` suffix — hence no fallback |
| `thinking_level` | honoured: `LOW` 51 vs `HIGH` 129 thought tokens on one prompt |
| native PDF | read a 3-page PDF and answered correctly |
| `model_version` | **populated** — returns `gemini-3.8-flash` |

Run through Event Mill's own code, not just the SDK: `MCPLLMClient` +
`LLMDispatcher` with the manifest's tier spec, on both the text path and
`_execute_document_query`. Both returned `model_used='gemini-3.8-flash'` and
`model_version='gemini-3.8-flash'`, `finish_reason='STOP'`, nothing truncated.

**PDF page cost, measured.** Marginal tokens per letter-size page, taken as the
difference between a 9-page and a 3-page document so fixed overhead cancels:

| `media_resolution` | declared | measured |
|---|---|---|
| `low` | 280 | 266 |
| `medium` | 560 | 520 |
| `high` | 1120 | 1102 |

The declared values are **kept**. They are a 2-7% conservative upper bound, page
size is not constant across real documents, and the guard exists to refuse
before the provider does. AGENTS.md's worked example survives either way: 1000
pages at `high` is 1.102M tokens measured against a 1M window, still a refusal.

## Found by testing, and fixed

Three things the live run surfaced that the offline pass could not:

- **The repo `.env` pinned `EVENTMILL_MODEL_LIGHT=gemini-3.5-flash`.** An env
  pin outranks the manifest, so the tier swap was correct in the source and
  inert in this environment — a failure with no error message, and the single
  most valuable thing this exercise turned up. Commented out, with a note saying
  why, so the manifest governs. `EVENTMILL_MODEL_HEAVY` is left pinned: it names
  the manifest's own model and heavy is out of scope.
- **A redundant pin warned as if it were a substitution.** `load_tier_specs()`
  warned about the output cap whenever an override was set, including when the
  override named the manifest's own model — noise on every start, and noise that
  reads like a misconfiguration. It now warns only when the override actually
  changes the model.
- **`thinking_level` and `media_resolution` were passed to the SDK as strings**
  where both fields are enum-typed, which emitted a Pydantic serializer warning
  on every document call. Values were coerced correctly — the 813-token `low`
  reading confirms the resolution was applied — but a future SDK need not keep
  coercing. `_build_config` now looks up `ThinkingLevel` and `MediaResolution`
  members.

## Stage 5 — the light-tier probe, run

> Read with the follow-up section below: the first pass ran at
> `thinking_level="low"` with the tier pinned heavy, which is what the code did
> at the time. Both were changed afterwards and the probe was re-run.

No PDF had been ingested locally under 3.5 Flash (those runs were on the
container), so rather than compare against a missing baseline the probe was run
as a **controlled A/B**: one document, `EVENTMILL_MODEL_LIGHT` pinned to
`gemini-3.5-flash` for one run and left to the manifest for the other,
everything else held constant.

The document is synthetic and its IOC inventory is **exact** —
`make_probe_pdf.py` emits a 3-page report carrying 94 unique indicators
(24 IP, 20 domain, 16 sha256, 12 URL, 10 CVE, 12 technique) plus the ground
truth as JSON. That turns the probe from "did the two agree" into "how much did
each one actually find", which is the question the 70-of-150 incident raised.
Regex finds 106 candidates against those 94 — the 12 extra being hostnames
inside the URLs — so the refinement stage has real discrimination to do.

| | 3.5 Flash | 3.8 Flash |
|---|---|---|
| Wall time | 42.2 s | **29.7–30.0 s** |
| Plan chosen | `native_batched`, 2 batches | identical |
| IOC records | 94 | 94 |
| Ground-truth IOCs recalled | 82/82 non-technique | 82/82 non-technique |
| Derived hostnames kept | 12 | 12 |
| `finish_reason` | STOP | STOP (both batches) |
| Truncated / repaired | no | no |
| Documented techniques recalled | **12/12** | **12/12** |
| Techniques inferred beyond the document | 6 | **3** |
| `tactic_mismatch` flagged | **T1078** | none |

**IOC extraction is indistinguishable.** Same 94 records, same values, same
derived hostnames, nothing truncated on either. For the work the light tier
actually does, the two models are interchangeable on this corpus.

**One tactic differed, and it was not the model — corrected below.** At
`thinking_level="low"` 3.5 labelled T1078 *Lateral Movement*, which ATT&CK does
not allow for that technique, so `_reconcile_mitre_mappings` set
`tactic_mismatch=true` and printed "Tactic needs analyst review"; 3.8 labelled
it *Persistence* and carried no mismatch. That looked like a model difference
and was reported as one. The control run at `medium` (below) shows **3.5 also
gets T1078 right once it is allowed to think**, so the difference belongs to the
thinking level, not to the model.

**3.8 Flash inferred less at `low`** — three techniques beyond the document
against 3.5's six, documented twelve fully recalled either way. At `medium` the
two converge on four each, so this too is a thinking-level effect rather than a
model one.

**~29% faster at equal output**, 42.2 s to 29.7 s, with `thinking_tokens: 0` on
both native batches — `thinking_level="low"` on extraction work spent nothing,
so the 4,096-token reserve `_native_content_budget()` held back was pure
headroom on this corpus.

## The ingester moves onto the light tier, and thinks harder

Two changes to `threat_intel_ingester` after the probe, both at the operator's
direction, on the reasoning that **3.8 Flash reads PDFs better than 3.1 Pro**.

**Unpinned, not repinned.** `_NATIVE_TIER = "heavy"` is gone rather than set to
`"light"`. The native call's `QueryHints` now names no tier at all, so
`TierScopedLLMClient` applies the manifest's `model_tier` and the manifest is
once again the only place this plugin's model is chosen. `_native_tier()`
replaces the constant, reading `model_tier` from the plugin's own manifest and
cached, used solely to size the output budget against the cap of the model that
will actually run. A missing or unreadable manifest falls back to `light`, which
is what the framework's precedence rule would have done anyway.

**`_NATIVE_THINKING_LEVEL` "low" → "medium".** The consequence is not free and
is worth stating: `_native_content_budget()` subtracts the reserve for the
level, so usable output per call drops **61,440 → 49,152** and dense documents
batch into smaller pieces. On this corpus the plan was unchanged (2 batches),
but a document near the boundary will now split where it did not before.

This also sits against a standing rule in `AGENTS.md` — *bulk extraction should
pass `thinking_level="low"` or it pays reasoning cost per chunk*. That rule is
still right for pure pattern work; the judgement here is that reading a report
is not pure pattern work. `AGENTS.md` now records the exception rather than
being silently contradicted by the code.

### Re-run, both models, under the new configuration

Same document, same ground truth, light tier and `medium` both times:

| | 3.5 Flash | 3.8 Flash |
|---|---|---|
| Wall time | 59.8 s | **41.9 s** |
| IOC records | 94 | 94 |
| Ground-truth IOCs | 82/82 | 82/82 |
| MITRE mappings | 16 | 16 |
| Documented techniques | 12/12 | 12/12 |
| Inferred beyond the document | 4 | 4 |
| `tactic_mismatch` | none | none |
| T1078 tactic | Persistence | Persistence |

**At `medium` the two models are indistinguishable on output and 3.8 is 30%
faster.** That is the cleanest result the exercise produced, and it also
retracts the earlier T1078 claim: 3.5's wrong tactic came from `low` thinking,
not from being the older model.

**What `medium` bought on this corpus is mostly latency.** For 3.8, `low` → `medium`
cost 30.0 s → 41.9 s (+40%) and moved mappings 15 → 16 with identical IOC
output. This document is synthetic and IOC-dense — the case least likely to
need reasoning — so it is close to a worst case for justifying the extra
thinking, and a real report with ambiguous prose is where the change should pay
off. Worth re-checking against a genuine report before treating `medium` as
settled.

## Heavy tier thinking — audited, not changed

Asked to confirm 3.1 Pro still runs at high thinking. **It does not, and it never
uniformly did.** The mechanism is intact — `client.py` still resolves an unset
level to `"high"` whenever `needs_reasoning` is set, and the enum change above
did not touch that branch — but only one call path reaches it:

| Heavy-tier plugin | Thinking level it actually gets |
|---|---|
| `threat_report_analyzer` (synthesis pass) | **high** — `QueryHints(tier="heavy", needs_reasoning=True)` |
| `adversary_path_projector` | **medium** — `DEFAULT_THINKING_LEVEL`, deliberate, env- and payload-overridable |
| `threat_model_analyzer` | provider default (**medium**) — sends no `QueryHints` at all |
| `risk_assessment_analyzer` | provider default (**medium**) — same |
| `log_investigator` | provider default (**medium**) — same |
| `pcap_ai_analyzer` | provider default (**medium**) — same |

Four heavy plugins pass no hints, so they get whatever Gemini 3.x defaults to,
which `AGENTS.md` records as `medium`. Whether that is intended is a separate
decision from this swap, and nothing here changed it.

## Not in this change

- **The heavy tier**, and therefore the projector's model. Stage B, with the
  `stepstate-medium-2` baseline to be judged against — rejections being the
  number that matters.
- **`_NATIVE_TIER` in `threat_intel_ingester`.** The probe surfaced that this
  light-manifest plugin pins `tier="heavy"` on its native PDF path
  (`tool.py:290`), so in production that path runs on **3.1 Pro**, not on the
  light model; only its chunked-text fallback is `tier="light"`. The probe
  measured the two Flash models on that path because only a light client was
  connected and the dispatcher falls back when the preferred tier is absent — a
  valid comparison of the two models on that work, but **not what production
  does there**. Whether a light-manifest plugin should pin heavy for its main
  path is a real question, and not one to settle inside a model swap.
- **Per-tier `output_budget` / `file_handling`.** See Decisions.
- **Any prompt change.** Prompt tokens have to stay identical or a model
  comparison means nothing.
- **Phase 4 (`normalize_flow_map`)**, untouched and still the projector's next
  piece of work.
