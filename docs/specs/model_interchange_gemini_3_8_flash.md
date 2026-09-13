# Plan — moving to Gemini 3.8 Flash

**Date:** 2026-09-12
**Branch:** `llm-tiering-gemini-3x`
**Status:** Stage A (light tier) implemented 2026-09-12; Stage B (heavy tier)
not started. See `docs/change_log/2026-09-12-light-tier-gemini-3-8-flash.md`.

The first real test of whether Event Mill's model layer is interchangeable.
Most of what that test needs already exists — a single-source-of-truth provider
manifest, per-tier env overrides, token clamping keyed by model id, and a
deterministic validation layer that turns "did the new model do worse" into a
number. This plan is mostly about using those, in an order that keeps the answer
attributable.

---

## The scope decision, first

"Moving to Flash 3.8" reads two ways, and they are different jobs:

| | What changes | Plugins affected | Risk |
|---|---|---|---|
| **A — light tier** | `gemini-3.5-flash` → `gemini-3.8-flash` | `log_pattern_analyzer`, `pcap_report_correlator`, and `threat_intel_ingester`'s *chunked-text fallback only* — see the correction below | low |
| **B — heavy tier** | `gemini-3.1-pro-preview` → `gemini-3.8-flash` | `adversary_path_projector`, `threat_model_analyzer`, `threat_report_analyzer`, `risk_assessment_analyzer`, `log_investigator`, `pcap_ai_analyzer` | high |

**Decided 2026-09-12: A only. The heavy tier is untouched** — `model_id` still
`gemini-3.1-pro-preview`, and its `fallback_model_id` still `gemini-3.5-flash`,
which is now a model no tier runs as its primary. That is a loose end, not a
fault: 3.5 Flash remains a live GA endpoint, so a retired Pro still lands
somewhere that works. Retarget it when Stage B is taken up.

**Recommendation: A first, then B as a separate change.** A exercises every
mechanical step of a swap — manifest, env override, clamping, tests, docs — with
a small blast radius. B is the interesting test (deep reasoning, closed-set
obedience, strict JSON under a ~3,900-token prompt) and it has a measured
baseline to be judged against. Done together, a regression cannot be attributed
to a tier.

If B also lands, the two tiers become the same model family and "tier" degrades
to a thinking-level and cost distinction. That is a legitimate outcome — but it
should be a decision recorded in `AGENTS.md`, not a side effect.

---

## Stage 0 — confirm the model facts before editing anything

**DONE 2026-09-12**, against the live API using `GEMINI_FLASH_API_KEY` from the
repo `.env`:

| Fact | Answer |
|---|---|
| model id | `models/gemini-3.8-flash` exists; `display_name` "Gemini 3.8 Flash" |
| context / output | 1,048,576 / 65,536 — identical to 3.5 Flash and to heavy |
| GA or Preview | **GA** — no `-preview` suffix, so no `fallback_model_id` |
| `thinking_level` | honoured; `LOW` 51 vs `HIGH` 129 thought tokens on one prompt |
| native PDF | yes — read a 3-page PDF and answered correctly |
| PDF page cost | marginal per letter page: `low` 266, `medium` 520, `high` 1102 |
| `model_version` | populated, so the Stage 6 capture is not decorative |

The declared page costs (280 / 560 / 1120) are **kept**, as a deliberate 2-7%
upper bound: page size is not constant across real documents and the guard
exists to refuse before the provider does.

---

## Stage 1 — canary by environment variable, no code

```bash
export EVENTMILL_MODEL_LIGHT=gemini-3.8-flash
export EVENTMILL_MAX_OUTPUT_LIGHT=<cap>    # only if it differs from 65,536
```

`load_tier_specs()` in `framework/llm/providers/__init__.py` warns when the
model override is set without the matching cap override, because a substitute
model clamped against the wrong cap fails at the provider. An override naming
the manifest's own model is a redundant pin, not a substitution, and is silent.

**The trap this stage exists to catch, found live:** the repo `.env` pinned
`EVENTMILL_MODEL_LIGHT=gemini-3.5-flash`. An env pin outranks the manifest, so
the tier change would have been inert in this environment and correct in the
source — the failure mode with no error message. Check deployment `.env` files
before concluding a model change did nothing.

Then `connect`, then one light-tier plugin. **If this stage needs a code change,
that is the finding** — the override path is the interchange mechanism, and
anything it cannot express is real coupling.

Verification: `model_used` is the id the client was *constructed* with;
`model_version` (added 2026-09-12, Stage 6) is what the provider says served the
request. Check both — the first confirms the override took, the second confirms
what ran.

---

## Stage 2 — promote into the provider manifest

`framework/llm/providers/gcp_gemini.json` is the only place model facts belong.

- the `light` tier block: `model_id`, `display_name`, `max_output_tokens`,
  `max_context_tokens`, `capabilities`, `fallback_model_id`, `_fallback_note`
- ~~**the `heavy` tier's `fallback_model_id`**~~ — deliberately left at
  `gemini-3.5-flash` on 2026-09-12, because the heavy tier was out of scope. A
  retired Pro still lands on a live GA endpoint; retarget it with Stage B.
- **the `light` tier's `fallback_model_id`** stays `""`. It was briefly set to
  `gemini-3.5-flash` as a hedge against an unverified id; Stage 0 confirmed 3.8
  Flash is GA, so the hedge came back out — a fallback there would only have
  masked a mistyped model id.

### The one structural problem to settle here

`output_budget` and `file_handling` are **provider-global, not per-tier**:
`thinking_reserve_tokens()` and `tokens_per_pdf_page()` take no tier argument.
A mixed state — 3.8 Flash on light, 3.1 Pro on heavy — cannot express two
different thinking reserves or two different PDF page costs.

Two ways out, and the choice should be deliberate:

1. **Keep them shared**, taking the more conservative of the two models'
   numbers. Costs nothing, slightly over-reserves on one tier.
2. **Move `output_budget` and `file_handling` under each tier**, with
   provider-level values as the default. A loader change plus an accessor
   signature change — `thinking_reserve_tokens(level, tier=...)` — and every
   call site with it. This is the first genuine structural cost interchange has
   surfaced.

Recommendation: **(1) now, (2) only if the two models' numbers actually
differ.** Stage 0 answers that.

---

## Stage 3 — invariants that may not survive, and pins to update

**1. "The tiers are capacity-identical."** Documented in `AGENTS.md` and
asserted by `test_tiers_are_capacity_identical`. If 3.8 Flash's caps differ, the
invariant is gone — retire it from `AGENTS.md` and `README.md` rather than
loosening the test quietly. The adjacent rule, *tier must never be chosen from
data size*, still holds and must not be reopened.

**2. `deep_reasoning` is not in the light tier's capabilities.** Asserted by
`test_ships_light_and_heavy_tiers`. A reasoning-capable Flash invites declaring
it, which fails that test and flattens the tier distinction. Worth knowing
before deciding: `deep_reasoning` has **no runtime consumer** — it appears only
in the manifest, one spec diagram, and two tests. It is a label with no
behaviour attached, so this is a documentation decision, not a functional one.

**3. Pins to fix:**

| Location | Issue |
|---|---|
| `tests/framework/test_llm_dispatcher.py:686` | NOT_FOUND retry fixture names `gemini-3.1-pro-preview` — **left as is**, heavy is untouched |
| `tests/framework/test_llm_dispatcher.py:350-387` | the two invariant tests above — **both still pass**; the assumed caps kept capacity-identical true, and `deep_reasoning` was not declared on light |
| `framework/cli/shell.py:443` | **done** — legacy no-spec fallback now names 3.8 Flash |
| `framework/llm/client.py:139` | **done** — `MCPLLMClient` default `model_id` |
| `docker-compose.yml:13,33` | **done** — the dead `EVENTMILL_MODEL_ID` is removed from both services, with a comment naming the real overrides |

---

## Stage 4 — documentation

| File | What |
|---|---|
| `AGENTS.md:79-82` | the tier table, plus the Preview/fallback bullet |
| `README.md:69-70` | tier table |
| `cloud_install/README.md:179-180, 388-389` | tier table and the env-var reference |
| `docs/specs/eventmill_v1_1.md:166` | env-var defaults |
| `docs/guides/network_forensics_analysis.md:1304` | sample `connect` output |

---

## Stage 5 — what counts as evidence

The point is not "it ran". It is whether output quality held, measured against
numbers that already exist.

### Light tier (Stage A) — DONE 2026-09-12

Run as a controlled A/B rather than against a historical baseline: one synthetic
3-page report with an **exact 94-IOC ground truth**, run twice with only
`EVENTMILL_MODEL_LIGHT` changed. Full table in
`docs/change_log/2026-09-12-light-tier-gemini-3-8-flash.md`. Result:

- **IOC extraction is indistinguishable** — 94 records both, same values,
  `finish_reason` STOP, nothing truncated or repaired.
- **~29% faster** at identical output: 42.2 s to 29.7 s.
- Two apparent quality differences at `thinking_level="low"` — 3.5 mislabelling
  T1078's tactic, and 3.5 inferring six extra techniques to 3.8's three —
  **did not survive the control run**. Re-run at `medium`, both models produce
  94 IOCs, 16 mappings, 4 inferred and no `tactic_mismatch`. Those were
  thinking-level effects, not model differences.
- Re-run at `medium` on the light tier: **3.5 59.8 s vs 3.8 41.9 s**, output
  indistinguishable. Speed is the whole of the difference on this corpus.

**Correction the probe forced.** `threat_intel_ingester` declares
`model_tier: light` in its manifest but pins `tier="heavy"` on its native PDF
path (`_NATIVE_TIER`, `tool.py:290`), and per-call hints outrank the manifest. So
in production that path runs on **3.1 Pro**, and only the chunked-text fallback
is light. The probe reached the Flash models there because only a light client
was connected and the dispatcher falls back when the preferred tier is absent —
a valid comparison of the two models on that work, but not what production does
on that path. The affected-plugins table above is corrected accordingly.

### Heavy tier (Stage B)

The projector against `claims_portal_flow_map.json`, Volt Typhoon,
`--runs 3 --run_group flash38-medium`, `thinking_level=medium`, **prompt and
flow map untouched** so the map hash `03dbb641ee79` still matches and the run
records compare directly to `stepstate-medium-2` (2026-09-11):

| Metric | Baseline (3.1 Pro, `medium`) | What a move means |
|---|---|---|
| Prompt tokens | 3,909 | should be ~identical; a shift is tokenizer, not behaviour |
| **Rejections** | **0** | the closed-set obedience measure — non-zero means techniques placed outside the actor's documented set |
| Paths per run | 2, 2, 1 | breadth |
| Steps, total | 29 | depth per path |
| Routes | `portal→claims_api→doc_store` 3 of 3; `portal→claims_api→claims_db` 2 of 3 | route recurrence is the Phase 3b signal |
| `finish_reason` / `truncated` | STOP ×3 / false | the 48K cap was nowhere near binding |
| Completion / thinking / total, mean | 2,232 / 4,226 / 10,368 | cost |
| Wall time, mean | 52.7 s (37.8–74.1) | against the 180 s `X-Server-Timeout` |
| State-gap classification | 4 delegated-access, 2 reach-without-control | whether the most useful line still prints |

**Pass bar:** zero rejections, nothing truncated, both crown jewels reached in
at least 2 of 3 runs, and the `doc_store` route still 3 of 3. Anything less and
3.8 Flash is cheaper and worse on this work — a finding worth writing down, not
a reason to move the bar.

Run the group twice if the first is marginal. Three runs is a small sample and
the existing records already show run-to-run variance in path count.

---

## Stage 6 — two gaps this swap makes expensive

Both pre-existing, both optional, and both harder to ignore once two models are
being compared.

**`model_version` — DONE 2026-09-12.** `LLMResponse.model_version` now carries
the id the API reports, captured by `_model_version()` on all three paths that
hold a provider response (text, multimodal, native document). The projector
writes it as `model.model_served` alongside `model_configured`, at run record
`schema_version` 3. A provider-side version change inside one alias is now
visible in the corpus, which is what Stage B's conclusions rest on.

**`structured_output` is declared and unused — and stays that way for now.**
No `response_schema` or `response_mime_type` anywhere in `client.py`. The
projector states the reply shape in prose (`tool.py:1133-1160`), and
`_parse_llm_json` strips fences, parses once, and refuses to repair a truncated
reply. That is determinism by refusing to guess, and constrained decoding is the
same instinct moved earlier — not a retreat to prompt-coaxing. But its ceiling
is narrow and its cost during a comparison is real:

- **What a schema could enforce:** valid JSON, required keys and types, and the
  seven-state `access_before` / `access_after` vocabulary as an `enum`.
- **What it could not:** `TACTIC_CORRECTED` (a relationship, not a value set),
  and `KILL_CHAIN_REGRESSION` / `HOP_NOT_DECLARED` / `STATE_GAP` — the reasoning
  checks, which are the point.
- **What it must not:** `technique_id` and `component_id` as per-call dynamic
  enums. That drives `TECHNIQUE_NOT_IN_SET` to zero by steering the model
  instead of catching it, and destroys the one number Stage 5 is built on.
- **Why not during the swap:** an off-vocabulary `access_before` produces
  `ACCESS_STATE_UNKNOWN` today, which is evidence about how well a model follows
  the contract. An `enum` forces a legal value and the tell disappears. The
  warning codes are the instrument; do not change the instrument while taking
  the measurement.
- **It also does not fix truncation.** A reply cut at the output cap is invalid
  JSON constrained or not; the `truncated` check at `tool.py:3406` stays first.
- **And it is a provider feature in the provider-neutral layer.** `_build_config`
  sets only generic generation controls. A `response_schema` would be the first
  time a plugin's output shape is encoded into a provider's API object, inside
  the layer whose job is interchange. If it ever lands it belongs behind a
  `QueryHints` field the dispatcher translates, never a `genai_types` object
  built in a plugin.

**The narrow fix, if Stage 5 produces parse failures** (as opposed to rejections
or warnings, which are working as designed): `response_mime_type="application/json"`
alone, no schema. It removes fences and prose preamble without encoding any
plugin shape in the provider call and without constraining a single value, so
every validator, alias table and warning code behaves exactly as it does now. A
full `response_schema` only if the envelope itself proves unstable.

---

## Out of scope, deliberately

- **No prompt changes during the swap.** Prompt tokens must stay identical or
  the comparison means nothing. Prompt work and model work are separate commits.
- **No reasoning-depth changes.** The projector stays at `medium`. Depth is a
  floor to defend, not a dial to turn while swapping models.
- **No tier-selection logic.** Tier is never chosen from data size.
- **Phase 4 (`normalize_flow_map`)** is unrelated and should not be interleaved;
  a failed swap and a new code path in one working tree is two problems at once.

## Rollback

Stage 1 reverts by unsetting `EVENTMILL_MODEL_LIGHT`. Stage 2 reverts by
restoring one block in one JSON file. The manifest is only edited after the
canary has passed live, so the rollback that matters is the cheap one.
