# Plan — running `adversary_path_projector` across three vendors

**Date:** 2026-09-14
**Status:** proposed, nothing built
**Parent:** `docs/specs/multi_provider_llm_clients.md` — this is the
implementation plan for the enabling half of its Stage 5 and the run design in
its Part 2. It does not restate the metrics; those are settled there.

---

## Why this and not the PDF guard

The PDF guard reading Gemini's 1000-page / 50 MB limits whatever provider is
selected is a wrong answer rather than a missing feature, and it is correctly
listed first in the Stage 2 accessor work. It is also **not on this path.**

`adversary_path_projector` has exactly one LLM call — `tool.py:3384`,
`query_text`, heavy tier. It never calls `query_with_document`, never touches
`pdf_handling()` or `tokens_per_pdf_page()`, and never needs `remote_uri_gs`.
Its input is a flow map read from disk and an ATT&CK technique set assembled
deterministically in-process. So the whole document-parity branch of Stage 2 —
items 1, 4 and 6 of the handoff list — gates nothing here.

That is the reason the parent plan named this module first, and it still holds:
**the projector is the one module that can be compared across three vendors
with none of the document work resolved.**

What it does need is smaller, and lives almost entirely in the shell and the
run record.

## What is actually missing

Verified in the tree at `d314815`, not assumed:

| # | Gap | Where | Effect |
|---|---|---|---|
| 1 | `do_connect` constructs `GeminiClient` directly, in both its branches | `shell.py:3565-3688` | no second vendor can be bound for tool execution, whatever `EVENTMILL_LLM_PROVIDERS` says |
| 2 | `_discover_models` reads `self._tier_specs` (Gemini's manifest only) and stamps `provider: DEFAULT_PROVIDER_ID` on every row | `shell.py:401-454` | a mounted `ANTHROPIC_API_KEY` is invisible to `models` and to `connect` |
| 3 | `TierScopedLLMClient` is built with no `default_provider` | `shell.py:2786` | the parameter exists, is threaded through the dispatcher, and nothing sets it |
| 4 | no operator-facing way to choose a vendor | — | `use <provider> [for <tool>]` is unwritten |
| 5 | the run record hardcodes `"provider": "gcp_gemini"` | `tool.py:3506` | **every record from every vendor would claim Gemini** — the one failure that makes a multi-vendor group unreadable rather than merely incomplete |
| 6 | `_summarize_run_group` has no provider dimension | `tool.py:2325` | three Gemini samples would outvote two other vendors on the recurrence threshold |

Items 1 and 2 are Stage 5 of the parent plan. Item 3 is the last thread of the
Stage 2 rekey. Items 5 and 6 are new work in the plugin, and 6 is the only
place a real design decision is left.

## The constraint that shapes the design

`test_a_plugin_cannot_reach_the_provider_argument` asserts that
`TierScopedLLMClient`'s signature exposes no `provider`, and the recorded
requirement is why: vendor choice is an operator decision, so a plugin must not
be able to see or override it.

**The projector therefore cannot fan itself out across vendors.** One
`execute()` runs against exactly one provider — the one the shell scoped its
wrapper to. Spreading runs across vendors has to happen one level up.

The parent plan's Part 2 says "concurrent binding makes this one invocation
rather than three sessions". The confound it names is *three sessions* — session
state, artifact set and environment drift all move between them. **Three
invocations inside one session hold every one of those fixed**, so:

> `use <provider> for adversary_path_projector` plus three `run` commands in one
> session removes the confound the plan was worried about. A single-command
> fan-out is convenience, not correctness, and is deferred.

That matters because `do_run` (`shell.py:2653`) is one long method with payload
parsing and execution inline; an `--across` flag needs the execution body
extracted into a helper first. Worth doing eventually, not worth doing to get
the demonstration.

---

# Stages

## Stage A — `connect` binds every configured provider — **DONE 2026-09-14**

Change log: `docs/change_log/2026-09-14-connect-binds-every-provider.md`.
Landed as written except for two deviations recorded there: `do_connect` takes
only the *class* from the registry rather than calling `build_clients`, so the
legacy single `GEMINI_API_KEY` keeps working; and the vestigial
`EVENTMILL_MCP_TRANSPORT` no longer reaches the client. Two things the plan did
not anticipate were needed and are in: a placeholder key must bind nothing, and
the shell must hand the dispatcher a `(provider_id, tier)`-keyed spec map or
Anthropic's 128,000-token cap gets priced off Gemini's 65,536.

The whole demonstration is blocked on this and nothing else is blocked on it.

- `_discover_models` iterates `llm_factory.configured_providers()` and calls
  `load_tier_specs(provider_id)` per provider, stamping the real `provider`.
  Keep the legacy `GEMINI_API_KEY` fallback exactly as it is — it is scoped to
  Gemini and must stay scoped to Gemini.
- `do_connect`'s no-argument branch calls `llm_factory.build_clients(pid)` for
  each configured provider and merges the results into a
  `{(provider_id, tier): client}` dict. The dispatcher accepts both shapes, so
  pass the two-dimensional one now that the shell actually has it.
- `do_connect <model_id>` resolves the model through the discovered rows (which
  now carry `provider`) and builds through the factory too. Its silent "other
  tier for quota fallback" bind stays **within the selected provider** —
  `_fallback_client` is provider-scoped and this must not reintroduce
  cross-vendor hopping through the back door.
- Every bind prints provider, tier, model id and key env var. The 3.8 swap's
  lesson was a change correct in source and inert in the environment; several
  vendors bound at once has strictly more ways to be half-applied.

**The guard test has to be rewritten, not deleted.**
`TestOnlyGeminiIsBoundForToolExecution` (`test_provider_registry.py:431`) says
"binds exactly one" because keying by tier alone made a second vendor evict the
first. The rekey removed that hazard; the test's *premise* is now stale but its
*subject* is not. It becomes `TestOnlyConfiguredProvidersAreBound`:

- with `EVENTMILL_LLM_PROVIDERS=gcp_gemini`, `_clients` is Gemini-only even with
  all four keys present — **a mounted key is not a bound provider**;
- with all three named, `bound_providers()` is all three and every client's
  `provider_id` matches the key it was built from;
- `providers probe` still leaves `_clients` byte-identical.

**Done when:** `connect` on a three-provider `.env` prints six bindings and
`models` lists six provider-qualified rows.

## Stage B — the operator chooses, per module — **DONE 2026-09-14**

Change log: `docs/change_log/2026-09-14-use-provider-per-module.md`. Landed as
written, plus three things the plan did not call for and should have: `connect`
prunes a selection whose provider is no longer bound, `ask:` follows the
session default (but not a per-tool override — it is not a tool), and an
unknown tool name in `use ... for <tool>` is refused rather than stored.

- **`do_use`** (no collision; `do_run` is the tool runner):

  ```
  use <provider>                     session default for every tool
  use <provider> for <tool_name>     override for one module
  use default [for <tool_name>]      clear it
  use                                show what is set
  ```

  Refuse a provider that is not bound, naming what is, rather than accepting it
  and failing at the next run. Store as `self._provider_default: str | None` and
  `self._provider_by_tool: dict[str, str]`, session-scoped and not persisted —
  an A/B selection surviving a restart invisibly is the same hazard as a stale
  `.env` pin.

- **`shell.py:2786`** passes the resolved provider:

  ```python
  scoped_llm = TierScopedLLMClient(
      self.llm_client,
      default_tier=model_tier,
      default_provider=self._provider_for(tool_name),
  )
  ```

  `_provider_for` is per-tool override, then session default, then `None` — and
  `None` must keep meaning "the dispatcher's own default", so a single-vendor
  session stays byte-identical to today.

- Announce it at run time. `do_run` already prints
  `Running <tool> (timeout Ns)...`; append the provider when one is scoped, so
  every line of a three-vendor transcript says which vendor produced it.

**Done when:** `use anthropic for adversary_path_projector` followed by a run
produces a response whose `provider_id` is `anthropic`, with no other tool
affected.

## Stage C — attribution on the record — **DONE 2026-09-14**

Change log: `docs/change_log/2026-09-14-run-record-attribution.md`. Landed as
written, minus `effort_requested` — `model.thinking_level` already records what
was asked for, and a second field saying the same thing would be a duplicate
rather than a fact. The `medium`/`high` mapping to `output_config.effort` and
`reasoning_effort` is recorded in the change log instead. Added beyond the
plan: `provider` on the single-run result, so an operator reads it off the run
rather than opening the record; and a cross-hash-seed check proving the prompt
carries nothing set-ordered, which the plan assumed.

`RUN_RECORD_SCHEMA_VERSION` 3 to 4. Four changes in the `model` block
(`tool.py:3500-3515`):

- `provider` reads `getattr(response, "provider_id", None)` — the dispatcher
  stamps it as a backstop, so it is always present on a real run. **Never fall
  back to the literal `"gcp_gemini"`**; a record that guesses its vendor is
  worse than one that admits it does not know. On a failed attempt with no
  response, write `null`.
- `tier` stays `"heavy"` (a constant of the call site). `model_configured` /
  `model_served` already work on all three clients (`anthropic.py:418`,
  `openai.py:415`), so the "what actually served it" gap is already closed.
- **`prompt_sha256`** — new, and the cheapest thing in this plan. The whole
  comparison rests on the prompt being byte-identical across vendors, and that
  is currently an argument rather than a fact on the record. A hash of
  `prompt + PROJECTION_SYSTEM_CONTEXT` makes it checkable, and lets
  `_summarize_run_group` warn when it is comparing runs that were not given the
  same input.
- `effort_requested` — the `thinking_level` the tool asked for. It maps to
  `output_config.effort` on Anthropic and `reasoning_effort` on OpenAI, and both
  map `medium` and `high` identically (`anthropic.py:52`, `openai.py:57`), so
  the baseline's `medium` is comparable across all three. `minimal` is mapped
  *up* to `low` on both non-Gemini vendors and must not be used for a
  comparison run.

Readers of v3 records must tolerate a missing `model.provider` (treat as
`unknown`) rather than crash — the 09-11 and 09-12 group records are the
baseline this is measured against.

**Done when:** a run under `use openai` writes a record whose `model.provider`
is `openai`, and `--runs 3` under each of three providers yields nine records
naming three vendors.

## Stage D — make the group summary read a mixed group — **DONE 2026-09-14**

Change log: `docs/change_log/2026-09-14-group-summary-provider-dimension.md`.
The five proposed rules landed as written. Two things the plan did not settle,
decided while building: `recurring` is true when **at least one** provider kept
finding the route (not a majority of providers) — the tool is triage and a
route one model produced consistently is a reason to look; and a vendor whose
every run failed does not vote, or unanimity becomes unreachable for reasons
unrelated to the architecture. Also rewritten: the report's "found in N of M
runs is a pattern worth testing" paragraph, which quoted a threshold that no
longer decides recurrence in a mixed group.

This is the only genuine design decision, and it needs a call before the code.

Today, `recurring` = a route found in at least half the **successful runs of the
group**, with a three-successful-run minimum (`tool.py:2357-2380`). In a
nine-record, three-vendor group that is wrong in a specific way: a route found
in all three Gemini runs and nowhere else scores 3/9 and is not recurring, while
a route found twice by Gemini and twice by OpenAI scores 4/9 and also is not.
Those are very different findings and one number cannot tell them apart.

**Proposed: two statistics, not one.**

| Statistic | Question it answers | Denominator |
|---|---|---|
| `recurrence` (existing, rescoped) | does this model keep finding it? | successful runs **of that provider** |
| `agreement` (new) | does it survive a change of reasoner? | providers in the group |

Each route summary gains:

```json
"by_provider": {
   "gcp_gemini": {"runs": [1,2,3], "run_count": 3, "recurring": true},
   "anthropic":  {"runs": [4],     "run_count": 1, "recurring": false},
   "openai":     {"runs": [],      "run_count": 0, "recurring": false}
},
"providers_finding_it": 2,
"agreement": "partial"
```

Rules, stated so they are arguable:

1. **Recurrence is a within-provider statistic.** It measures one model's
   sampling variance and always did; the group-wide denominator was only ever
   correct because a group was always one vendor.
2. **Agreement is separate and is never averaged with recurrence.** Three
   samples from one vendor must not outvote two vendors — that would let the
   cheapest provider to run decide the finding.
3. **A single-provider group reports exactly what it reports today.** Same
   numbers, same threshold, same wording, plus `agreement: "single"`. This is a
   backward-compatibility requirement and deserves a test pinning it, in the
   shape of the dispatcher suite's `TestSingleProviderBehaviourIsUnchanged`.
4. **Unanimous** = every provider in the group found it in at least one run;
   **majority** = a strict majority of providers did. With two providers there
   is no majority tier, only unanimous or partial.
5. The group-mixing guard (`_load_group_records:3829`) refuses mixed maps and
   actors and **must keep allowing mixed providers** — that is the point. It
   gains a *warning*, not a refusal, when runs in a group differ in `max_paths`,
   `software_scope`, `thinking_level` or `prompt_sha256`: those are confounds an
   operator should see named, and refusing would remove the ability to record a
   deliberate knob-varying group.

The Markdown group report (`tool.py:2500+`) gains one line in the run header —
"n runs across k providers" — and, for a mixed group, a short per-route line
naming which vendors found each recurring route. The report is the thing a
person reads to a room; a three-vendor comparison that exists only in the JSON
has not been delivered.

**Done when:** a nine-record three-vendor group summarises with per-provider
recurrence and an agreement grade, and a three-record single-vendor group
produces byte-identical output to today.

## Stage E — the run itself

With A–D in, this is operating the tool, not building it.

1. One session, `connect`, confirm six bindings.
2. `providers probe` first — `connect` cannot answer reachability, because every
   client builds an SDK handle with no round trip.
3. Baseline config from the parent plan: same flow map, same actor,
   `thinking_level medium`, same `max_paths`, one `run_group` for the whole
   comparison.
4. `use gcp_gemini for adversary_path_projector`, `run ... --runs 3 --export`,
   then repeat under `anthropic` and `openai`. n ≥ 5 per vendor is the parent
   plan's number; 3 is the minimum that makes recurrence countable at all
   (`MIN_RUNS_FOR_RECURRENCE`). Start at 3 per vendor to prove the machinery,
   then take it to 5.
5. `run adversary_path_projector --action summarize_run_group --run_group <g>`
   with the flow map, and read the Markdown report.
6. Score against `stepstate-medium-2`
   (`docs/change_log/2026-09-11-live-run-findings.md:158`). Acceptance for a
   vendor is the parent plan's: rejection count at or below baseline, no parse
   failure, no truncation. Everything else is a cost discussion.

**Budget the wall clock.** All three clients use a 180 s per-request timeout
(`gemini.py:216`, `anthropic.py:127`, `openai.py:130`) and the plugin's `long`
class allows 600 s total. `--runs 3` is three sequential calls inside that
600 s. At heavy tier with a 49,152-token budget that is tight; a third run
starting late can be killed by the plugin timeout rather than the client. Prefer
`--runs 2` twice into the same group over `--runs 3` once if any vendor runs
long — the group numbers runs across invocations correctly by design.

---

## Out of scope here, and why that is safe

- **The PDF guard's provider argument.** Not on this path; see the opening.
  Still the highest-value item in the accessor list, and unaffected by this
  work.
- **`remote_uri_gs` and byte materialisation.** Gates the document modules
  (items 7 and 8 of the parent plan's order), not this one.
- **Per-tier `output_budget`.** `PROJECTION_MAX_TOKENS` is 49,152 — inside
  Gemini's 65,536 cap and far inside the other two vendors' 128,000 — so the
  clamp is inert for this module on all three.
- **An `--across` fan-out in `do_run`.** Argued above: three invocations in one
  session already hold the confounds fixed, and the flag needs `do_run`'s
  execution body extracted first.
- **Anything in the plugin's prompt or validator.** The analysis tools do not
  change — that is the property the whole comparison rests on. The only plugin
  edits here are the run record (Stage C) and the group summary (Stage D),
  neither of which touches what is sent to a model.

## Risks worth naming before starting

- **`needs_structured_output` is inert on every provider.** Nothing in any
  client reads it — there is no `response_mime_type` or `response_schema`
  anywhere in `framework/llm/` — so JSON arrives because the prompt demands it,
  identically on all three. Good for comparability, and worth knowing before
  someone reads the hint and assumes JSON mode is being enforced.
- **`_parse_llm_json` becomes load-bearing across vendors.** It was tuned
  against Gemini's habits. A parse failure on another vendor is a real result
  (it is the envelope metric) but should be confirmed as model behaviour rather
  than a fence-stripping bug before it is scored against a vendor.
- **Cost.** Nine heavy-tier runs with a 49 k output budget across three vendors
  is the most expensive single thing this project has run. It is a deliberate
  operator spend, not a side effect, and `--runs 3` before `--runs 5` is the
  cheap way to find out the machinery works.
- **Attribution regressions are silent.** If Stage C is skipped or half-done,
  every record still says `gcp_gemini` and the group summary will confidently
  compare nine Gemini runs. A test asserting the record's provider equals the
  response's `provider_id` is the cheapest possible insurance.

## Suggested order and rough shape

| Stage | Blocks | Shape |
|---|---|---|
| A | everything | shell + factory wiring, one guard test rewritten |
| C | reading any result | ~20 lines in `tool.py`, schema bump, two tests |
| B | choosing a vendor | new `do_use`, one line at `shell.py:2786` |
| D | comparing | the only design work; per-provider summary + report line |
| E | — | operating the tool |

A and C can land together and are worth a single change log entry; B is small
and independent; D deserves its own entry, because rescoping recurrence is a
behaviour change that a reader of an older group report needs to know about.
