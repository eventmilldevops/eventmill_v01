# Adversary Path Projector — Step State (Phase 3c)

Status: **Implemented 2026-09-11** as Phase 3c, with the six recommended
decisions at the end taken as defaults. **Not yet run against a live model** —
the budget measurement below is still outstanding. See
`docs/change_log/2026-09-11-projection-step-state.md`.
Parent spec: `docs/specs/adversary_path_projector.md`.
Proposed order: before Phase 3b (run-group summary).

---

## Problem

A projected path is recorded as

```
technique → component → technique → component
```

with a free-text `rationale` per step. It does not record the **attack state**
that connects one step to the next — what the attacker holds after a step, and
what the next step needs. A path can jump from exploiting a frontend to reusing
OAuth tokens on the API without ever saying how the frontend compromise yielded
a usable token.

Sometimes the model supplies the bridge anyway. The live Volt Typhoon run of
2026-09-11 placed `portal:T1552` — "searching local Django configuration files
or environment variables to extract the OAuth2 tokens" — before
`claims_api:T1078`. But nothing asks for that bridge, requires it, or checks it,
and when it is skipped the path is under-specified rather than wrong.

Two existing weaknesses make this worse:

- **Access levels are not state.** `required_access` / `resulting_access` come
  from `_ACCESS_BY_TACTIC`, a fixed table keyed on tactic. They are identical
  for every Credential Access step and do not chain — the Volt run's AE-0004
  ends at `credentials` and AE-0005 starts at `user`. The report has had to
  label them "typical for this tactic, not tracked".
- **The rationale is unstructured and unvalidated.** It is the only view inside
  a step, and a reviewer cannot tell which parts are facts from the map, which
  are the model's reasoning, and which are unstated assumptions. The Volt run's
  rationale called the document store "unauthenticated"; the map says the
  store requires IAM and it is the flow into it that is unauthenticated.

The criticism that prompted this design is correct: the format is
**under-specified, not excessively speculative.**

## Goal

Make each projected step **reviewable and testable without pretending it is
proven.** A threat modeller reading a step should see what had to be true
before it, what it exploits, how the attacker got there, what they hold after,
and — most usefully — which assumptions a person could go and test.

## Non-goals

- **No change to path mapping.** The closed technique set, component
  validation, declared-flow hop checks, tactic correction, and kill-chain checks
  are untouched. A technique outside the actor's set is still rejected, whatever
  the model says about it.
- **No likelihood.** Nothing here scores how likely a step or path is.
- **No control-effectiveness scoring.** Whether a control stops a technique
  stays with the later control-quality step. This design records how the model
  *says* a step contends with a control; it does not judge it.
- **No validation of assumptions.** Assumptions are, by definition, what the
  flow map does not state. They are the test plan, not a claim the tool checks.

## Principle: the model supplies only what cannot be computed

The same rule that already governs `evidence`: a model cannot be trusted to
label facts the tool already holds, and restating them invites contradiction.

| Field | Source | Why |
|---|---|---|
| `precondition` | Model | What must already be true — reasoning |
| `access_before` | Model, from a fixed vocabulary | Needed for the continuity check |
| `exploited_condition` | Model | The property of this component the technique relies on |
| `result` | Model | What the attacker holds afterwards, in words |
| `access_after` | Model, from a fixed vocabulary | Needed for the continuity check |
| `assumptions` | Model, 1–3 per step | What must be true that the map does not state — the test plan |
| `control_note` | Model, optional | How the step contends with this component's controls — narrative only |
| `transition` | **Flow map** | The declared flow from the previous component: id, protocol, authenticated, crosses boundary |
| `controls_in_play` | **Flow map** | Controls on the component and on the transition flow, with status |
| `actor_support` | **ATT&CK, derived** | See below; never read from the reply |
| `procedure_excerpt` | **ATT&CK** | A documented procedure example for this actor and technique, when one exists |
| `state_check` | **Tool** | Result of the continuity check |

The proposal that prompted this design had the model supply `transition_via`,
`control_interaction` and `actor_support`. All three are facts the tool already
holds or can derive, so they move to the right-hand column.

## Access-state vocabulary

Free-text states cannot be checked. A small fixed vocabulary can:

| State | Meaning | Scope |
|---|---|---|
| `none` | No foothold | — |
| `network_reach` | Can send traffic to the component | component |
| `code_execution` | Running commands or code in the component's workload or host | component |
| `user_credential` | Holds a user's credential, session or token | portable |
| `service_credential` | Holds a service or workload credential — API token, key, certificate, service account | portable |
| `privileged` | Admin or root on the component, or equivalent | component |
| `data_access` | Can read the target data | component |

Component-scoped states are held *on a component*: execution on the portal is
not execution on the API. Credentials are portable: a token taken on the portal
can be presented anywhere a flow reaches. Detail belongs in `result`; the state
is the checkable part.

## The continuity check (Phase C addition)

The attacker's held state accumulates along a path — they keep what they
gained. Per path:

1. Start with `none`, and `network_reach` on every internet- or
   partner-exposed component.
2. Before each step, the step's `access_before` must be held — on this
   component if it is component-scoped. `network_reach` on a component is also
   held if the attacker holds `code_execution` or `privileged` on a component
   with a declared flow to it.
3. After each step, add `access_after` (on this component, if scoped).

A step whose `access_before` is not held gets a **`STATE_GAP`** warning naming
what was needed and what was held — e.g. *"needs service_credential; path holds
code_execution on portal, network_reach on claims_api"*. The frontend-to-API
jump in the criticism is caught automatically instead of by a reviewer.

**Warning, not rejection** — the same reasoning as tactic correction and the
kill-chain checks: rejecting a step strands the `leads_to` edges either side and
splits the graph, and a gap usually means a missing bridge step, not a wrong
placement. The warning appears in `summarize_for_llm()`, on the step as
`state_check`, and in the analyzer report.

**What the check does not do.** It catches omissions, not falsehoods. A model
can claim a step yields `service_credential` when nothing on that component
holds one; the check only confirms the chain is internally consistent. That is
exactly why `assumptions` exists — "the Django settings file holds a reusable
API token" is the claim a person tests.

## `actor_support`

A refinement of `evidence`, derived from ATT&CK and never from the reply:

| Value | Meaning |
|---|---|
| `procedure_documented` | ATT&CK has a procedure example with this actor (or, for a `via_software` technique, its software) as the source for this technique |
| `technique_documented` | ATT&CK attributes the technique to the actor, but no procedure example describes how |
| `via_software` | Only the actor's tooling implements it (unchanged meaning) |

`evidence` keeps its current two values for compatibility. When a procedure
example exists, `procedure_excerpt` carries its first ~200 characters — the
closest the tool can get to "how could this happen" from sourced material rather
than from the model. Built from one scan of the procedure list per run, as
`_procedures_for_sources` already does; `procedures_for_technique` per step
would re-scan all 17k procedures each time.

## Example

Built from the real Volt Typhoon steps, not the test fixture:

```json
{
  "technique_id": "T1552",
  "tactic": "Credential Access",
  "component_id": "portal",
  "precondition": "Attacker can run commands on the portal host via the web shell",
  "access_before": "code_execution",
  "exploited_condition": "Django reads its OAuth client credentials from local settings or environment",
  "result": "OAuth2 client credential for the claims API",
  "access_after": "service_credential",
  "assumptions": [
    "The credential is stored on the host rather than fetched per request from a vault",
    "The credential is not bound to the portal host (no mTLS or workload identity)"
  ],
  "control_note": "The partial WAF sees inbound HTTP only; nothing declared inspects local file reads",

  "transition": null,
  "controls_in_play": [{"name": "WAF", "status": "partial", "on": "component"}],
  "actor_support": "procedure_documented",
  "procedure_excerpt": "Volt Typhoon has obtained credentials insecurely stored on targeted network appliances.",
  "state_check": "ok",

  "evidence": "documented",
  "rationale": "…",
  "leads_to": ["T1078"]
}
```

The next step, `claims_api:T1078`, would carry
`transition: {"flow": "f3", "from": "portal", "to": "claims_api",
"protocol": "https", "authenticated": true}` and
`access_before: "service_credential"` — held, so `state_check: "ok"`. Had the
model skipped the T1552 step, the same T1078 step would read `STATE_GAP: needs
service_credential; path holds code_execution on portal`.

The procedure excerpt is real — ATT&CK's G1017/T1552 procedure example,
checked against the lookup. It also shows why the excerpt earns its place: ATT&CK
documents Volt Typhoon taking stored credentials from **network appliances**,
and the projection places the same technique on a **Django web host**. A
reviewer sees at a glance that the technique is documented for the actor but
the setting is the model's adaptation — which is precisely the distinction
between `procedure_documented` and a placement worth testing. The lookup also
holds G1017 procedures for T1190, T1505.003, T1078, T1552.004 and T1005, so most
steps of the Volt run would carry an excerpt.

## Prompt changes

A `STEP STATE` section added to `PROJECTION_PROMPT`:

- The access vocabulary, verbatim, with scope.
- `access_before` must be something the attacker already holds from an earlier
  step or from the entry point. **If you cannot say how the attacker came to
  hold it, add the step that gives it to them** — from the closed set. If the
  closed set has no technique for that bridge, say so in `assumptions` rather
  than skipping it.
- `assumptions` are things that must be true and that the component table does
  not state. Do not restate the table. One to three, each under ~20 words.
- Do not restate flows or controls — the tool attaches those.
- `rationale` stays, shortened to one sentence, so existing consumers keep
  working.

Everything the model returns under the new keys is still bound by the five hard
rules; none of it can admit a technique or component the rules would reject.

## Budget

| | Today | With step state (estimate) |
|---|---|---|
| Output per step | ~60–80 tokens | ~200–250 tokens |
| 3 paths × 7 steps | ~1.5k tokens | ~5k tokens |
| `max_tokens` on the call | 16,384 | 49,152 — 48K (provider cap is 65,536 per `gcp_gemini.json`) |
| Client request timeout (`client.py`) | 120 s | 180 s — applies to every LLM plugin |

Output is not the latency driver — thinking is — but it adds. Before settling
defaults: the claims portal and telemetry SaaS maps, `medium`, three runs each,
before and after, compared through the existing run records (wall time,
completion and thinking tokens, `finish_reason`). The ~110s gateway deadline is
the ceiling to watch.

## Downstream

| Consumer | Change |
|---|---|
| Attack graph artifact | New per-step keys. `attack_path_visualizer` reads only the keys it knows and is unaffected |
| Scenario seed / `threat_model_analyzer` `AttackEvent` | New optional fields: `precondition`, `exploited_condition`, `assumptions`, `transition` (one-line text), `actor_support`, `state_check`, `access_source`. `result` goes into the existing `success_indicators`. Additive, like `tactic` and `evidence`; old seeds import unchanged |
| `required_access` / `resulting_access` | Taken from the model's states when present, with `access_source: "model"`; otherwise the tactic table, `access_source: "tactic_table"` |
| Analyzer report, per step | *Precondition*, *Exploits*, *Via*, *Result*, *Assumptions to test* (bulleted), *State check*. The access label depends on source: *Access (stated by the LLM, checked for continuity)* or today's *Typical access for this tactic* |
| Analyzer report, per scenario | A new **Assumptions to Test** section collecting every assumption with its step — the test plan a threat modeller works from |
| `gap_analysis` | Adds counts of assumptions and state gaps |
| Projector summary | One line: *N assumption(s) to test; M state gap(s).* Stays under the 2000-character cap |
| Run record | `sampled` steps gain the model's fields; `deterministic` is unchanged; `RUN_RECORD_SCHEMA_VERSION` 1 → 2 |
| Phase 3b | Recurrence stays keyed on (component, technique), never on prose. A recurring path can then be reported with the assumptions it rests on |

## Failure handling

- **Fields missing from a step** — the step is kept with a
  `MISSING_STEP_STATE` warning, and access falls back to the tactic table. A
  model that ignores the new section degrades to today's output rather than
  failing; the existing test fixture, which has no state fields, stays valid.
- **Access state outside the vocabulary** — mapped to the nearest state where
  unambiguous, else treated as missing, with a warning naming the value.
- **More than three assumptions** — kept, truncated to three, with a warning.
- **A truncated reply** is still refused outright, as today.

## Risks

- **A detailed story reads as more certain.** Readers who struggle with
  ambiguity may take precondition-result prose as established. Mitigated by
  presenting assumptions as *Assumptions to test* and keeping the projection
  notice beside them — but it is a real risk and the reason the report leads
  with the notice.
- **Vacuous continuity.** A model can satisfy the check by declaring whatever
  the previous step produced. The check proves consistency, not truth; the
  assumptions carry the truth claim.
- **More variance between runs.** Prose varies more than technique ids. Run
  comparison stays keyed on ids.
- **Truncation.** Larger replies make the output cap more reachable; hence the
  higher `max_tokens` and the measurement before defaults are fixed.

## Tests (planned)

- Continuity: a chain that holds, a skipped bridge flagged `STATE_GAP`,
  component scoping (execution on A is not execution on B), portable
  credentials, `network_reach` derived through a declared flow.
- `transition` and `controls_in_play` computed from the map, and a model's
  attempt to supply them ignored.
- `actor_support` derived, including a model-supplied value ignored.
- Missing fields degrade to today's behaviour; an off-vocabulary state warns.
- Seed round trip into `threat_model_analyzer`; the report's new sections, and
  their absence on analyst-built scenarios.
- Run-record schema v2 validates; v1 records remain readable.

## Decisions taken

Taken as the recommended defaults when implementation was requested:

1. **The seven access states**, as listed.
2. **Procedure excerpts in the output, not in the prompt** for v1. Revisit
   prompt grounding after the budget measurement.
3. **Three assumptions per step**; more are truncated with a warning.
4. **`STATE_GAP` is a warning**, never a rejection.
5. **The aggregated *Assumptions to Test* section** is in the analyzer report.
6. **This lands before Phase 3b.**

## Refinements made during implementation

- **An excerpt only where it matches the label.** A directly attributed
  technique with no procedure example from the actor — but one from its
  software — gets `technique_documented` and **no** excerpt. Showing the
  tooling's procedure beside that label would read as the actor's own
  behaviour. A `via_software` step shows its tooling's excerpt.
- **A gap is reported once.** After flagging `STATE_GAP`, the check treats the
  missing access as held, so one skipped bridge does not flag every later step.
- **An omitted `access_after` stops the check for the rest of the path.** Later
  steps are `unchecked`, not `gap` — a gap there could be an artefact of the
  omission rather than a real break.
- **Unambiguous synonyms are accepted silently** (`RCE` → `code_execution`,
  `admin` → `privileged`, `api_token` → `service_credential`, and so on);
  anything else is `ACCESS_STATE_UNKNOWN` and treated as missing.
- **`network_reach` is derived** for a component when the attacker holds
  `code_execution` or `privileged` on a component with a declared flow to it,
  as designed. The check examines only the stated `access_before`; it does not
  separately require reach to a component a credential is presented to — the
  hop check already covers connectivity between consecutive steps.
- **Step state is not counted in `total_issues`.** An assumption is something
  to test, not a defect; a state gap is a question about the projection, not the
  defences. `gap_analysis` reports both separately.
