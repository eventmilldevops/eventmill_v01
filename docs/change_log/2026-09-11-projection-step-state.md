# Change Log — `adversary_path_projector` Phase 3c: step state

**Date:** 2026-09-11
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`plugins/threat_modeling/adversary_path_projector/schemas/projection_run.schema.json`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`,
`plugins/threat_modeling/threat_model_analyzer/tool.py`,
`plugins/threat_modeling/threat_model_analyzer/schemas/output.schema.json`,
`plugins/threat_modeling/threat_model_analyzer/tests/test_contract.py`
**Supporting Files:**
`plugins/threat_modeling/threat_model_analyzer/README.md`,
`docs/specs/adversary_path_projector_step_state.md`,
`docs/specs/adversary_path_projector.md`

Follows `2026-09-11-adversary-path-projector-phase-3.md`. Design:
`docs/specs/adversary_path_projector_step_state.md`.

---

## Problem

A review criticised the projected path format as **under-specified, not
excessively speculative**. It recorded technique → component → technique →
component, but not the attack state connecting the steps, so a path could jump
from exploiting a frontend to reusing an API token without saying how the token
was obtained. A projection was hard to review and impossible to test.

The access levels did not help: `required_access` / `resulting_access` came
from a fixed table keyed on tactic, did not chain from step to step, and had
already been relabelled "typical for this tactic, not tracked".

## Changes

### Each step now carries its state

The model supplies what only it can reason about; the tool supplies everything
it already holds. That split follows the rule `evidence` has always followed —
a model does not get to label facts the tool can compute.

| Field | Source |
|---|---|
| `precondition`, `exploited_condition`, `result` | Model |
| `access_before`, `access_after` | Model, from a fixed seven-state vocabulary |
| `assumptions` (up to 3) | Model — what must be true that the flow map does not state; the test plan |
| `control_note` | Model, optional |
| `transition` | Flow map — the entry point's exposure, or the declared flow the step arrived over |
| `controls_in_play` | Flow map — controls on the component and on the arriving flow |
| `actor_support` | ATT&CK — `procedure_documented`, `technique_documented` or `via_software` |
| `procedure_excerpt` | ATT&CK — the actor's own procedure example for the technique, citations stripped |
| `state_check`, `state_note` | Tool — the continuity check |

A model's attempt to supply `transition` or `actor_support` is ignored; tests
assert both.

The vocabulary: `none`, `network_reach`, `code_execution`, `user_credential`,
`service_credential`, `privileged`, `data_access`. Reach, execution, privilege
and data access are held **on a component**; credentials travel with the
attacker.

### The continuity check

Phase C tracks what the attacker holds along each path — starting with reach
on the externally exposed components, accumulating each step's `access_after`
— and checks every step's `access_before` against it. Execution on a component
grants reach to its declared flow targets. A step needing access nothing earlier
provided gets a **`STATE_GAP`** warning naming what was needed and what was held.
It is a warning, never a rejection, for the same reason as the kill-chain checks:
rejecting strands the edges either side, and a gap usually means a missing
bridge step.

The check proves the chain is **consistent, not that it is true**. A model can
claim a step yields a credential nothing on that host holds; the assumptions
carry that claim, which is why they are the part a person tests.

Degradation is deliberate: a step that omits its state is kept with
`MISSING_STEP_STATE` and `state_check: "unchecked"`, and a missing
`access_after` leaves the rest of that path unchecked rather than flagged. A
model that ignores the new prompt section produces exactly today's output.

### Prompt, budget and records

- `PROJECTION_PROMPT` gained a STEP STATE section and the new fields in its
  reply format. It tells the model to **add the bridging step** when it cannot
  say how the attacker came to hold something, and to record in `assumptions`
  when the closed set has no technique for that bridge — never to skip it.
- `max_tokens` on the projection call 16,384 → **49,152** — 48K, 48 × 1024
  (`PROJECTION_MAX_TOKENS`). Headroom for steps roughly three times larger, and
  deliberately generous: part of this assessment is demonstrating what deep
  work really costs, so the cap should not be what trims it. It stays inside the
  provider's cap in `gcp_gemini.json`. See the follow-up below.
- ATT&CK procedure examples are indexed once per invocation (one scan of ~17k
  procedures, reused by every run of a `--runs` loop), as
  `_procedures_for_sources` already does.
- Run records: `RUN_RECORD_SCHEMA_VERSION` 1 → 2; `sampled` steps carry the
  model's state fields, `actor_support` and `state_check`.
- Projector summary gains one line, e.g. *Step state: 3 assumption(s) to test;
  1 state gap(s) — portal-to-db.steps[1].*

### Scenario seed and `threat_model_analyzer`

- Seed events take `required_access` / `resulting_access` from the model's
  states when it gave both, marked `access_source: "model"`; otherwise the
  tactic table, `access_source: "tactic_table"`. `result` goes into the existing
  `success_indicators`.
- `AttackEvent` gained optional `precondition`, `exploited_condition`,
  `assumptions`, `transition`, `actor_support`, `procedure_excerpt`,
  `control_note`, `state_check`, `access_source`. Additive — old seeds and
  exports import unchanged; the round trip carries the new fields.
- The report shows each field on projected steps, all model-written lines marked
  *(LLM)*. The access label now depends on its source: *Access (stated by the
  LLM, checked for continuity)* or, as before, *Typical access for this tactic*.
- A new **Assumptions to Test** section collects every assumption with its step
  — the scenario's test plan in one place — and the gap summary counts
  assumptions and state gaps.
- `gap_analysis` reports `assumptions_to_test` and `state_gaps` alongside, but
  **not inside**, `total_issues`: an assumption is something to test, not a
  defect, and a gap is a question about the projection rather than the defences.

## Rendered output

A projection over the three-tier sample map with one planted gap, imported into
the analyzer (excerpt):

```
### Step 1: Exploit Public-Facing Application on Portal frontend [CONTROL_PRESENT]
- **ATT&CK support:** procedure_documented — ATT&CK has a procedure example of this actor using this technique
- **ATT&CK procedure example:** APT29 has exploited CVE-2019-19781 for Citrix, CVE-2019-11510 for Pulse Secure VPNs, CVE-2018-13379 for FortiGate VPNs, and CVE-2019-9670 in Zimbra software to gain access.
- **Via:** entry point (internet-exposed)
- **Precondition (LLM):** The portal is reachable from the internet
- **Access (stated by the LLM, checked for continuity):** network_reach -> code_execution
- **Assumptions to test:**
  - The exploited route is not filtered by the WAF
- **State check:** ok

### Step 2: Valid Accounts on Portal API [UNPROTECTED]
- **Via:** flow f1: web -> api (https, authenticated)
- **Access (stated by the LLM, checked for continuity):** service_credential -> code_execution
- **State check:** gap — needs service_credential; path holds code_execution on web, network_reach on web

## Assumptions to Test
1. **Step 1** (T1190 on Portal frontend): The exploited route is not filtered by the WAF
2. **Step 2** (T1078 on Portal API): Tokens on the web tier are reusable against the API
3. **Step 3** (T1005 on Customer database): The API's database role can read customer tables
```

Two things this shows that the design predicted. Step 2 is the criticism's own
case — a token reused on the API with no step that took it — caught
automatically. And step 1's procedure example documents APT29 exploiting
Citrix, Pulse Secure, FortiGate and Zimbra, while the placement is an nginx
portal: the reader sees at a glance that the technique is documented for the
actor and the setting is the model's adaptation.

## Tests

`adversary_path_projector` 215 (was 198), `threat_model_analyzer` 77 (was 71),
full suite **911 passed** (was 888). `validate_manifests.py` still reports
exactly the 15 pre-existing `stability` errors.

Covered: a continuous chain; a skipped bridge flagged once, not downstream;
execution scoped to its component; portable credentials; reach requiring
execution and a declared flow; missing state degrading to `unchecked` and the
tactic table; an omitted `access_after` stopping the check; aliases and an
unknown state; the assumption cap; `transition` and `controls_in_play` from the
map with the reply's values ignored; `actor_support` derived from ATT&CK and
checked against the lookup with the reply's value ignored; the seed's access
source, transition text and gap description; the summary line; the prompt; a
v2 run record validating against its schema; and on the analyzer side every
report line, the collected section, `gap_analysis` counts kept out of
`total_issues`, the export/import round trip, a malformed `assumptions` refused,
and none of it on analyst-built scenarios.

## Not verified

**No live run.** Everything above ran against scripted replies. Still to do
before the defaults are settled: the claims portal and telemetry SaaS maps at
`medium`, three runs each, before and after, comparing wall time, completion and
thinking tokens, and `finish_reason` through the run records — the ~110s
gateway deadline is the ceiling to watch. Whether the model actually adds
bridging steps when told to, and how often it produces gaps, is unknown until
then.

## Follow-up: 180 s request timeout and a 48K output cap

Part of this assessment is demonstrating the real cost — time and tokens — of
deep reasoning work, so neither limit should be what cuts a run short.

- **`framework/llm/client.py`: the per-request HTTP timeout 120 s → 180 s.**
  This was the value the 2026-09-09 change log flagged as unexamined. It is a
  framework setting and **applies to every LLM-using plugin**, not only the
  projector.
- **`PROJECTION_MAX_TOKENS` 32,768 → 49,152** (48K), as above.

Two interactions to know before reading the cost numbers:

- **Retries now outlast the plugin timeout.** The client makes
  `max_retries + 1` = 4 attempts with 1/2/4 s backoff, and a client-side timeout
  is retriable. A request that times out every time now holds the call for
  4 × 180 + 7 = **727 s**, past the 600 s `long` timeout class, so the executor
  cuts it off during the fourth attempt and reports `TIMEOUT` rather than the
  LLM error. At 120 s the worst case was 487 s, inside the limit. Each retried
  attempt is also billed again, so a run that fails slowly costs more than one
  that fails fast — worth showing in the cost figures, not hiding. The timeout
  class was left unchanged.
- **The client timeout is also the server deadline.** google-genai 1.69.0
  sends `X-Server-Timeout: ceil(timeout in seconds)` on every request
  (`_api_client.populate_server_timeout_header`). At 120 s the header said 120,
  so the 504 `DEADLINE_EXCEEDED` observed on 2026-09-09 at ~110 s was very
  likely Google enforcing the deadline *we* requested, not a fixed gateway
  limit — which corrects the 2026-09-09 change log's reading of it. At 180 s the
  requested server deadline moves with it. **Unverified:** Google may cap the
  header. The next `high`-thinking run shows which — completion past 120 s, or
  a 504 near 180 s, means the header is honoured; a 504 still near 110–120 s
  means a cap.
- **Streaming is not the fix for that error.** A server-side deadline applies
  to the whole request, streamed or not. Streaming (`generate_content_stream`,
  present in the installed SDK, unused here) protects against intermediaries
  that drop idle connections and shows partial progress — and with Gemini 3 it
  only sends bytes during thinking when thought summaries are requested
  (`include_thoughts`). TCP or HTTP/2 keep-alives likewise protect an idle
  connection, not a request deadline.

## Environment note

Running Python from inside a plugin directory imports `framework` from a
**different checkout**, `C:\projects\eventmill_v01\eventmill_v01`, presumably
through the editable install; that checkout predates `TACTIC_ORDER` and fails
on import. From the repo root the local package shadows it, which is why
`pytest` is unaffected. Worth fixing with `pip install -e .` from this checkout
before anyone runs a script from a subdirectory and gets silently stale code.
