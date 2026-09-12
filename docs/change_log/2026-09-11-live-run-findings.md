# Change Log — the first live step-state runs, and what they changed

**Date:** 2026-09-11
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`,
`plugins/threat_modeling/threat_model_analyzer/tool.py`,
`plugins/threat_modeling/threat_model_analyzer/tests/test_contract.py`
**Supporting Files:**
`plugins/threat_modeling/adversary_path_projector/examples/README.md`,
`docs/specs/adversary_path_projector_step_state.md`

Follows `2026-09-11-projection-step-state.md`, which built Phase 3c without
running it.

---

## The measurement

Volt Typhoon against `claims_portal_flow_map.json`, Gemini 3.1 Pro at `medium`,
`--runs 3 --run_group stepstate-medium`. One flow map hash, one deterministic
block, three records.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Paths / steps | 1 / 6 | 1 / 7 | 1 / 7 |
| Wall time | 54.7 s | 42.9 s | 53.7 s |
| Prompt tokens | 3,834 | 3,834 | 3,834 |
| Completion | 1,344 | 1,603 | 1,598 |
| Thinking | 5,236 | 3,914 | 5,221 |
| `finish_reason` | STOP | STOP | STOP |
| Rejections | 0 | 0 | 0 |

Thinking is roughly 3× completion and tracks wall time; completion does not.
Completion is about 3% of the 48K cap, so **the output cap is nowhere near
binding** and nothing was truncated. Identical prompt tokens across the three
runs confirm the prompt is deterministic, which is what makes records
comparable at all.

The spine reproduced in all three runs:

```
portal:T1190 -> portal:T1505.003 -> portal:T1552 -> portal:T1090.001 -> claims_api:T1078
```

`portal:T1059.004`, `claims_api:T1078` and `doc_store:T1005` each appear in two
of three; `claims_api:T1046` and `portal:T1074.001` in one each. The route
`portal → claims_api → doc_store` recurs in two of three, which is exactly the
shape Phase 3b is meant to collapse to one representative.

**Step state works.** 20 steps, every state field populated, no
`MISSING_STEP_STATE`, no off-vocabulary value, 24 assumptions, and the cap of
three never reached. The bridge step the design asked for (`portal:T1552`
yielding the credential before anything uses it) is present in all three runs.

## Changes

### 1. Wording: the interpretation contradicted the output

`PROJECTION_INTERPRETATION` still read "required/resulting access is typical
for each step's tactic, not tracked attacker state". Phase 3c made that false —
every step in these runs carries access the model stated and the tool checked —
and the files carrying that sentence are the ones people open directly. The
analyzer's projected-report paragraph said the same thing for every scenario,
even while the per-step label beside it already switched on `access_source`.

Both now say the access is the model's own, checked for continuity — that an
earlier step produced what the step needs — and never for truth, with a step
that states no access falling back to a per-tactic value. The analyzer's clause
switches on whether any event has `access_source == "model"`, so an old seed
still reads correctly. A test had locked the stale wording in place; it now
asserts the new one, and the analyzer has a test for each variant.

### 2. A gap now says which kind of gap it is

All three runs gapped on the last step, and always for the same reason: the
path reaches the document store only *through* the API, which no step takes
control of. Three identical-looking notes for a recurring structural finding is
noise, so `_describe_gap` separates three cases:

- **A portable credential nothing yields** — "no earlier step yields one". The
  skipped bridge the check was built for.
- **Reach without control** — "the path reaches it but no earlier step takes
  code_execution there". Connectivity exists, the foothold does not.
- **Delegated access** — "the declared flow to it comes from claims_api, which
  no earlier step takes control of, so the path depends on claims_api acting
  for the attacker". This is the triage question worth asking, and the model's
  own assumption states the claim: "the API allows arbitrary document
  retrieval".

The held-state list is also scoped now. It previously named reach on every
internet-exposed component — `cdn` and `idp` appeared in a note about
`doc_store` — and now names only what is held on the component in question and
on components with a declared flow to it.

**A state for delegated use was considered and rejected.** Adding one would let
any credential holder reach every downstream store with no reader noticing, and
would bury the assumption that is the part a person tests. The gap is the
signal; it just has to say so.

### 3. "Initial Access" past the entry point is corrected

Two of the three runs labelled `claims_api:T1078` Initial Access mid-path,
earning `KILL_CHAIN_REGRESSION` and `LATE_INITIAL_ACCESS` each time. Presenting
a stolen token to an internal API is not initial access; the entry happened
four steps earlier.

`_resolve_step_tactic` previously accepted any label the technique carries, and
T1078 carries Initial Access among four tactics. Past the first step, when the
technique carries an alternative, the label is now corrected and recorded as
`TACTIC_CORRECTED`. The existing rule that a correction never introduces a
second entry point already lived in `_closest_tactic`; this extends it to
labels that are merely valid.

Verified against the lookup, T1078 (`Stealth`, `Persistence`, `Privilege
Escalation`, `Initial Access`) corrects to:

| Previous step | Correction | Regression |
|---|---|---|
| Initial Access (3) | Persistence | none (forward) |
| Credential Access (10) | Stealth | 3 — under the threshold, no warning |
| Command and Control (14) | Stealth | 7 — still over the threshold of 6 |

So run 1's shape loses both warnings, and run 2's shape loses
`LATE_INITIAL_ACCESS` but keeps `KILL_CHAIN_REGRESSION`. C2 followed by Stealth
is ordinary tradecraft, so that last one is arguably a threshold question —
`TACTIC_REGRESSION_THRESHOLD` was left at 6 rather than tuned on one example.

A technique whose only tactic is Initial Access cannot be relabelled, so a
genuine second entry point is still flagged. `test_late_initial_access_is_flagged`
had to swap its techniques to keep testing that: it used T1133, which also
carries Persistence and is now corrected instead.

### 4. The prompt asks for distinct routes

Four post-3c runs have each returned exactly one path, where `max_paths`
allowed three or four and the map has two crown jewels. The pre-3c run of the
same actor and map gave two. Nothing truncated, so this is attention, not
budget: the STEP STATE section pulls the model toward depth on one path.

The prompt said "Prefer few strong paths over many weak ones". It now asks for
distinct routes where the reachable routes support them, says a second path
ending at a different crown jewel beats a longer version of the first, and adds
one line after the step-state section saying detail on one path is not a reason
to return fewer paths.

## Tests

916 passed, was 911. Five added: the delegated-access note and its scoped held
list, reach separated from control, the mid-path Initial Access correction, the
entry step keeping its label, and the prompt asking for distinct routes. Three
existing tests updated — the interpretation wording, the gap note for a missing
credential, and the late-Initial-Access fixture.

`ruff` and `black` are still not installed in this environment; style was
matched by hand.

## Measured: `stepstate-medium-2`

The same three-run group, same actor, same map hash `03dbb641ee79`, run after
the four changes. Three runs, three `STOP`, no truncation, no rejections.

| | Before (`stepstate-medium`) | After (`stepstate-medium-2`) |
|---|---|---|
| Paths per run | 1, 1, 1 | 2, 2, 1 |
| Steps, total | 20 | 29 |
| Crown jewels covered | `doc_store` only | both, in 2 of 3 runs |
| Prompt tokens | 3,834 | 3,909 |
| Completion, mean | 1,515 | 2,232 |
| Thinking, mean | 4,790 | 4,226 |
| Total tokens, mean | 10,139 | 10,368 |
| Wall time, mean | 50.4 s | 52.7 s (37.8–74.1) |

**Breadth was nearly free.** Completion rose 47% and thinking fell 12%, so mean
total tokens moved 2% and mean wall time 2.3 s. Completion per step is
unchanged — 227 tokens before, 231 after — which confirms the single-path runs
were never constrained by budget. The longest run, 74 s, is the most expensive
this map has produced, and still well inside the 180 s deadline.

**The route to `claims_db` is back.** It had not appeared in any of the four
post-3c runs; it appears in 2 of 3 here, and one run reached it by a different
entry — stolen SAML credentials at the portal rather than exploitation. Route
recurrence across the group: `portal → claims_api → doc_store` in 3 of 3,
`portal → claims_api → claims_db` in 2 of 3. Both recur under the Phase 3b
rule, which now has a group worth summarising.

**The gap classification works and is the most useful line the tool prints.**
Six gaps: four *delegated access*, all naming `claims_api`, and two
*reach-without-control*. The held-state list is now two items instead of six,
with no `cdn` or `idp` noise. Four of six gaps say the same thing — **every
route to a crown jewel in this estate depends on the API acting for the
attacker** — which is a finding about the architecture, not about the model.

**The Initial Access correction did not fire.** The model labelled the
mid-chain T1078 steps `Stealth` itself in all three runs, so no step reached
the new branch and there were no `LATE_INITIAL_ACCESS` warnings at all, against
two runs carrying them before. The improvement is the model's, not
demonstrably the correction's; **the new branch remains unexercised live.** The
older correction path did fire once, on a reply that put the technique *name*
in the tactic field ("tactic 'Valid Accounts' is not one this technique
carries; using 'Stealth'").

## Fix 5, after the measurement: the regression check is scoped to one component

Run 3 produced the one warning this change log predicted and hoped not to see:

```
KILL_CHAIN_REGRESSION: Stealth regresses 7 kill-chain positions from the
previous step
```

The tool corrected the tactic to `Stealth`, then warned about its own choice.

The check compares kill-chain positions from `TACTIC_ORDER` and warns when a
step falls more than six positions behind the one before it. `Command and
Control` sits at position 14, so a step after C2 warns only when its tactic is
at position 7 or lower — Stealth, Privilege Escalation, Persistence, Execution,
Initial Access, Resource Development, Reconnaissance. Credential Access,
Discovery, Lateral Movement and Collection after C2 are all inside the
threshold and pass silently; run 1 shows it, with C2 followed by Credential
Access and then Stealth and no warning at all. **An earlier draft of this entry
claimed every step after C2 except Exfiltration and Impact would warn. That was
wrong.**

Volt Typhoon establishes the proxy early and works through it, so C2 followed
by credential reuse — Stealth, at 7 — is this actor's normal shape, and that is
the pairing that trips the check.

**The first proposal — that a C2 step should not advance the kill-chain
position — was rejected, and rightly.** C2 *is* a stage: an established channel
persists and the attacker keeps acting through it, unlike a shell that dies
with its parent. Treating it as concurrent background activity would have
contradicted that.

What was wrong is narrower. A regression only means something **within one
foothold**. A kill chain restarts per host, so arriving at the next component
and doing early-stage work there — presenting a stolen token at the API — is
ordinary, not a late-stage action placed before the work that enables it, which
is what the warning claims. The check now fires only when the step stays on the
same component, and the message names it: "regresses 7 kill-chain positions
from the previous step on portal".

Two alternatives were dropped. Narrowing the warning to tactics that cannot
recur collapses to nearly this same rule once Execution and Privilege
Escalation are excluded as legitimately repeating per host. Raising
`TACTIC_REGRESSION_THRESHOLD` is the bluntest option: it would hide real
regressions, and would have to pass exactly the value in question.
`LATE_INITIAL_ACCESS` still catches a second entry point and ignores components
entirely, so a path that re-enters somewhere new is not lost.

Tests: **918 passed**, two added — the live Volt Typhoon shape (proxy on the
entry host, then the token on the API) no longer warning, and the identical
tactic pair without the hop still warning exactly once. The three existing
same-component regression tests are unchanged and still pass.

## Fix 6: a path may come back the way it came, and nothing else

The plan here was to edit the claims portal map — make f3 and f5 bidirectional
so the staging steps stopped earning `HOP_NOT_DECLARED`. Looking at what
`bidirectional` actually does changed that.

`_build_adjacency` expands a bidirectional flow into a full reverse edge, which
feeds reachability, the crown-jewel routes, the REACHABLE ROUTES block in the
prompt, and the reach the continuity check derives. So `bidirectional: true` on
f3 asserts that an attacker holding `claims_api` can **initiate** to `portal`,
and on f5 that one holding `doc_store` can initiate to `claims_api`. An HTTP
response channel grants no such thing. Applied consistently — "a response
channel is usable" is true of f1, f3, f4 and f5 — the graph becomes nearly
symmetric and direction stops meaning anything.

It also would not have fixed the case that prompted it. Group 2's warning was
`no declared flow from 'claims_db' to 'portal'`: two hops apart, with the API
in between. No bidirectionality on f3 or f5 makes that hop declared, and it
should stay flagged.

The principle, from the user: **a claimed path must never get from one node to
another by skipping a hop point — there should always be a path that can be
explained or defended.** The miss was in the check, not the map. The hop check
only ever compared consecutive steps, so a step returning to a component the
path had come from read as an arrival somewhere new.

Each path now records the hops it makes over declared flows. A step going back
to the component it arrived from is allowed when **that exact edge was
travelled by this path** — the attacker holds the component they left and the
data returns over a connection they opened. The step's `transition` carries the
flow it arrived on plus `"return": true`, and the report says so: *"back over
flow f1: api -> web (https, authenticated)"*. A reader sees which connection is
being used rather than silence.

Everything else still warns. In particular, "a component the path already
holds" was rejected as the rule: it would also excuse group 2's
`claims_db → portal`, which is exactly the skipped hop the principle forbids —
that data would have to return through the API, and the path does not say so.

**The example map is unchanged.** Its flow directions are correct as written.

Tests: **920 passed**, two added — the group-1 return-hop shape, asserting both
the `return` marker and the rendered transition text; and the group-2 shape,
asserting one `HOP_NOT_DECLARED` naming `customer_db` to `web` with a null
transition. `test_undeclared_hop_is_flagged` still passes unchanged, because
its first hop was never declared and so was never recorded as travelled.

## Still open

- **`git_sha` is empty in all six records** written on the container. It exists
  to tell code versions apart, since the manifest has read 0.2.0 since Phase 2,
  so while it is blank the records cannot separate a pre-fix run from a
  post-fix one. Most likely no `.git` in the image; needs baking in at build
  time rather than reading at runtime.
- **Whether a response channel should ever be modelled as a flow** is still
  open in the abstract. Fix 6 handles the attacker returning along an edge they
  travelled, which covers the cases seen live, but nothing models data flowing
  back through an intermediate component the attacker never held — group 2's
  `claims_db → portal` is correctly flagged and a reader still has to reason
  out the return path themselves.
- **The model's prose still contradicts the map**, calling the IAM-protected
  document store "unauthenticated" when it is flow f5 that is unauthenticated.
  Prose is not validated, by design; a `description` on f5 would likely stop
  it.
- **The wording fix is unobservable in a run record** — it lives in the graph
  and seed artifacts and in the analyzer report. Covered by tests; not yet seen
  in a live artifact. Importing a group-2 seed into `threat_model_analyzer`
  would confirm it.
- **The Initial Access correction is unexercised live**, as above.
- **A forgiven gap flatters what follows.** In run 2 the last step of
  `doc-store-unauth-access` reads `ok` only because the gap before it was
  recorded and then treated as held. That is the report-once rule working as
  designed, and worth knowing when reading a path end to end.
