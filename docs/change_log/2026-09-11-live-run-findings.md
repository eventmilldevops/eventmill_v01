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

## Not verified

**Every one of these four changes is unmeasured against a live model.** The
next run is a repeat of the same three-run group on the **unchanged** map, so
`flow_map_sha256` still matches and the comparison holds: does the model return
more than one path, do the sequence warnings drop, and do the gap notes read
better.

## Open, not changed

- **`git_sha` is empty in all three records.** It exists to tell code versions
  apart, since the manifest has read 0.2.0 since Phase 2, and it is blank on
  the container — most likely no `.git` in the image. Needs baking in at build
  time rather than reading at runtime.
- **The model's prose still contradicts the map**, calling the IAM-protected
  document store "unauthenticated" when it is flow f5 that is unauthenticated.
  Prose is not validated by design; a `description` on f5 would likely stop it.
- **The claims portal map declares f3 and f5 one-way.** Run 2 staged data back
  on the portal and earned `HOP_NOT_DECLARED`; in reality both are
  request/response. Editing the map changes its hash and starts a new baseline,
  so it waits until after the re-measurement.
- `TACTIC_REGRESSION_THRESHOLD`, as above.
