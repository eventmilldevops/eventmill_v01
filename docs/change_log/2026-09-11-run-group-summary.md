# Change Log — Phase 3b: the run-group summary

**Date:** 2026-09-11
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/input.schema.json`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`plugins/threat_modeling/adversary_path_projector/manifest.json`
**Supporting Files:**
`plugins/threat_modeling/adversary_path_projector/examples/README.md`,
`docs/specs/adversary_path_projector.md`

Follows `2026-09-11-live-run-findings.md`.

---

## Problem

Projection is sampled: the same actor against the same map does not produce the
same paths twice. Run records have existed since 2026-09-10 and made a group
*comparable*, but comparing was left to a person opening files side by side.
The live groups showed why that does not scale — group 2 produced five paths
across three runs, of which two pairs were near-duplicates of one route.

Triage's second question is "is there a credible path we have not considered",
and credible means sourced **and** recurring. Nothing counted recurrence.

## What a route is

A route is **the components a path visits, with consecutive repeats
collapsed** — `portal → claims_api → doc_store`. Two runs that enter at the
portal, work through the API and read the document store found the same way in
even when they choose different techniques along it, and reporting them as two
findings is the "four flavours of vanilla" problem.

Within a route, recurrence is keyed on **(component, technique) pairs, never on
prose**. Descriptions and rationales vary between runs by design; comparing
them would make every run look unique.

- **Recurring** = found in at least half the *successful* runs, in a group of
  three or more successful runs. Below that, routes are still counted and
  nothing is called recurring — `recurrence_countable` is false and the
  threshold is null, because two runs cannot establish that anything recurs.
- **One variant is shown per route**: the one with the most (component,
  technique) pairs in common with the others, ties going to the earliest run,
  so the same corpus always names the same representative.
- **`stable_pairs` needs a strict majority** of a route's variants, not half.
  With two variants — the commonest shape — a pair in one of them is exactly
  the sampling variance the split exists to expose.

Each route also carries the representative's assumptions, with the step each
belongs to, and a count of its state gaps. A recurring route with its
assumptions is the test plan for that route.

## Two ways in

- **`summarize_run_group --run_group <label>`**, no LLM. Reads the run records
  registered in this session, refusing a group that mixes flow map hashes or
  actors — the same route against two estates is not the same finding, and
  counting across them would be meaningless. The message names the maps and
  actors it found.
- **Automatically at the end of a `--runs` loop**, as `run_group_summary` on
  the result *and* in the terminal output. The loop already holds every record
  it wrote, so it answers its own question without a second command and without
  depending on the records still being registered.

  The loop's rendering is deliberately shorter than the group action's — three
  routes rather than four, and no variance or assumption lines — because it
  shares one 2000-character budget with the per-run lines above it. Both call
  the same `_render_route_lines`, so the two readers get the same words for the
  same thing; a three-run group renders in about 700 characters. It closes with
  a pointer to `summarize_run_group` for the full breakdown.

Records are found through registered artifact metadata rather than by scanning
the workspace: the registry is the session's own account of what was written,
and on Cloud Run a local directory is ephemeral. The consequence is worth
knowing — **a group written before the last `new`, or in another session, is
not visible**, and the error says so.

## Two bugs the tests caught

**The raw reply was labelled a run record.** `_write_run_record` registered
both the record JSON and the raw model reply with identical metadata, including
`kind: "projection_run"`. The raw reply is usually valid JSON, so the loader
parsed it as a record and died on the missing `run` block. The two are
different things and now say so: the reply is `projection_raw_response`. The
loader also skips any document labelled a record that has no `run` block — a
missing count is recoverable, a crashed action is not.

**A test fixture asked for a technique the actor does not use.** The
two-variant corpus used `T1083`, which is not in APT29's set, so Phase C
rejected it and the "different" variant collapsed into the first — two tests
were asserting against a corpus that never existed. The fixture now uses
`T1016.001`, which APT29 is documented using, and a
`_assert_corpus_intact` helper fails any test whose fixture is silently
rejected on the way in. The closed set was working exactly as designed; the
test was wrong.

## A group is built from batches, and that exposed a counting bug

A run takes 40–75 s at `medium`, and the plugin's `long` timeout class caps one
invocation at **600 s**, so three runs is comfortable and six in a single
invocation is not. The intended way to a larger group is therefore several
`--runs 3` invocations sharing a `--run_group` label — they accumulate, because
records are selected by that label rather than by invocation.

That did not work. `run_index` restarts at 1 in every invocation, and route
counting deduplicated on it, so two batches of three read as runs 1,2,3,1,2,3
and collapsed to three. Measured on a corpus where one route appeared in **four
of six** runs:

```
before:  runs listed [1, 2]        run_count 2   recurring False
after:   runs listed [1, 2, 4, 5]  run_count 4   recurring True
```

A false negative, and precisely in the workflow that exists to stay inside the
timeout — the longer the group, the more likely it is to hide a recurring
route.

Runs are now numbered **within the group**, 1..N in the order they happened,
and records are sorted by `created_at` so batches interleave correctly rather
than by an index that means nothing across invocations. Each route's
representative also carries the `record_file` it came from, so a reader can get
from the summary back to the run without counting. The schema says why the
group ordinal is not the record's own `run_index`.

Two consequences worth knowing: the ordinals are group-relative, so run 4 in a
summary is the first run of the second batch, not a record whose `run_index` is
4; and each invocation still writes its own attack graph and scenario seed, so
a two-batch group leaves two pairs of those.

## What the first live six-run group changed

Volt Typhoon against the claims portal, two batches of three, all six
successful. It found two faults.

**Reconnaissance was splitting a route in two.** The group reported three
routes, the third being `cdn -> portal -> claims_api -> doc_store`. That is the
second route with a Reconnaissance step against the CDN in front of it —
nothing is compromised at the CDN and the attacker moves nowhere, so counting
it as part of the route diluted a recurring finding into a recurring one plus a
one-off.

Route identity now skips **pre-intrusion tactics** — Reconnaissance and
Resource Development — which are work done before or without a foothold. They
remain in the representative variant's steps, where a reader can see them; they
just no longer decide which route a path is. On the live shape:

```
before:  3 routes — db 6 variants, doc 4 variants, cdn+doc 1 variant
after:   2 routes — portal -> claims_api -> claims_db  6 of 6 runs
                    portal -> doc_store                5 of 6 runs
```

**Every state gap in the group was one labelling mistake.** All three routes
carried exactly one, and each was a step naming what the attacker held on the
*previous* component: the clearest was the API exploit claiming it needed
`code_execution` on the API in order to gain code execution there. The check was
right to flag a self-contradictory step; the prompt had never said which
component `access_before` refers to. It now does, and says that the first time a
path touches a component the answer is normally `network_reach`, because
execution is what the step produces rather than what it needs.

## Tests

**930 passed**, was 920. Ten added: a recurring route counted and shown once
with a one-off beside it; a pair in half the variants counted as varying, not
stable; the representative and its tie-break; a small group counting routes but
calling nothing recurring; a group mixing maps refused; an unknown group naming
where records come from; `run_group` required; the loop summarising its own
group; a failed run counting toward the group's size but not its findings and
costing it the recurrence claim; and the summary under the 2000-character cap
saying what each count is out of.

`validate_manifests.py` still reports exactly the 15 pre-existing `stability`
errors and nothing new. `ruff` and `black` are not installed here; style was
matched by hand.

## Wording

The summary says what each count is out of — "recurring, 2/3 run(s), 2
variant(s)" — because "recurring" alone is the kind of word a reader takes for
a verdict. A group too small to judge says so in its own line rather than
silently reporting zero recurring routes. `PROJECTION_NOTICE` closes the
summary, as everywhere else.

## Verified live

**2026-09-12, `phase3b-claims`.** Six runs of Volt Typhoon against the claims
portal, assembled from two batches of three in one session and counted as six.
It confirmed the batching fix end to end, and it is what found the two faults
recorded above — the `run_index` collision and Reconnaissance splitting a
route — neither of which any scripted corpus had exposed.

The group summary and the report built from it both rendered without issue. The
earlier `stepstate-medium*` groups were never summarised under the fixed code:
they predate it, and records are session-scoped, so they would need re-running
rather than re-reading.

## Not in this change

- **No comparison across groups.** A route recurring in two separate groups —
  the signal that a finding survived a prompt change — is still a person
  reading two summaries.
- **No seed of the representative paths.** The plan included writing one for
  `import_scenario`, so gap analysis could run against the recurring routes
  rather than run 1's paths. Deferred deliberately: the summary is worth
  reading before deciding what an artifact of it should contain.
- The route ordering is recurring-first, then by run count, then alphabetical.
  Nothing weights a route by how close it gets to a crown jewel.
