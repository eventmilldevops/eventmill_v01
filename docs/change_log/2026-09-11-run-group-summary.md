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
  the result. The loop already holds every record it wrote, so it answers its
  own question without a second command and without depending on the records
  still being registered.

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

## Not verified

**No live run.** Everything here ran against scripted replies. The two
`stepstate-medium*` groups on the container are the real first test: group 2
should report `portal → claims_api → doc_store` in 3 of 3 runs and
`portal → claims_api → claims_db` in 2 of 3, both recurring, with the
`claims_db` route's representative carrying the delegated-access gap.

Since records are session-scoped, summarising those groups needs either a
session that still holds them or a fresh `--runs` invocation.

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
