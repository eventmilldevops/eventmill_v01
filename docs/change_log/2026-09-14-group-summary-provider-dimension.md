# Change Log — recurrence per provider, agreement across them

**Date:** 2026-09-14
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`

**1095 tests pass** (was 1083; +12). Stage D of
`docs/specs/projector_three_vendor_run.md` — the last one before the live run.

---

## The number that was wrong

`recurring` meant "found in at least half the successful runs of the group". In
a nine-record group from three vendors that counts nine runs as one population,
and two different findings become indistinguishable:

- a route all three Gemini runs found and nobody else — 3 of 9
- a route Gemini found twice and OpenAI twice — 4 of 9

Neither clears a threshold of 5, and the reader cannot tell them apart. Worse,
three samples from one vendor outvote two other vendors, so **the provider that
is cheapest to run decides the finding**.

## Two statistics, never averaged

| | Question | Denominator |
|---|---|---|
| `recurrence` | does this model keep finding it? | that provider's own successful runs |
| `agreement` | does it survive a change of reasoner? | providers in the group |

Each route now carries `by_provider` (which of that vendor's runs found it, and
whether that met **its** threshold), `providers_finding_it`, and an `agreement`
grade of `unanimous` / `majority` / `partial` / `single`.

**`recurring` is true when at least one provider kept finding it.** Not a
majority of providers — this tool is triage, and its job is surfacing credible
paths nobody has considered. A route one model produced consistently is a
reason to look, not something to suppress; `agreement` is what tells the reader
how far the support extends.

With two providers there is no majority tier, because a strict majority of two
is two. A route found by one of them is `partial` — precisely the disagreement
the grade exists to show.

**A vendor whose every run failed does not vote.** Counting it would make
"found by every provider" unreachable for reasons that have nothing to do with
the architecture. It still appears in `runs_by_provider` with its failure count,
because what the group cost is worth knowing.

## A single-provider group is arithmetically identical

The per-provider denominator *is* the group denominator when there is one
provider, so this is not a special case. `TestSingleProviderGroupIsUnchanged`
pins the numbers, and the report keeps its old wording exactly: the vendor
clause, the per-vendor column and the agreement prose all appear only when more
than one provider served the group.

The sort gained a vendor term — recurring, then **vendors** that found it, then
runs, then route — because a route two vendors found twice each is a stronger
finding than one a single vendor found five times. With one provider every
route scores 1 there, so the order does not move.

The in-loop `run_group_summary` is unaffected by construction: one `execute()`
runs against one provider, so a loop's own group is always single-vendor.

## The report

```
9 runs, 9 completed, across gcp_gemini, anthropic, openai …

| Route                               | Found in                                  |
| Customer portal → Customer database | 5 of 9 runs (gcp_gemini 3, anthropic 2; majority) |
| Customer portal                     | 4 of 9 runs (anthropic 1, openai 3; majority)     |

No recurring route was found by every provider in this group. Each rests on one
vendor's reading of the same architecture, and the same question.
```

One paragraph had to be rewritten rather than extended. *"A route found in 5 or
more of 9 runs is a pattern worth testing"* quotes the group-wide threshold,
which is no longer what decides recurrence — it would have told the reader to
apply a test the summary did not use. For a mixed group it now reads *"counted
per provider … (gcp_gemini 2 of 3, anthropic 2 of 3, openai 2 of 3). Agreement
is counted separately, in vendors rather than runs."* The single-vendor wording
is untouched.

## Confounds warn, and never refuse

`_group_confounds` reports a group whose runs differ in `thinking_level`,
`max_paths`, `software_scope`, or `prompt_sha256`. Warnings, not refusals: a
group deliberately varying one knob is a legitimate experiment and refusing it
would remove the ability to record one — but the same variation arrived at by
accident silently turns "these vendors disagree" into "these vendors were asked
different questions".

`prompt_sha256` is the strongest of the four and subsumes most of the others:
if it differs, the models were not asked the same thing whatever the individual
settings say. It exists because of Stage C.

**Mixing providers stays allowed** — that is the point — while mixing the
estate or the actor is still refused outright.

## A bug found on the way

`_summarize_run_group_action` **assigned** `report_warnings` on the
blocking-map-error branch and **appended** on the next one. With confound
warnings added ahead of both, a group with an unreadable flow map would have
silently discarded them. Now both append.

## Verified

- **1095 passed**, none skipped, none xfailed. 259 in the projector's suite.
- 12 new tests: per-provider recurrence, all four agreement grades, the
  two-provider case with no majority tier, a failed vendor not blocking
  unanimity, a v3 record grouped as `unknown` rather than guessed at,
  single-provider numbers and report wording unchanged, and the three confound
  warnings.
- `validate_schemas.py` — 34 schemas, all valid.
- A nine-record three-vendor group rendered end to end and read by eye.
- `ruff` / `black` / `mypy` are not installed in this venv, so none was run.

## Stage E is now unblocked

Everything the three-vendor run needs is in: `connect` binds all three, `use`
points a module at one, the record names the vendor and hashes the question,
and the group summary reads a mixed group without letting one vendor's sampling
outvote another's. What remains is operating it — `docs/specs/projector_three_vendor_run.md`
Stage E — plus the `shlex` backslash defect noted in
`2026-09-14-run-record-attribution.md`, which a Windows operator will hit when
typing a flow map path.
