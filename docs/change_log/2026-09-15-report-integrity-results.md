# Results — report processing integrity, Stage 1 and Stage 2 to date

**Date:** 2026-09-15
**Branch:** `llm_5`, not pushed. Tree clean at `59dca48`.
**Plan:** `docs/specs/report_processing_integrity.md`
**Scope:** `plugins/log_analysis/threat_intel_ingester` (`ti`),
`plugins/threat_modeling/threat_report_analyzer` (`tra`)
**Status:** Stage 1 complete. Stage 2 half done (2.0, 2.1, 2.2), live-verified
on one provider, **not signed off**. Stages 3 and 4 not started.

This entry reports outcomes against the plan's three goals. The per-step
entries say what changed and why; this one says what it bought and what is
still unmeasured. Nothing here is new work.

---

## Against the goals the plan set

The plan replaced "establish that all relevant report context survived
processing" with three goals that can be failed. Standing now:

| Goal | Testable how | Stage | Status |
|---|---|---|---|
| **A.** Incomplete work is never reported as complete | Synthetic responses | 1 | **Holds** for both tools, on control flow and on five live runs |
| **B.** Evidence the model produced is never destroyed deterministically | Synthetic responses | 2 | **Holds for the merge** (2.1, 2.2). Batching (2.5) and the analyzer's caps (2.6) outstanding |
| **C.** Meaning is more likely to survive a chunk boundary | Analyst-labeled fixtures | 3 | **Not started, still gated** — the Appendix A fixture set does not exist |

Goal C is gated on purpose: it is an improvement in odds, and building it
before the fixtures exist ships a change nobody can evaluate.

## Counted outcomes

| Measure | Before Stage 1 | After Stage 1 | Now |
|---|---|---|---|
| Full suite | 1,177 | 1,319 | **1,380** |
| Tests in the two report plugins | — | 263 | **324** |
| `ti/tool.py` lines | ~2,440 | 2,661 | 3,017 |
| Schemas valid (`validate_schemas.py`) | 34 | 34 | **34, exit 0** |

Stage 2 so far: **+61 tests**, all deterministic, no live model call required by
any of them.

## Defects closed, by how they were found

**This is the number worth keeping.** The plan's method was a deterministic
review, then a live run. Both found real defects, and the split is the argument
for doing both.

| Discovery route | Count | What |
|---|---|---|
| Parent review, read against the tree | 8 | The findings settled in `2026-09-15-chunking-integrity-review.md` |
| Found while reading the code to plan the work | 2 | The budget starvation the external review missed (reordered Stage 1 so 1.1 went first); 2.1's cannot-split fall-through, absent from the plan's write-up |
| Found by tests during implementation | 1 | The merge's arrival-order pass — a superseded partial created the canonical record *and* raised a conflict against its own retry |
| **Found by running the tools** | **5** | 3 after Stage 1, 2 after Stage 2's merge work |

Five of sixteen — nearly a third — were invisible to a green suite and a code
review. Both times, the code had just passed a full suite *and* a mutation
check when the live run found more.

### The five live findings

| Stage | Defect | Class |
|---|---|---|
| 1 | Rejection note counted verdicts returned and called them "all candidates" | A |
| 1 | Coverage counted lines and labelled them pages | A |
| 1 | Analyzer export stated no page count on the native path | A |
| 2 | A dropped false positive took its `conflicts` out of the output — 25 counted, 17 visible | B |
| 2 | `technique_name` as a conflict field set whole runs `partial` over a naming variant | A |

The Stage 2 pair both landed on code written the same day.

## What the live runs established

Five runs, `gcp_gemini` light tier (`gemini-3.8-flash` — the manifest tier),
against `scripts/make_probe_pdf.py`'s 3-page probe with exact ground truth, and
a purpose-built text fixture that contradicts itself across chunk boundaries.
Full detail in `2026-09-15-stage-2-live-runs.md`.

**Confirmed working on real traffic:**

- Supersession by page-range containment, **both routes** — bisected retries
  covering their parent, and the cannot-split fall-through to the chunked path.
  Four partials superseded in one run.
- Occurrence retention: 32 indicators carried more than one sighting; none was
  discarded.
- Conflict recording: a chunk that called three indicators false positives at
  low confidence, against three chunks calling them high-confidence malicious.
  Pre-2.2 the reader saw the first verdict and nothing else.
- 2.0's invariant (`candidates_not_submitted == 0`) on all five shapes,
  including the most complex.
- Recall against ground truth: **72/82 non-technique, 12/12 technique** on the
  page-batched run.

**Confirmed but with no measured benefit:** of the superseded sightings, **zero
disagreed with the retry that replaced them.** Gemini was self-consistent, so a
pre-2.1 first-wins merge would have produced identical output on that run. 2.1
is verified as working, not as having mattered. Its real-world severity is
unmeasured.

**A live corroboration of Stage 1.1.** Same model, same document, 6,000-token
cap: one call spent 5,756 tokens thinking and had 239 left for the answer,
while a call with a *larger* prompt spent 2,607 and got 3,389. At a 1,400 cap,
thinking took 1,340 and left ~50 — below what `_repair_truncated_json` can
recover. Thinking spend is non-deterministic and charged against the reply's
budget, on live traffic, which is exactly what Stage 1.1 was built on and what
[[llm-ping-budget-starvation]] recorded from probes.

## What the tools now say about their own work

The reportable surface both plugins gained, all additive — no top-level key any
existing consumer reads has moved, and neither
`attack_path_visualizer` nor `adversary_path_projector` needed a change.

| Field | Answers |
|---|---|
| `analysis_status` + `analysis_notes` | complete / partial / degraded, stated first, with every cause named |
| `coverage` + `unit` / `coverage_unit` | how much was read, in pages or lines — the field that would have caught a summary being ingested as a report |
| `truncated_chunks`, `chunks_attempted`, `chunks_failed` | which calls were cut off and which produced nothing |
| `candidates_rejected` | verdicts the model actually returned |
| `candidates_unassessed` | candidates submitted that got no verdict — the model's silence |
| `candidates_not_submitted` | candidates that reached no prompt — our coverage gap, kept separate on purpose |
| `occurrences[]` | every sighting of an indicator or technique role, with batch, attempt and page range |
| `conflicts[]` | scalar disagreements between standing reports, recorded and **never auto-resolved** |
| `recovered_from_partial` | records surviving only from a cut-off reply the retry did not restate |
| `rejected_with_dissent` | rejections another batch argued against — absent from `iocs`, so this is their only record |
| `merge_stats`, `native_attempts` | what the merge did, and native outcomes that `chunks_attempted` cannot see |

## Verification method, and where it fell short

Every step was mutation-checked: the change reverted, the new tests confirmed
to fail on the defect rather than merely pass on the fix. **Ten mutations
across Stage 2, all caught** — but two of them were not caught on the first
attempt:

- 2.0's integration test patched the wrong extraction pass, so it passed on the
  fix *and* on the defect.
- The `rejected_with_dissent` tests drove `_analysis_fields` and the schema but
  never a real run, so the capture could be deleted with the suite green.

Both were found by the mutation check and replaced with tests that drive a real
run. The lesson is narrower than "write tests": **a mutation check that only
exercises a helper proves nothing about the path that calls it.** A test that
cannot fail is a claim, not a check.

## Not verified — read this before trusting any of the above

- **One provider of three.** Every live run was `gcp_gemini` light. Anthropic
  and OpenAI keys are present and were not used. Supersession is driven by
  truncation, and truncation behaviour and thinking spend are per-vendor.
- **Not at scale.** The runs used a 3-page probe and a 23,000-character text
  fixture. The batching shapes were reached with real knobs
  (`EVENTMILL_NATIVE_S_PER_PAGE`, a forced per-call cap, a pinned planner
  estimate), not real size. The 154-page report named in Stage 2's acceptance
  has not been run since Stage 1.
- **`recovered_from_partial` never fired live.** Unit coverage only.
- **Conflict frequency on a genuine report is unknown.** The fixture that
  produced conflicts was built to contradict itself. If real reports come back
  `partial` over routine restatement, the threshold needs revisiting rather
  than readers learning to ignore the status.
- **Stage 2 is half done.** 2.3 (`path_id` namespacing), 2.4 (multiple actors
  and campaigns), 2.5 (candidate/text alignment — the only step with a real
  behavioural change), 2.6 (the analyzer's silent caps) are outstanding.
- **Latency is still modelled pessimistically.** Unchanged and deliberately
  untouched: Stage 3.1 owns it, and it is gated. See
  [[ingester-latency-model-pessimistic]].
- **`validate_manifests.py` still reports 15 `'stable' is not one of [...]`
  errors** and exits 0. Pre-existing, documented in `CLAUDE.md`, untouched —
  `stability` governs visibility and auto-invoke policy, so remapping it is a
  behaviour decision rather than a typo fix.
- `ruff` and `black` are still not installed in the active interpreter, so
  neither has run against any of this work.

## Commits

| Commit | Contents |
|---|---|
| `866c27d` | The review and the staged plan — docs only |
| `a83e74e` | Stage 1.1, plus the analyzer PDF-alignment work |
| `2d7eec2` | Stages 1.2–1.7 |
| `2efb594` | Post-Stage-1 repairs, found by running the tools |
| `fe4a244` | Stage 2.0 and 2.1+2.2 |
| `59dca48` | The two defects the Stage 2 live runs found |
