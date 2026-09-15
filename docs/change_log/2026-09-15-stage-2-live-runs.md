# Change Log — Stage 2 live runs, and the two defects they found

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md` Stage 2 — the live-run
requirement its acceptance sets
**Provider:** `gcp_gemini`, light tier (`gemini-3.8-flash`) — the manifest tier
**Scope:** `plugins/log_analysis/threat_intel_ingester/` (`ti`)
**Status:** five live runs made; two defects found in the 2.1/2.2 code and
fixed; Stage 2.0/2.1/2.2 now live-verified.

---

## Why this entry exists

Stage 1 was signed off on control flow and a green suite, and the first live
run found three further Goal A defects. The plan's own conclusion was **run the
tools before calling a stage done**. This is that run for 2.0/2.1/2.2, and it
found two more — both in the code the previous entries describe.

## Instrument

`scripts/make_probe_pdf.py`, already in the tree: a deterministic 3-page report
with exact ground truth (94 indicators — 24 IPv4, 20 domain, 16 sha256, 12 URL,
10 CVE, 12 technique). Plus a second fixture built for this run: a text report
that restates five indicators across four sections that frame them in
contradictory ways (confirmed C2 / probable CDN false positive / low-confidence
historical / re-confirmed), so chunk boundaries fall between framings. That is
the only way to make a real disagreement appear — the probe's indicators are
page-unique, so no entity is ever reported twice.

The harness wires the same objects the shell does — `build_clients` →
`LLMDispatcher` → `TierScopedLLMClient` — so routing, clamping and native
document dispatch are the real ones.

## The runs

| # | Shape | Result |
|---|---|---|
| 1 | Native, whole document | `complete`, 1 attempt, 0 unassessed, 62 IOCs |
| 2 | Native, page-batched (`EVENTMILL_NATIVE_S_PER_PAGE=60`) | `complete`, 3 attempts, 72/82 non-technique and 12/12 techniques |
| 3 | Native, cap forced to 1,400 tokens | every reply starved below repair; all pages fell to the chunked path |
| 4 | Native, cap 6,000, planner under-estimating | **4 partials superseded, both routes** |
| 5 | Chunked text, contradictory framings | **25 conflicts, then 8 after the fix** |

Runs 3 and 4 force conditions with real knobs: `--cap` lowers the per-call
`max_tokens` exactly as a denser document would, and `--underestimate` makes
the planner group pages it should not — which is the production condition
`bisect_range` exists for. The model's truncation is its own
(`finish_reason=MAX_TOKENS`), not a stub's.

### Run 4 is the one that matters for 2.1

```
[NATIVE] p1-3 cut off after 30 of 74 candidates — re-running as p1-2 and p3
[NATIVE] p1-2 cut off after 2 of 40 candidates  — re-running as p1 and p2
[NATIVE] p1  finish=STOP    — 16 refined_iocs, 7 techniques
[NATIVE] p2  cut off, cannot be split further   — pages 2-2 to the chunked path
[NATIVE] p3  cut off, cannot be split further   — pages 3-3 to the chunked path
[MERGE] 4 truncated native partial(s) were replaced by a later attempt:
        p1-3 <- p1-2, p1, p2, p3, chunked text path
        p1-2 <- p1, p2, chunked text path
        p2   <- chunked text path
        p3   <- chunked text path
```

Both supersession routes fired on real traffic: bisected retries covering their
parent by page containment, **and the cannot-split fall-through to the chunked
path** — the route the plan's original write-up did not have, added while
implementing 2.1. 32 indicators carried more than one sighting; all were kept.
`candidates_not_submitted` was 0 on this shape as on every other, which is
2.0's invariant holding on the most complex run of the five.

**Honest limit on what run 4 proves.** The machinery is confirmed; the defect's
impact is not. Checked directly: of the superseded sightings, **zero disagreed
with the canonical value** — Gemini was self-consistent across attempts, so a
pre-2.1 first-wins merge would have produced the same output on this run. 2.1
is verified as *working*, not as *having mattered here*. How often a partial and
its retry actually disagree on a real report is still unmeasured.

### A live corroboration of Stage 1.1

Thinking spend, same model, same document, four calls:

| Call | Prompt | Thinking | Content | Cap |
|---|---|---|---|---|
| p1-3 | 25,282 ch | 2,607 | 3,389 | 6,000 |
| p1-2 | 16,375 ch | **5,756** | **239** | 6,000 |
| p1 | 8,952 ch | 1,653 | 2,621 | 6,000 |
| p3 | 15,587 ch | 5,762 | 234 | 6,000 |

A *smaller* prompt spent more than twice the thinking of a larger one and left
239 tokens for the answer. At a 1,400 cap (run 3) thinking took 1,340 and left
~50 — too little even for `_repair_truncated_json` to recover. This is Stage
1.1's premise and the ping-starvation note, reproduced on live traffic:
**thinking spend is non-deterministic and is charged against the reply's
budget.**

---

## Defect 1 — a dropped false positive took its dissent with it

Run 5 reported **25 conflicts** and the reader could find **17**.

The missing eight belonged to two indicators whose canonical verdict was
`is_false_positive: true` while other chunks called them real. The
false-positive filter drops those records — correctly, per Stage 1.5, which
exists precisely because reinstating a rejection turns a right answer into a
wrong one — but it took their `conflicts` entries out of the output with them.

This is a Goal B failure introduced by 2.2, and it lands on the single most
analyst-relevant case: *one attempt says malicious, another says false
positive.* Every other disagreement was visible; that one was removed.

**Fix.** The rejection still stands and the record still leaves `iocs`. What
changes is that the disagreement is named: `rejected_with_dissent` lists the
values (capped at 25), a `REJECTED OVER DISSENT` note states the count and says
plainly that this note is the only record of it, and the run is `partial`.
Counts now reconcile — run 5 re-run: 8 counted, 8 visible.

An *undisputed* rejection is untouched: every attempt agreeing it is a false
positive is an assessment, not a disagreement, and raises nothing. There is a
test for that, because conflating the two would undo Stage 1.5.

## Defect 2 — a spelling set the run to partial

Run 5 raised four MITRE conflicts of this shape:

```
T1566.001  'Spearphishing Attachment'  vs  'Phishing: Spearphishing Attachment'
T1071.001  'Web Protocols'             vs  'Application Layer Protocol: Web Protocols'
```

The same technique, named two ways. `technique_name` was in
`_MITRE_CONFLICT_FIELDS`, and **any** conflict makes a run `partial` — so a
naming variant degraded the status of the whole run. Worse, the name is not
even contested information: `_reconcile_mitre_mappings` overwrites it from the
local ATT&CK lookup regardless of what the model said.

**Fix.** `_MITRE_CONFLICT_FIELDS = ("confidence",)`. Both sightings are still
kept as occurrences; only the phantom disagreement is gone. Run 5 re-run: MITRE
conflicts 4 → 0, total 25 → 8, and the remaining eight are all real
(`confidence` and `priority` disagreements on indicators the sections genuinely
framed differently).

This was my design error in the 2.2 change, not a pre-existing defect.

---

## What run 5 shows when it works

```
198.51.100.77   canonical: confidence=high priority=high fp=False
   chunk 1/4    conf=high  prio=high  fp=False
   chunk 2/4    conf=low   prio=low   fp=True
   chunk 3/4    conf=high  prio=high  fp=False
   CONFLICT confidence:       high vs low   (chunk 2/4)
   CONFLICT priority:         high vs low   (chunk 2/4)
   CONFLICT is_false_positive: False vs True (chunk 2/4)
```

Before 2.2 the reader saw `confidence: high` and nothing else. The second
chunk's read of the same indicator — that it sits in shared CDN space and
should not be blocked — was discarded by first-wins. It is now in front of the
analyst, unresolved on purpose: a later correction and a lower-confidence
restatement are not distinguishable by value, and this fixture contains both.

## Unrelated observation, not acted on

Run 2's recall was **72/82 non-technique, 12/12 technique — but 10/20 on
domains**, and run 1 got 0/20 domains while scoring 24/24, 16/16, 12/12, 10/10
on every other type. The probe's domains sit under RFC 2606 reserved TLDs, and
`make_probe_pdf.py`'s own header flags that a model may rank a `.invalid` host
as obvious test data and decline to report it. That matches what happened. It
is a property of the fixture, it affects every provider equally, and it is
nothing to do with Stage 2 — recorded here so the next person reading a domain
recall figure does not chase it as a regression.

## Verified

- Full suite: **1380 passed** (1372 before these fixes; 8 new tests).
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.
- **Mutation-checked**, both fixes:

  | Mutation | Tests that failed |
  |---|---|
  | `technique_name` restored as a conflict field | 2 |
  | dissent on a dropped rejection not captured | 1 |

  The second mutation was **not caught on the first attempt** — the new tests
  drove `_analysis_fields` and the schema but never a real run, so the capture
  could be deleted with the suite still green. An end-to-end test was added
  (two chunked calls disputing one indicator) and the mutation is caught now.
  Worth recording: a test that cannot fail is a claim, not a check, and this is
  the second time in Stage 2 that the mutation check caught one.

## Not verified

- **One provider only.** Every run was `gcp_gemini` light tier. Anthropic and
  OpenAI keys are present and were not used; per-provider truncation behaviour
  and thinking spend differ, and the supersession path is driven by truncation.
- **Not the 154-page report.** The plan's acceptance names a live run against
  it; these ran against a 3-page probe and a 23,000-character text fixture. The
  batching shapes were reached with real knobs rather than real size, so
  per-call latency and cost at scale are unmeasured here.
- **`recovered_from_partial` never fired live.** Every superseded partial's
  entities were restated by a successor, so the retention path has unit
  coverage only.
- **Conflict frequency on real reports is unknown.** Run 5's fixture was built
  to contradict itself. Whether a genuine threat report produces conflicts at a
  rate that makes `partial` the normal status is exactly the question to watch
  on the next real run — if most real runs come back `partial` over routine
  restatement, the threshold needs revisiting rather than the reader getting
  used to ignoring it.
- `ruff` and `black` are still not installed in the active interpreter.
