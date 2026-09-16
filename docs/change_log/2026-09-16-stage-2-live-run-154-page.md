# Stage 2 live run — the 154-page report, and the defect it found

**Date:** 2026-09-16
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md`, Stage 2 acceptance
**Report:** `vendor_advisories/Anthropic-Detecting-and-countering-091026.pdf`, 154 pages
**Provider:** `gcp_gemini` — analyzer on `gemini-3.1-pro-preview` (heavy)
**Run stamps:** analyzer `20260916T010145Z`, ingester ~`20260916T011513Z`

Both report tools were run against the report named in Stage 2's acceptance.
The run did what the acceptance asked of it: it exercised most of the stage on
real traffic **and it found a defect that a green suite and 37 mutations had
not.** That is the sixth defect found by running the tools, against sixteen
found by review and tests.

---

## What the run confirmed

### threat_report_analyzer

| Step | Evidence |
|---|---|
| 1.4 `analysis_status` | `complete`, stated first in the export header |
| 1.6 stamped exports, persisted provenance | `Run: 20260916T010145Z`, `Answered by: gcp_gemini/gemini-3.1-pro-preview` |
| 1.7 coverage | `154 of 154, read natively as a whole document (no text extraction)` — the native branch, worded apart from the extracted-pages branch because no page-level extraction ran |
| **2.6 `ignore_caps`** | `List bounds: waived` in the header; 57 key findings returned where the bound would have given 50 |

**`ignore_caps` is verified live on its first use.** Added the same day in
response to the earlier run cutting 7 findings.

**Not exercised:** the native path sets `chunk_count = 1` and skips the
chunk-summary branch, so the **cross-chunk technique union never ran**. That is
the second unordered cap 2.6 found and the plan had not named. Unit-tested only.

2.6's two halves are now both covered live, but by **two different runs** — the
earlier one exercised the drop reporting, this one the waiver.

### threat_intel_ingester

Run status `PARTIAL`, with both causes named:
`UNASSESSED CANDIDATES: 1 of 139 submitted` (`heyhru.com`) and
`UNRESOLVED CONFLICTS: 8`.

| Step | Evidence |
|---|---|
| Stage 1 reconciliation | 1 of 139 submitted candidates got no verdict, named individually |
| **2.2 conflicts** | **8 real conflicts on a genuine report.** Every previous conflict came from a fixture purpose-built to contradict itself; this is the first evidence that conflicts occur in ordinary material |
| **2.4 actors and campaigns** | ~30 further actors and ~20 further campaigns collected beyond the scalars. **Before 2.4 every one of them was dropped** and the report would have claimed a single actor. The largest visible payoff in the change set |
| 2.5 tripwire | no `CANDIDATES NOT SUBMITTED` note, so `candidates_not_submitted == 0` — page coverage held |
| Multiple batches | conflicts require two batches reporting one entity, so the run was batched, not a single whole-document call |
| ATT&CK v19 | `T1078 (Initial Access, Privilege Escalation, Stealth)` — the v19 tactic, correctly reconciled |
| Reconciliation | 4 tactics auto-corrected, 2 flagged `tactic_mismatch` with `allowed_tactics` and an `ACTION:` line |

Extracted 157 IOCs and 91 unique techniques across 98 tactical roles, with a
31-path attack graph.

**Still unconfirmed: whether 2.5 ran at all.** 2.5 rewrote only the **chunked
text path**. The run was batched, but `native_batched` and `chunked_text` are
both batched and only the second executes `_build_chunk_units`. The `[PLAN]`
line or `summary.ingestion_plan.strategy` settles it and has not been read.
Until it is, 2.5 is verified by its tripwire (no coverage was lost) and not by
execution.

---

## The defect the run found — 2.4 regressed Stage 1.4

**`summarize_for_llm` came back at 3,712 characters against a 2,000-character
contract.**

2.4 collected every actor and campaign — correct, and the point of the step —
but then **narrated all of them**, and the report named thirty-odd actors and
twenty-odd campaigns, several of which the model returned as comma-separated
lists inside a single field. Those two sentences alone came to **2,033
characters, more than the entire budget.**

### Correction, same day — nothing was actually lost on this run

The first version of this entry said the findings "were being cut". **They were
not, and the claim was wrong.** Checked afterwards rather than assumed:

- The cap lives in `PluginExecutor` (`executor.py:166`), and the shell does not
  go through `PluginExecutor`. `do_run` calls `instance.execute()` directly,
  then `summarize_for_llm` at `shell.py:3097`, stores the result whole and
  prints it whole at `shell.py:3112`.
- **`PluginExecutor` is instantiated nowhere in the live code** — only its own
  module, the package `__init__`, and tests reference it.

So the 2000-character limit was a contract plugins are written against that
nothing enforced at runtime, and the full summary reached the operator intact.

What was true is narrower and still worth fixing: the summary was 85% over the
contract, it is stored in the session database in full, and at the point the
contract *is* enforced the material at risk is everything after the attribution
— the IOC counts, the technique line, the attack graph, the `ACTION:` line
naming two tactics that need analyst confirmation, and the output artifact id.
That is precisely the failure mode Stage 1.4 exists to prevent, reintroduced by
a later step that did not think about the budget.

### The fix

The plugin decides what to drop, rather than letting the truncator decide.

- `_bounded_list` caps any narrated list at 180 characters and states how many
  were not named. The first entry always goes in, however long.
- `_attribution_narration` sizes itself against the room the **rest of the
  summary actually left**, measured after everything else is assembled. Three
  tiers: narrate what fits; or state the counts and where to look; or, when not
  even that fits, say nothing.
- The full lists are untouched in `report_metadata.actors` / `.campaigns` and in
  the artifact. Only the narration is rationed.

The third tier is a deliberate exception to this project's "nothing is dropped
silently" rule, and it is worth being explicit about why. Attribution sits
*before* the IOC counts in reading order, so a counts-line squeezed in against a
cap that is already full does not land at the end — it pushes the findings off
it. The summary is lossy by construction; the artifact is not.

Replaying the live report's data through the fix: **3,712 → 1,413 characters**,
with the IOC counts, technique line and attack graph all intact.

**The budget is now per-manifest** (`2026-09-16-manifest-summary-budget.md`):
4000 by default, 8000 for both report tools, and enforced against the
manifest's number rather than a constant. The bounded narration stays
regardless — a bigger ceiling is not a reason to narrate thirty proper nouns,
and the analyst has the artifact and the source document.

### Verification

7 mutations, all caught — but **two survived the first attempt**, and for the
same reason as the four in the previous change set: the fixture was
well-behaved. A replay of the live report lands at 1,413 characters, comfortably
under the cap, so the *dynamic* sizing never bound and a mutation that ignored
the remaining room passed. Replaced with a sweep across the pressure band
(padding 0 → 1800) that walks the summary up to the cap, which catches both.

A fixed per-list budget is not sufficient on its own, and the arithmetic says
so: with the rest of the summary at 1,679 characters, even a 100-character
budget per list lands on 1,999 of 2,000. Tuning a constant to squeeze under is
the kind of fix that breaks on the next report.

---

## Two further findings, neither from this change set

### 1. The analyzer has no MITRE reconciliation at all

The analyzer's summary contains:

> | **Defense Evasion** | T1027 | Obfuscated Files or Information |

In the pinned v19.2 lookup, **T1027's only valid tactic is `Stealth`**, and
"Defense Evasion" does not exist as a tactic anywhere in the dataset. The model
also cited "MITRE ATT&CK Framework (v14+)" as a source.

Checked rather than assumed: `threat_report_analyzer` contains **one** match for
`mitre_attack|reconcile|tactic` in the whole file, and it is a comment.
`relevant_techniques` is a raw `T\d{4}` regex scrape, and every tactic name in
that table is unvalidated model prose.

So the same report through the two tools **disagrees about tactic names**, and
the analyzer's is the wrong one — the ingester remapped the identical retired
tactic correctly on the same document, the same day. An analyst reading the
exported `.summary.md` has no indication the labels are stale.

Not a regression and outside Stage 2's scope. Recorded for a decision: either
run the analyzer's extracted ids through the same reconciler, or state in the
export header that its technique labels are unvalidated.

### 2. `social_media_handle` is not a declared `ioc_type`

The run reported `17 social_media_handles`. The output schema's `iocs[].ioc_type`
enum declares nine values and that is not one of them.

Harmless at runtime — nothing validates plugin output against the schema, which
I checked. But the schema is then wrong about what the field can contain, and
the model relabels `ioc_type` freely by design. Either the enum grows or it
should stop claiming to be exhaustive.

---

## Status

**Stage 2 is not yet signed off.** The acceptance asks for one live run
covering the whole stage, and the change log to say which steps it exercised.
This entry says so, and two gaps remain:

1. `ingestion_plan.strategy` has not been read, so **2.5's execution is
   unconfirmed** — its tripwire held, which is not the same thing.
2. The analyzer's cross-chunk technique union did not run, because the document
   went native.

2.3 is in the same position it was in after the unit work: `paths_namespaced`
was not reported in the summary line, so whether a real slug collision occurred
on a 31-path graph is unknown. Verified as not breaking anything; not verified
as having mattered.

## Files

| File | What |
|---|---|
| `ti/tool.py` | `_SUMMARY_CAP`, `_SUMMARY_SAFETY`, `_SUMMARY_LIST_BUDGET`, `_bounded_list`, `_attribution_narration`; `summarize_for_llm` reserves an attribution slot and fills it last |
| `ti/tests/test_graph_and_attribution.py` | `TestTheSummaryStaysInsideItsBudget` — 11 tests, replaying the live report's actor and campaign lists verbatim, plus the pressure sweep |
