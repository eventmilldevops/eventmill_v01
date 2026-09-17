# Change Log — the 154-page live run, retired ATT&CK ids, and a stale deadline

**Date:** 2026-09-14
**Branch:** `llm_5`
**Primary Files Modified:** `framework/reference_data/mitre_attack.py`,
`framework/reference_data/mitre_retired_techniques.json` (new),
`plugins/log_analysis/threat_intel_ingester/tool.py`,
`plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json`,
`tests/framework/test_mitre_retired_techniques.py` (new),
`plugins/log_analysis/threat_intel_ingester/tests/test_contract.py`

**1159 tests pass** (was 1137; +22). Everything here comes out of one live
run of `threat_intel_ingester` on a 154-page report.

---

## The run, and what it proved

Intake at scale, on `gcp_gemini`, heavy tier: **154 pages read, completed in
~345 s**, 169 IOCs, 96 unique techniques across 101 tactical roles, 45 attack
paths, artifact written and consumed by `attack_path_visualizer`.

Before the same day's page-limit fix this document stopped at page 50 and
reported `page_count: 50` with nothing to indicate that 104 pages had never
been examined. That fix is validated end to end by this run.

## The latency model is ~6.3x pessimistic — recorded, not yet changed

The plan estimated **2185 s** for a run that took **~345 s**. Reconstructing
the batch list from the `[PLAN]` log reproduces 2185 s exactly, so the
arithmetic is not in doubt:

| term | contribution |
|---|---|
| `seconds_per_page` (12.0) x 154 | **1848 s — 85%** |
| `base_seconds` (10.0) x 24 batches | 240 s |
| `seconds_per_candidate` (0.7) x 139 | 97 s |

`LatencyModel`'s own docstring says *"Writing the records dominates — the
per-candidate term is what keeps a batch inside the deadline."* The
coefficients say the opposite: the page term is 85% of the estimate. It was
fit on a single 5-page/14-candidate observation, where pages and candidates
could not be separated.

The visible symptom is not a timeout but **over-splitting**: 24 batches of
6-7 pages each, sized by pages rather than by work — `p1-7` carried 0
candidates and `p8-11` carried 44, yet both got the same budget. That costs
24x the per-call overhead and, more to the point, **separates pages that
should be read together**: an indicator on p7 and its attribution on p9 land
in different calls and neither call sees both.

**Not corrected here.** One measurement fixes the direction but not the
coefficients, and `EVENTMILL_NATIVE_BASE_S` / `_S_PER_PAGE` /
`_S_PER_CANDIDATE` already allow recalibration without a code change. Two or
three runs of different shapes are wanted before refitting.

**A planner budget check was proposed and withdrawn.** The earlier
recommendation was that `plan_ingestion` compare its total against the
plugin's 600 s timeout and refuse up front. Against this model it would have
**refused a run that completed in 345 s**. A budget guard on top of a
6x-pessimistic estimate blocks work that would succeed, so calibration has to
come first. Recorded here because the ordering is the lesson.

## Fix 1 — retired ATT&CK ids were demoting correct findings

The run logged four `[RECONCILE] Unvalidated technique` warnings:
`T1562.001`, `T1656` (twice) and `T1562`. None of them was a model error.

The bundled database is `attack_version: 19.2`, and v19 split the former
Defense Evasion tactic into **Stealth** and **Defense Impairment**,
renumbering techniques in the process:

| Emitted (pre-v19) | 19.2 |
|---|---|
| `T1562.001` Impair Defenses: Disable or Modify Tools | **`T1685`** Disable or Modify Tools |
| `T1656` Impersonation | **`T1684.001`** Impersonation |
| `T1562` Impair Defenses | split across **`T1685`-`T1690`** |

A model emits the numbering in its training data and in most published
reporting, so a correct technique arrives under a retired id. With nothing to
bridge them — `mitre_relationships.json` carries campaigns, groups, matrices,
mitigations, procedures and software, but no revocation map — each one was
marked `mitre_validated: false` and had "(non-ATT&CK ID)" appended to its
name. That drops it out of every ATT&CK-keyed view and tells an analyst it is
not a real technique. It would have happened on **every** ingestion.

### How it resolves now

`resolve_retired_technique(id, name)` in `mitre_attack.py`, in two layers:

1. **A curated map** (`mitre_retired_techniques.json`) for ids whose *name*
   also changed, or which have no single successor. Seeded from this run's
   evidence only — three entries — and deliberately **not** a complete v19
   migration table.
2. **Name resolution** for the general case, which is most of it: v19 mostly
   renumbered without renaming. The whole name is tried, then the part after
   the last colon, since a retired id arrives with its old parent attached.
   This caught `T1562.004` -> `T1686` with no curation at all.

It refuses rather than guesses. 23 enterprise names are shared by several
sub-techniques ("Botnet" is both `T1583.005` and `T1584.005`); an ambiguous
leaf is narrowed using the old parent name, and anything still ambiguous is
left flagged. Attaching a real ATT&CK id to the wrong technique is worse than
an entry an analyst has to look at.

**A split technique is never remapped.** `T1562` has six successors, so
choosing one would be a guess — it stays flagged, but the warning now names
all six and says to pick the one the report describes.

**Both views are rewritten, together.** The pass runs as step 0a of
`_reconcile_mitre_mappings`, ahead of the tactic normalisation, over
`mitre_mappings` *and* the attack graph's `technique_id` and `leads_to`.
Rewriting only the mappings would leave the graph pointing at ids that no
longer exist and the two views of one report disagreeing.

**Nothing is renumbered silently.** A remapped entry carries
`technique_id_retired_from` (now in the output schema), and each retirement
logs one line regardless of how many times the id appears.

**Remapping can merge entries**, which the pass handles: a report naming both
the retired id and its successor for one tactic collapses to a single entry —
`context_paths` folded, retired id recorded. The identity index downstream is
keyed on `(technique_id, tactic)` and would otherwise keep one entry while
the output carried the technique twice.

Replaying the run's four warnings now gives two clean remaps, one correctly
flagged split, and `3 retired ids remapped` in the summary.

### What this does not do

- **It is not a version upgrade.** It bridges old ids to 19.2; it does not
  add techniques 19.2 is missing, and none are known to be missing.
- **It cannot launder a hallucinated id.** `T9999` with an unknown name still
  fails validation — covered by a test, because a resolver that falls back to
  something plausible would be worse than none.
- **The curated map is evidence-seeded, not complete.** Entries are added
  with a note recording how each was verified; name resolution covers the
  name-stable cases meanwhile.

## Fix 2 — `_NATIVE_CALL_DEADLINE_S` was stale at 120 s

It cited `framework/llm/client.py`, a module that no longer exists. All three
clients now agree on **180 s** (`clients/gemini.py:222`,
`clients/anthropic.py:127`, `clients/openai.py:134`), so the planner's
effective per-call deadline was 96 s where it should have been 144 s.

Understating the deadline splits a document into more batches than it needs —
the same over-splitting the latency model causes, by an independent route.
Now 180 s, with the comment pointing at the three clients that set it.

## Next

1. **Recalibrate the latency model** from two or three more runs, then
   reconsider the planner budget check against the corrected model.
2. **Grow the retired-id map** from what real ingestions log. Each
   `[RECONCILE] Retired technique ... matched by name` line is a candidate
   for curation; each remaining `Unvalidated technique` line is a gap.
