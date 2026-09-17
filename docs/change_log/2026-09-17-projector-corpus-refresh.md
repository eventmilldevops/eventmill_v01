# The fixture corpus is replaced, and the export shape gets its own document

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** documentation only. New `docs/specs/projector_export_shapes.md`;
`docs/specs/attack_path_detection_normalization.md` — header, §0, §1.1b
(replaced), §3 transition counts, §4.3 3a, §5, §6 N1/N3 gates, new §7a,
decision 6, §9. No code changed, no tests run, no LLM call made by the
assistant.
**Status:** the new corpus is authoritative; N1 implements against it.

## What happened

The operator ran the projector three more times on the current code
(`git_sha 1c2ba74`), against three different applications:

| Run | Actor | Flow map | Shape |
|---|---|---|---|
| `20260917_122549` | Scattered Spider (G1015) | `telemetry_saas_flow_map.json` | 2 paths, 11 nodes |
| `20260917_123525` | APT29 (G0016), input `Midnight Blizzard` | `application_b_flow_map.json` | 2 paths, 10 nodes |
| `20260917_124121` | Volt Typhoon (G1017) | `claims_portal_flow_map.json` | 2 paths, 13 nodes |

With `20260917_022646` (Fox Kitten on the telemetry map) that is **four pairs,
43 nodes, one code revision, three applications, four actors** — and, for the
first time, a **run record** alongside three of the four pairs. The three older
pairs are retired.

## Why the refresh was worth its cost

The retired corpus was not wrong; it was *mixed*. `165537` and `204815`
predate the provenance block and can never be joined on `run_id`. `192507`
predates the code-identity change. Counts stated over "all four fixtures" were
therefore counts over four different producers, and every one of them was
about to become an N1 test constant.

Two things the refresh buys outright:

1. **The commit blocker is gone.** All four pairs were projected against flow
   maps that are already in the repository, so the applications are the
   repository's own examples and CLAUDE.md's prohibition on tenant identifiers
   does not bite. Decision 2 of the two that gated N1 is resolved; decision 1
   — where `normalize_paths` lives, given whole-plugin
   `safe_for_auto_invoke` — is untouched and still blocks code.
2. **`component_bound_partial` has real instances.** The grade was added on
   2026-09-17 with the note that no fixture exercised it. Five nodes now do:
   `front_door` and `users` on Application B, `claims_db` and `doc_store` on
   Claims Portal — components that bind but declare no `technologies` or
   `authentication: none`.

And what it costs, recorded rather than discovered later (spec §7a): the
10-step path, the three-path graph, the within-path technique repeats, the
no-provenance case and the `git_worktree` code-identity branch all lose their
real subject. The within-path identity rule is now covered by the synthetic
case **only**, which makes that test load-bearing rather than supplementary.

## What the new measurements confirmed, changed, and found

**Confirmed on data that shares no run with the original measurement:**

- The `state_check` split/join holds **43 of 43, 0 conflicts**, with the note
  branch exercised by the 9 gap nodes. Across the retired and current corpora
  that rule is now 101 of 101 over seven runs and three applications.
- The mitigation finding reproduces: **163 of 169 uncovered, 6 covered**, 3.9
  per node, with M1026 (112 techniques) and M1018 (119) the most frequent
  members. The earlier figure was 147 of 154.
- No `(technique_id, component_id)` pair repeats within a path anywhere.

**Changed:** all the corpus-derived constants in the plan — the N1 gate
(9, 11, 10, 13 = 43), the transition shape counts (8 entry / 18 declared flow /
17 null, of which 16 are in-place and 1 undeclared), the grade distribution
(38 `component_bound`, 5 `component_bound_partial` with the map; 43
`asset_named` without it).

**Found, and new to the plan:**

- **`transition` needs canonicalizing, like `state_check`.** The graph carries
  an object, the seed carries prose. The prose is derivable from the object but
  **not the reverse** — it omits `crosses_boundary` entirely, so an intra-zone
  flow and a boundary crossing render identically. Without an explicit rule,
  every non-null transition in every pair joins as a conflict. Added to §4.3 as
  part of rule 3a.
- **Run-record warnings join positionally and can be lost.** `STATE_GAP`,
  `TACTIC_CORRECTED`, `HOP_NOT_DECLARED` and `LATE_INITIAL_ACCESS` carry
  findings no other document holds, keyed only by `<path_id>.steps[<n>]`. The
  run record is also missing for one of the four pairs, so it cannot be a
  required input.
- **`controls_in_play[].on` is `component` on all 65 entries.** The flow-scoped
  form the field permits has never been produced.
- **`access_source` is `model` on 43 of 43.** The tactic-default fallback is
  declared and unexercised.
- **The seed's `blocking_controls` / `detecting_controls` are control
  *names*, not `control_id`s**, and on 18 of the 22 events carrying any, the
  two lists are identical. `detecting_controls` is closer to "controls on this
  component" than to "controls that would detect this step"; the discriminating
  signal is the catalogue's `detection_capability`.
- **`leads_to` no longer dangles.** 35 edges, 0 pointing at a technique absent
  from the run — the dead-edge problem carried in the handoff notes is not
  present in this corpus.
- **`mitre_mappings` is exactly the technique set of the steps** in all four
  runs, so it is a projection of the steps and not an independent field.
- The v19 restructure is visible in output: 12 tactics including `Stealth` (3)
  and `Defense Impairment` (2), no `Defense Evasion`, and three live
  `TACTIC_CORRECTED` relabels.

## Why a separate shape document

`attack_path_detection_normalization.md` is a consumer-side plan that had
accumulated the producer's shape inside its findings sections, dated to
whichever fixtures existed that day. A second corpus change would have meant
another pass over prose whose *findings* are still correct. The producer's
shape now lives once, in `docs/specs/projector_export_shapes.md`: the
three-document contract, the envelope, all 25 step fields and all 23 event
fields, the vocabularies as observed, what the output does not carry, and a
closing section of consequences for schema work. §§1.1–1.6 of the plan were
deliberately **not** rewritten — §0 dates them to the retired corpus, and a
finding that explains why a rule exists is worth more than a count restated.

## Verified

Both exports of all four current pairs and all three run records parsed with
`encoding="utf-8"` and diffed field by field; all 43 `component_id` values
resolved against the three example flow maps; mitigation breadth recomputed
from `framework/reference_data/mitre_relationships.json` (96 mitigations,
ATT&CK 19.2). Every count in both documents comes from that pass.

Not done: no code changed, no test run, no validator run, nothing committed,
and the retired pairs were **not** deleted — that is the operator's to do. The
four current pairs are still outside the repository, in
`C:/projects/eventmill_v02/test_data/path_projector/`; committing copies is now
permitted but has not been done.
