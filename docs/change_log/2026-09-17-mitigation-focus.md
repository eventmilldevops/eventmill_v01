# `uncovered_mitigations` is not a coverage finding

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** planning only. `docs/specs/attack_path_detection_normalization.md`
— new §1.4b, revised §1.4 table, `DetectionNodeContext` mitigation fields in
§3, the N3 gate in §6, four contract tests in §7, decision 4 in §8, §9 review
status. No code changed, no tests run, no LLM call made.
**Status:** decided and recorded; implementation lands with N3.

## The question

Defenders never implement every ATT&CK mitigation, so an "uncovered" list read
as a coverage gap is at best noise. Could normalization instead surface the one
or two mitigations most relevant to the telemetry a detection would use, for
the actor named in the projector run?

## What the measurement found

Neither narrowing filter is available locally, and the field itself carries
much less than the spec claimed.

**It is ~95% identical to `mitigations`.** Across `165537`, `192507` and
`022646`: 154 mitigations, 147 uncovered, **7 covered**. Mean 4.4 uncovered per
node against 4.5 total. The pack was about to carry the same list twice.

**Its frequency profile is inverted.** The most-often-uncovered M-IDs are the
broadest in ATT&CK:

| M-ID | Name | Techniques covered | Times uncovered |
|---|---|---:|---:|
| M1018 | User Account Management | 119 | 23 |
| M1026 | Privileged Account Management | 112 | 18 |
| M1047 | Audit | 110 | 15 |
| M1017 | User Training | 60 | 27 |
| M1032 | Multi-factor Authentication | 48 | 21 |

M1017 yields no telemetry at all. The list is dominated by advice applying to a
third of the matrix.

**It is component-blind.** `T1078` at `telemetry_db` and `T1078` at `scm` in
`022646` carry byte-identical eight-item lists. The set derives from the
technique, so it repeats verbatim wherever the technique repeats.

**No telemetry filter exists.** A mitigation entry in
`framework/reference_data/mitre_relationships.json` has exactly `description`,
`matrices`, `name`, `techniques`, `url`. No data sources, no data components —
the same absence §1.5 already records for techniques. Ranking by sensor
relevance would be a model claim with nothing local to check it, which is the
`DS####`-from-memory failure the spec forbids elsewhere.

**No actor filter exists either.** Mitigations attach to techniques, and the
technique at a node was chosen *because* the named actor uses it — the actor
constraint is applied upstream, when the projector builds the path. Filtering
again at the node re-derives the same set.

Two further corrections to §1.4's old wording. What the projector computes
(`plugins/threat_modeling/adversary_path_projector/tool.py:2042-2063`) is the
technique's mitigations minus the M-IDs tagged on controls declared **on that
one component** — not an estate-wide check, and absence of a *tag* rather than
absence of a *control*. The projector already narrates this at `tool.py:4593`:
untagged controls cannot be matched, and estate-wide and flow controls are not
checked at all. Calling the field "what this estate does not implement" was
wrong in both directions.

## What was decided

Split the audience, not the data.

- **The pack keeps `mitigations[]` and `uncovered_mitigations[]` whole.** They
  are already in the export, they cost nothing, and discarding them would make
  a later change to this rule unexplainable.
- **`mitigation_focus[]`** — the one or two narrowest uncovered mitigations,
  ranked ascending by `len(mitigations[M].techniques)`, ties broken by M-ID,
  each carrying its breadth so a reviewer sees the basis. A local deterministic
  lookup. On `022646` step 1 (`T1190`) it yields M1016 *Vulnerability Scanning*
  (5) and M1048 *Application Isolation and Sandboxing* (14) in place of M1026
  (112).
- **`mitigations_covered[]` and `mitigation_coverage`** — the covered half is
  the smaller and more informative one: a tagged control exists on that
  component, so a draft there is a tuning case rather than a gap case.
  `tag_caveat` carries the projector's own `control_tagging` counts so
  "uncovered" can never be read as "no control exists".
- **Generation consumes only those three.** 255 near-generic M-IDs across 58
  nodes is not a pack-size problem; it is a problem with what the model is told
  to reason about.

Recorded explicitly: breadth is a proxy for specificity, **not** for
detectability. M1015 *Active Directory Configuration* is narrow (15 techniques)
but is a configuration posture, not a sensor. `mitigation_focus[]` narrows the
prompt; it never argues a detection should exist. The fields that do argue that
were already on the §1.4 list — `detecting_controls`, `detection_capability`,
`controls_in_play` — and unlike mitigations they are per-component and
per-flow. Mitigation data is a preventive-control taxonomy; using it to justify
a detection is a category borrow.

## Contract tests added to §7

Deterministic ordering with the `T1190` case as the worked example; an empty
focus list is a normal outcome and raises no warning; the generation input
contains the three derived fields and neither raw list while the persisted pack
contains all five; the 7 covered mitigations each land in
`mitigations_covered[]` with the tag caveat reproduced.

## Still open

Six contract issues raised in the same review are untouched by this edit and
remain open against N1: exports use `actor_attack_id` and `model` where §4.1
says `actor_attck_id` and `provider` (and no `provider` key exists to read);
§4.2's legacy identity cannot produce equal graph-only and seed-only keys;
the graph's `state_check`/`state_note` pair joins the seed's combined string
exactly, on an em dash, for all 58 nodes; `component_bound` needs the map
supplied and joined, not merely hashed; and §1.1/§7 assert repeat counts the
Scattered Spider fixture does not contain — no `(technique, component)` pair
repeats within any path, so the within-path identity rule currently has no
test.
