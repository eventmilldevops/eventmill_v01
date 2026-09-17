# Normalization plan for attack-path detection guidance

**Date:** 2026-09-16
**Branch:** `llm_5`
**Scope:** `docs/specs/attack_path_detection_normalization.md` (new),
a pointer in section 3 and a revision note in section 10 of
`docs/specs/attack_path_detection_designer.md`
**Status:** planning only. No plugin code, no schema and no export was
changed. No LLM run was performed.

The detection designer plan proposes generating one detection draft per node
of a projected attack path. Everything it generates rests on section 3's
normalization step, and that step was reviewed against the actual projector
exports and reference data rather than against the plan's own description of
them. Five things did not hold.

---

## What the review found

**The plan was written against one export pair; there are two.**
`20260915_204815` is Scattered Spider (G1015) against "Application B" — a
different actor and a different estate, in a file whose top-level shape is
indistinguishable from the APT29 one. It has 24 nodes across paths of 7, 7 and
10, and its longest path visits `T1078` three times, `T1552.001` three times
and `oracle_int` on three consecutive steps. So `(technique, component)`
repeats *within* a single path, not just across paths, and every "15 nodes" and
"three calls, one per five-step path" constant in the designer plan is an
artefact of the single fixture it was written against.

**The exports carry nothing that identifies them.**
`_write_projection_artifacts` writes seven top-level keys. `run_id`,
`flow_map_sha256`, `attack_version`, prompt hash and provider attribution all
exist in `run_context` a few hundred lines earlier and none of them reaches the
file. The designer plan requires a verified graph/seed pair and recorded
flow-map provenance, and then rules out the only discriminator the files
actually have — "a matching application name is not proof". Both statements are
right; together they mean the join cannot be done at all today. The fix is an
additive `provenance` block on the export, which is the one item in the new
plan that touches shipped code.

**The scenario seed is not a lossy subset of the graph.** The plan says it
loses the component ID and flattens the transition, implying a subset. It also
*adds* `access_source`, `blocking_controls`, `detecting_controls`,
`success_indicators`, and a scenario-level control catalogue carrying
`detection_capability` and `bypass_difficulty` — none of which the graph's
per-step `controls_in_play` has. A merge that prefers the graph throughout
drops precisely the fields that are about detection. Normalization has to be a
declared union with a per-field precedence table.

**The node context omits the fields detection guidance is built from.**
`uncovered_mitigations` is the strongest argument a node has for needing a
detection at all — it names the ATT&CK mitigations this estate does not
implement, so detection has to carry the weight. It was not in the context
struct, and neither were `detecting_controls`, `detection_capability`,
`success_indicators`, `access_source`, or the transition's protocol, which is
what actually chooses a sensor.

**Three declared context fields exist in no export.** `technologies`,
`authentication` and `zone` appear only in the flow map, which the plan lists
as optional. A context pack can therefore pass the plan's Stage 1 gate — same
15 ordered node occurrences from either input — while carrying nothing that
could name a product. That is why the new plan grades context completeness per
node (`component_bound` / `asset_named` / `asset_text_only` / `unbound`) and
binds what a draft may claim to its grade, and why the projector's own
outstanding `normalize_flow_map` (its Phase 4) became part of this work rather
than a separate errand.

Also confirmed while checking: `mitre_techniques.json` carries four fields per
technique and `mitre_relationships.json` has no data components, so there is no
local ATT&CK detection reference of any kind. A model asked for detection
guidance will emit `DS####` identifiers from memory and nothing here can check
them — the same shape as the invented `v14` citation in
`2026-09-16-one-attack-taxonomy.md`. The new plan rejects them at validation.
The exports' `Stealth` tactic, by contrast, agrees with the pinned v19.2
lookup and is to be preserved.

## The call

Normalization ships first, as its own deterministic `normalize_paths` action
writing a `detection_context_pack` artifact, with no LLM and no cost. Stages
N1–N4 are provider-free and testable today against both fixtures; the guidance
layer then consumes packs instead of raw exports, which also makes a bad draft
re-examinable against the exact input it was given.

The alternative — finish normalization inside the generation path, as the
designer plan assumed — was rejected because it makes the 24-node fixture
untestable until a provider is configured, and because it leaves the pair-join
and flow-map-binding questions to be settled by a prompt.

## Verified

Both export pairs were parsed and field-diffed node by node; the projector's
export writer, `run_context` and flow-map hash comparison were read in source;
`attack_version` 19.2, the technique record's field set, the `mitigations`
section and the absence of data components were confirmed by loading the
reference files.

Not done: no code written, no tests run (this change adds none), no live
generation. Whether a detection drafted at `asset_named` grade is useful to an
analyst is still an open question that only stage 5 of the designer plan can
answer.
