# A readable digest, and G1 grounding: the assessment tuple

**Date:** 2026-09-20
**Branch:** `llm_5`
**Scope:** code. `plugins/threat_modeling/attack_path_detection_designer/` —
new `grounding.py`, `normalization.py` (digest, grounding pass), `tool.py`
(`digest` action, bounded summary), `schemas/input.schema.json`, 13 tests.
**Status:** built. Suite **1668 → 1681**. G1's deterministic half only: no
prompt, no model call, no workbook.

## Why the digest exists

The operator's reaction to the pack was that it is "too long for a SOC analyst
or detection engineer to comprehend". Measured on the 13-node Claims Portal
pair: ~187,000 characters, of which **58% is `provenance_by_field`** and 1% is
the inventory. The pack is not verbose about the attack; it carries an audit
trail for every field of every node, which is what makes a later draft
defensible and what nobody reads in bulk.

So the pack stays machine-facing — the operator confirmed that middle machine
layers are fine — and a `digest` action renders the same run as three lines
per node:

```text
9 nodes, pair verified, 0 conflict(s), flow map same_map. component_bound 9.
scm-to-vault  1  T1059 Command and Scripting Interpreter  ci_runner
  component_bound | ubuntu/docker/github-actions-runner | monitoring none | state gap | multistep_access=true ?
  focus: M1033 Limit Software Installation (17), M1045 Code Signing (22)
```

It is a troubleshooting aid, not the deliverable — the workbook of drafts is
still G1's output. It never contains the pack, and its summary cuts on a node
boundary with a stated remainder, because `summarize_for_llm` truncates from
the end and a half-rendered node is worse than an honest count.

## G1 grounding (designer plan §4 and the §5 tuple)

New plugin-local `grounding.py`, loaded by file location the way
`normalization.py` is. Every node now carries:

- **`assessment`** — the versioned, named tuple: `actor_evidence` and
  `multistep_access`, each with value, reason codes, basis and a warning flag.
  A named mapping, never a positional array, so a later element cannot shift
  what the existing two mean.
- **`procedure_evidence[]`** — up to three local procedure examples, the
  actor's own first, each with source id, a content hash, and an explicit
  statement that the ATT&CK link is an *index reference* rather than a
  recovered report citation. The local corpus has no report URLs and the draft
  must not imply otherwise.

The export's `actor_support` is untouched. It answers "is this technique
documented for the actor"; the tuple's `actor_evidence` answers "is this
technique *against this target class* established". They may legitimately
disagree, which §4 of the designer plan requires.

## The digest immediately found a defect

Rendered for a person, the first run read `multistep_access=true ?` on **every
node**. `access_source: model` had been treated as a trigger, and the
projector sets it on all 43 nodes of the corpus, so the element was true 43 of
43 — a constant, not an assessment, and the same failure this repository
already recorded for an agreement grade that could not discriminate.

`access_source` is now a **qualifier** recorded on the element rather than a
trigger. The value comes from what actually varies: the nine inherited state
gaps and the one undeclared transition. The distribution is now **10 true, 33
false**, and a test asserts those counts so the element cannot silently become
constant again.

That is the digest paying for itself before it was even documented.

## Recorded, not hidden: `actor_evidence` is true 43 of 43

The same check shows `actor_evidence` true on every node, and this one is
**correct by construction**: the projector only builds a path from techniques
already mapped to the actor, so re-checking the mapping locally re-derives an
upstream constraint — exactly what §1.4b found when it looked for an actor
filter on mitigations.

It is kept because the tuple requires it on every node and because a false
would be a real signal (it would mean the projector used an unmapped
technique, which a test now guards). The judgment that actually bites —
technique against *target class*, "valid accounts against VPNs does not
document Kafka service credentials" — needs reasoning the local corpus cannot
supply, and belongs to generation. Grounding sets the floor, never the ceiling,
and the docstring says so.

## Verified, and not

- 158 plugin tests (145 → 158), full suite 1681 passing.
- Both tuple distributions are asserted, not assumed: 10/33 for
  `multistep_access`, 43 true for `actor_evidence`, nine gap nodes always true.
- The digest is 2,160 characters for a 9-node pair, and a 60-node synthetic
  case cuts on a node boundary inside the budget.
- **Not built, and next:** the telemetry reference library, the draft schema,
  the prompt, batching, the coverage ledger and the workbook renderer.
- **No model call has been made by this plugin yet.**
- `ruff`, `black` and `mypy` are not installed in this environment.
