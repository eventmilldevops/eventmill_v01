# 2026-09-23 — Parameters stay parameters

The Opus run on `fb708dc` — 9 nodes, two calls, 9/9, nothing rejected — is the
first output of this plugin good enough to hand a detection engineer as a
starting guide. This entry records what confirms that and the four defects it
exposed, all of them in the machine-readable fields rather than in the drafts.

## What the run confirms

| Check | Result |
|---|---|
| Invented field names | **0 of 13 citations** |
| Derived indicators | **all five used**, eight times |
| `caveats` / `review_flags` split | clean; flags all `{code, message}`, no `UNCODED` |
| Attribution | *"Generation model: claude-opus-5; the path was projected by gemini-3.1-pro-preview"* |

The strongest evidence is one draft. The 09-20 T1210 draft placed the actor
"from web console" and alerted on `client_ip NOT IN known_web_console_ips` — a
rule that could not fire on its own scenario, and the finding that started this
work. This run's T1210 on the warehouse keys on a `client_addr` **"present but
outside the approved web console egress set"** together with audited statements
in the same session, names the allowlist as the false-positive driver, and asks
for a release cycle of baseline first. Same technique, same kind of node, done
correctly.

The Vault draft goes further and reasons about the null trap explicitly: *"an
absent identity field cannot be used as the trigger — the logic keys on
rejected-status probing and on present display names whose behaviour
deviates."* The prompt rule is being understood, not merely obeyed.

## Prose in the parameter fields

Across three vendors, 4 of 19 `thresholds` entries arrived as sentences, and
one `join_keys` entry was a whole clause:

```
"runs_per_principal_per_window": "proposed starting point: alert on the first event; …"
"join_keys": ["approximate temporal join only; no shared identifier exists …"]
```

This is the third time the same thing has happened, after `limitations` and
`review_flags`: a model with something worth saying says it in whichever field
is nearest, and the field stops being parseable. The content is good — "no
shared identifier exists" is a real and useful answer about a join — so each
machine field now has a prose sibling and the text is **moved, not discarded**.
`threshold_notes` keeps each note under its parameter's name; `join_notes`
keeps what the draft said about the join.

## It was also corrupting the derived kind

The run's single `LOGIC_KIND_CORRECTED` was **wrong**. The T1078 draft is a
plain `WHERE workflow_changed_and_run_by_same_actor = true` — a `single_event`.
It was rewritten to `threshold` because `thresholds` was non-empty, and the
entry that made it non-empty reads *"alert on the first event"*. Only numeric
thresholds count now.

Relocating the prose then exposed the mirror-image defect in the test replay:
stripping the sentence out of `join_keys` left the T1059 draft with a window,
no keys and no numeric threshold, so a genuine two-source temporal correlation
derived as `threshold`. More than one source over a window is now a
correlation whether or not a key is named. **Relocating an explanation must
never change what the record claims.**

## `LOGIC_KIND_AMBIGUOUS` retired

It fired on **eight of nine drafts**. A flag at that rate tells a reader
nothing, and all it reported was that the declared kind was kept — which is the
default everywhere else. The guard remains: a draft declaring `threshold` or
`correlation` on an ambiguous shape still keeps its answer, silently.

## Changes

- `generation.py` — `numeric_threshold`, `has_numeric_threshold`,
  `is_field_name`, `_separate_prose_from_parameters`. `derive_kind` takes a
  source count and counts only numeric thresholds.
  `LOGIC_KIND_AMBIGUOUS` removed from the catalogue. Prompt and `DRAFT_EXAMPLE`
  gain the two notes fields and the rules for both.
- `schemas/detection_draft.schema.json` — `thresholds` values are numbers,
  `join_keys` entries carry no whitespace, `threshold_notes` and `join_notes`
  added, retired code removed from the enum.
- Spec — a *Parameters stay parameters* section and the revised derivation.

Replayed against the run: the false correction is gone and the draft stays
`single_event`; the prose join key moves to `join_notes` while the draft stays
`correlation`; the genuine numeric thresholds and their keys are untouched.

## Not done

Two defects in the Opus output are unaddressed and neither is caught by
anything. One draft emitted a stray `" catalogue_status"` key — the correct
name with a leading space — alongside the real one, which passed because the
real one is also present. One draft omitted `grounding.limitations` entirely;
`grounding` is not a required block, so nothing noticed.

No live run since these changes.

## Documentation

The plugin README gains two sections. *Keeping a generated record honest* sets
out the three mechanisms and, more importantly, the line between them: a
**rejection** needs a comparison of two values both present in the record; a
**derivation** is for what the record's shape determines better than its label;
everything requiring inference is a **flag**, phrased as a question, that never
blocks. It also records the relocation pattern — four fields now, from
`limitations` through `join_notes` — and the fact that the checks themselves
have needed correcting four times, which is the argument for that line.

*Descriptors: a language, not a vocabulary* explains how the long snake_case
names are built: each compresses a complete proposition into one token,
readable as a sentence with the articles removed, deliberately long because the
reader is deciding what to collect. It separates the **authored half** (36
sources, 38 derived indicators, 59 enrichment descriptors, versioned with the
library) from the **coined half** (aliases, threshold names and caveats, minted
per run and unenumerable by construction), and references
`framework/reference_data/telemetry_descriptor_glossary.md` as a reading primer
for a language whose grammar is fixed and whose lexicon is open — never as a
controlled vocabulary, and never complete.

## Tests

19 new cases; 293 in the plugin, 1840 overall.
