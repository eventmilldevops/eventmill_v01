# One ATT&CK taxonomy across both report tools

**Date:** 2026-09-16
**Branch:** `llm_5`
**Scope:** `framework/reference_data/mitre_attack.py`, both report plugins,
the analyzer's output schema and README
**Status:** built and mutation-checked (21 mutations, all caught).
Suite **1475 → 1503**. **Needs a live run** — this changes prompts in *both*
tools.

The 154-page live run produced an analyzer summary whose ATT&CK table read
`Defense Evasion | T1027`, and cited "MITRE ATT&CK Framework (v14+)" as a
source. The ingester reconciled the identical retired tactic correctly on the
same document the same day. One report, two tools, two taxonomies — and the
analyzer's export is the one an analyst opens.

*(Operator decision, 2026-09-16: reconcile **and** ground, with the reconciled
list surfacing in both the result and the export.)*

---

## Where the v14 came from

**Nowhere in this repository.** `v14` appears in no prompt template, no
reference data and no decoration — it was the model's own.

The cause is structural, and it is the same cause as "Defense Evasion":

- The analyzer passed **no grounding and no reference data** to any LLM call.
  Its only `reference_data` use was `_scan_local_reference_data()`, which scans
  the directory for *report files*.
- Its prompts asked for "MITRE ATT&CK technique IDs" with no version anchor.
- Nothing checked the answer afterwards — `relevant_techniques` was a raw
  `T\d{4}` regex scrape published unvalidated.

So the model answered from its training data, which for every current model
predates v19. Told nothing and checked by nothing, it published the release it
learned.

## The second dead-code path

Chasing that, the ingester turned out to be ungrounded too, for a different
reason:

```python
mitre_data = context.reference_data.get("mitre_attack_enterprise")   # ti:2419
```

The shell populates `reference_data` with **`mitre_techniques`** and
**`mitre_relationships`** (`shell.py:3000-3004`). `mitre_attack_enterprise` was
read in that one place and **written nowhere**. `grounding` was therefore
always `[]`, and every ingester prompt — native and chunked — has gone out with
no ATT&CK anchor since the check was written.

That is not cosmetic. It explains the ingester's own live-run numbers: **4
tactics auto-corrected and 2 flagged for analyst review.** Its correctness has
been coming entirely from the reconciler cleaning up after an ungrounded model,
rather than from the model being told which release to use.

This is the second dead mechanism found in two days, after `PluginExecutor`
(`2026-09-16-manifest-summary-budget.md`). Both are the same shape: something
the code and the docs describe as active that nothing reaches.

## What changed

### Shared, in `framework/reference_data/mitre_attack.py`

Both tools call one implementation rather than keeping two in step.

| Helper | Does |
|---|---|
| `attack_version()` | the release the local lookup was built from — `19.2` |
| `attack_grounding()` | names the release, lists the valid **enterprise** tactics, and states that *Defense Evasion* was retired and split into Stealth and Defense Impairment |
| `reconcile_technique_ids()` | validate, remap retired ids (curated map, **never guessed**), enrich with official names and v19 tactics |

`attack_grounding()` returns **empty** when no lookup has been built — claiming
a version we cannot check would be worse than saying nothing. It omits the
ICS-only tactics, which are real v19 tactics but inviting their use in a prompt
about an enterprise threat report.

`reconcile_technique_ids()` is deliberately the **narrow** half of what the
ingester's reconciler does: no attack graph, no tactic-role assignment. It is
what a tool that scrapes ids from prose needs, and nothing more.

### threat_report_analyzer

- All three prompt templates carry an `ATT&CK REFERENCE:` block, on all four
  call sites (whole-report native, single-pass, section, synthesis).
- `relevant_techniques` is reconciled. **Its shape is unchanged** — still a
  list of id strings — but the ids are the reconciled ones, so a retired id
  reported in the prose appears here as its successor.
- `attack_techniques[]` and `attack_version` added to the result and declared
  in the output schema.
- The exported `.md` gains a checked table between the provenance header and
  the model's prose:

```
## ATT&CK techniques (reconciled against v19.2)

| Technique | Name | Tactics |
| T1027 | Obfuscated Files or Information | Stealth |
| T9999 | *not in ATT&CK - treat as an unverified reference* | — |

> 1 id(s) are not in ATT&CK v19.2 and could not be resolved
```

An id ATT&CK does not know is **listed and marked**, not dropped and not
presented as fact. No techniques means no block — an empty table would imply
the report named none.

### threat_intel_ingester

The dead `reference_data` key is replaced by `attack_grounding()`, which reads
the lookup directly and depends on no context key.

## What was deliberately not done

**The analyzer does not build attack paths.** The ingester produces the
reconciled `attack_graph`, and `attack_path_visualizer` and
`adversary_path_projector` consume it. A second, prose-derived path
representation in the analyzer would be unreconciled by construction — the
exact divergence this change exists to remove. These two tools have already
drifted once by keeping separate PDF implementations; repeating it on taxonomy
would be worse, because taxonomy is what the downstream consumers key on.

**Prose is not rewritten.** Narrative text cannot be safely edited after the
fact. Grounding is what makes the prose right; the export block is what
guarantees the file carries one list that was checked regardless.

## Verification

21 mutations, all caught — **five survived the first attempt**, all the same
lesson this project keeps relearning, that a fixture which never reaches a code
path proves nothing about it:

- The **native document** path was ungrounded-testable: the stub's
  `supports_native_document` returned False, so every test took the chunked
  path. That is the path the 154-page run actually used.
- The **section** and **synthesis** calls were never made, because every
  fixture produced a single chunk and took the whole-report branch. A long
  report makes those calls sixteen times.
- An unknown id could be presented as fact: the test asserted "not in ATT&CK"
  appeared *somewhere* in the block, which the footnote satisfied even when the
  row did not. Now asserted on the row.
- `self._reconciled = None` was unfalsifiable, because the field is reassigned
  on every run that reaches reconciliation. Now driven by a run that returns
  **before** reconciliation, which is the case the reset exists for.

One mutation was **retired rather than fixed**: removing the `ATT&CK
REFERENCE:` label while keeping the `{attack_grounding}` slot changes nothing —
the grounding text is self-describing. The real defect is the *slot*
disappearing, which `str.format()` ignores in silence, and that is what is
tested now.

## Not verified

- **No live run.** This changes prompts in both tools, which is the class of
  change every live-only finding in this project has come from. The run that
  validates it must cover both, and the analyzer's must be long enough to
  exercise the section and synthesis prompts — the 154-page report went native
  as a whole document and made neither call.
- **Whether grounding reduces the correction load.** The expectation is that
  the ingester needs fewer than its four auto-corrections and two analyst flags
  now that the model is told the release. That is a hypothesis until measured.
- `relevant_techniques` can now differ from the ids in the prose above it, when
  a retired id was remapped. That is intended and documented, but no consumer
  has been checked against it beyond the tests.

## Unrelated, and now characterised

`adversary_path_projector`'s run-group ordering flake reproduces at roughly
**1 run in 8** of its own test file, **on clean `HEAD` as well as on this
branch** — verified by stashing. So it is not caused by this work. The trigger
the earlier note could not identify appears to be a **timestamp collision**:
`created_at` values equal when two run records are built inside one clock tick,
at which point the sort at `tool.py:4137-4139` degenerates to `run_index` and
interleaves batches. Not fixed here.
