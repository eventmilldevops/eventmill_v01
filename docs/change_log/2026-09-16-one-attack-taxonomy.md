# One ATT&CK taxonomy across both report tools

**Date:** 2026-09-16
**Branch:** `llm_5`
**Scope:** `framework/reference_data/mitre_attack.py`, both report plugins,
the analyzer's output schema and README
**Status:** built, mutation-checked (21 mutations, all caught), and
**live-confirmed for the analyzer** on the 154-page report, run
`20260916T025734Z`. Suite **1475 → 1503**. The ingester half is still unrun.

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

## Confirmed live — analyzer, run `20260916T025734Z`

The 154-page Anthropic report, `gcp_gemini/gemini-3.1-pro-preview`, native
whole-document, `analysis_status: complete`. **Every claim below was checked
against the lookup rather than read off the output.**

**The reconciled block rendered, and it is correct.** Sixteen techniques. Every
name and tactic pair matches `mitre_techniques.json` exactly, including the two
v19 renames that would betray a stale release — `T1027 → Stealth` and
`T1036.005 Match Legitimate Resource Name or Location`.

**The retired-id remap fired on real traffic for the first time:**

```
| T1685 (reported as T1562.001) | Disable or Modify Tools | Defense Impairment |
> 1 id(s) arrived under a retired number and were remapped to their current one.
```

`T1562.001` is genuinely absent from v19.2, and the resolution came from the
**curated map**, not name matching — the high-confidence path. Before this
change that id would have been published unvalidated, and before the retired-id
work it would have been demoted to "non-ATT&CK" and dropped from every
ATT&CK-keyed view.

**Grounding reached the prose.** The narrative writes "regain **Stealth**",
headers a section "Persistence, Stealth, and Defense Impairment", and titles
its technique list "Relevant MITRE ATT&CK Techniques (v19.2)". No occurrence of
"Defense Evasion" anywhere in the document, and the "(v14+)" citation that
prompted this work is gone.

**The designed discrepancy behaved as designed.** The prose body still says
`T1562.001` where the table says `T1685`. Narrative is not rewritten; the table
is checked and names the difference. A consumer reading the prose rather than
the table still gets the retired id — which is the argument for the table
existing, not against it.

## Not verified

- **The ingester half is unrun.** Its grounding fix has never been near a
  model. Baseline to beat, from the pre-grounding run on the same document:
  **4 tactic auto-corrections and 2 analyst flags.** Whether grounding reduces
  that is a hypothesis until measured.
- **The analyzer's section and synthesis prompts.** A PDF that succeeds
  natively sets `chunk_count = 1` and skips both branches, so all three
  154-page runs left them unexercised while looking complete. Reaching them
  needs a **non-PDF** report (`capec/capec-stix.xml`,
  `mitre/enterprise-attack.json`).
- **The unknown-id path.** All sixteen ids were valid, so
  `*not in ATT&CK - treat as an unverified reference*` has unit coverage only.
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
