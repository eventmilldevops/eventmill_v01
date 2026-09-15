# Change Log — a retry beats the partial it replaced, and no sighting is dropped

**Date:** 2026-09-15
**Branch:** `llm_5`
**Plan:** `docs/specs/report_processing_integrity.md` **Stage 2.1 + 2.2**
**Scope:** `plugins/log_analysis/threat_intel_ingester/` (`ti`)
**Status:** implemented. Goal B — *evidence the model produced is never
destroyed deterministically*.

Landed as one change set because both steps rewrite
`_merge_llm_chunk_results`'s contract; done separately, the merge gets written
twice.

---

## Defect 1 — the partial won its own retry

`_merge_llm_chunk_results` is first-wins on `(ioc_type, value.lower())`. The
native loop appended a truncated partial to `native_batch_results` at
`ti:1947`, *then* pushed the bisected halves onto `pending` at `ti:1971`, and
`chunk_results` was seeded from `native_batch_results` at `ti:2048`. So the
partial sat ahead of its own retry in merge order and supplied the answer.

This is the one finding in the parent review whose behaviour is the **opposite
of what the logs say**. The log line reports the retry re-running those pages
and succeeding; the merged record came from the reply that was cut off.

### Supersession is by page-range containment, not by label

`PageRange.label` is derived from the page numbers
(`framework/documents/profile.py:170`), so bisecting `p1-4` yields `p1-2` and
`p3-4` and **no child ever shares its parent's label**. Matching on labels
would never fire. `_mark_superseded()` instead marks a truncated partial
replaced once the attempts after it cover every page it covered, walking the
list in reverse so a child that was itself replaced counts as covered through
its own successors.

### The cannot-split fall-through needed it too

Not in the plan's original write-up, and found by reading `ti:1976-1982`. When
a truncated batch cannot be bisected — a single page, or an exhausted call
budget — its pages go to `failed_pages` for the chunked text path **while its
partial stays in `native_batch_results`**. So the partial beat the chunked
re-read of the same pages, by the same first-wins rule, through a different
door.

`_mark_superseded` takes the set of pages the chunked path re-read and treats
it as coverage, which closes both doors with one rule. That is the reason to
prefer containment over special-casing the bisect: there were two paths, not
one.

Supersession is resolved in `execute`, before the merge, not inside it — the
page bookkeeping lives out there, and the merge stays a pure function of what
it is handed.

## Defect 2 — every later sighting of an entity was discarded

`(ioc_type, value)` and `(technique_id, tactic)` are **entity** identities, not
**evidence** identities. Several procedures share one technique; one indicator
carries several roles. First-wins threw away every report after the first.

### The shape, chosen to break no consumer

- The canonical scalars stay **first-wins**, so the top level every downstream
  reader sees is byte-for-byte what it was.
- Each merged indicator and technique role carries
  `occurrences: [{batch_label, attempt_id, page_start, page_end, context,
  superseded}]` — every report, in merge order.
- When two *standing* reports disagree on a scalar, the entity gets
  `conflicts: [{field, canonical, reported, batch_label, attempt_id}]` and the
  run goes `partial`.

**Conflicts are not auto-resolved, and specifically not by taking the highest
confidence.** A later correction and a lower-confidence restatement are not
distinguishable by value. The first reading stays canonical, every reading is
recorded, and the reader decides. A test asserts the low-then-high case keeps
`low` canonical, so that nobody later "fixes" this into a max().

A **superseded** result contributes its occurrence for the audit trail and
nothing else: it sets no canonical value and raises no conflict, because the
attempt that replaced it is the answer. Without that exclusion, every
successful bisect would manufacture a conflict against its own parent.

### What is *not* being built

The external review proposed source hashes, spans and image regions. That is an
evidence graph, it is Stage 4 territory, and it would break every downstream
consumer at once. Declined.

## The merge is two passes, and that is the whole fix

The first implementation iterated results in arrival order with a
`superseded` check inside. It still failed: the superseded partial reached the
canonical record *first*, created it, and the retry then folded in behind it as
an occurrence — and raised a conflict against the value it was supposed to
replace. Six tests caught it.

Results that still stand now establish the canonical record; superseded
partials are folded in afterwards. A single pass in arrival order **is** the
defect, restated.

## Evidence the retry did not restate is kept, not dropped

Skipping superseded results wholesale would destroy exactly what this stage
exists to protect. An entity reported *only* by a superseded partial is
retained and flagged `recovered_from_partial: true`, and the run says so:

> `RECOVERED FROM A PARTIAL REPLY: N record(s) survive only from a batch whose
> reply was cut off and were not restated by the attempt that replaced it`

That is honest in both directions — the indicator is not lost, and nobody reads
it as confirmed.

## Stage 1 was not regressed

The plan's note 3 said this is the most likely way Stage 2 breaks Stage 1, and
it named the verdict side: once superseded results stop winning, the assessed
set can no longer be read off the post-merge `refined_iocs` **if** superseded
entities are dropped. They are not dropped — an entity only the partial
reported is retained — so `refined_iocs` still contains every value any attempt
returned a verdict on, and the reconciliation is intact. Asserted directly:
a run with a superseded partial reports `candidates_unassessed == 0`.

## Native batch outcomes now reach the summary

`chunks_attempted` is 0 on a clean native run, which the plan flagged as
leaving native outcomes outside `analysis_status`. The summary now carries
`native_attempts` and `merge_stats.superseded_results` alongside it.

Deliberately **not** reported as a coverage note: a failed native batch falls
back to the chunked path and its candidates *are* assessed there, so calling it
incomplete would be noise. What is worth a note is a record that exists only
because of a cut-off reply, and that is `recovered_from_partial` above.

## Verified

- Full suite: **1372 passed** (1319 before Stage 2; 53 new across 2.0 and
  2.1/2.2, 40 of them here).
- `scripts/validate_schemas.py`: 34 schemas valid, exit 0.
- Schema additions are additive; nothing Stage 2 touches sets
  `additionalProperties: false`. Declared anyway, and a test asserts the
  `conflicts.field` enums match `_IOC_CONFLICT_FIELDS` /
  `_MITRE_CONFLICT_FIELDS` in code, plus that `merge_stats`' declared keys are
  exactly what the merge returns — so the schema cannot drift into a lie.
- `occurrences` and `conflicts` confirmed to survive
  `_reconcile_mitre_mappings`, which rebuilds technique dicts.
- Consumers checked: `attack_path_visualizer`
  (`_build_stages_from_threat_intel`) and `adversary_path_projector` both read
  named keys through `.get()` and never enumerate or strictly validate, so the
  added fields pass through them untouched.
- **Mutation-checked.** Five mutations, all caught:

  | Mutation | Tests that failed |
  |---|---|
  | merge in arrival order instead of two passes | 8 |
  | supersede by label equality instead of containment | 7 |
  | ignore the chunked re-read as coverage | 2 |
  | drop superseded results entirely | 4 |
  | never record a conflict | 2 |

## Not verified

- **No live model requests.** Every conclusion is about control flow, which is
  exactly the basis Stage 1 was signed off on before a live run found three
  more defects. One live run against the 154-page report covers the whole of
  Stage 2 before any of it is called done.
- The truncation mock returns a body that parses while the transport reports
  `MAX_TOKENS`. That is a real shape, but it is not the same as a body cut
  mid-record and repaired by `_repair_truncated_json`; the repair path is
  exercised by `test_truncation.py`, not here.
- `occurrences` is persisted with the artifact, so exports grow with the number
  of batches. Unmeasured on a real 154-page run.
- `ruff` and `black` are still not installed in the active interpreter.
