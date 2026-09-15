# Stage 2.3–2.6 — names stop costing evidence, and prompts pair with their text

**Date:** 2026-09-15
**Branch:** `llm_5`, not pushed.
**Plan:** `docs/specs/report_processing_integrity.md`, Stage 2 steps 2.3–2.6
**Scope:** `plugins/log_analysis/threat_intel_ingester` (`ti`),
`plugins/threat_modeling/threat_report_analyzer` (`tra`)
**Status:** built and mutation-checked against synthetic responses.
**Not signed off** — the single live run Stage 2's acceptance requires has not
been made.

Suite **1,380 → 1,445** (+65). The two report plugins go 324 → 389.
`validate_schemas.py` 34 valid, exit 0.

---

## Line numbers, re-derived at `59dca48`

The plan's table is from `2efb594` and was stale by roughly 350 lines in `ti`.
These are the positions the work actually edited, before this change set added
its own.

| Step | Construct | Plan says | Actual at `59dca48` |
|---|---|---|---|
| 2.3 | `path_id` union | `ti:519-521` | `ti:684-690` |
| 2.4 | `report_metadata` first-wins | `ti:523` | `ti:678-679` |
| 2.4 | attribution scalars on the result | `ti:2246-2258` | `ti:2801-2812` |
| 2.5 | the two independent splits | `ti:1910-1914` | `ti:2303-2308`, paired at `ti:2327-2330` |
| 2.5 | native-failure fallback | `ti:2009-2013` | `ti:2284-2288` |
| 2.5 | type-major candidate order | `ti:270` | `ti:269` |
| 2.6 | the two caps | `tra:1888`, `tra:1893` | `tra:1887`, `tra:1893` |

---

## 2.3 — `path_id` is a slug, not an identity

**The defect.** The union was `if not any(p.get("path_id") == pid for p in
ag_paths)`. Separate model calls coin slugs independently, so two batches
describing unrelated paths can both call theirs `initial-access-to-exfil` — and
the second was dropped entirely, with nothing recorded to say a second existed.

**The change.** Reconciliation is on the step sequence — `(technique_id,
tactic, leads_to)` per step — not on the slug. Two batches that described the
same path merge to one path carrying both `batch_labels`; two batches that
described different paths both survive.

**Operator decision, 2026-09-15: namespace only on collision.** The plan's text
said "prefix each path's id with its batch label before the union", which would
rewrite every id on every run including single-batch ones, and both consumers
render the id. Instead the first path keeps its slug and a colliding,
structurally different path becomes `p11-20:initial-access-to-exfil` with
`original_path_id` recording what the model emitted. `merge_stats.paths_namespaced`
counts it, and is **0 on any run without a collision — which is every
single-batch run.** Nothing consumer-visible moves except in the case the
defect actually occurs.

**A superseded partial contributes on the same terms as anywhere else in 2.2:**
only a path nothing else reported, flagged `recovered_from_partial`. Its
truncated draft of a path its own retry restated is not a second path.

An empty step list is deliberately **not** an identity — every pathless path
would share it, and merging them would lose their descriptions.

**Verified against the consumers before merging** (re-grepped at
`attack_path_visualizer:181-249`, `adversary_path_projector:1851`): both treat
`path_id` as an opaque display and grouping label. `leads_to`,
`convergence_points` and `branch_points` are all technique ids, so namespacing
breaks no cross-reference.

## 2.4 — one report can name two groups

**The defect, and it was worse than the plan recorded.** `report_metadata` was
taken object-at-a-time: `if not report_meta: report_meta = result.get(...)`.
The first batch to fill in *any* field took the whole record — so a batch that
recognised only the title discarded the batch that identified the actor. The
plan described the attribution loss; the field-level loss is the same line.

**The change.** Metadata merges field by field, first non-empty wins. Every
actor and campaign named anywhere is collected into `report_metadata.actors`
and `.campaigns`, each carrying the batch that named it; actors carry the
confidence stated *with that actor*, because attribution confidence is not a
scalar property of a report and a later section qualifying an earlier assertion
is exactly the case this exists for. `attributed_actor`, `campaign_name` and
`attribution_confidence` keep their first value for the consumers that read
them.

Both lists reach the returned result and `summarize_for_llm`, which now names
the actors the scalar cannot — a single-actor line there otherwise reads as the
report's whole attribution.

**Deliberately not an analysis note.** In `ti._analysis_fields` every note
except `NO INDICATORS ACCEPTED` forces `partial` (`ti:838-845`). Two groups in
one report is complete work, not a caveat about it, so this reaches the reader
through `report_metadata` and the summary instead. Adding a second
"note that doesn't count" exclusion would have made the status harder to read,
not easier.

## 2.5 — a candidate is asked about beside the text it came from

**The only step here with a real behavioural change.**

**The defect.** Two independent splits paired by index. `ioc_batches` sliced
`fallback_iocs` fifty at a time; `text_chunks` split `fallback_text` on
paragraph boundaries; chunk *i* sent `ioc_batches[i]` with `text_chunks[i]`.
The orderings have no relationship at all. On the whole-document path the
candidate order is type-major — the regex pass loops `for ioc_type in
ioc_types` at `ti:269` — so the first batch was in practice every IP in the
document, appendix included, sent beside the document's first 6,000 characters.
Past the end of `text_chunks`, the overflow batch went out with **no text at
all**.

**The change.** `_build_chunk_units` builds text units first and takes each
unit's candidates from that unit's pages, so the pairing is true by
construction:

- Contiguous pages are packed into a unit under the character budget.
- A page larger than the whole budget is split by paragraph with candidates
  **re-extracted per piece** — this is the path every non-PDF report takes,
  since a text artifact is a single page and page granularity buys nothing.
- A unit over `_MAX_IOC_PER_CHUNK` splits **within the unit**, every piece
  keeping the same text.
- The unit's page label travels in the prompt, and a jump between
  non-adjacent page ranges is stated, so a section starting at page 30 does not
  read as continuing one that ended at 19.

**Operator decision, 2026-09-15: global dedupe.** A value on pages 3 and 40 is
still submitted once — with the unit whose text contains it, which is the part
that was wrong. Submitting it in each unit would pair it with every context at
the cost of a longer prompt per repeat; that is a cost decision, not a
correctness one, and the single expensive 154-page sign-off run is the reason
not to move cost and correctness in the same change.

**A gap is only a page the run was never asked to cover** — not a blank page
skipped while packing. Calling a blank page "analysed separately" would be a
claim nobody can check.

**Two knock-on changes, both deliberate.**

1. **Chunk results now carry a page range.** Before 2.5 a chunk had
   `page_start: None`, so an indicator found on the chunked path could say
   which chunk saw it and nothing about where in the report it was. Its label
   now reads `chunk 3/8 (pages 12-19)` and its occurrences carry the range.
2. **A chunked result is never superseded by page containment**
   (`_mark_superseded`). Supersession answers "did a later attempt re-read
   these pages", and nothing re-reads a chunk. Without the guard, giving chunks
   a page range would have made a truncated chunk look replaced — by
   `chunked_pages`, which contains its own pages, or by a sibling unit sharing
   its page range because the candidate cap split it, which assessed an
   entirely different set of candidates.

**2.0's invariant is what holds this honest.** `candidates_not_submitted == 0`
is asserted on a pure chunked run, a short single-chunk run, a crowded run
where the cap splits a unit, and a chunked PDF run. It was built in 2.0 as the
tripwire for exactly this rewrite, and it is the half that says the change
gained alignment without losing coverage.

## 2.6 — the analyzer's caps, one of them nondeterministic

**The defect.** `findings[:10]` and `list(set(techniques))[:20]`. Both dropped
in silence — nothing counted the remainder, no note reached `analysis_status`.
The technique cap was worse than lossy: `set` has no ordering, so *which*
twenty ids survived varied between identical runs over identical text. It was
the one place in either report tool where two runs disagreed about what the
report said. And it applied twice — per chunk, then on the cross-chunk union at
`tra:734-735`, **which was `list({...})` as well** and is not mentioned in the
plan.

**The change.** Both lists are order-stable by first appearance, both are
counted, and anything dropped reaches the result as a `LIST TRUNCATED` note
that makes the run `partial`.

**Operator decision, 2026-09-15: raise, keep a bound.** `_MAX_KEY_FINDINGS` 50
and `_MAX_RELEVANT_TECHNIQUES` 200. 10 and 20 fired on ordinary reports; these
are there for a runaway or adversarial summary, not for ordinary work. A cap is
defensible when it is reported, and an unbounded list in the result and the
export is a worse failure than a stated one.

`_dropped` is run state, reset in `_summarize_report` alongside `_truncations`
and `_degradations` — the same tool object summarises many reports in a
session, and a count left over would put one report's note on another's.

---

## Verification

Every step was mutation-checked: the change reverted, the new tests confirmed
to **fail on the defect** rather than merely pass on the fix.

| Step | Mutations | Result |
|---|---|---|
| 2.3 + 2.4 | 16 | all caught |
| 2.5 | 12 | all caught |
| 2.6 | 9 | all caught |

**Four survived the first attempt, and all four were the same lesson** the
Stage 2 write-up already recorded — *a mutation check that only exercises a
helper proves nothing about the path that calls it*:

- Nulling `report_metadata.actors` in the result assembly left the suite green.
  The merge tests drove `_merge_llm_chunk_results`; nothing drove `execute`.
  Fixed with `TestTheResultCarriesWhatTheMergeKept`, which runs a two-chunk
  report end to end.
- Nulling chunk provenance's page range left the suite green: the label was
  built from the unit, so the assertion on the label never touched the
  provenance record. Fixed by asserting the occurrence's `page_start`/`page_end`
  and that each indicator's recorded range contains the page it is on.
- The cross-chunk technique union could go back to `list({...})` unnoticed,
  because the end-to-end fixture only ever produced one chunk and took the
  single-chunk branch. Fixed with a genuinely multi-chunk run.
- `_dropped` failing to reset between runs was invisible because the fixture
  built a fresh tool each time. Fixed by reusing one instance across two runs.

**One mutation was not fixed but deleted.** An empty-value guard in
`_merge_metadata` was unfalsifiable — redundant with the falsy check that
followed it — so the branch was removed rather than left as code no test can
hold. A test that cannot fail is a claim, not a check; so is a line no mutation
can break.

## Not verified

- **No live run.** Stage 2's acceptance requires one run against the 154-page
  Anthropic report covering the whole stage before any change log claims
  completion. **This entry does not claim it.** 2.5 changes what the prompts
  contain, which is precisely the class of change five of the sixteen defects
  so far were only found by running the tools.
- **Still one provider of three.** Anthropic and OpenAI keys are present and
  have not been used for any of this.
- **2.5's cost profile is reasoned, not measured.** Global dedupe keeps the
  candidate count identical; the unit split can produce a different number of
  calls than the old `max(len(ioc_batches), len(text_chunks))`, and repeating a
  unit's text across a cap split adds tokens the old pairing did not spend
  (it sent no text at all there). Neither is measured.
- **Conflict frequency on a genuine report is still unknown**, unchanged from
  the Stage 2 write-up.
- `ruff` and `black` are still not installed in the active interpreter. Added
  Python lines were checked against the 88-column limit by hand; none exceeds
  it. Schema `description` strings do, and are not Python.
- `validate_manifests.py` still reports its 15 pre-existing `'stable'` errors.
  Untouched.

## Files

| File | What |
|---|---|
| `ti/tool.py` | `_path_shape`, `_merge_path`, `_merge_metadata`, `ChunkUnit`, `_pack_pages`, `_build_chunk_units`, `_unit_report_text`; merge body, `_mark_superseded` guard, chunked-path assembly, result assembly, `summarize_for_llm` |
| `ti/schemas/output.schema.json` | `actors`, `campaigns`, `merge_stats.paths_namespaced`, and `attack_graph` — which was undeclared entirely |
| `ti/tests/test_graph_and_attribution.py` | new, 23 tests (2.3, 2.4) |
| `ti/tests/test_chunk_alignment.py` | new, 23 tests (2.5) |
| `ti/tests/test_merge_provenance.py` | the `merge_stats` key set now includes `paths_namespaced` |
| `tra/tool.py` | `_first_seen`, `_cap`, `_MAX_KEY_FINDINGS`, `_MAX_RELEVANT_TECHNIQUES`, `_dropped` run state, both extractors, the cross-chunk union, the note in `_analysis_fields` |
| `tra/schemas/output.schema.json` | `relevant_techniques` and `key_findings` now document their ordering and bound |
| `tra/tests/test_extraction_caps.py` | new, 19 tests (2.6) |
