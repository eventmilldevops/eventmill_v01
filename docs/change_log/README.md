# Change log

One file per significant change, named `YYYY-MM-DD-short-slug.md`. Dates are
UTC, which is why an entry can be dated a day ahead of the local clock it was
written on.

Each entry says what changed, **why it was the right call**, and what was
verified — including what was *not* run. They are written to be read months
later by someone who has lost the context, so an entry that only lists files is
not finished.

Read newest-first. This index covers the current thread only; older entries are
self-describing and listed by filename.

## Report processing integrity — 2026-09-15

Whether a long threat report survives chunking with its evidence intact. Plan:
`docs/specs/report_processing_integrity.md`.

| Date | Entry | What landed |
|---|---|---|
| 09-15 | `2026-09-15-threat-report-analyzer-pdf-alignment.md` | Provider limits out of plugin code; provider refusals no longer downgrade silently; page coverage reported; stamped exports; the plugin's first 18 tests |
| 09-15 | `2026-09-15-chunking-integrity-review.md` | **Review only, no code changed.** Eight findings verified against the tree, four corrections to the external analysis, and the budget-starvation cause it missed |
| 09-15 | `2026-09-15-analyzer-output-budgets.md` | **Stage 1.1.** Every analyzer call was sized *below* the thinking reserve for the level it requested, so thinking could consume the whole budget and return empty text with `ok=True`. Budgets now read the provider manifest. Also corrects the plan's own recommendation: its native `"medium"` was Gemini's default, which would have silently demoted Anthropic |
| 09-15 | `2026-09-15-truncation-is-recorded.md` | **Stage 1.2.** Four call sites discarded `LLMResponse.truncated`; the ingester's text path also dropped the bracket-repair flag. Both signals are read now, and the affected chunk or page range is named |
| 09-15 | `2026-09-15-section-status-and-substitution.md` | **Stage 1.3.** Raw pypdf text was initialised into `summary`, so a failed section was persisted to a file named `.summary.md` and fed to synthesis as though a model had written it. Sections now carry `complete/partial/empty/failed`, and substitutions are labelled everywhere they travel |
| 09-15 | `2026-09-15-analysis-status.md` | **Stage 1.4.** One `analysis_status` per run, stated *first* — `summarize_for_llm` is capped at 2000 characters and truncates from the end, so the warnings were the part being cut |
| 09-15 | `2026-09-15-chunk-failures-and-rejection.md` | **Stage 1.5.** `if not refined_iocs:` reinstated the exact indicators the model had rejected, as a regex baseline. Split from "refinement never ran". Per-chunk failures also reach the result now, closing a Goal A gap 1.4 left open |
| 09-15 | `2026-09-15-persisted-provenance-and-page-outcomes.md` | **Stages 1.6 + 1.7.** Coverage and status are written into the exports, not just the result; an unreadable page no longer counts as read, and a blank one is not a defect. **Stage 1 complete** |
| 09-15 | `2026-09-15-unassessed-candidates-and-units.md` | **Post-Stage-1, found by running the tools.** The rejection note counted verdicts returned and called them "all candidates"; coverage counted lines and named them pages; the analyzer's export stated no page count on the native path. Three Goal A failures a deterministic review could not catch |
| 09-15 | `2026-09-15-submitted-baseline.md` | **Stage 2.0.** The reconciliation is measured against what actually reached a prompt, with `candidates_not_submitted` reported separately from the model's silence. **Changes no output today** — the defect it was written against turned out to be unreachable, and the entry says so; kept as the invariant tripwire 2.5 needs |
| 09-15 | `2026-09-15-retry-supersedes-partial.md` | **Stage 2.1 + 2.2.** A truncated partial beat its own bisected retry in the merge — the one finding whose behaviour was the opposite of what the logs reported — and every sighting of an entity after the first was discarded. Supersession is by page-range containment, canonical scalars stay first-wins, and disagreements are recorded rather than resolved |
| 09-15 | `2026-09-15-stage-2-live-runs.md` | **Stage 2 live runs.** Five runs on Gemini light. Supersession fired on real traffic by both routes, including the cannot-split fall-through — but changed no value, because the model agreed with itself. Found two defects in the 2.1/2.2 code: a dropped false positive took its dissent out of the output, and a MITRE naming variant set whole runs to `partial` |
| 09-15 | `2026-09-15-stage-2-second-half.md` | **Stage 2.3–2.6.** Three more places a *name* cost evidence: a second batch's attack path was dropped because it reused a slug, a second actor was dropped because metadata was taken object-at-a-time, and the analyzer's technique list kept an arbitrary twenty of twenty-five — differently on each identical run. **2.5 is the behavioural one**: candidates and text were split independently and paired by index, so an appendix indicator went out beside the introduction. Built and mutation-checked; **no live run, so Stage 2 is still not signed off** |
| 09-15 | `2026-09-15-report-integrity-results.md` | **Results to date, no new work.** Stage 1 and Stage 2-so-far measured against the plan's three goals: suite 1,177 → 1,380, and **5 of 16 defects were found by running the tools rather than by review or tests** — twice on code that had just passed both. Says plainly what is still unverified |
| 09-16 | `2026-09-16-stage-2-live-run-154-page.md` | **The Stage 2 live run.** Both tools against the 154-page report. Confirmed 2.2 conflicts on genuine material (8, where every previous one came from a fixture built to contradict itself) and 2.4 collecting ~30 actors that were previously dropped. **Found a regression**: 2.4's unbounded attribution narration reached 3,712 characters against a 2,000 contract, putting the IOC counts and the analyst-action line past the cut wherever it is enforced. Carries an inline correction — the first version claimed data was lost, and it was not |
| 09-16 | `2026-09-16-manifest-summary-budget.md` | **`summary_budget` moves to the manifest**, default doubled to 4000 and set to 8000 for both report tools. A tool that reads a 154-page report has more to say than one that lists files. Records that **`PluginExecutor` is instantiated nowhere** — the cap, its timeout and its input validation are a contract nothing reaches at runtime |
| 09-16 | `2026-09-16-one-attack-taxonomy.md` | **Both report tools answer to ATT&CK v19.2.** The analyzer had no MITRE mapping at all — a raw regex scrape of model prose, ungrounded and unvalidated, which published `Defense Evasion \| T1027` and cited "v14+". Now grounded *and* reconciled, with a checked technique table in the export. **Live-confirmed for the analyzer**, including the curated-map remap `T1562.001 → T1685` firing on real traffic. Found a second dead mechanism: the ingester's grounding read a reference_data key nothing writes |
| 09-16 | `2026-09-16-unknown-flags-and-afc.md` | **A mistyped flag is named.** `--ignore_cap` for `--ignore_caps` was accepted in silence and the run did the opposite of what was asked. Warns and lists the tool's real arguments — deliberately no correction and no guess, with a mutation that fails if anyone adds one. Also silences the per-run AFC notice, which described a code path that ran once and did nothing |

**Stage 1 is complete.** Goal A — *incomplete work is never reported as
complete* — holds for both plugins. Suite went 1177 → 1319.

**Stage 2 is code-complete and partly live-verified.** 2.0-2.2 were verified
on Gemini light; 2.3, 2.4 and 2.6 were confirmed by the 154-page run on 09-16.
Suite 1319 → 1513. **Results through 2.2 are consolidated in
`2026-09-15-report-integrity-results.md`.**

**Three things remain unrun, and each is named rather than assumed:**

1. **Whether 2.5 executed at all.** It rewrote only the chunked text path. The
   154-page run was batched, but `native_batched` and `chunked_text` are both
   batched and only the second calls `_build_chunk_units`. A `[CHUNK] n/m done`
   log line settles it; `ingestion_plan` is on the ToolResult and not in the
   persisted artifact, so the log is the only place to look.
2. **The ingester's ATT&CK grounding.** Baseline to beat, same document:
   4 tactic auto-corrections and 2 analyst flags.
3. **The analyzer's section and synthesis prompts.** A PDF that succeeds
   natively sets `chunk_count = 1` and skips both, so all three 154-page runs
   left them unexercised while looking complete. A non-PDF report reaches them.

**The live runs found two more defects, both in the code that had just passed a
green suite and a mutation check** (last row above). That is twice in two
stages: Stage 1 was signed off on control flow and a live run found three, and
Stage 2's deterministic verification missed two. The lesson is holding — run
the tools. What remains unmeasured is scale: these ran against a 3-page probe
and a synthetic text fixture, not the 154-page report, and against one provider
of the three that are keyed.

**The seven steps were verified on control flow alone, and the first live run
found three more Goal A failures** (last row above). A deterministic review is
necessary and not sufficient: **run the tools before calling a stage done.**
That run also gave Stage 3.1 its first calibration point — a 154-page document
estimated at 2105s finished in ~260s, 8.1x pessimistic.

**Next:** the plan's recommended stopping point is here, before Stage 2
(*evidence the model produced is never destroyed* — the first-wins merge, the
partial that beats its own successful retry, `path_id` collisions across
batches). Stage 3 stays hard-gated on the Appendix A fixture set.

Two items carried out of Stage 1 and still open: native batch outcomes sit
outside `analysis_status` (Stage 2.1's subject), and the
`adversary_path_projector` run-group ordering defect diagnosed in
`2026-09-15-analysis-status.md`, which is unrelated to this plan.

## Multi-provider LLM support — 2026-09-13/14

The thread that took Event Mill from one vendor to three. Plans:
`docs/specs/multi_provider_llm_clients.md` (the framework) and
`docs/specs/projector_three_vendor_run.md` (the demonstration).

| Date | Entry | What landed |
|---|---|---|
| 09-13 | `provider-seam-stage-0.md` | The seam pinned with 7 `xfail(strict=True)` tests |
| 09-13 | `provider-seam-stage-1.md` | `GeminiClient` extracted; dispatcher made vendor-free |
| 09-13 | `multi-vendor-concurrency-correction.md` | **Premise corrected**: concurrent providers and per-module override were requirements, not out of scope. Only automatic failover is forbidden |
| 09-13 | `three-vendor-secret-wiring.md` | All four LLM keys reach the container; unadopted vendors hold `placeholder` |
| 09-13 | `three-provider-connectivity-probe.md` | `probe()` — auth and ping, reported separately |
| 09-13 | `three-provider-clients.md` | Anthropic and OpenAI clients; all six tier clients green live |
| 09-14 | `llm-sdks-to-current-stable.md` | Every LLM SDK pinned to current stable with a major ceiling |
| 09-14 | `provider-tier-rekey.md` | `_clients` keyed by `(provider_id, tier)`; cross-vendor fallback forbidden in code |
| 09-14 | `cloud-run-three-provider-verification.md` | All six tier clients verified **in the container** |
| 09-14 | `connect-binds-every-provider.md` | `connect` binds every configured provider, not just Gemini |
| 09-14 | `use-provider-per-module.md` | `use <provider> [for <tool>]` — the runtime A/B control |
| 09-14 | `run-record-attribution.md` | Projector run record names the vendor that served it; `prompt_sha256` (schema v4) |
| 09-14 | `all-providers-configured-by-default.md` | `EVENTMILL_LLM_PROVIDERS` defaults to all three on every deploy path |
| 09-14 | `group-summary-provider-dimension.md` | Recurrence per provider, agreement across them |

**Next:** the live three-vendor run — Stage E of
`docs/specs/projector_three_vendor_run.md`. Nothing in the code blocks it.

## Attack path detection guidance — 2026-09-16

Turning projected attack paths into per-node detection drafts. Plans:
`docs/specs/attack_path_detection_designer.md` (the workbook and draft format),
`docs/specs/attack_path_detection_normalization.md` (the node context the
workbook is generated from).

| Date | Entry | What landed |
|---|---|---|
| 09-17 | `2026-09-17-code-identity-on-cloud-run.md` | A container has no `.git`, so every Cloud Run export carried an empty `git_sha` — and the manifest version deliberately does not move, leaving those exports with no code identity at all. The deploy now forwards the image tag it already computes, and `code_id_source` distinguishes unavailable from unpopulated. Suite 1519 → 1523 |
| 09-16 | `2026-09-16-component-bound-fixture.md` | A live projection against the example flow map produced the first `component_bound` fixture — 2 paths, 10 nodes, every node binding to a component with technologies, authentication and zone — and live-confirmed the provenance block, including real provider attribution |
| 09-16 | `2026-09-16-projector-export-provenance.md` | Both projector exports now carry a `provenance` block — `run_id`, flow map and prompt hashes, ATT&CK release, actor ID, tool version, provider — minted once so the graph, the seed and the run record share it. Previously a graph and a seed could only be paired by filename stamp. Additive; the visualizer is unaffected. Suite 1513 → 1519 |
| 09-16 | `2026-09-16-attack-path-normalization-plan.md` | **Planning only.** The designer plan's normalization was reviewed against the real exports: the second fixture repeats a technique three times inside one path, the exports carry no `run_id` or flow-map hash to join on, the scenario seed is not a subset of the graph, and `technologies`/`authentication`/`zone` exist in no export. Normalization becomes a deterministic provider-free `normalize_paths` action, and the projector's Phase 4 `normalize_flow_map` becomes part of the same seam |

## Earlier threads

- **`adversary_path_projector`** (09-09 to 09-12): phases 1, 2, 3, 3b and 3c,
  the live-run findings, run records, step state, the run-group summary and the
  group report. Phase 4 (`normalize_flow_map`, the plugin README, the manifest
  bump to 0.3.0) is still outstanding.
- **Document handling** (09-04 to 09-06): the profiler, page-range batching,
  and truncation-aware batching.
- **Routing and discovery** (09-05 to 09-08): the `also_useful_in` manifest
  field, pillar-scoped listings, pillar adjacency removed, expansion mode.
- **Model interchange** (09-12): the light tier moved to Gemini 3.8 Flash.
