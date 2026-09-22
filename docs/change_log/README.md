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

## Attack path detection guidance — 2026-09-16/17

Turning projected attack paths into per-node detection drafts. Plans:
`docs/specs/attack_path_detection_designer.md` (the workbook and draft format),
`docs/specs/attack_path_detection_normalization.md` (the node context the
workbook is generated from, and the active one — it replaces the designer
plan's section 3).

Two entries below are code; four are planning or fixtures. The projector
export pairs these fixtures refer to live **outside the repository**, in
`C:/projects/eventmill_v02/test_data/path_projector/`, so git records neither
them nor their history; the inventory of what each one exercises is §1.1b of
the normalization spec, and the shape of the documents themselves is
`docs/specs/projector_export_shapes.md`.

**The corpus was replaced on 2026-09-17** — four pairs, 43 nodes, one code
revision, three applications (`2026-09-17-projector-corpus-refresh.md`). Counts
in entries below that date are historical; the three pairs they measure are
retired.

**N1 is built** (`2026-09-17-n1-adapters-and-identity.md`, commit `bbd4384`),
and **artifacts are the confirmed input and output route** for the first
version of detection generation (decision 8,
`2026-09-17-artifact-input-route.md`). **N2 is closed**
(`2026-09-19-n2-flow-map-lineage.md`, decision 9): a flow map's hash records
lineage and never refuses a map. **N3 is complete**, built in four slices:
N3a (the flow-map join and the five completeness grades) and N3b (controls) on
09-19, N3c (mitigations) and N3d (taxonomy) on 09-20. N2 and N3a/N3b were
live-confirmed on Cloud Run on 09-20. Next: **N4**, the context pack's own
schema and `metadata.kind` — not persistence, which the shell already does.
N5, the projector's own `normalize_flow_map`, can run in parallel.

| Date | Entry | What landed |
|---|---|---|
| 09-21 | `2026-09-21-draft-field-closure-and-derived-logic-shape.md` | **Code.** An external review of the 09-20 live run found four issues; all four reproduce. The flagship: the T1210 draft places the actor "from web console" and alerts on `client_ip NOT IN known_web_console_ips`, so its only discriminator excludes its own modelled source. A path-aware check was drafted and **rejected** — pseudocode is generated and then tested, and a validator that reviews the rule rather than describing it will be wrong in its own turn. The same draft declares `username` and never reads it, so one mechanical check catches it with no understanding of the attack. G1b now **annotates after validation**: `kind` derived from `join_keys`/`thresholds`/`window` (a declared `baseline_deviation` is never overwritten); windows canonical as `value_timeunit` (`60_sec`, `10_min`), a bare number being seconds; and field closure in both directions, grounded in the telemetry library so only real field names are reported. `review_flags` becomes a closed catalogue and no code rejects a draft. The `single_event` every live draft declared was the **prompt skeleton's own placeholder** — both placeholders are now enumerations. Replayed over the nine drafts: no false positives, and draft 6 is worse than the review scored it, reading `file_path` from a source the library says has no such field. Known gap: a field the library has never heard of (draft 8's `db_user`) is still invisible. Suite 1757 → 1782 |
| 09-20 | `2026-09-20-g1a-g1b-telemetry-join-and-generation.md` | **Code. G1a + G1b.** The telemetry library joins to nodes — 38 `stream_available`, 2 `periodic_only`, 3 `none_declared` across the corpus, where the bare three are exactly the components declaring no technologies. Readiness is a **separate axis** from the completeness grade, and a `protocol: physical` hop draws badge and door sources rather than the network telemetry its technologies match. The join exposed seven unmatched components, so the library gained `application.runtime_log` and `edge.waf_decision` (v0.2.0, 36 sources). `generate_detections` is implemented: batched by path with the full path outline, `provenance_by_field` and `uncovered_mitigations` withheld from the prompt, and validation that refuses an un-offered telemetry source, any `DS####`, a product named below `component_bound`, a changed technique id, or `missing_data_behaviour` that lets absent data read as benign. Coverage is a set comparison; a partial run returns `ok: false` **with** its output. Per the operator: `actor_evidence: false` never excludes a node — asserted by test. Scripted replies only, no live call yet. **Generation works end to end.** Suite 1705 → 1757. **Five live runs, five defects, all ours, no model failures**: a crash on reply shape; loyalty sources leaking onto a telemetry warehouse, which validation would have accepted; a contract naming required keys without their shapes; and `logsource.product` filled with our own source_id instead of a vendor name. The drafts themselves read as real work |
| 09-20 | `2026-09-20-projector-scoring-observations.md` | **Planning only, no code.** Two projector scoring findings that modelling a physical estate exposed, written up rather than folded into feature work because both change numbers the committed fixtures already carry. **(1)** A component with no outbound flow can rank first as an entry point — `oob_cellular`, the *exfiltration* path, scores 155 against the lobby badge reader's 130, and the ranking reaches the projection prompt. The obvious fix, suppressing dead ends, was **killed by checking it**: `idp` and `okta` are exposed with no outbound edge and are real entry points whose maps simply do not draw the return flow. Recommends annotating first, then ranking by reachable value. **(2)** `unauthenticated_hops` counts a badge-line door and an unauthenticated ethernet jack identically, so the narration reports "2 unauthenticated hops" for one network finding and one physical one. Plus a G1 item: a `protocol: physical` hop should draw physical telemetry, not the network sources its technologies match |
| 09-20 | `2026-09-20-reserved-vocabulary.md` | **Documentation.** `docs/specs/reserved_vocabulary.md`: every enforced enum and reserved spelling across the flow map, projector, designer, telemetry library and manifest, in one place, with a debugging-by-symptom table. Started from `protocol: physical` and extended on the operator's point that `rdp`/3389, `mqtt` and `modbus` each signify a kind of interchange rather than a transport — so each row says what its presence implies for detection. Also fixes the number-in-protocol trap (`protocol: rdp, port: 3389`). Linked from CLAUDE.md. No code changed |
| 09-20 | `2026-09-20-telemetry-library-seed.md` | **Code + reference data.** `framework/reference_data/telemetry_library.json` (v0.1.0, **34 sources** across the five estates) with a loader and validator. Every `collection.status` is `unknown` on purpose — the entries say what these products emit, not what anyone collects. `validate_library()` refuses an invented ATT&CK id (two candidates were dropped while writing: `T1562.001` retired, `T0855` absent), requires a `relation_kind` and rationale on every `adjacent`, and forbids a `decision_support` entry from claiming a detection. 15 unmapped behaviours with `EM-` ids; both audits classified `variance_management`; CCTV `on_request`; NetFlow states it cannot see the cellular path; the ledger records `join_keys` for actor and approver; and a test enforces that Kubernetes API audit does not claim to see in-container file reads. No `EM-AGENT-` entries and no consumer yet. Suite 1681 → 1705 |
| 09-20 | `2026-09-20-telemetry-library-spec-and-two-maps.md` | **Spec + fixtures, no code.** `docs/specs/telemetry_reference_library.md`, written against two new flow maps built for it: a branch office where an implant on a meeting-room wall port exfiltrates over cellular, and a loyalty estate where theft needs two accounts because dual approval separates duties. Three mapping states — `exact`, `adjacent` (with `broader`/`narrower`/`precursor`/`consequence`/`variant`), `unmapped` with local `EM-PHYS-`/`EM-OT-`/`EM-FRAUD-`/`EM-PROC-` ids — so a badge alert is never forced into a `T####`; and check the 97 local ICS techniques before calling anything unmapped. Artefact, cadence, latency and owner are first-class, because a quarterly clipboard audit and a live alarm both read `detection_capability: medium` in a flow map. Building the maps found that **the entry surface is network-only** — the branch's crown jewels validated as unreachable until physical movement was modelled as a flow with `protocol: physical`. Four schema gaps recorded, none patched by widening an enum. **Revised the same day with FAIR-CAM control function** (`loss_event` / `variance_management` / `decision_support`) plus `supports[]` edges, which reclassify the quarterly asset audit and the monthly badge audit as variance management rather than attack detection, and make "a control whose trigger depends on missing decision support" a reportable finding. Agent behaviour is the same problem operationally — commission, delegation, provenance, baseline are all decision support — and this repo already emits that record. Explicitly stops short of risk quantification: taxonomy borrowed, arithmetic not |
| 09-20 | `2026-09-20-digest-and-g1-grounding.md` | **Code. A readable digest, and G1's deterministic half.** The pack measured 187k characters on a 13-node pair, 58% of it `provenance_by_field`, so the pack stays machine-facing and a `digest` action renders three lines per node for a person. G1 grounding adds the versioned `assessment` tuple (`actor_evidence`, `multistep_access`, with reason codes and basis) and up to three local procedure examples carrying source ids, content hashes and an explicit "index reference, not a recovered citation" limitation. **The digest found a defect on its first render**: `access_source: model` is on all 43 nodes, so treating it as a trigger made `multistep_access` true 43 of 43 — a constant, not an assessment. It is a qualifier now and the distribution is 10/33, asserted by test. `actor_evidence` is true 43 of 43 by construction (the projector's actor filter is upstream) and that is recorded rather than presented as a finding. Suite 1668 → 1681 |
| 09-20 | `2026-09-20-n3c-n3d-mitigations-and-taxonomy.md` | **Code. N3c and N3d, completing N3.** Mitigation names from the local reference data, `mitigations_covered[]`, the 1–2 narrowest `mitigation_focus[]` and the coverage ratio; `tag_caveat` recomputed from the map per decision 11, or null **with a reason**, since a silent null would read as "every control is tagged". Both of the spec's independent figures reproduce from code: the M1016 (5) / M1048 (14) cut excluding M1026 (112), and 6 covered of 169. Taxonomy against v19.2 gives `technique:current` and `tactic:as_supplied` on every node — the expected result, since the projector already reconciled — with `Stealth` intact and `Defense Evasion` nowhere. A retired technique id is never rewritten: `technique_id_current` sits beside it. Four advisory codes added, caught missing from the spec by the catalogue test. Suite 1652 → 1668 |
| 09-19 | `2026-09-19-n3a-n3b-join-grades-controls.md` | **Code + decisions 10 and 11. N3a and N3b.** The flow-map join (zone, exposure, technologies, authentication, data classification, crown jewel, and `port`, which exists only on the map's flow), the five completeness grades, and controls per node with a derived `monitoring_claim`. The gate holds on the whole corpus: 38 `component_bound` + 5 partial with the map, 43 `asset_named` without, 43 `asset_text_only` from the seed. Two spec assumptions failed against the documents — the control catalogue has no component key (decision 10: structural from the map, else name **plus** the component id in the description, since `WAF` protects two components) and `tag_caveat`'s counts are in no export (decision 11: compute from the map, else null). A derived field records the fields it was computed from in place of a pointer; an unenriched field is absent, not null. N3c mitigations and N3d taxonomy outstanding. Suite 1635 → 1652 |
| 09-19 | `2026-09-19-n2-flow-map-lineage.md` | **Code + decision 9. N2 closed.** A flow map is an analyst-editable working document tracked in git, not a forensic copy, so its hash is lineage — `same_map` / `edited_map` / `unhashed` — and never refuses enrichment or withholds `component_bound`. What the hash had stood in for is asked directly: the map's application against the export's, and every node component against the map, where only an unresolved component withholds anything, from its own nodes. The projector's hash is reproduced without a cross-plugin import and held to all eight fixture documents. Warning, review-flag and error codes become closed catalogues with a severity each (§4.4). The pair rows of §4.2 are unchanged. Suite 1597 → 1635 |
| 09-17 | `2026-09-17-artifact-input-route.md` | **Code + decision 8.** The designer takes `artifact_ids` resolved through `context.artifacts`, not file paths: in the container an export is auto-exported to a bucket and only the registry knows where it landed. Also accepts the singular `artifact_id` the shell injects `file_path`/`path` beside, without reading that path a second time as a phantom pair. A registered artifact with unreadable bytes is `ARTIFACT_UNAVAILABLE` naming its `storage_uri`, never a missing file. Confirmed in a real shell run. Corrects a claim made earlier the same day: the shell already auto-persists a result that registers nothing, so N4 adds the pack's schema, not persistence. Suite 1589 → 1597 |
| 09-17 | `2026-09-17-n1-adapters-and-identity.md` | **Code. Stage N1.** New `attack_path_detection_designer` plugin: graph/seed/single-scenario adapters, the three identities of §4.2a, `(projection_identity, path_id, node_index)` keys, deterministic `draft_id`, the union merge with `provenance_by_field`, and the `state_check` / `transition` canonicalizations. The gate passes — graph-only, seed-only and joined input give identical ordered keys and draft ids on all four pairs (9, 11, 10, 13 = 43), 0 conflicts. Ships one working deterministic action, `validate_input`; `normalize_paths` and `generate_detections` are named as planned. The library is loaded as a sibling by file location, because the loader gives a plugin a flat module name and no package. Suite 1523 → 1589 |
| 09-17 | `2026-09-17-normalize-paths-plugin-shape.md` | **Planning only, and the last thing blocking N1.** `normalize_paths` and `generate_detections` become two actions of one plugin at `safe_for_auto_invoke: false`; §2's per-action `true` was unimplementable, since the field is whole-plugin and the schema has no `actions` property. Two plugins would have forced the normalization library into `framework/`, duplicated it, or reversed decision 2 — no plugin in the repo imports another. The cost is currently unobservable: nothing in the framework reads the flag. Widening the schema for a per-action form was rejected for now, on the same grounds as the `stability` enum |
| 09-17 | `2026-09-17-projector-corpus-refresh.md` | **Documentation only.** Three fresh runs (Scattered Spider/telemetry, APT29/Application B, Volt Typhoon/Claims Portal) join Fox Kitten to give four pairs on one code revision — 43 nodes, 3 applications, and run records for the first time. Every pair binds to a flow map already in the repo, which resolves the commit blocker. `component_bound_partial` gains 5 real instances. The `state_check` join reconfirms 43/43 and the mitigation split 163/169 uncovered on data sharing no run with the original measurement. New: `transition` needs the same canonicalization as `state_check` — the seed's prose drops `crosses_boundary`, so every non-null transition would otherwise join as a conflict. The producer's shape moves into its own document, `docs/specs/projector_export_shapes.md` |
| 09-17 | `2026-09-17-n1-contract-fixes.md` | **Planning only.** Six issues found by re-reading the four fixtures against the normalization spec, fixed before N1 encodes them. Two were self-contradictions: `source_identity` (document hash + filename) could never satisfy the N1 gate requiring graph-only and seed-only to yield the same node keys — split into artifact / projection / occurrence identity; and `state_check` equality would have rejected all 58 nodes, since the graph splits it across two fields where the seed combines them on an em dash (58/58 match under the canonical rule, 6 gap nodes exercise the note branch). Also: §4.1 named `actor_attck_id` and `provider` where the export has `actor_attack_id` and `model`, and no `provider` key exists to read; a `flow_map_sha256` alone no longer confers `component_bound`, and `component_bound_partial` is added for a bound component with no technologies; and §1.1's within-path repeat claim was wrong — no `(technique, component)` pair repeats within any path, so a synthetic case now covers the rule |
| 09-17 | `2026-09-17-mitigation-focus.md` | **Planning only.** `uncovered_mitigations` measured across the fixtures: ~95% identical to `mitigations` (7 of 154 covered), its most frequent members are ATT&CK's broadest (M1018 at 119 techniques), and it repeats verbatim wherever a technique repeats. Neither a telemetry filter nor an actor filter exists locally — mitigations carry no data-source link, and the actor constraint is already applied when the path is built. The pack keeps the full lists; generation reads only `mitigation_focus[]` (1–2 narrowest by technique breadth), `mitigations_covered[]` and the ratio |
| 09-17 | `2026-09-17-fox-kitten-fixture.md` | Fourth fixture (Fox Kitten G0117, 2 paths, 9 nodes, from Cloud Run). The first that is `component_bound` **and** carries a `state_check: gap`, so the inherited-gap route to `multistep_access: true` can be tested at full context grade. Also the only one with a live tactic reconciliation to `Stealth` and `code_id_source: build_env` |
| 09-17 | `2026-09-17-code-identity-on-cloud-run.md` | A container has no `.git`, so every Cloud Run export carried an empty `git_sha` — and the manifest version deliberately does not move, leaving those exports with no code identity at all. The deploy now forwards the image tag it already computes, and `code_id_source` distinguishes unavailable from unpopulated. **Live-confirmed** on the redeployed container. Suite 1519 → 1523 |
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
