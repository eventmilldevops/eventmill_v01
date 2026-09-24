# Threat Intel Ingester

Event Mill plugin for ingesting threat intelligence reports and extracting structured IOC data.

## Purpose

Ingests threat intelligence reports (PDF, HTML, STIX, CSV/JSON IOC lists) and
extracts structured IOC data with MITRE ATT&CK mapping.

For **PDF reports** the plugin prefers **native document ingestion** — the PDF is
sent to the model as a document, preserving tables, layout and cross-page context
that text extraction loses. It measures the document first, picks one of three
strategies, and falls back to chunked text extraction when native ingestion is
unavailable.

**The plugin reports on its own work.** Every result carries an
`analysis_status`, what was read, what was cut off, what the model was asked and
never answered, and every disagreement between batches. Read
[What the result says about itself](#what-the-result-says-about-itself) before
trusting an IOC list — an empty list and a failed run look identical unless you
read the status.

## How to Run

### Prerequisites

1. **A keyed provider.** The plugin is provider-agnostic: it asks for a *tier*
   and the operator picks the vendor. Any configured provider works
   (`gcp_gemini`, `anthropic`, `openai`). Keys are read from the environment or
   `~/.eventmill/deploy.env`. **`connect` must be run before any LLM action.**

   ```
   connect                                       # bind every keyed provider
   use                                           # show the current selection
   use gcp_gemini                                # session default for every tool
   use anthropic for threat_intel_ingester       # override this tool only
   ```

   The plugin never chooses a vendor and never fails over to one. Provider
   choice is an operator decision that never reaches plugin code — a plugin
   cannot see it and cannot override it — and automatic cross-provider fallback
   is forbidden by design: it would send investigation data to a vendor nobody
   chose and leave the output unattributable.

   Running the same report under two providers is a supported comparison. The
   prompt stays byte-identical across the swap and every response is stamped
   with the provider that served it.

2. **Python dependencies** — `pip install ".[plugins-log-analysis]"` from the
   project root.

3. **MITRE ATT&CK lookup** (one-time) — build the shared technique database:
   ```bash
   python scripts/build_mitre_lookup.py
   ```
   Downloads the Enterprise and ICS ATT&CK STIX bundles from the
   [MITRE CTI repository](https://github.com/mitre/cti) (pinned to
   **ATT&CK v19.2**) and writes `framework/reference_data/mitre_techniques.json`
   (~794 techniques). See [MITRE reconciliation](#mitre-reconciliation).

### Running in Event Mill

Arguments are passed as `--key value` flags.

```bash
eventmill                                   # start the shell
connect                                     # bind providers — required
load /path/to/threat_report.pdf             # load an artifact
artifacts                                   # prints the artifact ID

run threat_intel_ingester --artifact_id <artifact_id>

# With source context
run threat_intel_ingester --artifact_id <id> --source_context "Mandiant M-Trends 2025"

# Restrict the IOC types extracted (comma-separated)
run threat_intel_ingester --artifact_id <id> --ioc_types ip,domain,cve

# Cap cost on a very long report — pages beyond it are reported, not hidden
run threat_intel_ingester --artifact_id <id> --max_pages 50

# Chain to the visualizer using the output artifact
run attack_path_visualizer --artifact_id <output_artifact_id> --format mermaid

export <output_artifact_id>                 # push the JSON to cloud storage
```

### Input Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `artifact_id` | **Yes** | — | ID of the loaded artifact to process |
| `source_context` | No | `""` | Describes the report source (max 500 chars) |
| `ioc_types` | No | ip, domain, hash_sha256, url, cve, mitre_technique | Which IOC types to extract |
| `confidence_threshold` | No | `"low"` | Minimum confidence to include: `low`, `medium`, `high` |
| `max_pages` | No | *unset — read the whole document* | Deliberate cost ceiling on pages read |

**`max_pages` is a cost knob, not a limit.** Omit it and the whole document is
read. The limit that actually applies is the **selected provider's**, enforced
before the call: `gcp_gemini` 1000 pages, `anthropic` and `openai` 100. Setting
`max_pages` reports the remainder as `pages_dropped` and marks the run
`partial`; it never silently ignores pages.

> A 50-page stop used to be this plugin's own undocumented default. It is gone —
> the guard now reads whichever provider the run is routed to.

**JSON alternative.** Every tool also accepts a JSON payload. It is only needed
for list or object arguments a flag cannot express:
```
run threat_intel_ingester {"artifact_id": "art_0001", "ioc_types": ["ip", "domain"], "confidence_threshold": "low"}
```

## Supported Artifact Types

**Consumed:**
- `pdf_report` — PDF threat intel reports, vendor advisories (**native ingestion**)
- `html_report` — HTML blog posts, advisories, CERT bulletins
- `text` — Plain text, CSV, STIX bundles

**Produced:**
- `json_events` — Structured IOC records

## What the result says about itself

Everything below is additive — no key an existing consumer reads has moved.

### Status, first

`summary.analysis_status` is `complete`, `partial` or `degraded`, with
`analysis_notes` naming every cause. It leads `summarize_for_llm()`, because
`PluginExecutor` truncates that summary at this plugin's manifest
`summary_budget` (**8000 characters**, against a framework default of 4000)
*from the end* — a warning placed after the content is exactly the part that
gets cut.

Lists inside the summary are bounded regardless of the room available, and say
how many they did not name. A 154-page report can name thirty threat actors;
narrating all of them produces a summary that is mostly proper nouns and no
longer a summary. The complete lists are in `report_metadata` and in the
artifact.

`degraded` outranks `partial`: a run that fell back to a worse input path is a
more serious statement than one that analysed less of the report.

### Coverage

| Field | Means |
|---|---|
| `report_metadata.pages_total` / `pages_read` / `pages_dropped` | how much of the document was examined |
| `summary.coverage_unit` | **`pages` or `lines`** — a PDF is counted in pages, everything else in lines |

`coverage_unit` exists because loading a *generated summary* by mistake looks
identical to loading a report. A 114-line markdown summary reports
`coverage_unit: "lines"`; the same report as a PDF reports `pages`. If you see
`lines` where you expected `pages`, you ingested the wrong file.

### What the model was asked, and what came back

These three are deliberately separate counters. One number cannot say which
happened, and they have different fixes.

| Field | Means |
|---|---|
| `candidates_rejected` | verdicts the model returned calling something a false positive |
| `candidates_unassessed` | candidates that **were** submitted and got no verdict — the model's silence |
| `candidates_not_submitted` | candidates that reached **no prompt at all** — our coverage gap |

Rejecting three of three is an assessment. Rejecting three of forty is not.
`candidates_not_submitted` is 0 on every current path and is kept as an
invariant tripwire.

**An empty IOC list can be the right answer.** If refinement ran and judged every
candidate a false positive, the result is zero IOCs and `complete`, with a
`NO INDICATORS ACCEPTED` note. The regex baseline is *not* reinstated — doing so
would return the exact indicators the model just rejected, at low confidence,
and label a correct filtering result as a failure. The baseline comes back only
when refinement never ran, and that run is `regex_only` and `degraded`.

### Truncation and per-chunk outcomes

| Field | Means |
|---|---|
| `truncated` / `truncated_chunks` | replies that stopped at the output cap; their candidates were only partly assessed |
| `chunks_attempted` / `chunks_failed` / `chunk_failure_breakdown` | how many calls produced nothing, split by `json_parse` / `llm_call` / `exception` |
| `native_attempts` | native outcomes, which `chunks_attempted` cannot see |

Two signals are read, and neither subsumes the other: the transport's finish
reason, and whether the JSON parsed only after unmatched brackets were repaired.

### Evidence, not just entities

`(ioc_type, value)` and `(technique_id, tactic)` are **entity** identities, not
**evidence** identities — several procedures share one technique, and one
indicator carries several roles. So canonical scalar fields stay first-wins (no
consumer sees a different shape) and every sighting is kept underneath.

| Field | Means |
|---|---|
| `occurrences[]` | every sighting: `batch_label`, `attempt_id`, `page_start`/`page_end`, `context`, `confidence` |
| `conflicts[]` | scalar disagreements between batches, **never auto-resolved** |
| `recovered_from_partial` | a record surviving only from a cut-off reply its retry did not restate |
| `summary.rejected_with_dissent` | indicators dropped as false positives that another batch called real — they are **absent from `iocs`**, so this is their only record |
| `summary.merge_stats` | `conflicts`, `recovered_from_partial`, `superseded_results`, `occurrences`, `paths_namespaced` |

**Conflicts are never resolved by confidence.** A later correction and a
lower-confidence restatement are not distinguishable by value, so the first
value is canonical and the disagreement is handed to you.

**A successful retry supersedes the partial it replaces.** A truncated batch that
is bisected and retried used to *beat its own retry* in the merge — the one
defect whose behaviour was the opposite of what the logs reported. Supersession
is by page-range containment, not label match, because bisecting `p1-10` yields
`p1-5` and `p6-10` and no child ever shares its parent's label. The same rule
covers a truncated batch that could not be split and handed its pages to the
chunked path.

### Attribution

A report can name more than one group, and a later section can qualify what an
earlier one asserted.

| Field | Means |
|---|---|
| `report_metadata.attributed_actor` / `campaign_name` / `attribution_confidence` | the first of each, kept for existing consumers |
| `report_metadata.actors[]` | every actor named anywhere, with the confidence stated **with that actor** and the batch that named it |
| `report_metadata.campaigns[]` | every campaign named anywhere, with its batch |

Two actors is complete work, not a caveat — it does **not** make the run
`partial`. It reaches you through these fields and through `summarize_for_llm()`.

### Attack graph

Paths from separate calls are unioned and reconciled on their **step sequence**,
not on `path_id` — separate calls coin slugs independently, so a shared slug is
no evidence of a shared path, and two different slugs are no evidence of two
paths.

- Two batches describing the same path merge to one path carrying both
  `batch_labels`.
- Two batches coining the same slug for structurally different paths both
  survive; the later one is namespaced (`p11-20:initial-access-to-exfil`) and
  keeps `original_path_id`. `merge_stats.paths_namespaced` counts it.
- **Ids are unchanged on any run without a collision**, which is every
  single-batch run.

`leads_to`, `convergence_points` and `branch_points` are technique ids, never
path ids.

## PDF Processing Paths

### Path 1: Native document ingestion (preferred)

When the routed provider supports native PDF, the document is sent via
`query_with_document()`. The dispatcher resolves the transport:

- **GCS URI** (`gs://...`) — zero-copy, the model reads from cloud storage
- **Inline bytes** — a local file uploaded as raw bytes

`LLMResponse.transport_path` records which was used.

The native calls **pin no tier**. The manifest's `model_tier` (`light`) governs,
applied by `TierScopedLLMClient`, so the manifest stays the one place the model
is chosen. They pass `prefers_native_file=True`, `needs_structured_output=True`
and `thinking_level="medium"` — reading a report is not pure pattern work.

> Thinking tokens come out of the **same budget as the reply**. That is why the
> content budget holds some back and batches are smaller; it is the trade being
> made, not an oversight. A call with a small output cap can spend its whole
> budget thinking and return `ok=True` with empty text.

### Page-range batching (dense documents)

Before any call the plugin measures the document: pages, regex candidates per
page, and an estimate of the output tokens the model must write (~70 per
candidate). **The reply grows with the candidate count, not the page count**, so
a 20-page IOC appendix costs more than a 100-page narrative.
`framework.documents.plan_ingestion` turns that into one of three strategies,
logged as `[PLAN]` and stored in `summary.ingestion_plan`:

| Strategy | When | What happens |
|---|---|---|
| `native` | the whole document fits one call's output cap and deadline | a single `query_with_document()` call |
| `native_batched` | it does not | the PDF is cut into page-range sub-PDFs with pypdf (page boundaries only), each sent with only that range's candidates; results are merged |
| `chunked_text` | native ingestion unavailable | Path 2 |

A batch that fails sends **only its pages** to the chunked path; other batches'
native results are kept. A truncated batch is bisected and retried, and the
retry supersedes it. Sub-PDFs live under
`workspace/artifacts/<artifact_id>_batches_*/` and are deleted when the run ends.

Batch sizing uses a latency model overridable per deployment with
`EVENTMILL_NATIVE_BASE_S`, `EVENTMILL_NATIVE_S_PER_PAGE`,
`EVENTMILL_NATIVE_S_PER_CANDIDATE`. On a timeout the `[NATIVE]` line reports the
observed seconds-per-page to recalibrate from.

> **The latency model is known to be pessimistic** — measured 6–8× over on live
> runs, which over-splits documents. Recalibration is tracked work; do not add a
> budget guard on top of it first.

### Path 2: Chunked text extraction (fallback)

Used when native ingestion is unavailable, and for every non-PDF artifact.

1. Text extraction (`pdfplumber` for PDFs)
2. **Page-aligned units** — see below
3. `query_text()` calls at `tier="light"`, `thinking_level="low"`
4. Merge and deduplication across units

**Candidates are paired with the text they came from.** Text units are built
first, and each unit's candidates are the ones extracted from that unit's pages:

- Contiguous pages are packed into a unit under the character budget (~6000).
- A page larger than the whole budget is split by paragraph, with candidates
  **re-extracted per piece** — the path every non-PDF report takes, since a text
  artifact is a single page.
- A unit holding more than 50 candidates splits **within the unit**, every piece
  keeping the same text.
- The unit's page label travels in the prompt, and a jump between non-adjacent
  page ranges is stated, so a section starting at page 30 does not read as
  continuing one that ended at 19.

> Previously the candidates and the text were split **independently and paired by
> index**. Candidate order is type-major, so the first batch was in practice
> every IP in the document — appendix included — sent beside the document's first
> 6000 characters, and any overflow batch went out with no text at all.

Chunk results carry their page range, so an indicator found on this path records
where in the report it was seen.

### Regex pre-scan

Both paths are preceded by a regex pass that identifies IOC candidates, which are
included in the prompt for the model to validate against the document.

## MITRE reconciliation

The shared module `framework.reference_data.mitre_attack` is used to:

- **Enrich** LLM output with authoritative technique names and tactics
- **Backfill** technique IDs referenced in attack graphs but missing from mappings
- **Validate** every technique ID — `mitre_validated: false` and a
  `(non-ATT&CK ID)` suffix mark an LLM guess
- **Validate tactics** against each technique's allowed tactics
- **Remap retired technique IDs.** Models still emit pre-v19 ids. These are
  remapped from a curated map plus name matching, and **never guessed**
- **Migrate retired tactics.** v19 replaced "Defense Evasion" with "Stealth" and
  "Defense Impairment"; the reconciler rewrites to whichever successor the
  technique actually lists (T1027 → Stealth, T1553 → Defense Impairment).
  Occurrences it cannot resolve are left alone and flagged

`TACTIC_ORDER` and `LEGACY_TACTIC_ALIASES` live in that module so every plugin
shares one definition.

### Multi-role tactic mappings

`mitre_mappings` uses **`(technique_id, tactic)` as the identity key**. Consumers
**must** consider both together — grouping by `technique_id` alone flattens the
tactical context and loses the per-path role distinctions the attack graph
encodes.

When one technique serves different roles in different paths (T1078 as Initial
Access in one, Persistence in another) it appears as multiple entries with
`context_paths` listing the path IDs where each role was observed. A
single-role technique produces a single entry, exactly as before.

A **kill-chain progression rule** reassigns entry-point-only tactics (Initial
Access, Reconnaissance, Resource Development) on non-first graph steps to the
best alternative from the technique's valid tactics, so the matrix is not
flattened by repeated "Initial Access" labels.

### Tactic correction and mismatch labeling

Three outcomes; only the last needs a person.

1. **Corrected automatically** — `tactic_corrected_from` holds the original
   label. Applies when the label is unambiguously wrong: a retired tactic whose
   technique lists exactly one v19 successor; one of the Stealth / Defense
   Impairment pair where the technique allows only the other; or a technique with
   a single valid tactic (633 of 794 are single-tactic). Graph steps are
   corrected the same way so nodes and mappings agree.
2. **Case fixed** — "Command And Control" → "Command and Control".
3. **Needs analyst review** — several valid tactics and the LLM chose none of
   them. The label is kept (it may describe the role the report gives it) and
   flagged with the options:

   ```json
   {
     "technique_id": "T1078",
     "tactic": "Lateral Movement",
     "mitre_validated": true,
     "tactic_mismatch": true,
     "allowed_tactics": ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"]
   }
   ```

   The run summary prints an `ACTION:` line, `summary.tactic_mismatch_count`
   counts them, and `attack_path_visualizer` marks the node "tactic unconfirmed".

## Output Persistence

```
workspace/artifacts/<artifact_id>_ti_iocs.json
```
Registered as a `json_events` session artifact whose ID is shown in the run
summary. **Coverage, `ingestion_mode` and the full analysis block travel with the
artifact**, not just the in-session result — a file read back from a bucket
months later has only what was written into it. Use `export <artifact_id>` to
push it to `common/exports/threat_intel_ingester/`.

## LLM Dependency

**requires_llm: true** · **manifest `model_tier`: light** · **`timeout_class`: long**

Used for contextual extraction beyond regex, confidence and priority assessment,
MITRE inference, attack-graph construction, and false-positive filtering.

| Path | Tier | Thinking | Other hints |
|---|---|---|---|
| Native PDF | *manifest* (`light`) | `medium` | `prefers_native_file`, `needs_structured_output` |
| Chunked text | `light` | `low` | `needs_structured_output` |

`QueryHints` carries **no provider field and must not gain one** — that would put
vendor choice in plugin code and let a plugin override an operator's selection.

Without an LLM connection the plugin falls back to regex-only extraction at low
confidence, and says so: `ingestion_mode: "regex_only"` and
`analysis_status: "degraded"`.

## Example `summarize_for_llm()` Output

```
PARTIAL — TRUNCATED OUTPUT: chunk 3 stopped at the output cap; their candidates were only partly assessed; UNRESOLVED CONFLICTS: 2 reported value(s) disagree between batches. Ingested pdf_report (154 pages): APT29 Campaign Analysis. Attributed to APT29 (high confidence), campaign: SolarWinds Follow-on. Also attributed, elsewhere in the report: UNC2452. Extracted 147 IOCs: 23 ips, 12 domains, 8 hash_sha256s, 4 cves. 3 IOCs flagged as high-priority. Mapped to 5 unique techniques across 7 tactical roles. Attack graph: 2 path(s) identified, converging at T1059.001. Output artifact: art_0002 (json_events). Quick chart: run attack_path_visualizer --artifact_id art_0002 --format mermaid
```

The status leads. The **Quick chart** command at the end generates a Mermaid
attack path diagram — copy it into the shell.

## Reading the Logs

| Tag | When | What it tells you |
|---|---|---|
| `[PROFILE]` | before any LLM call | pages, text size, candidates by type and per page, estimated output tokens, `narrative` vs `ioc_dense` |
| `[PLAN]` | after the profile | strategy, page-range batches with candidate counts, estimated seconds, and why |
| `[BATCH]` | batched runs | sub-PDFs written, or why splitting failed |
| `[NATIVE]` | each native call | batch label, candidates sent, elapsed, model, transport, response size, token usage; on a timeout, observed seconds-per-page |
| `[CHUNK]` | each fallback call | elapsed, candidates in, response size, token usage |
| `[TRUNCATED]` | a reply hit the output cap | records recovered by bracket repair; anything after the cut is lost |
| `[MERGE]` | after merging | superseded partials, conflicts recorded, rejections another batch disputed |
| `[DIAG]` | throughout | unassessed candidates, candidates that reached no prompt, merged counts |
| `[TACTIC-FIX]` / `[RECONCILE]` | post-processing | corrections, backfills, entries needing review |
| `[TIMING]` | end of run | `extract_s`, `native_s`, `chunks_s`, `reconcile_s`, `total_s` |

The profile and timings are also in `summary.document_profile` and
`summary.timings`, so they travel with the artifact.

## Limitations

- Requires a keyed, connected provider; `connect` first
- The chunked fallback may lose table formatting and cross-page context
- Provider page limits apply and are enforced before the call: `gcp_gemini`
  1000 pages / 50 MB, `openai` 600 / 50 MB, `anthropic` 250 / 24 MB (read
  from `framework/llm/providers/<id>.json`)
- The latency model is pessimistic and over-splits documents (see above)
- STIX 2.1 parsing not yet implemented
- **Verified on `gcp_gemini` light only.** Truncation behaviour and thinking
  spend are per-vendor, and supersession is driven by truncation

## Safety Notes

**safe_for_auto_invoke: true**

Read-only and low-risk. Processes local artifacts and makes external calls only
to the configured provider via the framework's LLM dispatcher.

## Dependencies

Beyond framework baseline (`pip install ".[plugins-log-analysis]"`):
- `pdfplumber>=0.10.0` (text extraction)
- `beautifulsoup4>=4.12.0` (HTML processing)
- `stix2>=3.0.0` (future STIX support)
- `python-docx>=1.1.0`

`pypdf` (page counting, page-range splitting) is a **framework baseline**
dependency, not a plugin extra — the dispatcher's PDF guard and the shell's
artifact registration both need a page count.

## Reference Data Overrides

- **`framework/reference_data/mitre_techniques.json`** — shared ATT&CK lookup
  (Enterprise + ICS), built by `scripts/build_mitre_lookup.py`, accessed via
  `framework.reference_data.mitre_attack.get_mitre_db()`. See Prerequisites
  step 3.
