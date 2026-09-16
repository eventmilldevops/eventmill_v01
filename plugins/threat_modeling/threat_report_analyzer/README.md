# Threat Report Analyzer

**Summarize threat intelligence reports from the common bucket into context for analysis tools.**

## What It Does

Reads threat intelligence reports (MITRE ATT&CK, CAPEC, CISA advisories, vendor
bulletins, vendor PDFs) from the common bucket and generates markdown summaries
for use as context in other analysis tools.

Large files are processed natively where the provider supports it, and otherwise
in page- or paragraph-bounded sections, each summarized independently and then
synthesized into one coherent output.

**The tool reports on its own work.** Every summary carries an `analysis_status`,
how many pages were actually read, which calls were cut off, and whether any
section fell back to raw extracted text instead of a summary. See
[What the result says about itself](#what-the-result-says-about-itself) — a
summary that covers a third of a report and one that covers all of it are
otherwise indistinguishable.

Three actions:

1. **list_reports** — list available threat reports in the common bucket
2. **summarize** — generate an LLM-powered markdown summary of one report
3. **search_reports** — search across report content for keywords

## Prerequisites

**A keyed provider, and `connect` before any LLM action.** The tool is
provider-agnostic: it asks for a *tier* and the operator picks the vendor.

```
connect                                       # bind every keyed provider
use                                           # show the current selection
use anthropic                                 # session default for every tool
use gcp_gemini for threat_report_analyzer     # override this tool only
```

The plugin never chooses a vendor and never fails over to one. Provider choice
is an operator decision that never reaches plugin code, and automatic
cross-provider fallback is forbidden by design. Every exported summary is
stamped with the provider and model that answered, so two runs under different
vendors can be compared afterwards.

## Common Bucket Structure

```
{prefix}-common/
├── mitre/                    # MITRE ATT&CK framework data
├── capec/                    # CAPEC attack patterns
├── cisa/                     # CISA advisories and KEV catalog
├── vendor_advisories/        # Vendor security bulletins
├── threat_actors/            # Threat actor profiles
├── campaigns/                # Threat campaign reports
└── vulnerabilities/          # CVE/vulnerability data
```

Falls back to the local `framework/reference_data/` directory when the common
bucket is unavailable.

## Supported Input Formats

| Format | Extensions | Notes |
|--------|-----------|-------|
| PDF | `.pdf` | Native document ingestion where supported; otherwise pypdf text extraction, chunked |
| Word | `.docx`, `.doc` | Extracted via python-docx |
| JSON / STIX | `.json` | MITRE ATT&CK bundles, STIX 2.x |
| XML | `.xml` | CAPEC, CVRF, STIX 1.x |
| Markdown | `.md`, `.markdown` | Pre-processed summaries |
| Plain text | `.txt` | Raw advisories, bulletins |
| CSV | `.csv` | Structured IOC/vulnerability lists |

## Example Usage

Arguments are passed as `--key value` flags.

### List available reports
```
run threat_report_analyzer --action list_reports
```

### Summarize a report
```
run threat_report_analyzer --action summarize --report_path mitre/enterprise-attack.json --max_word_count 2000
```

### Summarize with focus areas
```
run threat_report_analyzer --action summarize --report_path capec/capec-stix.xml --focus_areas attack_techniques,mitigations
```

`--focus_areas` takes a comma-separated list. Repeating the flag appends, so
`--focus_areas attack_techniques --focus_areas mitigations` is equivalent.

### Report every finding, with no upper bound
```
run threat_report_analyzer --action summarize --report_path vendor_advisories/apt29.pdf --ignore_caps
```

### Search reports
```
run threat_report_analyzer --action search_reports --query ransomware
```

**JSON alternative.** Every tool also accepts a JSON payload. It is only needed
for list or object arguments a flag cannot express:
```
run threat_report_analyzer {"action": "summarize", "report_path": "capec/capec-stix.xml", "focus_areas": ["attack_techniques", "mitigations"]}
```

### Input Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `action` | **Yes** | — | `list_reports`, `summarize`, `search_reports` |
| `report_path` | for `summarize` | — | Path in the common bucket |
| `query` | for `search_reports` | — | Search string |
| `max_word_count` | No | `2000` | Target words in the summary (500–4000) |
| `focus_areas` | No | — | Areas to emphasize |
| `ignore_caps` | No | `false` | Report `key_findings` and `relevant_techniques` in full, with no upper bound |

## Extracted lists, and their bounds

Two lists are extracted from the summary the model produced — `key_findings`
(bulleted or numbered items, in document order) and `relevant_techniques` (ATT&CK
ids, deduplicated in first-appearance order).

Both are **bounded by default**: 50 findings and 200 techniques. Anything the
bound cuts is counted and named in `analysis_notes` as a `LIST TRUNCATED` note,
which makes the run `partial`. Ordering is **stable across identical runs** — the
technique list used to be `list(set(...))[:20]`, so which twenty ids survived
varied between identical runs over identical text.

**`--ignore_caps` turns the bounds off entirely.** A reported cap is still a cap:
"key findings" is read as the findings that matter, and being told seven were
left out says neither which seven nor how to get them back. Both lists are
extracted from a summary the model already produced — no extra call, no extra
tokens — so an operator who wants all of them can have all of them.

When set, the result carries `caps_waived: true` and the exported file's header
says so. Two runs of one report can legitimately return lists of different
lengths; this is what says which run produced which.

## What the result says about itself

### Status, first

`analysis_status` is `complete`, `partial` or `degraded`, with `analysis_notes`
naming every cause. It leads `summarize_for_llm()`, because `PluginExecutor`
truncates that summary at this plugin's manifest `summary_budget` (**8000
characters**, against a framework default of 4000) *from the end* — a warning placed after
the content is exactly the part that gets cut.

`degraded` outranks `partial`. A run that fell back to a worse input path is the
more serious statement: calling it "partial" would suggest the same analysis
covering less of the report, when part of it was never analysed at all.

### Coverage

| Field | Means |
|---|---|
| `pages_total` / `pages_read` / `pages_dropped` | how much was examined; `pages_dropped` is **never attempted**, not "failed" |
| `pages_empty` | pages that yielded no text (blank — not a defect) |
| `pages_extract_failed` | pages pypdf could not read (scanned or damaged) |

`pages_read` counts only pages that yielded text. A page pypdf failed on *was*
attempted, and calling it dropped would hide that the file itself is the problem.

Coverage is **empty** when native ingestion read the whole document — coverage is
total by construction there, and claiming a page count the plugin never counted
would be worse than saying nothing.

### Section outcomes

A section that produces no summary is never silently replaced by raw text. Each
carries a status, and a substitution is labelled everywhere it travels — into the
synthesis prompt, into the exported file, and into the result.

| Status | Means |
|---|---|
| `complete` | a summary was written |
| `partial` | the reply stopped at the output cap; it covers only part of that range |
| `empty` | the model returned no text; raw extracted text follows |
| `failed` | the call failed; raw extracted text follows |

`empty` is its own status because `ok=True` with no text is **budget
starvation** — thinking spent the whole output budget. The transport does not
report it as a failure, so it is caught here.

### Truncation and degradation

| Field | Means |
|---|---|
| `truncated` / `truncation_notes` | which calls were cut off at the output cap |
| `degraded` / `degradation_notes` | where the run fell back to a worse input than intended |
| `caps_waived` | whether the extracted lists were bounded |

## Output budgets

Every call's output budget is sized from the **provider's declared thinking
reserve for the level actually requested**, bounded by the tier cap.

Thinking is spent from the reply budget, so a bare content figure is silently a
thinking cap. On live traffic, one call spent 5,756 of a 6,000-token budget
thinking and had 239 left for the answer, while a call with a *larger* prompt
spent 2,607 and got 3,389. Thinking spend is non-deterministic and prompt size
does not predict it.

Limits are read per provider from `framework/llm/providers/<id>.json` — never one
vendor's numbers applied to another.

### Reasoning depth

The whole-document pass runs at `medium`. Raise it per deployment with
`EVENTMILL_REPORT_NATIVE_THINKING=low|medium|high` in `~/.eventmill/deploy.env` —
Cloud Run has latency headroom an interactive session does not, and reasoning
depth dominates latency. The budget is sized from the level, so the two move
together. An unrecognised value warns and falls back to `medium`.

Section summaries stay at `low` (bulk, repetitive work) and the synthesis pass at
`high`. Both are deliberate and not exposed.

## Intake limits

| Constant | Value | What it bounds |
|---|---|---|
| `MAX_LOCAL_PDF_BYTES` | 200 MB | what this process reads off disk with pypdf |
| `MAX_LOCAL_PDF_PAGES` | 2000 | ditto |
| `MAX_PAGES_PER_CHUNK` | 100 | pages per section |
| `MAX_TOKENS_PER_CHUNK` | 100,000 | text per section |
| `MAX_TEXT_TOKENS_SINGLE_PASS` | 150,000 | above this, text is sectioned |

**These are resource ceilings, not provider limits.** What a vendor accepts lives
in `framework/llm/providers/<id>.json` and is enforced by the dispatcher's PDF
guard against the provider actually routed to.

> They previously held 50 MB / 1000 pages, which are Gemini's figures — wrong for
> two of the three vendors (Anthropic and OpenAI accept 100 pages / 32 MB) and
> phrased as though the plugin were setting provider policy.

## Output Persistence

Summaries are written to the common bucket mirror path, **stamped with a UTC run
identifier**:

```
workspace/storage/<bucket>/generated/threat_report_analyzer/<report_name>.<stamp>.summary.md
```

Multi-section reports also write each section:
```
.../<report_name>.<stamp>.chunk_NNN.summary.md
```

The stamp goes **before** the suffix so anything globbing `*.summary.md` keeps
matching. **Runs no longer overwrite each other** — the same report summarised
twice leaves both copies. That is the intent: storage is cheap, and a replaced
summary cannot be compared against the one it replaced. Re-runs accumulate.

### Every file carries its own provenance

A file named `.summary.md` read back from a bucket months later has only its
contents to go on, so each one is stamped with a header:

```markdown
<!-- Event Mill threat_report_analyzer -->
> **Source:** `vendor_advisories/apt29.pdf`
> **Run:** 20260915T211957Z
> **Answered by:** anthropic/claude-opus-5
> **Analysis status:** partial
> - INCOMPLETE COVERAGE: only 120 of 154 pages were read, so a topic missing here may simply be in the part that was not read
> **Pages:** 120 read of 154, 2 blank
```

With `--ignore_caps` the header also states that the list bounds were waived.

The framework additionally registers the final summary as a `text` session
artifact. Use `artifacts` for its ID, then `load` it or pass it to
`risk_assessment_analyzer` or `threat_model_analyzer`.

## LLM Integration

**requires_llm: true** · **manifest `model_tier`: heavy** · **`timeout_class`: long**

| Pass | Tier | Thinking |
|---|---|---|
| Whole-document (native PDF) | `heavy` | `medium`, overridable |
| Section summary | `light` | `low` |
| Synthesis | `heavy` | `high` |

Summaries are structured markdown with an executive summary, key threat
actors/techniques, relevant ATT&CK techniques with IDs, detection opportunities,
and recommended controls.

Without an LLM connection, sections come back `failed` with their raw extracted
text as a labelled substitution — never presented as a summary.

## Chains

- **To**: `risk_assessment_analyzer`, `attack_path_visualizer`
- **From**: — (entry point for the threat intel workflow)

## Safety Notes

**safe_for_auto_invoke: false** — this tool writes files to the common bucket.

## ATT&CK taxonomy

**Both report tools answer to the same ATT&CK release** — v19.2, the one
`scripts/build_mitre_lookup.py` pins. That takes two mechanisms, because
neither does the job alone.

**The prompts are grounded.** Every summarization prompt carries the release,
the valid enterprise tactic list, and the fact that *Defense Evasion* was
retired in v19 and split into **Stealth** and **Defense Impairment**. Without
it a model answers from its training data — which for every current model
predates v19 — and writes retired tactic names into its narrative. A live run
on 2026-09-16 produced a table headed `Defense Evasion | T1027` and cited
"MITRE ATT&CK Framework (v14+)"; neither string exists anywhere in this
repository.

**The extracted ids are reconciled.** `relevant_techniques` is scraped from the
model's prose, so it arrives under whatever numbering the model learned. Every
id is validated against the local lookup, retired ids are remapped from the
curated map (**never guessed**), and the result carries:

| Field | Means |
|---|---|
| `attack_techniques[]` | each id with its official `technique_name`, the `tactics` ATT&CK allows, and `mitre_validated` |
| `attack_techniques[].remapped_from` / `remap_basis` | the retired id it was reported under, and whether the remap was `curated` or resolved by name |
| `attack_version` | the release it was reconciled against |

`relevant_techniques` keeps its shape — a list of id strings — so existing
consumers are unaffected, but the ids in it are the reconciled ones and can
differ from those in the prose above.

**The export carries a checked table.** Narrative text cannot be safely
rewritten after the fact, so the summary file gets its own
`## ATT&CK techniques (reconciled against v19.2)` block between the provenance
header and the model's prose. An id ATT&CK does not know is listed and marked
*not in ATT&CK*, not quietly dropped and not presented as fact.

**The analyzer does not build attack paths.** `threat_intel_ingester` produces
the reconciled `attack_graph`, and `attack_path_visualizer` and
`adversary_path_projector` consume it. A second, prose-derived path
representation here would be unreconciled by construction — the exact
divergence this section exists to remove.

The shared primitives live in `framework/reference_data/mitre_attack.py`
(`attack_grounding`, `reconcile_technique_ids`, `attack_version`), so both
tools call one implementation rather than keeping two in step.

## Notes

- Extracts MITRE ATT&CK technique IDs (T1234 format) from summaries, in stable
  first-appearance order, then reconciles them — see
  [ATT&CK taxonomy](#attck-taxonomy)
- PDF handling here is **separate from `threat_intel_ingester`'s**; the two do
  not share PDF code, and only the ingester uses `framework/documents`
- Section summaries are written for multi-section reports even when a section
  failed, with a failure header — a missing file cannot distinguish a section
  that failed from one never attempted
