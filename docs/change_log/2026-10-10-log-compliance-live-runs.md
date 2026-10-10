# 2026-10-10 — Logging compliance: first live runs, and what they changed

First runs of `logging_standard_profiler` and `log_compliance_auditor` against
a real model, using the example corpus in `plugins/log_analysis/examples/`
(the YMMV Industrial Event Observability Standard and the legacy invoicing
logs). Follows `2026-10-10-log-compliance-audit.md`, which recorded both
plugins as untested against a model.

All runs: `gcp_gemini`, heavy tier (`gemini-3.1-pro-preview`), thinking level
medium, driven through the real shell (`connect`, `load`, `run`) from a local
workspace.

## What the runs found

Three defects, all in this code, none visible to the scripted tests.

### 1. The profiler under-extracted (fixed)

The standard has 144 sentences worded shall, must, should or required. The
first run returned 11 requirements. It missed section 5.4 (location and
source), a "shall" about record content, and nearly all of retention,
protection and review. Every quote it did return was verbatim.

The prompt said "keep only" certain statements. Rewording it to demand
exhaustiveness raised the count to 25: record-content sections were then
covered, but the handling sections were still sampled at about one sentence
per heading. Prompt wording does not make one pass exhaustive.

Fix, in two parts:

- **A local count.** `extraction.obligation_sentences` finds every sentence
  with obligation wording, with its page and numbered heading. The profile's
  new `statement_coverage` block says how many were quoted, so a thin
  extraction is visible without reading the standard beside the profile.
- **A sentence sweep.** A second call sends the model only the sentences the
  first read left unquoted, numbered, and asks it to classify each: requirement
  or not, obligation, `assessable_from`, elements. A swept requirement's quote
  is the sentence as extracted locally, never model text. Each requirement
  carries `extracted_by: document_read | sentence_sweep`.

Result on the same standard: 122 requirements (18 testable against records,
92 not assessable from a sample, 12 about records but outside the catalogue),
21 sentences judged not a requirement and listed with the reason, 0 not
classified. Two calls, 145 s.

The sweep is skipped when the first read returns nothing, when the time budget
is nearly spent, or with `--skip_sweep`; the profile says which. Requirements
are now written in document order.

### 2. A Java exception line was counted as a record (fixed)

The Catalina log has 240 logical events; the auditor counted 243. The first
line of a Java stack trace (`java.sql.SQLTransientConnectionException: ...`)
starts at column 0, and the continuation rule only knew indented lines,
`Caused by:` and Python's `Traceback`. The model dutifully wrote a pattern for
the three stray lines. The rule now also takes a package-qualified class name
ending in Exception, Error or Throwable. Count is 240, matching
`ymmv_legacy_invoicing_catalina.ground_truth.json`.

### 3. The report was too long to read (fixed)

Each assessed requirement printed a row per record type per element: 56 KB for
a 200-record log. It now prints one row per element summed over record types,
followed by the record types that fall short and why. Same audit: 34 KB, most
of which is the list of 92 out-of-reach requirements.

## Audit results

| Log | Records | Mapped | Record types | Rounds | Lines sent | Elapsed |
|---|---|---|---|---|---|---|
| `ymmv_legacy_invoicing_database_audit.log` | 200 | 200 | 11 | 2 | 62 | 58 s |
| `ymmv_legacy_invoicing_catalina.log` (before fix 2) | 243 | 243 | 12 | 2 | 87 | 84 s |
| `ymmv_legacy_invoicing_catalina.log` (after) | 240 | 238 | 12 | 1 | 85 | 64 s |

Checked against ground truth:

- Database audit: record count exact. Actor counts extracted with the tested
  patterns equal `actor_counts` exactly (8 identities, 200 records).
- Catalina: record count exact after fix 2.

Findings that hold up on reading the logs:

- Database audit: timestamps carry an offset and parse in every record; the
  database server's own host is named only in the 6 backup records (`src` and
  `client` are the caller, mapped to `source_address`); 48 records (commits,
  connects, backup verifies) name no target object.
- Catalina: no timestamp carries a timezone or offset; `host=` appears only on
  the 69 completed-request records; there is no event code field.

## What the runs showed that is not fixed

- **Element mapping varies between runs.** Two Catalina audits on the same
  file: one mapped the HTTP `method` to `event_type` (35% of records), the
  other did not (6%). The database run chose `action` over `category` for the
  pipe-delimited records, where the generator's ground truth counts by
  category. Each choice is defensible; the finding still moves. The extraction
  spec is the place to pin a mapping, and `assess` re-tests it with no model.
- **Conditional requirements are counted against every record.** "Where
  applicable" and "when an outcome exists" produce `partially_observed` for
  record types the requirement arguably does not apply to. The report shows
  which types fall short; it does not judge applicability.
- **A requirement naming many elements reads as 0%.** 5.1 lists six elements;
  the database log has four of them in every record and is `not_observed`
  because no record has all six. The per-element table shows this; the
  one-line summary does not.
- **The profile needs its review.** Plausible-but-wrong examples from this run:
  1.3 (the objectives paragraph) mapped to six elements as though it were a
  record requirement; 6.2#2 (a prohibition on message-only fields) mapped to
  `message`; a sentence about recording unavailable provider logs judged not a
  requirement.
- **Sentence splitting is naive.** A citation bracket stays glued to the next
  sentence (`SRC-CIS-8] The required timestamp...`), and a list introduced by
  a colon is split at its semicolons.
- `assess` keeps a saved pattern that now matches nothing (the stray exception
  pattern, after fix 2) and still counts it as a record type.

## Files

- `plugins/log_analysis/logging_standard_profiler/extraction.py`: prompt
  opening; `obligation_sentences`, `not_quoted`, `build_sweep_prompt`,
  `parse_sweep`, `sweep_requirements`, `in_document_order`
- `plugins/log_analysis/logging_standard_profiler/tool.py`: sweep call,
  `statement_coverage`, document order, summary line
- `plugins/log_analysis/logging_standard_profiler/schemas/input.schema.json`:
  `skip_sweep`
- `plugins/log_analysis/log_compliance_auditor/survey.py`: continuation rule
- `plugins/log_analysis/log_compliance_auditor/renderers.py`: per-element
  table, record types falling short
- Tests: 7 for the sweep, 1 for the stack trace
- READMEs, `docs/specs/log_compliance_audit.md`,
  `docs/specs/reserved_vocabulary.md`

## Verified

- `pytest -q tests/ plugins/`: 2045 passed, 1 skipped.
- Profiler: three live runs on the PDF by the native document path
  (`inline_bytes`), the last with the sweep.
- Auditor: `survey`, `audit` and `assess` live through the shell on two logs,
  six artifacts registered each time.

## Not verified

- Only Gemini. No run on Anthropic or OpenAI.
- The `syslog` and `auth` sample logs were not audited. Both use classic syslog
  timestamps with no year, which exercises `year_absent`.
- `resume` was never needed, so it has still only run against scripted replies.
- Largest file was 249 lines. Nothing here tests the 100,000-line case or the
  time budget under it.
- Splunk and Elastic renderings still not loaded into either product; BigQuery
  SQL still not executed.
- Nothing on Cloud Run.
- The last profiler run predates two small edits (the summary's sentence count
  and code formatting); those are covered by tests, not by a further live run.

## Noted in passing

`plugins/log_analysis/examples/` sits inside a pillar directory, so the plugin
loader logs "Plugin directory examples missing manifest.json" at start-up and
`validate_schemas.py` reports it as an error. Harmless, and the same as the
existing `postures` directory.
