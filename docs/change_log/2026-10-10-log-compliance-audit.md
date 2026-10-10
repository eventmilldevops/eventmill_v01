# 2026-10-10 — Logging compliance: a standard profiler and a log auditor

Two new plugins in `plugins/log_analysis/`. Together they answer whether an
application's log output contains what a logging standard requires, and they
produce tested extraction patterns for ingesting the same log.

Spec: `docs/specs/log_compliance_audit.md`.

**Built and tested with scripted model replies only. Neither plugin has been
run against a real model.** See *Not verified* before relying on either.

## What was asked for

A variation of `log_pattern_analyzer` for compliance: ground on a standard such
as NIST SP 800-92 or an internal one, and confirm an uploaded log meets it.
The records may take any form and order, but repeat a few shapes. A model
should see 100 to 200 rows at a time, propose regexes, and the tool should test
them against the sample in the container, iterating until the elements are
mapped. Output: an alignment report and extraction filters for Splunk, Elastic
or BigQuery.

During planning the operator added that standards are heavy on boilerplate and
light on technical specification, so reading one should be its own step,
producing JSON that an audit step consumes with the log sample.

## What was built

- **`logging_standard_profiler`**: reads a standard (PDF natively where the
  provider supports it, extracted text otherwise) and writes a requirement
  profile. Actions `extract_profile` and `validate_profile`.
- **`log_compliance_auditor`**: surveys a log, runs a propose / test / feed-back
  loop to map record elements with RE2 patterns, assesses the result against a
  profile, and writes a report and an extraction pack. Actions `survey`,
  `audit`, `resume`, `assess`.

`log_pattern_analyzer` itself is unchanged. Its discover mode was not reusable:
it masks only IPs, dates and numbers, so free text keeps every distinct word
and a large file yields thousands of signatures. The auditor has its own
Drain-style clusterer.

## Decisions taken, and why

The full list is in the spec, section 2. The ones that shape behaviour:

- **Two plugins joined by a JSON profile**, not one. The reading of a standard
  is done once and can be reviewed and edited; audits are then repeatable. A
  hand-written profile for an internal standard uses the same file.
- **`assessable_from` is the answer to the boilerplate problem.** Retention,
  protection and review requirements are kept and reported as out of reach of a
  log sample, never as met or unmet.
- **RE2 via `google-re2`** (new dependency in the `plugins-log-analysis`
  extra). Stdlib `re` has no timeout and a plugin thread cannot be killed. RE2
  is also BigQuery's dialect.
- **A generated profile is `draft_unreviewed`** and an audit against one says
  so first. Each requirement's quote is searched for in locally extracted text
  and flagged when absent.
- **Findings describe rather than certify.** There is no "compliant" state.
- **Stopping short is a status.** A 600 s plugin limit against heavy-tier calls
  makes an incomplete mapping an ordinary outcome; `resume` continues it.
- **No URL input.** The operator mentioned pointing at a URL; no plugin makes
  outbound calls today, so this was left out and the standard is loaded as an
  artifact. A separate change if wanted.

Two additions beyond the approved plan:

- **`assess` action.** Re-tests saved patterns against a log with no model
  call. It fell out of building the deterministic half first, and it is the
  cheap way to re-check the same application later.
- **`logging_standard_profiler` is also in `DEFAULT_AUTO_EXPORT_TOOLS`**, not
  only the auditor. The profile is the file a person has to review, so it needs
  to reach the bucket on Cloud Run.

One item in the plan was **not done**: a section in
`docs/guides/Event_Mill_Starter_Guide.md`. That file has uncommitted edits in
the working tree and was left alone.

## Files

New:
- `plugins/log_analysis/logging_standard_profiler/` (`tool.py`,
  `extraction.py`, `profile_schema.py`, `catalogue.json`, manifest, schemas,
  examples including a hand-written `profile.example.json`, README, 49 tests)
- `plugins/log_analysis/log_compliance_auditor/` (`tool.py`, `survey.py`,
  `validators.py`, `mapping_loop.py`, `assessment.py`, `renderers.py`,
  manifest, schemas, example, README, 77 tests)
- `docs/specs/log_compliance_audit.md`

Changed:
- `pyproject.toml`: `google-re2>=1.1` in `plugins-log-analysis`
- `framework/cli/shell.py`: `DEFAULT_AUTO_EXPORT_TOOLS` gains both tools
- `framework/routing/config/keywords.json`: four `log_analysis` keywords
- `docs/specs/reserved_vocabulary.md`: new section 7a
- `cloud_install/README.md`: auto-export default

No manifest schema change. Both manifests validate against
`docs/specs/manifest_schema.json` (asserted by a test in each plugin).
`validate_manifests.py` passes both and still exits non-zero on its
pre-existing errors, none of which come from these plugins.

## Verified

- `pytest -q tests/ plugins/`: 2017 passed, 1 skipped (was 1891).
- Both plugins loaded by the real `PluginLoader` and driven through the real
  shell with `run`: `validate_profile`, `survey` and `assess` end to end with
  artifact ids, typed flags, six registered output artifacts, and a mistyped
  flag named. `audit` reached `LLM_UNAVAILABLE` as expected with no model.
- A scripted two-round audit of a 1,000-record fixture built to the awkward
  cases: timestamp last, program first, custom codes, a second shape with a
  coarser timestamp, JSON lines, stack-trace continuations, junk lines. Record
  counts per requirement are asserted exactly.
- A pattern that is exponential under a backtracking engine completes over
  2,000 long lines in bounded time.
- Every BigQuery single-group regex returns what the tested pattern captured.

## Not verified

- **No live model run of either plugin.** The scripted tests were written by
  the author of the code, which this repository has repeatedly found does not
  catch what a real reply does. Unknown: how a model sorts a real standard,
  whether real replies match the pattern shape, how many rounds a real log
  takes, whether 480 s is enough.
- Native PDF ingestion was exercised with a fake client only.
- Splunk and Elastic renderings were not loaded into either product. The
  BigQuery SQL was not executed; only its regexes were.
- Nothing was run on Cloud Run.
- Clustering thresholds and sample sizes are untuned.
- `ruff` reports only line-length and `timezone.utc` style findings on the new
  code, in line with the rest of the tree. `mypy` was not run.

## A note on the standard named

I do not know of an SP 800-92 "r3"; the editions I know of are the 2006
original and a Rev. 1 draft, and this was not checked online. Whichever
edition is used, it is log management guidance and says little about record
content, so most of it should land under `not_assessable_from_sample`. SP
800-53 AU-3 and AU-8 state record content directly and would exercise the
auditor more.

## Suggested first live runs

1. `extract_profile` on a short internal standard, then read the profile for
   requirements that are plausible rather than correct, and check the
   `quote_not_found` ones.
2. `audit` on two real application logs of different shapes, one provider.
   Note rounds used, lines sent, elapsed time against the budget.
3. The same audit on a second provider.
