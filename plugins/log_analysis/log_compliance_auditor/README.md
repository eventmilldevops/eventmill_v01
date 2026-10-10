# Log Compliance Auditor

**Tests whether the records in a log sample contain what a logging standard
requires, and produces tested extraction patterns for ingesting that log.**

It is built for application and service logs that follow no convention: the
timestamp at the end of the line, the program name first, event codes nobody
else uses. Such logs still repeat a handful of record shapes over and over, and
that repetition is what the tool works on.

Spec: `docs/specs/log_compliance_audit.md`.

## How it works

1. **Survey.** The whole file is read locally and its lines grouped into rough
   shapes. JSON lines are recognised as such.
2. **Propose.** A model is shown a few dozen lines of each shape, at most 200
   lines in total, with the list of record elements the standard asks for. It
   returns one pattern per record shape: a regex with named groups, and which
   element each group holds.
3. **Test.** Every pattern is run over **every record in the file**, here in
   the container. Each captured value is checked against what it was claimed
   to be: a timestamp must parse with the stated format and fall in a sane
   range, an address must be an address, an integer an integer.
4. **Feed back.** Only the failures go back to the model: the values that
   failed their check and a sample of the lines nothing matched. Steps 2 to 4
   repeat until the patterns cover the file and the values hold, or a round
   improves nothing, or the round or time limit is reached.
5. **Assess.** The confirmed elements are joined to the requirement profile and
   each requirement gets a finding with the record counts behind it.

The file is never uploaded. The result states exactly how many lines and
characters were sent.

## Inputs

- A log file, loaded as a `log_stream` or `text` artifact.
- A requirement profile from `logging_standard_profiler`, or one written by
  hand. See that tool's README.

## Actions

| Action | Model | What it does |
|---|---|---|
| `survey` | none | Record count, container format, record shapes with samples. No profile needed. |
| `audit` | heavy tier, one call per round | The loop above, the report and the extraction pack |
| `resume` | heavy tier | Continue an incomplete audit from its result artifact |
| `assess` | none | Re-test saved patterns against a log and re-assess |

```
run log_compliance_auditor --action survey --artifact_id art_log

run log_compliance_auditor --artifact_id art_log --profile_artifact_id art_profile

run log_compliance_auditor --action resume --artifact_id art_log \
    --profile_artifact_id art_profile --state_artifact_id art_result

run log_compliance_auditor --action assess --artifact_id art_newlog \
    --profile_artifact_id art_profile --state_artifact_id art_spec
```

`assess` is the cheap way to re-check the same application later: point it at
a new sample and the extraction spec from an earlier audit. It also accepts a
spec whose patterns you have edited by hand.

Options: `--max_rounds` (default 4), `--target_coverage` (0.98),
`--sample_lines` (160, at most 200), `--max_records` (default: whole file),
`--time_budget_seconds` (480), `--thinking_level` (medium).

## Reading the result

The summary and the report lead with how mapping ended:

| `status` | Meaning |
|---|---|
| `converged` | Patterns cover the target share of records and every mapped value passes its check |
| `stopped_round_limit`, `stopped_time_budget`, `stopped_no_progress`, `stopped_llm_failure` | Mapping is incomplete. Findings cover only the records matched so far. Use `resume`. |
| `assessed_without_model` | `assess` re-tested saved patterns |

An incomplete run is a normal outcome, not an error. The tool has ten minutes
and a heavy-tier call can take two or three of them, so it stops starting new
calls with time in hand and saves what it has.

Each requirement gets one of five findings:

| Finding | Meaning |
|---|---|
| `observed` | Every required element was captured, with valid values, in at least 99% of **all** records |
| `partially_observed` | In some records and not others. The report shows which record types fall short and why. |
| `not_observed` | No record carried all the required elements |
| `not_assessable_from_sample` | The requirement is about retention, protection, review or the like. A log file cannot show it either way. |
| `not_evaluated` | The requirement is about records but names no catalogue element, so nothing was tested |

**None of these means compliant.** The report describes what this sample
contains. It cannot see events the application never logged, and it does not
judge whether the right events are being recorded.

Records that no pattern matched count against every requirement, because
nothing is known about them. Their shapes are listed under `unmatched_groups`.

Value flags such as `year_absent`, `no_timezone`, `constant_value` and
`out_of_order` are observations for a reader. None of them fails a check.

## Outputs

Six artifacts per audit, stamped with the UTC run time:

| File | Contents |
|---|---|
| `..._result_<stamp>.json` | Everything: findings, patterns, per-round history, what was sent. `resume` and `assess` read this. |
| `..._report_<stamp>.md` | The alignment report |
| `..._extraction_spec_<stamp>.json` | The tested patterns: record types in match order, named-group regex, field types, timestamp formats, fill and validity rates |
| `..._bigquery_<stamp>.sql` | `REGEXP_EXTRACT` query per record type |
| `..._splunk_props_<stamp>.conf` | `EXTRACT-` stanzas |
| `..._elastic_pipeline_<stamp>.json` | Ingest pipeline with grok and date processors |

The extraction spec is the tested artefact. The patterns are RE2, which is
BigQuery's own dialect, so the BigQuery regexes are the ones that were tested;
the SQL around them has not been executed. The Splunk and Elastic files are
renderings of the same patterns into those products' syntax and have **not been
run against either product**. Both say so in their header.

On Cloud Run all six are exported to the common bucket automatically. The
result and the report contain sample lines and example values from the log, so
treat them with the same care as the log.

## Why RE2

Patterns here are written by a model and run over files of a hundred thousand
lines or more. Python's `re` backtracks and has no timeout, so one badly
nested pattern could hold a run until the container killed it. RE2 runs in
time linear in the input. The cost is that lookahead, lookbehind and
backreferences are unavailable; a proposal that uses them is refused and the
reason sent back.

## Limitations

- **A multi-line record is read by its first line.** Indented lines and stack
  traces are joined to the record above and counted, not parsed.
- **Record counts for a requirement are an upper bound when it needs several
  elements.** The pass keeps per-field counts, not per-record combinations, so
  the smallest field count is reported as the number of records carrying all
  of them.
- **Timestamps without a year** (classic syslog) parse and are flagged
  `year_absent`; their plausibility is not checked.
- **`allowed_values`** is checked exactly for fields with up to 200 distinct
  values and from the most common values beyond that, which understates.
- **Sample lines go to the model provider selected with `use`.** If the log
  holds credentials or personal data, so may the sample. Lines are cut at 1,000
  characters; nothing is masked.
- Splunk and Elastic output is unexecuted, as above. `TIME_PREFIX` is not set.
- Requires `google-re2` (the `plugins-log-analysis` extra).
