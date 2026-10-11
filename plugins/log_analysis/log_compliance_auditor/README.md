# Log Compliance Auditor

**Tests whether the records in a log sample contain what a logging standard
requires, and produces tested extraction patterns for ingesting that log.**

It is built for application and service logs that follow no convention: the
timestamp at the end of the line, the program name first, event codes nobody
else uses. Such logs still repeat a handful of record shapes over and over, and
that repetition is what the tool works on.

It answers two questions, and keeps them apart:

- **Is there enough in these records to support an investigation?** A table of
  seven things an investigator needs (when, what, who, and so on), counted
  from the records, beside a grade of how plainly the standard asks for each.
- **Which clauses of the standard does this sample meet?** One finding per
  requirement, with the record counts behind it.

Spec: `docs/specs/log_compliance_audit.md`. Why the report is built this way:
`docs/adr/0001-grade-the-standard-and-the-log-against-fixed-categories.md`.

## How it works

1. **Survey.** The whole file is read locally and its lines grouped into rough
   shapes. JSON lines are recognised as such.
2. **Propose.** A model is shown a few dozen lines of each shape, at most 200
   lines in total, with the list of record elements to look for: those
   the standard asks for, and those of the seven investigation categories
   whatever the standard says. It returns one pattern per record shape: a regex with named groups, and which
   element each group holds.
3. **Test.** Every pattern is run over **every record in the file**, here in
   the container. Each captured value is checked against what it was claimed
   to be: a timestamp must parse with the stated format and fall in a sane
   range, an address must be an address, an integer an integer.
4. **Feed back.** Only the failures go back to the model: the values that
   failed their check and a sample of the lines nothing matched. Steps 2 to 4
   repeat until the patterns cover the file and the values hold, or a round
   improves nothing, or the round or time limit is reached.
5. **Assess.** Coverage of the seven categories is counted from the records.
   Then the confirmed elements are joined to the requirement profile and each
   requirement gets a finding with the record counts behind it.

The file is never uploaded. The result states exactly how many lines and
characters were sent.

## Syslog, and logs that are a header plus free text

Syslog fixes the header and leaves the message to each program, so one file
holds as many message formats as it has programs. The tool handles the two
parts differently:

- **The header is parsed by the tool, not proposed by a model.** When at least
  90% of the first 2,000 records fit a syslog envelope (BSD / RFC 3164, the
  same with an ISO 8601 timestamp, or RFC 5424), the timestamp, host, program
  and process id come from a fixed pattern. They are the same in every run.
  The result says how many records fit, how many carry a PRI value and how
  many a process id.
- **The message is kept whole as one element, then broken down per program.**
  Sample messages are grouped by program and the model writes patterns for one
  program's messages at a time. A message pattern is joined to the header
  pinned to its program, so it cannot take another program's records. Messages
  of different programs are never compared.
- **A record no message pattern takes still has its header.** It falls to the
  header-only record type `envelope`, with its message whole.

The same idea guards other logs. A pattern such as timestamp, level and `.*`
matches every line and finds nothing in it. When a pattern takes at least 5%
of the file and one free-text field holds half or more of each line, the next
round shows the model what that field is holding and asks for specific
patterns. If that changes nothing the text is accepted as prose and the result
says how many records are held that way.

`depth` in the result, and the report's opening section, give the count of
records broken down beyond a free-text field. The loop keeps asking until that
is 85% of records or a round adds nothing.

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

### What an investigation needs from each record

The report's first table, and the one to read first:

| An investigator needs | Elements | Records | Share | Log | Standard |
|---|---|---|---|---|---|
| Who or what did it | actor_identity | 200 of 200 | 100.0% | 5 of 5 | 4 of 5 |
| Where it came from | host (6), source_component (182), source_address (194) | 200 of 200 | 100.0% | 5 of 5 | 5 of 5 |
| What links it to related events | session_id | 184 of 200 | 92.0% | 5 of 5 | 3 of 5 |
| What was acted on | target_object | 152 of 200 | 76.0% | 4 of 5 | 4 of 5 |

The seven categories are fixed, in the catalogue:

| Category | An investigator needs | Elements, any one of |
|---|---|---|
| `when` | When it happened | `timestamp` |
| `what` | What happened | `event_type` |
| `who` | Who or what did it | `actor_identity` |
| `outcome` | How it ended | `outcome` |
| `where` | Where it came from | `host`, `source_component`, `source_address` |
| `link` | What links it to related events | `session_id` |
| `target` | What was acted on | `target_object` |

- **`Log`** is the share of records carrying any one of the category's
  elements with a valid value, in five bins: 1 is under 20%, 2 the 20s, 3 the
  40s, 4 the 60s and 70s, 5 is 80% or better. It is counted from the records
  and does not read the requirements.
- **`Standard`** is the profiler's grade of how plainly the standard requires
  the category, also 1 to 5. See the profiler's README for the rubric. If the
  profile carries no grade, or one older than its last edit, the report says
  so and how to refresh it.

Read the two together:

| Log | Standard | What it points at |
|---|---|---|
| low | high | A gap in the application's logging. The standard is clear and the records fall short. |
| high | low | The log is ahead of the standard. Tighten the clause, or the next application may not be. |
| low | low | Both. Fix the clause first, or the gap cannot be called a finding. |

Under the table the report lists every category graded below 5, with the
reason and the clauses it was read from.

### Findings per requirement

Each requirement gets one of five findings:

| Finding | Meaning |
|---|---|
| `observed` | Every required element was captured, with valid values, in at least 99% of **all** records |
| `partially_observed` | In some records and not others. The report shows which record types fall short and why. |
| `not_observed` | No record carried all the required elements |
| `not_assessable_from_sample` | The requirement is about retention, protection, review or the like. A log file cannot show it either way. |
| `not_evaluated` | The requirement is about records, but it is not a rule that an element must be present (a prohibition, a rule about value quality, a rule that some event is logged, a permission), or it names no catalogue element. Nothing was counted. |

A requirement can need several elements together, and can accept any one of a
group of alternatives (the profile's `any_of`). The report says which: "All
required elements present in ...", "At least one of the elements below is
present in ...", or a `Needs:` line when both apply. A `may` requirement is
marked `Optional`.

**Only presence rules are counted.** The report lists the others under
"Requirements about records that were not counted", grouped by kind, with how
many records carry the elements each one names. Those lines are reference for
a reviewer and are not findings: `message in 0 of 200` beside a rule that free
text must not be the only representation is good news, not a gap.

**None of these means compliant.** The report describes what this sample
contains. It cannot see events the application never logged, and it does not
judge whether the right events are being recorded.

Records that no pattern matched count against every requirement and every
category, because nothing is known about them. Their shapes are listed under
`unmatched_groups`.

Value flags such as `year_absent`, `no_timezone`, `constant_value` and
`out_of_order` are observations for a reader. None of them fails a check.

### Do not score the audit by counting findings

"Share of requirements observed" is not a stable number. It depends on how
the model that wrote the profile cut the standard into requirements. Two
profiles of the same standard, audited against the same log with the same
element counts, gave 7 of 10 and 9 of 11 observed: one model had left an
alternative out of a group, the other had counted three overlapping clauses.
The category table was identical for both. Use the table for an overall
judgement and the findings to locate the clause.

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

## Different models, different runs

A model reads the standard and a model maps the log, so two runs can differ,
and two vendors can differ more. The tool treats that the way an audit team
treats two auditors: it fixes what should not be a matter of opinion, labels
what is, and gives you the means to compare.

| What | Decided by | Moves between runs or models? |
|---|---|---|
| Record counts, value checks, coverage arithmetic, bins | Code | No |
| The seven categories and the clarity rubric | Catalogue and code | No |
| The syslog header | Code | No |
| Which field is which element | Model, then tested on every record | Sometimes, where a field is ambiguous |
| How the standard is cut into requirements, and each one's kind and groups | Model, then reviewed by a person | Yes |

What was measured on the example standard and its database sample log
(2026-10-11, Gemini and Anthropic heavy tier, each writing its own profile and
its own mapping):

- Both mapped every element to the same fields with the same record counts,
  from different record-type splits (11 types and 6).
- The profiles held 135 and 152 requirements. Of 126 sentences both quoted,
  118 were classified the same way.
- The category table was the same for both. The count of findings was not.
- Before the catalogue descriptions were reworded, one model mapped a
  transaction id as `session_id` in one run and `event_id` in another, moving
  `link` between 92% and 10%. After, three runs agreed. `target_object` still
  moved between 76% and 100% across those runs.

So when a category bin is low, look at the field table at the end of the
report before believing it: an element sitting unmapped beside a likely field
is a mapping question, not a logging gap. Running the audit on a second
provider (`use <provider> for log_compliance_auditor`) is the cheapest second
opinion, and the tool never switches provider on its own.

### Telling whether two runs agree

Each result carries what is needed:

- `run.inputs_fingerprint`: the log, profile, catalogue, prompt and plugin
  versions, settings and model. The same value means the same question.
- `run.outcome_fingerprint`: the findings and what each element captured.
- `assessment.elements.<name>.signature`: a hash of `(line, value)` for every
  record that carried the element. Two runs that chose differently named
  fields or wrote different regexes still get the same signature when they
  captured the same values from the same records.
- `assessment.split_signature`: the same idea for how the file was divided
  into record types.
- `assessment.investigation_coverage`: the category table as data.

`scripts/audit_repeatability.py` runs the audit N times and reports agreement
per element and per finding. The figures below are from the example corpus
(four logs, five runs each, Gemini and Anthropic heavy tier) on 2026-10-10.
**They predate `any_of` groups, requirement kinds and catalogue 1.1.0** and
have not been re-measured; read them as the order of magnitude.

| | Result |
|---|---|
| Runs mapping at least 85% of records | 40 of 40 (lowest 99.2%) |
| Findings with the same state in at least 4 of 5 runs | 137 of 144 |
| Findings with the same state in all 5 runs | 122 of 144 |
| Majority finding the same on both providers | 66 of 72 |

On the two syslog samples `timestamp`, `host`, `source_component` and
`message` had the same signature in all 20 runs, and 97% to 100% of records
had their message broken down. `process_id` matched in 18 of 20: in two runs a
model also mapped a process id it found inside a message.

## Why RE2

Patterns here are written by a model and run over files of a hundred thousand
lines or more. Python's `re` backtracks and has no timeout, so one badly
nested pattern could hold a run until the container killed it. RE2 runs in
time linear in the input. The cost is that lookahead, lookbehind and
backreferences are unavailable; a proposal that uses them is refused and the
reason sent back.

## Limitations

- **A multi-line record is read by its first line.** Indented lines and stack
  traces (including the unindented `java.x.SomeException: ...` line that
  opens one) are joined to the record above and counted, not parsed.
- **Which field is which element is a judgment, and it varies.** Two audits
  of the same file can map different fields to an element. The record count
  behind a finding, and a category's coverage, move with the mapping.
- **The seven categories are fixed.** `severity`, `destination_address`,
  `event_id`, `process_id` and `message` belong to none, and a standard with a
  different idea of what a record needs is still graded against these seven.
- **Coverage counts presence.** A record that names a shared service account
  covers `who`. Whether that is enough to identify a person is not judged.
- **A conditional requirement is counted against every record.** "Where
  applicable" is not interpreted; the report lists the record types that
  fall short and leaves applicability to the reader.
- **This is a first look at a log, not a controlled audit.** Each run maps the
  log afresh. Measured over 40 runs on two providers, the finding for a
  requirement was the same in at least 4 of 5 runs 96% of the time; see
  *Different models, different runs* above. Nothing carries a mapping from one run to the next.
- **Timestamps without a year** (classic syslog) parse and are flagged
  `year_absent`; their plausibility is not checked.
- **`allowed_values`** is checked exactly for fields with up to 200 distinct
  values and from the most common values beyond that, which understates.
- **Sample lines go to the model provider selected with `use`.** If the log
  holds credentials or personal data, so may the sample. Lines are cut at 1,000
  characters; nothing is masked.
- **Envelope detection is syslog only.** Other fixed headers (a web server's
  combined log format, for instance) are left to the model like any other log.
- **A PRI value is captured, not decoded** into facility and severity.
- Splunk and Elastic output is unexecuted, as above. `TIME_PREFIX` is not set.
- Requires `google-re2` (the `plugins-log-analysis` extra).
