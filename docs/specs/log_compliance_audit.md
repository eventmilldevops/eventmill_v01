# Log compliance audit

Two plugins in `plugins/log_analysis/` that together answer one question: does
an application's log output contain what a logging standard requires?

| Plugin | Input | Output |
|---|---|---|
| `logging_standard_profiler` | A standard (PDF or text) | A requirement profile (JSON) |
| `log_compliance_auditor` | A log sample and a profile | An alignment report and an extraction pack |

Status: built 2026-10-10 and run live the same day on one provider against
the example corpus in `plugins/log_analysis/examples/`. Section 9 lists what
that covered and what it did not.

## 1. Why two steps

A standard is read once and audited against many times. Reading it is the
judgment-heavy part and its result has to be reviewable, so it is a separate
step with a durable, editable output. Every audit after that is repeatable
against the same profile, and two audits can be compared because they asked the
same questions.

The profile is also the seam for internal standards: a person can write one by
hand and skip the profiler entirely.

Neither plugin imports the other. The profile carries its own copy of the
element catalogue, so the auditor reads the catalogue the profile was written
against.

## 2. Decisions

1. **The profile separates what a log can show from what it cannot.** Each
   requirement carries `assessable_from`. Retention, protection and review
   requirements are kept, labelled `not_assessable_from_sample`, and reported
   as out of reach. They are never counted as met or unmet.
2. **Elements are a closed catalogue of fourteen.** A requirement the catalogue
   cannot express is kept with `elements: []` and an `unmapped_reason`, and the
   audit reports it `not_evaluated`. A model-supplied element name outside the
   catalogue is dropped at normalisation, never tested as though it meant
   something.
3. **Every requirement carries a verbatim quote, and the quote is checked.**
   The profiler extracts the document's text locally and searches for each
   quote, ignoring case, whitespace, line-break hyphenation and typographic
   quotes. A miss sets `quote_status: quote_not_found`. It is a flag for the
   reviewer, not a rejection.
3a. **One read is not exhaustive, so coverage is counted and swept.** A live
   run quoted 25 of 144 obligation sentences however the prompt was worded.
   The profiler now finds every sentence worded shall, must, should or
   required in the local text, and a second call classifies the ones the
   first read left unquoted. A swept requirement's quote is the local
   sentence, not model text. The profile's `statement_coverage` block
   accounts for every such sentence: quoted, added by the sweep, judged not
   a requirement (with the reason), or not classified. It is a wording
   match, so it over-collects, and a requirement worded another way is seen
   only by the first read.
4. **A generated profile is `draft_unreviewed`.** Only a person sets
   `reviewed`. An audit against a draft says so first, in the summary and the
   report.
5. **Patterns are RE2.** Stdlib `re` has no timeout and a plugin thread cannot
   be killed, so a model-written catastrophic pattern would hang the run. RE2
   is linear-time. It is also BigQuery's dialect and a subset of what Splunk
   and Elastic accept, so the tested pattern is the shipped pattern.
6. **A pattern must match the whole line and name every group.** It is a
   splitter, not a finder. The first pattern that matches takes the record;
   order is most fields first.
7. **The model sees a sample; the file is tested whole.** At most 200 lines in
   the first round and 30 unmatched lines per later round, each cut at 1,000
   characters. The result records lines, characters and calls sent.
8. **Clusters are sampling strata, not record types.** The Drain-style
   clusterer only decides which lines to show. Record types are the patterns
   that survive testing.
9. **A revision is adopted only if it is not worse.** A round's candidate set
   replaces the held set when coverage does not fall and failing fields do not
   rise, or when coverage rises by more than a point. Otherwise it is discarded
   and the model is told.
10. **Stopping short is a status, not an error.** `stopped_round_limit`,
    `stopped_time_budget`, `stopped_no_progress` and `stopped_llm_failure`
    return `ok` with whatever was mapped, and `resume` continues. Only a run
    that ends with no usable pattern fails (`MAPPING_FAILED`). State is written
    to disk before each model call so a run cut off mid-call loses one round.
11. **Findings describe, they do not certify.** `observed` means the elements
    were captured with valid values in at least 99% of all records in this
    sample. Unmatched records count against every requirement.
12. **Value flags are observations.** `constant_value`, `year_absent`,
    `no_timezone`, `out_of_order`, `high_cardinality_for_a_category` and
    `mostly_empty` inform a reader and fail nothing.
13. **Both plugins are heavy tier, not auto-invocable, `experimental`.** The
    auditor sends raw log lines to a vendor.
14. **No URL input.** No plugin makes outbound calls today; the standard is
    downloaded and loaded as an artifact.

## 3. Profile shape

```json
{
  "profile_version": "1.0",
  "standard": {"title": "...", "version": "...", "source_file": "...",
               "document_sha256": "...", "pages": 14},
  "provenance": {"generated_by": "...", "provider_id": "...",
                 "model_version": "...", "transport": "..."},
  "review_status": "draft_unreviewed",
  "catalogue": {"catalogue_version": "1.0.0", "elements": {"timestamp": {...}}},
  "requirements": [
    {
      "requirement_id": "4.2.1",
      "section": "4.2 Record content",
      "page": 7,
      "obligation": "must",
      "assessable_from": "record_content",
      "summary": "...",
      "quote": "...",
      "quote_status": "found",
      "elements": [{"element": "timestamp",
                    "constraints": {"timezone_required": true,
                                    "min_precision": "millisecond"}}],
      "unmapped_reason": null
    }
  ]
}
```

A complete hand-written example is
`plugins/log_analysis/logging_standard_profiler/examples/profile.example.json`.
Enumerations are in `docs/specs/reserved_vocabulary.md` section 7a.

## 4. Pattern shape

What the model returns and what the extraction spec stores:

```json
{"pattern_id": "auth", "kind": "regex",
 "regex": "^(?P<program>[\\w.-]+)\\[(?P<pid>\\d+)\\] ... @(?P<ts>\\S+)$",
 "fields": {"program": {"element": "source_component"},
            "ts": {"element": "timestamp", "format": "iso8601"},
            "bytes": {"element": null}}}

{"pattern_id": "api", "kind": "json",
 "fields": {"time": {"element": "timestamp", "format": "epoch_ms"},
            "user.name": {"element": "actor_identity"}},
 "requires": ["time"]}
```

A field with `element: null` is extracted for ingestion and plays no part in
the assessment. A timestamp `format` is a strptime format or one of
`iso8601`, `epoch_s`, `epoch_ms`, `epoch_us`.

## 5. The loop

```
survey ──> propose ──> test over whole file ──> converged? ──> assess, render
              ^                 │
              └── feedback <────┘  failing values, unmatched lines,
                                   proposals that could not be used
```

Convergence: coverage at or above `target_coverage` (0.98) and no mapped field
below `target_pass_rate` (0.99). Stop conditions: round limit (4), two rounds
without improvement, a failed model call, or less than 150 s left of the time
budget (480 s of the plugin's 600 s).

Value checks by type:

| Type | Passes when |
|---|---|
| `timestamp` | Parses with the claimed format, and is between 1990 and two days from now when it has a year |
| `address` | Is an IP address, or a hostname. `ip:port` fails. |
| `integer` | Optional sign and digits |
| `identifier` | No whitespace |
| `category` | 64 characters or fewer |
| `identity`, `text` | Non-empty |

`-`, `null`, `n/a` and similar count as empty, not invalid. When a timestamp
field fails, the feedback names a known format that does parse the failing
values, if one exists.

## 6. Assessment

For each testable requirement and each record type, the field carrying each
required element is found, and the count of its valid values that also meet
the element's constraints is taken. The record type's count for the
requirement is the smallest of those. Counts are summed over record types and
divided by all records.

This is an upper bound when a requirement needs several elements: the pass
keeps per-field counts, not per-record combinations.

## 7. Outputs

Six artifacts per audit: result JSON, Markdown report, extraction spec,
BigQuery SQL, Splunk `props.conf`, Elastic ingest pipeline. The spec's
`execution` block states what each was subjected to:

| Output | `execution` |
|---|---|
| Extraction spec | `tested_against_sample` |
| BigQuery | `regex_dialect_tested_sql_not_executed` |
| Splunk, Elastic | `rendered_not_executed` |

A test re-runs every BigQuery single-group regex through RE2 on the fixture and
requires it to return what the tested pattern captured.

## 8. Untrusted shape

Every model-controlled field is normalised before use, and a malformed item
costs itself, not the run:

- Profiler: a requirement with the wrong types is coerced or dropped with a
  note; a reply cut off mid-array has its complete requirements salvaged.
- Auditor: a pattern that does not compile under RE2, has unnamed or no named
  groups, or is not an object is refused, and the reason is sent back in the
  next round.
- Prior state read by `resume` and `assess` goes through the same
  normalisation, because a person may have edited it.

Failure messages carry the diagnosis: which round, what came back, where state
was saved.

## 9. Verified live, and not yet

Run live on 2026-10-10 (Gemini heavy tier, through the shell); details in
`docs/change_log/2026-10-10-log-compliance-live-runs.md`:

- The profiler on a 14-page standard: 122 requirements in two calls, 145 s.
- The auditor on a key-value database audit log (200 records, 11 record types,
  2 rounds, 58 s) and a Tomcat log with stack traces (240 records, 12 record
  types, 1 round, 64 s). Record counts match the corpus ground truth; actor
  counts for the database log match exactly.

Not yet:

- Any provider but Gemini.
- `resume` against a real model; neither audit stopped short.
- A file larger than 249 lines against a real model, so the 480 s budget is
  untested where it matters.
- Classic syslog input (no year in the timestamp).
- The Drain similarity threshold (0.5) and the sampling sizes were chosen, not
  tuned.
- Splunk and Elastic renderings have not been loaded into either product.

Known from those runs and not addressed:

- Which field a model maps to `event_type` varies between runs on the same
  file, and the finding moves with it. Pin the mapping in the extraction spec
  and use `assess`.
- A conditional requirement ("where applicable") is counted against every
  record.

## 10. Later

- URL input for the standard.
- Multi-line record bodies.
- Per-record element combinations, to turn the upper bound into a count.
- An applicability field on a requirement, so a conditional one is not
  counted against record types it does not apply to.
- `record_set` checks beyond timestamp ordering: gaps, expected event kinds.
- Masking of sample lines before they are sent.
