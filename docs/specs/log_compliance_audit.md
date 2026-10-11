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
  "catalogue": {"catalogue_version": "1.1.0", "elements": {"timestamp": {...}},
                "investigation_categories": [{"id": "when", "question": "...", "elements": ["timestamp"]}]},
  "standard_clarity": {"bins": 5, "requirements_sha256": "...", "categories": [...]},
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

A requirement about records also carries `kind`, which says what sort of
rule it is:

| Kind | The sentence asks | Counted |
|---|---|---|
| `presence` | A record carries an element, possibly in a stated format | Yes |
| `prohibition` | Something must not be in a record, or must not be done | No |
| `quality` | Values are correct, stable, consistent or unambiguous | No |
| `event_selection` | A kind of event is logged at all | No |
| `permission` | Something is allowed | No |

Counting the records that carry an element answers a presence rule and no
other. A prohibition scored that way reports the compliant case (the banned
thing is absent) as a shortfall, and an event-selection rule reports
"observed" whenever records have an event type at all. So only `presence` is
counted; the others are listed in the report with what the sample holds for
their elements, for a person to judge.

`kind` is null for `not_assessable_from_sample`. A profile without `kind` is
read as all `presence`. When a profile is extracted, a requirement whose quote
is worded as a ban ("shall not", "must not", "never", "prohibited") and that
the model called `presence` is set to `prohibition`: a wrong label may cost a
finding and may not invent one. That rule is applied at extraction only, so a
reviewer's edit stands.

An entry in `elements` is one of two things:

- `{"element": name, "constraints": {...}}`: the record must carry it.
- `{"any_of": [{"element": a}, {"element": b}], "label": "origin"}`: the record
  must carry at least one member. For a clause that lists interchangeable ways
  to satisfy one thing ("a host, service, component or other stable
  identifier"). At least two members; `label` is optional and only for the
  report. An element may appear in more than one group.

Entries side by side are all required. A profile written before groups existed
is a list of plain entries and is read as it always was.

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

### 5a. Envelopes and depth

Coverage alone does not show that a log was understood: a header followed by
`.*` matches every record. Two mechanisms address that.

**Syslog envelope.** `survey.detect_envelope` tries three fixed header regexes
(RFC 5424, BSD / RFC 3164, BSD with an ISO 8601 timestamp) on the first 2,000
records and adopts one when at least 90% fit. From then on:

- The header pattern is the tool's own (`pattern_id: envelope`), held from the
  start and ordered last. Its element mapping is fixed: `timestamp`, `host`,
  `program` as `source_component`, `pid` as `process_id`, `message`, and for
  RFC 5424 `msgid` as `event_type`. PRI is captured and left unmapped.
- Clustering is done on the message and separately per program.
- The model is asked for `{"program", "message_regex", "fields"}`. The tool
  composes the whole-line regex as header (pinned to that program) plus the
  message regex wrapped in the `message` group. A group named like a header
  field is renamed with a `msg_` prefix.
- An optional header field that is always empty for a program, such as a
  process id the kernel does not write, is not a failing field.

**Under-split check.** `shallow_patterns` flags the envelope pattern, and any
other regex pattern that takes at least 5% of the file (and 20 records) and
has one field, unmapped or mapped to `message`, holding at least half the
characters of its records with values that vary. `depth` is the share of
records not taken by such a pattern.

The loop's finishing rule is now: coverage at target, no failing field, and
either depth at `target_depth` (0.85) or one round already spent without gain.
A round's candidates are compared on depth as well as coverage. In a later
round the model is shown clustered samples of what the shallow patterns hold.

## 6. Assessment

The test pass records, for every record, which elements it carried with a
valid value, the timestamp's timezone and precision, and the value of any
element a requirement restricts. A requirement's count is the number of
records whose combination carries every required element, and at least one
member of every `any_of` group, meeting their constraints. Each finding has
`needs`: one entry per required element or group, with the records that
filled it.

A requirement whose `kind` is not `presence` gets no count: its state is
`not_evaluated`, `basis` says why, and `reference_elements` gives the records
carrying each element it names. `not_counted_by_kind` totals them. The count is exact; `count_is_exact` is false only when a record
type had more than 5,000 distinct combinations.

### 6a. Comparing two runs

A model proposes the mapping, so repeat runs can differ. A result identifies
itself in two ways:

- `run.inputs_fingerprint` hashes the log, profile, catalogue version, prompt
  version, plugin version, settings, provider and model. Equal fingerprints
  mean the same question was asked.
- `run.outcome_fingerprint` hashes the findings and each element's signature.

An element's signature hashes `(line number, value)` over every record that
carried it; a record type's `line_signature` hashes the line numbers it took.
Both identify a mapping by what it captured, so different field names and
different regexes that capture the same thing compare equal.

Scope decision (2026-10-10): this tool assesses a log as though nobody has
seen it before. Pinning a reviewed mapping, comparing audits over time and
carrying review decisions forward belong to a longer-running audit tool and
are out of scope here. `scripts/audit_repeatability.py` measures agreement
between repeat runs; the measured figures are in the auditor's README.

### 6b. Investigation coverage and the clarity of the standard

Findings per requirement depend on how a model cut the standard into
requirements. Two profiles of one standard gave 70% and 82% "fully observed"
for the same log while agreeing on every count underneath. Two measures are
reported that do not have that weakness. Both use seven categories, held in
the catalogue as `investigation_categories`:

| Category | An investigator needs | Elements, any one of |
|---|---|---|
| `when` | When it happened | `timestamp` |
| `what` | What happened | `event_type` |
| `who` | Who or what did it | `actor_identity` |
| `outcome` | How it ended | `outcome` |
| `where` | Where it came from | `host`, `source_component`, `source_address` |
| `link` | What links it to related events | `session_id` |
| `target` | What was acted on | `target_object` |

**Coverage of the log** (`assessment.investigation_coverage`, auditor). Per
category, the records carrying at least one of its elements with a valid
value, over all records. It is counted from the records and the field mapping
and does not read the requirements. The auditor asks the model to map the
category elements whether or not the standard requires them. The share lands
in one of five bins: under 20%, 20s, 40s, 60s, and 80% or better.

**Clarity of the standard** (`standard_clarity` in the profile, profiler).
Per category, bin 1 plus one for each criterion met:

| Criterion | Met when |
|---|---|
| countable | A presence rule names an element of the category |
| mandatory | Such a rule is `must` |
| specific | Such a rule needs the category on its own: a required element, or a group whose members are all in the category |
| unconditional | A rule meeting all three is not hedged ("where applicable", "when needed", "where feasible", "to the extent") |

Bin 1 with `addressed: false` means no requirement about records names the
category. Each grade lists the clauses behind it and the criteria it lacks.
It grades the profile's reading of the standard, so a poor extraction lowers
it as poor wording does.

The grade carries `requirements_sha256`. The auditor does not compute the
rubric; it shows the stored grade and reports it `absent` or `out_of_date`
when the digest no longer matches the requirements. `validate_profile`
recomputes the grade and, when the stored one is missing or stale, writes a
copy of the profile that carries it.

The mapping still decides which field is which element, so coverage can move
between runs where a field is ambiguous. See section 9.

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
  file. Measured: the finding's state held in at least 4 of 5 runs for 138 of
  144 cases; the record count behind it moved more often.
- On free-text syslog, Gemini returned a two-pattern split (header plus
  message) in 3 of 5 runs, which mapped every record and almost no elements.
  Section 5a was added for this. Re-measured: Gemini's syslog findings held
  in at least 4 of 5 runs for 18 of 18 (was 14), and the two providers'
  majority findings agreed for 17 of 18 (was 12).
- A conditional requirement ("where applicable") is counted against every
  record.

## 10. Later

- URL input for the standard.
- Multi-line record bodies.
- An applicability field on a requirement, so a conditional one is not
  counted against record types it does not apply to.
- `record_set` checks beyond timestamp ordering: gaps, expected event kinds.
- Masking of sample lines before they are sent.
