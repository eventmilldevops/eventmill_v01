# 2026-10-10 — Logging compliance: repeatability measured, scope set, syslog envelope

Follows `2026-10-10-log-compliance-live-runs.md`, which found that two audits
of the same log could disagree.

## Scope decision

A plan to make audits repeatable was approved and then narrowed by the
operator part-way through step 1:

> This is a preliminary assessment tool; managing state for a longer running
> audit tool is out of scope. The function of this version is to assess a new
> log as if the user has never seen it before.

An auditor reviewing many application log samples makes a cursory pass over a
point-in-time sample, and an analyst investigating an incident can work around
some inconsistency. The stated bar: about 85% coverage on 4 of 5 runs, on two
different models, may be acceptable.

**Dropped as out of scope, none of it built:** pinned mapping baselines per log
source, a `compare` action, carrying review decisions into a regenerated
profile, shipping a reviewed profile. Also not built from the plan: split-then-
assign mapping rounds, catalogue precedence rules, candidate ranking, majority
voting, sentence-first requirement ids. The measurement below is why: the bar
is met without them. The loop's finishing rule did change later the same day,
with the under-split check described further down.

## What was built

- **Exact counts.** The test pass now records per record which elements it
  carried with a valid value. A requirement needing several elements is
  counted exactly, replacing the per-field upper bound. `count_is_exact` on
  each finding.
- **Signatures.** An element's signature hashes `(line, value)` for every
  record that carried it; a record type's hashes its line numbers. Two runs
  that named fields differently or wrote different regexes compare equal when
  they captured the same thing.
- **Run fingerprints.** `run.inputs_fingerprint` (log, profile, catalogue,
  prompt and plugin versions, settings, provider, model) and
  `run.outcome_fingerprint` (findings and element signatures) in every result.
- **`scripts/audit_repeatability.py`.** Runs the audit N times through the
  real shell and reports agreement per element and per finding, optionally
  against a ground-truth value count.

`FieldStats.add` now returns what it decided about the value. Plugin version
0.2.0. `mapping_loop.PROMPT_VERSION` must be bumped when a prompt's wording
changes.

## Measurement

Four example logs, five audits each, two providers (Gemini
`gemini-3.1-pro-preview`, Anthropic `claude-opus-5`), heavy tier, thinking
level medium, against the 122-requirement draft profile of the YMMV standard
(18 requirements assessed against records). 40 runs, all `converged`.

| Log | Provider | Runs at 85%+ coverage | Findings same in 4+ of 5 | Same in all 5 | Elements same in 4+ of 5 | Mean time |
|---|---|---|---|---|---|---|
| database_audit (200) | Gemini | 5/5 | 18/18 | 17/18 | 8/9 | 41 s |
| database_audit | Anthropic | 5/5 | 18/18 | 17/18 | 8/9 | 42 s |
| catalina (240) | Gemini | 5/5 | 18/18 | 16/18 | 2/12 | 65 s |
| catalina | Anthropic | 5/5 | 17/18 | 14/18 | 7/12 | 63 s |
| auth (780) | Gemini | 5/5 | 17/18 | 11/18 | 7/11 | 47 s |
| auth | Anthropic | 5/5 | 18/18 | 16/18 | 8/13 | 41 s |
| syslog (3000) | Gemini | 5/5 | 14/18 | 10/18 | 5/12 | 30 s |
| syslog | Anthropic | 5/5 | 18/18 | 18/18 | 8/11 | 28 s |

- **Coverage:** lowest of the 40 runs was 98.9% of records mapped.
- **Findings:** the state was the same in at least 4 of 5 runs for 138 of 144
  finding/log/provider cases (96%), and in all 5 for 119 (83%).
- **Across providers:** the majority finding was the same on both for 62 of 72
  (86%): database 18/18, auth 17/18, catalina 15/18, syslog 12/18.
- **Ground truth:** database actor counts matched `actor_counts` in 10 of 10.
- **Cost:** 1 or 2 model calls and 55 to 112 log lines sent per run.

What the element column shows: a finding's *state* is much more stable than
the mapping under it. On the Catalina log Gemini agreed with itself on only 2
of 12 elements, yet every finding kept its state in at least 4 of 5 runs,
because `partially_observed` covers a wide range of counts.

Where it varied:

- `event_type`, `target_object` and `message` are the unstable elements on
  every log. `timestamp`, `host`, `outcome`, `actor_identity`,
  `source_address` and `process_id` are stable.
- **Gemini on the syslog sample is the weak case.** In 3 of 5 runs it returned
  two generic patterns (syslog header plus free-text message). That maps every
  record and almost no elements, so `actor_identity`, `outcome` and
  `target_object` came out `not_observed` where Anthropic, splitting into 6 or
  7 types, found them in part. Four findings there fell short of 4 in 5.
- The whole measurement is one profile and one corpus of synthetic logs.

## Under-split check and syslog envelope (added after the measurement)

Requested by the operator after the figures above, with the approach: validate
the syslog header against its specification, keep the message as a single
element, and compare messages only within one program.

- **Envelope.** Three fixed header patterns (BSD / RFC 3164, BSD with an ISO
  8601 timestamp, RFC 5424), adopted when 90% of the first 2,000 records fit.
  The header is the tool's own pattern with a fixed element mapping. The
  survey reports records fitting, PRI present, process id present, and the
  programs with their record and message-shape counts.
- **Per-program messages.** Clustering and sampling are per program; the model
  returns `program` plus `message_regex`; the tool joins it to the header
  pinned to that program. Records no message pattern takes fall to the
  header-only `envelope` record type with the message whole.
- **Under-split check for any log.** A pattern that takes 5% or more of the
  file with one free-text field holding half or more of each line gets one
  more round, shown what that field holds.
- **Finishing rule.** Coverage, value checks, and depth of at least 85% or a
  round without gain. `depth` is in the result, the summary and the report.

Re-measured, same corpus, profile and providers, five runs each:

| Log | Provider | Findings same in 4+ of 5 (before) | Same in all 5 (before) | Records with message broken down |
|---|---|---|---|---|
| syslog | Gemini | 18/18 (14) | 15/18 (10) | 97% to 99% |
| syslog | Anthropic | 17/18 (18) | 15/18 (18) | 99% |
| auth | Gemini | 18/18 (17) | 18/18 (11) | 98% |
| auth | Anthropic | 17/18 (18) | 17/18 (16) | 98% to 100% |
| database_audit | Gemini | 18/18 (18) | 14/18 (17) | n/a |
| database_audit | Anthropic | 17/18 (18) | 16/18 (17) | n/a |
| catalina | Gemini | 15/18 (18) | 13/18 (16) | n/a |
| catalina | Anthropic | 17/18 (17) | 14/18 (14) | n/a |

- **The target case moved.** Gemini on syslog: 14 to 18 of 18. Majority finding
  the same on both providers for syslog: 12 to 17 of 18. Gemini on auth, same
  state in all five runs: 11 to 18 of 18.
- **Header elements are now fixed.** `timestamp`, `host`, `source_component`
  and `message` had one signature across all 20 syslog and auth runs.
  `process_id` did in 18 of 20: in two Gemini auth runs a process id inside a
  message was mapped as well, for records whose header has none.
- **Totals barely moved.** 137 of 144 in at least 4 of 5 (was 138); 122 in all
  5 (was 119); 66 of 72 the same across providers (was 62). The database and
  Catalina logs have no envelope and no pattern there tripped the under-split
  check, so their code path is unchanged; the differences on those two logs,
  in both directions, are run-to-run variation at five runs a cell.
- **What still varies on syslog** is which message fields become `event_type`
  and `target_object`: 20% to 40% signature agreement on both providers.
- Syslog audits took one round each. Anthropic's mean time rose from 28 s to
  52 s; it now writes 30 to 40 message patterns in that round.
- Eight harnesses ran at once and Gemini returned transient errors on two
  runs, which the client retried; those runs took 169 s to 306 s. No run
  failed.

Not exercised live: the under-split check on a non-syslog log (scripted tests
only), RFC 5424 and ISO-timestamp syslog (unit-level regex only, no sample),
a syslog file with PRI values (scripted test only).

## Verified

- `pytest -q tests/ plugins/`: 2063 passed, 1 skipped. Of the new tests, 14
  cover the envelope and the under-split check and 5 cover exact combination
  counts, signatures that follow captured values and not regex text, and
  identical fingerprints for identical scripted runs.
- 80 live audits through the shell: 40 before the under-split check and 40
  after, all `converged`.

## Not verified

- OpenAI. A file over 3,000 lines. Anything on Cloud Run.
- `resume` against a real model: no run stopped short.
- The profiler was not re-run for this entry; every audit used the profile
  generated in `2026-10-10-log-compliance-live-runs.md`.

## State at hand-off

Branch `compliance_assessment`, head `4c39744`. Uncommitted: the auditor's
`assessment.py`, `mapping_loop.py`, `renderers.py`, `survey.py`, `tool.py`,
`validators.py`, its tests and README, `docs/specs/log_compliance_audit.md`,
`docs/specs/reserved_vocabulary.md`, this entry, and
`scripts/audit_repeatability.py`. The operator began live testing at this
point; results of that testing are not in this entry.

What an operator testing live should expect to see:

- For a syslog file, an `Envelope:` line in the summary, and `envelope` as the
  last record type.
- A log matched by a header-plus-free-text pattern costs one more model call
  than it did, and the summary says how many records are held as free text.
- Two audits of the same file can still report different record counts for
  `event_type` and `target_object`. `run.outcome_fingerprint` and the element
  signatures show whether they did.
