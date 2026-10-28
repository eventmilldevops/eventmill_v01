# 2026-10-12 — Log compliance audit: merged, and confirmed by the operator

No code changed. This entry closes the thread that began with
`2026-10-10-log-compliance-audit.md` and records what the operator's testing
settles and what it does not.

## State

- The `compliance_assessment` branch was merged to `main` as pull request #6
  (`be4fdcc`). `main` is at `a429399`, which adds a cosmetic change to the
  shell banners.
- `pytest -q tests/ plugins/`: 2081 passed, 1 skipped, at the last run before
  the merge. `scripts/validate_schemas.py`: all valid.

## Confirmed by the operator

Reported by the operator on 2026-10-12, after the merge:

- `logging_standard_profiler` and `log_compliance_auditor` work on all three
  vendors: Gemini, Anthropic and OpenAI.
- Both the database audit log
  (`ymmv_legacy_invoicing_database_audit.log`) and the Linux syslog sample
  (`ymmv_legacy_invoicing_syslog.log`) were audited.

The operator's judgment of the results, from the commit that preceded the
merge: the three models are as consistent as three auditors reading the same
standard and the same log. That is the bar this tool was built to, as set out
in `docs/adr/0001-grade-the-standard-and-the-log-against-fixed-categories.md`.

This is the operator's report. The run outputs were not reviewed for this
entry and no figures from them are recorded here.

## What this closes

Items listed as not verified in earlier entries:

- OpenAI on either plugin (`2026-10-10-log-compliance-repeatability.md`).
- Gemini and OpenAI on catalogue 1.1.0, and a fresh `extract_profile` since
  the categories were added
  (`2026-10-11-investigation-coverage-and-standard-clarity.md`).
- Syslog on the current code, which had last been run before `any_of` groups,
  requirement kinds and the categories existed.

## Still not verified

- A second standard, or a log family beyond the four examples. The seven
  categories and the hedge wording list were written against one standard.
- The Catalina and authentication example logs on the current code.
- `resume` against a real model. No audit has stopped short.
- A file larger than a few hundred lines against a real model.
- Repeatability figures on the current code. The published figures (137 of
  144 findings stable in 4 of 5 runs) are from 2026-10-10 and predate `any_of`
  groups, requirement kinds and the categories.
- Whether the open-list rule for `allowed_values` fired, and what
  `provenance.token_usage` recorded, in the operator's runs. Both were live
  for those runs. Neither was checked in the output.
- RFC 5424 and PRI-bearing syslog.
- Splunk and Elastic renderings loaded into either product.

## Known and left as found

Unchanged from `docs/specs/log_compliance_audit.md` section 9:

- Which field a model maps to `target_object` varies between runs (76% to
  100% on the database log).
- "Shared identities should be supplemented with the individual identity" is
  read as a presence rule by all three vendors.
- Vendors disagree on whether some sentences are presence or quality rules.
- A profile exported before the grade was changed to rest on one clause shows
  the old wording in the report. `validate_profile` writes a regraded copy.
