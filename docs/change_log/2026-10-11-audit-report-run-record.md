# 2026-10-11 — Run record and reliance note in the audit report

Asked for by the operator.

## The change

- **Report.** A "Run record" section, first after the banners: when the report
  was produced, the provider and model that mapped the log, the number of
  model calls and the tokens they used (in, out, thinking, total), and the
  model, date and tokens behind the requirement profile. Then a note on
  reliance: where a log supports a regulatory obligation, or the organization
  would bear a material consequence if critical information were missing, the
  owner of that risk should have a reasonable sample of records reviewed by a
  qualified person, in proportion to the impact.
- **Result JSON.** `run_record` holds the same figures.
- **Profiler.** `provenance.token_usage` in a new profile: token totals over
  the extraction's calls.
- Auditor plugin version 0.6.0. `renderers.run_record` and `REVIEW_NOTE`.

Edge cases: an `assess` run shows "no model: saved patterns were re-tested"
and 0 tokens; a profile with no provenance shows "written by hand?" and no
token row; a profile written before today shows its tokens as "not recorded";
a call whose provider reports no total is totalled from its parts.

## Verified

- `pytest -q tests/ plugins/`: 2081 passed, 1 skipped (assertions added to an
  existing test).
- Live, local shell, `anthropic`, the operator's OpenAI profile and the
  database sample log: the section rendered with 1 call, 13,472 tokens (9,143
  in, 4,329 out), "Standard read by openai/gpt-5.6-sol" and its date.

## Not verified

- `provenance.token_usage` from a live extraction; the profiler was not run.
- A resumed audit, Gemini's thinking-token figure, Cloud Run.

## Seen in the same live run

The profile was written before the clarity grade was changed to rest on one
clause, so the report's "Where the standard could be firmer" lines carry the
old wording and no clause beside the grade. `validate_profile` on the profile
writes a regraded copy. The audit does not flag this, because the grade's
digest still matches the requirements.
