# 2026-10-11 — Investigation coverage in the audit report, and a clarity grade for the standard

Asked for by the operator after field-testing the profiler and auditor on
Gemini and Anthropic.

## Why

Both models mapped the database sample log to the same elements with the same
counts, yet "requirements fully observed" came to 70% for one profile and 82%
for the other, because each cut the standard into requirements differently.
The table of what an investigator needs (when, what, who, outcome, where,
link, target) was identical for both. The operator asked for that table in
the report, and for a matching measure of the standard itself, each in five
bins, since a loosely worded standard lowers scores as surely as a poor log.

## The change

- **Catalogue 1.1.0.** `investigation_categories`: seven categories, each a
  question and the elements that answer it. Descriptions of
  `source_component`, `session_id` and `event_id` reworded (see "Found while
  verifying").
- **Auditor: coverage.** `assessment.investigation_coverage`: per category,
  records carrying any one of its elements, share, bin 1 to 5 (80% or better
  is 5), and the count per element. Computed from the records and the
  mapping; the requirements are not read. The category elements are always
  among the elements the model is asked to map. A profile whose catalogue
  predates 1.1.0 uses the auditor's copy of the categories; a test holds the
  two equal. Plugin version 0.5.0.
- **Profiler: clarity.** New `clarity.py`. Per category, bin = 1 + criteria
  met out of countable, mandatory, specific, unconditional. Stored in the
  profile as `standard_clarity` with the clauses behind each grade, the
  criteria it lacks, and a digest of the requirements it was computed from.
  Shown in the summary of both actions.
- **`validate_profile`** recomputes the grade and, when the stored one is
  missing or out of date, writes `<profile>_graded_<stamp>.json` and registers
  it. This is the action's first write.
- **Report.** "What an investigation needs from each record", after the
  summary: one row per category with both bins, then the categories where the
  standard could be firmer, with reasons and clauses. The auditor reads the
  stored grade and never computes the rubric; it says when the grade is absent
  or older than the requirements.
- One line of coverage in the auditor's summary.

## Verified

- `pytest -q tests/ plugins/`: 2077 passed, 1 skipped (4 new tests).
  `validate_schemas.py`: all valid.
- `validate_profile` on the operator's two exported profiles (Gemini, 135
  requirements; Anthropic, 152):

  | | when | what | who | outcome | where | link | target |
  |---|---|---|---|---|---|---|---|
  | Gemini profile | 5 | 5 | 4 | 5 | 5 | 3 | 4 |
  | Anthropic profile | 5 | 5 | 3 | 5 | 5 | 3 | 4 |

  The one difference is real: Anthropic's 5.5 puts the actor in a group with
  process, component and host, so nothing requires an actor on its own.
- Live, local shell, `anthropic`, the graded Anthropic profile and the
  database sample log, three runs after the catalogue rewording: when, what,
  who, outcome, where 100% and link 92% in all three; target 100%, 76%, 78%.

## Found while verifying

Coverage rests on which field the model assigns to which element, and the
table makes a disagreement visible at once.

- With the 1.0.0 descriptions the same model mapped `tx=` to `session_id` in
  the operator's run (link 92%) and to `event_id` in mine (link 10%), and left
  `app=` unmapped in one run. `event_id` said "unique identifier ... of this
  individual record" and `session_id` did not mention transactions; in this
  log every transaction id happens to occur once. The descriptions now say a
  session id names the unit of work and may sit on one record or many, an
  event id is the record's own and not its transaction's, and a source
  component includes the client program in a server's audit log. Three runs
  after the change agreed on both fields.
- `target_object` still moves (76% to 100%): one run mapped a field on the
  commit and logon records that the others left unmapped. Not addressed.

## Not verified

- Gemini and OpenAI with the reworded catalogue. A fresh `extract_profile`
  since the change (the grade was computed on existing profiles).
- Cloud Run: nothing deployed.
- Any other log or standard. The hedge wording list was written against this
  one standard.

## Known limits

- The grade is of the profile. It cannot tell vague wording from a poor
  extraction; it lists the clauses so a person can.
- A profile already exported keeps its old catalogue descriptions; only the
  categories are added when it is graded.
- `severity`, `destination_address`, `event_id`, `process_id` and `message`
  belong to no category.
- Coverage counts an element as present; it says nothing about the events
  that were never logged.
