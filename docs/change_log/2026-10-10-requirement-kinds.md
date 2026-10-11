# 2026-10-10 — Only presence rules are counted: requirement kinds

Follows `2026-10-10-profile-alternative-elements.md`. Asked for by the
operator after reviewing a live audit, accepting that it sends more
requirements to a person.

## The defect

The auditor counts records that carry an element. Every requirement that named
an element was scored that way, whatever the sentence asked. In the operator's
Cloud Run audit of the database sample that produced, among 28 findings:

- **False failures.** 6.2#3 (free-form text shall not be the sole
  representation) `not_observed` because the log has no `message` field, which
  is the compliant case. 5.5#3 and 6.3#2 likewise.
- **False passes.** 8.2#3 (elevated access to logging systems shall be logged)
  and 8.6#3 (search and export shall be logged) `observed` at 100% because
  every record has an event type and an actor. Nothing looked for such events.

## The change

- **Profile.** A requirement about records carries `kind`: `presence`,
  `prohibition`, `quality`, `event_selection` or `permission`; null when not
  assessable from a sample. Missing reads as `presence`, so older profiles
  behave as before. `validate_profile` rejects an unknown value.
- **Profiler.** Both prompts define the kinds with examples; the example reply
  shows a prohibition and an event-selection rule. A requirement returned as
  `presence` whose quote matches `shall|must|should|may|will|can not`,
  `never` or `prohibited` is set to `prohibition` with a note. Counts gain
  `by_kind`; `testable_against_records` counts presence rules only; the
  summary names the rest.
- **Auditor.** Only `presence` is counted. Any other kind is `not_evaluated`
  with a `basis` saying why and `reference_elements` (records carrying each
  named element); it has no `share`. An unknown kind is `not_evaluated`, never
  counted. `not_counted_by_kind` in the assessment and a line in the summary.
  Plugin version 0.4.0.
- **Report.** "Requirements about records that were not counted", grouped by
  kind, each with its reference counts. Requirements with no catalogue element
  are the last group there.
- `examples/profile.example.json` carries `kind` on every requirement.

## Verified

- `pytest -q tests/ plugins/`: 2073 passed, 1 skipped (10 new cases).
- Live, local shell, `openai` for both tools, example standard and database
  sample log:
  - Profile: 165 requirements; 16 presence rules testable; not countable: 7
    prohibition, 18 quality, 4 event_selection, 8 permission; 111 not
    assessable from a sample. No requirement needed the wording rule: the
    model labelled every ban itself.
  - Audit: 16 assessed: 14 observed, 2 partially observed, 0 not observed; 38
    not evaluated. 6.2#3, 5.5#4, 8.2#3, 8.6#3 and 7.1#2 are in the not-counted
    section with their reference counts.
  - The model split clause 5.5's last sentence into a quality rule (stable
    identifiers) and a prohibition (no credentials), both quoting it.

## Not verified

- Gemini and Anthropic with the new prompt; any other log or standard.
- Cloud Run: nothing deployed.
- The wording rule has only been exercised by tests.

## Known after this change

- **A lost finding.** 5.3#3 (timestamps machine parseable and internally
  valid) was labelled `quality` and is no longer counted, although the tool
  does parse every timestamp. The same sentence was counted in earlier
  profiles. This is the cost side of the classification and a reviewer can
  set it back to `presence`.
- **A remaining false pass.** 5.5#2 (shared identities should be supplemented
  by an individual identity) is `presence` on `actor_identity` and reads
  observed, while 175 of 200 records name only a shared application account.
- **A remaining false shortfall.** 5.6 is 96%: the profile again took the
  standard's prose list of outcomes, including "another documented state", as
  literal `allowed_values`, so `DENIED`, `STARTED` and `OPENED` fail.
  Not addressed here.
- **Profiles still differ run to run.** This one picked up the appendix
  checklist (EOR-01 to EOR-10) as requirements, duplicating section 5.
- The 2026-10-10 repeatability figures predate `any_of` and `kind` and do not
  describe the current tool.
