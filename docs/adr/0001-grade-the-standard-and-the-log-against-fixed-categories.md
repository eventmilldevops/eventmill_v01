# ADR 0001: Grade the standard and the log against fixed categories, and treat model differences as auditors' opinions

- **Status:** Accepted
- **Date:** 2026-10-11
- **Applies to:** `plugins/log_analysis/logging_standard_profiler`,
  `plugins/log_analysis/log_compliance_auditor`
- **Related:** `docs/specs/log_compliance_audit.md` (sections 3, 6, 6b),
  change logs `2026-10-10-profile-alternative-elements.md`,
  `2026-10-10-requirement-kinds.md`,
  `2026-10-11-investigation-coverage-and-standard-clarity.md`

## Context

The two plugins answer one question for an operator: is there enough
information in an application's event records to support an investigation if
an incident is suspected, judged against a written logging standard. A model
reads the standard and writes a requirement profile. A model proposes how the
log's fields map to record elements. Code tests the mapping on every record
and counts.

Field testing on 2026-10-10 and 2026-10-11 (one 14-page standard, one
200-record database audit log, Gemini and Anthropic heavy tier) showed three
things.

1. **The evidence was stable and the score was not.** Two models mapped the
   log to the same elements with identical record counts. Their profiles of
   the standard held 135 and 152 requirements. "Requirements fully observed"
   came to 7 of 10 for one and 9 of 11 for the other. Under a management
   target of "80% or better", one audit failed and one passed on the same
   facts. The difference was how each model had cut the standard into
   requirements, which is not a property of the log.
2. **Some of the score was the standard's doing.** The two categories where
   the log fell short were ones the standard asks for with "where applicable"
   and "should ... when needed". A log cannot fail a requirement the standard
   does not firmly make, and no measure said so.
3. **Model and run differences are real and not removable.** No provider
   client sets a temperature, one heavy tier is a preview model, and automatic
   cross-provider fallback is forbidden by design. The same model mapped a
   transaction id to two different elements in two runs.

Earlier decisions already narrowed what is counted: a requirement can accept
any one of a group of elements, and only presence rules are counted, with
prohibitions, quality rules, event-selection rules and permissions listed for
a person. Those made each finding mean what it says. They did not make the
total a fair score.

## Decision

### 1. Measure against a fixed, small set of categories, not against the count of requirements

The catalogue defines seven categories of what an investigator needs from a
record, each answered by one or more catalogue elements: when, what, who,
outcome, where, link, target. They are generally accepted for security
investigation and operational reliability and do not come from any one
standard. Both measures below use them, so they line up row for row.

### 2. Grade the log on those categories from the records alone

The auditor reports, per category, the share of records carrying any one of
its elements with a valid value. The requirements are not read. The category
elements are always among those the model is asked to map, so a standard that
omits a category does not hide it. This is the headline measure for the
operator's question.

### 3. Grade the standard on the same categories with a fixed rubric

The profiler grades how plainly the standard requires each category. Four
criteria, each a property of the extracted requirements: a countable presence
rule exists; it is mandatory; it asks for the category on its own and not
inside a list of alternatives; it is not hedged. The grade is 1 plus the
criteria met. It is stored in the profile with the clauses behind it, the
criteria it lacks, and a digest of the requirements it was computed from.

The rubric is deterministic code. No model is asked whether a standard is
well written.

### 4. Five bins for both

Coverage share and clarity both land in bins 1 to 5, with 5 as "80% or
better" for the log and "plain, mandatory, specific, unhedged" for the
standard. Five bins are coarse on purpose. Differences inside a bin are within
what run-to-run variation produces, and a reader comparing two reports should
not be invited to argue over 92% against 94%.

### 5. Treat a model as an auditor, and separate what is opinion from what is not

Each part of the result is assigned to one of three owners.

| Owner | What it decides | How variation is handled |
|---|---|---|
| Code | Counting, value checks, bins, the rubric, the categories, quote checks, the syslog header | None possible. Same inputs, same output. |
| Model, tested by code | Which field holds which element | Every pattern is run on every record and every value checked. Element and split signatures show whether two runs captured the same thing. The category table makes a disagreement visible in one line. |
| Model, reviewed by a person | How the standard is cut into requirements; each one's kind and groups | The profile is `draft_unreviewed` until a person sets otherwise. Every requirement carries a verbatim quote that is checked against the document. The clarity grade lists clauses so a wrong reading can be found. |

A second run, or a run on a second vendor, is a second opinion and is used
that way. The operator selects the provider per tool. The tool never selects
or switches one.

### 6. Keep the grade with the artefact it describes

The profiler owns the rubric. The auditor shows the stored grade and compares
digests to say when it is absent or older than the requirements. It does not
import or re-implement the rubric. `validate_profile` recomputes the grade and
writes a graded copy when needed.

## What is distinctive

- **The standard is graded, not only the log.** A compliance check usually
  takes the standard as given. Here a weak clause is itself a reported result,
  beside the evidence it weakens, with the clause number and the reason. The
  report can say "the log is short here and the standard is clear", "the log
  is fine and the standard would not have caught it if it were not", or "fix
  the clause first".
- **The headline measure does not depend on how a model read the standard.**
  It is counted against categories the tool defines, so two models, or two
  runs, that agree on what the records contain give the same table whatever
  their profiles look like.
- **Variation between models and runs is designed for, not averaged away.**
  The result says which parts cannot vary, tests the parts that can, labels
  the parts that need a person, and provides the means to compare two runs.
  Two vendors agreeing is treated as corroboration, and their disagreement as
  a pointer to an ambiguous clause or field.

## Consequences

**Gained**

- An overall judgement that two vendors reproduced exactly on the test case.
- A way to tell a logging gap from a wording gap.
- A report that fits how the operator reads audits: a few graded categories
  first, clauses after.

**Costs and limits**

- The seven categories are a judgement built into the catalogue. A standard
  with a different view of what a record needs is still graded against them.
  Five catalogue elements belong to no category.
- The clarity grade is of the profile. A poor extraction lowers it as poor
  wording does. It names clauses so a person can tell which.
- The hedge criterion is a fixed English word list written against one
  standard.
- Coverage still rests on the model's field mapping. `target_object` moved
  between 76% and 100% across three runs of one model. A low bin has to be
  checked against the field table.
- Coverage counts presence. A shared service account covers `who`.
- More is left to a person than a single score would suggest: 22 to 28
  requirements per audit were listed for review and not counted.
- A profile exported before catalogue 1.1.0 has to be passed through
  `validate_profile` to gain a grade.

## Alternatives considered

- **Score by share of requirements observed.** The obvious measure and the
  one a target such as "80%" suggests. Rejected as the headline: it gave 70%
  and 82% for the same evidence.
- **Ask a model to rate the standard's quality.** Rejected. It would add a
  judgement that varies by model to the one measure meant to expose such
  variation, and it could not cite a rule for its grade.
- **Pin the model so runs repeat.** Not available: no temperature control,
  preview model ids, and a requirement to support several vendors.
- **Majority vote across runs or vendors by default.** Deferred. It multiplies
  cost, and the operator's stated use is a first look. Running a second
  provider by hand gives the same information when it is wanted.
- **Controlled baselines carried between runs.** Out of scope for a
  preliminary tool with no cross-run state.
- **Have the auditor compute the rubric too.** Rejected. Two implementations
  of one rubric in two isolated plugins would drift. A stored grade with a
  digest keeps one owner.
- **A finer scale than five bins.** Rejected for the reason in decision 4.

## Evidence at the time of the decision

- Element counts for the database sample log, identical for the Gemini and
  Anthropic audits: timestamp, event type, actor, outcome 200 of 200; source
  address 194; session id 184; source component 182; target object 152;
  host 6.
- Clarity grades from the two profiles: Gemini 5, 5, 4, 5, 5, 3, 4;
  Anthropic 5, 5, 3, 5, 5, 3, 4 (when, what, who, outcome, where, link,
  target).
- Three live audits on Anthropic after the catalogue descriptions were
  reworded: when, what, who, outcome, where at 100% and link at 92% in all
  three; target at 100%, 76%, 78%.
- Not yet measured: Gemini and OpenAI on catalogue 1.1.0, a second standard,
  a second log type, and repeatability figures since `any_of`, kinds and the
  categories were added.

## Revisit when

- A second standard or log family shows the seven categories or the hedge
  list do not travel.
- Field mapping for a category keeps moving after catalogue wording has been
  tightened. The next step would be a deterministic check, for example
  refusing `event_id` for a field whose values repeat.
- An operator needs a controlled, repeatable audit and not a first look.
