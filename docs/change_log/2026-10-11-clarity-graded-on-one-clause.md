# 2026-10-11 — The clarity grade rests on one named clause

Follows `2026-10-11-investigation-coverage-and-standard-clarity.md`. From a
review of the operator's second pair of live profiles (Gemini and Anthropic,
catalogue 1.1.0) beside the first pair.

## What the review found

- **A grade moved between two drafts by the same model.** Gemini's second
  draft graded `who` and `target` 5 where its first gave 4. It had mapped the
  summary clauses 1.3 and 5.1 with a required actor and target, unhedged.
  Clause 1.3 says "in proportion to risk and technical capability", which the
  hedge list did not hold.
- **Criteria were pooled across clauses.** Anthropic's `who` took "mandatory"
  from 5.5, which lists the actor among alternatives, and "specific" from
  5.5#2, an advisory clause about shared accounts.
- **A 5 showed nothing to check.** Clauses were listed only for categories
  below 5.
- **Anthropic now quotes list items as their own requirements** ("when the
  event occurred;", ids such as `5.1 (2)`, and ten items of clause 4.1 as
  event-selection rules). The item's quote has no obligation word and loses a
  condition stated in the lead-in. With 18 clauses naming `event_type`, the
  list of eight shown did not include 5.2.

## The change

`logging_standard_profiler/clarity.py`:

- A category is graded on its strongest single presence clause. `graded_on`
  holds its id. Criteria are per clause and are not pooled.
- Ties go to the clause naming the fewest elements, then document order.
- A requirement whose quote has no obligation word is read with the preceding
  requirement of the same section whose quote ends in a colon.
- Hedge list gains "in proportion to", "commensurate with", "as far as",
  "unless impractical/infeasible", and where/when "relevant", "warranted",
  "justified".
- `clauses` lists the graded clause first.
- Summary line reads "who 4 (on 5.5)". The audit report's Standard column
  reads "4 of 5 (5.5)".
- Gap wording changed to speak of the strongest clause.

Example profile regraded. READMEs, spec section 6b, reserved vocabulary and
ADR 0001 (amendment) updated.

## Verified

- `pytest -q tests/ plugins/`: 2081 passed, 1 skipped (4 new cases). `validate_schemas.py`: all valid.
- All four operator profiles regraded locally, no model call:

  | | when | what | who | outcome | where | link | target |
  |---|---|---|---|---|---|---|---|
  | Gemini 18:10 | 5 (5.3) | 5 (5.2) | 4 (5.5) | 5 (5.6) | 5 (5.4) | 3 (6.5) | 4 (5.5) |
  | Gemini 20:13 | 5 (5.3) | 5 (5.2) | 5 (5.1) | 5 (5.6) | 5 (5.4) | 3 (6.5) | 4 (5.5) |
  | Anthropic 18:26 | 5 (5.3) | 5 (5.2) | 4 (5.1) | 5 (5.6) | 5 (5.4) | 3 (6.5) | 4 (5.5) |
  | Anthropic 20:20 | 5 (5.1 (2)) | 5 (5.1 (1)) | 4 (5.1 (6)) | 5 (5.1 (5)) | 5 (5.1 (3)) | 3 (6.5) | 4 (5.1 (6)) |

  Before the change the same four gave `who` 4, 5, 3, 4 and `target` 4, 5, 4, 4.

## Added after the OpenAI profile arrived

The operator's OpenAI profile (142 requirements, written on the code before
this change) regrades to the same bins as three of the four others: when 5,
what 5, who 4 (5.1), outcome 5, where 5, link 3, target 4 (5.5). It classifies
133 quoted sentences in common with the second Anthropic draft and differs on
13.

It again took clause 5.6's prose list ("success, failure, denial, ... or
another documented state") as literal `allowed_values`, the false shortfall
first seen on 2026-10-10. Now:

- `normalise_requirement` drops `allowed_values` when the quoted sentence
  gives an open list ("or another", "such as", "including", "for example",
  "or equivalent", "etc") and notes it.
- The catalogue's description of `allowed_values`, which the prompt quotes,
  says it is for literal codes the standard defines and not for a prose list
  of kinds. Catalogue version left at 1.1.0.

A closed prose list ("success, failure or denial") is still taken as given;
the rule cannot tell categories from literal values there.

## Not verified

- No live run: the rubric is deterministic and was run on saved profiles.
- The `allowed_values` rule on a live extraction: tests only.

## Left as found

- Gemini's `who` 5 rests on its reading of clause 5.1 as requiring an actor
  outright. The rubric cannot know that is an over-reading. It now names the
  clause.
- Profiles already exported carry the old grade. `validate_profile` writes a
  regraded copy.
- Seen in the same profiles and not changed, all in the profiler's prompts:
  Gemini's group for 5.4 still omits `source_address`; both models call 5.5#2
  (shared identities) a presence rule; the two disagree on whether "machine
  parseable" and "ISO 8601" are presence or quality; Gemini's first read
  quoted 42 of 144 obligation sentences and Anthropic's 101.
