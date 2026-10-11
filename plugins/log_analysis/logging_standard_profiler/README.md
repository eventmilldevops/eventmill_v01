# Logging Standard Profiler

**Reads a logging or audit standard and writes the requirement profile that
`log_compliance_auditor` tests a log sample against.**

Most of a standard is scope, definitions, roles and rationale. This tool keeps
the statements that say what must be logged, what a record has to contain and
how logs are handled, and sorts them into two piles: those a log file can show,
and those it cannot (retention, protection, review). The second pile is kept
and labelled, never dropped, so an audit can say "out of reach of a log sample"
instead of implying a pass.

It also grades the standard itself. What an event record should say is
broadly agreed, so the tool checks how plainly the standard asks for each of
seven basics and reports the weak clauses. A loosely worded standard cannot be
audited against, whatever the logs contain.

Spec: `docs/specs/log_compliance_audit.md`. Why the standard is graded:
`docs/adr/0001-grade-the-standard-and-the-log-against-fixed-categories.md`.

## The profile is a draft until a person says otherwise

`extract_profile` is a model reading a document. Its output carries
`review_status: draft_unreviewed`, and every audit run against it says so in
its first lines. To accept a profile, open the JSON, check the requirements
against the standard, fix what is wrong, and set `review_status` to
`reviewed`. No tool sets that value.

Four things make the review quicker:

- **Every requirement carries an exact quote**, and the tool searches for each
  quote in the text it extracted from the document itself. A quote it cannot
  find is marked `quote_not_found`. That is where to look first: the model
  either paraphrased or invented.
- **`page` is corrected** to wherever the quote was actually found.
- **Elements come from a closed catalogue** (`catalogue.json`). A requirement
  the catalogue cannot express is kept with no elements and an
  `unmapped_reason`. It shows in the audit as `not_evaluated`.
- **The clarity grade names clauses.** A category graded low lists the
  requirements it was read from. If the standard's wording is in fact plain,
  the extraction of those clauses is what needs fixing.

## Two calls, and a count of what was covered

A model asked to read a standard returns a selection, not everything: on a
14-page standard a single read quoted 25 of 144 obligation sentences. So the
tool also finds every sentence worded shall, must, should or required in the
text it extracted itself, and makes a second call (the sweep) that asks the
model to classify the ones the first read left out. Those requirements carry
`extracted_by: sentence_sweep` and quote the document's own sentence.

The profile's `statement_coverage` block accounts for every such sentence:
quoted by the first read, added by the sweep, judged not a requirement (listed
with the model's reason, worth a skim), or not classified. `--skip_sweep`
leaves the second call out. The count is a wording match: it includes
sentences that merely define "shall", and it cannot see a requirement worded
another way.

A scanned PDF with no text layer can still be read natively by the model, but
there is no sweep and its quotes come back `not_checked`, because there is no
local text to search.

## Actions

| Action | Model | What it does |
|---|---|---|
| `extract_profile` | heavy tier, 2 calls (more for a long text-only document) | Reads the standard, grades it, writes `logging_profile_<stamp>.json`, registers it as a `json_events` artifact |
| `validate_profile` | none | Checks any profile, generated or hand-written, lists errors and warnings, and recomputes the clarity grade. When the grade in the file is missing or out of date it writes `<profile>_graded_<stamp>.json` and registers it. |

```
load nist_sp_800-53_au.pdf pdf_report
run logging_standard_profiler --artifact_id art_xxxx

run logging_standard_profiler --action validate_profile --artifact_id art_yyyy
```

The standard is a PDF or a text file loaded as an artifact. There is no URL
input: download the document and `load` it. A PDF is sent natively where the
selected provider supports it, and as locally extracted text otherwise or with
`--force_text`.

## Writing a profile by hand

An internal standard is often a page of bullet points, and writing the profile
directly is quicker than extracting it. Copy `examples/profile.example.json`,
keep its `catalogue` block unchanged, replace the requirements, and run
`validate_profile`. The `standard_clarity` block in the example describes the
example's requirements; `validate_profile` writes a copy of your profile with
the grade for yours, and that copy is the one to audit with. Each requirement
needs:

| Field | Meaning |
|---|---|
| `requirement_id` | Your clause number. Must be unique. |
| `obligation` | `must`, `should` or `may` |
| `assessable_from` | `record_content`, `record_set`, or `not_assessable_from_sample` |
| `kind` | What sort of rule it is; see below. null when not assessable |
| `elements` | `[{"element": "timestamp", "constraints": {...}}, ...]` from the catalogue, or a group of alternatives (below); empty when not assessable |
| `summary`, `quote`, `section`, `page` | For the report's reader |

Constraints: `timezone_required` and `min_precision` (`second`, `millisecond`,
`microsecond`) on a timestamp; `allowed_values` on any element.

### Alternatives

Entries side by side are all required in the same record. When the standard
lists alternatives ("a host, service, component or other stable identifier"),
group them, and a record needs only one:

```json
"elements": [
  {"element": "timestamp"},
  {"any_of": [{"element": "host"}, {"element": "source_component"}], "label": "origin"}
]
```

**Check the groups when reviewing a draft.** A group that is too wide makes a
requirement trivially met: "one of actor_identity / source_component" is
satisfied by any record that names its program, whether or not it names a
user.
A group that leaves out an alternative the clause names does the opposite and
reports a shortfall that is not there. Both mistakes have been seen in drafts
of the same clause from two models.

### Kinds of requirement

| Kind | The sentence asks | Counted |
|---|---|---|
| `presence` | A record carries an element, possibly in a stated format | Yes |
| `prohibition` | Something must not be in a record, or must not be done | No |
| `quality` | Values are correct, stable, consistent or unambiguous | No |
| `event_selection` | A kind of event is logged at all | No |
| `permission` | Something is allowed | No |

The auditor counts records for `presence` requirements only and lists the
rest for a person to look at. This is the field most worth checking in a
draft, because it decides whether a requirement produces a finding at all:

- A requirement wrongly marked `presence` gives a number that means nothing
  ("search and export activity shall be logged" scored as observed because
  every record has an event type).
- A requirement wrongly marked anything else silently drops a finding the
  tool could have given.

A requirement the model called `presence` whose quote is worded as a ban is
changed to `prohibition` at extraction and noted. Edit `kind` by hand to
overrule it.

## How clearly the standard asks for the basics

A log audit can only be as good as the standard behind it. If a clause says
records "should, where applicable" identify a user, a log with no user in it
has not failed anything. So the profile carries a grade of the standard,
`standard_clarity`, on seven categories that are generally accepted as what an
event record should say, for security investigation and for operational
reliability alike:

| Category | An investigator needs | Elements, any one of |
|---|---|---|
| `when` | When it happened | `timestamp` |
| `what` | What happened | `event_type` |
| `who` | Who or what did it | `actor_identity` |
| `outcome` | How it ended | `outcome` |
| `where` | Where it came from | `host`, `source_component`, `source_address` |
| `link` | What links it to related events | `session_id` |
| `target` | What was acted on | `target_object` |

The categories live in `catalogue.json` as `investigation_categories`. Each
category is graded on **its strongest single clause**, and the grade names
that clause (`graded_on`). The grade starts in bin 1 and moves up one for each
criterion the clause meets:

| Criterion | The clause | A clause that fails it says |
|---|---|---|
| countable | Plainly requires records to carry an element of the category | Nothing, or only that values must be "consistent" |
| mandatory | Is a shall or must | "should record a session identifier" |
| specific | Needs the category on its own: a required element, or a group whose members are all in the category | "a user, process, host or other subject" |
| unconditional | Is not hedged | "where applicable", "when needed", "where feasible", "to the extent", "in proportion to" |

Criteria are not pooled. A mandatory clause that hides the actor in a list of
alternatives and an advisory clause that names the actor do not add up to a
clause that is both. When two clauses score the same, the one naming the
fewest elements is named: the clause written for the category, not a summary
that lists everything. A list item quoted on its own ("when the event
occurred;") is read with the sentence that introduces the list, so a
condition there still counts.

| Bin | Reads as |
|---|---|
| 1 | Not asked for, or mentioned only in a rule that cannot be counted |
| 2 to 4 | Asked for, with one to three of the weaknesses above |
| 5 | A plain, mandatory, unhedged requirement for this category on its own |

Each grade lists the criteria it lacks, the clauses it was read from, and how
many of them are rules about value quality. The summary of both actions names
the weakest categories and why:

```
Clarity of the standard by category, bin 1 to 5: when 5 (on 5.3), what 5
(on 5.2), who 4 (on 5.5), outcome 5 (on 5.6), where 5 (on 5.4), link 3 (on
6.5), target 4 (on 5.5). To shore up: who (its strongest clause is hedged
...); link (its strongest clause is a should or may ...); ...
```

**Check the named clause even when the grade is 5.** A model that over-reads
a general clause earns a grade the standard has not: in one draft, clause
5.1 ("the identity of relevant individuals, subjects, objects, processes, or
other entities") was mapped as a plain requirement for an actor, and `who`
came out 5 on 5.1 where three other drafts gave 4.

On the YMMV example standard, four drafts from two models (2026-10-11):

| Profile written by | when | what | who | outcome | where | link | target |
|---|---|---|---|---|---|---|---|
| Gemini, first draft | 5 | 5 | 4 | 5 | 5 | 3 | 4 |
| Gemini, second draft | 5 | 5 | 5 | 5 | 5 | 3 | 4 |
| Anthropic, first draft | 5 | 5 | 4 | 5 | 5 | 3 | 4 |
| Anthropic, second draft | 5 | 5 | 4 | 5 | 5 | 3 | 4 |

`who` and `target` lose a bin because clause 5.5 opens with "Where
applicable" and clause 5.1 lists alternatives. `link` is 3 because clause 6.5
is a "should ... when needed". Those are fair criticisms of the standard, and
they are the categories where the example database log is least complete.

**The grade is of the profile's reading, not of the document directly.** The
one 5 for `who` above is the model, not the standard: that draft read clause
5.1 as requiring an actor outright. That is why the clause is named. Check it
before proposing a change to the standard, and fix the profile if the reading
is what is wrong.

The grade is deterministic: the same requirements always give the same grade.
It carries a digest of the requirements it was computed from, and the auditor
uses that to say when a profile has been edited since. After editing a
profile, run `validate_profile`.

## Different models read a standard differently

Two models given the same standard do not return the same profile, and one
model run twice does not either. On the 14-page example standard, two
vendors returned 135 and 152 requirements. Of 126 sentences both quoted, 118
were classified the same way.

What is the same every time, because code decides it:

- The quote check, the count of obligation sentences and what happened to
  each, and the catalogue.
- The clarity rubric. Two profiles that read a category's clauses alike get
  the same grade.

What varies, and is the reviewer's to settle:

- How many requirements a paragraph becomes, and their ids.
- `kind`: one model called "shared identities should be supplemented with the
  individual identity" a presence rule, another a quality rule.
- Which elements go in a group of alternatives.

Treat a second model's profile as a second auditor's reading. Where the two
agree, the clause is probably clear. Where they differ, read the clause; the
difference is usually a sign the wording allows both. Comparing the two
clarity grades is a quick way to find those places. `use <provider> for
logging_standard_profiler` selects the model.

## What to expect from a public standard

A log management guide such as NIST SP 800-92 is mostly about programme and
infrastructure: expect a long `not_assessable_from_sample` list and few
testable requirements. Record-content requirements are stated more directly in
control catalogues (NIST SP 800-53 AU-3 and AU-8, for instance) and in internal
application logging standards.

## Limitations

- One document per run. Requirements spread across two documents need two
  profiles, or one merged by hand.
- The catalogue has fourteen elements. It is deliberately small; a standard
  that requires something outside it produces `not_evaluated` findings rather
  than a stretched mapping.
- A prohibition ("records shall not contain passwords") is recorded with
  `kind: prohibition` and listed in the audit for a person. It is not tested.
- The clarity grade covers the seven categories and nothing else. A standard
  can score 5 throughout and still say nothing useful about retention or
  review, which are outside what a log sample shows.
- The hedge wording the `unconditional` criterion looks for is a fixed list in
  English. A condition phrased another way is not seen, and a legitimate
  condition ("when an operation has an outcome") is not counted as a hedge.
- Long documents on the text path are read in parts of about 120,000
  characters, and the run stops starting new parts near its time limit, naming
  the pages it did not read.
