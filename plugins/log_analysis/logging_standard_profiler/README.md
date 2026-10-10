# Logging Standard Profiler

**Reads a logging or audit standard and writes the requirement profile that
`log_compliance_auditor` tests a log sample against.**

Most of a standard is scope, definitions, roles and rationale. This tool keeps
the statements that say what must be logged, what a record has to contain and
how logs are handled, and sorts them into two piles: those a log file can show,
and those it cannot (retention, protection, review). The second pile is kept
and labelled, never dropped, so an audit can say "out of reach of a log sample"
instead of implying a pass.

Spec: `docs/specs/log_compliance_audit.md`.

## The profile is a draft until a person says otherwise

`extract_profile` is a model reading a document. Its output carries
`review_status: draft_unreviewed`, and every audit run against it says so in
its first lines. To accept a profile, open the JSON, check the requirements
against the standard, fix what is wrong, and set `review_status` to
`reviewed`. No tool sets that value.

Three things make the review quicker:

- **Every requirement carries an exact quote**, and the tool searches for each
  quote in the text it extracted from the document itself. A quote it cannot
  find is marked `quote_not_found`. That is where to look first: the model
  either paraphrased or invented.
- **`page` is corrected** to wherever the quote was actually found.
- **Elements come from a closed catalogue** (`catalogue.json`). A requirement
  the catalogue cannot express is kept with no elements and an
  `unmapped_reason`. It shows in the audit as `not_evaluated`.

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
| `extract_profile` | heavy tier, 2 calls (more for a long text-only document) | Reads the standard, writes `logging_profile_<stamp>.json`, registers it as a `json_events` artifact |
| `validate_profile` | none | Checks any profile, generated or hand-written, and lists errors and warnings |

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
`validate_profile`. Each requirement needs:

| Field | Meaning |
|---|---|
| `requirement_id` | Your clause number. Must be unique. |
| `obligation` | `must`, `should` or `may` |
| `assessable_from` | `record_content`, `record_set`, or `not_assessable_from_sample` |
| `elements` | `[{"element": "timestamp", "constraints": {...}}, ...]` from the catalogue; empty when not assessable |
| `summary`, `quote`, `section`, `page` | For the report's reader |

Constraints: `timezone_required` and `min_precision` (`second`, `millisecond`,
`microsecond`) on a timestamp; `allowed_values` on any element.

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
- A prohibition ("records shall not contain passwords") is not expressible as
  an element and is not tested.
- Long documents on the text path are read in parts of about 120,000
  characters, and the run stops starting new parts near its time limit, naming
  the pages it did not read.
