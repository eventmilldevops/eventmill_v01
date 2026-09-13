# Change Log — the run-group report

**Date:** 2026-09-12
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/input.schema.json`
**Supporting Files:**
`plugins/threat_modeling/adversary_path_projector/examples/README.md`

Follows `2026-09-11-run-group-summary.md`.

---

## Problem

Phase 3b counted recurring routes correctly and emitted JSON. The operator's
verdict on it was the one that matters: *"the json output is too hard to
decipher."* A six-run group is several hundred lines of nested objects, and the
finding inside it — two routes, both ending at regulated data, both through one
uncontrolled component — has to be read out to people who will never open it.

Translating that by hand each time is where a report gets its numbers wrong.

## Changes

`summarize_run_group` now writes a Markdown report as a registered artifact,
`adversary_projection_group_<group>_<stamp>.md`, and returns its name as
`report_file`. The JSON result is unchanged, so nothing that reads it breaks.

The report is one page, then an appendix:

- **Bottom line** — how many routes recurred, which crown jewels they end at,
  which were *not* reached, the strongest route with its count, what every
  recurring route passes through, and which of those components the flow map
  records no controls on.
- **The routes**, as a table: route in component names, found in *N of M* runs,
  where it ends (marked when it is a crown jewel, with the data classification
  when the map is supplied), and what reaching the data rests on.
- **What we should check** — every assumption across every route, deduplicated,
  split into how things are set up and what we would see.
- **What this is, and is not** — the framing, with the recurrence threshold
  stated in words.
- **Appendix** — one representative path per route as a step table, with the
  record filename so any line can be traced back.

### Rules the report holds to

- **Every count says what it is out of.** "2 of 3 runs", never "recurring".
- **Model-written text is marked `(LLM)`** — the "what it rests on" column and
  the appendix's exploited-condition and result columns are the model's
  sentences, and the column headers say so.
- **Nothing asserts a control failed.** The report says a component has no
  controls *recorded*, or names what the map itself rates. That distinction is
  what keeps it defensible in a room.
- **Two deterministic choices where a model would have been easier.** The "what
  it rests on" column is the assumption attached to the step at the route's
  destination, chosen by position, never by judging the text. The check-list
  split is a keyword heuristic on the assumption's wording — documented as a
  heuristic, and an assumption in the wrong list is still the same question
  asked of the same people.
- **Plural forms are real.** "1 route", not "1 route(s)": the terminal
  summaries can look generated, a document handed to someone cannot.

### The flow map is optional

`--file_path` (or an artifact id, or inline) adds control context: data
classification on the destination, and which components on a recurring route
have no controls recorded. Without it the report still counts routes and says
plainly that controls were not checked. If the supplied map's hash does not
match the one the runs were projected against, the report is still written and
`report_warnings` says the names and controls may not match.

A report that cannot be written never costs the summary — the failure lands in
`report_warnings`.

## Tests

**937 passed**, was 934. Added: the report is written, registered and names its
routes with the crown jewel and the run counts; the test plan deduplicates an
assumption two routes share; the report says when controls were not checked,
and names an uncontrolled component when the map is supplied.

Two of those tests failed first for reasons worth recording. The route fixtures
carried no step state, so the report had no test-plan section at all — the
fixtures now carry assumptions, which is what the report is mostly made of. And
the helper's positional `flow_map` parameter collided with the `flow_map`
payload key it forwarded; renamed.

`validate_manifests.py` still reports exactly the 15 pre-existing `stability`
errors. `ruff`/`black` are not installed here; style matched by hand.

## Verified live

**2026-09-12, `phase3b-claims`, six runs, all completed.** Volt Typhoon against
the claims portal on the container, summarised with the flow map supplied. The
report rendered without issue and the operator's verdict was that it reads
fine — which is the bar it was written to, since the JSON it replaces did not
clear it.

That group is also the first to exercise the batching fixes end to end: six
runs assembled from two invocations, counted as six.

## Not in this change

- **No diagram.** A route is three or four components; the table carries it.
- **No cross-group comparison.** A route recurring in two groups — the signal
  that a finding survived a prompt change — is still a person reading two
  reports.
- **No HTML or PDF.** Markdown renders anywhere the operator already works, and
  a converter is not this plugin's job.
