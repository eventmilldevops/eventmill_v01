# 2026-09-22 — Fields are offered, not invented

The first live run on the annotated build (`fa8403c`, 6 nodes across two paths,
two `gcp_gemini` calls, telemetry library 0.3.0) confirmed the 09-21 prompt
changes and exposed a larger defect underneath them, plus two defects in the
annotation itself.

## What the 09-21 changes did

| | 09-20 run | 09-22 run |
|---|---|---|
| `kind` | `single_event` on all nine, including two carrying windows | `baseline_deviation`, `single_event` ×3, `correlation`, `threshold` |
| `window` | `60` and `"10 minutes"` | `24_hour`, `10_min` — canonical **on emission**, no `WINDOW_UNPARSED` |
| `logsource.product` | `github_actions.workflow_run` | `github`, `linux`, `hashicorp_vault`, `nodejs`, `postgresql` |

Replacing the fixed placeholders in `DRAFT_EXAMPLE` with enumerations was the
whole of it. The model had been copying the example, exactly as suspected.

## The defect underneath: we never said what fields exist

**All six drafts invented field names — 14 of them, every draft affected.**
`http_method` for `method`, `head_branch` for `ref`, `user_name` for a field
`pgaudit.object_access` does not have at all.

The cause was four lines in `telemetry.py`. `_candidate()` — the projection of
a library entry into the prompt — passed `prerequisites`, `observes`,
`supports` and `absent_without_enrichment`, but **not `native` or `derived`**.
The model was told what each source lacks, never what it has, and then asked to
fill `required_fields`.

The proof is in the same drafts: `prerequisites` match the library **verbatim,
three for three** — `"log sink reachable or Vault seals"`,
`"pgaudit.log = 'read,write'"`. Where the pack supplies data the model copies
it exactly; where it does not, the model fabricates something plausible. This
is another defect of ours, not a model failure.

It also cost the run the best field in every source. Each library entry carries
one purpose-built derived indicator, and **none were used because none were
offered**:

| The draft hand-rolled | The library already had |
|---|---|
| unexpected author on an unprotected branch | `workflow_changed_and_run_by_same_actor` |
| shell binaries reading credential files | `token_file_read_by_unexpected_process` |
| anomalous unauthenticated Vault reads | `secret_read_rate_per_principal` |
| `COUNT(statement) BY user_name` | `rows_touched_estimate` |

The last is the 09-20 review's own finding — *counting queries is a different
observation from the amount of data read* — and the right field existed the
whole time.

## Two defects in the annotation

1. **False positive.** Draft 3 mapped `connection.remote_address` to
   `source_ip` and filtered on `source_ip`; the check read the draft's own
   alias as a native field, and because `source_ip` is native to two other
   sources, reported `FIELD_FROM_UNCITED_SOURCE`. `logic_field_references` now
   subtracts the names `normalized_fields` defines. The `from` side stays in,
   so the native field behind an alias still counts as read.

2. **A correct kind was overwritten.** Draft 6 counted statements
   `BY user_name` over ten minutes and declared itself a `threshold`, which was
   right. `derive_kind` saw `join_keys` and rewrote it to `correlation`.
   `join_keys` carries two meanings — grouping and joining — and the precedence
   picked the wrong one. This is the failure the 09-21 entry warned about,
   reproduced in that entry's own code: the derivation stopped describing and
   started judging.

   Thresholds now outrank keys, and where both are present the shape genuinely
   supports either reading: a draft declaring `threshold` or `correlation`
   keeps its answer and carries `LOGIC_KIND_AMBIGUOUS`. A draft still carrying
   the `single_event` placeholder expressed no view and is still derived,
   because the placeholder is definitively wrong once a threshold exists.

Draft 5's `FIELD_UNDECLARED_IN_LOGIC` on `method` was **right by accident**:
the real field is `method` and the draft had declared the invented
`http_method`. Correct finding, faulty reasoning; the field check now catches
it for the right reason.

## Changes

- `telemetry.py` — `_candidate` carries `fields.native` and `fields.derived`.
- `generation.py` — `_validate_telemetry` refuses a `required_fields` entry the
  cited candidate does not offer, naming what it does offer. Reads the
  candidate, not the library, so a draft is judged on what it was told; a
  candidate with no field list is not second-guessed. `logic_field_references`
  subtracts aliases. `derive_kind` reorders; `kind_is_ambiguous` added with
  `LOGIC_KIND_AMBIGUOUS`. Prompt gains the field rule and a note preferring a
  derived indicator over reconstructing the same signal.
- `schemas/detection_draft.schema.json` — the new flag code.
- Spec — a *Fields are offered, not invented* section and the revised
  derivation table.

Replayed against the run: **all six drafts are now refused**, each naming the
fields its source actually has. That is the correct outcome — all six named
fields that do not exist — and it is why the rejection had to land in the same
change as offering the fields. Rejecting on fields before supplying them would
fail every draft with no way to comply.

## An absence is not a signal

Draft 3 alerted on `auth_identity IS NULL` to mean "unauthenticated". If that
field is not collected every record satisfies the condition and the rule fires
on all traffic through the source - the same shape as an empty bucket prefix,
reading as a signal when it is really the absence of one. The spec forbids
null-as-match outright, so `null_as_match` now flags it.

**A flag, not a rejection**, and the line is the point. `_validate_telemetry`
rejects because a source or field that was never offered is a checkable fact
about the record. This is a pattern read out of prose pseudocode, where the
same words express the defect (`auth_identity IS NULL`) and the handling the
contract asks for (`IF principal IS NULL THEN insufficient_telemetry`, which is
excluded). `IS NOT NULL` and `!= NULL` are excluded too: requiring presence is
the opposite failure and a legitimate condition. The first regex caught
`!= NULL`, which a test found before it reached anything.

## Not done

No live run since these changes: the field offer is verified against the
library and the fixtures, not against a model.

## Tests

26 new cases; 268 in the plugin, 1815 overall. The field tests use a
hand-written candidate rather than the library, so they describe the rule and
not the seed library's current contents.
