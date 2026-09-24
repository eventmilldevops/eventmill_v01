# 2026-09-22 — Prose pseudocode, caveats, and who made what

A second live run on `8d39656`, this one on `gpt-daybreak-red-latest` across
the 9-node Fox Kitten pair, two calls, 9/9 coverage, nothing rejected. It
confirms the field fix and finds three things the fix made visible.

## The field fix holds

**Zero invented field names across 10 source citations, down from 14 of 14.**
Every `required_fields` entry in all nine drafts is a real field of the source
it cites.

Three of the five purpose-built derived indicators are now in use, because they
are finally offered:

| Draft | Indicator |
|---|---|
| T1078 SCM | `workflow_changed_and_run_by_same_actor` |
| T1505.003 web_console | `first_time_route_for_principal` |
| T1210 telemetry_db | `rows_touched_estimate` |

The last closes the 09-20 review's own finding. The previous draft counted
queries; this one thresholds on `rows_touched: 1000` estimated rows — the
observation the rule was always after.

Two other 09-22 changes are visibly working. `LOGIC_KIND_AMBIGUOUS` fired twice
and **preserved both declared kinds** (`threshold`, `correlation`) rather than
overwriting them. No `LOGIC_NULL_AS_MATCH`: one draft writes "any **present**
auth.display_name or auth.policies is unexpected", which is the new prompt rule
followed to the letter.

## Prose pseudocode produced four false findings

All four `FIELD_FROM_UNCITED_SOURCE` flags in the run are wrong, and all fail
the same way:

| Draft | Flagged | The pseudocode |
|---|---|---|
| T1059 | `command` | "executing **command** patterns outside the established **command** profile" |
| T1046 | `request`, `status` | "a health, **status**, or service-information endpoint… monitoring **request** patterns" |
| T1552.001 | `request` | "Flag a successful **request** whose route is…" |

This model writes pseudocode as English prose, which `DRAFT_EXAMPLE` has always
permitted (`"<the logic, as prose or pseudocode>"`), and the tokenizer cannot
tell a field reference from an ordinary word that is also a field name
somewhere in the library.

The library checks now report only **distinctive** names — containing `_` or
`.`. Every true positive to date is distinctive (`request.operation`,
`file_path`, `db_user`), so nothing is lost. `method` would no longer be caught,
but that case became a rejection when fields started being offered.

Replayed: all four disappear, and `file_path` in prose is still caught.

## The model was writing its own review_flags

```
"review_flags": ["collection_status_unknown",
                 "authentication_not_directly_observed",
                 {"code": "FIELD_DECLARED_UNUSED", "message": "..."}]
```

Bare strings mixed with derived objects — breaking the `{code, message}` shape
the schema requires, and counting as `UNCODED` in `summarize_for_llm`.

The content is good: `authentication_not_directly_observed`,
`network_channel_not_observed`, `post_exploitation_outcome_only`,
`telemetry_does_not_observe_local_file_access` are precisely the caveats a
tester wants. The model was answering a useful question in a field reserved for
the derived answer.

So `caveats` exists for it, the prompt asks for it by name, and anything left in
`review_flags` is **moved rather than discarded**. A well-formed flag the model
supplies is kept in place. `review_flags` stays machine-derived, which keeps the
summary line coded.

## One export, two models

`engagement.model_attribution` reads `provenance.model` from the **input
projector export** — the model that produced the path, not the one that drafted
the detections, which is `calls[].model_used`. Both models sat in one export
under one name, and on review the projector's Gemini attribution was taken for
the drafting model. That is exactly the confusion attribution exists to
prevent; a run whose output cannot be attributed to the vendor that produced it
is the failure the no-silent-failover rule is written against.

- `engagement.projection_model` / `projection_model_present` — renamed, with
  `model_attribution` kept as an alias so no consumer breaks.
- `generation_model` — new, on the generation result, from `calls[].model_used`.
- `summarize_for_llm` names both: *"Generation model: X; the path was projected
  by Y."*

## An identity mapping is not an alias

Two further runs on `8d39656`, both reporting `gemini-3.1-pro-preview`, showed
the alias subtraction going too far. A draft writing
`{"name": "actor", "from": "actor"}` declares that it reads `actor`; removing
the name removed the native reference with it, so the field read most plainly
of all came back as `FIELD_DECLARED_UNUSED`. Five false findings across the two
runs - `actor`, `repository`, `container_id`, `process_path`.

A name is now subtracted only when it differs from its `from`. Replayed, the
five disappear and every true positive stays.

Worth stating plainly: this is the second defect in the field-closure check
itself, after the foreign-alias one it was written to fix. The check is small
and mechanical and has still needed correcting twice by live output - which is
the argument for it flagging rather than rejecting.

## Not done

**The prose fix is still unexercised by a live run.** The two later runs both
wrote SQL-shaped pseudocode, so no bare library word ever reached the check -
the only pseudocode carrying one (`status`) had it declared, which suppresses
the flag for a different reason. Daybreak Red remains the only prose writer
seen, and the fix is confirmed only by replaying its sentences.

**Two runs labelled as different vendors both report
`model_used: gemini-3.1-pro-preview`,** with the same `run_id` and the same
`flow_map_sha256`. The identical run_id is expected - it belongs to the shared
input projection - but the drafts differ substantially, so these are two
generation runs whose `calls` name one model. Either an operator `use`
selection did not reach the dispatcher, or `model_used` does not reflect the
client that answered. Undiagnosed, and worth settling before any cross-vendor
comparison is graded: a grade needs to know which vendor produced which output.

One of the four attempts failed and passed on a rerun. That failure has not
been diagnosed and no record of it survives here.

## Tests

15 new cases; 282 in the plugin, 1829 overall. The prose cases use the live
run's own sentences.
