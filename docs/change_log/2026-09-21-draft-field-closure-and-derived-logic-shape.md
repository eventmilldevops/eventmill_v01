# 2026-09-21 — Draft field closure, derived kind, canonical windows

Stage G1b annotates drafts after validation instead of asking the model for a
record that needs none. Prompted by an external review of the 2026-09-20 live
run (`exports_..._20260920_192030.json`, nine drafts, two Gemini calls), which
found four issues. All four reproduce.

## What the review found, and what it turned out to be

The flagship finding was the T1210 draft: it places the actor "from web
console" and then alerts on `client_ip NOT IN known_web_console_ips`, so its
only discriminator excludes its own modelled source. The draft is silent on the
scenario it was written for.

The tempting response was a path-aware check — flag a negated-membership
predicate whose excluded set names a predecessor component. That was the wrong
instinct. Pseudocode is generated and then tested; pushing the model toward
never being wrong about a detection rule is not a target the pillar can hold,
and a validator that reviews the rule rather than describing it will be wrong
in its own turn.

The same draft declares `username` in `required_fields` and never reads it. One
mechanical check — do the fields collected and the fields read agree — catches
it with no understanding of Postgres, the path, or the attack, and hands the
question to whoever tests the rule. That is the shape adopted here.

## Changes

`generation.py`

- `normalize_window` — canonical `value_timeunit` (`60_sec`, `10_min`). A bare
  number is seconds. Unreadable windows are kept verbatim and flagged.
- `derive_kind` — `kind` from `join_keys` / `thresholds` / `window`.
  `baseline_deviation` and `reconciliation`, being claims about method, are
  never overwritten.
- `field_closure_flags` — both directions, grounded in the telemetry reference
  library so only real field names are reported.
- `annotate` — runs the above on a validated draft, appends to `review_flags`.
- `REVIEW_FLAG_CODES` — closed catalogue, mirroring the normalization stage.
- Prompt: `kind` and `window` placeholders in `DRAFT_EXAMPLE` were fixed values
  (`"single_event"`, `None`). A model that reasons about the logic still copies
  a fixed placeholder, which is why every draft in the live run declared
  `single_event` including the two carrying windows and thresholds. Both are
  now enumerations. Two rules added for windows and field closure.

`tool.py` — `annotate` runs on drafts that pass validation. An annotation that
raises becomes `ANNOTATION_FAILED` on the draft rather than costing it.

`schemas/detection_draft.schema.json` — `window` gains the `value_timeunit`
pattern; `review_flags` gains the code enum and requires `code` and `message`.
This file is descriptive: nothing loads it, which is why the live run's integer
`60` passed a schema that already said `["string", "null"]`.

`docs/specs/attack_path_detection_designer.md` — window spelling, the derivation
rules, and the flag catalogue.

## Replay against the live run

Nine drafts, no false positives:

| Draft | Flags |
|---|---|
| 0 T1078 scm | `FIELD_DECLARED_UNUSED` (event, status, workflow_id) |
| 1 T1059 ci_runner | `FIELD_DECLARED_UNUSED` (action, file_path) |
| 2 T1083 ci_runner | `LOGIC_KIND_CORRECTED` → threshold, window `60` → `60_sec`; `FIELD_DECLARED_UNUSED` |
| 3 T1555.005 vault | `FIELD_UNDECLARED_IN_LOGIC` (`request.operation`) |
| 4 T1190 web_console | `FIELD_DECLARED_UNUSED` (status_code) |
| 5 T1505.003 web_console | none |
| 6 T1552.001 web_console | `FIELD_DECLARED_UNUSED`; `FIELD_FROM_UNCITED_SOURCE` (`file_path` belongs to `container.file_access`) |
| 7 T1210 telemetry_db | `FIELD_DECLARED_UNUSED` (`username`) |
| 8 T1005 telemetry_db | `LOGIC_KIND_CORRECTED` → threshold, window `"10 minutes"` → `10_min` |

Draft 6 is the one the review scored as merely narrow. It is worse than that:
the rule reads `file_path` from `application.runtime_log`, which the library
says has no such field.

`FIELD_DECLARED_UNUSED` fires on six of nine, and most are benign — `status_code`
and `action` are sensible to collect as context. It is phrased as a question for
that reason and can never reject. The undeclared directions fire on two and have
almost no benign reading.

## Known gap

A field the library has never heard of is not reported in either direction.
Draft 8 groups by `db_user`, which is not a field of `pgaudit.object_access` in
the seed library and not attributed anywhere else, so nothing flags it. Closing
that needs either a richer library or a tokenizer that can tell a field
reference from a placeholder, and the second is how this check would start
producing findings nobody asked for.

## Not done

The rest of the review's material is unchanged by this. The T1210 rule is still
wrong; it now carries the flag that leads a tester to why. Undefined predicates
(`unusual_for_runner`, `known_exploit_patterns`) are left as they are — naming
the work is the projector behaving as triage, not a defect.

## Tests

`tests/test_generation.py` gains 22 cases against a fixture library rather than
the seed, so they describe the check and not the library's current contents.
235 pass in the plugin, 812 across `plugins/threat_modeling/`, 1782 overall.
