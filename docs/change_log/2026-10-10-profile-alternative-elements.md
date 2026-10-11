# 2026-10-10 — Requirement profiles can say "any one of these elements"

Found by the operator in a live audit of the database sample log on Cloud Run
(profile and audit both on `openai`, build `4c39744`).

## The defect

Clause 5.4 of the YMMV standard says location and source "may be a host,
service, application, ... network address, component, or other stable
identifier". The profiler mapped it to `host`, `source_component` and
`source_address`. A requirement's `elements` was a flat list and the auditor
counted a record only when it carried **every** listed element, so 5.4#2 was
reported `not_observed`, 0 of 200, although every record names its source
component and has either a host or a client address. The same reading put 1.3,
5.1, 5.4, 5.5 and 6.3 at 3% (the six backup records, the only ones with
`host`).

The profile had no way to express alternatives, so this was the design's
fault and not the model's.

## The change

- **Profile.** An `elements` entry is either `{"element": name}` (required) or
  `{"any_of": [...], "label": ...}` (one member is enough). At least two
  members; a group left with one usable member becomes a required element with
  a note. `validate_profile` checks groups. `profile_version` stays `1.0`: a
  flat list means what it meant.
- **Profiler prompts.** Both the document read and the sentence sweep explain
  the group and when to use it; the example reply contains one.
- **Auditor.** A requirement is a set of slots; a group's slot is filled by
  any member. An element may sit in several groups. Each finding and each of
  its record types gains `needs` with the records that filled every slot.
  `records_with_all_elements` keeps its name and now means records meeting the
  requirement. Plugin version 0.3.0 (it is part of the run fingerprint).
- **Report.** "At least one of the elements below is present in ...", or
  "Everything needed is present in ..." with a `Needs:` line when a
  requirement mixes required elements and groups. `may` requirements are
  marked `Optional`. Record types falling short say "none of a / b".

## Verified

- `pytest -q tests/ plugins/`: 2063 passed, 1 skipped (4 new tests).
- Live, local shell, `openai` for both tools, the example standard and
  `ymmv_legacy_invoicing_database_audit.log`:
  - The profiler used groups on its own for 5.1, 5.4, 5.5, 5.5#3, 5.6#2, 6.3
    and 6.4#5. 146 requirements, 23 testable.
  - The audit: 20 observed, 2 partially observed, 1 not observed (was 14 / 8 /
    6 on the operator's run). 5.1, 5.4, 5.5 and 6.3 are observed in 200 of
    200. The saved patterns were then re-scored with the `assess` action after
    a last code change; the counts were the same.
  - This profile had no separate 5.4#2; the "may be a host ..." sentence was
    folded into 5.4's group. Profiles still differ between runs.

## Not verified

- Gemini and Anthropic with the new prompt. Any other log or standard.
- Cloud Run: nothing was deployed.
- The profile example file has no group in it.

## What this does not fix

Problems from the same live run that remain and are separate work:

- **Rules that are not about presence.** 6.2#3 (free-form text must not be the
  only representation) is still `not_observed` because the log has no
  `message` field, which is the compliant case. 5.5#3 (identifiers must not
  expose credentials) and 8.6#3 (search and export must be logged) are now
  `observed` only because the elements exist. Grouping made 5.5#3 pass where
  it failed before; neither answer says anything about the rule.
- **Groups can be too wide.** The model wrote "associated entity: one of
  actor_identity / source_component / host / target_object" for 5.1. Any
  record naming its program fills that, so the requirement no longer tests for
  an actor. A reviewer has to check the groups; the profiler README says so.
- `allowed_values` taken from a prose list (5.6) did not recur in this profile
  and was not changed.
