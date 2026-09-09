# Change Log — `adversary_path_projector` Phase 1: the deterministic spine

**Date:** 2026-09-09
**Primary Files Modified:** `plugins/threat_modeling/adversary_path_projector/`
(new: `manifest.json`, `tool.py`, `schemas/input.schema.json`,
`schemas/output.schema.json`, `schemas/flow_map.schema.json`,
`tests/test_contract.py`)
**Supporting Files:** `framework/routing/config/keywords.json`,
`docs/specs/adversary_path_projector.md` (new)

---

## Problem

Everything in the `threat_modeling` pillar runs retrospectively: a published
report goes into `threat_intel_ingester`, techniques come out, and
`attack_path_visualizer` draws them. Nothing runs the other direction — an
analyst who names a threat actor and has a flow map of the application they
defend has no way to ask what that actor would do to it.

`threat_model_analyzer` looks like it covers this and does not.
`analyze_document` is a single free-text LLM call whose prompt asks for
technique IDs and whose code never parses or validates them; the plugin imports
nothing from `framework.reference_data.mitre_attack`, so it cannot know what an
actor is documented to do. Its `SecurityControl` model — implementation status,
bypass difficulty, detection capability, seven defense layers — is the best
control vocabulary in the repo and is worth building on.

The actor half of the problem is already a deterministic lookup:
`mitre_attack.py` indexes 178 groups, 831 software entries and 96 mitigations
with aliases resolved. The application half had no vocabulary at all — no flow
map, DFD or trust-boundary concept existed anywhere in the repo.

## Design

The full design is in `docs/specs/adversary_path_projector.md`. The property
this phase exists to make enforceable:

> The LLM never chooses techniques. It only chooses placement.

Phase A resolves the actor and builds a closed technique set. Phase B (LLM,
not yet implemented) binds techniques from that set onto flow map components.
Phase C rejects any step outside the set. Phase 1 is Phase A plus the
reachability that will stop Phase B inventing topology.

## Changes

### New plugin: `plugins/threat_modeling/adversary_path_projector/`

Two actions, both deterministic, no LLM:

**`profile_actor`** resolves a name, alias or id against groups, then campaigns,
then software, and returns the actor's directly attributed techniques with
provenance per technique — `attck_group`, `attck_campaign` or `intel_report`,
plus the specific ids backing each claim.

Techniques reached only through the actor's associated software are returned as
a **separate block**, not merged. ATT&CK maps a group to its tooling and the
tooling to everything that tooling implements, which for APT29 turns 66
attributed techniques into 230 — and most of the addition is not informative.
An actor generally uses whatever is on the host to move laterally, enumerate
and collect; that their malware also implements those techniques says little
about what they would do on a given estate. What is actor-specific is the
delivery chain: the dropper, loader, implant and its channel are properties of
the software.

So each software-derived technique is banded by tactic — `delivery` when its
tactics include Resource Development, Initial Access, Execution, Persistence or
Command and Control, `operational` otherwise — and `software_scope`
(`none` / `delivery` / `all`, defaulting to `delivery`) selects how much enters
`allowed_technique_ids`:

| Actor | core | +delivery | +all |
|---|---|---|---|
| APT29 | 66 | 110 | 230 |
| Volt Typhoon | 81 | 97 | 125 |
| Scattered Spider | 64 | 81 | 139 |

The blocks are disjoint, the core set never varies with scope, and profiling a
malware family by name puts its techniques in the core set (it is the subject,
not the tooling). Each software entry names the tools backing it and carries a
`source` field (`attck_lookup`) — keeping the block out of the core set is what
will let an on-demand lookup for current tooling intel replace or augment it
without touching directly attributed techniques or the Phase C validator.

`tactic_coverage` and `uncovered_tactics` are computed over the core set only,
so the stronger claim stays visible; both fields document that a tactic can be
listed as uncovered while `software_scope: "all"` puts techniques for it in the
allowed set.

Also returns procedure examples for the actor and its tooling.
`intel_artifact_id` unions a `threat_intel_ingester` output's `mitre_mappings`
into the core set, which is what lets an actor ATT&CK does not document be
profiled at all.

ICS tactics are excluded from an enterprise-only actor's uncovered list. The
ICS-only set is derived from the technique database (a tactic carried only by
`matrix: "ics"` techniques) rather than hardcoded, so it tracks whichever
ATT&CK release the lookup was built from.

**`validate_flow_map`** lints a flow map, ranks its entry surface, and computes
reachability. Structural problems that make projection impossible are errors
(dangling flow endpoints, duplicate ids, unknown crown jewels); everything the
tool can work around is a warning, and the normalized value reflects the
fallback applied — an unrecognised `exposure` becomes `internal` and says so.

Entry-surface scoring is explainable: every ranked component carries the
reasons that produced its score. A control only lowers a score when its
`implementation_status` is `implemented`, so a planned WAF earns no credit.

Reachability is breadth-first over the declared flows, honouring direction
(`bidirectional` opens the reverse edge) and reporting hops, boundary
crossings and unauthenticated hops per route. Crown jewels no entry point can
reach are reported rather than silently omitted — that usually means the flow
map is incomplete.

### New: `schemas/flow_map.schema.json`

The first application-topology vocabulary in the repo: components with
`exposure` and `data_classification`, zones with `trust_level`, directed flows
with `crosses_boundary`, and crown jewels. Control fields reuse
`threat_model_analyzer`'s `SecurityControl` names and enums verbatim so a
scenario seed imports without translation — vocabulary shared, code isolated,
per the plugin convention in CLAUDE.md.

### `framework/routing/config/keywords.json`

Eight keywords added to `threat_modeling`: `threat actor`, `adversary`, `apt`,
`flow map`, `trust boundary`, `crown jewel`, `attack surface`,
`what would they do`.

## Manifest notes

The manifest describes what the plugin does *today*, not what Phase 2 will make
it: `model_tier: none`, `requires_llm: false`, `timeout_class: fast`,
`safe_for_auto_invoke: true`. Phase 2 flips these when the heavy-tier
projection action lands.

`stability: experimental` is deliberate — `"stable"` is what the other 15
manifests declare and is exactly the value that makes `validate_manifests.py`
exit non-zero.

Capabilities follow `threat_intel_ingester`'s namespaces (`artifact:`,
`operation:`, `entity:`, `domain:`, `output:`) rather than the pillar-prefixed
form the other 15 use. This surfaced a second pre-existing schema failure that
CLAUDE.md's note does not mention: the capability pattern `^[a-z]+:` forbids an
underscore in the namespace, so `threat_modeling:...` fails it. All 15 legacy
manifests hit this, but `jsonschema.validate` raises on the first error and
`stability` masks it. `threat_intel_ingester` is the only manifest that
validates cleanly, and it uses the documented namespaces; this plugin follows
it. `validate_manifests.py` still reports exactly the 15 pre-existing
`stability` errors and nothing new.

## Tests

89 contract tests in `plugins/threat_modeling/adversary_path_projector/tests/`,
covering manifest conformance (including schema validation, so the plugin
cannot silently start failing the validator), the protocol surface, actor
resolution and provenance, tactic vocabulary (an explicit assertion that
nothing resurrects the retired "Defense Evasion"), flow map linting, entry
scoring, and reachability including direction and unreachable targets.

Full suite: 733 passed.

## Not in this phase

- `project_paths` and `normalize_flow_map` — Phase 2 and Phase 4. Both are
  named in `PLANNED_ACTIONS` so `validate_inputs` says "planned but not
  implemented yet" rather than "invalid action".
- `export_scenario` / `import_scenario` on `threat_model_analyzer`, and
  narrowing its `analyze_document` description — Phase 3.
- README — Phase 4.

## Known issue, unchanged

`ScenarioTracker` in `threat_model_analyzer` is process-scoped, not
session-scoped as its docstring claims: `PluginLoader` is constructed once at
`shell.py:345`, `get_instance()` caches one instance per process, and `do_new`
never resets either. Scenarios leak across `new` and die on shell restart.
Deliberately left alone — Phase 3's `export_scenario` gives persistence a
manual path, which is the part that blocks work.
