# Adversary Path Projector

Version: 0.2.0
Pillar: `threat_modeling`
Status: Phases 1, 2 and 3 implemented (`profile_actor`, `validate_flow_map`,
`project_paths`, and the `threat_model_analyzer` handoff). Phase 4
(`normalize_flow_map`, README) outstanding.

Scope: first-step triage. The tool answers two questions — *is there a control
at all where the actor's path lands*, and *is there a credible path we have not
considered*. It does not assess how good a control is, and it does not issue a
safety verdict; both are later steps, and the second is a human conversation.

---

## Purpose

Given a **named threat actor** and a **flow map of an application**, produce the
attack paths that actor would plausibly take through that specific
architecture, grounded in what MITRE ATT&CK documents the actor doing.

Every existing path in the `threat_modeling` pillar is retrospective: a
published report goes in, techniques come out, `attack_path_visualizer` draws
them. Nothing runs the other direction. `threat_model_analyzer` gets closest,
but its `analyze_document` action is a single free-text LLM call that returns
prose under 1000 words — it asks for technique IDs and never parses or
validates them, and it imports nothing from `framework.reference_data.mitre_attack`.
It cannot know what an actor does.

The actor half is already a deterministic lookup. `mitre_attack.py` indexes 178
groups, 831 software entries and 96 mitigations with aliases resolved:
`find_group("Cozy Bear")` → `G0016`, then `techniques_for_group()`,
`techniques_for_software()`, `mitigations_for_technique()`,
`procedures_for_technique()`. The missing half is the application — no flow
map, DFD or trust-boundary vocabulary exists anywhere in the repo.

---

## Grounding discipline

**The LLM never chooses techniques. It only chooses placement.**

This is the property the whole tool's credibility rests on, and it is enforced
deterministically rather than by prompt instruction.

| Phase | LLM | Work |
|---|---|---|
| A | no | Resolve actor → group id. Build the core set from `techniques_for_group(gid)` (∪ intel-report techniques, see below) and a **separate** software-derived block (see below). `allowed_techniques` is their union. Enrich each from `mitre_techniques.json`. Normalize the flow map, rank entry-surface candidates. |
| B | heavy | Given the closed technique set and the normalized flow map, bind techniques to components: each step is `technique_id` + `tactic` + `component_id` + rationale. |
| C | no | Reject any step whose technique is outside `allowed_techniques` or whose component is absent from the flow map. Normalize tactics through `canonical_tactic()` / `resolve_legacy_tactic()`. Validate every id with `validate_technique_id()`. Attach `mitigations_for_technique()` and diff against declared controls. |

Phase C rejects rather than repairs technique hallucinations: a step naming a
technique the actor has no documented use of is not a near-miss to be corrected,
it is the failure mode the closed set exists to prevent. Tactic errors *are*
repaired, using the same vocabulary helpers the ingester uses.

### Evidence marking

Each step carries `evidence`, recording how strong the actor-to-technique claim
is:

- `documented` — ATT&CK attributes this technique to this actor directly.
- `via_software` — only the actor's tooling implements it (see the software
  block below).

**The placement is a model inference either way.** That is the point of the
field: capability is sourced, placement never is, and nothing in the output may
read as "this actor attacked this application." Every projected output —
`summarize_for_llm()`, both artifact files (`status: "projected"` plus an
`interpretation` field) and `threat_model_analyzer`'s report for an imported
scenario — carries the same sentence: "Projected from threat intelligence, not
a confirmed attack path." "Projected" rather than "estimated": the tool scores
no likelihood, and "estimated" invites the question of how likely. The framing: an LLM reasons over the actor's
documented techniques the way an adversary would, but with the organization's
inside view of its own architecture and controls.

`evidence` is **derived from the closed set, never read from the model's
reply** — a model cannot be trusted to label the strength of its own source. A
contract test asserts that an `evidence` key in the reply is ignored.

### Tactic vocabulary

Taken from `TACTIC_ORDER`, and the Phase B prompt names the ATT&CK v19 tactics
explicitly the way `threat_intel_ingester` does. "Defense Evasion" was retired
in v19 and must never be emitted; `Stealth` and `Defense Impairment` replace it.

### The software block is separate, and banded

ATT&CK maps a group to its tooling and the tooling to every technique that
tooling implements. Merged into the core set that swamps it — for APT29, 66
directly attributed techniques become 230.

Worse, most of what it adds is not informative. An actor generally uses
whatever is already on a host to move laterally, enumerate and collect: net.exe,
RDP, SMB, LSASS. That their malware also implements those techniques says
almost nothing about what they would do on a given estate. What *is* specific
to the actor is the delivery chain — the dropper, the loader, the implant and
the channel it beacons over are all properties of the software.

So software-derived techniques live in their own block, banded by tactic:

- **`delivery`** — the technique's tactics include Resource Development,
  Initial Access, Execution, Persistence or Command and Control. The actor's
  tooling determines the technique here, so the mapping is real signal.
- **`operational`** — everything else. Dominated by living-off-the-land
  behaviour any actor would perform.

`software_scope` selects how much of it enters the allowed set: `none`,
`delivery` (the default), or `all`. Measured effect:

| Actor | core | +delivery | +all |
|---|---|---|---|
| APT29 | 66 | 110 | 230 |
| Volt Typhoon | 81 | 97 | 125 |
| Scattered Spider | 64 | 81 | 139 |

Persistence is the marginal band member — implant install mechanisms are
tool-chosen often enough to keep, even though `schtasks` is as
living-off-the-land as it gets.

Two consequences worth stating:

- `tactic_coverage` and `uncovered_tactics` are computed over the **core set
  only**, so the stronger claim stays visible. Under `software_scope: "all"` a
  tactic can be listed as uncovered while techniques for it sit in
  `allowed_technique_ids`. Both output fields say so.
- The block carries a `source` field (`attck_lookup` today). Keeping it out of
  the core set is what lets an on-demand lookup — a websearch for current
  tooling intel on the named actor — replace or augment it later without
  touching the directly attributed techniques or the Phase C validator.

### Actors ATT&CK does not cover

`intel_artifact_id` accepts a `threat_intel_ingester` output and unions its
`mitre_mappings` into `allowed_techniques`. This covers vendor-named actors
absent from the lookup, and intel newer than the lookup build. Provenance is
tracked per technique — `attck_group`, `attck_software`, or `intel_report` — so
the output can always say where a capability claim came from.

---

## Flow map

New canonical schema, `schemas/flow_map.schema.json`. Control fields use
`threat_model_analyzer`'s vocabulary verbatim (same seven defense layers, same
`implementation_status` / `bypass_difficulty` / `detection_capability` enums) so
the two tools' artifacts interoperate without a shared import — vocabulary
shared, code isolated, per the convention in CLAUDE.md.

```json
{
  "application": "Customer Portal",
  "zones": [
    {"id": "dmz", "name": "DMZ", "trust_level": "untrusted"},
    {"id": "app", "name": "Application tier", "trust_level": "semi_trusted"},
    {"id": "data", "name": "Data tier", "trust_level": "trusted"}
  ],
  "components": [
    {
      "id": "web",
      "name": "Portal frontend",
      "type": "web_app",
      "zone": "dmz",
      "exposure": "internet",
      "technologies": ["nginx", "nodejs"],
      "authentication": "saml_sso",
      "data_classification": "pii",
      "controls": [
        {
          "name": "WAF",
          "control_type": "perimeter",
          "implementation_status": "implemented",
          "bypass_difficulty": "medium",
          "detection_capability": "high"
        }
      ]
    }
  ],
  "flows": [
    {
      "id": "f1",
      "from": "web",
      "to": "api",
      "protocol": "https",
      "authenticated": true,
      "crosses_boundary": true
    }
  ],
  "crown_jewels": ["customer_db"]
}
```

`exposure` (`internet` / `partner` / `internal` / `management`) and
`crosses_boundary` are what let Phase A rank entry candidates deterministically,
before the LLM sees anything.

Analysts will not hand-write this, so conversion is a separate cheap action
(`normalize_flow_map`, light tier) that saves canonical JSON as its own
artifact — reviewable, editable, and reusable across many actors without
re-paying for it.

---

## Actions

| Action | LLM | Purpose |
|---|---|---|
| `profile_actor` | none | `find_group` → tactic coverage, associated software, top procedure examples. A 20 ms answer to "is this actor known?" rather than a failed heavy-tier call. |
| `normalize_flow_map` | light | Markdown / Mermaid / prose → canonical flow map JSON, saved as an artifact. |
| `validate_flow_map` | none | Lint: dangling flow endpoints, unzoned components, no internet-exposed entry point, orphaned crown jewels. |
| `project_paths` | heavy | The main action. Phases A → B → C. |

---

## Outputs

### 1. Attack graph artifact (`json_events`)

Exactly the shape `attack_path_visualizer._load_stages_from_artifact`
(`plugins/threat_modeling/attack_path_visualizer/tool.py:894`) already reads:

```
{"mitre_mappings": [...],
 "attack_graph": {"paths": [{"path_id", "description",
                             "steps": [{"technique_id", "tactic", "leads_to"[]}]}],
                  "convergence_points": [], "branch_points": []}}
```

Steps carry additional keys — `component_id`, `asset`, `evidence`, `rationale`,
`mitigations` — which today's renderer ignores. So the tool chains to
`attack_path_visualizer` on day one with no changes to that plugin.

### 2. Scenario seed artifact (`json_events`)

Populated `SecurityControl` and `AttackEvent` structures matching
`threat_model_analyzer`'s dataclasses field-for-field, with
`blocking_controls` / `detecting_controls` already resolved from the flow map's
declared controls and `technique_id` already validated. `required_access` and
`resulting_access` are defaulted deterministically from the step's tactic
(Initial Access → `none` → `user`, Privilege Escalation → `user` → `admin`, and
so on); the LLM may override.

**One path per scenario.** `AttackEvent.sequence_order` is a linear integer and
the projector produces a DAG. Flattening a branching graph into one sequence
would misrepresent it, so the seed emits one scenario per `path_id`.
`import_scenario` imports each path as its own scenario, up to `--max_paths`
(default 6); `--path_id` imports one. There is no "highest-ranked" default —
the projection prompt does not rank paths, so seed order is only reply order.

`security_controls` carries **every** control the flow map declares:
per-component, per-flow and estate-wide. Only per-component controls were
emitted until Phase 3, which made gap analysis report an estate-wide SIEM as
absent.

Each event carries the step's `tactic` and `evidence` (`documented` /
`via_software`) so an imported scenario can be audited on its own.

`blocking_controls` is per component: any implemented preventive control on the
component the step lands on counts, whether or not it addresses that technique.
That is the right test for triage's "is there a control at all" and a known
overstatement for "is the control good enough", which is deferred to a separate
control-quality step.

---

## Changes to `threat_model_analyzer`

Three changes, all additive except the third.

### `export_scenario` (new action)

Returns the full structured scenario — `security_controls` and
`attack_sequence` included — as `result.result`, so the shell's auto-persist
(`framework/cli/shell.py:3033`) writes a reloadable artifact.

This closes a real defect. No current action can serialize a scenario:
`list_scenarios` returns `to_dict()`, which is counts only, and `export`
returns markdown prose. A half-built threat model cannot be saved or reloaded,
which is exactly what the plugin's own documented six-step workflow asks the
analyst to build.

### `import_scenario` (new action)

`import_scenario --artifact_id <id> [--path_id <id>] [--max_paths N]` loads a
scenario seed into the `ScenarioTracker`, one complete scenario per path. `gap_analysis` and `export`
then run unchanged against ATT&CK-grounded events instead of fifteen hand-typed
`add_event` calls. This is the whole reason for the split: the projector never
reimplements bypass-difficulty or defense-coverage analysis, it just hands over
a populated scenario.

Requires adding `"actor_projection"` to the `source_type` enum in
`schemas/input.schema.json`, so projected scenarios stay distinguishable from
analyst-built ones in the exported report.

### Narrow `analyze_document`

Edit `description_long` and `THREAT_MODEL_PROMPT` so the action claims document
summarization rather than attack-path extraction. It currently advertises
capability it does not structure, and once the projector exists that overlap is
what makes the two tools hard for the router to tell apart.

### Known issue left open

`ScenarioTracker` is process-scoped, not session-scoped as its docstring
claims: `PluginLoader` is constructed once at `shell.py:345`, `get_instance()`
caches one instance per process (`framework/plugins/loader.py:90`), and
`do_new` never resets either. Scenarios leak across `new` and die on shell
restart. Deliberately not fixed here — `export_scenario` / `import_scenario`
give persistence a manual path, which is the part that blocks work.

---

## Manifest

```
tool_name:            adversary_path_projector
pillar:               threat_modeling
model_tier:           heavy
requires_llm:         true
timeout_class:        long
cost_hint:            moderate
safe_for_auto_invoke: false
stability:            experimental
artifacts_consumed:   ["json_events", "text"]
artifacts_produced:   ["json_events", "text"]
chains_to:            ["attack_path_visualizer", "threat_model_analyzer"]
chains_from:          ["threat_intel_ingester", "threat_report_analyzer"]
```

Two notes.

`stability: "experimental"` is deliberate. `"stable"` is what the other 15
manifests declare and is precisely the value that makes
`scripts/validate_manifests.py` exit non-zero. A new plugin should not add a
16th instance of a known-broken value.

The plugin imports `QueryHints` and `ArtifactRef` from
`framework.plugins.protocol` rather than defining local result dataclasses,
matching `threat_report_analyzer` and `threat_intel_ingester` — the convention
for LLM-using plugins.

### Routing

`framework/routing/config/keywords.json`, `threat_modeling` rules, add:
`threat actor`, `adversary`, `apt`, `flow map`, `architecture`,
`what would they do`.

---

## Phasing

**Phase 1 — deterministic spine. DONE.** Flow map schema and `validate_flow_map`,
`profile_actor`, `allowed_techniques` assembly with provenance, entry-surface
ranking, contract tests. No LLM. This is the part Phase B's output gets checked
against, so it is built and tested first.

**Phase 2 — projection. DONE.** Phase B prompt, Phase C validator, both
artifacts, `summarize_for_llm()` under the 2000-character cap. Verified
against Gemini 3.1 Pro; see
`docs/change_log/2026-09-09-adversary-path-projector-phase-2.md`.

**Phase 3 — `threat_model_analyzer` handoff. DONE.** `export_scenario`,
`import_scenario`, `source_type` enum, narrowed `analyze_document`; the seed
gained `tactic`, `evidence` and the controls it used to drop. See
`docs/change_log/2026-09-11-adversary-path-projector-phase-3.md`.

**Phase 3c — step state (proposed, awaiting approval).** Each step records
the attack state connecting it to the next — precondition, access before and
after from a fixed vocabulary, what it exploits, what it yields, and the
assumptions a threat modeller could test — with a deterministic continuity check
that flags a step needing access no earlier step provided. Path mapping is
unchanged. Design: `docs/specs/adversary_path_projector_step_state.md`.
Proposed to land before 3b.

**Phase 3b — run-group summary (agreed, not started).** For one `run_group`,
count how often each path recurs across runs and show one representative
variant per recurring path, not every near-duplicate. Recurring means present in
at least half the runs of a group of three or more. Answers triage's second
question — a credible path is sourced *and* recurs.

**Phase 4 — ergonomics and docs.** `normalize_flow_map`, README,
`docs/change_log/` entry.

### Deferred: rendering the component binding

`_build_dag_from_attack_graph`
(`plugins/threat_modeling/attack_path_visualizer/tool.py:141`) constructs every
`DAGNode` with `controls=[]` and `gaps_detected=[]` and never populates them —
the fields exist but nothing fills them on the `attack_graph` path. Teaching it
to read `controls`, `gaps_detected` and `asset` off each step when present is
purely additive; absent fields behave exactly as today. It is what turns the
Mermaid output from a generic actor TTP graph into a picture of *this*
application.

Worth doing, but it is a distinct change to a 1180-line renderer and should not
ride along silently with a new plugin.
