# Adversary Path Projector

Takes a **named threat actor** and a **flow map of one application** and
projects the attack paths that actor would plausibly take through that
architecture. Each step is grounded in what MITRE ATT&CK documents the actor
doing, and bound to a real component of the flow map.

The paths are **projections, not findings**. Every export carries
`status: "projected"` and the sentence *"Projected from threat intelligence,
not a confirmed attack path."* The model reasons over the actor's documented
techniques the way an adversary would, but with the defender's inside view of
the architecture and its controls. What comes out is a set of hypotheses about
where the actor would go, which a person then tests.

It is the first of three tools that together turn *"how exposed are we to this
actor?"* into detection drafts a detection engineer can work from. The next
section walks through all three on one real question. The reference material
for this plugin follows it.

Design: `docs/specs/adversary_path_projector.md`.
Export shapes: `docs/specs/projector_export_shapes.md`.
Writing a flow map: [`examples/README.md`](examples/README.md).

**Implemented:** `profile_actor`, `validate_flow_map`, `project_paths`,
`summarize_run_group`, run records, step state and the continuity check,
cross-vendor group summaries, and export provenance. **Not implemented:**
`normalize_flow_map` (Phase 4). Flow maps are written by hand today.

---

# From a leader's question to detection drafts

## The ask

A senior leader has read about Scattered Spider. They own a line-of-business
application, Application B, and they ask:

> *"I am very concerned about Scattered Spider. How well protected is
> Application B, and what can we do to make it better?"*

A detection engineer has to answer that. Doing it by hand means reading the
actor's tradecraft, mapping it onto an architecture diagram, deciding which
steps matter, and drafting detections for them. The work takes days, and it
gives one engineer's reading, done once.

Three plugins speed that up, and make it repeatable across several models:

| # | Tool | LLM | Goes in | Comes out | Question it answers |
|---|---|---|---|---|---|
| 1 | `adversary_path_projector` | heavy | actor name + flow map | a path graph, a scenario seed and a run record, per projection | *Where would this actor plausibly go in this application?* |
| 2 | `attack_path_visualizer` | none | the path graph | a Mermaid / ASCII picture | *What shape does that projection have, and where do paths converge?* |
| 3 | `attack_path_detection_designer` | heavy (drafting only) | the graph + seed pair, and the flow map | one detection draft per path step, as JSON | *What would we look at to catch each step, and what can we not see?* |

The **outcome is the detection designer's JSON**: one draft per step, each
marked `validation_status: draft_unvalidated`. The engineer still reasons over
those drafts. The tools do not replace that judgement. They make it quick to
produce several independent sets of drafts, from several models, so the
engineer can see which patterns keep recurring and which outliers need a
closer look.

## What the tools can and cannot say to that leader

Settle this before running anything, because it shapes the answer you give
back.

The projector is **triage**. It answers two questions:

1. **Is there a control at all where this actor's plausible path lands?**
2. **Is there a credible path we have not considered?**

It does not measure how *good* a control is, it scores no likelihood, and it
issues no safety verdict. So *"how well protected is Application B"* cannot be
answered with a grade. What you can say is: *here are the routes this actor's
documented techniques would plausibly take, here is where each lands on a
control and where it lands on nothing, and here is what we can and cannot
observe at each step.* *"What can we do to make it better"* becomes a list of
detections to build, collection gaps to close and assumptions to test. That is
more useful than a grade, and it can be defended.

## Step 1 — Is the actor well documented? (free, no LLM)

```text
eventmill> run adversary_path_projector --action profile_actor --threat_actor "Scattered Spider"
```

```text
Actor Scattered Spider (G1015) — ATT&CK v19.2. 64 techniques attributed to the actor
directly; 17 more via associated software (scope 'delivery').
Tactic coverage: Reconnaissance (4), Resource Development (4), Initial Access (3),
Execution (3), Persistence (9), Privilege Escalation (7), Stealth (6), Defense Impairment (6), +7 more.
```

Sixty-four direct techniques gives the projector enough to work with. The
projector may use **only** these techniques (plus the 17 delivery-band
software techniques), and any step citing a technique outside the set is
rejected. So the size of this set limits what a projection can say. An actor
with two documented techniques produces a thin projection however hard the
model reasons. If you have a recent report that ATT&CK has not caught up with,
pass it in through `--intel_artifact_id` (a `threat_intel_ingester` output) to
widen the set.

Read the list before moving on. For Scattered Spider, much of the set is about
**identity**: `T1621` MFA Request Generation, `T1556.006` and `T1556.009`
(modifying MFA and conditional access), `T1598.004` Spearphishing Voice,
`T1684.001` Impersonation, `T1539` Steal Web Session Cookie, `T1078.004`
Cloud Accounts, `T1098` Account Manipulation, `T1484.002` Trust Modification.
That affects the next step.

## Step 2 — Is the map fit for this actor? (free, no LLM)

```text
eventmill> run adversary_path_projector --action validate_flow_map \
             --file_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json
```

```text
Flow map 'Application B': 14 components, 16 flows, 6 zones, 5 crown jewels, 25 controls.
VALID (0 error(s), 4 warning(s)).
Top entry candidates: users (internet, score 130), front_door (internet, score 90), okta (internet, score 65).
10 route(s) to crown jewels; shortest is front_door -> entry_api -> blob_storage
(2 hops, 2 boundary crossing(s), 0 unauthenticated).
```

The four warnings are known: `private_link` is not an `exposure` value, so it
is coerced to `internal` (twice), and two flows are declared twice. Neither
blocks projection, but read every warning on your own map, because most of them
mean the map is not saying what you meant.

Then do the step no tool can do for you: **check that the map contains the
places this actor attacks.** The projector routes only over declared flows.
If a flow is not declared, it does not exist for the projector. Application
B's map models Okta as one component, with MFA and sign-on policies as
controls. It has no help desk, no Okta admin plane, no reset or enrolment
process, and no deployment pipeline. For an actor whose documented techniques
centre on persuading a help desk and bending MFA policy, the planes it
operates on may not be on the map at all.

You have two options, and both are legitimate:

- **Project the map as it stands.** This answers *"given the application as
  documented, where would this actor go?"* If the leader's question is about
  the application itself, that may be enough.
- **Copy the map and add what is missing.** For example, an Okta admin console,
  a help-desk reset flow, or the CI/CD path into the containers. Validate it
  and project that instead. The detection designer records an analyst-edited
  map as `edited_map` lineage and never refuses it, so an edited copy tracked
  in git is the intended way of working (see *Flow maps are working documents*
  in the designer's README).

Whichever you choose, **write it down**. The answer to the leader has to say
which map it is about.

## Step 3 — Project several times, on several models (costs heavy-tier calls)

Projection is sampled. The same map and the same actor do not produce the same
paths twice. One run tells you what one model said once. Several runs tell
you which paths keep coming back. Several models tell you whether a path holds
up when a different model does the reasoning.

```text
eventmill> connect
eventmill> providers probe
eventmill> use gcp_gemini for adversary_path_projector
eventmill> run adversary_path_projector --action project_paths \
             --threat_actor "Scattered Spider" \
             --file_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json \
             --max_paths 3 --runs 3 --run_group ss-appb
eventmill> use anthropic for adversary_path_projector
eventmill> run adversary_path_projector --action project_paths ... (same arguments, same --run_group)
eventmill> use openai for adversary_path_projector
eventmill> run adversary_path_projector --action project_paths ... (same arguments, same --run_group)
```

- `connect` is required. Without it the plugin sees no LLM client and returns
  `LLM_UNAVAILABLE`, even though the banner lists models. `providers probe`
  checks each provider is actually reachable, which `connect` does not.
- `use <provider> for <tool>` is how an operator chooses the vendor. The prompt
  is byte-identical across the switch, and every record is stamped with the
  provider that answered. The plugin cannot choose a provider itself, and
  nothing fails over to another vendor automatically.
- Keep **everything else fixed** inside a group: the map, the actor,
  `--max_paths`, `--thinking_level`, `--objective`. The group summary refuses a
  group that mixes maps or actors, and it warns when these settings vary. A
  difference that shows up in the output should come from the model, not from
  a changed setting.
- `--objective "exfiltration of customer PII"` weights the projection toward a
  concern the leader named. Use it when they named one, and keep it the same
  across the group.
- **Budget the time.** A run takes roughly 40–80 s. An invocation is capped at
  600 s, so `--runs 3` is comfortable and `--runs 6` is not. Run `--runs 3`
  again with the same `--run_group` to build a bigger group. Three runs per
  provider is the minimum at which recurrence is counted at all.

Each invocation registers **one path graph and one scenario seed** (from its
first successful run), plus a run record per run. Note the artifact ids per
provider as they are printed, or list them later with `artifacts`. The graph and
seed pair from each invocation is what the next two tools read.

## Step 4 — Separate the common patterns from the outliers (free, no LLM)

```text
eventmill> run adversary_path_projector --action summarize_run_group --run_group ss-appb \
             --file_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json
```

This counts every **route** across the group's records. A route is the
sequence of components a path takes a foothold on, such as
`front_door -> entry_api -> entry_db`. It writes a Markdown report
(`adversary_projection_group_ss-appb_<stamp>.md`) that you can hand to someone.
With `--file_path` pointing at the map, the report also names the data
classification at each destination and the components on a recurring route
that have no controls recorded.

Two statistics, deliberately kept apart:

| Statistic | Question | Denominator |
|---|---|---|
| **recurrence** | does *this model* keep finding the route? | successful runs of that provider |
| **agreement** | does the route survive a change of model? | providers in the group (`unanimous`, `majority`, `partial`, or `single`) |

How to read them for the leader's question:

- **Recurring and unanimous.** Every model keeps finding this route. It is the
  **common pattern**, and it belongs at the centre of the answer.
- **Recurring for one model, absent for the others.** One model consistently
  sees something the others do not. This is the **outlier worth a person's
  time**. It may be the path nobody has considered, or it may be that model's
  bias. The route's assumptions and step rationale usually show which.
- **Seen once.** Sampling variance. Do not throw it away: read its assumptions,
  because an unlikely route can still rest on an assumption nobody has
  checked.

One caution. Independent vendors have converged closely on this tool before
(`docs/change_log/2026-09-14-stage-e-live-cross-vendor-run.md`). Agreement
may show that the prompt leaves room for only a few readings as much as it
shows that the finding is robust. Treat `unanimous` as *"worth building for"*,
not as proof.

The report also collects each route's **assumptions** into a checklist, and
counts **state gaps**, which are steps needing access that no earlier step
provided. Read both as feedback on the estate *and* on the map (see *What a
projection's assumptions say about your map* in `examples/README.md`). An
assumption like *"the entry API accepts tokens minted for the SPA"* is a test
to run against the real system.

## Step 5 — Look at the shape (free, no LLM)

```text
eventmill> run attack_path_visualizer --artifact_id <graph id> --format mermaid --attack_type "Scattered Spider"
```

Render the graph from each provider's invocation. The Mermaid output marks
entry points, exit points and **convergence points**, which are techniques more
than one path reaches. When they sit on one component, a single detection
there covers several routes. Putting two providers' renderings side by side is
the quickest way to see where they differ.

The picture is by technique, not by component, and it does not show controls.
See the visualizer's README for what it shows and what it leaves out. Use it to
orient yourself and to show the leader, not as the record.

## Step 6 — Draft detections for each step (free check, then heavy-tier calls)

Choose which projections to draft from. **At least two is the useful minimum:**
one pair whose paths include the common pattern, and one whose paths include
the outlier. Check first, for free:

```text
eventmill> run attack_path_detection_designer --action digest \
             --artifact_ids <graph id>,<seed id> \
             --flow_map_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json
```

The digest gives three lines per step. Each shows the context grade
(`component_bound` is what you want), the component's technologies,
`monitoring_claim`, the projector's `state_check`, the `multistep_access`
assessment, and the one or two narrowest uncovered ATT&CK mitigations. If the
pair is not `verified`, or the map lineage is not what you expect, stop and fix
that before spending anything. Then draft:

```text
eventmill> use anthropic for attack_path_detection_designer
eventmill> run attack_path_detection_designer --action generate_detections \
             --artifact_ids <graph id>,<seed id> \
             --flow_map_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json
```

Two independent choices of model are now in play. Keep them apart:

| | Chosen by | Decides | Recorded as |
|---|---|---|---|
| **projection model** | `use … for adversary_path_projector` | *which paths* | `engagement.projection_model` |
| **generation model** | `use … for attack_path_detection_designer` | *which detections* | `generation_model` |

Drafting **the same pair** under two generation models gives two sets of
drafts with **identical `draft_id`s**. A `draft_id` comes from the projection
and the step's position, not from the model, so the two sets line up step by
step. That is the cleanest comparison available: same step, same context,
different model. Drafting **different pairs** compares projections, not
detection design.

Before grading anything as a cross-vendor result, **check `generation_model`
on each output.** Two runs once labelled as different vendors both reported
the same served model. The field exists so that this is visible, and nothing
yet explains the case.

The result is persisted as `attack_path_detection_designer_<stamp>.json` and
registered as an artifact. A run that produces fewer valid drafts than steps
fails with `GENERATION_INCOMPLETE`. The message explains why, and the drafts
that did pass are saved and registered as
`attack_path_detection_designer_partial_<stamp>.json`. Read those drafts, but
re-run before treating the set as complete.

## Step 7 — Reason over the drafts

This is the engineer's work. Each file holds `drafts[]`, and each draft keeps
its working content under `x_eventmill`. For each step, read:

| Field (under `x_eventmill`) | What it tells you |
|---|---|
| `node.telemetry_readiness` | `stream_available`, `periodic_only`, or `none_declared`. The last means there is **nothing to look at**, which is a collection gap and a direct answer to *"what can we do"* |
| `node.context_completeness` | how much of the estate the draft could see. `component_bound` means it knew the product, the zone and the authentication |
| `assessment` | `actor_evidence` and `multistep_access`, each with a reason and a basis. `multistep_access: true` means the step depends on access the path never established, so test the assumption before trusting the step |
| `telemetry.required_fields`, `detection_logic` | the hypothesis to test, over fields the telemetry library says the source actually has |
| `grounding.limitations`, `caveats` | what the draft cannot see or distinguish |
| `review_flags` | questions for whoever tests the rule, such as a field collected and never read, or a condition that fires on a missing value |

Keep the Step 6 digest open next to the drafts. Two things a draft leaves out
are there: `monitoring_claim` (whether the map claims something watches this
component, which is a claim and not coverage), and the step's mitigations. A
covered mitigation means a tagged control already exists, so the draft is a
**tuning** case. The focus names the narrowest missing mitigation.
`--action validate_input` returns the full context pack if you need every
field.

Then compare across files:

- **A step that recurs across projections, drafted consistently across
  generation models**, is the common pattern. It is where a built and tested
  detection pays off most.
- **A step only one projection found, or one where the generation models
  disagree about the telemetry or the logic**, is the outlier. Some outliers are
  noise. Others are the one place where a model saw a join key, a blind spot or
  a credential assumption the others missed. Reading those carefully is the
  point of running more than one model.
- **The same `none_declared` step in every run** is not a detection to write.
  It is a collection gap to close.

Every draft says `draft_unvalidated`, and it means it. The drafts are
hypotheses to test against real telemetry, not rules to deploy.

## Step 8 — Answer the leader

An answer these tools can support:

> Across *N* projections on *K* models, Scattered Spider's documented
> techniques lead into Application B mainly through *these routes*, against
> *[the map as documented / our amended map, which adds the help-desk and
> admin planes]*. At *these steps* a control exists; at *these* nothing does.
> We can build *M* detections with telemetry we already collect. At *P* steps
> we cannot see the activity at all, and closing that needs *this collection*.
> The paths rest on *these assumptions*, which we will test. One model also
> found *this route*, which we are looking at separately.

An answer they cannot support: *"We are protected against Scattered Spider."*
Nothing here measures control quality or likelihood, and every path is a
projection.

## Keeping the work

On Cloud Run the container's workspace is ephemeral. By default only the
visualizer's output is exported automatically. Before closing the session,
push everything to the common bucket:

```text
eventmill> export --all ss-appb
```

Or set `EVENTMILL_AUTO_EXPORT_TOOLS` to include `adversary_path_projector`
and `attack_path_detection_designer`. Group summaries read only records
registered in **the current session**, so finish the group before running
`new`.

---

# Reference

## Actions

| Action | LLM | What it does |
|---|---|---|
| `profile_actor` | none | Resolves an actor name, alias or ATT&CK id, and returns tactic coverage, associated software and procedure examples. Answers *"is this actor known, and how well?"* in milliseconds. |
| `validate_flow_map` | none | Lints the map, ranks the entry surface and computes routes from every externally exposed component to every crown jewel. `project_paths` refuses a map with blocking errors. |
| `project_paths` | heavy | Binds techniques from the actor's closed set onto components, along routes the map declares. Writes the graph and seed, plus a run record per run under `--export` or `--runs`. |
| `summarize_run_group` | none | Counts route recurrence per provider and agreement across providers for one `--run_group`, and writes a Markdown report. |
| `normalize_flow_map` | light | **Not implemented.** Prose / Mermaid to canonical map JSON. |

## Arguments

| Argument | Actions | Default | Notes |
|---|---|---|---|
| `threat_actor` | profile, project | — | Name, alias or ATT&CK id. `Cozy Bear`, `APT29` and `G0016` resolve alike |
| `software_scope` | profile, project | `delivery` | `none`, `delivery` or `all`. How much of the actor's tooling-derived techniques to allow |
| `intel_artifact_id` | profile, project | — | A `threat_intel_ingester` output whose techniques are added to the set |
| `flow_map` / `flow_map_artifact_id` / `file_path` | validate, project | — | One of the three. `file_path` also adds control context to `summarize_run_group` |
| `max_paths` | project | 3 | Path count is what the model returns, up to this. Nothing downstream may assume it |
| `objective` | project | — | An analyst concern to weight the projection toward |
| `thinking_level` | project | `medium` | Stated explicitly, because the dispatcher would otherwise pick `high` |
| `export` | project | false | Write a run record per run |
| `runs` | project | 1 | 1–25 runs, each its own call and record. Implies `export` |
| `run_group` | project, summarize | `ungrouped` | Label tying a comparison set together |

## Grounding: the model chooses placement, never techniques

| Phase | LLM | Work |
|---|---|---|
| A | no | Resolve the actor. Build the closed technique set, with the software-derived block kept separate and banded. Normalize the map, rank entries, compute routes. |
| B | heavy | Bind techniques from the set to components along declared flows, with rationale, access state, and assumptions. |
| C | no | Reject any step citing a technique outside the set or a component outside the map. Reconcile tactics to ATT&CK v19.2. Attach mitigations and compare them with the controls declared on the step's component. Run the continuity check. |

A technique the actor has no documented use of is **rejected, not repaired**,
because that is the exact failure the closed set exists to prevent. A tactic
error *is* repaired (`TACTIC_CORRECTED`), using the same vocabulary helpers the
ingester uses. `Defense Evasion` is retired in v19 and never emitted.
`Stealth` and `Defense Impairment` replace it.

`evidence` (`documented` or `via_software`) is **derived from the closed set,
never read from the model's reply**. A model is not trusted to label the
strength of its own source.

The **continuity check** flags a step that needs access no earlier step
provided (`STATE_GAP`). A path that lands on a component with no declared flow
in is flagged `HOP_NOT_DECLARED`. A path may never skip a hop point.

## What a projection produces

Three JSON documents per invocation, sharing one `provenance.run_id`:

| Document | File | Read by |
|---|---|---|
| **path graph** | `adversary_path_graph_<stamp>.json` | `attack_path_visualizer`, `attack_path_detection_designer` |
| **scenario seed** | `adversary_scenario_seed_<stamp>.json` | `attack_path_detection_designer`, `threat_model_analyzer import_scenario` |
| **run record** | `adversary_projection_run_<stamp>_<id>.json` (with `--export` / `--runs`) | `summarize_run_group` |

The graph and the seed are **two renderings of one projection**, and each
carries fields the other lacks. The designer joins them on `run_id` and
records the pair as `verified`. `provenance` also carries the flow map's hash,
the prompt's hash, the ATT&CK release, the tool's code identity, and the
provider and served model. That is what lets a detection draft name the model
that projected its path. The complete field-by-field description is
`docs/specs/projector_export_shapes.md`.

The seed also chains to `threat_model_analyzer`
(`import_scenario --artifact_id <seed>`), one scenario per path, for its
bypass-difficulty and gap analysis.

## Mitigation lists are narrower than they look

`uncovered_mitigations` means *"no **tagged** control on **this step's
component** carries this M-ID"*. It does not mean the estate lacks the
control. A control with no `mitre_mitigation_id` never covers anything, and
estate-wide and flow controls are not consulted. On the current fixtures 163
of 169 mitigations read as uncovered, and most of those are ATT&CK's broadest.
The summary says this in its closing caution. The detection designer reduces
the list to the one or two narrowest per step. Tag your controls and the list
gets shorter and more trustworthy.

## Run records and groups

Covered in depth in [`examples/README.md`](examples/README.md#recording-runs):
what a record holds (the split between `deterministic` and `sampled` is the
point), how routes are counted and a representative chosen, why failed runs
are recorded too, and how to build a large group from small batches. The
cross-vendor rules come from
`docs/change_log/2026-09-14-group-summary-provider-dimension.md`.

One limitation: `model.model_configured` is what was asked for. Read
`model_served` for what answered.

## Why this plugin is not auto-invocable

`safe_for_auto_invoke` is **false**. Three of the four actions are free and
deterministic, but the flag covers the whole plugin, and `project_paths` is a
heavy-tier call an operator should choose to spend. The detection designer
has the same shape for the same reason.

## Sensitivity

A flow map, a run record and a raw reply together describe your estate's
topology, its trust boundaries, which controls are missing, and a model's
reasoning about how to exploit them. Treat a corpus of them as you would the
architecture itself. They are written with default permissions and no
encryption.

## Known open items

- **Entry ranking can put a dead end first.** A component with no outbound
  flow (`okta` on Application B) still ranks as an entry candidate. Routes are
  unaffected. See `docs/change_log/2026-09-20-projector-scoring-observations.md`.
- **Unauthenticated hops are counted without regard to kind.** A door and an
  open network port count as the same weakness. Same entry.
- **`on: flow` controls are never emitted.** Controls on flows and estate-wide
  controls are not evaluated per step.

## Where to look

| Question | File |
|---|---|
| Writing and validating a flow map; entry ranking; reachability | [`examples/README.md`](examples/README.md) |
| Field-by-field export shapes | `docs/specs/projector_export_shapes.md` |
| Step state and the continuity check | `docs/specs/adversary_path_projector_step_state.md` |
| Running across vendors | `docs/specs/projector_three_vendor_run.md` |
| Every enum and reserved spelling | `docs/specs/reserved_vocabulary.md` |
| Rendering a graph | `../attack_path_visualizer/README.md` |
| Drafting detections from a graph and seed | `../attack_path_detection_designer/README.md` |
