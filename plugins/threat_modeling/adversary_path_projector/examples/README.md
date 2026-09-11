# Flow map examples

A **flow map** is the application half of `adversary_path_projector`. The actor
half is a deterministic ATT&CK lookup; the flow map is the part you write. It
describes the estate you defend — what it is built from, which parts trust which,
what talks to what, and what an attacker would ultimately want.

Given both halves the projector answers a question nothing else in the repo
answers: *given this named actor and this architecture, what would they actually
do?*

This directory holds three worked examples. Read one, copy it, change it into
your own estate.

---

## The three examples

| File | Estate | Why it is here |
|---|---|---|
| `claims_portal_flow_map.json` | Internet-facing claims portal, 7 components | The simplest shape: a classic three-tier web app. Start here. |
| `telemetry_saas_flow_map.json` | Multi-tenant telemetry SaaS with its own build pipeline, 10 components | A **supply-chain** shape — the build path runs parallel to the runtime path and re-enters it at the cluster. |
| `plant_ot_flow_map.json` | Bottling plant with corporate IT, an IT/OT DMZ and a control network, 10 components | A **segmented** shape — five trust zones, unauthenticated industrial protocols, and a dual-homed workstation that bypasses the DMZ. |

All three deliberately contain findings. That is the point: a flow map with no
weaknesses projects nothing interesting. Each file's `description` field says
what was planted in it.

## Running them

The projector takes a flow map inline, from an artifact, or from a file path.
From the shell:

```
eventmill> connect
eventmill> run adversary_path_projector --action validate_flow_map \
             --file_path plugins/threat_modeling/adversary_path_projector/examples/plant_ot_flow_map.json

eventmill> run adversary_path_projector --action project_paths \
             --threat_actor "Volt Typhoon" \
             --file_path plugins/threat_modeling/adversary_path_projector/examples/plant_ot_flow_map.json \
             --max_paths 2
```

`connect` is required before `project_paths` — without it the plugin sees no LLM
client and returns `LLM_UNAVAILABLE`, even though the startup banner lists the
models. `validate_flow_map` needs no LLM and no `connect`.

**Always run `validate_flow_map` first on a new map.** It is free, and
`project_paths` refuses to spend a heavy-tier call on a map with blocking errors.

## Which actor to pair with which map

The projector constrains the model to techniques the actor is documented to use,
so the pairing matters — an actor with no relevant tradecraft produces a thin
projection:

| Map | Try |
|---|---|
| `claims_portal_flow_map.json` | `Scattered Spider`, `FIN7`, `APT29` |
| `telemetry_saas_flow_map.json` | `APT29`, `Sandworm Team`, `Lazarus Group` |
| `plant_ot_flow_map.json` | `Volt Typhoon`, `Sandworm Team`, `Dragonfly` |

Names, aliases and ATT&CK ids all resolve — `Cozy Bear`, `APT29` and `G0016`
are the same lookup.

**Check the actor before you spend a projection on it.** Reputation is a poor
guide to how much ATT&CK actually documents. `profile_actor` is free and tells
you the size of the closed set:

```
eventmill> run adversary_path_projector --action profile_actor --threat_actor "Dragonfly"
```

The actors above carry 58–94 directly attributed techniques each, which is
enough to project from. Plenty of well-known names do not: `TEMP.Veles`, the
group behind TRITON and the obvious pick for an OT map, has **2**. An actor that
thin produces a thin projection, and no amount of reasoning depth fixes it —
reach for `intel_artifact_id` to widen the set from a report instead.

---

# Writing your own

## Anatomy

A flow map is one JSON object with five parts. Only `application` and
`components` are required, but a map without `flows` and `crown_jewels` cannot
produce routes, which is most of the value.

```json
{
  "application": "Tiny App",
  "zones":        [ ... ],
  "components":   [ ... ],
  "flows":        [ ... ],
  "crown_jewels": [ ... ],
  "controls":     [ ... ]
}
```

- **`zones`** — trust boundaries. Components reference them by id.
- **`components`** — the systems. Everything else refers to these by id.
- **`flows`** — directed edges. Reachability is computed over these and nothing
  else.
- **`crown_jewels`** — component ids worth attacking. The targets routes are
  computed *to*.
- **`controls`** — estate-wide controls not tied to one component.

## A minimal working map

This validates clean and produces a route. Everything else is elaboration:

```json
{
  "application": "Tiny App",
  "zones": [
    {"id": "edge", "trust_level": "untrusted"},
    {"id": "data", "trust_level": "restricted"}
  ],
  "components": [
    {"id": "web", "name": "Web front end", "type": "web_app",
     "zone": "edge", "exposure": "internet", "authentication": "password"},
    {"id": "db", "name": "Customer database", "type": "database",
     "zone": "data", "exposure": "internal", "authentication": "password",
     "data_classification": "pii"}
  ],
  "flows": [
    {"id": "f1", "from": "web", "to": "db", "protocol": "postgres",
     "authenticated": true}
  ],
  "crown_jewels": ["db"]
}
```

Which produces:

```
entry surface   web  130  [internet-facing, sits in a untrusted zone,
                           no implemented preventive control]
                db    10  [internal-facing, sits in a restricted zone,
                           no implemented preventive control]
routes          web -> db   1 hop, 1 boundary crossing, 0 unauthenticated hops
```

## The fields that actually change the output

Most fields are documentation. These five drive the analysis, so spend your
effort here and be honest about them:

| Field | Where | What it drives |
|---|---|---|
| `exposure` | component | Entry ranking, and whether the component can start a path at all |
| `authentication` | component | Entry ranking — `none`, `anonymous`, `public`, `n/a` or empty all count as unauthenticated |
| `controls[].implementation_status` | component | Whether a control lowers the score, and whether its mitigation counts as covered |
| `flows` | top level | **All** reachability. A component with no flow is unreachable no matter how exposed it is |
| `crown_jewels` | top level | The targets. No crown jewels means no routes |

`technologies` deserves a special mention. It does not affect scoring or
reachability, but it is in the prompt and it visibly steers the model toward
technology-appropriate techniques. Name real products and frameworks
(`nginx`, `django`, `kubernetes`, `postgres`), not categories.

## How entry ranking works

Every component is scored as an entry candidate, and each score carries the
reasons that produced it. The weights are relative — the absolute numbers mean
nothing outside the ranking:

```
exposure         internet +100   partner +60   management +45   internal +5
zone trust       untrusted +15   semi_trusted +5   trusted 0   restricted -10
no auth          +25       (authentication is none/anonymous/public/n/a/empty)
no preventive    +15       (no implemented control in a preventive layer)
each implemented trivial 0   low -3   medium -10   high -20   very_high -30
preventive control
```

Scores floor at zero. Preventive layers are `perimeter`, `network`, `endpoint`,
`application` and `identity` — a `monitoring` or `data` control never changes an
entry score, because it records an attacker rather than stopping one.

**Only `implemented` controls lower a score.** A `partial`, `planned` or
`missing` control earns nothing, and a component whose controls are all planned
scores as if it had none. This is deliberate and it is the single most useful
thing the ranking tells you — in `plant_ot_flow_map.json` the VPN tops the
ranking at 130 precisely because its MFA is still `planned`.

## How reachability works

Breadth-first over the declared flows only. Nothing is inferred from zones,
naming or component type — **if you did not declare the flow, it does not
exist.**

- Flows are directed. `bidirectional: true` opens the reverse edge.
- Routes are computed from every externally exposed component (`internet` or
  `partner`) to every crown jewel, shortest first.
- Each route reports `hops`, `boundary_crossings` and `unauthenticated_hops`.
- A crown jewel no entry point can reach lands in `unreachable_crown_jewels`.
  That usually means your map is incomplete, not that the asset is safe.
- If nothing is externally exposed, ranking falls back to the highest-scoring
  component so an internal-only map still produces routes.

`crosses_boundary` is derived by comparing the two components' zone trust levels,
so you rarely need to set it. Set it explicitly when the derivation would be
wrong — a flow between two components in the same zone that nonetheless leaves a
security boundary.

## Errors vs warnings

The split is deliberate: **errors** are what makes projection impossible and stop
the run before any LLM call; **warnings** are things the tool can work around,
and the normalized value tells you which fallback it applied.

Errors — these block `project_paths`:

| Code | Meaning |
|---|---|
| `MISSING_APPLICATION` | No `application` name |
| `NO_COMPONENTS` | No components declared |
| `DUPLICATE_COMPONENT_ID` / `DUPLICATE_ZONE_ID` | An id declared twice |
| `COMPONENT_MISSING_ID` / `ZONE_MISSING_ID` | A component or zone with no id |
| `DANGLING_FLOW_ENDPOINT` | A flow referencing a component that does not exist |
| `FLOW_MISSING_ENDPOINT` | A flow missing `from` or `to` |
| `UNKNOWN_CROWN_JEWEL` | A crown jewel that is not a declared component |

Warnings — these are worth reading, and most mean the map is not saying what you
think it says:

| Code | Meaning |
|---|---|
| `INVALID_ENUM` | An unrecognised enum value; the fallback used is named in the message |
| `UNKNOWN_ZONE` | Component references an undeclared zone |
| `COMPONENT_WITHOUT_ZONE` | No zone, so boundary crossings through it cannot be counted |
| `DUPLICATE_FLOW` | The same `from`/`to` pair declared twice |
| `SELF_FLOW` | A flow from a component to itself; ignored |
| `NO_FLOWS` | Nothing is reachable from anything |
| `NO_CROWN_JEWELS` | No target to compute routes to |
| `NO_EXTERNAL_EXPOSURE` | No internet- or partner-facing component, so no external entry point |

## Recipe

1. **Name the crown jewels first.** Everything else exists to explain how an
   attacker gets to them. If you cannot name two or three, you are not ready to
   draw the map.
2. **Draw the zones**, coarsely. Four or five is plenty. Trust level is a
   judgement about what an attacker gains by standing there.
3. **List the components** that carry, process or guard the crown jewels, plus
   everything internet- or partner-facing. Resist mapping the whole estate —
   7 to 12 components is the useful range.
4. **Set `exposure` and `authentication` honestly.** These are the two fields
   people flatter themselves on, and they drive the ranking.
5. **Declare the flows.** This is where maps are usually wrong: the forgotten
   flow is exactly the one an attacker uses. Include admin, backup, monitoring,
   replication and vendor support paths, not just the happy path.
6. **Add controls where they exist**, with truthful `implementation_status`.
   A map full of `implemented` controls projects nothing useful.
7. **Run `validate_flow_map`.** Fix errors; read every warning.
8. **Check `unreachable_crown_jewels` is empty.** If it is not, you are missing
   a flow.
9. **Then project**, starting at `--max_paths 2`.

## Common mistakes

- **Modelling the network instead of the application.** Switches and firewalls
  are components only when an attacker would traverse or subvert them. The map
  is about reachability, not cabling.
- **Forgetting the management plane.** Jump hosts, CI runners, vendor support
  channels and backup agents reach crown jewels by design, which is exactly why
  they get used. Both larger examples have one.
- **Marking everything `implemented`.** The projector reads control status
  closely and will route around your defences; a map that claims perfection just
  produces a projection that ignores it.
- **Declaring flows in one direction when traffic goes both ways.** If a
  response channel is usable, set `bidirectional: true`.
- **Too many components.** Prompt size grows with the map, and a large map at a
  high `thinking_level` can run into the request deadline — 180 s, set by the
  client timeout in `framework/llm/client.py`, which the SDK also sends to Google
  as the server deadline. Shrink the map before reducing reasoning depth.

## Notes on mitigation ids

`mitre_mitigation_id` is optional and only affects `uncovered_mitigations` — per
step, the projector diffs ATT&CK's mitigations for the technique against the ids
declared by the controls **on that step's own component**. A control with no id
simply never counts as covering anything, and estate-wide and flow controls are
not consulted.

That is why a `project_paths` summary ends with up to three lines about
controls, each saying exactly what was checked:

```
No controls declared at all on: claims_api, doc_store.
ATT&CK mitigations for these techniques that no control on the targeted component declares: M1013, ... +16 more.
Caution: 1 of 2 control(s) on the targeted components carry no ATT&CK mitigation id and cannot be matched, so some listed mitigations may already be in place. Estate-wide and flow controls are not checked against this list.
```

The first line is the plain triage answer. The second is only as good as your
tagging — the claims portal map tags just its WAF, so most of its list reflects
untagged controls rather than missing ones. The caution appears whenever an
untagged control sits on a projected path. Tag your controls and the list gets
both shorter and more trustworthy.

Use **enterprise** ids (`M1xxx`). The closed technique set is enterprise, so ICS
mitigations (`M0xxx`) can never match and would make every mitigation look
uncovered. All three examples follow this, the OT map included — its segmentation
controls use `M1030`, not the ICS equivalent.

## Validating outside the shell

The JSON schema is stricter than the tool. The tool tolerates an unrecognised
component `type` and quietly keeps it; `flow_map.schema.json` rejects it. Check
against the schema too:

```bash
python -c "
import json, jsonschema
schema = json.load(open('plugins/threat_modeling/adversary_path_projector/schemas/flow_map.schema.json'))
jsonschema.validate(json.load(open('my_flow_map.json')), schema)
print('valid')
"
```

## What a projection's assumptions say about your map

Every projected step lists up to three **assumptions** — things that must be
true for the step to work and that the map does not state. Read them as
feedback on the map as much as on the estate:

- An assumption the map *could* have answered — "the API accepts tokens from
  the web tier", "the database credential is stored on the API host" — is a
  missing flow attribute, authentication method or control. Add it and the next
  projection either stops assuming it or routes elsewhere.
- An assumption only the real system can answer — "the exploited route is not
  filtered by the WAF" — is a test to run. The analyzer's report collects these
  under **Assumptions to Test**.

A **`STATE_GAP`** — a step that needs access no earlier step provided — can
also mean the map omits the flow or credential store that would supply it, so
check the map before blaming the model. The note says which of three it is:

- **"no earlier step yields one"** — a credential appears from nowhere. Either
  the model skipped the step that takes it, or the map does not say where that
  credential lives.
- **"the path reaches it but no earlier step takes …"** — connectivity is
  there and the foothold is not. Usually a skipped bridge step.
- **"depends on X acting for the attacker"** — the only declared flow in comes
  from a component the path never takes control of, so the path leans on that
  component answering the attacker's calls. This is the one to read closely:
  the step's assumptions say what it is relying on, and whether a token holder
  really can make X do that is a question for the team that runs X.

---

# Recording runs

Projection is sampled, not deterministic — the same map and the same actor do
not produce the same paths twice. `--export` leaves a provenance record per run
so runs can be compared long after the terminal output is gone.

```
eventmill> run adversary_path_projector --action project_paths \
             --threat_actor "APT29" \
             --file_path plugins/threat_modeling/adversary_path_projector/examples/telemetry_saas_flow_map.json \
             --max_paths 2 --export --run_group apt29-telemetry --runs 10
```

| Flag | Effect |
|---|---|
| `--export` | Write a run record as a registered artifact. Off by default. |
| `--run_group` | Label tying a comparison set together. Free text; defaults to `ungrouped`. |
| `--runs` | Repeat the projection 1–25 times. Each run is its own LLM call and its own record. Implies `--export`. |

Records land in `$EVENTMILL_WORKSPACE/artifacts/` as
`adversary_projection_run_<stamp>_<id>.json`, alongside
`adversary_projection_raw_<stamp>_<id>.txt` holding the unparsed reply. Nothing
is ever overwritten. In a `--runs` loop the attack graph and scenario seed are
written once, for the first successful run; every run still gets its own record.

A run that fails is recorded too, with no `sampled` block. That is deliberate —
a map that reliably hits the request deadline at a given reasoning depth is a
finding about the map, and it vanishes if only successes are kept. Inside a loop
a dead run does not stop the ones after it.

## What a record holds

Five blocks. The split between `deterministic` and `sampled` is the whole point:

- **`run`** — ids, timestamps, `flow_map_sha256`, and the resolved actor. The
  hash is computed over the map **as supplied**, with sorted keys and no
  insignificant whitespace, so reformatting does not change it but a content
  change does. Two records sharing it were run against the same estate; nothing
  else in the record can prove that.
- **`model`** — provider, tier, and the **resolved** `thinking_level` — what
  actually ran, which is not always what was asked for.
- **`deterministic`** — entry ranking, routes, unreachable crown jewels,
  validation warnings. Fixed by the flow map hash. If two records share a hash
  and differ here, something is wrong with the tool, not the model.
- **`sampled`** — the model's paths. `technique_id` is a first-class field, so a
  one-off is something you spot by scanning a column. Since record schema
  version 2 each step also carries its state — access before and after,
  precondition, result, assumptions — and the continuity check's verdict, so two
  runs can be compared on *why* a path works, not only *which* techniques it
  uses.
- **`outcome`** — status, the provider's verbatim stop reason, token usage
  including thinking tokens, and wall time.

Comparison is by eye for now: open two records from the same `run_group` and
read the `sampled` blocks against each other. When they disagree, the raw reply
beside each record is what shows why.

**One limitation worth knowing.** `model.model_configured` is the id the client
was configured with, not the id the API response reports — the framework does
not currently carry the latter. A silent provider-side model bump would not show
up in these records. Read that field as "what we asked for", never as "what ran".

## Sensitivity

A run record contains your estate's topology, its trust boundaries, and the
implementation status of every control — including the ones that are missing.
The retained raw reply adds a model's reasoning about how to exploit them.

Treat a corpus of records as you would the flow maps themselves. They are
written with default filesystem permissions and no encryption; if that is not
appropriate for your estate, keep `EVENTMILL_WORKSPACE` somewhere that is.

## Reference

| What | Where |
|---|---|
| Full schema, every field and enum | `../schemas/flow_map.schema.json` |
| Run record schema | `../schemas/projection_run.schema.json` |
| Design and the three projection phases | `../../../../docs/specs/adversary_path_projector.md` |
| Plugin contract | `../../../../docs/specs/tool_plugin_spec.md` |
| Control vocabulary this borrows | `threat_model_analyzer`'s `SecurityControl` |
