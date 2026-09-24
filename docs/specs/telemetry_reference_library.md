# Telemetry reference library — what an organization can actually observe

Status: **seed library built 2026-09-20** — `framework/reference_data/`
`telemetry_library.json` (v0.1.0, 34 sources) and `telemetry_library.py`.
Nothing consumes it yet; the designer join is G1 work. Written against the
five flow maps in
`plugins/threat_modeling/adversary_path_projector/examples/`, two of which
(`branch_physical_flow_map.json`, `loyalty_commerce_flow_map.json`) were built
for this document so that the non-ATT&CK cases are designed against real
subjects rather than against nothing.

Consumed by `attack_path_detection_designer` stage G1. It is **not** a
detection catalogue and holds no rule content.

**Scope.** Detection engineering and threat modelling. Both are inputs to a
risk management programme and are distinct from quantification and impact
analysis. §4.1 borrows FAIR-CAM's control classification and deliberately
stops there — the library can report that a control's trigger depends on data
nobody collects; what that is worth to the organization is out of scope for
this pillar.

---

## 0. Why this exists, and the two mistakes it prevents

A detection draft is only as good as the answer to "what would you see?".
Today the designer can reach `component_bound` — it knows a component runs
Postgres and pgaudit — and still cannot say which event families exist, which
fields they carry, or whether anyone collects them. The library is that
answer, recorded once per organization and versioned like the ATT&CK release
already is.

Two failure modes shape every rule below.

**Forcing everything into ATT&CK.** A badge reader raising an out-of-hours
grant, a historian recording an unexpected setpoint, a fraud engine scoring a
redemption — none of these is an ATT&CK technique, and labelling them with the
nearest `T####` conflates a physical event with a keyboard one. The library
therefore treats "no ATT&CK mapping" as a **complete, first-class answer**, not
a gap.

**Assuming a control produces evidence.** The branch map's quarterly asset
audit would find an implant by looking at it; the loyalty map's settlement
reconciliation would find the theft in aggregate. Neither is a log stream and
neither is continuous. A library that records only log sources declares both
invisible, and a draft written from it will propose a SIEM query for something
a person finds on a clipboard.

---

## 1. Scope

**In scope.** Sources of observation the organization has or could have:
log streams, audit records, alert feeds from non-security systems, periodic
reports, reconciliations and physical records — with their fields, prerequisites
and collection status.

**Out of scope.** Rule content, tuning, thresholds, severity, SIEM syntax,
vendor comparison, and any claim that a source is *deployed* where the
inventory says only that it *exists*.

---

## 2. The record

One entry per **observation source**. The fixture products are the seed set
(§8); nothing here is specific to them.

```yaml
source_id: pgaudit.object_access          # stable, local, lowercase dotted
name: "pgAudit object access records"
category: log | audit | alert_feed | report | reconciliation | physical_record | human_report
vendor_product: "PostgreSQL 16 + pgAudit 16.0"
version_scope: ">=13"                     # where the field set holds
applies_to:
  technologies: [postgres, pgaudit]       # joins to flow-map component.technologies
  component_types: [database]
  zones: []                               # optional narrowing
events:
  - event_ref: "AUDIT: OBJECT"            # native name or id, exactly as emitted
    mapping_status: native_identifier | description_only
    description: "Statement-level record naming the relation touched."
fields:
  native: [session_id, statement_id, object_name, command_tag]
  derived: []                             # computed, with derivation stated
  absent_without_enrichment: [tenant_id, application_request_id]
control_function:                         # section 4.1
  domain: loss_event | variance_management | decision_support
  note: "Detects that a statement touched a relation."
supports:                                 # edges, not a category
  - control: "Tenant scoping in the agent console"
    effect: provides_context
    without_it: "reads are visible, but not whether they were in scope"
collection:
  necessity: required | alternative | enrichment
  status: confirmed | assumed | missing | unknown
  prerequisites: ["pgaudit.log = 'read,write'", "log collector shipping to central store"]
  retention: "30d hot, 1y cold"
availability:
  artefact: machine_readable | human_readable | none
  cadence: continuous | daily | weekly | monthly | quarterly | on_request
  latency: "minutes" | "up to 7 days"
  owner: "Platform engineering"           # who holds it, which is often not security
observes:                                 # §3
  - behaviour: data_read_volume_anomaly
    attack_relation: exact
    attack_id: T1005
    matrix: enterprise
provenance:
  reference: "https://github.com/pgaudit/pgaudit"
  reviewed: 2026-09-20
```

Three rules the shape enforces:

- **`mapping_status: description_only` is normal.** Kafka, Vault, gRPC and
  Postgres do not have numeric event ids. A described event with no id is
  correct; an invented id is a defect (§1.5 of the normalization spec already
  forbids the equivalent for `DS####`).
- **Necessity and status are independent.** A source can be `required` and
  `missing`. A control existing is never evidence that its logs contain the
  fields — the loyalty map's session recording exists and captures tone, not
  adjustments.
- **`absent_without_enrichment` is load-bearing.** Every feature a later
  detection uses must trace to a native field, a stated derivation, or a
  declared gap.

---

## 3. Mapping to ATT&CK — three states, never a nullable id

`observes[]` links a source to a **behaviour**, and the behaviour carries the
ATT&CK relationship explicitly:

| `attack_relation` | Meaning | Requires |
|---|---|---|
| `exact` | The technique is what this observes | `attack_id`, `matrix` |
| `adjacent` | Related but not the same scope | `attack_id`, `relation_kind`, `rationale` |
| `unmapped` | Deliberately outside ATT&CK | `local_id`, `rationale` |

`relation_kind` — the vocabulary that stops conflation:

| Kind | Means | Example from the fixtures |
|---|---|---|
| `broader` | The source observes a superset | A badge grant observes *presence*, of which implant placement is one use |
| `narrower` | The source observes one instance | A settlement file shows gift-card conversion, one outcome of many |
| `precursor` | Observed before, enabling | Lobby badge grant precedes a console logon |
| `consequence` | Observed after, resulting | Customer complaints follow a points adjustment |
| `variant` | Same intent, different mechanism | A human approving a fraudulent adjustment versus a token replay |

**Local ids for the unmapped.** A namespace per domain, never ATT&CK-shaped:

| Namespace | Domain | Fixture subject |
|---|---|---|
| `EM-PHYS-####` | Physical access and tamper | Door contact alarm, asset audit, CCTV |
| `EM-OT-####` | Process and safety | Setpoint change, historian gap |
| `EM-FRAUD-####` | Value and business logic | Redemption velocity, points liability variance |
| `EM-PROC-####` | Human procedure and duty separation | Approval by a second account, escort compliance |
| `EM-INSIDER-####` | Authorised-actor misuse | Agent lookups without a ticket |
| `EM-AGENT-####` | Autonomous software agents acting under delegated authority | **Reserved, unused.** Identified for future development; see §4.3 |

**Use the ICS matrix before declaring something unmapped.** The local lookup
carries **97 ICS techniques** alongside 697 enterprise ones. A SCADA setpoint
change is not automatically `unmapped`; `T0836 Modify Parameter` may fit
exactly. `unmapped` means *outside ATT&CK*, not *outside the enterprise
matrix*, and a library entry that reaches for `EM-OT-` without checking ICS is
wrong in the opposite direction from the one this document was written to
prevent.

**One behaviour may carry several relations.** A fraud engine alert can be
`adjacent/consequence` to `T1078` and `unmapped` as `EM-FRAUD-0002` at the same
time. That is not indecision: it is the honest statement that one observation
serves two frames.

---

## 4. Detections that are not tools, and controls that are not security

The two new maps exist for this section. Both carry controls whose evidence is
real but is not a stream:

| Control | Map | Artefact | Cadence | Why a log-only library loses it |
|---|---|---|---|---|
| Quarterly hardware asset audit | branch | human_readable | quarterly | The only control that finds an implant by looking at it |
| Door contact alarm | branch | machine_readable | continuous | Alerts to facilities, ingested by no security tool |
| Footage reviewed on request | branch | human_readable | on_request | Evidence, not detection — the distinction must survive into the draft |
| Monthly badge audit report | branch | human_readable | monthly | The interval is the weakness, not the data |
| Nightly points liability reconciliation | loyalty | machine_readable | daily | Finds the aggregate no per-event rule sees |
| Partner daily settlement file | loyalty | machine_readable | weekly (reconciled) | Earliest external evidence, up to a week late |
| Customer complaints queue | loyalty | human_report | continuous | Frequently the true first detection, owned by customer service |

Consequences for the record:

- **`cadence` and `latency` are first-class.** A monthly artefact cannot
  support a draft that claims near-real-time detection, and the draft must say
  so rather than imply a stream.
- **`owner` is recorded** because acting on these requires a person outside
  security, and a draft that ignores that is not operable.
- **Prevention is in the flow map, detection is here.** The maps already carry
  `implementation_status`, `bypass_difficulty`, `bypass_requirements` and
  `detection_capability` per control. The library says what evidence that
  control actually leaves. A control with `detection_capability: high` and no
  library entry is a **finding**, not a matching failure: something is believed
  to detect and nobody has said where the evidence lands.

### 4.1 Control function: what a control does to risk

Our control vocabulary — `perimeter | network | endpoint | application | data |
identity | monitoring` — describes **where a control sits**. It cannot express
what the control *does*, which is why the branch estate's quarterly asset audit
and its door alarm both land on `monitoring` while doing entirely different
jobs. FAIR-CAM (Jack Jones, FAIR Institute) supplies the missing axis, and the
library borrows **only its classification**:

| `control_function.domain` | The control acts by | Fixture examples |
|---|---|---|
| `loss_event` | Preventing, detecting or responding to the event itself | Dual approval, badge alerting, WAF, EDR, the escort procedure |
| `variance_management` | Keeping other controls working as intended, and finding drift | Quarterly hardware asset audit, monthly badge audit, role recertification |
| `decision_support` | Informing choices so other controls are configured and fire correctly | Asset inventory, threat intelligence, identity role data, baselines, this library |

Two reclassifications this immediately forces, both of which change what a
draft may claim:

- **The quarterly hardware asset audit is not attack detection.** It detects
  that the estate no longer matches its inventory. Recorded as `monitoring`, a
  draft can imply it watches for an intruder; recorded as
  `variance_management`, it says what it really offers — the implant is found
  because the rack stopped matching the spreadsheet, up to three months later.
- **The monthly badge audit is variance management too.** It asks whether
  access rights have drifted, not whether someone is walking through a door.

**Scope boundary, stated once and enforced everywhere.** This pillar is
detection engineering and threat modelling. Both are *inputs* to a risk
management programme and are distinct from quantification and impact analysis.
The library therefore takes FAIR-CAM's taxonomy and **stops there**: no loss
magnitude, no frequency estimates, no control-value arithmetic, no dollar
figures. What the library may say is *"this control's trigger depends on data
nobody collects"*. What is worth doing about that is the organization's
question, answered with its own risk model — and probably outside the Event
Mill framework altogether.

### 4.2 Decision support is an edge, not a category

Many controls act only **through** other controls, and a control that supports
another must never be counted as though it detected something itself. The
library records that as `supports[]` on the entry:

| `effect` | Means | Example |
|---|---|---|
| `enables_trigger` | Without this data the control cannot evaluate at all | Role assignment data behind dual approval |
| `tunes_threshold` | Sets or corrects a boundary the control applies | Points-velocity baseline behind the fraud engine |
| `provides_context` | Lets an alert be judged rather than merely raised | Ticket scope behind an agent console lookup |
| `verifies_operation` | Confirms the control still runs as intended | Collector heartbeat behind any log-based detection |

Three consequences:

- **No double counting.** An asset inventory detects nothing; it makes an
  endpoint control's coverage real. Today a library entry can only claim
  detection, which overstates every supporting source in the estate.
- **A nominally implemented control can be practically defeated by missing
  support.** The loyalty estate's dual approval is `implemented` and
  `bypass_difficulty: high`, yet several agents hold both roles for holiday
  cover. The control is fine; the identity data feeding it is not.
- **"Missing decision support" becomes a reportable finding.** A control whose
  `effect: enables_trigger` source is `missing` or `unknown` is a distinct,
  detectable condition — and a valuable one, because nothing else in the estate
  will say it out loud. How much it matters is the risk programme's question,
  not this tool's.

**Efficacy vocabulary, borrowed and grounded.** FAIR-CAM's reliability,
capability and coverage dimensions map onto fields this document already
proposed for other reasons: `cadence` and `latency` are reliability;
`detection_capability` and `bypass_difficulty` are capability; `applies_to`
plus `collection.status` are coverage. That is the justification for those
fields; it is not an invitation to score them.

### 4.3 Agent behaviour — identified, scoped, and out of scope for now

**Status (operator, 2026-09-20): noted for future development. Not built, not
seeded, not designed against.** Distinguishing malicious from benign agent
behaviour is weeks of research on its own. What this section owes the future
is a name, the four elements, and the reason they are decision support — no
more.

Autonomous agents make §4.2's gap operational rather than theoretical. An
agent's action — a database read, an API call, a file write — is
indistinguishable from the same action performed benignly. Almost no security
product today holds what separates them, and the four elements are:

| Element | The question it answers | Without it |
|---|---|---|
| **Commission** | What was this agent asked to do, and by whom? | Every action looks authorised, because the agent *is* authorised |
| **Delegation** | Whose authority does it act under, and was that authority scoped to this action? | A compromised agent inherits its principal's full rights invisibly |
| **Provenance** | Which model, prompt, tool set and run produced this action? | Two runs of the same agent cannot be told apart, so nothing is attributable |
| **Baseline** | What does this agent normally touch — where "normally" may be days old, because it was deployed last week? | Anomaly detection has no stable normal to measure against |

All four are `decision_support`, not detections. An agent tool-call log detects
nothing by itself; it makes another control able to judge. That is the whole
claim this document makes about agents, and building on it needs its own
specification.

**Event Mill already emits this.** Every projector export carries `run_id`,
`run_group`, `run_index`, `prompt_sha256`, `model.provider`,
`model_configured`, `model_served` and a `tool_version` with
`code_id_source`. That is precisely the commission-and-provenance record an
`EM-AGENT-` entry would catalogue, which makes this repository the one worked
example available without describing a product from memory.

**Settled:** `EM-AGENT-` exists as a **reserved namespace only**. No entries in
the seed library, no consumer, and no design work until agent detection is
taken up as its own piece of research. The namespace is registered here so
that when it is, nothing has to be renamed.

### 4.4 Separation of duties needs a joined identity, not an event

The loyalty map's central control is *dual approval above 5,000 points*, whose
`bypass_requirements` name compromise of a second account holding the approver
role. Two consequences the library must support:

- **The signal is a relationship, not a record.** Neither the agent's
  adjustment nor the supervisor's approval is suspicious alone. The library
  therefore records `join_keys` — which field identifies the actor, which the
  approver, and whether both appear in one artefact. In this estate the
  adjustment audit log carries both; the session recording carries neither
  usefully.
- **Sub-threshold splitting is the other bypass**, and it is observable only in
  aggregate — by the reconciliation, the fraud engine or the complaints queue,
  each with different latency. A draft naming only the dual-approval event
  misses the attacker who never crosses the threshold.

A `EM-PROC-` behaviour ("one identity performed both sides of a separated
duty") is the natural home for this and has no ATT&CK equivalent, because
ATT&CK describes what an attacker does to systems, not how an organization
divides authority.

---

## 5. Joining a library entry to a node

**Component first, behaviour second, technique last.** A badge reader can
never be reached from a technique, so the technique cannot lead:

1. `applies_to.technologies` / `component_types` against the node's flow-map
   component. This is why the library only becomes useful at `component_bound`
   or `component_bound_partial`.
2. Behaviour class against the node's behaviour and access transition.
3. `attack_id` against `technique_id` — a bonus when it matches, never a
   requirement.

A node with no matching entry yields `telemetry_readiness: none_declared`,
which is a stated gap, not an empty list.

**Grades stay separate.** `context_completeness` (§5 of the normalization
spec) says how well the node is bound to the estate; `telemetry_readiness`
says what could be observed. A node can be `component_bound` with no telemetry,
or `asset_named` with an excellent badge feed. Folding them into one word would
repeat the `uncovered_mitigations` misreading — one field, two meanings, and
the weaker one wins.

---

## 6. Building the inventory, repeatably

The procedure an organization follows, in the order that avoids rework:

1. **Start from the flow map, not from the SIEM.** Walk components; for each,
   ask what it emits, not what is currently collected.
2. **Record the source before the status.** An entry with
   `status: unknown` is useful; a missing entry is not.
3. **Separate "we have the product" from "we have the events" from "we have
   the fields".** Three distinct questions, answered by `applies_to`, `events`
   and `fields`.
4. **Walk the controls next.** Every control in the map with
   `detection_capability` above `none` must resolve to an entry or be recorded
   as unevidenced.
5. **Ask who else observes.** Facilities, finance, customer service, safety,
   partner managers. This is where the non-tool sources come from, and they are
   never in a security backlog.
6. **Record cadence and owner honestly**, including `on_request`.
7. **Map last, and only where it is true.** `unmapped` requires no
   justification beyond a rationale; a forced `exact` is a defect.

Re-run on estate change, and version the library independently of any run.

---

## 7. Versioning and provenance

- `library_version` (semantic) and `reviewed` date per entry.
- Every draft pins the library version alongside the ATT&CK release, so a
  draft can be re-read against the library it was written from.
- An entry changing `collection.status` is a version bump: it changes what a
  draft may claim.

---

## 8. Seed content, limited to the maps we have — **built 2026-09-20**

`framework/reference_data/telemetry_library.json`, version `0.1.0`, with
`telemetry_library.py` as loader and validator. **34 sources** across the five
estates (claims portal 7, telemetry SaaS 9, plant OT 6, branch 12, loyalty 14;
several are shared), **15 unmapped behaviours** carrying local `EM-` ids, and
three `decision_support` entries. Every `collection.status` is `unknown`: the
entries describe what these products and processes emit, not what any
organization currently collects. `validate_library()` returns no errors and 24
contract tests hold it to §3 and §4.

Per the operator's instruction, the first library covers **only** the five
example estates:

| Estate | Sources the seed must carry |
|---|---|
| `claims_portal` | nginx/django access, Postgres + pgaudit, IdP (SAML), S3-style object access |
| `telemetry_saas` | Kafka broker/authorizer, Vault audit device, Kubernetes API audit, GitHub Actions, Postgres/TimescaleDB, OIDC |
| `plant_ot` | Windows security events, process historian, HMI/SCADA action records, jump-host session records, vendor VPN |
| `branch_physical` | Badge/door events, door contact alarm, CCTV retention, NetFlow, switch AAA, SMB object access, AD authentication, **plus the audits and reviews that are not streams** |
| `loyalty_commerce` | Ledger adjustment audit, agent console session records, fraud engine alerts, email suppression records, partner settlement file, complaints queue |

Deliberately excluded: products in none of these maps, and anything that would
have to be described from memory.

---

## 9. What this costs the existing design

Assessed against the built code, not estimated:

| Area | Impact |
|---|---|
| N1/N2 identity, pair join, flow-map lineage | none |
| N3a/N3b join, grades, controls | none; `telemetry_readiness` is additive |
| N3c/N3d mitigations, taxonomy | none; both stay ATT&CK-keyed |
| Pack schema | additive — `telemetry_candidates[]` per node |
| Generation prompt | real work: `unmapped` must be stated as a valid answer, or a model will invent a technique for the badge reader |
| Reference data | the bulk — new file, loader, validation, version pin |
| Control function and `supports[]` (§4.1, §4.2) | one field and one edge type on a library entry; no change to the ATT&CK states, no change to any built stage |

**And what it deliberately does not cost.** FAIR-CAM is a risk-quantification
model, and the temptation is to follow it into scoring. This pillar is
detection engineering and threat modelling — inputs to a risk management
programme, distinct from quantification and impact analysis. The library
classifies control function and stops. No loss magnitude, no frequency, no
control value, no dollars. Saying *"this control's trigger depends on data
nobody collects"* is in scope; saying what that is worth is the organization's
question, answered with its own risk model, and very likely outside the Event
Mill framework entirely.

---

## 10. Gaps this work exposed in the flow map schema

Found by building the two maps, and recorded rather than silently patched —
widening an enum is a behaviour decision, as the `stability` case already
established:

1. **`control_type` has no physical, process or business class, and describes
   anatomy rather than function.** The enum is `perimeter | network | endpoint
   | application | data | identity | monitoring`. A visitor escort procedure
   became `perimeter`, a key cabinet `identity`, a reconciliation `monitoring`.
   Workable, and lossy twice over: nothing distinguishes a firewall from a
   person with a clipboard, and nothing distinguishes a control that detects an
   attack from one that detects control drift. §4.1's `control_function` is the
   library's answer; the map still cannot express it, so a quarterly audit and
   a live alarm remain indistinguishable in the map alone.
2. **`exposure` has no physical value.** A public lobby was recorded
   `internet`, which is semantically wrong and structurally right — it is the
   unauthenticated outermost surface.
3. **The entry surface is network-only.** `file_server` and `corp_ad` first
   validated as *unreachable crown jewels*, because a physical break-in has no
   vocabulary. Resolved by modelling **physical movement as a flow** with
   `protocol: physical` — a person passing the badge line is real reachability,
   and the projector's own path logic then works unchanged. This convention is
   the recommendation; it wants confirmation before it spreads.
4. **Detection cadence has nowhere to live in the map.** A quarterly audit and
   a continuous alarm both read `detection_capability: medium`. The library
   carries cadence; the map cannot, and the two must be read together.

---

## 11. Review status

The five flow maps were parsed and both new ones validated with the
projector's own `validate_flow_map`: 10 components, 10 flows, 3 crown jewels,
19 controls for the branch estate; 10 components, 9 flows, 2 crown jewels, 19
controls for the loyalty estate. Both report `valid: true` with no warnings and
no unreachable crown jewels or isolated components after the `protocol:
physical` flows were added. The ICS technique count (97 of 794) was read from
`framework/reference_data/mitre_techniques.json`. No library file has been
written yet and no code consumes this document.

**Revision 2026-09-20 (later), control function.** §4.1–§4.3 added at the
operator's direction: borrow FAIR-CAM's control classification, stop short of
risk quantification. One caveat on provenance — the linked FAIR Institute post
(`fairinstitute.org/blog/mapping-nist-csf-to-fair-cam`) was fetched and
**announces the NIST CSF 1.1 → FAIR-CAM mapping without setting out the
taxonomy itself**. The three domains used here are therefore written from prior
knowledge of FAIR-CAM, not from that page, and the domain and sub-function
names should be checked against Jones's primary material before anything is
built on them. The two reclassifications they produce — the quarterly asset
audit and the monthly badge audit as variance management rather than attack
detection — stand on their own reasoning regardless of the exact naming.
