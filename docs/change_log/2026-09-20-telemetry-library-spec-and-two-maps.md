# The telemetry reference library spec, and two flow maps to design it against

**Date:** 2026-09-20
**Branch:** `llm_5`
**Scope:** specification and fixtures. New
`docs/specs/telemetry_reference_library.md`; new
`plugins/threat_modeling/adversary_path_projector/examples/branch_physical_flow_map.json`
and `loyalty_commerce_flow_map.json`; examples README.
**Status:** planning and fixtures. **No code changed**, no library file
written, no LLM call. Suite unchanged at 1681.

## What was asked, and why the maps came first

The operator asked for the telemetry library to have its own specification, so
an organization can walk its own estate and produce a repeatable inventory —
and for it to carry indicators that go beyond ATT&CK: badge readers, SCADA
alarms, fraud-engine warnings. With the instruction: *do not design against
nothing.*

So two estates were built before the specification was written, and the
specification is written against them.

**`branch_physical_flow_map.json`** — a staffed branch office. The path starts
at an unauthenticated meeting-room wall port patched into a routable print
VLAN, reaches the file server and the domain controller, and exfiltrates over
a cellular path that meets no estate egress control at all. Almost every
control that would catch it is not a security tool: a visitor escort procedure
with no artefact, a quarterly manual asset audit, a door contact alarm that
goes to facilities, CCTV reviewed only on request, a monthly badge report.

**`loyalty_commerce_flow_map.json`** — a small e-commerce estate where the
asset is value rather than data. Its central control is **separation of
duties**: an adjustment above 5,000 points needs one account to raise it and a
second with the supervisor role to approve it, and the approver console
requires a hardware key. The sub-threshold split is the other bypass. The
strongest detections are a vendor fraud engine, a nightly liability
reconciliation, the partner's daily settlement file, and customers complaining
that their points are missing.

Both validate with the projector's own `validate_flow_map`: `valid: true`, no
warnings, no isolated components, no unreachable crown jewels.

## The finding that came out of building them

The branch map first validated with **`file_server` and `corp_ad` as
unreachable crown jewels**. The projector's entry surface is network exposure,
and a physical break-in has no vocabulary in the flow map schema — so the most
realistic entry point in the estate was invisible to reachability.

Resolved by modelling **physical movement as a flow** with
`protocol: physical`: a person passing the badge line is real reachability, and
the projector's path logic then works unchanged. The route is now
`lobby_badge_reader → meeting_room_port → print_vlan_switch → file_server`,
three hops, two of them unauthenticated. It is a convention, not a schema
change, and the spec flags it as wanting confirmation before it spreads.

## The specification

`docs/specs/telemetry_reference_library.md`. Its load-bearing decisions:

**Three mapping states, never a nullable id.** A source's behaviour carries
`attack_relation: exact | adjacent | unmapped`. `adjacent` requires a
`relation_kind` — `broader`, `narrower`, `precursor`, `consequence`, `variant`
— plus a rationale, so "a badge grant precedes a console logon" can be stated
without pretending the badge grant *is* `T1078`. `unmapped` takes a local id in
a namespaced scheme (`EM-PHYS-`, `EM-OT-`, `EM-FRAUD-`, `EM-PROC-`,
`EM-INSIDER-`) and is a complete answer, not a gap.

**Check ICS before declaring something unmapped.** The local lookup carries 97
ICS techniques beside 697 enterprise ones, so a SCADA setpoint change may map
exactly to `T0836`. `unmapped` means outside ATT&CK, not outside the enterprise
matrix — the opposite error to the one the document is mainly guarding against,
and worth naming.

**Artefact, cadence, latency and owner are first-class.** A quarterly audit and
a continuous alarm both read `detection_capability: medium` in a flow map. The
library records that one is a clipboard at three-month intervals owned by
facilities, and the other is a live alert owned by nobody in security. Without
this a log-only library declares the two strongest controls in the branch
estate invisible.

**Separation of duties is a joined identity, not an event.** Neither half of a
dual-approval pair is suspicious alone, so entries record `join_keys` — which
field is the actor, which the approver, whether one artefact holds both. In the
loyalty estate the adjustment audit log does and the session recording does
not.

**Component first, behaviour second, technique last.** A badge reader is
unreachable from a technique, so the join to a node starts at the flow-map
component. This is also why the library only bites at `component_bound`.

**Telemetry readiness is a separate axis from context completeness.** A node
can be `component_bound` with no telemetry, or `asset_named` with an excellent
badge feed. Folding them into one word would repeat the `uncovered_mitigations`
misreading exactly.

## Cost to the existing design, assessed against built code

None to N1, N2, N3a, N3b, N3c or N3d. Additive to the pack. The real work is
the reference data file and its loader, plus one genuine risk: the generation
prompt must state that `unmapped` is a valid answer, or a model will
manufacture a technique for the badge reader.

## Gaps recorded rather than patched

Building the maps exposed four limits in the flow map schema — `control_type`
has no physical, process or business class; `exposure` has no physical value;
the entry surface is network-only; detection cadence has nowhere to live. All
four are recorded in §10 with what was done instead. None was fixed by
widening an enum, on the precedent already set for `stability`: the enum is a
behaviour decision, not a typo.

## Revision the same day: control function, without quantification

The operator asked whether FAIR-CAM's control classification would make this
easier. It does, and §4.1–§4.3 were added.

**The missing axis was function, not vocabulary.** `control_type` —
`perimeter | network | endpoint | application | data | identity | monitoring` —
says where a control sits. FAIR-CAM asks what it does to risk:
`loss_event`, `variance_management`, `decision_support`. Two fixture controls
reclassify immediately, and both change what a draft may claim:

- The branch estate's **quarterly hardware asset audit** is recorded
  `monitoring` today, which implies it watches for an intruder. It is
  `variance_management`: it detects that the rack no longer matches the
  spreadsheet, up to three months later.
- The **monthly badge audit** likewise asks whether access rights have
  drifted, not whether someone walked through a door.

**Decision support is an edge, not a category.** A `supports[]` list with an
`effect` of `enables_trigger`, `tunes_threshold`, `provides_context` or
`verifies_operation`. An asset inventory detects nothing; it makes another
control's coverage real, and counting it as a detection overstates every
supporting source in the estate. It also explains the loyalty estate exactly:
dual approval is `implemented` with `bypass_difficulty: high` and is partly
defeated because several agents hold both roles — the control is sound, the
identity data feeding it is not. **"A control whose trigger depends on missing
decision support" becomes a reportable finding**, which nothing else in the
estate says out loud.

**Agent behaviour is the same problem, operational.** An agent's database read
is indistinguishable from a benign one; what separates them is commission,
delegation, provenance and baseline — all decision support, none of them
detections. Recorded with a new `EM-AGENT-` namespace, and worth noting that
this repository already emits the record: every projector export carries
`run_id`, `prompt_sha256`, `model_configured` / `model_served` and a
`tool_version`. Whether `EM-AGENT-` joins the seed library is left open.

**Where it stops.** The operator set the boundary: this pillar is detection
engineering and threat modelling, both inputs to a risk programme and distinct
from quantification and impact analysis. The library borrows FAIR-CAM's
taxonomy and takes none of its arithmetic — no loss magnitude, no frequency, no
control value. FAIR-CAM's reliability / capability / coverage dimensions are
used only to justify fields the document already had (cadence and latency,
capability and bypass difficulty, scope and collection status), not to score
them.

**Provenance caveat, recorded in §11.** The linked FAIR Institute post was
fetched and announces the NIST CSF → FAIR-CAM mapping *without* setting out the
taxonomy. The three domains here are written from prior knowledge of FAIR-CAM
and should be checked against Jones's primary material before code depends on
them. The two reclassifications stand on their own reasoning either way.

## Verified, and not

- Both new maps parsed and validated with `validate_flow_map`; counts and
  routes in §11 of the spec are that tool's output, not estimates.
- The 97/697 ICS/enterprise split was read from the local lookup.
- **Nothing is implemented.** No library file exists, no code reads the spec,
  and the seed content in §8 is a list of what to write, not written.
