# Change Log — flow map examples and authoring guide

**Date:** 2026-09-10
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/examples/telemetry_saas_flow_map.json` (new),
`plugins/threat_modeling/adversary_path_projector/examples/plant_ot_flow_map.json` (new),
`plugins/threat_modeling/adversary_path_projector/examples/README.md` (new)
**Supporting Files:** none — no code changed.

Follows `2026-09-09-projection-hardening-and-llm-retry.md`.

---

## Problem

The projector shipped with one example flow map. One example is enough to prove
the plugin runs and not enough to test it: `claims_portal_flow_map.json` is a
single architectural shape — a three-tier web app — so every projection run
against it exercises the same topology, and a projector whose entire purpose is
reading *this* architecture rather than restating ATT&CK cannot be judged on one
architecture.

It also left the flow map schema effectively undocumented. The schema itself
lists fields and enums; nothing said which of them change the analysis, and the
two that matter most — `implementation_status` and the flow list — are the two
whose effect is least guessable from a type definition.

## Changes

### `telemetry_saas_flow_map.json` — Fleet Telemetry Platform

10 components, 11 flows, 4 zones, crown jewels `vault` and `telemetry_db`.

A multi-tenant SaaS whose build pipeline deploys into the estate it serves. The
shape the claims portal does not have is a **second path that re-enters the
first**: `scm → ci_runner → artifact_reg → k8s` runs parallel to the runtime
path and rejoins it at the cluster through an unsigned image pull.

Planted findings: `missing` partner credential rotation on a `partner`-exposed
API, a shared self-hosted runner with no controls at all, `planned` image
signing and commit signing, `missing` namespace network policies, and an
unauthenticated `ci_runner → vault` flow.

That last one is why the map is worth having. The shortest route to a crown
jewel is not through the product:

```
scm -> ci_runner -> vault    2 hops, 1 unauthenticated hop
```

Entry ranking discriminates rather than just sorting by exposure — `alb` 120,
`scm` 95, `partner_api` 80, `web_console` 65. The console is internet-facing and
still scores lowest of the four, because its WAF and MFA are both `implemented`;
the partner API outranks it on weaker controls despite only being
partner-exposed.

### `plant_ot_flow_map.json` — Bottling Plant OT Estate

10 components, 11 flows, 5 zones, crown jewels `plc` and `historian`.

Corporate IT, an IT/OT DMZ, supervisory control and a control network. The shape
here is **segmentation and the things that defeat it**: a jump host that exists
to be the only way in, and an engineering workstation with a second NIC that
makes it not the only way in.

Planted findings: VPN MFA still `planned`, `missing` vendor access review on a
standing integrator channel, `missing` application allowlisting on the
engineering workstation, shared local credentials and no controls on the SCADA
console, and unauthenticated Ethernet/IP into the control VLAN.

Both routes to the PLC run 4 hops with **2 unauthenticated hops**, and the
dual-homing shows up as topology rather than prose:

```
vpn           -> eng_ws  -> scada -> ot_switch -> plc
remote_vendor -> jump_ot -> scada -> ot_switch -> plc
```

The VPN tops entry ranking at 130 because `planned` MFA earns no score
reduction. That is the Phase 1 rule — only `implemented` controls lower a score
— producing the answer it was written to produce, on a map built to test it.

### Coverage the three maps now give together

The new maps were built to exercise what example 1 never touched: `partner` and
`management` exposure, `bidirectional` flows and therefore the reverse-edge
branch of reachability, explicit `crosses_boundary` overriding zone derivation,
the estate-wide `controls` array, all four `implementation_status` values, all
seven `control_type` values, `trivial` through `very_high` bypass difficulty, and
19 of the 22 component types (`actor`, `cache` and `datastore` remain unused).

Mitigation ids were checked against `get_mitre_relationships()` rather than
written from memory, and are **enterprise `M1xxx` throughout, including the OT
map**. The closed technique set is enterprise, so an ICS mitigation (`M0xxx`)
can never match `mitigations_for_technique()` and would make every mitigation on
that component read as uncovered. The OT map's segmentation controls therefore
carry `M1030`, not `M0930`.

### `examples/README.md`

An authoring guide, not a file listing. It documents the parts of the contract
that are not inferable from the schema:

- **The five fields that change the output** — `exposure`, `authentication`,
  `controls[].implementation_status`, `flows`, `crown_jewels` — separated from
  the majority of fields, which are documentation. `technologies` is called out
  separately: it affects neither scoring nor reachability, but it is in the
  prompt and visibly steers technique selection.
- **The entry-scoring weights in full**, including that scores floor at zero,
  that only the five preventive layers count, and that only `implemented`
  controls reduce a score.
- **That reachability is the declared flows and nothing else.** Nothing is
  inferred from zones, naming or component type. The forgotten flow is the one
  an attacker uses.
- **The error/warning split as a table**, framed by the reason for it: errors
  stop the run before any LLM call, warnings name the fallback that was applied.
- **A nine-step recipe** starting from crown jewels, and a common-mistakes list.
- **Actor pairings per map, with a warning to check first.** `TEMP.Veles` is
  named as the trap: the obvious pick for an OT map, 2 documented techniques.
  Reputation is a poor guide to what ATT&CK actually carries, `profile_actor` is
  free, and `intel_artifact_id` is the way to widen a thin actor.
- **That the JSON schema is stricter than the tool.** `_normalize_flow_map`
  keeps an unrecognised component `type` verbatim; `flow_map.schema.json` rejects
  it. Anyone validating only through the tool will not see it.

The minimal worked example in the guide was run before it was written down, and
the entry scores quoted for it (`web` 130, `db` 10) are actual output.

## Verified

- All three examples validate against `flow_map.schema.json`.
- `validate_flow_map` returns **zero errors and zero warnings** on both new maps;
  `unreachable_crown_jewels` and `isolated_components` are empty for each.
- Every actor named in the README resolves through `find_group`, and the
  technique counts quoted (58–94, and TEMP.Veles at 2) are from
  `techniques_for_group`.
- `--file_path` confirmed working as the README documents it.
- Full suite: **808 passed**, unchanged. Nothing references these files by name,
  so they are free-standing fixtures.

## Not in this change

- A deliberately malformed map. Nothing currently lets an operator exercise the
  lint errors or confirm by hand that Phase A refuses before spending a
  heavy-tier call. Worth a fourth fixture.
- No projection was run against either new map. Both are verified through
  `validate_flow_map` only, which needs no LLM; the heavy-tier pairing table in
  the README is reasoned from technique counts, not from observed output.

## Cosmetic, unfixed

`_score_component` builds the reason string `f"sits in a {trust} zone"`
(`tool.py:759`), which reads "sits in a untrusted zone". Noticed while quoting
real output into the guide. No test asserts on the string, so it is a one-line
fix whenever someone is in that file for another reason; left alone here because
this change touches no code.
