# Two projector scoring observations, found by modelling a physical estate

**Date:** 2026-09-20
**Branch:** `llm_5`
**Scope:** planning only. **No code changed**, suite unchanged at 1705.
Subject: `plugins/threat_modeling/adversary_path_projector/tool.py`.

Both surfaced while validating `branch_physical_flow_map.json`, the estate
whose entry is a person walking through a door. Neither is caused by the
`protocol: physical` convention — that convention exposed them. They are
written up separately because changing either alters every projection,
including the four committed fixtures, and that deserves its own before-and-
after rather than being folded into feature work.

---

## Item 1 — a component that leads nowhere can rank first as an entry point

**What happens.** `_entry_surface` (`tool.py:987`) scores every component and
sorts by score. `_score_component` (`tool.py:940`) adds exposure
(`internet` 100), a trust bonus (`untrusted` +15), `_UNAUTHENTICATED_BONUS`
(+25) when no authentication is declared, and `_NO_PREVENTIVE_CONTROL_BONUS`
(+15) when the component has no implemented preventive control.

On the branch estate that makes `oob_cellular` — the attacker's *exfiltration*
path — the top-ranked entry point at **155**, above the lobby badge reader at
130:

```text
entry oob_cellular 155 ['internet-facing', 'sits in a untrusted zone',
                        'no authentication declared', 'no implemented preventive control']
entry lobby_badge_reader 130 ['internet-facing', 'sits in a untrusted zone',
                        'no implemented preventive control']
```

It has **no outbound flows**, so no route can begin there. Nothing is
structurally broken: `_crown_jewel_routes` finds no path from it and the real
routes are produced correctly from the badge reader. The loyalty estate shows
the same shape more loudly — `redemption_partner` produces a route to itself of
zero hops.

**Why it still matters.** The ranked entry surface is not only an internal
intermediate — it is carried into the projection run (`tool.py:3535-3541`) and
shown to the operator. A reader, human or model, is being told the most
attractive way into the branch is the cellular link, which cannot be entered at
all. Every estate with a declared egress-only path — a cellular modem, a
one-way diode, a partner drop, an external payment endpoint — will have the
same shape.

**The obvious fix is wrong, and the data says so.** "Exclude components with no
outbound flow from the entry ranking" was the first recommendation written
here. Checking it against all five maps killed it:

| Map | Externally exposed **and** no outbound flow |
|---|---|
| `claims_portal` | `idp` |
| `application_b` | `okta` |
| `telemetry_saas` | — |
| `plant_ot` | — |
| `branch_physical` | `oob_cellular` |
| `loyalty_commerce` | `customer_identity`, `fraud_engine`, `email_provider`, `redemption_partner` |

`idp` and `okta` are identity providers. They are genuinely attackable entry
points; their maps simply do not draw an outbound edge, because the author
modelled the application calling the IdP rather than the IdP calling back.
Suppressing them would delete two real entry candidates to silence one
misleading row. **Absence of an outbound edge is a property of how the map was
drawn, not of the estate.**

**Options.**

| | Approach | Cost |
|---|---|---|
| A | Annotate rather than suppress: `leads_nowhere: true` on a ranked entry with no outbound adjacency, and say so in the narration | Smallest; the order still puts a dead end first, but no reader is misled and no real candidate is lost |
| B | Rank by *reachable value* — score entry candidates by what they can actually reach, so a component that reaches nothing sorts last regardless of exposure | Medium; fixes the order for the right reason and would also demote `fraud_engine` and `email_provider` |
| C | Score direction explicitly and add an `egress_surface` ranking as its own output | Largest, and the most useful: an egress list is something detection engineering wants in its own right |

**Recommendation: A, then B.** A is honest immediately and cannot lose a real
candidate. B is the correct model — an entry point that reaches nothing is not
an entry point worth ranking first — but it changes the ordering on every map
and should be measured on all six before it lands. C waits until exfiltration
paths are a question someone is asking.

**Acceptance gate.** For A: `oob_cellular`, `redemption_partner`,
`fraud_engine`, `email_provider`, `customer_identity`, `idp` and `okta` all
carry `leads_nowhere: true`; no component disappears from `entry_surface`;
crown-jewel routes for all six example maps are byte-identical before and
after; the narration names the flag. For B, additionally: the branch estate's
top entry becomes `lobby_badge_reader`, and the before-and-after ranking of all
six maps is recorded in the change log entry, because four committed fixture
pairs were projected under the old order.

---

## Item 2 — a door and an open network jack count as the same weakness

**What happens.** `_crown_jewel_routes` (`tool.py:1076`) counts a hop as
unauthenticated whenever the edge's `authenticated` is not true:

```python
"unauthenticated_hops": sum(
    1 for hop in hops
    if not edges.get(hop, {}).get("authenticated", False)
),
```

On the branch route that yields:

```text
route lobby_badge_reader -> meeting_room_port -> print_vlan_switch -> file_server
hops 3, boundary_crossings 2, unauthenticated_hops 2
```

Both counted hops are real weaknesses, and they are **not the same kind**. One
is an ethernet wall port with no 802.1X. The other is the badge line, marked
`authenticated: false` because tailgating and an unenforced escort procedure
defeat it. The narration at `tool.py:1295` and `tool.py:4720` then reports "2
unauthenticated hop(s)", which a reader will take as two network findings.

The same flattening applies to `protocol: ethernet` links generally — a patch
or uplink is a physical medium, not a service that could have authenticated.

**Options.**

| | Approach | Cost |
|---|---|---|
| A | Count physical hops separately: `unauthenticated_hops` keeps its meaning, a new `physical_hops` sits beside it | Small; additive field, existing counts change on physical maps only |
| B | Classify each hop by medium (`network`, `physical`, `out_of_band`) and report a breakdown | Medium; more faithful and more to narrate |
| C | Leave it, and rely on the route list showing the protocol per hop | None; the narration stays misleading |

**Recommendation: A.** It preserves the meaning of an existing number — which
four committed fixtures and any saved run record depend on — and adds the
distinction where it is needed. B is the better model if physical estates
become common; it can build on A without reversing it.

**Acceptance gate.** The branch route reports `unauthenticated_hops: 1` and
`physical_hops: 1`; the four existing fixture pairs report unchanged
`unauthenticated_hops`; the narration names the two separately; a map with no
physical flow produces no `physical_hops` key rather than a zero.

---

## Item 3 — the designer should prefer physical telemetry on a physical hop

Smaller, and it belongs to the designer rather than the projector, but it comes
from the same source.

A node whose `transition.protocol` is `physical` should draw its telemetry
candidates from the physical sources now in the library — `badge.door_event`,
`badge.door_contact_alarm`, `cctv.retention_index`, and the variance-management
audits — rather than from the network sources its component's technologies
would otherwise match. `sources_for_component()` is technology-first, which is
correct for everything else and wrong here: a wall port's technology is
`ethernet-wall-port`, and no amount of network telemetry observes a person.

This is a join rule in G1, not new data, and it needs
`docs/specs/reserved_vocabulary.md` §1 as its authority — the rule keys on the
reserved protocol spelling.

---

## Why none of this was changed now

Both projector items alter numbers that existing artifacts already carry. The
four committed fixture pairs, their run records and the exported packs all
contain entry rankings and hop counts produced by the current rules. Changing
the rules inside unrelated feature work would leave two generations of
artifacts that disagree without saying why. Each item wants its own change, its
own before-and-after on all five example maps, and its own change log entry.
