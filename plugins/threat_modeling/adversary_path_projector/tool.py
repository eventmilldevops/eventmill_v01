"""
Adversary Path Projector — project a named threat actor onto an application flow map.

Phase 1 (this module) is entirely deterministic and makes no LLM calls:

- ``profile_actor`` resolves an actor against ATT&CK and builds the closed set
  of techniques it is documented to use, carrying provenance per technique.
- ``validate_flow_map`` lints a flow map, ranks its entry surface, and computes
  the reachable routes from that surface to the crown jewels.

Path projection binds techniques from the closed set onto flow map components.
It is not implemented yet — the set assembled here is what will constrain it,
and the reachability computed here is what keeps it from inventing topology.

See docs/specs/adversary_path_projector.md.
"""

from __future__ import annotations

import json
from collections import deque
from typing import Any

from framework.plugins.protocol import ToolResult, ValidationResult
from framework.reference_data.mitre_attack import (
    TACTIC_ORDER,
    canonical_tactic,
    find_campaign,
    find_group,
    find_software,
    get_mitre_db,
    get_mitre_relationships,
    tactic_ordinal,
    techniques_for_campaign,
    techniques_for_group,
    techniques_for_software,
)

ACTIONS = ("profile_actor", "validate_flow_map")

# Planned but not yet implemented; named so validate_inputs can say so.
PLANNED_ACTIONS = ("normalize_flow_map", "project_paths")

SOFTWARE_SCOPES = ("none", "delivery", "all")

# Where the software-derived block came from. ATT&CK's software-to-technique
# mapping is the only source today; the block is kept separate from the actor's
# own techniques so a live lookup can replace it without touching the core set.
SOFTWARE_SOURCE_ATTCK = "attck_lookup"

# Tactics where the actor's own tooling determines the technique: the dropper,
# the loader, the implant and the channel it beacons over are all properties of
# the software, so ATT&CK's software mapping is real signal there.
#
# Everywhere else an actor generally uses what is already on the host — net.exe
# for discovery, RDP and SMB for lateral movement — so a technique reached only
# through the actor's malware says little about what they would do on a given
# estate, and folding it into the closed set mostly adds noise. Persistence is
# the marginal member: implant install mechanisms are tool-chosen often enough
# to keep, even though schtasks is as living-off-the-land as it gets.
DELIVERY_TACTICS = frozenset({
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Command and Control",
})


# ---------------------------------------------------------------------------
# Flow map vocabulary
#
# Control fields mirror threat_model_analyzer's SecurityControl so a scenario
# seed imports without translation.
# ---------------------------------------------------------------------------

EXPOSURE_LEVELS = ("internet", "partner", "internal", "management")
TRUST_LEVELS = ("untrusted", "semi_trusted", "trusted", "restricted")
DEFENSE_LAYERS = (
    "perimeter", "network", "endpoint", "application",
    "data", "identity", "monitoring",
)
IMPLEMENTATION_STATUSES = ("implemented", "partial", "planned", "missing")
BYPASS_DIFFICULTIES = ("trivial", "low", "medium", "high", "very_high")
DETECTION_CAPABILITIES = ("none", "low", "medium", "high")

# Layers that stop an attacker rather than merely record them.
PREVENTIVE_LAYERS = frozenset(
    {"perimeter", "network", "endpoint", "application", "identity"}
)

# Values that mean "anyone can talk to this".
_UNAUTHENTICATED = frozenset({"", "none", "anonymous", "public", "n/a"})

# Entry-surface scoring. Weights are relative and only ever compared with each
# other; the absolute numbers carry no meaning outside this ranking.
_EXPOSURE_SCORE = {"internet": 100, "partner": 60, "management": 45, "internal": 5}
_TRUST_BONUS = {"untrusted": 15, "semi_trusted": 5, "trusted": 0, "restricted": -10}
_BYPASS_PENALTY = {
    "trivial": 0, "low": -3, "medium": -10, "high": -20, "very_high": -30,
}
_UNAUTHENTICATED_BONUS = 25
_NO_PREVENTIVE_CONTROL_BONUS = 15

# Exposures an external attacker can originate from.
_EXTERNAL_EXPOSURES = frozenset({"internet", "partner"})


# ---------------------------------------------------------------------------
# ATT&CK helpers
# ---------------------------------------------------------------------------

_ICS_ONLY_TACTICS: set[str] | None = None


def _ics_only_tactics() -> set[str]:
    """Tactics carried only by ICS-matrix techniques.

    Derived from the technique database rather than hardcoded, so the set
    tracks whichever ATT&CK release the lookup was built from.  Used to keep
    ICS tactics out of an enterprise-only actor's uncovered list.
    """
    global _ICS_ONLY_TACTICS
    if _ICS_ONLY_TACTICS is not None:
        return _ICS_ONLY_TACTICS

    matrices_by_tactic: dict[str, set[str]] = {}
    for entry in get_mitre_db().values():
        matrix = entry.get("matrix", "")
        for tactic in entry.get("tactics", []):
            matrices_by_tactic.setdefault(tactic, set()).add(matrix)

    _ICS_ONLY_TACTICS = {
        tactic for tactic, matrices in matrices_by_tactic.items()
        if matrices == {"ics"}
    }
    return _ICS_ONLY_TACTICS


def _resolve_actor(query: str) -> dict[str, Any] | None:
    """Resolve an actor name, alias or id to an ATT&CK entity.

    Groups are tried first, then campaigns, then software, so that a name
    shared between a group and its signature malware resolves to the group.
    """
    relationships = get_mitre_relationships()
    for entity_type, finder, section in (
        ("group", find_group, "groups"),
        ("campaign", find_campaign, "campaigns"),
        ("software", find_software, "software"),
    ):
        entity_id = finder(query)
        if entity_id:
            return {
                "entity_type": entity_type,
                "attck_id": entity_id,
                "record": relationships.get(section, {}).get(entity_id, {}),
            }
    return None


def _add_claim(
    claims: dict[str, dict[str, set[str]]],
    technique_id: str,
    provenance: str,
    source: str,
) -> None:
    """Record that *source* backs the claim that the actor uses *technique_id*."""
    if not technique_id:
        return
    claim = claims.setdefault(technique_id, {"provenance": set(), "sources": set()})
    claim["provenance"].add(provenance)
    claim["sources"].add(source)


def _collect_actor_techniques(
    actor: dict[str, Any],
    intel_mappings: list[dict] | None = None,
    intel_source: str = "",
) -> dict[str, dict[str, set[str]]]:
    """Techniques the actor itself is documented using, with provenance per id.

    This is the core set: ATT&CK attributes these to the actor directly, not to
    something the actor has been seen carrying.  Techniques reached through the
    actor's tooling are a separate and weaker claim — see
    :func:`_collect_software_techniques`.
    """
    claims: dict[str, dict[str, set[str]]] = {}
    entity_type = actor["entity_type"]
    entity_id = actor["attck_id"]

    if entity_type == "group":
        for tid in techniques_for_group(entity_id):
            _add_claim(claims, tid, "attck_group", entity_id)
    elif entity_type == "campaign":
        for tid in techniques_for_campaign(entity_id):
            _add_claim(claims, tid, "attck_campaign", entity_id)
    elif entity_type == "software":
        # Profiling a malware family directly: its techniques are the core set.
        for tid in techniques_for_software(entity_id):
            _add_claim(claims, tid, "attck_software", entity_id)

    for mapping in intel_mappings or []:
        _add_claim(
            claims,
            mapping.get("technique_id", ""),
            "intel_report",
            intel_source or "intel_report",
        )

    return claims


def _technique_band(tactics: list[str]) -> str:
    """Classify a technique as 'delivery' or 'operational' by its tactics.

    Permissive: any delivery tactic makes the technique delivery-band, so a
    technique that is genuinely dropper-relevant is never dropped for also
    having a post-compromise role.
    """
    for raw_tactic in tactics:
        if (canonical_tactic(raw_tactic) or raw_tactic) in DELIVERY_TACTICS:
            return "delivery"
    return "operational"


def _collect_software_techniques(
    actor: dict[str, Any],
    scope: str,
    exclude: set[str],
) -> list[dict[str, Any]]:
    """Techniques reached only through the actor's associated software.

    Kept out of the core set on purpose.  ATT&CK maps a group to its tooling
    and the tooling to every technique that tooling implements, which for a
    well-documented actor is several times the group's own technique count and
    is dominated by generic post-compromise behaviour.  An actor will use
    whatever is already on a host to move laterally; what their malware does at
    the delivery stages is the part that actually distinguishes them.

    ``scope`` is 'none', 'delivery' (delivery-band techniques only) or 'all'.
    Anything already in *exclude* — the actor's own documented techniques — is
    omitted, so the two blocks stay disjoint and their counts stay meaningful.
    """
    if scope == "none" or actor["entity_type"] not in ("group", "campaign"):
        return []

    database = get_mitre_db()
    relationships = get_mitre_relationships()
    by_technique: dict[str, set[str]] = {}

    for software_id in actor["record"].get("software", []):
        for tid in techniques_for_software(software_id):
            if tid and tid not in exclude:
                by_technique.setdefault(tid, set()).add(software_id)

    collected: list[dict[str, Any]] = []
    for technique_id in sorted(by_technique):
        entry = database.get(technique_id, {})
        tactics = list(entry.get("tactics", []))
        band = _technique_band(tactics)
        if scope == "delivery" and band != "delivery":
            continue
        collected.append({
            "technique_id": technique_id,
            "name": entry.get("name", ""),
            "tactics": tactics,
            "band": band,
            "source": SOFTWARE_SOURCE_ATTCK,
            "software": [
                {
                    "id": software_id,
                    "name": relationships["software"]
                    .get(software_id, {})
                    .get("name", ""),
                }
                for software_id in sorted(by_technique[technique_id])
            ],
            "in_lookup": bool(entry),
        })
    return collected


def _enrich_claims(claims: dict[str, dict[str, set[str]]]) -> list[dict[str, Any]]:
    """Attach names and tactics from the technique lookup, sorted by id."""
    database = get_mitre_db()
    enriched: list[dict[str, Any]] = []
    for technique_id in sorted(claims):
        entry = database.get(technique_id, {})
        enriched.append({
            "technique_id": technique_id,
            "name": entry.get("name", ""),
            "tactics": list(entry.get("tactics", [])),
            "provenance": sorted(claims[technique_id]["provenance"]),
            "sources": sorted(claims[technique_id]["sources"]),
            "in_lookup": bool(entry),
        })
    return enriched


def _tactic_coverage(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group the technique set by tactic, in kill-chain order."""
    by_tactic: dict[str, list[str]] = {}
    for technique in techniques:
        for raw_tactic in technique["tactics"]:
            tactic = canonical_tactic(raw_tactic) or raw_tactic
            by_tactic.setdefault(tactic, []).append(technique["technique_id"])

    return [
        {
            "tactic": tactic,
            "ordinal": tactic_ordinal(tactic),
            "technique_count": len(technique_ids),
            "technique_ids": sorted(technique_ids),
        }
        for tactic, technique_ids in sorted(
            by_tactic.items(), key=lambda kv: (tactic_ordinal(kv[0]), kv[0])
        )
    ]


def _uncovered_tactics(covered: set[str], matrices: list[str]) -> list[str]:
    """Tactics with no documented technique, limited to the actor's matrices."""
    skip = set() if "ics" in matrices else _ics_only_tactics()
    return [t for t in TACTIC_ORDER if t not in covered and t not in skip]


def _procedures_for_sources(
    source_ids: set[str],
    technique_ids: set[str],
    limit: int,
) -> list[dict[str, str]]:
    """Procedure examples written about these sources, capped at *limit*.

    Scans the procedure list once.  Calling ``procedures_for_technique`` per
    technique would re-scan all 17k procedures for each of several hundred
    techniques.
    """
    if limit <= 0:
        return []
    found: list[dict[str, str]] = []
    for procedure in get_mitre_relationships().get("procedures", []):
        if (
            procedure.get("source") in source_ids
            and procedure.get("technique") in technique_ids
        ):
            found.append({
                "technique_id": procedure.get("technique", ""),
                "source": procedure.get("source", ""),
                "text": procedure.get("text", ""),
            })
            if len(found) >= limit:
                break
    return found


# ---------------------------------------------------------------------------
# Flow map normalization and linting
# ---------------------------------------------------------------------------

def _issue(code: str, message: str, location: str = "") -> dict[str, str]:
    return {"code": code, "message": message, "location": location}


def _normalize_control(
    raw: Any,
    location: str,
    warnings: list[dict[str, str]],
) -> dict[str, Any] | None:
    """Coerce one control to the canonical vocabulary, warning on bad enums."""
    if not isinstance(raw, dict):
        warnings.append(
            _issue("CONTROL_NOT_OBJECT", "Control is not an object.", location)
        )
        return None

    name = str(raw.get("name", "")).strip()
    if not name:
        warnings.append(
            _issue("CONTROL_MISSING_NAME", "Control has no name.", location)
        )
        return None

    def _enum(field: str, allowed: tuple[str, ...], default: str) -> str:
        value = str(raw.get(field, default) or default).strip().lower()
        if value not in allowed:
            warnings.append(_issue(
                "INVALID_ENUM",
                f"Control '{name}' has {field}={value!r}; using {default!r}.",
                location,
            ))
            return default
        return value

    control_type = str(raw.get("control_type", "") or "").strip().lower()
    if control_type and control_type not in DEFENSE_LAYERS:
        warnings.append(_issue(
            "INVALID_ENUM",
            f"Control '{name}' has control_type={control_type!r}, "
            f"which is not a defense layer.",
            location,
        ))
        control_type = ""

    mitigation_id = str(raw.get("mitre_mitigation_id", "") or "").strip().upper()
    known_mitigations = get_mitre_relationships().get("mitigations", {})
    if mitigation_id and mitigation_id not in known_mitigations:
        warnings.append(_issue(
            "UNKNOWN_MITIGATION",
            f"Control '{name}' cites mitigation {mitigation_id}, "
            f"which is not in the ATT&CK lookup.",
            location,
        ))

    return {
        "name": name,
        "control_type": control_type,
        "description": str(raw.get("description", "") or ""),
        "implementation_status": _enum(
            "implementation_status", IMPLEMENTATION_STATUSES, "implemented"
        ),
        "bypass_difficulty": _enum("bypass_difficulty", BYPASS_DIFFICULTIES, "medium"),
        "bypass_requirements": [
            str(r) for r in (raw.get("bypass_requirements") or []) if str(r).strip()
        ],
        "detection_capability": _enum(
            "detection_capability", DETECTION_CAPABILITIES, "medium"
        ),
        "mitre_mitigation_id": mitigation_id,
    }


def _normalize_flow_map(raw: Any) -> tuple[dict[str, Any], list[dict], list[dict]]:
    """Coerce a raw flow map into canonical form.

    Returns ``(flow_map, errors, warnings)``.  Structural problems that make
    projection impossible are errors; everything the tool can work around is a
    warning, and the normalized value reflects the fallback that was applied.
    """
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    if not isinstance(raw, dict):
        return (
            {},
            [_issue("FLOW_MAP_NOT_OBJECT", "Flow map must be a JSON object.")],
            [],
        )

    application = str(raw.get("application", "") or "").strip()
    if not application:
        errors.append(
            _issue("MISSING_APPLICATION", "Flow map has no 'application' name.")
        )

    # --- zones ---
    zones: dict[str, dict[str, Any]] = {}
    for index, raw_zone in enumerate(raw.get("zones") or []):
        location = f"zones[{index}]"
        if not isinstance(raw_zone, dict):
            errors.append(_issue("ZONE_NOT_OBJECT", "Zone is not an object.", location))
            continue
        zone_id = str(raw_zone.get("id", "") or "").strip()
        if not zone_id:
            errors.append(_issue("ZONE_MISSING_ID", "Zone has no id.", location))
            continue
        if zone_id in zones:
            errors.append(_issue(
                "DUPLICATE_ZONE_ID", f"Zone id '{zone_id}' is declared twice.", location
            ))
            continue
        trust = str(raw_zone.get("trust_level", "trusted") or "trusted").strip().lower()
        if trust not in TRUST_LEVELS:
            warnings.append(_issue(
                "INVALID_ENUM",
                f"Zone '{zone_id}' has trust_level={trust!r}; using 'trusted'.",
                location,
            ))
            trust = "trusted"
        zones[zone_id] = {
            "id": zone_id,
            "name": str(raw_zone.get("name", "") or zone_id),
            "trust_level": trust,
            "description": str(raw_zone.get("description", "") or ""),
        }

    # --- components ---
    components: dict[str, dict[str, Any]] = {}
    raw_components = raw.get("components") or []
    if not raw_components:
        errors.append(_issue("NO_COMPONENTS", "Flow map declares no components."))

    for index, raw_component in enumerate(raw_components):
        location = f"components[{index}]"
        if not isinstance(raw_component, dict):
            errors.append(_issue(
                "COMPONENT_NOT_OBJECT", "Component is not an object.", location
            ))
            continue
        component_id = str(raw_component.get("id", "") or "").strip()
        if not component_id:
            errors.append(
                _issue("COMPONENT_MISSING_ID", "Component has no id.", location)
            )
            continue
        if component_id in components:
            errors.append(_issue(
                "DUPLICATE_COMPONENT_ID",
                f"Component id '{component_id}' is declared twice.",
                location,
            ))
            continue

        exposure = str(
            raw_component.get("exposure", "internal") or "internal"
        ).strip().lower()
        if exposure not in EXPOSURE_LEVELS:
            warnings.append(_issue(
                "INVALID_ENUM",
                f"Component '{component_id}' has exposure={exposure!r}; "
                f"using 'internal'.",
                location,
            ))
            exposure = "internal"

        zone_id = str(raw_component.get("zone", "") or "").strip()
        if zone_id and zone_id not in zones:
            warnings.append(_issue(
                "UNKNOWN_ZONE",
                f"Component '{component_id}' references undeclared zone '{zone_id}'.",
                location,
            ))
        elif not zone_id:
            warnings.append(_issue(
                "COMPONENT_WITHOUT_ZONE",
                f"Component '{component_id}' is not assigned to a zone; "
                f"boundary crossings through it cannot be counted.",
                location,
            ))

        controls = []
        raw_controls = raw_component.get("controls") or []
        for control_index, raw_control in enumerate(raw_controls):
            control = _normalize_control(
                raw_control, f"{location}.controls[{control_index}]", warnings
            )
            if control:
                controls.append(control)

        components[component_id] = {
            "id": component_id,
            "name": str(raw_component.get("name", "") or component_id),
            "type": str(raw_component.get("type", "other") or "other"),
            "zone": zone_id,
            "exposure": exposure,
            "technologies": [
                str(t)
                for t in (raw_component.get("technologies") or [])
                if str(t).strip()
            ],
            "authentication": str(raw_component.get("authentication", "") or ""),
            "data_classification": str(
                raw_component.get("data_classification", "") or ""
            ),
            "description": str(raw_component.get("description", "") or ""),
            "controls": controls,
        }

    # --- flows ---
    flows: list[dict[str, Any]] = []
    seen_flows: set[tuple[str, str]] = set()
    for index, raw_flow in enumerate(raw.get("flows") or []):
        location = f"flows[{index}]"
        if not isinstance(raw_flow, dict):
            errors.append(_issue("FLOW_NOT_OBJECT", "Flow is not an object.", location))
            continue
        source = str(raw_flow.get("from", "") or "").strip()
        target = str(raw_flow.get("to", "") or "").strip()
        if not source or not target:
            errors.append(_issue(
                "FLOW_MISSING_ENDPOINT", "Flow needs both 'from' and 'to'.", location
            ))
            continue
        for endpoint, role in ((source, "from"), (target, "to")):
            if endpoint not in components:
                errors.append(_issue(
                    "DANGLING_FLOW_ENDPOINT",
                    f"Flow '{role}' references unknown component '{endpoint}'.",
                    location,
                ))
        if source not in components or target not in components:
            continue
        if source == target:
            warnings.append(_issue(
                "SELF_FLOW", f"Flow from '{source}' to itself is ignored.", location
            ))
            continue
        if (source, target) in seen_flows:
            warnings.append(_issue(
                "DUPLICATE_FLOW",
                f"Flow '{source}' -> '{target}' is declared twice.",
                location,
            ))
        seen_flows.add((source, target))

        source_zone = components[source]["zone"]
        target_zone = components[target]["zone"]
        declared_crossing = raw_flow.get("crosses_boundary")
        if isinstance(declared_crossing, bool):
            crosses = declared_crossing
        else:
            crosses = bool(source_zone and target_zone and source_zone != target_zone)

        controls = []
        for control_index, raw_control in enumerate(raw_flow.get("controls") or []):
            control = _normalize_control(
                raw_control, f"{location}.controls[{control_index}]", warnings
            )
            if control:
                controls.append(control)

        flows.append({
            "id": str(raw_flow.get("id", "") or f"f{index}"),
            "from": source,
            "to": target,
            "protocol": str(raw_flow.get("protocol", "") or ""),
            "port": raw_flow.get("port"),
            "authenticated": bool(raw_flow.get("authenticated", False)),
            "encrypted": raw_flow.get("encrypted"),
            "crosses_boundary": crosses,
            "bidirectional": bool(raw_flow.get("bidirectional", False)),
            "description": str(raw_flow.get("description", "") or ""),
            "controls": controls,
        })

    if not flows and components:
        warnings.append(_issue(
            "NO_FLOWS",
            "Flow map declares no flows, so nothing is reachable from anything. "
            "Reachability analysis will be empty.",
        ))

    # --- crown jewels ---
    crown_jewels: list[str] = []
    for index, raw_jewel in enumerate(raw.get("crown_jewels") or []):
        jewel = str(raw_jewel or "").strip()
        if not jewel:
            continue
        if jewel not in components:
            errors.append(_issue(
                "UNKNOWN_CROWN_JEWEL",
                f"Crown jewel '{jewel}' is not a declared component.",
                f"crown_jewels[{index}]",
            ))
            continue
        crown_jewels.append(jewel)

    if not crown_jewels and components:
        warnings.append(_issue(
            "NO_CROWN_JEWELS",
            "No crown jewels declared, so there is no target to compute routes to.",
        ))

    if components and not any(
        c["exposure"] in _EXTERNAL_EXPOSURES for c in components.values()
    ):
        warnings.append(_issue(
            "NO_EXTERNAL_EXPOSURE",
            "No component is exposed to the internet or a partner, so an external "
            "attacker has no entry point. Entry ranking falls back to the "
            "highest-scoring component.",
        ))

    estate_controls = []
    for control_index, raw_control in enumerate(raw.get("controls") or []):
        control = _normalize_control(
            raw_control, f"controls[{control_index}]", warnings
        )
        if control:
            estate_controls.append(control)

    flow_map = {
        "application": application,
        "description": str(raw.get("description", "") or ""),
        "zones": zones,
        "components": components,
        "flows": flows,
        "crown_jewels": crown_jewels,
        "controls": estate_controls,
    }
    return flow_map, errors, warnings


# ---------------------------------------------------------------------------
# Entry surface and reachability
# ---------------------------------------------------------------------------

def _score_component(
    component: dict[str, Any], zones: dict[str, dict]
) -> dict[str, Any]:
    """Score one component as an entry candidate, recording why."""
    reasons: list[str] = []
    exposure = component["exposure"]
    score = _EXPOSURE_SCORE.get(exposure, 0)
    reasons.append(f"{exposure}-facing")

    trust = zones.get(component["zone"], {}).get("trust_level", "")
    bonus = _TRUST_BONUS.get(trust, 0)
    if bonus:
        score += bonus
        reasons.append(f"sits in a {trust} zone")

    authentication = component["authentication"].strip().lower()
    if authentication in _UNAUTHENTICATED:
        score += _UNAUTHENTICATED_BONUS
        reasons.append("no authentication declared")

    implemented_preventive = [
        c for c in component["controls"]
        if c["control_type"] in PREVENTIVE_LAYERS
        and c["implementation_status"] == "implemented"
    ]
    if implemented_preventive:
        for control in implemented_preventive:
            penalty = _BYPASS_PENALTY.get(control["bypass_difficulty"], 0)
            score += penalty
            if penalty:
                reasons.append(
                    f"{control['name']} ({control['bypass_difficulty']} to bypass)"
                )
    else:
        score += _NO_PREVENTIVE_CONTROL_BONUS
        reasons.append("no implemented preventive control")

    return {
        "component_id": component["id"],
        "name": component["name"],
        "score": max(score, 0),
        "exposure": exposure,
        "zone": component["zone"],
        "reasons": reasons,
    }


def _entry_surface(flow_map: dict[str, Any]) -> list[dict[str, Any]]:
    """Rank every component as an entry candidate, highest score first."""
    zones = flow_map["zones"]
    ranked = [_score_component(c, zones) for c in flow_map["components"].values()]
    ranked.sort(key=lambda r: (-r["score"], r["component_id"]))
    return ranked


def _build_adjacency(
    flows: list[dict[str, Any]]
) -> tuple[dict[str, list[str]], dict[tuple[str, str], dict]]:
    """Directed adjacency plus edge lookup, expanding bidirectional flows."""
    adjacency: dict[str, list[str]] = {}
    edges: dict[tuple[str, str], dict] = {}
    for flow in flows:
        pairs = [(flow["from"], flow["to"])]
        if flow["bidirectional"]:
            pairs.append((flow["to"], flow["from"]))
        for source, target in pairs:
            adjacency.setdefault(source, [])
            if target not in adjacency[source]:
                adjacency[source].append(target)
            edges.setdefault((source, target), flow)
    return adjacency, edges


def _shortest_route(
    adjacency: dict[str, list[str]], start: str, target: str
) -> list[str] | None:
    """Breadth-first shortest route from *start* to *target*, or None."""
    if start == target:
        return [start]
    previous: dict[str, str] = {start: ""}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for neighbour in adjacency.get(current, []):
            if neighbour in previous:
                continue
            previous[neighbour] = current
            if neighbour == target:
                route = [neighbour]
                while previous[route[-1]]:
                    route.append(previous[route[-1]])
                return list(reversed(route))
            queue.append(neighbour)
    return None


def _crown_jewel_routes(
    flow_map: dict[str, Any], entry_surface: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Shortest routes from each external entry point to each crown jewel.

    Falls back to the highest-scoring component when nothing is externally
    exposed, so a purely internal map still produces routes rather than
    silently returning nothing.
    """
    components = flow_map["components"]
    crown_jewels = flow_map["crown_jewels"]
    if not crown_jewels:
        return [], []

    entries = [
        entry["component_id"] for entry in entry_surface
        if components[entry["component_id"]]["exposure"] in _EXTERNAL_EXPOSURES
    ]
    if not entries and entry_surface:
        entries = [entry_surface[0]["component_id"]]

    adjacency, edges = _build_adjacency(flow_map["flows"])
    routes: list[dict[str, Any]] = []
    reached: set[str] = set()

    for entry in entries:
        for target in crown_jewels:
            route = _shortest_route(adjacency, entry, target)
            if route is None:
                continue
            reached.add(target)
            hops = list(zip(route, route[1:]))
            routes.append({
                "entry": entry,
                "target": target,
                "hops": len(hops),
                "route": route,
                "boundary_crossings": sum(
                    1 for hop in hops if edges.get(hop, {}).get("crosses_boundary")
                ),
                "unauthenticated_hops": sum(
                    1 for hop in hops
                    if not edges.get(hop, {}).get("authenticated", False)
                ),
            })

    routes.sort(key=lambda r: (r["hops"], r["entry"], r["target"]))
    return routes, [j for j in crown_jewels if j not in reached]


def _isolated_components(flow_map: dict[str, Any]) -> list[str]:
    """Components with no inbound and no outbound flow."""
    connected: set[str] = set()
    for flow in flow_map["flows"]:
        connected.add(flow["from"])
        connected.add(flow["to"])
    return sorted(cid for cid in flow_map["components"] if cid not in connected)


# ---------------------------------------------------------------------------
# Tool implementation
# ---------------------------------------------------------------------------

class AdversaryPathProjector:
    """Project a named threat actor onto an application flow map.

    Phase 1 provides the deterministic groundwork: the closed technique set
    that constrains projection, and the reachability that keeps it honest
    about topology.
    """

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "adversary_path_projector",
            "version": "0.1.0",
            "pillar": "threat_modeling",
            "actions": list(ACTIONS),
            "planned_actions": list(PLANNED_ACTIONS),
            "attack_version": get_mitre_relationships().get("attack_version", ""),
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        action = payload.get("action")

        if not action:
            errors.append("'action' is required")
        elif action in PLANNED_ACTIONS:
            errors.append(
                f"Action '{action}' is planned but not implemented yet. "
                f"Available actions: {', '.join(ACTIONS)}."
            )
        elif action not in ACTIONS:
            errors.append(
                f"Invalid action '{action}'. Must be one of: {', '.join(ACTIONS)}."
            )

        if action == "profile_actor":
            if not str(payload.get("threat_actor", "") or "").strip():
                errors.append("'threat_actor' is required for profile_actor")
            max_procedures = payload.get("max_procedures", 5)
            if not isinstance(max_procedures, int) or isinstance(max_procedures, bool):
                errors.append("'max_procedures' must be an integer")
            elif not 0 <= max_procedures <= 50:
                errors.append("'max_procedures' must be between 0 and 50")

            scope = payload.get("software_scope", "delivery")
            if scope not in SOFTWARE_SCOPES:
                errors.append(
                    f"Invalid software_scope {scope!r}. Must be one of: "
                    f"{', '.join(SOFTWARE_SCOPES)}."
                )

        if action == "validate_flow_map":
            has_inline = isinstance(payload.get("flow_map"), dict)
            has_reference = bool(
                str(payload.get("flow_map_artifact_id", "") or "").strip()
                or str(payload.get("file_path", "") or "").strip()
            )
            if not has_inline and not has_reference:
                errors.append(
                    "validate_flow_map needs 'flow_map', 'flow_map_artifact_id' "
                    "or 'file_path'"
                )
            if "flow_map" in payload and not has_inline:
                errors.append("'flow_map' must be an object")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        action = payload["action"]
        try:
            if action == "profile_actor":
                return self._profile_actor(payload, context)
            if action == "validate_flow_map":
                return self._validate_flow_map(payload, context)
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=f"Unknown action: {action}",
            )
        except Exception as exc:
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(exc))

    # -------------------------------------------------------------------
    # Artifact access
    # -------------------------------------------------------------------

    @staticmethod
    def _read_json_artifact(
        artifact_id: str, context: Any
    ) -> tuple[dict | None, ToolResult | None]:
        """Load a json_events artifact's content, or return the error to surface."""
        artifacts = getattr(context, "artifacts", None) or []
        artifact = next((a for a in artifacts if a.artifact_id == artifact_id), None)
        if artifact is None:
            return None, ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=(
                    f"Artifact '{artifact_id}' not found in session. "
                    "Use 'artifacts' to list loaded artifacts."
                ),
            )
        try:
            with open(artifact.file_path, "r", encoding="utf-8") as handle:
                return json.load(handle), None
        except Exception as exc:
            return None, ToolResult(
                ok=False,
                error_code="ARTIFACT_UNREADABLE",
                message=f"Failed to read artifact '{artifact_id}': {exc}",
            )

    # -------------------------------------------------------------------
    # Actions
    # -------------------------------------------------------------------

    def _profile_actor(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Resolve an actor and build its closed technique set."""
        query = str(payload["threat_actor"]).strip()
        software_scope = str(payload.get("software_scope", "delivery"))
        max_procedures = payload.get("max_procedures", 5)
        intel_artifact_id = str(payload.get("intel_artifact_id", "") or "").strip()

        relationships = get_mitre_relationships()
        if not relationships.get("groups"):
            return ToolResult(
                ok=False,
                error_code="DEPENDENCY_MISSING",
                message=(
                    "MITRE relationships lookup is empty. Run "
                    "'python scripts/build_mitre_lookup.py' to build it."
                ),
            )

        intel_mappings: list[dict] = []
        if intel_artifact_id:
            data, error = self._read_json_artifact(intel_artifact_id, context)
            if error is not None:
                return error
            intel_mappings = (data or {}).get("mitre_mappings", []) or []

        actor = _resolve_actor(query)
        if actor is None and not intel_mappings:
            return ToolResult(
                ok=False,
                error_code="ACTOR_NOT_FOUND",
                message=(
                    f"'{query}' does not match any ATT&CK group, campaign or "
                    f"software name, alias or id. Supply 'intel_artifact_id' with a "
                    f"threat_intel_ingester output to profile an actor ATT&CK does "
                    f"not document."
                ),
            )

        resolved = actor is not None
        if actor is None:
            # Unresolved name, but intel gives us a technique set to work from.
            actor = {"entity_type": "", "attck_id": "", "record": {}}

        claims = _collect_actor_techniques(
            actor,
            intel_mappings=intel_mappings,
            intel_source=intel_artifact_id,
        )

        record = actor["record"]
        techniques = _enrich_claims(claims)
        software_techniques = _collect_software_techniques(
            actor, software_scope, exclude=set(claims)
        )
        coverage = _tactic_coverage(techniques)
        covered = {entry["tactic"] for entry in coverage}

        software = [
            {
                "id": software_id,
                "name": relationships["software"].get(software_id, {}).get("name", ""),
                "type": relationships["software"].get(software_id, {}).get("type", ""),
            }
            for software_id in record.get("software", [])
        ]

        source_ids = {actor["attck_id"]} | {s["id"] for s in software}
        source_ids.discard("")
        procedures = _procedures_for_sources(
            source_ids, {t["technique_id"] for t in techniques}, max_procedures
        )

        return ToolResult(
            ok=True,
            result={
                "action": "profile_actor",
                "actor": {
                    "query": query,
                    "resolved": resolved,
                    "attck_id": actor["attck_id"],
                    "name": record.get("name", "") or query,
                    "entity_type": actor["entity_type"] if resolved else "",
                    "aliases": list(record.get("aliases", [])),
                    "description": record.get("description", ""),
                    "software": software,
                    "attack_version": relationships.get("attack_version", ""),
                },
                "technique_count": len(techniques),
                "techniques": techniques,
                "software_scope": software_scope,
                "software_source": SOFTWARE_SOURCE_ATTCK,
                "software_technique_count": len(software_techniques),
                "software_techniques": software_techniques,
                "allowed_technique_ids": sorted(
                    {t["technique_id"] for t in techniques}
                    | {t["technique_id"] for t in software_techniques}
                ),
                "tactic_coverage": coverage,
                "uncovered_tactics": _uncovered_tactics(
                    covered, list(record.get("matrices", []))
                ),
                "procedures": procedures,
                "unknown_techniques": [
                    t["technique_id"] for t in techniques if not t["in_lookup"]
                ],
            },
        )

    def _validate_flow_map(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Lint a flow map, rank its entry surface, and compute reachability."""
        raw: Any = payload.get("flow_map")

        if raw is None:
            artifact_id = str(payload.get("flow_map_artifact_id", "") or "").strip()
            file_path = str(payload.get("file_path", "") or "").strip()
            if artifact_id:
                raw, error = self._read_json_artifact(artifact_id, context)
                if error is not None:
                    return error
            elif file_path:
                try:
                    with open(file_path, "r", encoding="utf-8") as handle:
                        raw = json.load(handle)
                except Exception as exc:
                    return ToolResult(
                        ok=False,
                        error_code="ARTIFACT_UNREADABLE",
                        message=f"Failed to read flow map '{file_path}': {exc}",
                    )

        flow_map, errors, warnings = _normalize_flow_map(raw)

        if not flow_map.get("components"):
            return ToolResult(
                ok=True,
                result={
                    "action": "validate_flow_map",
                    "application": flow_map.get("application", ""),
                    "valid": False,
                    "errors": errors,
                    "warnings": warnings,
                    "counts": {
                        "components": 0, "zones": 0, "flows": 0,
                        "crown_jewels": 0, "controls": 0,
                    },
                    "entry_surface": [],
                    "crown_jewel_routes": [],
                    "unreachable_crown_jewels": [],
                    "isolated_components": [],
                },
            )

        entry_surface = _entry_surface(flow_map)
        routes, unreachable = _crown_jewel_routes(flow_map, entry_surface)
        isolated = _isolated_components(flow_map)

        for jewel in unreachable:
            warnings.append(_issue(
                "UNREACHABLE_CROWN_JEWEL",
                f"No declared flow reaches crown jewel '{jewel}' from any entry "
                f"point. The flow map is probably incomplete.",
                f"crown_jewels/{jewel}",
            ))
        for component_id in isolated:
            warnings.append(_issue(
                "ISOLATED_COMPONENT",
                f"Component '{component_id}' has no inbound or outbound flow.",
                f"components/{component_id}",
            ))

        control_count = (
            len(flow_map["controls"])
            + sum(len(c["controls"]) for c in flow_map["components"].values())
            + sum(len(f["controls"]) for f in flow_map["flows"])
        )

        return ToolResult(
            ok=True,
            result={
                "action": "validate_flow_map",
                "application": flow_map["application"],
                "valid": not errors,
                "errors": errors,
                "warnings": warnings,
                "counts": {
                    "components": len(flow_map["components"]),
                    "zones": len(flow_map["zones"]),
                    "flows": len(flow_map["flows"]),
                    "crown_jewels": len(flow_map["crown_jewels"]),
                    "controls": control_count,
                },
                "entry_surface": entry_surface,
                "crown_jewel_routes": routes,
                "unreachable_crown_jewels": unreachable,
                "isolated_components": isolated,
            },
        )

    # -------------------------------------------------------------------
    # LLM summary
    # -------------------------------------------------------------------

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context. Hard cap 2000 characters."""
        if not result.ok:
            return f"adversary_path_projector failed: {result.message}"

        data = result.result or {}
        action = data.get("action", "unknown")

        if action == "profile_actor":
            summary = self._summarize_actor(data)
        elif action == "validate_flow_map":
            summary = self._summarize_flow_map(data)
        else:
            summary = f"adversary_path_projector completed action '{action}'."

        return summary[:2000]

    @staticmethod
    def _summarize_actor(data: dict[str, Any]) -> str:
        actor = data.get("actor", {})
        software_techniques = data.get("software_techniques", [])
        scope = data.get("software_scope", "delivery")

        label = actor.get("name") or actor.get("query", "?")
        if actor.get("attck_id"):
            label = f"{label} ({actor['attck_id']})"

        lines = [
            f"Actor {label} — ATT&CK v{actor.get('attack_version', '?')}. "
            f"{data.get('technique_count', 0)} techniques attributed to the actor "
            f"directly; {len(software_techniques)} more via associated software "
            f"(scope '{scope}')."
        ]
        if not actor.get("resolved"):
            lines.append(
                "Not found in ATT&CK; technique set comes from the supplied "
                "intel report only."
            )
        if scope == "delivery" and software_techniques:
            lines.append(
                "Software techniques are limited to the delivery bands "
                "(resource development, initial access, execution, persistence, "
                "C2) — post-compromise behaviour is generally whatever is on the "
                "host, not the actor's tooling."
            )

        coverage = data.get("tactic_coverage", [])
        if coverage:
            covered = ", ".join(
                f"{c['tactic']} ({c['technique_count']})" for c in coverage[:8]
            )
            more = f", +{len(coverage) - 8} more" if len(coverage) > 8 else ""
            lines.append(f"Tactic coverage: {covered}{more}.")

        uncovered = data.get("uncovered_tactics", [])
        if uncovered:
            lines.append(
                f"Nothing attributed to the actor directly for: "
                f"{', '.join(uncovered)}."
            )

        unknown = data.get("unknown_techniques", [])
        if unknown:
            lines.append(
                f"{len(unknown)} technique id(s) not in the local lookup: "
                f"{', '.join(unknown[:5])}."
            )

        lines.append(
            "Projection may use only these techniques; anything outside the set "
            "is unsupported by the actor's documented behaviour."
        )
        return "\n".join(lines)

    @staticmethod
    def _summarize_flow_map(data: dict[str, Any]) -> str:
        counts = data.get("counts", {})
        errors = data.get("errors", [])
        warnings = data.get("warnings", [])

        lines = [
            f"Flow map '{data.get('application', '?')}': "
            f"{counts.get('components', 0)} components, "
            f"{counts.get('flows', 0)} flows, "
            f"{counts.get('zones', 0)} zones, "
            f"{counts.get('crown_jewels', 0)} crown jewels, "
            f"{counts.get('controls', 0)} controls. "
            f"{'VALID' if data.get('valid') else 'INVALID'} "
            f"({len(errors)} error(s), {len(warnings)} warning(s))."
        ]

        for error in errors[:4]:
            lines.append(f"  ERROR {error['code']}: {error['message']}")
        if len(errors) > 4:
            lines.append(f"  ... {len(errors) - 4} more error(s).")

        surface = data.get("entry_surface", [])
        if surface:
            top = ", ".join(
                f"{entry['component_id']} ({entry['exposure']}, score {entry['score']})"
                for entry in surface[:3]
            )
            lines.append(f"Top entry candidates: {top}.")

        routes = data.get("crown_jewel_routes", [])
        if routes:
            shortest = routes[0]
            lines.append(
                f"{len(routes)} route(s) to crown jewels; shortest is "
                f"{' -> '.join(shortest['route'])} "
                f"({shortest['hops']} hops, "
                f"{shortest['boundary_crossings']} boundary crossing(s), "
                f"{shortest['unauthenticated_hops']} unauthenticated)."
            )

        unreachable = data.get("unreachable_crown_jewels", [])
        if unreachable:
            lines.append(f"Unreachable crown jewels: {', '.join(unreachable)}.")

        return "\n".join(lines)
