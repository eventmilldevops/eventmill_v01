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

import hashlib
import json
import logging
import os
import re
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.plugins.protocol import QueryHints, ToolResult, ValidationResult
from framework.reference_data.mitre_attack import (
    TACTIC_ORDER,
    canonical_tactic,
    find_campaign,
    find_group,
    find_software,
    get_mitre_db,
    get_mitre_relationships,
    mitigations_for_technique,
    resolve_legacy_tactic,
    tactic_ordinal,
    techniques_for_campaign,
    techniques_for_group,
    techniques_for_software,
)

logger = logging.getLogger("eventmill.plugin.adversary_path_projector")

ACTIONS = (
    "profile_actor", "validate_flow_map", "project_paths", "summarize_run_group",
)

# Planned but not yet implemented; named so validate_inputs can say so.
PLANNED_ACTIONS = ("normalize_flow_map",)

SOFTWARE_SCOPES = ("none", "delivery", "all")

THINKING_LEVELS = ("minimal", "low", "medium", "high")

# Reasoning depth for the projection call, stated explicitly rather than left to
# the dispatcher. `needs_reasoning=True` with no level makes client.py resolve
# to "high", which is the latency that pushes a multi-path run into the
# provider's gateway deadline. Deep reasoning about how an actor would move
# through *this* architecture is the entire value over re-summarising ATT&CK, so
# this is a deliberate floor, not a cost saving — drop it per call only when a
# large map needs the latency back.
DEFAULT_THINKING_LEVEL = "medium"

# Operator override for the above, so an environment with more latency headroom
# than an interactive session can run deeper without a code edit — Cloud Run at
# "high", a laptop at "medium". Named after the existing tier overrides in
# framework/llm/providers/__init__.py.
THINKING_LEVEL_ENV_OVERRIDE = "EVENTMILL_PROJECTION_THINKING"

# Run records. The corpus these build is compared by eye, one record against
# another, so the schema version is what tells a later reader whether two
# records are the same shape.
# 2: sampled steps carry the model's step state (Phase 3c).
# 3: model.model_served — the id the provider reports, so a comparison across
#    models rests on what ran rather than on what was asked for.
RUN_RECORD_SCHEMA_VERSION = 3

# Output cap for the projection call: 48K (48 x 1024). Step state roughly
# triples the size of a step, and the assessment sets out to show what deep
# work really costs, so the cap leaves the model room rather than trimming it.
# Still inside the provider's own output cap (gcp_gemini.json). Latency, not
# this number, is the practical ceiling.
PROJECTION_MAX_TOKENS = 49152

# A run at "medium" on a ten-component map is roughly 27s, so 25 is already a
# ten-minute invocation. The cap is about keeping that a deliberate choice.
MAX_RUNS = 25

DEFAULT_RUN_GROUP = "ungrouped"

# A projection is not a confirmed attack, and readers struggle with ambiguity,
# so every projected output carries the same sentence. threat_model_analyzer
# uses identical wording for imported scenarios. "Projected", not "estimated":
# the tool scores no likelihood, and "estimated" invites the question.
PROJECTION_NOTICE = "Projected from threat intelligence, not a confirmed attack path."

# Written into the graph and seed files, which people open directly.
PROJECTION_INTERPRETATION = (
    "Projected attack paths: not confirmed attacks, and not a likelihood "
    "assessment. An LLM placed techniques that MITRE ATT&CK documents this "
    "actor using onto the organization's own flow map, reasoning the way an "
    "adversary would. Technique ids, technique names and controls are "
    "sourced; the route, the step rationales and the access states are the "
    "model's projection. Each step's access is checked only for continuity — "
    "that an earlier step produced what the step needs — never for truth. A "
    "step that states no access falls back to a typical value for its tactic."
)


def _default_thinking_level() -> str:
    """Reasoning depth for a call that does not name one.

    Precedence mirrors the tier rule in CLAUDE.md: per-call payload > env >
    the constant above. Read at call time rather than import time so a .env
    loaded after this module is imported still takes effect, and so tests can
    set it without reloading. An unusable value warns and falls back rather
    than failing the run — an operator typo should not cost a projection.
    """
    value = (os.environ.get(THINKING_LEVEL_ENV_OVERRIDE) or "").strip().lower()
    if not value:
        return DEFAULT_THINKING_LEVEL
    if value in THINKING_LEVELS:
        return value
    logger.warning(
        "Ignoring %s=%r — must be one of: %s. Using %r.",
        THINKING_LEVEL_ENV_OVERRIDE, value,
        ", ".join(THINKING_LEVELS), DEFAULT_THINKING_LEVEL,
    )
    return DEFAULT_THINKING_LEVEL

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
# Run provenance
# ---------------------------------------------------------------------------

def _canonical_flow_map_hash(raw: Any) -> str:
    """SHA-256 over a canonical serialisation of the flow map as supplied.

    Sorted keys and no insignificant whitespace, so reformatting or reordering
    a map does not change the hash but a content change does.  Hashed *before*
    _normalize_flow_map runs: normalization fills defaults, so two genuinely
    different files can normalize to the same thing.  This is the join key a
    later comparison uses to know two records describe the same estate.
    """
    canonical = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_GIT_SHA: str | None = None


def _git_short_sha() -> str:
    """Short SHA of the working tree, read from .git without shelling out.

    Recorded alongside the manifest version because the manifest version does
    not move on its own: it has read 0.2.0 since the projection action landed,
    while tactic correction, the kill-chain checks and the thinking-level
    default all shipped after it.  The SHA is the field that can actually tell
    two runs of different code apart.
    """
    global _GIT_SHA
    if _GIT_SHA is not None:
        return _GIT_SHA

    _GIT_SHA = ""
    for parent in Path(__file__).resolve().parents:
        git_dir = parent / ".git"
        if not git_dir.exists():
            continue
        try:
            if git_dir.is_file():  # worktree or submodule
                git_dir = parent / git_dir.read_text(encoding="utf-8").split(
                    "gitdir:", 1
                )[1].strip()
            head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
            if head.startswith("ref:"):
                ref = head.split(":", 1)[1].strip()
                ref_file = git_dir / ref
                if ref_file.exists():
                    head = ref_file.read_text(encoding="utf-8").strip()
                else:  # packed-refs
                    packed = (git_dir / "packed-refs").read_text(encoding="utf-8")
                    head = next(
                        (
                            line.split()[0]
                            for line in packed.splitlines()
                            if line.endswith(f" {ref}")
                        ),
                        "",
                    )
            _GIT_SHA = head[:7]
        except Exception as exc:
            logger.debug("Could not read git SHA: %s", exc)
        break
    return _GIT_SHA


_MANIFEST_VERSION: str | None = None


def _manifest_version() -> str:
    global _MANIFEST_VERSION
    if _MANIFEST_VERSION is None:
        _MANIFEST_VERSION = ""
        try:
            manifest = json.loads(
                (Path(__file__).resolve().parent / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            _MANIFEST_VERSION = str(manifest.get("version", "") or "")
        except Exception as exc:
            logger.debug("Could not read manifest version: %s", exc)
    return _MANIFEST_VERSION


def _slug(value: str, fallback: str) -> str:
    """Filesystem- and metadata-safe form of an operator-supplied label."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return cleaned[:64] or fallback


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
# Phase B — projection prompt
# ---------------------------------------------------------------------------

# Cap on techniques listed in the prompt. Delivery scope keeps a well-documented
# actor near 110, so this only bites on 'all'. Core-set techniques are kept
# first, so what gets dropped is the weakest material.
MAX_TECHNIQUES_IN_PROMPT = 250

PROJECTION_SYSTEM_CONTEXT = (
    "You are a threat modelling analyst. You map a named adversary's documented "
    "tradecraft onto a specific application architecture. You never invent "
    "techniques an adversary is not documented using, and you never invent "
    "connectivity the architecture does not declare."
)

PROJECTION_PROMPT = """Project how {actor_label} would move through this application.

You are NOT choosing techniques. The technique set below is closed — it is what
MITRE ATT&CK documents this actor using. Your job is PLACEMENT: deciding which
of these techniques lands on which component of this specific architecture, and
in what order.

HARD RULES — a step breaking any of these is discarded:
1. `technique_id` MUST be copied exactly from the TECHNIQUE SET below.
2. `component_id` MUST be copied exactly from the COMPONENTS table below.
3. `tactic` MUST be one of the ATT&CK v19 tactics listed below, and MUST be a
   tactic that technique actually carries.
4. Consecutive steps MUST follow a declared flow, or stay on one component.
   The REACHABLE ROUTES below are the only connectivity that exists. Do not
   invent a hop between components with no flow between them.
5. The first step of a path MUST be on an internet- or partner-exposed
   component. That is where an external attacker starts.

ATT&CK v19 tactics (use these names exactly):
{tactic_names}

"Defense Evasion" was retired in v19. Use "Stealth" for hiding, blending in,
obfuscation or masquerading, and "Defense Impairment" for disabling or
tampering with security controls. Never output "Defense Evasion".

APPLICATION: {application}
{application_description}

COMPONENTS:
{components_table}

REACHABLE ROUTES (entry point to crown jewel, over declared flows):
{routes_block}

TECHNIQUE SET — the closed set, grouped by tactic:
{technique_block}

{objective_block}
Produce up to {max_paths} attack path(s). Give each a short slug id. Cover
DISTINCT routes: where the REACHABLE ROUTES above reach more than one crown
jewel, or reach one by a materially different route, give each its own path. A
second path ending at a different crown jewel is worth more than a longer
version of the first. Return a single path only if the architecture genuinely
supports one. For each step, `rationale` must say in one sentence
what about THIS component makes THIS technique apply — its technology, its
exposure, its authentication, its data, or the control that is missing or weak.
A rationale that would read the same for any application is not useful.

STEP STATE — make every step reviewable by someone who will test it:
- `access_before` is what the attacker must already hold for this step;
  `access_after` is what they hold once it succeeds. Use exactly one of:
  {access_states}.
  network_reach, code_execution, privileged and data_access are held ON a
  component; credentials travel with the attacker. At the start the attacker
  holds only network_reach on the externally exposed components.
- `access_before` means what they hold **on THIS step's component** — except
  credentials, which they carry. The first time a path touches a component,
  that is normally `network_reach`: you do not need code execution on a
  component in order to exploit it, because code execution is what the step
  produces. Saying otherwise describes what you hold somewhere else, and the
  step will be flagged as unexplained.
- `access_before` must be something an earlier step in the same path gave the
  attacker. If you cannot say how they came to hold it, add the step that gives
  it to them, using a technique from the set. If the set has no technique for
  that bridge, say so in `assumptions` rather than skipping it.
- `precondition`: what must already be true, in one sentence.
- `exploited_condition`: the property of THIS component the technique relies on.
- `result`: what the attacker holds afterwards, concretely.
- `assumptions`: one to three things that must be true for this step to work
  and that the COMPONENTS table does not state — what a defender would go and
  check. Do not restate the table. Under 20 words each.
- `control_note` (optional): how the step gets past, or around, the controls on
  this component.
Do not describe flows or list controls; the tool attaches those from the map.
Every path carries this state for every step. Detail on one path is not a
reason to return fewer paths than the routes support.

`leads_to` lists the `technique_id` values of the next steps within the same
path. The final step of a path has an empty `leads_to`.

Respond ONLY with a JSON object in this exact format:
{{
  "paths": [
    {{
      "path_id": "short-slug",
      "description": "One sentence describing this path.",
      "objective": "What the actor achieves at the end of it.",
      "steps": [
        {{
          "technique_id": "T1190",
          "tactic": "Initial Access",
          "component_id": "portal",
          "rationale": "One sentence: why this technique on this component.",
          "precondition": "What must already be true.",
          "access_before": "network_reach",
          "exploited_condition": "The property of this component the technique relies on.",
          "result": "What the attacker holds afterwards.",
          "access_after": "code_execution",
          "assumptions": ["Something the map does not state that must be true."],
          "control_note": "How the step deals with this component's controls.",
          "leads_to": ["T1059.001"]
        }}
      ]
    }}
  ],
  "convergence_points": ["T1059.001"],
  "branch_points": []
}}
"""


def _parse_llm_json(response_text: str) -> tuple[dict | None, str]:
    """Parse an LLM JSON reply, stripping markdown fences.

    Returns ``(parsed, error)``.  No truncation repair: a partial projection is
    a partial attack path, and silently closing brackets would hand back a
    graph missing steps with no indication that it is incomplete.  The caller
    reports the failure instead.
    """
    text = (response_text or "").strip()
    if not text:
        return None, "empty response"

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning(
            "Projection JSON parse failed at char %d (line %d col %d): %s "
            "| length=%d last_100=%r",
            exc.pos, exc.lineno, exc.colno, exc.msg, len(text), text[-100:],
        )
        return None, f"invalid JSON at line {exc.lineno} col {exc.colno}: {exc.msg}"

    if not isinstance(parsed, dict):
        return None, f"expected a JSON object, got {type(parsed).__name__}"
    return parsed, ""


def _format_components(flow_map: dict[str, Any]) -> str:
    """Compact component table for the prompt."""
    zones = flow_map["zones"]
    lines = []
    for component in flow_map["components"].values():
        trust = zones.get(component["zone"], {}).get("trust_level", "unzoned")
        bits = [
            f"  {component['id']} | {component['name']} | {component['type']}",
            f"exposure={component['exposure']}",
            f"zone={component['zone'] or '-'}({trust})",
        ]
        if component["authentication"]:
            bits.append(f"auth={component['authentication']}")
        if component["technologies"]:
            bits.append(f"tech={','.join(component['technologies'])}")
        if component["data_classification"]:
            bits.append(f"data={component['data_classification']}")
        if component["controls"]:
            controls = "; ".join(
                f"{c['name']}({c['implementation_status']},"
                f"bypass={c['bypass_difficulty']})"
                for c in component["controls"]
            )
            bits.append(f"controls=[{controls}]")
        else:
            bits.append("controls=[none declared]")
        lines.append(" | ".join(bits))

    if flow_map["crown_jewels"]:
        lines.append(f"  CROWN JEWELS: {', '.join(flow_map['crown_jewels'])}")
    return "\n".join(lines)


def _format_routes(routes: list[dict[str, Any]], flows: list[dict[str, Any]]) -> str:
    """Reachable routes plus the raw flow list, so the model can see the graph."""
    lines = []
    if routes:
        for route in routes[:12]:
            lines.append(
                f"  {' -> '.join(route['route'])}  "
                f"({route['hops']} hops, "
                f"{route['boundary_crossings']} boundary crossing(s), "
                f"{route['unauthenticated_hops']} unauthenticated hop(s))"
            )
    else:
        lines.append("  (no route from an entry point to a crown jewel)")

    lines.append("  DECLARED FLOWS:")
    for flow in flows:
        arrow = "<->" if flow["bidirectional"] else "->"
        auth = "authenticated" if flow["authenticated"] else "UNAUTHENTICATED"
        proto = flow["protocol"] or "?"
        lines.append(f"    {flow['from']} {arrow} {flow['to']} ({proto}, {auth})")
    return "\n".join(lines)


def _format_techniques(
    techniques: list[dict[str, Any]],
    software_techniques: list[dict[str, Any]],
) -> tuple[str, int]:
    """Group the closed set by tactic for the prompt, core techniques first.

    Provenance is shown inline so the model can prefer what the actor is
    documented doing over what its tooling merely implements.
    """
    entries: list[tuple[str, str, str]] = []  # (tactic, technique_id, line)

    def _push(technique: dict[str, Any], label: str) -> None:
        for raw_tactic in technique["tactics"] or ["Unknown"]:
            tactic = canonical_tactic(raw_tactic) or raw_tactic
            entries.append((
                tactic,
                technique["technique_id"],
                f"  {technique['technique_id']}  "
                f"{technique['name'] or '(unnamed)'}  [{label}]",
            ))

    kept = 0
    for technique in techniques:
        if kept >= MAX_TECHNIQUES_IN_PROMPT:
            break
        _push(technique, "documented")
        kept += 1
    for technique in software_techniques:
        if kept >= MAX_TECHNIQUES_IN_PROMPT:
            break
        tools = ", ".join(s["name"] or s["id"] for s in technique["software"][:3])
        _push(technique, f"via {tools}" if tools else "via actor tooling")
        kept += 1

    by_tactic: dict[str, list[str]] = {}
    for tactic, _tid, line in entries:
        by_tactic.setdefault(tactic, []).append(line)

    blocks = []
    for tactic in sorted(by_tactic, key=lambda t: (tactic_ordinal(t), t)):
        blocks.append(tactic.upper())
        blocks.extend(sorted(set(by_tactic[tactic])))
    return "\n".join(blocks), kept


def _build_projection_prompt(
    actor_label: str,
    techniques: list[dict[str, Any]],
    software_techniques: list[dict[str, Any]],
    flow_map: dict[str, Any],
    routes: list[dict[str, Any]],
    objective: str,
    max_paths: int,
) -> tuple[str, int]:
    technique_block, listed = _format_techniques(techniques, software_techniques)
    objective_block = (
        f"ANALYST'S STATED CONCERN: {objective}\nWeight paths toward it.\n"
        if objective else ""
    )
    prompt = PROJECTION_PROMPT.format(
        actor_label=actor_label,
        tactic_names=", ".join(TACTIC_ORDER),
        application=flow_map["application"],
        application_description=flow_map["description"] or "",
        components_table=_format_components(flow_map),
        routes_block=_format_routes(routes, flow_map["flows"]),
        technique_block=technique_block,
        objective_block=objective_block,
        max_paths=max_paths,
        access_states=", ".join(ACCESS_STATES),
    )
    return prompt, listed


# ---------------------------------------------------------------------------
# Phase C — validate the model's placement against the closed set
# ---------------------------------------------------------------------------

# A step whose tactic regresses more than this many kill-chain positions from
# the previous step is flagged. Real chains loop — Lateral Movement back to
# Discovery, C2 back to Credential Access — so small regressions are normal. A
# large one means a late-stage action landed before the work that enables it.
TACTIC_REGRESSION_THRESHOLD = 6


def _closest_tactic(candidates: list[str], previous_ordinal: int) -> str:
    """Pick the candidate tactic that best continues the kill chain.

    Prefers the earliest candidate at or after the previous step's position so
    a corrected step carries the chain forward; otherwise the candidate nearest
    to it.
    """
    ranked = sorted(candidates, key=tactic_ordinal)
    if previous_ordinal:
        # Initial Access is the entry point by definition. Past the first step
        # it is never the right correction while anything else is available —
        # otherwise correcting a mid-chain step would introduce a second entry.
        narrowed = [t for t in ranked if t != "Initial Access"]
        if narrowed:
            ranked = narrowed
    forward = [t for t in ranked if tactic_ordinal(t) >= previous_ordinal]
    if forward:
        return forward[0]
    return min(ranked, key=lambda t: abs(tactic_ordinal(t) - previous_ordinal))


def _resolve_step_tactic(
    raw_tactic: str,
    technique_tactics: list[str],
    previous_ordinal: int = 0,
) -> tuple[str, str]:
    """Normalise a step's tactic, correcting it where ATT&CK is unambiguous.

    Returns ``(tactic, note)``; note is '' when the model's label was right.

    A technique's documented tactics are ground truth: every technique in the
    lookup carries at least one and 79% carry exactly one, so a mismatch is
    usually correctable rather than merely detectable. Correcting beats
    rejecting — the placement is typically sound even when the label is not
    ("T1190 / Impact" on an internet-facing app is the right technique with the
    wrong word), and dropping the step would split the graph at that point and
    strand the edges either side of it.
    """
    claimed = (raw_tactic or "").strip()
    canonical = canonical_tactic(claimed)

    # A retired name (pre-v19 "Defense Evasion") the technique can resolve.
    if canonical is None:
        resolved = resolve_legacy_tactic(claimed, technique_tactics)
        if resolved:
            return resolved, f"retired tactic {claimed!r} mapped to {resolved!r}"

    if canonical is not None and canonical in technique_tactics:
        # A label the technique carries is normally right. "Initial Access" past
        # the first step is the exception: the entry has already happened, so
        # presenting a stolen credential to an internal component is not initial
        # access. Two live runs labelled T1078 that way, each earning two
        # sequence warnings for what is really a wording problem.
        if (
            canonical == "Initial Access"
            and previous_ordinal
            and len(technique_tactics) > 1
        ):
            chosen = _closest_tactic(technique_tactics, previous_ordinal)
            if chosen != "Initial Access":
                return chosen, (
                    f"tactic 'Initial Access' after the first step corrected to "
                    f"{chosen!r}, which ATT&CK also documents for this technique "
                    f"— the entry point is earlier in the path"
                )
        return canonical, ""

    if not technique_tactics:
        return canonical or claimed, f"unrecognised tactic {claimed!r}"

    if len(technique_tactics) == 1:
        only = technique_tactics[0]
        return only, (
            f"tactic {claimed!r} corrected to {only!r}, the only tactic ATT&CK "
            f"documents for this technique"
        )

    chosen = _closest_tactic(technique_tactics, previous_ordinal)
    return chosen, (
        f"tactic {claimed!r} is not one this technique carries "
        f"({', '.join(technique_tactics)}); using {chosen!r}"
    )


# ---------------------------------------------------------------------------
# Step state — what the attacker holds between steps (Phase 3c)
#
# A path of technique -> component pairs does not say how one step leads to the
# next. The model states each step's access before and after from a fixed
# vocabulary, and Phase C checks the chain is continuous. The check proves
# consistency, not truth: the assumptions carry the claims a person tests.
# ---------------------------------------------------------------------------

ACCESS_STATES = (
    "none", "network_reach", "code_execution", "user_credential",
    "service_credential", "privileged", "data_access",
)

# Held on one component: execution on the portal is not execution on the API.
# Credentials are portable — a token taken on one host works wherever a flow
# reaches.
COMPONENT_SCOPED_STATES = frozenset({
    "network_reach", "code_execution", "privileged", "data_access",
})

# A stronger foothold on a component implies the weaker ones there.
_STATE_IMPLIES = {
    "privileged": {"code_execution", "network_reach"},
    "code_execution": {"network_reach"},
    "data_access": {"network_reach"},
}

# Execution on a component lets the attacker reach its declared flow targets.
_REACH_GRANTING_STATES = frozenset({"code_execution", "privileged"})

# Unambiguous synonyms a model is likely to use. Anything else is not guessed.
_ACCESS_ALIASES = {
    "no_access": "none",
    "unauthenticated": "none",
    "network": "network_reach",
    "network_access": "network_reach",
    "reach": "network_reach",
    "execution": "code_execution",
    "code_exec": "code_execution",
    "command_execution": "code_execution",
    "rce": "code_execution",
    "shell": "code_execution",
    "user_session": "user_credential",
    "user_credentials": "user_credential",
    "service_credentials": "service_credential",
    "service_account": "service_credential",
    "api_token": "service_credential",
    "admin": "privileged",
    "administrator": "privileged",
    "root": "privileged",
    "data": "data_access",
}

MAX_ASSUMPTIONS = 3

# What makes a step's state reviewable. A step missing any of these is kept —
# dropping it would strand its edges — and its continuity may go unchecked.
_STEP_STATE_FIELDS = (
    "precondition", "access_before", "result", "access_after", "assumptions",
)

_CITATION = re.compile(r"\(Citation:[^)]*\)")


def _normalize_access_state(value: Any) -> tuple[str | None, str | None]:
    """Map a reply's access state onto the vocabulary: ``(state, unrecognised)``."""
    if value is None:
        return None, None
    text = re.sub(r"[\s\-]+", "_", str(value).strip().lower())
    if not text:
        return None, None
    if text in ACCESS_STATES:
        return text, None
    if text in _ACCESS_ALIASES:
        return _ACCESS_ALIASES[text], None
    return None, str(value)


def _read_step_state(
    raw_step: dict[str, Any], location: str, warnings: list[dict[str, str]]
) -> dict[str, Any]:
    """The model's account of one step's state, normalized. Never raises."""
    def text(key: str) -> str:
        return " ".join(str(raw_step.get(key, "") or "").split())

    state: dict[str, Any] = {
        key: text(key)
        for key in ("precondition", "exploited_condition", "result", "control_note")
    }

    raw_assumptions = raw_step.get("assumptions") or []
    if isinstance(raw_assumptions, str):
        raw_assumptions = [raw_assumptions]
    assumptions = (
        [" ".join(str(a).split()) for a in raw_assumptions if str(a).strip()]
        if isinstance(raw_assumptions, list) else []
    )
    if len(assumptions) > MAX_ASSUMPTIONS:
        warnings.append(_issue(
            "ASSUMPTIONS_TRUNCATED",
            f"{len(assumptions)} assumptions given; kept the first {MAX_ASSUMPTIONS}.",
            location,
        ))
        assumptions = assumptions[:MAX_ASSUMPTIONS]
    state["assumptions"] = assumptions

    for key in ("access_before", "access_after"):
        value, unrecognised = _normalize_access_state(raw_step.get(key))
        if unrecognised:
            warnings.append(_issue(
                "ACCESS_STATE_UNKNOWN",
                f"{key} {unrecognised!r} is not one of: {', '.join(ACCESS_STATES)}; "
                f"treated as missing.",
                location,
            ))
        state[key] = value

    missing = [key for key in _STEP_STATE_FIELDS if not state.get(key)]
    if missing:
        warnings.append(_issue(
            "MISSING_STEP_STATE", f"Step omits {', '.join(missing)}.", location
        ))
    return state


class _HeldState:
    """What the attacker holds along one path. Access accumulates."""

    def __init__(
        self, entry_ids: set[str], adjacency: dict[str, list[str]]
    ) -> None:
        self._portable: set[str] = {"none"}
        self._scoped: dict[str, set[str]] = {c: {"network_reach"} for c in entry_ids}
        self._adjacency = adjacency

    def _on(self, component: str) -> set[str]:
        held = set(self._scoped.get(component, set()))
        for state in list(held):
            held |= _STATE_IMPLIES.get(state, set())
        return held

    def holds(self, state: str, component: str) -> bool:
        if state not in COMPONENT_SCOPED_STATES:
            return state in self._portable
        if state in self._on(component):
            return True
        if state == "network_reach":
            return any(
                component in self._adjacency.get(source, [])
                and self._on(source) & _REACH_GRANTING_STATES
                for source in self._scoped
            )
        return False

    def add(self, state: str, component: str) -> None:
        if state in COMPONENT_SCOPED_STATES:
            self._scoped.setdefault(component, set()).add(state)
        else:
            self._portable.add(state)

    def describe(self) -> str:
        parts = sorted(s for s in self._portable if s != "none")
        parts += sorted(
            f"{state} on {component}"
            for component, states in self._scoped.items() for state in states
        )
        if not parts:
            return "nothing"
        more = f", +{len(parts) - 6} more" if len(parts) > 6 else ""
        return ", ".join(parts[:6]) + more

    def sources_reaching(self, component: str) -> list[str]:
        """Components with a declared flow to *component* where something is held."""
        return sorted(
            source for source in self._scoped
            if source != component and component in self._adjacency.get(source, [])
        )

    def describe_for(self, component: str) -> str:
        """What is held that bears on reaching *component*.

        The full list names reach on every exposed component, which for a gap
        deep in a path is noise. What a reader needs is what is held here, and
        what is held on the components with a declared flow to here.
        """
        relevant = [component] + self.sources_reaching(component)
        parts = sorted(s for s in self._portable if s != "none")
        parts += sorted(
            f"{state} on {name}"
            for name in relevant for state in self._scoped.get(name, set())
        )
        if not parts:
            return "nothing that bears on it"
        more = f", +{len(parts) - 6} more" if len(parts) > 6 else ""
        return ", ".join(parts[:6]) + more


def _step_transition(
    previous: str,
    component_id: str,
    flow: dict[str, Any] | None,
    components: dict[str, dict[str, Any]],
    return_hop: bool = False,
) -> dict[str, Any] | None:
    """How the attacker arrived at this step, from the map — never the reply.

    A return hop names the flow the path arrived on, read backwards, and says
    so: the reader should see that the step came back over a connection this
    path opened rather than over a flow declared in that direction.
    """
    if not previous:
        return {"entry": True, "exposure": components[component_id]["exposure"]}
    if flow is None:
        return None
    transition = {
        "flow": flow["id"],
        "from": previous,
        "to": component_id,
        "protocol": flow["protocol"],
        "authenticated": flow["authenticated"],
        "crosses_boundary": flow["crosses_boundary"],
    }
    if return_hop:
        transition["return"] = True
    return transition


def _controls_in_play(
    component: dict[str, Any], flow: dict[str, Any] | None
) -> list[dict[str, str]]:
    """Controls on the component and on the flow the step arrived over."""
    in_play = [
        {
            "name": c["name"],
            "control_type": c["control_type"],
            "status": c["implementation_status"],
            "on": "component",
        }
        for c in component["controls"]
    ]
    if flow:
        in_play += [
            {
                "name": c["name"],
                "control_type": c["control_type"],
                "status": c["implementation_status"],
                "on": f"flow {flow['id']}",
            }
            for c in flow["controls"]
        ]
    return in_play


def _procedure_index(
    actor_id: str, software_ids: set[str], technique_ids: set[str]
) -> dict[str, dict[str, str]]:
    """The first ATT&CK procedure example per technique, for this actor or its tooling.

    One scan of the procedure list per invocation, as _procedures_for_sources
    does. The actor's own example is preferred over its software's, since it is
    the stronger claim.
    """
    index: dict[str, dict[str, str]] = {}
    for procedure in get_mitre_relationships().get("procedures", []):
        technique = procedure.get("technique")
        source = procedure.get("source")
        if technique not in technique_ids:
            continue
        if actor_id and source == actor_id:
            if index.get(technique, {}).get("by") != "actor":
                index[technique] = {
                    "source": source, "text": procedure.get("text", ""), "by": "actor",
                }
        elif source in software_ids and technique not in index:
            index[technique] = {
                "source": source, "text": procedure.get("text", ""), "by": "software",
            }
    return index


def _excerpt(text: str, limit: int = 200) -> str:
    """A procedure example trimmed for display, citations removed."""
    text = " ".join(_CITATION.sub("", text or "").split())
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


def _describe_transition(transition: dict[str, Any] | None) -> str:
    """One line for a report: how the attacker arrived at the step."""
    if not transition:
        return ""
    if transition.get("entry"):
        return f"entry point ({transition['exposure']}-exposed)"
    auth = "authenticated" if transition["authenticated"] else "unauthenticated"
    protocol = f"{transition['protocol']}, " if transition.get("protocol") else ""
    direction = "back over flow" if transition.get("return") else "flow"
    return (
        f"{direction} {transition['flow']}: {transition['from']} -> "
        f"{transition['to']} ({protocol}{auth})"
    )


def _describe_gap(needed: str, component_id: str, held: _HeldState) -> str:
    """Why a step's access_before is not held, in terms a reader can act on.

    Three gaps read alike and mean different things. Needing access on a
    component nothing earlier touches is the skipped bridge the check was built
    for. Needing it on a component the attacker can only talk to — over a
    declared flow, holding no control of the component at the other end — is
    the path leaning on that component to act for the attacker, which is a
    question to ask rather than a missing step. Needing a stronger foothold
    somewhere already reached is a missing step again, but a different one.
    """
    holdings = held.describe_for(component_id)
    if needed not in COMPONENT_SCOPED_STATES:
        return f"needs {needed}; no earlier step yields one. Path holds {holdings}"

    if held.holds("network_reach", component_id):
        return (
            f"needs {needed} on {component_id}; the path reaches it but no "
            f"earlier step takes {needed} there. Path holds {holdings}"
        )

    talking = held.sources_reaching(component_id)
    if talking:
        named = ", ".join(talking[:3])
        return (
            f"needs {needed} on {component_id}; the declared flow to it comes "
            f"from {named}, which no earlier step takes control of, so the path "
            f"depends on {named} acting for the attacker. Path holds {holdings}"
        )
    return (
        f"needs {needed} on {component_id}; no earlier step reaches it. "
        f"Path holds {holdings}"
    )


def _describe_state_check(step: dict[str, Any]) -> str:
    status = step.get("state_check", "")
    note = step.get("state_note", "")
    return f"{status} — {note}" if status and note else status


def _control_tagging(
    components: dict[str, dict[str, Any]], paths: list[dict[str, Any]]
) -> dict[str, Any]:
    """How far a step's uncovered-mitigation list can be trusted.

    Uncovered mitigations are diffed against the mitre_mitigation_id values on
    the step's own component. A control with no id can never cover anything, so
    read without these counts the gap list overstates what is missing.
    """
    targeted = sorted({s["component_id"] for p in paths for s in p["steps"]})
    controls = [c for cid in targeted for c in components[cid]["controls"]]
    return {
        "targeted_components": targeted,
        "control_count": len(controls),
        "tagged_control_count": sum(1 for c in controls if c["mitre_mitigation_id"]),
        "components_without_controls": [
            cid for cid in targeted if not components[cid]["controls"]
        ],
    }


def _validate_projection(
    parsed: dict[str, Any],
    core_ids: set[str],
    software_ids: set[str],
    flow_map: dict[str, Any],
    entry_ids: set[str],
    procedures: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Reject placements the closed set and the flow map do not support.

    Technique and component violations are rejections: a technique outside the
    closed set is exactly what the set exists to prevent, and a component that
    is not in the map cannot be reasoned about at all. Tactic problems and
    unsupported hops are warnings recorded on the step — the placement may be
    right even when the label is not.
    """
    database = get_mitre_db()
    components = flow_map["components"]
    allowed = core_ids | software_ids

    adjacency, edges = _build_adjacency(flow_map["flows"])

    rejections: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    clean_paths: list[dict[str, Any]] = []
    mappings: dict[tuple[str, str], dict[str, Any]] = {}

    for path_index, raw_path in enumerate(parsed.get("paths") or []):
        if not isinstance(raw_path, dict):
            rejections.append(_issue(
                "PATH_NOT_OBJECT", "Path is not an object.", f"paths[{path_index}]"
            ))
            continue

        path_id = str(raw_path.get("path_id", "") or f"path-{path_index + 1}")
        steps: list[dict[str, Any]] = []
        previous_component = ""
        previous_ordinal = 0
        held = _HeldState(entry_ids, adjacency)
        # Hops this path actually made over declared flows. Going back the way
        # it came is a connection the attacker opened and can defend; landing
        # somewhere the path never travelled from is a jump, and stays flagged.
        traversed: set[tuple[str, str]] = set()
        # Once a step omits what it yields, later gaps may be artefacts of the
        # omission rather than real — so later steps go unchecked, not flagged.
        chain_known = True

        for step_index, raw_step in enumerate(raw_path.get("steps") or []):
            location = f"{path_id}.steps[{step_index}]"
            if not isinstance(raw_step, dict):
                rejections.append(_issue(
                    "STEP_NOT_OBJECT", "Step is not an object.", location
                ))
                continue

            technique_id = str(raw_step.get("technique_id", "") or "").strip()
            component_id = str(raw_step.get("component_id", "") or "").strip()

            if technique_id not in allowed:
                rejections.append(_issue(
                    "TECHNIQUE_NOT_IN_SET",
                    f"{technique_id or '(missing)'} is not in the actor's "
                    f"documented technique set.",
                    location,
                ))
                continue
            if component_id not in components:
                rejections.append(_issue(
                    "COMPONENT_NOT_IN_FLOW_MAP",
                    f"{component_id or '(missing)'} is not a component of this "
                    f"application.",
                    location,
                ))
                continue

            entry = database.get(technique_id, {})
            technique_tactics = list(entry.get("tactics", []))
            tactic, tactic_note = _resolve_step_tactic(
                str(raw_step.get("tactic", "") or ""),
                technique_tactics,
                previous_ordinal,
            )

            notes: list[str] = []
            if tactic_note:
                notes.append(tactic_note)
                warnings.append(_issue("TACTIC_CORRECTED", tactic_note, location))

            # Sequence checks. Unlike a technique outside the closed set, a step
            # in the wrong position is not repairable by overwriting a field —
            # but rejecting it would strand the edges either side, so it is
            # flagged loudly and left for the analyst to judge.
            ordinal = tactic_ordinal(tactic)
            regression = previous_ordinal - ordinal
            # Same component only. A kill chain restarts per host: arriving at
            # the next component and doing early-stage work there is ordinary,
            # not a late-stage action placed before its enabler. Volt Typhoon
            # proxies from the entry host (C2, position 14) and then presents
            # the stolen token on the next one (Stealth, 7), which read as a
            # 7-position regression until this was scoped. A second entry point
            # is caught by LATE_INITIAL_ACCESS, which ignores components.
            if (
                previous_ordinal
                and component_id == previous_component
                and regression > TACTIC_REGRESSION_THRESHOLD
            ):
                note = (
                    f"{tactic} regresses {regression} kill-chain positions from "
                    f"the previous step on {component_id} — a late-stage action "
                    f"placed before the work that enables it"
                )
                notes.append(note)
                warnings.append(_issue("KILL_CHAIN_REGRESSION", note, location))

            if steps and tactic == "Initial Access":
                note = (
                    "Initial Access after the first step, but access was already "
                    "gained upstream"
                )
                notes.append(note)
                warnings.append(_issue("LATE_INITIAL_ACCESS", note, location))

            if not steps and component_id not in entry_ids:
                note = (
                    f"path starts on '{component_id}', which is not "
                    f"externally exposed"
                )
                notes.append(note)
                warnings.append(_issue("ENTRY_NOT_EXPOSED", note, location))

            return_hop = False
            if previous_component and component_id != previous_component:
                if component_id in adjacency.get(previous_component, []):
                    traversed.add((previous_component, component_id))
                elif (component_id, previous_component) in traversed:
                    # Back the way it came: the attacker holds the component it
                    # left and the data returns over the connection they opened.
                    # One reverse hop along an edge this path travelled, which a
                    # reader can defend — not an arrival somewhere new.
                    return_hop = True
                else:
                    note = (
                        f"no declared flow from '{previous_component}' to "
                        f"'{component_id}'"
                    )
                    notes.append(note)
                    warnings.append(_issue("HOP_NOT_DECLARED", note, location))

            # Step state. The model's account of what the attacker holds is
            # checked against what earlier steps gave them. A gap is flagged,
            # never rejected: it usually means a missing bridge step, and
            # rejecting would strand the edges either side.
            state = _read_step_state(raw_step, location, warnings)
            if not chain_known:
                state_check = "unchecked"
                state_note = "an earlier step omitted its access_after"
            elif state["access_before"] is None:
                state_check = "unchecked"
                state_note = "step omits access_before"
            elif held.holds(state["access_before"], component_id):
                state_check, state_note = "ok", ""
            else:
                state_check = "gap"
                state_note = _describe_gap(
                    state["access_before"], component_id, held
                )
                notes.append(f"state gap: {state_note}")
                warnings.append(_issue("STATE_GAP", state_note, location))
                # Report the gap once, not again on every later step.
                held.add(state["access_before"], component_id)
            if state["access_after"] is None:
                chain_known = False
            else:
                held.add(state["access_after"], component_id)

            flow = None
            if previous_component and previous_component != component_id:
                flow = edges.get((previous_component, component_id))
                if flow is None and return_hop:
                    # The flow they arrived on, read backwards.
                    flow = edges.get((component_id, previous_component))

            # Evidence is derived, never taken from the model — it cannot be
            # trusted to label the strength of its own source. actor_support
            # refines it from ATT&CK's procedure examples, by the same rule.
            evidence = "documented" if technique_id in core_ids else "via_software"
            procedure = (procedures or {}).get(technique_id)
            if evidence == "via_software":
                actor_support = "via_software"
            elif procedure and procedure["by"] == "actor":
                actor_support = "procedure_documented"
            else:
                actor_support = "technique_documented"
                # A tooling procedure beside "technique_documented" would read
                # as the actor's own behaviour; show only what matches the label.
                procedure = None

            mitigations = mitigations_for_technique(technique_id)
            declared = {
                c["mitre_mitigation_id"]
                for c in components[component_id]["controls"]
                if c["mitre_mitigation_id"]
            }

            steps.append({
                "technique_id": technique_id,
                "technique_name": entry.get("name", ""),
                "tactic": tactic,
                "component_id": component_id,
                "asset": components[component_id]["name"],
                "evidence": evidence,
                "rationale": str(raw_step.get("rationale", "") or ""),
                "leads_to": [
                    str(t).strip() for t in (raw_step.get("leads_to") or [])
                    if str(t).strip()
                ],
                "mitigations": mitigations,
                "uncovered_mitigations": [
                    m for m in mitigations if m not in declared
                ],
                "notes": notes,
                # From the model, checked for continuity:
                "precondition": state["precondition"],
                "access_before": state["access_before"],
                "exploited_condition": state["exploited_condition"],
                "result": state["result"],
                "access_after": state["access_after"],
                "assumptions": state["assumptions"],
                "control_note": state["control_note"],
                # From the map and ATT&CK, never from the reply:
                "transition": _step_transition(
                    previous_component, component_id, flow, components,
                    return_hop=return_hop,
                ),
                "controls_in_play": _controls_in_play(components[component_id], flow),
                "actor_support": actor_support,
                "procedure_excerpt": _excerpt(procedure["text"]) if procedure else "",
                "state_check": state_check,
                "state_note": state_note,
            })
            previous_component = component_id
            previous_ordinal = ordinal

            key = (technique_id, tactic)
            if key not in mappings:
                mappings[key] = {
                    "technique_id": technique_id,
                    "technique_name": entry.get("name", ""),
                    "tactic": tactic,
                    "confidence": "high" if evidence == "documented" else "medium",
                }

        if not steps:
            rejections.append(_issue(
                "PATH_EMPTY",
                f"Path '{path_id}' had no step survive validation.",
                f"paths[{path_index}]",
            ))
            continue

        # Drop leads_to targets that are not techniques in this path.
        present = {s["technique_id"] for s in steps}
        for step in steps:
            dropped = [t for t in step["leads_to"] if t not in present]
            if dropped:
                warnings.append(_issue(
                    "DANGLING_LEADS_TO",
                    f"Dropped leads_to target(s) not in path '{path_id}': "
                    f"{', '.join(dropped)}.",
                    path_id,
                ))
            step["leads_to"] = [t for t in step["leads_to"] if t in present]

        clean_paths.append({
            "path_id": path_id,
            "description": str(raw_path.get("description", "") or ""),
            "objective": str(raw_path.get("objective", "") or ""),
            "steps": steps,
        })

    kept_ids = {s["technique_id"] for p in clean_paths for s in p["steps"]}
    return {
        "attack_graph": {
            "paths": clean_paths,
            "convergence_points": [
                t for t in (parsed.get("convergence_points") or [])
                if isinstance(t, str) and t in kept_ids
            ],
            "branch_points": [
                t for t in (parsed.get("branch_points") or [])
                if isinstance(t, str) and t in kept_ids
            ],
        },
        "mitre_mappings": [mappings[k] for k in sorted(mappings)],
        "rejections": rejections,
        "warnings": warnings,
        "control_tagging": _control_tagging(components, clean_paths),
    }


# ---------------------------------------------------------------------------
# Scenario seed — one scenario per path, for threat_model_analyzer
# ---------------------------------------------------------------------------

# Access level a tactic typically requires and confers. Used to fill
# AttackEvent.required_access / resulting_access deterministically.
#
# Must cover every entry in TACTIC_ORDER — a missing tactic falls through to
# the default and reports "none" access mid-chain, which reads as an
# unauthenticated step and is wrong. A contract test asserts the coverage,
# because the gap that motivated it was Stealth and Defense Impairment: the two
# tactics ATT&CK v19 introduced, and so the two most likely to appear.
_ACCESS_BY_TACTIC: dict[str, tuple[str, str]] = {
    "Reconnaissance": ("none", "none"),
    "Resource Development": ("none", "none"),
    "Initial Access": ("none", "user"),
    "Execution": ("user", "user"),
    "Persistence": ("user", "user"),
    "Privilege Escalation": ("user", "admin"),
    "Stealth": ("user", "user"),
    "Defense Impairment": ("admin", "admin"),
    "Evasion": ("user", "user"),  # ICS
    "Credential Access": ("user", "credentials"),
    "Discovery": ("user", "user"),
    "Lateral Movement": ("user", "user"),
    "Collection": ("user", "data"),
    "Command and Control": ("user", "user"),
    "Inhibit Response Function": ("admin", "admin"),  # ICS
    "Impair Process Control": ("admin", "admin"),  # ICS
    "Exfiltration": ("data", "data"),
    "Impact": ("admin", "admin"),
}

# For a tactic string that is not canonical at all. Never ("none", "none"):
# an unrecognised tactic is far more likely mid-chain than at the entry point,
# and claiming no access required there understates the step.
_ACCESS_FALLBACK = ("user", "user")


def _build_scenario_seeds(
    actor_label: str,
    flow_map: dict[str, Any],
    attack_graph: dict[str, Any],
) -> list[dict[str, Any]]:
    """One scenario per path, shaped for threat_model_analyzer's dataclasses.

    AttackEvent.sequence_order is a linear integer and a projection is a graph,
    so flattening every path into one scenario would misrepresent the branching.
    One scenario per path keeps each sequence honest.
    """
    controls: list[dict[str, Any]] = []

    def _add_control(control: dict[str, Any], default_description: str) -> None:
        controls.append({
            "control_id": f"SC-{len(controls) + 1:04d}",
            "name": control["name"],
            "control_type": control["control_type"] or "application",
            "description": control["description"] or default_description,
            "implementation_status": control["implementation_status"],
            "bypass_difficulty": control["bypass_difficulty"],
            "bypass_requirements": control["bypass_requirements"],
            "detection_capability": control["detection_capability"],
        })

    # Every control the map declares, not only per-component ones: gap analysis
    # answers "is there a control at all", and a dropped estate-wide control
    # would read as absent.
    for component in flow_map["components"].values():
        for control in component["controls"]:
            _add_control(
                control, f"Protects {component['name']} ({component['id']})."
            )
    for flow in flow_map.get("flows", []):
        for control in flow["controls"]:
            _add_control(
                control,
                f"Protects flow {flow['id']} ({flow['from']} -> {flow['to']}).",
            )
    for control in flow_map.get("controls", []):
        _add_control(control, "Estate-wide control, not tied to one component.")

    seeds = []
    for path in attack_graph["paths"]:
        events = []
        for order, step in enumerate(path["steps"], start=1):
            component = flow_map["components"][step["component_id"]]
            blocking, detecting = [], []
            for control in component["controls"]:
                name = control["name"]
                if control["implementation_status"] != "implemented":
                    continue
                if control["control_type"] in PREVENTIVE_LAYERS:
                    blocking.append(name)
                if control["detection_capability"] in ("medium", "high"):
                    detecting.append(name)

            # The model's stated access when it gave both ends, since that is
            # what the continuity check examined; the tactic table otherwise.
            if step.get("access_before") and step.get("access_after"):
                required, resulting = step["access_before"], step["access_after"]
                access_source = "model"
            else:
                required, resulting = _ACCESS_BY_TACTIC.get(
                    step["tactic"], _ACCESS_FALLBACK
                )
                access_source = "tactic_table"
            events.append({
                "event_id": f"AE-{order:04d}",
                "name": (
                    f"{step['technique_name'] or step['technique_id']} "
                    f"on {component['name']}"
                ),
                "description": step["rationale"],
                "sequence_order": order,
                "target_asset": component["name"],
                "attack_technique": step["technique_name"],
                "technique_id": step["technique_id"],
                "tactic": step["tactic"],
                "evidence": step["evidence"],
                "required_access": required,
                "resulting_access": resulting,
                "access_source": access_source,
                "blocking_controls": blocking,
                "detecting_controls": detecting,
                "success_indicators": [step["result"]] if step.get("result") else [],
                "precondition": step.get("precondition", ""),
                "exploited_condition": step.get("exploited_condition", ""),
                "assumptions": list(step.get("assumptions", [])),
                "control_note": step.get("control_note", ""),
                "transition": _describe_transition(step.get("transition")),
                "actor_support": step.get("actor_support", ""),
                "procedure_excerpt": step.get("procedure_excerpt", ""),
                "state_check": _describe_state_check(step),
            })

        seeds.append({
            "path_id": path["path_id"],
            "name": f"{actor_label} vs {flow_map['application']}: {path['path_id']}",
            "description": path["description"],
            "source_type": "actor_projection",
            "threat_actor_profile": actor_label,
            "attack_objective": path["objective"],
            "target_assets": sorted({
                flow_map["components"][s["component_id"]]["name"]
                for s in path["steps"]
            }),
            "entry_vectors": [path["steps"][0]["component_id"]],
            "security_controls": controls,
            "attack_sequence": events,
        })
    return seeds


# ---------------------------------------------------------------------------
# Run-group summary (Phase 3b)
#
# Projection is sampled, so one run cannot tell a finding from a one-off. A
# group of runs over the same map can — but only if near-duplicates of one
# route are collapsed: four flavours of vanilla is not four findings. Routes
# are counted, and each recurring one is shown through the single variant most
# typical of those seen.
# ---------------------------------------------------------------------------

# Below this, a group is too small for "recurs" to mean anything; routes are
# still listed with their counts, and nothing is called recurring.
MIN_RUNS_FOR_RECURRENCE = 3


# Pre-intrusion tactics: work done before, or without, a foothold. A step like
# Reconnaissance against a CDN compromises nothing and moves the attacker
# nowhere, so counting the component as part of the route splits one recurring
# route in two — which is what a live six-run group did, reporting
# cdn -> portal -> claims_api -> doc_store as distinct from
# portal -> claims_api -> doc_store.
PRE_INTRUSION_TACTICS = frozenset({"Reconnaissance", "Resource Development"})


def _route_signature(path: dict[str, Any]) -> tuple[str, ...]:
    """The components a path takes a foothold on, consecutive repeats collapsed.

    Route identity is the way through the architecture, not the prose and not
    the exact technique list: two runs that enter at the portal, work through
    the API and read the document store found the same way in, even when they
    choose different techniques along it.

    Pre-intrusion steps are skipped — see PRE_INTRUSION_TACTICS. They stay in
    the representative variant's steps, where a reader can see them; they just
    do not decide which route a path is.
    """
    route: list[str] = []
    for step in path.get("steps", []):
        if str(step.get("tactic", "") or "") in PRE_INTRUSION_TACTICS:
            continue
        component = str(step.get("component_id", "") or "")
        if component and (not route or route[-1] != component):
            route.append(component)
    return tuple(route)


def _pair_set(path: dict[str, Any]) -> set[tuple[str, str]]:
    """(component, technique) pairs in a path — what recurrence is keyed on.

    Never prose: descriptions and rationales vary between runs by design, and
    comparing them would make every run look unique.
    """
    return {
        (str(s.get("component_id", "") or ""), str(s.get("technique_id", "") or ""))
        for s in path.get("steps", [])
        if s.get("technique_id")
    }


def _jaccard(left: set[Any], right: set[Any]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _representative_index(variants: list[dict[str, Any]]) -> int:
    """The variant most typical of the ones seen.

    Highest mean overlap with the other variants on (component, technique)
    pairs. Ties go to the earliest run, so the same corpus always names the
    same representative.
    """
    if len(variants) == 1:
        return 0
    pairs = [_pair_set(v["path"]) for v in variants]
    best_index, best_score = 0, -1.0
    for index, own in enumerate(pairs):
        others = [p for position, p in enumerate(pairs) if position != index]
        score = sum(_jaccard(own, other) for other in others) / len(others)
        if score > best_score:
            best_index, best_score = index, score
    return best_index


def _summarize_run_group(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Count routes across a group's records and pick one variant of each.

    Records are expected to share a flow map and an actor; the caller checks
    that, because a group that mixes them is an operator error rather than a
    finding. Failed runs count toward the group's size but contribute no paths:
    they are part of what the group cost, not part of what it found.
    """
    successful = [r for r in records if r.get("sampled")]
    run_total = len(records)

    # Runs are numbered within the group, never by the run_index a record
    # carries: that restarts at 1 in every invocation, so a group built from two
    # batches of three would read 1,2,3,1,2,3 and count six runs as three —
    # under-counting recurrence exactly when a long group is split to stay
    # inside the timeout. The ordinal is for the reader; identity is the record.
    routes: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for ordinal, record in enumerate(successful, start=1):
        for path in record["sampled"].get("paths", []):
            signature = _route_signature(path)
            if not signature:
                continue
            routes.setdefault(signature, []).append({
                "run_index": ordinal,
                "run_id": record["run"].get("run_id", ""),
                "record_file": record["run"].get("record_file", ""),
                "path": path,
            })

    # Half the successful runs, rounded up: a route in two of three recurs.
    threshold = (len(successful) + 1) // 2
    countable = len(successful) >= MIN_RUNS_FOR_RECURRENCE

    summaries: list[dict[str, Any]] = []
    for signature, variants in routes.items():
        runs_with_route = sorted({v["run_index"] for v in variants})
        index = _representative_index(variants)
        chosen = variants[index]
        pairs_per_variant = [_pair_set(v["path"]) for v in variants]
        # A strict majority, not half: with two variants a pair present in one
        # of them is precisely the sampling variance this split exists to show,
        # and calling it stable would leave varying_pairs permanently empty for
        # the commonest group size.
        stable = sorted(
            pair for pair in set().union(*pairs_per_variant)
            if sum(1 for pairs in pairs_per_variant if pair in pairs)
            * 2 > len(variants)
        )
        varying = sorted(set().union(*pairs_per_variant) - set(stable))
        steps = chosen["path"].get("steps", [])
        summaries.append({
            "route": list(signature),
            "runs": runs_with_route,
            "run_count": len(runs_with_route),
            "variant_count": len(variants),
            "recurring": countable and len(runs_with_route) >= threshold,
            "representative": {
                "run_index": chosen["run_index"],
                "record_file": chosen.get("record_file", ""),
                "path_id": chosen["path"].get("path_id", ""),
                "description": chosen["path"].get("description", ""),
                "steps": steps,
            },
            "stable_pairs": [list(pair) for pair in stable],
            "varying_pairs": [list(pair) for pair in varying],
            "assumptions": [
                {"technique_id": s.get("technique_id", ""),
                 "component_id": s.get("component_id", ""),
                 "assumption": assumption}
                for s in steps for assumption in (s.get("assumptions") or [])
            ],
            "state_gaps": sum(1 for s in steps if s.get("state_check") == "gap"),
        })

    # Recurring first, then by how many runs found it, then by route, so the
    # reader meets the findings before the one-offs and the order is stable.
    summaries.sort(
        key=lambda s: (not s["recurring"], -s["run_count"], s["route"])
    )
    return {
        "run_count": run_total,
        "succeeded": len(successful),
        "failed": run_total - len(successful),
        "recurrence_threshold": threshold if countable else None,
        "recurrence_countable": countable,
        "route_count": len(summaries),
        "recurring_route_count": sum(1 for s in summaries if s["recurring"]),
        "routes": summaries,
    }


# ---------------------------------------------------------------------------
# The group report
#
# The JSON summary is the evidence and nobody reads it to a room. The report
# says what recurred, where it ended, and what to go and check. Two rules hold
# it together: every count is expressed out of the runs it came from, and
# nothing is claimed that the records do not carry. Model-written text is
# marked (LLM) wherever it appears.
# ---------------------------------------------------------------------------

MAX_REPORT_ROUTES = 4


def _plural(count: int, singular: str, plural: str = "") -> str:
    """'1 route', '2 routes'. A report handed to someone should not read
    '1 route(s)' — the terminal summaries can, a document cannot."""
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"

# Wording that makes an assumption a question about what we would *see* rather
# than how something is set up. A heuristic for grouping only — an assumption
# in the wrong list is still the same question, asked of the same people.
_DETECTION_WORDS = (
    "detect", "monitor", "alert", "alarm", "anomal", "flag", "logging",
    "logged", "ips", "ids", "edr", "rate-limit", "rate limit", "block",
    "notice", "visib", "scanning",
)


def _is_detection_question(text: str) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in _DETECTION_WORDS)


def _component_names(records: list[dict[str, Any]]) -> dict[str, str]:
    """Component id to display name, from the deterministic block."""
    names: dict[str, str] = {}
    for record in records:
        for entry in (record.get("deterministic") or {}).get("entry_ranking", []):
            component_id = entry.get("component_id", "")
            if component_id and component_id not in names:
                names[component_id] = entry.get("name", "") or component_id
    return names


def _crown_jewel_ids(records: list[dict[str, Any]]) -> set[str]:
    """Crown jewels, read from the routes the deterministic layer computed."""
    jewels: set[str] = set()
    for record in records:
        for route in (record.get("deterministic") or {}).get("routes", []):
            if route.get("target"):
                jewels.add(str(route["target"]))
    return jewels


def _hinge_assumption(route: dict[str, Any]) -> str:
    """The assumption at the end of the route — what reaching the data rests on.

    Chosen by position, never by judging the text: the assumption on the last
    step, else the last one stated. It is the model's sentence, so the report
    marks it.
    """
    assumptions = route.get("assumptions") or []
    if not assumptions:
        return ""
    final_component = route["route"][-1] if route.get("route") else ""
    for entry in reversed(assumptions):
        if entry.get("component_id") == final_component:
            return entry.get("assumption", "")
    return assumptions[-1].get("assumption", "")


def _render_group_report(
    data: dict[str, Any],
    names: dict[str, str],
    jewels: set[str],
    flow_map: dict[str, Any] | None,
    period: tuple[str, str],
) -> str:
    """The readable form of a run group, for someone who will not read JSON."""
    def label(component_id: str) -> str:
        return names.get(component_id, component_id)

    def route_text(route: list[str]) -> str:
        return " → ".join(label(c) for c in route)

    succeeded = data.get("succeeded", 0)
    routes = data.get("routes", [])
    recurring = [r for r in routes if r.get("recurring")]
    components = flow_map["components"] if flow_map else {}

    lines = [
        f"# Projected attack paths — {data.get('application', '?')} vs "
        f"{data.get('actor', '?')}",
        "",
        f"**{PROJECTION_NOTICE}**",
        "",
    ]

    run_line = f"{_plural(data.get('run_count', 0), 'run')}, {succeeded} completed"
    failed = data.get("failed", 0)
    if failed:
        run_line += f", {failed} failed"
    start, end = period
    when = f" between {start} and {end}" if start and end and start != end else (
        f" on {start}" if start else ""
    )
    lines += [
        f"{run_line}{when}, against one unchanged architecture "
        f"(map `{str(data.get('flow_map_sha256', ''))[:12]}`).",
        "",
        "## Bottom line",
        "",
    ]

    if not recurring:
        lines += [
            "No route came back often enough to be called recurring"
            + (
                f", and with {succeeded} successful run(s) recurrence cannot be "
                f"judged at all — {MIN_RUNS_FOR_RECURRENCE} are needed."
                if not data.get("recurrence_countable") else "."
            ),
            "",
        ]
    else:
        reached = sorted({
            r["route"][-1] for r in recurring if r["route"][-1] in jewels
        })
        missed = sorted(j for j in jewels if j not in set(reached))
        strongest = max(recurring, key=lambda r: r["run_count"])

        if reached:
            lines.append(
                f"{_plural(len(recurring), 'route')} came back across the runs, "
                f"ending at {', '.join(label(c) for c in reached)} — "
                f"{'an asset' if len(reached) == 1 else 'assets'} this "
                f"architecture names as a crown jewel."
            )
        else:
            lines.append(
                f"{_plural(len(recurring), 'route')} came back across the runs, "
                f"none of them reaching a crown jewel."
            )
        if reached and missed:
            lines.append("")
            lines.append(
                f"No recurring route reached "
                f"{', '.join(label(c) for c in missed)}."
            )
        lines.append("")
        lines.append(
            f"The strongest is **{route_text(strongest['route'])}**, found in "
            f"{strongest['run_count']} of {succeeded} runs."
        )

        shared = set(recurring[0]["route"])
        for route in recurring[1:]:
            shared &= set(route["route"])
        entries = {r["route"][0] for r in recurring}
        destinations = {r["route"][-1] for r in recurring}
        # Worth saying only when routes converge somewhere in the middle: with
        # one route everything on it is "shared", and its own start and end
        # say nothing.
        passing = sorted(shared - entries - destinations)
        if len(recurring) > 1 and passing:
            lines.append("")
            lines.append(
                f"Every recurring route passes through "
                f"**{', '.join(label(c) for c in passing)}**."
            )
        bare = [
            c for c in sorted({c for r in recurring for c in r["route"]})
            if c in components and not components[c]["controls"]
        ]
        if bare:
            lines.append("")
            lines.append(
                f"The flow map records no security controls on "
                f"{', '.join(label(c) for c in bare)}."
            )
        lines.append("")

    # --- the routes table ---
    lines += ["## The routes", ""]
    lines += [
        "| Route | Found in | Ends at | What reaching the data rests on (LLM) |",
        "|---|---|---|---|",
    ]
    for route in routes[:MAX_REPORT_ROUTES]:
        destination = route["route"][-1]
        ends = label(destination)
        if destination in jewels:
            ends += " — crown jewel"
        classification = (
            components.get(destination, {}).get("data_classification", "")
            if components else ""
        )
        if classification:
            ends += f" ({classification})"
        found = f"{route['run_count']} of {succeeded} runs"
        if not route["recurring"]:
            found += " — one-off"
        lines.append(
            f"| {route_text(route['route'])} | {found} | {ends} | "
            f"{_hinge_assumption(route) or '—'} |"
        )
    if len(routes) > MAX_REPORT_ROUTES:
        lines.append("")
        lines.append(
            f"{_plural(len(routes) - MAX_REPORT_ROUTES, 'further route')} "
            f"in the full result."
        )
    lines.append("")

    # --- the test plan ---
    seen: set[str] = set()
    configuration: list[str] = []
    detection: list[str] = []
    for route in routes:
        for entry in route.get("assumptions") or []:
            text = entry.get("assumption", "").strip()
            if not text or text.lower() in seen:
                continue
            seen.add(text.lower())
            where = label(entry.get("component_id", ""))
            bucket = detection if _is_detection_question(text) else configuration
            bucket.append(f"{text} — *{where}*")

    if configuration or detection:
        lines += [
            "## What we should check",
            "",
            "Each line is something the projection depends on and the flow map "
            "does not state. None has been verified.",
            "",
        ]
        if configuration:
            lines += ["**How things are set up**", ""]
            lines += [f"{i}. {t}" for i, t in enumerate(configuration, start=1)]
            lines.append("")
        if detection:
            lines += ["**What we would see**", ""]
            lines += [f"{i}. {t}" for i, t in enumerate(detection, start=1)]
            lines.append("")

    # --- framing ---
    lines += [
        "## What this is, and is not",
        "",
        f"An LLM placed techniques MITRE ATT&CK documents "
        f"{data.get('actor', 'this actor')} using onto this organization's own "
        f"flow map, {data.get('run_count', 0)} times independently. Technique "
        f"ids, technique names and the architecture are sourced; the routes and "
        f"the step rationales are the model's projection.",
        "",
        f"Repetition is the evidence. A route found once is a suggestion; a "
        f"route found in {data.get('recurrence_threshold') or 'most'} or more "
        f"of {succeeded} runs is a pattern worth testing. This is not an "
        f"observation, not a likelihood assessment, and not a complete list of "
        f"the ways in.",
        "",
    ]
    if not flow_map:
        lines += [
            "No flow map was supplied with this summary, so the report does not "
            "say which controls sit on these routes. Re-run with `--file_path` "
            "to include that.",
            "",
        ]

    # --- appendix ---
    lines += ["## Appendix — one representative path per route", ""]
    for route in routes[:MAX_REPORT_ROUTES]:
        representative = route["representative"]
        lines += [
            f"### {route_text(route['route'])}",
            "",
            f"Found in {route['run_count']} of {succeeded} runs, "
            f"{_plural(route['variant_count'], 'variant')}. Shown: run "
            f"{representative['run_index']}, path `{representative['path_id']}`"
            + (
                f", record `{representative['record_file']}`."
                if representative.get("record_file") else "."
            ),
            "",
        ]
        if representative.get("description"):
            lines += [
                f"*Path summary written by the LLM (projection):* "
                f"{representative['description']}",
                "",
            ]
        lines += [
            "| # | Technique | On | What it relies on (LLM) | Result (LLM) | Continuity |",
            "|---|---|---|---|---|---|",
        ]
        for index, step in enumerate(representative.get("steps", []), start=1):
            check = step.get("state_check", "") or "—"
            lines.append(
                f"| {index} | {step.get('technique_name', '')} "
                f"({step.get('technique_id', '')}) | "
                f"{label(step.get('component_id', ''))} | "
                f"{step.get('exploited_condition', '') or '—'} | "
                f"{step.get('result', '') or '—'} | {check} |"
            )
        lines.append("")
        if route.get("state_gaps"):
            lines += [
                f"{_plural(route['state_gaps'], 'step')} of this variant needed "
                f"access no earlier step provided — see the run record for what "
                f"was missing.",
                "",
            ]
        if route.get("varying_pairs"):
            lines += [
                f"{_plural(len(route['stable_pairs']), 'step')} appeared in most "
                f"variants of this route; {len(route['varying_pairs'])} varied "
                f"between runs.",
                "",
            ]

    lines += [
        "## Records",
        "",
        "This report was built from:",
        "",
    ]
    lines += [f"- `{name}`" for name in data.get("records", [])]
    lines.append("")
    return "\n".join(lines)


def _render_route_lines(
    group: dict[str, Any], limit: int, detail: bool
) -> list[str]:
    """Route lines for a summary, shared by the group action and the loop.

    Both readers need the same words for the same thing, and every count says
    what it is out of: "recurring" on its own is what gets mistaken for a
    verdict.
    """
    routes = group.get("routes", [])
    succeeded = group.get("succeeded", 0)
    lines: list[str] = []
    if routes and not group.get("recurrence_countable"):
        lines.append(
            f"Fewer than {MIN_RUNS_FOR_RECURRENCE} successful runs, so nothing "
            f"is called recurring — the counts are all there is."
        )
    for route in routes[:limit]:
        representative = route["representative"]
        hops = " -> ".join(
            f"{s['component_id']}:{s['technique_id']}"
            for s in representative.get("steps", [])
        )
        label = "recurring" if route["recurring"] else "one-off"
        lines.append(
            f"  [{label}, {route['run_count']}/{succeeded} run(s), "
            f"{route['variant_count']} variant(s)] "
            f"{' -> '.join(route['route'])}"
        )
        lines.append(
            f"    representative (run {representative['run_index']}): {hops}"
        )
        if detail and route["varying_pairs"]:
            lines.append(
                f"    {len(route['stable_pairs'])} step(s) in most variants, "
                f"{len(route['varying_pairs'])} varied between runs"
            )
        if detail and (route["state_gaps"] or route["assumptions"]):
            lines.append(
                f"    {len(route['assumptions'])} assumption(s) to test; "
                f"{route['state_gaps']} state gap(s) on this variant"
            )
    remaining = len(routes) - limit
    if remaining > 0:
        lines.append(f"  ... {remaining} more route(s).")
    return lines


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

        if action in ("profile_actor", "project_paths"):
            if not str(payload.get("threat_actor", "") or "").strip():
                errors.append(f"'threat_actor' is required for {action}")

            scope = payload.get("software_scope", "delivery")
            if scope not in SOFTWARE_SCOPES:
                errors.append(
                    f"Invalid software_scope {scope!r}. Must be one of: "
                    f"{', '.join(SOFTWARE_SCOPES)}."
                )

        if action == "profile_actor":
            max_procedures = payload.get("max_procedures", 5)
            if not isinstance(max_procedures, int) or isinstance(max_procedures, bool):
                errors.append("'max_procedures' must be an integer")
            elif not 0 <= max_procedures <= 50:
                errors.append("'max_procedures' must be between 0 and 50")

        if action in ("validate_flow_map", "project_paths"):
            has_inline = isinstance(payload.get("flow_map"), dict)
            has_reference = bool(
                str(payload.get("flow_map_artifact_id", "") or "").strip()
                or str(payload.get("file_path", "") or "").strip()
            )
            if not has_inline and not has_reference:
                errors.append(
                    f"{action} needs 'flow_map', 'flow_map_artifact_id' "
                    f"or 'file_path'"
                )
            if "flow_map" in payload and not has_inline:
                errors.append("'flow_map' must be an object")

        if action == "summarize_run_group":
            if not str(payload.get("run_group", "") or "").strip():
                errors.append("'run_group' is required for summarize_run_group")

        if action == "project_paths":
            max_paths = payload.get("max_paths", 3)
            if not isinstance(max_paths, int) or isinstance(max_paths, bool):
                errors.append("'max_paths' must be an integer")
            elif not 1 <= max_paths <= 10:
                errors.append("'max_paths' must be between 1 and 10")

            level = payload.get("thinking_level", _default_thinking_level())
            if level not in THINKING_LEVELS:
                errors.append(
                    f"Invalid thinking_level {level!r}. Must be one of: "
                    f"{', '.join(THINKING_LEVELS)}."
                )

            runs = payload.get("runs", 1)
            if not isinstance(runs, int) or isinstance(runs, bool):
                errors.append("'runs' must be an integer")
            elif not 1 <= runs <= MAX_RUNS:
                errors.append(f"'runs' must be between 1 and {MAX_RUNS}")

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
            if action == "project_paths":
                return self._project_paths(payload, context)
            if action == "summarize_run_group":
                return self._summarize_run_group_action(payload, context)
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

    def _load_actor_profile(
        self, payload: dict[str, Any], context: Any
    ) -> tuple[dict[str, Any] | None, ToolResult | None]:
        """Resolve the actor and build the closed technique set.

        Shared by profile_actor and project_paths so the set that constrains
        projection is assembled exactly once, in one place.
        """
        query = str(payload["threat_actor"]).strip()
        software_scope = str(payload.get("software_scope", "delivery"))
        intel_artifact_id = str(payload.get("intel_artifact_id", "") or "").strip()

        relationships = get_mitre_relationships()
        if not relationships.get("groups"):
            return None, ToolResult(
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
                return None, error
            intel_mappings = (data or {}).get("mitre_mappings", []) or []

        actor = _resolve_actor(query)
        if actor is None and not intel_mappings:
            return None, ToolResult(
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
        software = [
            {
                "id": software_id,
                "name": relationships["software"].get(software_id, {}).get("name", ""),
                "type": relationships["software"].get(software_id, {}).get("type", ""),
            }
            for software_id in record.get("software", [])
        ]
        label = record.get("name", "") or query
        if actor["attck_id"]:
            label = f"{label} ({actor['attck_id']})"

        return {
            "query": query,
            "resolved": resolved,
            "actor": actor,
            "record": record,
            "label": label,
            "software_scope": software_scope,
            "techniques": techniques,
            "software_techniques": software_techniques,
            "software": software,
            "relationships": relationships,
            "claims": claims,
        }, None

    def _profile_actor(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Resolve an actor and build its closed technique set."""
        profile, error = self._load_actor_profile(payload, context)
        if error is not None:
            return error
        assert profile is not None

        query = profile["query"]
        resolved = profile["resolved"]
        actor = profile["actor"]
        record = profile["record"]
        software_scope = profile["software_scope"]
        techniques = profile["techniques"]
        software_techniques = profile["software_techniques"]
        software = profile["software"]
        relationships = profile["relationships"]

        max_procedures = payload.get("max_procedures", 5)
        coverage = _tactic_coverage(techniques)
        covered = {entry["tactic"] for entry in coverage}

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

    def _load_flow_map_source(
        self, payload: dict[str, Any], context: Any
    ) -> tuple[Any, ToolResult | None]:
        """Resolve the flow map from an inline object, an artifact, or a file."""
        raw: Any = payload.get("flow_map")
        if raw is not None:
            return raw, None

        artifact_id = str(payload.get("flow_map_artifact_id", "") or "").strip()
        file_path = str(payload.get("file_path", "") or "").strip()
        if artifact_id:
            return self._read_json_artifact(artifact_id, context)
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as handle:
                    return json.load(handle), None
            except Exception as exc:
                return None, ToolResult(
                    ok=False,
                    error_code="ARTIFACT_UNREADABLE",
                    message=f"Failed to read flow map '{file_path}': {exc}",
                )
        return None, None

    def _validate_flow_map(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Lint a flow map, rank its entry surface, and compute reachability."""
        raw, error = self._load_flow_map_source(payload, context)
        if error is not None:
            return error

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

    def _project_paths(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Bind the actor's closed technique set onto the flow map (Phases A-C)."""
        max_paths = int(payload.get("max_paths", 3))
        objective = str(payload.get("objective", "") or "").strip()
        thinking_level = str(
            payload.get("thinking_level") or _default_thinking_level()
        )
        runs = int(payload.get("runs", 1))
        run_group = _slug(
            str(payload.get("run_group", "") or ""), DEFAULT_RUN_GROUP
        )
        # A loop that leaves no record is a loop whose output cannot be
        # compared, which is the only reason to run one.
        export = bool(payload.get("export", False)) or runs > 1

        # --- Phase A: the closed set and the topology, both deterministic ---
        profile, error = self._load_actor_profile(payload, context)
        if error is not None:
            return error
        assert profile is not None

        raw, error = self._load_flow_map_source(payload, context)
        if error is not None:
            return error

        flow_map, map_errors, map_warnings = _normalize_flow_map(raw)
        if map_errors:
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=(
                    f"Flow map has {len(map_errors)} blocking error(s); projection "
                    f"needs a valid topology. First: "
                    f"{map_errors[0]['code']} — {map_errors[0]['message']} "
                    f"Run 'validate_flow_map' for the full list."
                ),
                details={"errors": map_errors, "warnings": map_warnings},
            )

        core_ids = {t["technique_id"] for t in profile["techniques"]}
        software_ids = {t["technique_id"] for t in profile["software_techniques"]}
        if not (core_ids | software_ids):
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=(
                    f"No techniques in the closed set for "
                    f"'{profile['query']}' — nothing to project."
                ),
            )

        entry_surface = _entry_surface(flow_map)
        routes, unreachable = _crown_jewel_routes(flow_map, entry_surface)
        entry_ids = {
            e["component_id"] for e in entry_surface
            if flow_map["components"][e["component_id"]]["exposure"]
            in _EXTERNAL_EXPOSURES
        } or {entry_surface[0]["component_id"]}

        # --- Phase B: placement, the only step that needs a model ---
        if not getattr(context, "llm_query", None):
            return ToolResult(
                ok=False,
                error_code="LLM_UNAVAILABLE",
                message=(
                    "project_paths needs an LLM. Set GEMINI_PRO_API_KEY (see "
                    ".env.example) and run 'connect', or use 'profile_actor' and "
                    "'validate_flow_map' for the deterministic groundwork."
                ),
            )

        prompt, listed = _build_projection_prompt(
            profile["label"],
            profile["techniques"],
            profile["software_techniques"],
            flow_map,
            routes,
            objective,
            max_paths,
        )

        # Computed once and copied into every record of a --runs loop: it cannot
        # vary between iterations, so recomputing it would only cost time.  The
        # check that matters is across separate invocations of the same map.
        deterministic = {
            "entry_ranking": entry_surface,
            "routes": routes,
            "unreachable_crown_jewels": unreachable,
            "validation": map_warnings,
        }
        run_context = {
            "run_group": run_group,
            "runs": runs,
            "flow_map_path": str(payload.get("file_path", "") or ""),
            "flow_map_sha256": _canonical_flow_map_hash(raw),
            "application": flow_map["application"],
            "actor_input": str(payload.get("threat_actor", "") or ""),
            "unreachable": unreachable,
            "profile": profile,
            "thinking_level": thinking_level,
            "max_paths": max_paths,
            "software_scope": profile["software_scope"],
            "allowed_technique_count": len(core_ids | software_ids),
        }

        # ATT&CK procedure examples for the closed set: one scan, reused by
        # every run in a loop.
        procedures = _procedure_index(
            (profile.get("actor") or {}).get("attck_id", ""),
            {s["id"] for s in profile["software"]},
            core_ids | software_ids,
        )

        outcomes: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        export_errors: list[str] = []
        graph_written = False

        for index in range(1, runs + 1):
            attempt = self._run_one_projection(
                context, prompt, thinking_level, core_ids, software_ids,
                flow_map, entry_ids, profile["label"], procedures=procedures,
            )

            # The graph and the seed are the product of a projection and chain
            # onwards; in a loop only the first success needs to, or a 20-run
            # experiment buries the artifact listing under 40 files nobody asked
            # for.  Every run still leaves its own record.
            if attempt["ok"] and not graph_written:
                attempt["artifacts"] = self._write_projection_artifacts(
                    profile, flow_map, attempt["attack_graph"],
                    attempt["validated"]["mitre_mappings"], attempt["seeds"],
                    context,
                )
                artifacts.extend(attempt["artifacts"])
                graph_written = True

            if export:
                record = self._build_run_record(
                    run_context, deterministic, attempt, index
                )
                written, write_error = self._write_run_record(
                    record, attempt.get("raw_text"), context
                )
                artifacts.extend(written)
                attempt["record_file"] = record["run"]["record_file"]
                # Kept so the loop can summarise its own group without reading
                # the files back — see _multi_run_result.
                attempt["record"] = record
                if write_error:
                    export_errors.append(f"run {index}: {write_error}")

            outcomes.append(attempt)

        if runs == 1:
            return self._single_run_result(
                run_context, outcomes[0], listed, map_warnings, artifacts,
                export_errors,
            )
        return self._multi_run_result(
            run_context, outcomes, listed, artifacts, export_errors
        )

    def _run_one_projection(
        self,
        context: Any,
        prompt: str,
        thinking_level: str,
        core_ids: set[str],
        software_ids: set[str],
        flow_map: dict[str, Any],
        entry_ids: set[str],
        actor_label: str,
        procedures: dict[str, dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """One Phase B + Phase C cycle.

        Returns the attempt as data rather than a ToolResult so that a failure
        can still be recorded before it is returned.  A run that dies is a
        finding about the map — most usefully so inside a loop, where it must
        not stop the runs after it.
        """
        started = time.perf_counter()
        attempt: dict[str, Any] = {
            "ok": False,
            "error_code": None,
            "message": None,
            "details": None,
            "raw_text": None,
            "response": None,
        }

        response = context.llm_query.query_text(
            prompt=prompt,
            system_context=PROJECTION_SYSTEM_CONTEXT,
            max_tokens=PROJECTION_MAX_TOKENS,
            hints=QueryHints(
                tier="heavy",
                needs_reasoning=True,
                needs_structured_output=True,
                thinking_level=thinking_level,
            ),
        )
        attempt["response"] = response
        attempt["raw_text"] = getattr(response, "text", None)

        def _finish(**fields: Any) -> dict[str, Any]:
            attempt.update(fields)
            attempt["wall_time_ms"] = int((time.perf_counter() - started) * 1000)
            return attempt

        if not response.ok:
            return _finish(
                error_code="LLM_QUERY_FAILED",
                message=f"Projection query failed: {response.error}",
            )
        if getattr(response, "truncated", False):
            return _finish(
                error_code="LLM_QUERY_FAILED",
                message=(
                    "Projection reply hit the output-token cap and is incomplete. "
                    "Lower 'max_paths', or narrow 'software_scope' to shrink the "
                    "technique set."
                ),
            )

        parsed, parse_error = _parse_llm_json(response.text or "")
        if parsed is None:
            return _finish(
                error_code="LLM_QUERY_FAILED",
                message=f"Could not parse the projection reply: {parse_error}",
            )

        # --- Phase C: reject what the closed set and the map do not support ---
        validated = _validate_projection(
            parsed, core_ids, software_ids, flow_map, entry_ids, procedures
        )
        attack_graph = validated["attack_graph"]

        if not attack_graph["paths"]:
            return _finish(
                error_code="PROJECTION_REJECTED",
                message=(
                    f"No projected path survived validation "
                    f"({len(validated['rejections'])} rejection(s)). "
                    f"The model placed techniques outside the actor's documented "
                    f"set or components outside the flow map."
                ),
                details={"rejections": validated["rejections"]},
                validated=validated,
                attack_graph=attack_graph,
            )

        return _finish(
            ok=True,
            validated=validated,
            attack_graph=attack_graph,
            seeds=_build_scenario_seeds(actor_label, flow_map, attack_graph),
        )

    # -------------------------------------------------------------------
    # Run records
    # -------------------------------------------------------------------

    @staticmethod
    def _build_run_record(
        run_context: dict[str, Any],
        deterministic: dict[str, Any],
        attempt: dict[str, Any],
        index: int,
    ) -> dict[str, Any]:
        """Assemble one run record.

        The split between 'deterministic' and 'sampled' is the point of the
        record: everything under 'deterministic' is fixed by the flow map hash
        and must not vary between runs, so a reader comparing two records knows
        any difference below it came from the model.
        """
        run_id = str(uuid.uuid4())
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        profile = run_context["profile"]
        response = attempt.get("response")

        record: dict[str, Any] = {
            "run": {
                "schema_version": RUN_RECORD_SCHEMA_VERSION,
                "run_id": run_id,
                "run_group": run_context["run_group"],
                "run_index": index,
                "run_count": run_context["runs"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "tool_version": {
                    "manifest_version": _manifest_version(),
                    "git_sha": _git_short_sha(),
                },
                "flow_map_path": run_context["flow_map_path"],
                "flow_map_sha256": run_context["flow_map_sha256"],
                "application": run_context["application"],
                "actor_input": run_context["actor_input"],
                "actor_resolved": {
                    "name": profile["label"],
                    "resolved": profile["resolved"],
                    "attack_id": (profile.get("actor") or {}).get("attck_id", ""),
                    "entity_type": (profile.get("actor") or {}).get(
                        "entity_type", ""
                    ),
                    "aliases": (profile.get("record") or {}).get("aliases", []),
                    "technique_count": run_context["allowed_technique_count"],
                },
                "record_file": (
                    f"adversary_projection_run_{stamp}_{run_id[:8]}.json"
                ),
            },
            "model": {
                "provider": "gcp_gemini",
                "model_configured": getattr(response, "model_used", None),
                "model_served": getattr(response, "model_version", None),
                "tier": "heavy",
                "thinking_level": run_context["thinking_level"],
                "max_tokens": PROJECTION_MAX_TOKENS,
                "max_paths": run_context["max_paths"],
                "software_scope": run_context["software_scope"],
            },
            "deterministic": deterministic,
            "outcome": {
                "status": "ok" if attempt["ok"] else "error",
                "finish_reason": getattr(response, "finish_reason", None),
                "truncated": bool(getattr(response, "truncated", False)),
                "error_code": attempt["error_code"],
                "message": attempt["message"],
                "usage": getattr(response, "token_usage", None),
                "wall_time_ms": attempt.get("wall_time_ms"),
            },
        }

        if attempt.get("raw_text"):
            record["run"]["raw_response_file"] = (
                f"adversary_projection_raw_{stamp}_{run_id[:8]}.txt"
            )

        # 'sampled' is absent on a failure rather than empty: an empty block
        # reads as "the model returned nothing", which is a different event
        # from never having gotten a usable reply at all.
        if attempt["ok"]:
            record["sampled"] = {
                "paths": [
                    {
                        "path_id": path["path_id"],
                        "description": path.get("description", ""),
                        "steps": [
                            {
                                "technique_id": step["technique_id"],
                                "technique_name": step.get("technique_name", ""),
                                "tactic": step.get("tactic", ""),
                                "component_id": step.get("component_id", ""),
                                "evidence": step.get("evidence", ""),
                                "rationale": step.get("rationale", ""),
                                "uncovered_mitigations": step.get(
                                    "uncovered_mitigations", []
                                ),
                                "precondition": step.get("precondition", ""),
                                "access_before": step.get("access_before"),
                                "exploited_condition": step.get(
                                    "exploited_condition", ""
                                ),
                                "result": step.get("result", ""),
                                "access_after": step.get("access_after"),
                                "assumptions": step.get("assumptions", []),
                                "control_note": step.get("control_note", ""),
                                "actor_support": step.get("actor_support", ""),
                                "state_check": step.get("state_check", ""),
                            }
                            for step in path["steps"]
                        ],
                    }
                    for path in attempt["attack_graph"]["paths"]
                ],
                "rejections": attempt["validated"]["rejections"],
                "warnings": attempt["validated"]["warnings"],
                "raw_response_path": record["run"].get("raw_response_file"),
            }
        return record

    @staticmethod
    def _write_run_record(
        record: dict[str, Any], raw_text: str | None, context: Any
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Write and register the record, and the raw reply beside it.

        Returns ``(artifacts, error)``.  A write failure never raises — losing
        the record must not also lose the projection it describes.
        """
        workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
        art_dir = workspace / "artifacts"
        try:
            art_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            return [], f"could not create artifact directory: {exc}"

        register = getattr(context, "register_artifact", None)
        written: list[dict[str, Any]] = []
        errors: list[str] = []

        payloads: list[tuple[str, str, str]] = [
            (
                record["run"]["record_file"],
                json.dumps(record, indent=2, default=str),
                "json_events",
            )
        ]
        raw_name = record["run"].get("raw_response_file")
        if raw_name and raw_text:
            payloads.append((raw_name, raw_text, "text"))

        for filename, body, artifact_type in payloads:
            path = art_dir / filename
            try:
                path.write_text(body, encoding="utf-8")
            except Exception as exc:
                errors.append(f"could not write {filename}: {exc}")
                continue

            metadata = {
                # The record and the raw reply are different things, and only
                # the record is a run record. summarize_run_group selects by
                # this kind, and a raw reply that happens to be valid JSON —
                # which it usually is — would otherwise be counted as a record.
                "kind": (
                    "projection_run" if artifact_type == "json_events"
                    else "projection_raw_response"
                ),
                "run_id": record["run"]["run_id"],
                "run_group": record["run"]["run_group"],
                "run_index": record["run"]["run_index"],
                "flow_map_sha256": record["run"]["flow_map_sha256"],
                "status": record["outcome"]["status"],
            }
            if callable(register):
                try:
                    register(
                        artifact_type, str(path), "adversary_path_projector",
                        metadata,
                    )
                    continue
                except Exception as exc:
                    logger.warning("register_artifact failed for %s: %s", path, exc)
            written.append({
                "artifact_id": f"art_{path.stem}",
                "artifact_type": artifact_type,
                "file_path": str(path),
            })

        return written, "; ".join(errors) or None

    # -------------------------------------------------------------------
    # Result assembly
    # -------------------------------------------------------------------

    @staticmethod
    def _single_run_result(
        run_context: dict[str, Any],
        attempt: dict[str, Any],
        listed: int,
        map_warnings: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
        export_errors: list[str],
    ) -> ToolResult:
        """The one-run result, unchanged in shape from before export existed."""
        profile = run_context["profile"]
        if not attempt["ok"]:
            return ToolResult(
                ok=False,
                error_code=attempt["error_code"],
                message=attempt["message"],
                details=attempt["details"],
                output_artifacts=artifacts or None,
            )

        attack_graph = attempt["attack_graph"]
        validated = attempt["validated"]
        steps = [s for p in attack_graph["paths"] for s in p["steps"]]
        result = {
            "action": "project_paths",
            "actor": profile["label"],
            "application": run_context["application"],
            "software_scope": profile["software_scope"],
            "thinking_level": run_context["thinking_level"],
            "allowed_technique_count": run_context["allowed_technique_count"],
            "techniques_offered_to_model": listed,
            "path_count": len(attack_graph["paths"]),
            "step_count": len(steps),
            "evidence_counts": {
                "documented": sum(1 for s in steps if s["evidence"] == "documented"),
                "via_software": sum(
                    1 for s in steps if s["evidence"] == "via_software"
                ),
            },
            "attack_graph": attack_graph,
            "mitre_mappings": validated["mitre_mappings"],
            "scenario_seeds": attempt["seeds"],
            "rejections": validated["rejections"],
            "warnings": validated["warnings"] + map_warnings,
            "control_tagging": validated["control_tagging"],
            "unreachable_crown_jewels": run_context["unreachable"],
            "model_used": getattr(attempt.get("response"), "model_used", None),
        }
        if attempt.get("record_file"):
            result["run_record"] = attempt["record_file"]
            result["run_group"] = run_context["run_group"]
        if export_errors:
            result["export_errors"] = export_errors
        return ToolResult(
            ok=True, result=result, output_artifacts=artifacts or None
        )

    @staticmethod
    def _multi_run_result(
        run_context: dict[str, Any],
        outcomes: list[dict[str, Any]],
        listed: int,
        artifacts: list[dict[str, Any]],
        export_errors: list[str],
    ) -> ToolResult:
        """The --runs result: one line per run, no graph.

        The point of a loop is the corpus it leaves behind, so the terminal gets
        a manifest of what was written rather than the last run's paths.
        """
        runs = []
        for index, attempt in enumerate(outcomes, start=1):
            graph = attempt.get("attack_graph") or {"paths": []}
            steps = [s for p in graph["paths"] for s in p["steps"]]
            runs.append({
                "run_index": index,
                "status": "ok" if attempt["ok"] else "error",
                "error_code": attempt["error_code"],
                "path_count": len(graph["paths"]),
                "step_count": len(steps),
                "wall_time_ms": attempt.get("wall_time_ms"),
                "record": attempt.get("record_file"),
            })

        succeeded = sum(1 for r in runs if r["status"] == "ok")
        # The loop already holds every record it wrote, so it can answer its own
        # question — which routes came back — without a second command and
        # without depending on the records still being registered.
        group = _summarize_run_group(
            [record for record in (a.get("record") for a in outcomes) if record]
        )
        result = {
            "action": "project_paths",
            "actor": run_context["profile"]["label"],
            "application": run_context["application"],
            "run_group": run_context["run_group"],
            "run_group_summary": group,
            "flow_map_sha256": run_context["flow_map_sha256"],
            "thinking_level": run_context["thinking_level"],
            "software_scope": run_context["software_scope"],
            "allowed_technique_count": run_context["allowed_technique_count"],
            "techniques_offered_to_model": listed,
            "run_count": len(runs),
            "succeeded": succeeded,
            "failed": len(runs) - succeeded,
            "runs": runs,
        }
        if export_errors:
            result["export_errors"] = export_errors
        # A loop where every run died is a failed experiment, not a successful
        # one that happens to contain nothing.
        return ToolResult(
            ok=succeeded > 0,
            error_code=None if succeeded else "PROJECTION_REJECTED",
            message=(
                None if succeeded
                else f"All {len(runs)} run(s) failed; see the run records."
            ),
            result=result,
            output_artifacts=artifacts or None,
        )

    # -------------------------------------------------------------------
    # Run-group summary
    # -------------------------------------------------------------------

    @staticmethod
    def _load_group_records(
        run_group: str, context: Any
    ) -> tuple[list[dict[str, Any]], ToolResult | None]:
        """Every projection run record in this session carrying *run_group*.

        Records are read through the registered artifacts rather than by
        scanning the workspace: the registry is the session's own account of
        what was written, and on Cloud Run a local directory is ephemeral. The
        consequence is worth knowing — records from an earlier session, or from
        before 'new', are not visible.
        """
        records: list[dict[str, Any]] = []
        for artifact in getattr(context, "artifacts", None) or []:
            metadata = getattr(artifact, "metadata", None) or {}
            if metadata.get("kind") != "projection_run":
                continue
            if metadata.get("run_group") != run_group:
                continue
            try:
                with open(artifact.file_path, "r", encoding="utf-8") as handle:
                    document = json.load(handle)
            except Exception as exc:
                logger.warning(
                    "Skipping unreadable run record %s: %s",
                    artifact.file_path, exc,
                )
                continue
            # Anything else carrying this label is skipped rather than trusted:
            # a missing count is recoverable, a crashed action is not.
            if isinstance(document, dict) and "run" in document:
                records.append(document)
            else:
                logger.warning(
                    "Artifact %s is labelled a run record but has no 'run' "
                    "block; skipped.", artifact.file_path,
                )

        if not records:
            return [], ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=(
                    f"No projection run records for run group '{run_group}' in "
                    f"this session. Records are registered by "
                    f"'project_paths --export' or '--runs'; a group written "
                    f"before the last 'new', or in another session, is not "
                    f"visible here."
                ),
            )

        # One estate, one actor, or the counts mean nothing: the same route
        # found against two maps is not the same finding.
        maps = {r["run"].get("flow_map_sha256", "") for r in records}
        actors = {
            (r["run"].get("actor_resolved") or {}).get("name", "") for r in records
        }
        if len(maps) > 1 or len(actors) > 1:
            return [], ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=(
                    f"Run group '{run_group}' mixes "
                    f"{len(maps)} flow map(s) and {len(actors)} actor(s), so "
                    f"counting how often a route recurs would be meaningless. "
                    f"Maps: {', '.join(sorted(m[:12] for m in maps))}. "
                    f"Actors: {', '.join(sorted(a or '?' for a in actors))}. "
                    f"Re-run with a group label per map and actor."
                ),
            )

        # By when they ran, so batches added to a group over several
        # invocations number in the order they happened rather than
        # interleaving on a per-invocation index.
        records.sort(key=lambda r: (
            r["run"].get("created_at", ""), r["run"].get("run_index", 0)
        ))
        return records, None

    def _summarize_run_group_action(
        self, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        """Count recurring routes across a group of runs. No LLM."""
        run_group = _slug(str(payload.get("run_group", "") or ""), DEFAULT_RUN_GROUP)
        records, error = self._load_group_records(run_group, context)
        if error is not None:
            return error

        first = records[0]["run"]
        summary = _summarize_run_group(records)
        result = {
            "action": "summarize_run_group",
            "run_group": run_group,
            "application": first.get("application", ""),
            "actor": (first.get("actor_resolved") or {}).get("name", ""),
            "flow_map_sha256": first.get("flow_map_sha256", ""),
            "records": [r["run"].get("record_file", "") for r in records],
            **summary,
        }

        # The flow map is optional here: without it the report still counts
        # routes, it just cannot say which controls sit on them, and says so.
        flow_map: dict[str, Any] | None = None
        raw, load_error = self._load_flow_map_source(payload, context)
        if load_error is not None:
            return load_error
        if raw is not None:
            flow_map, map_errors, _ = _normalize_flow_map(raw)
            if map_errors:
                flow_map = None
                result["report_warnings"] = [
                    f"Flow map has {len(map_errors)} blocking error(s), so the "
                    f"report was written without control context."
                ]
            elif _canonical_flow_map_hash(raw) != result["flow_map_sha256"]:
                result.setdefault("report_warnings", []).append(
                    "The supplied flow map is not the one these runs were "
                    "projected against; component names and controls in the "
                    "report may not match the records."
                )

        stamps = sorted(
            r["run"].get("created_at", "")[:10] for r in records
            if r["run"].get("created_at")
        )
        report = _render_group_report(
            result,
            _component_names(records),
            _crown_jewel_ids(records),
            flow_map,
            (stamps[0] if stamps else "", stamps[-1] if stamps else ""),
        )
        artifacts, report_file, write_error = self._write_group_report(
            report, run_group, context
        )
        if report_file:
            result["report_file"] = report_file
        if write_error:
            result.setdefault("report_warnings", []).append(write_error)

        return ToolResult(
            ok=True, result=result, output_artifacts=artifacts or None
        )

    @staticmethod
    def _write_group_report(
        markdown: str, run_group: str, context: Any
    ) -> tuple[list[dict[str, Any]], str, str | None]:
        """Write and register the report. A failure never costs the summary."""
        workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
        art_dir = workspace / "artifacts"
        try:
            art_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            return [], "", f"could not create artifact directory: {exc}"

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"adversary_projection_group_{run_group}_{stamp}.md"
        path = art_dir / filename
        try:
            path.write_text(markdown, encoding="utf-8")
        except Exception as exc:
            return [], "", f"could not write {filename}: {exc}"

        # Its own kind: a report labelled 'projection_run' would be loaded as a
        # record by the next summary, which is a bug this plugin has had once.
        metadata = {"kind": "projection_group_report", "run_group": run_group}
        register = getattr(context, "register_artifact", None)
        if callable(register):
            try:
                register("text", str(path), "adversary_path_projector", metadata)
                return [], filename, None
            except Exception as exc:
                logger.warning("register_artifact failed for %s: %s", path, exc)
        return (
            [{
                "artifact_id": f"art_{path.stem}",
                "artifact_type": "text",
                "file_path": str(path),
            }],
            filename,
            None,
        )

    @staticmethod
    def _write_projection_artifacts(
        profile: dict[str, Any],
        flow_map: dict[str, Any],
        attack_graph: dict[str, Any],
        mitre_mappings: list[dict[str, Any]],
        seeds: list[dict[str, Any]],
        context: Any,
    ) -> list[dict[str, Any]]:
        """Write the visualizer graph and the scenario seed as separate files.

        The graph file carries exactly the keys attack_path_visualizer reads,
        so it chains with no translation; the extra per-step keys it does not
        read are harmless.
        """
        workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
        art_dir = workspace / "artifacts"
        try:
            art_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Could not create artifact directory: %s", exc)
            return []

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        written: list[dict[str, Any]] = []

        payloads = [
            (
                f"adversary_path_graph_{stamp}.json",
                {
                    "source_tool": "adversary_path_projector",
                    "status": "projected",
                    "interpretation": PROJECTION_INTERPRETATION,
                    "actor": profile["label"],
                    "application": flow_map["application"],
                    "mitre_mappings": mitre_mappings,
                    "attack_graph": attack_graph,
                },
            ),
            (
                f"adversary_scenario_seed_{stamp}.json",
                {
                    "source_tool": "adversary_path_projector",
                    "status": "projected",
                    "interpretation": PROJECTION_INTERPRETATION,
                    "actor": profile["label"],
                    "application": flow_map["application"],
                    "scenarios": seeds,
                },
            ),
        ]

        for filename, body in payloads:
            path = art_dir / filename
            try:
                path.write_text(
                    json.dumps(body, indent=2, default=str), encoding="utf-8"
                )
            except Exception as exc:
                logger.warning("Could not write %s: %s", path, exc)
                continue

            register = getattr(context, "register_artifact", None)
            if callable(register):
                try:
                    register(
                        "json_events",
                        str(path),
                        "adversary_path_projector",
                        {"kind": filename.split("_2")[0]},
                    )
                    continue
                except Exception as exc:
                    logger.warning("register_artifact failed for %s: %s", path, exc)
            written.append({
                "artifact_id": f"art_{path.stem}",
                "artifact_type": "json_events",
                "file_path": str(path),
            })
        return written

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
        elif action == "project_paths":
            summary = self._summarize_projection(data)
        elif action == "summarize_run_group":
            summary = self._summarize_group(data)
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
    def _summarize_projection(data: dict[str, Any]) -> str:
        if "runs" in data:
            return AdversaryPathProjector._summarize_runs(data)

        graph = data.get("attack_graph", {})
        evidence = data.get("evidence_counts", {})
        rejections = data.get("rejections", [])

        lines = [
            f"{data.get('actor', '?')} vs {data.get('application', '?')}: "
            f"{data.get('path_count', 0)} path(s), "
            f"{data.get('step_count', 0)} step(s). "
            f"{evidence.get('documented', 0)} step(s) use techniques attributed "
            f"to the actor directly, {evidence.get('via_software', 0)} via its "
            f"tooling. {PROJECTION_NOTICE}"
        ]

        for path in graph.get("paths", [])[:3]:
            hops = " -> ".join(
                f"{s['component_id']}:{s['technique_id']}" for s in path["steps"]
            )
            lines.append(f"  [{path['path_id']}] {hops}")
        remaining = len(graph.get("paths", [])) - 3
        if remaining > 0:
            lines.append(f"  ... {remaining} more path(s).")

        if rejections:
            codes: dict[str, int] = {}
            for rejection in rejections:
                codes[rejection["code"]] = codes.get(rejection["code"], 0) + 1
            detail = ", ".join(f"{code} x{n}" for code, n in sorted(codes.items()))
            lines.append(f"Rejected {len(rejections)} placement(s): {detail}.")

        # Sequence problems are kept steps, so they never show up as rejections.
        # Surface them or the loud warning is not loud.
        sequence = [
            w for w in data.get("warnings", [])
            if w["code"] in ("KILL_CHAIN_REGRESSION", "LATE_INITIAL_ACCESS")
        ]
        if sequence:
            lines.append(
                f"{len(sequence)} step(s) out of kill-chain sequence — review: "
                + "; ".join(w["location"] for w in sequence[:4])
            )

        corrected = [
            w for w in data.get("warnings", []) if w["code"] == "TACTIC_CORRECTED"
        ]
        if corrected:
            lines.append(f"{len(corrected)} tactic label(s) corrected against ATT&CK.")

        all_steps = [s for p in graph.get("paths", []) for s in p["steps"]]
        if all_steps:
            state_gaps = [
                w for w in data.get("warnings", []) if w["code"] == "STATE_GAP"
            ]
            assumptions = sum(len(s.get("assumptions", [])) for s in all_steps)
            unchecked = sum(1 for s in all_steps if s.get("state_check") == "unchecked")
            line = (
                f"Step state: {assumptions} assumption(s) to test; "
                f"{len(state_gaps)} state gap(s)"
            )
            if state_gaps:
                line += " — " + "; ".join(w["location"] for w in state_gaps[:4])
            if unchecked:
                line += f"; continuity not checked on {unchecked} step(s)"
            lines.append(line + ".")

        # Readers struggle with ambiguity, so each line says exactly what was
        # checked: an absent control first, then the gap list scoped to what it
        # compares, then why that list may overstate.
        tagging = data.get("control_tagging") or {}
        bare = tagging.get("components_without_controls", [])
        if bare:
            more = f", +{len(bare) - 6} more" if len(bare) > 6 else ""
            lines.append(
                f"No controls declared at all on: {', '.join(bare[:6])}{more}."
            )

        gaps = {
            m
            for path in graph.get("paths", [])
            for step in path["steps"]
            for m in step.get("uncovered_mitigations", [])
        }
        if gaps:
            listed = ", ".join(sorted(gaps)[:6])
            more = f", +{len(gaps) - 6} more" if len(gaps) > 6 else ""
            lines.append(
                f"ATT&CK mitigations for these techniques that no control on the "
                f"targeted component declares: {listed}{more}."
            )
            total = tagging.get("control_count", 0)
            untagged = total - tagging.get("tagged_control_count", 0)
            if untagged:
                lines.append(
                    f"Caution: {untagged} of {total} control(s) on the targeted "
                    f"components carry no ATT&CK mitigation id and cannot be "
                    f"matched, so some listed mitigations may already be in place. "
                    f"Estate-wide and flow controls are not checked against this list."
                )

        return "\n".join(lines)

    @staticmethod
    def _summarize_runs(data: dict[str, Any]) -> str:
        """Compress a --runs loop. Stays well inside the 2000-character cap.

        Per-run detail is in the records; what belongs here is whether the
        experiment produced a comparable corpus and where it is.
        """
        runs = data.get("runs", [])
        paths = [r["path_count"] for r in runs if r["status"] == "ok"]
        times = [r["wall_time_ms"] for r in runs if r.get("wall_time_ms")]
        lines = [
            f"{data.get('actor', '?')} vs {data.get('application', '?')}: "
            f"{data.get('run_count', 0)} run(s), {data.get('succeeded', 0)} ok, "
            f"{data.get('failed', 0)} failed. "
            f"Group '{data.get('run_group', '?')}', "
            f"thinking_level {data.get('thinking_level', '?')}, "
            f"map {str(data.get('flow_map_sha256', ''))[:12]}."
        ]
        if paths:
            lines.append(
                f"Paths per successful run: min {min(paths)}, max {max(paths)}."
            )
        if times:
            lines.append(f"Wall time {min(times)}-{max(times)}ms.")

        failures: dict[str, int] = {}
        for run in runs:
            if run["status"] != "ok":
                code = run.get("error_code") or "UNKNOWN"
                failures[code] = failures.get(code, 0) + 1
        if failures:
            lines.append(
                "Failures: "
                + ", ".join(f"{c} x{n}" for c, n in sorted(failures.items()))
                + "."
            )
        # The loop already counted its own routes, so the terminal shows what
        # the group found rather than only what it wrote. Fewer routes and less
        # detail than the group action: this has per-run lines above it and one
        # 2000-character budget to share.
        group = data.get("run_group_summary") or {}
        if group.get("routes"):
            lines.append(
                f"{group.get('route_count', 0)} distinct route(s), "
                f"{group.get('recurring_route_count', 0)} recurring:"
            )
            lines.extend(_render_route_lines(group, limit=3, detail=False))
            lines.append(
                f"Full breakdown: summarize_run_group --run_group "
                f"{data.get('run_group', '?')}."
            )

        lines.append(
            f"Records written per run; compare them directly. {PROJECTION_NOTICE}"
        )
        return "\n".join(lines)

    @staticmethod
    def _summarize_group(data: dict[str, Any]) -> str:
        """Compress a run group: which routes recur, and on what evidence.

        The point of a group is the routes that come back, so they lead; the
        one-offs are counted, not listed. Every count says how many runs it is
        out of, because "recurring" on its own is the kind of word a reader
        can take for a verdict.
        """
        succeeded = data.get("succeeded", 0)
        lines = [
            f"{data.get('actor', '?')} vs {data.get('application', '?')}, group "
            f"'{data.get('run_group', '?')}': {data.get('run_count', 0)} run(s), "
            f"{succeeded} ok, {data.get('failed', 0)} failed, "
            f"map {str(data.get('flow_map_sha256', ''))[:12]}. "
            f"{data.get('route_count', 0)} distinct route(s), "
            f"{data.get('recurring_route_count', 0)} recurring."
        ]
        lines.extend(_render_route_lines(data, limit=4, detail=True))
        lines.append(PROJECTION_NOTICE)
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
