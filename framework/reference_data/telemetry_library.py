"""Shared telemetry reference library: what an estate can actually observe.

The data lives in ``telemetry_library.json`` beside this module and is
specified by ``docs/specs/telemetry_reference_library.md``. It is an inventory
of observation sources - log streams, audit records, alert feeds, periodic
reports, reconciliations, physical records and human reports - not a detection
catalogue. It holds no rule content.

Usage from any plugin::

    from framework.reference_data.telemetry_library import (
        sources_for_component, get_source, library_version,
    )

    sources_for_component(["postgres", "pgaudit"], component_type="database")
    get_source("vault.audit_device")

Three properties the loader enforces, because each corresponds to a way the
library could quietly become wrong:

* An entry never carries an invented ATT&CK id. Every ``exact`` or ``adjacent``
  mapping is checked against the local release, and ``unmapped`` requires a
  local ``EM-`` id instead. See :func:`validate_library`.
* ``collection.status`` and ``collection.necessity`` are independent. A source
  can be required and missing; a control existing is never evidence that its
  logs carry the fields.
* A ``decision_support`` entry makes another control work and detects nothing
  on its own. Counting one as a detection overstates every supporting source
  in the estate, so ``supports`` edges are kept distinct from ``observes``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from framework.reference_data.mitre_attack import enrich_technique

_LIBRARY_FILE = Path(__file__).resolve().parent / "telemetry_library.json"

# Section 4.1. What a control does to risk, not where it sits.
CONTROL_FUNCTIONS = ("loss_event", "variance_management", "decision_support")

# Section 4.2. How a supporting source acts on the control it serves.
SUPPORT_EFFECTS = (
    "enables_trigger",
    "tunes_threshold",
    "provides_context",
    "verifies_operation",
)

# Section 3. The three mapping states, and the qualifiers `adjacent` needs.
ATTACK_RELATIONS = ("exact", "adjacent", "unmapped")
RELATION_KINDS = ("broader", "narrower", "precursor", "consequence", "variant")

CATEGORIES = (
    "log",
    "audit",
    "alert_feed",
    "report",
    "reconciliation",
    "physical_record",
    "human_report",
)
ARTEFACTS = ("machine_readable", "human_readable", "human_report", "none")
CADENCES = (
    "continuous",
    "daily",
    "weekly",
    "monthly",
    "quarterly",
    "on_request",
)
NECESSITIES = ("required", "alternative", "enrichment")
COLLECTION_STATUSES = ("confirmed", "assumed", "missing", "unknown")


class TelemetryLibraryError(ValueError):
    """The library file is unusable or internally inconsistent."""


@lru_cache(maxsize=1)
def get_library() -> dict[str, Any]:
    """The parsed library. Always read as UTF-8, never the platform default."""
    try:
        with open(_LIBRARY_FILE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - fatal
        raise TelemetryLibraryError(f"Cannot read {_LIBRARY_FILE}: {exc}") from exc


def library_version() -> str:
    """Pinned into every draft beside the ATT&CK release."""
    return str(get_library().get("library_version") or "unknown")


def all_sources() -> list[dict[str, Any]]:
    return list(get_library().get("sources") or [])


def get_source(source_id: str) -> dict[str, Any] | None:
    return next((s for s in all_sources() if s.get("source_id") == source_id), None)


def sources_for_component(
    technologies: list[str] | None = None,
    component_type: str | None = None,
) -> list[dict[str, Any]]:
    """Component first, behaviour second, technique last (spec section 5).

    A badge reader is unreachable from a technique, so the technique never
    leads. An entry matches when it names one of the component's technologies,
    or when it names the component type and claims no technologies of its own.
    """
    wanted = {t.lower() for t in (technologies or [])}
    matched: list[dict[str, Any]] = []
    for source in all_sources():
        applies = source.get("applies_to") or {}
        declared = {t.lower() for t in (applies.get("technologies") or [])}
        types = applies.get("component_types") or []
        if declared & wanted:
            matched.append(source)
        elif not declared and component_type and component_type in types:
            matched.append(source)
    return matched


def sources_for_estate(estate: str) -> list[dict[str, Any]]:
    """Every source the named example estate refers to. Used by the tests."""
    return [s for s in all_sources() if estate in (s.get("estates") or [])]


def supporting_sources() -> list[dict[str, Any]]:
    """Entries that make another control work rather than detecting anything."""
    return [
        s
        for s in all_sources()
        if (s.get("control_function") or {}).get("domain") == "decision_support"
    ]


def unmapped_behaviours() -> list[dict[str, Any]]:
    """Behaviours deliberately outside ATT&CK, with their local ids."""
    out: list[dict[str, Any]] = []
    for source in all_sources():
        for observation in source.get("observes") or []:
            if observation.get("attack_relation") == "unmapped":
                out.append({"source_id": source["source_id"], **observation})
    return out


def validate_library() -> list[str]:
    """Every way the library can be internally wrong, as a list of messages.

    Returns an empty list when the file is sound. The test suite asserts that;
    the function exists so a future ``scripts/validate_*`` run can too.
    """
    errors: list[str] = []
    library = get_library()
    if not library.get("library_version"):
        errors.append("library_version is missing")

    seen: set[str] = set()
    for source in all_sources():
        source_id = source.get("source_id") or "(unnamed)"
        if source_id in seen:
            errors.append(f"{source_id}: duplicate source_id")
        seen.add(source_id)

        if source.get("category") not in CATEGORIES:
            errors.append(f"{source_id}: category {source.get('category')!r} is not declared")

        function = (source.get("control_function") or {}).get("domain")
        if function not in CONTROL_FUNCTIONS:
            errors.append(f"{source_id}: control_function.domain {function!r} is not declared")

        collection = source.get("collection") or {}
        if collection.get("necessity") not in NECESSITIES:
            errors.append(f"{source_id}: collection.necessity is not declared")
        if collection.get("status") not in COLLECTION_STATUSES:
            errors.append(f"{source_id}: collection.status is not declared")

        availability = source.get("availability") or {}
        if availability.get("artefact") not in ARTEFACTS:
            errors.append(f"{source_id}: availability.artefact is not declared")
        if availability.get("cadence") not in CADENCES:
            errors.append(f"{source_id}: availability.cadence is not declared")
        if not availability.get("owner"):
            errors.append(f"{source_id}: availability.owner is missing")

        for event in source.get("events") or []:
            if event.get("mapping_status") not in ("native_identifier", "description_only"):
                errors.append(f"{source_id}: event mapping_status is not declared")

        for edge in source.get("supports") or []:
            if edge.get("effect") not in SUPPORT_EFFECTS:
                errors.append(f"{source_id}: supports.effect {edge.get('effect')!r} is not declared")
            if not edge.get("without_it"):
                errors.append(f"{source_id}: supports entry does not say what is lost without it")

        errors.extend(_validate_observations(source_id, source.get("observes") or []))

    return errors


def _validate_observations(source_id: str, observations: list[dict]) -> list[str]:
    """An invented ATT&CK id is the defect this library exists to prevent."""
    errors: list[str] = []
    for observation in observations:
        relation = observation.get("attack_relation")
        if relation not in ATTACK_RELATIONS:
            errors.append(f"{source_id}: attack_relation {relation!r} is not declared")
            continue

        if relation == "unmapped":
            local_id = observation.get("local_id") or ""
            if not local_id.startswith("EM-"):
                errors.append(f"{source_id}: unmapped observation needs a local EM- id")
            if local_id.startswith("T"):  # pragma: no cover - guarded by the above
                errors.append(f"{source_id}: local id must not be ATT&CK-shaped")
            if not observation.get("rationale"):
                errors.append(f"{source_id}: unmapped observation needs a rationale")
            if observation.get("attack_id"):
                errors.append(f"{source_id}: unmapped observation must not carry an attack_id")
            continue

        attack_id = observation.get("attack_id") or ""
        entry = enrich_technique(attack_id)
        if not entry:
            errors.append(f"{source_id}: {attack_id or '(missing)'} is not in the local ATT&CK release")
            continue
        if observation.get("matrix") != entry.get("matrix"):
            errors.append(
                f"{source_id}: {attack_id} is {entry.get('matrix')} in the local release, "
                f"recorded as {observation.get('matrix')!r}"
            )
        if relation == "adjacent":
            if observation.get("relation_kind") not in RELATION_KINDS:
                errors.append(f"{source_id}: {attack_id} adjacent without a declared relation_kind")
            if not observation.get("rationale"):
                errors.append(f"{source_id}: {attack_id} adjacent without a rationale")
    return errors


def _reset() -> None:
    """Drop the cache. For tests that write a temporary library."""
    get_library.cache_clear()
