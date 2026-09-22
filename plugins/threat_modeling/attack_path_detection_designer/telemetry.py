"""Stage G1a: what could be observed at a node.

Joins the shared telemetry reference library
(``framework/reference_data/telemetry_library.py``, specified in
``docs/specs/telemetry_reference_library.md``) to a normalized node.

Two rules from the specification are load-bearing here:

* **Component first, behaviour second, technique last.** A badge reader is
  unreachable from a technique, so the technique never leads. The library is
  matched on the flow map's component - which is why telemetry only becomes
  useful at ``component_bound`` or ``component_bound_partial``.
* **``telemetry_readiness`` is a separate axis from ``context_completeness``.**
  A node can be ``component_bound`` with nothing observable, or
  ``asset_named`` with an excellent badge feed. Folding the two into one word
  would repeat the ``uncovered_mitigations`` misreading exactly.

The physical rule is the one that needed a convention: a hop whose protocol is
``physical`` draws physical sources, because no amount of network telemetry
observes a person walking through a door. It keys on the reserved protocol
spelling registered in ``docs/specs/reserved_vocabulary.md``.
"""

from __future__ import annotations

from typing import Any

from framework.reference_data.telemetry_library import (
    all_sources,
    library_version,
    sources_for_component,
)

# Reserved protocol spellings whose evidence is physical, not network.
PHYSICAL_PROTOCOLS = ("physical",)

# Out-of-band carriers: reachable, and invisible to every estate egress point.
OUT_OF_BAND_PROTOCOLS = ("lte", "cellular")

PHYSICAL_NAMESPACE = "EM-PHYS-"

READINESS_NONE = "none_declared"
READINESS_PERIODIC = "periodic_only"
READINESS_STREAM = "stream_available"

# Why a source was attached, kept on each candidate so a draft can be audited.
MATCH_TECHNOLOGY = "component_technology"
MATCH_COMPONENT_TYPE = "component_type"
MATCH_PHYSICAL = "physical_hop"


def physical_sources() -> list[dict[str, Any]]:
    """Library entries that observe a physical behaviour."""
    return [
        source
        for source in all_sources()
        if any(
            str(observation.get("local_id", "")).startswith(PHYSICAL_NAMESPACE)
            for observation in source.get("observes") or []
        )
    ]


def estate_key(flow_map_filename: str | None) -> str | None:
    """The estate a supplied map describes, from its filename.

    Only meaningful for the seed library, which carries five example estates
    in one file. A real deployment's library holds one estate and this returns
    None, which keeps every entry in play.
    """
    if not flow_map_filename:
        return None
    name = flow_map_filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if name.endswith("_flow_map.json"):
        return name[: -len("_flow_map.json")]
    return None


def candidates_for_node(
    fields: dict[str, Any],
    component_type: str | None = None,
    estate: str | None = None,
) -> list[dict[str, Any]]:
    """Library entries that could observe this node, with why each matched.

    A physical hop replaces the technology match rather than extending it: the
    wall port's technology is ``ethernet-wall-port``, and matching network
    sources on it would offer a packet capture for a person in a corridor.
    """
    transition = fields.get("transition") or {}
    protocol = str(transition.get("protocol") or "").lower()

    if protocol in PHYSICAL_PROTOCOLS:
        return [_candidate(s, MATCH_PHYSICAL) for s in physical_sources()]

    technologies = fields.get("technologies") or []
    matched = sources_for_component(technologies, component_type, estate)
    out: list[dict[str, Any]] = []
    for source in matched:
        declared = {t.lower() for t in (source.get("applies_to") or {}).get("technologies") or []}
        reason = MATCH_TECHNOLOGY if declared else MATCH_COMPONENT_TYPE
        out.append(_candidate(source, reason))
    return out


def _candidate(source: dict[str, Any], matched_on: str) -> dict[str, Any]:
    """The subset of a library entry a draft needs, never the whole entry."""
    availability = source.get("availability") or {}
    collection = source.get("collection") or {}
    return {
        "source_id": source["source_id"],
        "name": source.get("name"),
        "category": source.get("category"),
        "matched_on": matched_on,
        "necessity": collection.get("necessity"),
        "collection_status": collection.get("status"),
        "prerequisites": collection.get("prerequisites") or [],
        "artefact": availability.get("artefact"),
        "cadence": availability.get("cadence"),
        "latency": availability.get("latency"),
        "owner": availability.get("owner"),
        "control_function": (source.get("control_function") or {}).get("domain"),
        "supports": source.get("supports") or [],
        "observes": source.get("observes") or [],
        # The fields a draft may name. Withholding these while still passing
        # `absent_without_enrichment` told a model what each source lacks and
        # never what it has, and the first live run on the annotated build
        # invented all 14 of its field names while copying `prerequisites`
        # verbatim - it used what it was given and fabricated the rest. The
        # `derived` entries are the library's purpose-built indicators, so
        # withholding them cost the drafts the best field each source offers.
        "fields": {
            "native": list((source.get("fields") or {}).get("native") or []),
            "derived": list((source.get("fields") or {}).get("derived") or []),
        },
        "absent_without_enrichment": (source.get("fields") or {}).get(
            "absent_without_enrichment"
        )
        or [],
    }


def readiness(candidates: list[dict[str, Any]]) -> str:
    """What kind of evidence exists, independent of how bound the node is.

    ``periodic_only`` is the honest answer for an estate whose best control is
    a quarterly audit: something would eventually be observed, but a draft
    claiming near-real-time detection from it would be false.
    """
    if not candidates:
        return READINESS_NONE
    detecting = [c for c in candidates if c["control_function"] != "decision_support"]
    if not detecting:
        return READINESS_NONE
    if any(
        c["cadence"] == "continuous" and c["artefact"] == "machine_readable"
        for c in detecting
    ):
        return READINESS_STREAM
    return READINESS_PERIODIC


def telemetry_requirements(candidates: list[dict[str, Any]]) -> list[str]:
    """What must be true before any of this is actually collectable."""
    notes: list[str] = []
    for candidate in candidates:
        if candidate["collection_status"] in ("missing", "unknown"):
            notes.append(
                f"{candidate['source_id']}: collection status "
                f"{candidate['collection_status']} - confirm before a draft relies on it"
            )
        if candidate["control_function"] == "decision_support":
            notes.append(
                f"{candidate['source_id']}: decision support - it makes another "
                "control judgeable and detects nothing on its own"
            )
        if candidate["cadence"] not in ("continuous", None):
            notes.append(
                f"{candidate['source_id']}: {candidate['cadence']} evidence "
                f"(latency {candidate['latency']}) - not a stream"
            )
    return notes


def attach(
    fields: dict[str, Any],
    component_type: str | None = None,
    flow_map_filename: str | None = None,
) -> dict[str, Any]:
    """The whole G1a contribution for one node, as fields to record."""
    candidates = candidates_for_node(fields, component_type, estate_key(flow_map_filename))
    transition = fields.get("transition") or {}
    protocol = str(transition.get("protocol") or "").lower()
    return {
        "telemetry_candidates": candidates,
        "telemetry_readiness": readiness(candidates),
        "telemetry_notes": telemetry_requirements(candidates),
        "telemetry_library_version": library_version(),
        "observation_medium": (
            "physical"
            if protocol in PHYSICAL_PROTOCOLS
            else "out_of_band"
            if protocol in OUT_OF_BAND_PROTOCOLS
            else "network"
        ),
    }
