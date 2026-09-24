"""Grounding for detection drafts: actor evidence and the assessment tuple.

Stage G1 (designer plan section 4 and its expandable tuple in section 5), the
deterministic half: what the local ATT&CK data actually documents about this
actor and technique, and what the path itself says about access.

Three claims are kept apart here and must stay apart downstream:

* **Documented actor behaviour** - a procedure or software mapping in the local
  reference data.
* **Modelled placement** - that the supplied path applies the behaviour to this
  component. The projector asserted it; this module never re-decides it.
* **Detection inference** - what would be observable. Not this module's job.

Nothing here calls a model, and nothing here rewrites an export value. The
export's own ``actor_support`` is untouched: it can legitimately read
``procedure_documented`` on a node whose contextual ``actor_evidence`` is
false, because the first is about the technique and the second about this
technique against this target class.
"""

from __future__ import annotations

import hashlib
from typing import Any

from framework.reference_data.mitre_attack import (
    attack_version,
    get_mitre_relationships,
    procedures_for_technique,
    software_for_technique,
    techniques_for_group,
)

ASSESSMENT_VERSION = "1.0"

# How many procedure candidates a node carries. The draft cites evidence; it
# does not reproduce the corpus.
MAX_PROCEDURES = 3

# actor_evidence reason codes.
ACTOR_DIRECT = "group_technique_documented"
ACTOR_VIA_SOFTWARE = "software_technique_documented"
ACTOR_NOT_ESTABLISHED = "not_established_in_local_sources"
ACTOR_NO_ACTOR_ID = "no_actor_attack_id_in_export"

# multistep_access reason codes.
ACCESS_STATE_GAP = "inherited_state_gap"
ACCESS_UNDECLARED_TRANSITION = "undeclared_transition"
ACCESS_MODELLED_SOURCE = "access_state_modelled_not_declared"
ACCESS_SATISFIED = "predecessors_supply_required_access"


def _digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def actor_software(actor_attack_id: str) -> list[str]:
    group = get_mitre_relationships().get("groups", {}).get(actor_attack_id) or {}
    return list(group.get("software") or [])


def procedure_evidence(technique_id: str, actor_attack_id: str) -> list[dict[str, Any]]:
    """Local procedure examples for this technique, actor's own ones first.

    Each entry carries its source id and a content hash. The local corpus has
    no report URL, so a draft may cite the ATT&CK page as an index reference
    and must not present it as a recovered original report citation.
    """
    own = procedures_for_technique(technique_id, actor_attack_id) if actor_attack_id else []
    software_ids = set(actor_software(actor_attack_id)) if actor_attack_id else set()
    via_software = [
        procedure
        for procedure in procedures_for_technique(technique_id)
        if procedure.get("source") in software_ids
    ]
    entries: list[dict[str, Any]] = []
    for procedure, relation in [(p, "actor") for p in own] + [
        (p, "software") for p in via_software
    ]:
        text = procedure.get("text", "")
        entries.append(
            {
                "source_id": procedure.get("source"),
                "relation": relation,
                "text": text,
                "content_sha256": _digest(text),
                "index_reference": f"https://attack.mitre.org/techniques/{technique_id}/",
                "provenance_limitation": (
                    "local ATT&CK corpus carries no original report URL; the link "
                    "is an index reference, not a recovered citation"
                ),
            }
        )
        if len(entries) >= MAX_PROCEDURES:
            break
    return entries


def assess_actor_evidence(
    technique_id: str, actor_attack_id: str, procedures: list[dict[str, Any]]
) -> dict[str, Any]:
    """Does the local data document *this actor* using *this technique*?

    Deliberately narrow: it answers the association, not whether the actor has
    ever attacked this product. A false here is "not established in the
    reviewed sources", which is not the same as "the actor never does this" -
    the reason code says which.

    **What this cannot discriminate yet.** On a projector-sourced pack it is
    true on every node - 43 of 43 across the fixture corpus - because the
    projector only builds a path from techniques already mapped to the actor.
    The constraint is applied upstream, so re-checking it locally re-derives
    the same answer, exactly as section 1.4b found for mitigation filtering.
    The judgment that actually bites is the technique-on-*target-class* fit
    ("valid accounts against VPNs does not document Kafka service
    credentials"), which needs reasoning the local corpus cannot supply. That
    belongs to generation, which may set this false with its own basis; this
    function establishes the floor and never the ceiling.
    """
    if not actor_attack_id:
        return _element(False, ACTOR_NO_ACTOR_ID, basis="", warning=True)

    if technique_id in techniques_for_group(actor_attack_id):
        return _element(
            True,
            ACTOR_DIRECT,
            basis=f"{actor_attack_id} documented for {technique_id}",
            support="direct",
            procedures=[p["source_id"] for p in procedures if p["relation"] == "actor"],
        )

    shared = sorted(set(software_for_technique(technique_id)) & set(actor_software(actor_attack_id)))
    if shared:
        return _element(
            True,
            ACTOR_VIA_SOFTWARE,
            basis=f"via associated software {', '.join(shared)}",
            support="via_software",
            procedures=shared,
        )

    return _element(
        False,
        ACTOR_NOT_ESTABLISHED,
        basis=(
            f"{technique_id} is not mapped to {actor_attack_id} or its associated "
            "software in the local ATT&CK release; absence from this corpus does "
            "not establish that the actor never uses it"
        ),
        warning=True,
    )


def assess_multistep_access(fields: dict[str, Any]) -> dict[str, Any]:
    """Does this node depend on access no earlier step establishes?

    True is the cautious answer and the warning condition. An inherited state
    gap can never be argued away here: the projector already found that the
    path depends on a component acting for the attacker.

    ``access_source: model`` is **not** a trigger, though it looks like one.
    Every node of every fixture carries it - the projector models the access
    chain rather than reading it from an estate - so triggering on it made the
    element true 43 times out of 43, which is a constant, not an assessment.
    It is recorded as a qualifier on the element instead, so a reviewer still
    sees that the access chain was inferred.
    """
    reasons: list[str] = []
    if (fields.get("state_check") or "") == "gap":
        reasons.append(ACCESS_STATE_GAP)
    if (fields.get("transition") or {}).get("movement") == "undeclared":
        reasons.append(ACCESS_UNDECLARED_TRANSITION)

    qualifier = (
        ACCESS_MODELLED_SOURCE if fields.get("access_source") == "model" else None
    )
    if not reasons:
        element = _element(False, ACCESS_SATISFIED, basis=fields.get("state_note") or "")
    else:
        element = _element(
            True, *reasons, basis=fields.get("state_note") or "", warning=True
        )
    if qualifier:
        element["qualifiers"] = [qualifier]
    return element


def _element(
    value: bool,
    *reason_codes: str,
    basis: str = "",
    support: str | None = None,
    procedures: list[str] | None = None,
    warning: bool = False,
) -> dict[str, Any]:
    element: dict[str, Any] = {
        "value": value,
        "reason_codes": list(reason_codes),
        "basis": basis,
        "warning": warning,
    }
    if support is not None:
        element["support"] = support
    if procedures is not None:
        element["source_ids"] = procedures
    return element


def assess_node(fields: dict[str, Any], actor_attack_id: str) -> dict[str, Any]:
    """The versioned, expandable tuple required on every node.

    A named mapping, never a positional array: adding an element later must
    not shift what the existing ones mean.
    """
    technique_id = fields.get("technique_id") or ""
    procedures = procedure_evidence(technique_id, actor_attack_id)
    return {
        "version": ASSESSMENT_VERSION,
        "attack_version": attack_version(),
        "tuple": {
            "actor_evidence": assess_actor_evidence(
                technique_id, actor_attack_id, procedures
            ),
            "multistep_access": assess_multistep_access(fields),
        },
        "procedure_evidence": procedures,
    }
