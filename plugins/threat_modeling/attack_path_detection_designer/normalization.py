"""Normalization of adversary path projector exports into node contexts.

Stage N1 of ``docs/specs/attack_path_detection_normalization.md``: adapters for
the three input shapes, the three identities of section 4.2a, the node
occurrence key, a deterministic ``draft_id``, and the union merge with the
section 4.3 precedence table.

Stage N2 adds flow-map lineage: a supplied map is hashed, compared with the
export's ``flow_map_sha256`` and checked for fit, but never refused, because a
map is an analyst-editable working document (spec decision 9). It also closes
the warning and review-flag codes into the section 4.4 catalogue.

No LLM, no network. Enrichment and grading are stage N3; the
``normalize_paths`` action and the context pack artifact are stage N4.

This module is plugin-local by decision 7 of the spec. It is loaded as a
sibling of ``tool.py`` by file location, because the loader imports a plugin
under a flat module name and there is no package to import from.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The one framework import: reference data is cross-cutting infrastructure and
# is how every plugin reaches ATT&CK. Nothing detection-specific lives there.
from framework.reference_data.mitre_attack import (
    canonical_tactic,
    enrich_technique,
    get_mitre_relationships,
    is_legacy_tactic,
    resolve_legacy_tactic,
    resolve_retired_technique,
)


def _load_plugin_module(filename: str, alias: str):
    """Load the sibling module by file location.

    Same reason as `tool.py`'s `_load_sibling`: the loader gives a plugin a
    flat module name and no package, so `import grounding` cannot find it.
    """
    if alias in sys.modules:
        return sys.modules[alias]
    spec = importlib.util.spec_from_file_location(
        alias, Path(__file__).resolve().parent / filename
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


grounding = _load_plugin_module(
    "grounding.py", "attack_path_detection_designer_grounding"
)
telemetry = _load_plugin_module(
    "telemetry.py", "attack_path_detection_designer_telemetry"
)

# U+2014 EM DASH with one space either side. The seed joins state_check and
# state_note with exactly this; a hyphen or en dash is a different string and
# turns every gap node into a spurious conflict.
STATE_NOTE_SEPARATOR = " — "

GRAPH_ROLE = "graph"
SEED_ROLE = "seed"
SCENARIO_ROLE = "scenario"

# Origins recorded in provenance_by_field.
ORIGIN_GRAPH = "graph"
ORIGIN_SEED = "seed"
ORIGIN_PAIR_AGREED = "pair_agreed"
ORIGIN_DERIVED = "derived"
ORIGIN_FLOW_MAP = "flow_map"
ORIGIN_REFERENCE = "reference_data"

# Local ATT&CK files, named in provenance so a resolved name is never mistaken
# for something a model supplied.
RELATIONSHIPS_DOCUMENT = "mitre_relationships.json"
TECHNIQUES_DOCUMENT = "mitre_techniques.json"
TELEMETRY_DOCUMENT = "telemetry_library.json"

# Section 1.4b: how many of the narrowest uncovered mitigations generation sees.
MITIGATION_FOCUS_LIMIT = 2

# Context completeness, section 5. The grade limits what a later draft may
# claim, so it is a property of the inputs supplied and not of the export.
GRADE_COMPONENT_BOUND = "component_bound"
GRADE_COMPONENT_BOUND_PARTIAL = "component_bound_partial"
GRADE_ASSET_NAMED = "asset_named"
GRADE_ASSET_TEXT_ONLY = "asset_text_only"
GRADE_UNBOUND = "unbound"

# A control that observes nothing cannot support a monitoring claim.
_CAPABILITY_CLAIMS = ("medium", "high")

# Fields each document alone carries, section 1.3. Precedence rules 1 and 2
# are these two lists; rule 3 is everything in SHARED_FIELDS.
GRAPH_ONLY_FIELDS = (
    "component_id",
    "asset_name",
    "technique_name",
    "rationale",
    "expected_result",
    "access_before",
    "access_after",
    "notes",
    "leads_to",
    "controls_in_play",
    "mitigations",
    "uncovered_mitigations",
)
SEED_ONLY_FIELDS = (
    "source_event_id",
    "sequence_order",
    "access_source",
    "blocking_controls",
    "detecting_controls",
    "success_indicators",
    "behavior",
)
# Carried by both, and required to agree after canonicalization.
SHARED_FIELDS = (
    "technique_id",
    "tactic",
    "evidence",
    "actor_support",
    "procedure_excerpt",
    "precondition",
    "exploited_condition",
    "control_note",
    "assumptions",
)


SEVERITY_BLOCKING = "blocking"
SEVERITY_ADVISORY = "advisory"

# Section 4.4. Blocking: the output omits or downgrades something because of
# the condition. Advisory: the output is complete but needs a second look.
WARNING_CODES = {
    "PAIR_REFUSED": SEVERITY_BLOCKING,
    "PAIR_CONTENT_CONFLICT": SEVERITY_BLOCKING,
    "NODE_ONLY_IN_SECONDARY": SEVERITY_BLOCKING,
    "PATH_NOT_IN_BOTH": SEVERITY_ADVISORY,
    "PATH_LENGTH_DIFFERS": SEVERITY_ADVISORY,
    "STATE_NOTE_ENCODING": SEVERITY_ADVISORY,
    "FLOW_MAP_EDITED": SEVERITY_ADVISORY,
    "FLOW_MAP_UNHASHED": SEVERITY_ADVISORY,
    "FLOW_MAP_APPLICATION_MISMATCH": SEVERITY_ADVISORY,
    "FLOW_MAP_COMPONENT_UNRESOLVED": SEVERITY_BLOCKING,
    "MITIGATION_UNRESOLVED": SEVERITY_ADVISORY,
    "TACTIC_UNRESOLVED": SEVERITY_ADVISORY,
    "TECHNIQUE_RETIRED": SEVERITY_ADVISORY,
    "TECHNIQUE_UNRESOLVED": SEVERITY_ADVISORY,
}
REVIEW_FLAG_CODES = ("UNDECLARED_TRANSITION", "TRANSITION_UNPARSED")

# Flow map lineage, section 4.2. Recorded, never used to refuse a map.
LINEAGE_SAME = "same_map"
LINEAGE_EDITED = "edited_map"
LINEAGE_UNHASHED = "unhashed"


class NormalizationError(ValueError):
    """Raised when inputs cannot be normalized at all."""


def _warning(code: str, location: str, message: str) -> dict[str, str]:
    """A warning from the closed catalogue. An undeclared code is a bug."""
    return {
        "code": code,
        "severity": WARNING_CODES[code],
        "location": location,
        "message": message,
    }


def _review_flag(code: str, message: str) -> dict[str, str]:
    if code not in REVIEW_FLAG_CODES:
        raise KeyError(code)
    return {"code": code, "message": message}


# ---------------------------------------------------------------------------
# Canonical JSON and hashing
# ---------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    """Stable JSON text for hashing: sorted keys, no insignificant space."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Identity, section 4.2a
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArtifactIdentity:
    """Identity of one contributing document. Differs per document by design."""

    role: str
    filename: str
    content_sha256: str

    @property
    def value(self) -> str:
        return f"{self.role}:{self.filename}:{self.content_sha256[:16]}"

    def as_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "filename": self.filename,
            "content_sha256": self.content_sha256,
            "value": self.value,
        }


@dataclass(frozen=True)
class ProjectionIdentity:
    """Identity of one projection run, equal across that run's documents."""

    value: str
    status: str  # "verified" when from provenance.run_id, else "derived"

    @property
    def is_derived(self) -> bool:
        return self.status == "derived"

    def as_dict(self) -> dict[str, str]:
        return {"value": self.value, "status": self.status}


def artifact_identity(
    document: dict[str, Any], filename: str, role: str
) -> ArtifactIdentity:
    """Hash of the canonical document plus its filename and role."""
    return ArtifactIdentity(
        role=role,
        filename=filename,
        content_sha256=_sha256(canonical_json(document)),
    )


def projection_identity(document: dict[str, Any], role: str) -> ProjectionIdentity:
    """``provenance.run_id`` when present, otherwise a run-invariant digest.

    The digest deliberately excludes filenames, timestamps and role, so a
    graph and a seed of the same projection derive the same value. It covers
    actor, actor ATT&CK id, application, ordered path ids and, per path, the
    ordered technique ids and asset names.
    """
    provenance = document.get("provenance")
    if isinstance(provenance, dict):
        run_id = provenance.get("run_id")
        if isinstance(run_id, str) and run_id:
            return ProjectionIdentity(value=run_id, status="verified")

    paths = _ordered_path_content(document, role)
    invariant = {
        "actor": document.get("actor"),
        "actor_attack_id": _provenance_get(document, "actor_attack_id"),
        "application": document.get("application"),
        "paths": paths,
    }
    return ProjectionIdentity(
        value=_sha256(canonical_json(invariant)), status="derived"
    )


def _ordered_path_content(document: dict[str, Any], role: str) -> list[dict[str, Any]]:
    """Run-invariant per-path content, read identically from either document."""
    out: list[dict[str, Any]] = []
    for path_id, steps in _iter_raw_paths(document, role):
        out.append(
            {
                "path_id": path_id,
                "technique_ids": [s.get("technique_id") for s in steps],
                "assets": [_asset_name(s, role) for s in steps],
            }
        )
    return out


def _asset_name(step: dict[str, Any], role: str) -> Any:
    return step.get("asset") if role == GRAPH_ROLE else step.get("target_asset")


def _iter_raw_paths(
    document: dict[str, Any], role: str
) -> list[tuple[str, list[dict]]]:
    if role == GRAPH_ROLE:
        graph = document.get("attack_graph") or {}
        return [
            (p.get("path_id"), p.get("steps") or [])
            for p in graph.get("paths") or []
        ]
    return [
        (s.get("path_id"), s.get("attack_sequence") or [])
        for s in document.get("scenarios") or []
    ]


def _provenance_get(document: dict[str, Any], key: str) -> Any:
    provenance = document.get("provenance")
    if isinstance(provenance, dict):
        return provenance.get(key)
    return None


def draft_id(projection: ProjectionIdentity, path_id: str, node_index: int) -> str:
    """Deterministic id derived from the occurrence key alone.

    It must not incorporate an artifact identity: the determinism rule in
    section 7 requires the same id whether a node arrived from the graph, the
    seed or both.
    """
    digest = _sha256(f"{projection.value}|{path_id}|{node_index}")
    return f"drf_{digest[:16]}"


def node_key(
    projection: ProjectionIdentity, path_id: str, node_index: int
) -> tuple[str, str, int]:
    return (projection.value, path_id, node_index)


# ---------------------------------------------------------------------------
# Canonicalization, section 4.3 rule 3a
# ---------------------------------------------------------------------------

def split_state_check(combined: str | None) -> tuple[str, str]:
    """Seed's combined string into the graph's two-field form."""
    if not combined:
        return "", ""
    if STATE_NOTE_SEPARATOR in combined:
        check, note = combined.split(STATE_NOTE_SEPARATOR, 1)
        return check.strip(), note.strip()
    return combined.strip(), ""


def join_state_check(check: str | None, note: str | None) -> str:
    """Graph's two fields into the seed's combined string."""
    check = (check or "").strip()
    note = (note or "").strip()
    if not note:
        return check
    return f"{check}{STATE_NOTE_SEPARATOR}{note}"


def looks_like_mangled_separator(combined: str | None) -> bool:
    """A separator the transport damaged, rather than a content disagreement.

    A dash-like character that is not U+2014 between two non-empty halves means
    the em dash did not survive the round trip. That is an encoding warning; it
    must never be reported as a content conflict on every gap node at once.
    """
    if not combined or STATE_NOTE_SEPARATOR in combined:
        return False
    return bool(re.search(r"\s[–‒‐-]\s", combined))


# The seed renders a transition as prose. Both readings are parsed back into
# the graph's field names and marked evidence: text, because the prose cannot
# carry crosses_boundary and must never outrank the object.
_SEED_FLOW_RE = re.compile(
    r"^(?P<ret>back over )?flow (?P<flow>\S+): (?P<from>\S+) -> (?P<to>\S+) "
    r"\((?P<protocol>[^,]+), (?P<auth>authenticated|unauthenticated)\)$"
)
_SEED_ENTRY_RE = re.compile(r"^entry point \((?P<exposure>[^)]*)-exposed\)$")


def canonical_transition(
    raw: Any,
    *,
    component_id: str | None,
    previous_component_id: str | None,
    source: str,
) -> dict[str, Any]:
    """One transition shape from either document, with a movement discriminator.

    ``null`` is two cases, not one: acting in place on a component already held
    is not missing data, and a component change with no declared flow is
    movement the flow map does not describe.
    """
    parsed: dict[str, Any] = {
        "movement": None,
        "flow_id": None,
        "from": None,
        "to": None,
        "protocol": None,
        "authenticated": None,
        "crosses_boundary": None,
        "exposure": None,
        "returns": None,
        "evidence": "structured" if source == GRAPH_ROLE else "text",
        "raw": raw if raw not in (None, "") else None,
    }

    if isinstance(raw, dict):
        if raw.get("entry"):
            parsed.update(movement="entry", exposure=raw.get("exposure"))
            return parsed
        if raw.get("flow"):
            parsed.update(
                movement="declared_flow",
                flow_id=raw.get("flow"),
                protocol=raw.get("protocol"),
                authenticated=raw.get("authenticated"),
                crosses_boundary=raw.get("crosses_boundary"),
                returns=bool(raw.get("return")),
            )
            parsed["from"] = raw.get("from")
            parsed["to"] = raw.get("to")
            return parsed
    elif isinstance(raw, str) and raw:
        entry = _SEED_ENTRY_RE.match(raw)
        if entry:
            parsed.update(movement="entry", exposure=entry.group("exposure"))
            return parsed
        flow = _SEED_FLOW_RE.match(raw)
        if flow:
            parsed.update(
                movement="declared_flow",
                flow_id=flow.group("flow"),
                protocol=flow.group("protocol"),
                authenticated=flow.group("auth") == "authenticated",
                returns=bool(flow.group("ret")),
            )
            parsed["from"] = flow.group("from")
            parsed["to"] = flow.group("to")
            # crosses_boundary stays None: the prose does not carry it, and
            # guessing False would make an intra-zone flow and a boundary
            # crossing indistinguishable.
            return parsed
        parsed["movement"] = "unparsed"
        return parsed

    if previous_component_id is not None and component_id == previous_component_id:
        parsed["movement"] = "in_place"
    elif previous_component_id is None:
        # No predecessor and no transition object: nothing to compare against.
        parsed["movement"] = "undeclared"
    else:
        parsed["movement"] = "undeclared"
    return parsed


def transitions_agree(graph_form: dict[str, Any], seed_form: dict[str, Any]) -> bool:
    """Do the two representations describe the same movement?

    Only the fields the prose can carry are compared. ``crosses_boundary`` is
    absent from the seed by construction and is never a disagreement.
    """
    comparable = (
        "movement", "flow_id", "from", "to", "protocol", "authenticated", "exposure",
    )
    for field_name in comparable:
        seed_value = seed_form.get(field_name)
        if seed_value is None:
            continue
        if graph_form.get(field_name) != seed_value:
            return False
    return True


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

@dataclass
class SourceDocument:
    """One parsed input document with its identities."""

    document: dict[str, Any]
    role: str
    filename: str
    artifact: ArtifactIdentity
    projection: ProjectionIdentity

    @property
    def has_provenance(self) -> bool:
        return isinstance(self.document.get("provenance"), dict)


@dataclass
class AdaptedNode:
    """One node as read from one document, before any merge."""

    path_id: str
    node_index: int
    fields: dict[str, Any]
    pointers: dict[str, str]
    origin: str


@dataclass
class AdaptedDocument:
    source: SourceDocument
    nodes: list[AdaptedNode]
    paths: list[dict[str, Any]]
    engagement: dict[str, Any]
    warnings: list[dict[str, str]] = field(default_factory=list)


def load_document(
    document: dict[str, Any], filename: str, role: str | None = None
) -> SourceDocument:
    """Wrap a parsed export, inferring its role when not given."""
    role = role or infer_role(document)
    return SourceDocument(
        document=document,
        role=role,
        filename=filename,
        artifact=artifact_identity(document, filename, role),
        projection=projection_identity(document, role),
    )


def infer_role(document: dict[str, Any]) -> str:
    if isinstance(document.get("attack_graph"), dict):
        return GRAPH_ROLE
    if isinstance(document.get("scenarios"), list):
        return SEED_ROLE
    if isinstance(document.get("attack_sequence"), list):
        return SCENARIO_ROLE
    raise NormalizationError(
        "Unrecognized document: expected attack_graph, scenarios or attack_sequence"
    )


def adapt(source: SourceDocument) -> AdaptedDocument:
    """Read one document into ordered nodes with a JSON pointer per field."""
    if source.role == GRAPH_ROLE:
        return _adapt_graph(source)
    if source.role == SEED_ROLE:
        return _adapt_seed(source)
    return _adapt_single_scenario(source)


def _engagement(document: dict[str, Any]) -> dict[str, Any]:
    provenance = document.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    model = provenance.get("model")
    return {
        "actor_label": document.get("actor"),
        "actor_attack_id": provenance.get("actor_attack_id"),
        "application": document.get("application"),
        "attack_version": provenance.get("attack_version"),
        # Read model, never provider: there is no provenance.provider key, and
        # a normalizer looking for one records "no attribution" on an export
        # that carries full attribution.
        "model_attribution": dict(model) if isinstance(model, dict) else None,
        "model_attribution_present": isinstance(model, dict),
        "flow_map_path": provenance.get("flow_map_path"),
        "flow_map_sha256": provenance.get("flow_map_sha256"),
        "run_id": provenance.get("run_id"),
        "run_group": provenance.get("run_group"),
        "run_index": provenance.get("run_index"),
        "tool_version": provenance.get("tool_version"),
    }


def _adapt_graph(source: SourceDocument) -> AdaptedDocument:
    document = source.document
    graph = document.get("attack_graph") or {}
    nodes: list[AdaptedNode] = []
    paths: list[dict[str, Any]] = []

    for path_index, path in enumerate(graph.get("paths") or []):
        path_id = path.get("path_id")
        steps = path.get("steps") or []
        paths.append(
            {
                "path_id": path_id,
                "description": path.get("description"),
                "objective": path.get("objective"),
                "node_count": len(steps),
            }
        )
        previous_component: str | None = None
        for node_index, step in enumerate(steps):
            base = f"/attack_graph/paths/{path_index}/steps/{node_index}"
            component_id = step.get("component_id")
            fields: dict[str, Any] = {
                "technique_id": step.get("technique_id"),
                "technique_name": step.get("technique_name"),
                "tactic": step.get("tactic"),
                "component_id": component_id,
                "asset_name": step.get("asset"),
                "evidence": step.get("evidence"),
                "actor_support": step.get("actor_support"),
                "procedure_excerpt": step.get("procedure_excerpt"),
                "rationale": step.get("rationale"),
                "precondition": step.get("precondition"),
                "exploited_condition": step.get("exploited_condition"),
                "expected_result": step.get("result"),
                "access_before": step.get("access_before"),
                "access_after": step.get("access_after"),
                "assumptions": step.get("assumptions") or [],
                "control_note": step.get("control_note"),
                "controls_in_play": step.get("controls_in_play") or [],
                "mitigations": step.get("mitigations") or [],
                "uncovered_mitigations": step.get("uncovered_mitigations") or [],
                "notes": step.get("notes") or [],
                "leads_to": step.get("leads_to") or [],
                "state_check": step.get("state_check"),
                "state_note": step.get("state_note") or "",
                "transition": canonical_transition(
                    step.get("transition"),
                    component_id=component_id,
                    previous_component_id=previous_component,
                    source=GRAPH_ROLE,
                ),
            }
            pointers = {
                name: f"{base}/{_source_key(name, GRAPH_ROLE)}" for name in fields
            }
            nodes.append(
                AdaptedNode(
                    path_id=path_id,
                    node_index=node_index,
                    fields=fields,
                    pointers=pointers,
                    origin=ORIGIN_GRAPH,
                )
            )
            previous_component = component_id

    return AdaptedDocument(
        source=source, nodes=nodes, paths=paths, engagement=_engagement(document)
    )


def _adapt_seed(source: SourceDocument) -> AdaptedDocument:
    document = source.document
    nodes: list[AdaptedNode] = []
    paths: list[dict[str, Any]] = []
    warnings: list[dict[str, str]] = []

    for scenario_index, scenario in enumerate(document.get("scenarios") or []):
        nodes_for_scenario, path_record, scenario_warnings = _adapt_scenario(
            scenario, f"/scenarios/{scenario_index}"
        )
        nodes.extend(nodes_for_scenario)
        paths.append(path_record)
        warnings.extend(scenario_warnings)

    return AdaptedDocument(
        source=source,
        nodes=nodes,
        paths=paths,
        engagement=_engagement(document),
        warnings=warnings,
    )


def _adapt_single_scenario(source: SourceDocument) -> AdaptedDocument:
    nodes, path_record, warnings = _adapt_scenario(source.document, "")
    return AdaptedDocument(
        source=source,
        nodes=nodes,
        paths=[path_record],
        engagement=_engagement(source.document),
        warnings=warnings,
    )


def _adapt_scenario(
    scenario: dict[str, Any], base_pointer: str
) -> tuple[list[AdaptedNode], dict[str, Any], list[dict[str, str]]]:
    path_id = scenario.get("path_id")
    sequence = scenario.get("attack_sequence") or []
    warnings: list[dict[str, str]] = []
    nodes: list[AdaptedNode] = []
    previous_asset: str | None = None

    for node_index, event in enumerate(sequence):
        base = f"{base_pointer}/attack_sequence/{node_index}"
        combined = event.get("state_check")
        if looks_like_mangled_separator(combined):
            warnings.append(
                _warning(
                    "STATE_NOTE_ENCODING",
                    f"{path_id}.attack_sequence[{node_index}]",
                    "state_check separator is not U+2014; the transport did not "
                    "preserve the em dash, so the note cannot be split reliably",
                )
            )
        state_check, state_note = split_state_check(combined)
        asset_name = event.get("target_asset")
        fields: dict[str, Any] = {
            "technique_id": event.get("technique_id"),
            "tactic": event.get("tactic"),
            "asset_name": asset_name,
            "behavior": event.get("attack_technique"),
            "evidence": event.get("evidence"),
            "actor_support": event.get("actor_support"),
            "procedure_excerpt": event.get("procedure_excerpt"),
            "precondition": event.get("precondition"),
            "exploited_condition": event.get("exploited_condition"),
            "assumptions": event.get("assumptions") or [],
            "control_note": event.get("control_note"),
            "source_event_id": event.get("event_id"),
            "sequence_order": event.get("sequence_order"),
            "access_before": event.get("required_access"),
            "access_after": event.get("resulting_access"),
            "access_source": event.get("access_source"),
            "blocking_controls": event.get("blocking_controls") or [],
            "detecting_controls": event.get("detecting_controls") or [],
            "success_indicators": event.get("success_indicators") or [],
            "state_check": state_check,
            "state_note": state_note,
            "transition": canonical_transition(
                event.get("transition"),
                # The seed carries no component_id, so in-place cannot be
                # distinguished from undeclared here; the asset name is the
                # only positional handle it has.
                component_id=asset_name,
                previous_component_id=previous_asset,
                source=SEED_ROLE,
            ),
        }
        pointers = {name: f"{base}/{_source_key(name, SEED_ROLE)}" for name in fields}
        nodes.append(
            AdaptedNode(
                path_id=path_id,
                node_index=node_index,
                fields=fields,
                pointers=pointers,
                origin=ORIGIN_SEED,
            )
        )
        previous_asset = asset_name

    path_record = {
        "path_id": path_id,
        "description": scenario.get("description"),
        "objective": scenario.get("attack_objective"),
        "node_count": len(sequence),
        "control_catalogue": scenario.get("security_controls") or [],
    }
    return nodes, path_record, warnings


# Normalized name -> key in the source document, for JSON pointers.
_GRAPH_SOURCE_KEYS = {
    "asset_name": "asset",
    "expected_result": "result",
}
_SEED_SOURCE_KEYS = {
    "asset_name": "target_asset",
    "behavior": "attack_technique",
    "source_event_id": "event_id",
    "access_before": "required_access",
    "access_after": "resulting_access",
    "state_note": "state_check",
}


def _source_key(name: str, role: str) -> str:
    if role == GRAPH_ROLE:
        return _GRAPH_SOURCE_KEYS.get(name, name)
    return _SEED_SOURCE_KEYS.get(name, name)


# ---------------------------------------------------------------------------
# Pair gating, section 4.2
# ---------------------------------------------------------------------------

@dataclass
class PairDecision:
    """Whether two documents may be joined, and on what authority."""

    join: bool
    provenance_status: str
    pair_join: str
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "join": self.join,
            "provenance_status": self.provenance_status,
            "pair_join": self.pair_join,
            "reason": self.reason,
        }


def decide_pair(
    primary: SourceDocument,
    secondary: SourceDocument,
    *,
    accept_unverified_pair: bool = False,
) -> PairDecision:
    """Apply the section 4.2 table. Name matching never upgrades a status."""
    if primary.role == secondary.role:
        return PairDecision(
            False, "conflict", "refused",
            f"both documents are role '{primary.role}'; a pair is one graph "
            "and one seed",
        )

    both = primary.has_provenance and secondary.has_provenance
    neither = not primary.has_provenance and not secondary.has_provenance

    if both:
        if primary.projection.value == secondary.projection.value:
            return PairDecision(True, "verified", "run_id")
        return PairDecision(
            False, "conflict", "refused",
            "provenance run_id differs between the two documents",
        )

    if not neither:
        # One document carries provenance and the other does not. The single
        # run_id has nothing to be checked against, so the pair is refused
        # rather than half-trusted.
        return PairDecision(
            False, "conflict", "refused",
            "one document carries provenance and the other does not",
        )

    if primary.projection.value != secondary.projection.value:
        return PairDecision(
            False, "conflict", "refused",
            "derived projection identities differ; the documents describe "
            "different projections",
        )
    if not accept_unverified_pair:
        return PairDecision(
            False, "derived", "refused",
            "neither document carries provenance; pass accept_unverified_pair "
            "to join on derived identity",
        )
    return PairDecision(True, "derived", "asserted_by_operator")


# ---------------------------------------------------------------------------
# Flow map lineage, section 4.2 and decision 9
# ---------------------------------------------------------------------------

class FlowMapError(NormalizationError):
    """The supplied flow map is not a flow map at all."""


@dataclass
class FlowMapSource:
    """A supplied flow map with the hash the projector would have recorded."""

    document: dict[str, Any]
    filename: str
    sha256: str


def flow_map_hash(raw: Any) -> str:
    """The projector's ``_canonical_flow_map_hash``, reproduced.

    Plugins cannot import each other, so this is a second implementation of
    the same serialisation. The tests hold it to the ``flow_map_sha256`` the
    four fixture exports recorded against the repository maps, which fails the
    moment the two drift. Like the projector, it hashes the map as supplied,
    before any normalization.
    """
    return _sha256(canonical_json(raw))


def load_flow_map(document: Any, filename: str) -> FlowMapSource:
    if not isinstance(document, dict) or not isinstance(
        document.get("components"), list
    ):
        raise FlowMapError(
            f"{filename} is not a flow map: expected an object with a 'components' list"
        )
    return FlowMapSource(
        document=document, filename=filename, sha256=flow_map_hash(document)
    )


def assess_flow_map(
    flow_map: FlowMapSource | None,
    engagement: dict[str, Any],
    nodes: list[NormalizedNode],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Record where a supplied map came from and how well it fits the nodes.

    Nothing here refuses a map. The hash says whether this is the map the
    projection ran against; an analyst's edited copy is an expected input, not
    a conflict. The application and component checks are what say whether the
    map fits, and an unresolved component withholds enrichment from its own
    nodes only.
    """
    export_hash = engagement.get("flow_map_sha256") or None
    record: dict[str, Any] = {
        "supplied": flow_map is not None,
        "export_sha256": export_hash,
        "export_flow_map_path": engagement.get("flow_map_path"),
    }
    if flow_map is None:
        return record, []

    warnings: list[dict[str, str]] = []
    if export_hash is None:
        lineage = LINEAGE_UNHASHED
        warnings.append(
            _warning(
                "FLOW_MAP_UNHASHED",
                flow_map.filename,
                "the export records no flow map hash, so which map the projection "
                "used cannot be checked; supplying the map is taken as the "
                "operator's assertion",
            )
        )
    elif export_hash == flow_map.sha256:
        lineage = LINEAGE_SAME
    else:
        lineage = LINEAGE_EDITED
        warnings.append(
            _warning(
                "FLOW_MAP_EDITED",
                flow_map.filename,
                "the supplied map differs from the one the paths were projected "
                "against; it is used as given, but re-project if the edit changes "
                "topology or controls",
            )
        )

    map_application = flow_map.document.get("application")
    export_application = engagement.get("application")
    application_matches = map_application == export_application
    if not application_matches:
        warnings.append(
            _warning(
                "FLOW_MAP_APPLICATION_MISMATCH",
                flow_map.filename,
                f"map describes {map_application!r}, the export {export_application!r}; "
                "this is likelier the wrong map than an edited one",
            )
        )

    known = {
        component.get("id")
        for component in flow_map.document.get("components") or []
        if isinstance(component, dict)
    }
    nodes_per_component: dict[str, int] = {}
    for node in nodes:
        component_id = node.fields.get("component_id")
        if component_id:
            nodes_per_component[component_id] = (
                nodes_per_component.get(component_id, 0) + 1
            )
    resolved = [c for c in nodes_per_component if c in known]
    unresolved = [c for c in nodes_per_component if c not in known]
    for component_id in unresolved:
        warnings.append(
            _warning(
                "FLOW_MAP_COMPONENT_UNRESOLVED",
                component_id,
                f"component not in the supplied map; its "
                f"{nodes_per_component[component_id]} node(s) will not be enriched",
            )
        )

    record.update(
        filename=flow_map.filename,
        sha256=flow_map.sha256,
        lineage=lineage,
        application=map_application,
        application_matches=application_matches,
        components_resolved=resolved,
        components_unresolved=unresolved,
    )
    return record, warnings


# ---------------------------------------------------------------------------
# Union merge, section 4.3
# ---------------------------------------------------------------------------

@dataclass
class NormalizedNode:
    draft_id: str
    key: tuple[str, str, int]
    path_id: str
    node_index: int
    fields: dict[str, Any]
    provenance_by_field: dict[str, dict[str, str]]
    input_conflicts: list[dict[str, Any]] = field(default_factory=list)
    review_flags: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        out = dict(self.fields)
        out.update(
            draft_id=self.draft_id,
            path_id=self.path_id,
            node_index=self.node_index,
            provenance_by_field=self.provenance_by_field,
            input_conflicts=self.input_conflicts,
            review_flags=self.review_flags,
        )
        return out


@dataclass
class NormalizationResult:
    nodes: list[NormalizedNode]
    inventory: dict[str, Any]
    engagement: dict[str, Any]
    identities: dict[str, Any]
    pair: dict[str, Any]
    warnings: list[dict[str, str]]
    input_conflicts: list[dict[str, Any]]
    flow_map: dict[str, Any] = field(default_factory=dict)

    @property
    def node_keys(self) -> list[tuple[str, str, int]]:
        return [node.key for node in self.nodes]

    def as_dict(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory,
            "engagement": self.engagement,
            "identities": self.identities,
            "pair": self.pair,
            "flow_map": self.flow_map,
            "nodes": [node.as_dict() for node in self.nodes],
            "warnings": self.warnings,
            "input_conflicts": self.input_conflicts,
        }


def normalize(
    primary: SourceDocument,
    secondary: SourceDocument | None = None,
    *,
    accept_unverified_pair: bool = False,
    flow_map: FlowMapSource | None = None,
) -> NormalizationResult:
    """Normalize one document, or a graph and seed of the same projection.

    A refused pair is not an error: the primary source is processed alone and
    the refusal is reported, because half a join is worse than none. A flow
    map is assessed for lineage and fit only; enrichment from it is stage N3.
    """
    warnings: list[dict[str, str]] = []
    pair_decision = PairDecision(False, "single_source", "not_attempted")

    if secondary is not None:
        pair_decision = decide_pair(
            primary, secondary, accept_unverified_pair=accept_unverified_pair
        )
        if not pair_decision.join:
            warnings.append(
                _warning(
                    "PAIR_REFUSED",
                    secondary.filename,
                    pair_decision.reason or "pair join refused",
                )
            )
            secondary = None

    primary_doc = adapt(primary)
    warnings.extend(primary_doc.warnings)
    secondary_doc = None
    if secondary is not None:
        secondary_doc = adapt(secondary)
        warnings.extend(secondary_doc.warnings)

    graph_doc = _document_with_role(primary_doc, secondary_doc, GRAPH_ROLE)
    other_doc = secondary_doc if graph_doc is primary_doc else primary_doc
    if graph_doc is None:
        # No graph in play: the seed (or single scenario) leads.
        graph_doc = primary_doc
        other_doc = secondary_doc

    projection = primary.projection
    nodes: list[NormalizedNode] = []
    conflicts: list[dict[str, Any]] = []

    leader = graph_doc
    follower = other_doc if other_doc is not graph_doc else None
    follower_by_key = (
        {(n.path_id, n.node_index): n for n in follower.nodes} if follower else {}
    )
    leader_keys = {(n.path_id, n.node_index) for n in leader.nodes}

    if follower:
        _check_path_alignment(leader, follower, warnings)

    for node in leader.nodes:
        counterpart = follower_by_key.get((node.path_id, node.node_index))
        merged, node_conflicts, flags = _merge_node(
            node,
            counterpart,
            leader.source,
            follower.source if follower else None,
        )
        conflicts.extend(node_conflicts)
        nodes.append(
            NormalizedNode(
                draft_id=draft_id(projection, node.path_id, node.node_index),
                key=node_key(projection, node.path_id, node.node_index),
                path_id=node.path_id,
                node_index=node.node_index,
                fields=merged["fields"],
                provenance_by_field=merged["provenance_by_field"],
                input_conflicts=node_conflicts,
                review_flags=flags,
            )
        )

    if follower:
        for key in sorted(set(follower_by_key) - leader_keys):
            warnings.append(
                _warning(
                    "NODE_ONLY_IN_SECONDARY",
                    f"{key[0]}.steps[{key[1]}]",
                    "node present in the secondary document only; not merged",
                )
            )

    engagement = dict(leader.engagement)
    if follower:
        for name, value in follower.engagement.items():
            if engagement.get(name) in (None, "", [], {}):
                engagement[name] = value

    identities = {
        "projection_identity": projection.as_dict(),
        "artifact_identity": [
            d.source.artifact.as_dict() for d in (leader, follower) if d
        ],
        "node_key_form": "(projection_identity, path_id, node_index)",
    }
    inventory = {
        "paths": leader.paths,
        "node_count": len(nodes),
        "expected_node_keys": [list(node.key) for node in nodes],
        "sources": [
            {
                "role": d.source.role,
                "filename": d.source.filename,
                "node_count": len(d.nodes),
            }
            for d in (leader, follower)
            if d
        ],
    }

    pair = pair_decision.as_dict()
    # Rule 3: a field both documents carry, disagreeing after canonicalization,
    # blocks the join from being reported verified. The provenance is still
    # whatever it was — what disagreed is content, not identity — so the two
    # are reported separately rather than collapsing one into the other.
    pair["content_conflicts"] = len(conflicts)
    pair["verified"] = bool(pair_decision.join and not conflicts)
    if conflicts:
        warnings.append(
            _warning(
                "PAIR_CONTENT_CONFLICT",
                primary.filename,
                f"{len(conflicts)} field(s) disagree between the paired documents "
                "after canonicalization; the graph value is kept and the join is "
                "not reported verified",
            )
        )

    flow_map_record, flow_map_warnings = assess_flow_map(flow_map, engagement, nodes)
    warnings.extend(flow_map_warnings)

    components = _component_index(flow_map)
    catalogues = _catalogue_by_path(leader, follower)
    catalogue_source = _catalogue_source(leader, follower)
    lineage = flow_map_record.get("lineage")
    tag_caveat = flow_map_tag_caveat(flow_map, components, nodes, lineage)
    caveat_reason = (
        "no flow map supplied; control tagging cannot be counted, so this is "
        "not evidence that controls are untagged"
    )
    for node in nodes:
        component_id = node.fields.get("component_id")
        component, component_index = components.get(component_id, (None, None))
        before = len(node.input_conflicts)
        enrich_node(
            node,
            component,
            component_index,
            flow_map,
            lineage,
            catalogues.get(node.path_id, []),
            catalogue_source,
        )
        # Appended after the pair statistics above: a map disagreeing with an
        # export is not the two documents disagreeing with each other.
        conflicts.extend(node.input_conflicts[before:])
        warnings.extend(resolve_mitigations(node, tag_caveat, caveat_reason))
        warnings.extend(reconcile_taxonomy(node))
        ground_node(node, engagement.get("actor_attack_id") or "")
        attach_telemetry(node, (component or {}).get("type"))

    inventory["completeness"] = _grade_distribution(nodes)
    inventory["mitigation_coverage"] = _coverage_totals(nodes)
    inventory["taxonomy"] = _taxonomy_distribution(nodes)

    return NormalizationResult(
        nodes=nodes,
        inventory=inventory,
        engagement=engagement,
        identities=identities,
        pair=pair,
        warnings=warnings,
        input_conflicts=conflicts,
        flow_map=flow_map_record,
    )


def _component_index(
    flow_map: FlowMapSource | None,
) -> dict[Any, tuple[dict[str, Any], int]]:
    if flow_map is None:
        return {}
    return {
        component.get("id"): (component, index)
        for index, component in enumerate(flow_map.document.get("components") or [])
        if isinstance(component, dict)
    }


def _catalogue_by_path(
    leader: AdaptedDocument, follower: AdaptedDocument | None
) -> dict[str, list[dict[str, Any]]]:
    """The seed carries the control catalogue, one per scenario."""
    catalogues: dict[str, list[dict[str, Any]]] = {}
    for document in (leader, follower):
        if document is None:
            continue
        for path in document.paths:
            entries = path.get("control_catalogue") or []
            if entries:
                catalogues[path["path_id"]] = entries
    return catalogues


def _catalogue_source(
    leader: AdaptedDocument, follower: AdaptedDocument | None
) -> SourceDocument | None:
    for document in (leader, follower):
        if document is not None and document.source.role in (SEED_ROLE, SCENARIO_ROLE):
            return document.source
    return None


def _grade_distribution(nodes: list[NormalizedNode]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for node in nodes:
        grade = node.fields.get("context_completeness")
        distribution[grade] = distribution.get(grade, 0) + 1
    return dict(sorted(distribution.items()))


def digest_lines(result: NormalizationResult) -> list[str]:
    """A three-line-per-node reading of the pack, for a person.

    A troubleshooting aid, not a deliverable: the pack is machine-facing and
    58% of it is the per-field audit trail nobody reads in bulk. This says
    what each node is, what may be claimed about it, and what is doubtful -
    at a glance, and with no model involved.
    """
    lines: list[str] = []
    for node in result.nodes:
        fields = node.fields
        technique = f"{fields.get('technique_id')} {fields.get('technique_name') or ''}"
        lines.append(
            f"{node.path_id}  {node.node_index}  {technique.strip()}  "
            f"{fields.get('component_id') or fields.get('asset_name') or '(unbound)'}"
        )

        detail = [str(fields.get("context_completeness"))]
        technologies = fields.get("technologies")
        if technologies:
            detail.append("/".join(technologies))
        if fields.get("crown_jewel"):
            detail.append("crown jewel")
        detail.append(f"monitoring {fields.get('monitoring_claim')}")
        # The best predictor of whether a draft can say anything concrete.
        readiness = fields.get("telemetry_readiness")
        if readiness:
            detail.append(
                f"telemetry {readiness}"
                f" ({len(fields.get('telemetry_candidates') or [])})"
            )
        if (fields.get("state_check") or "") == "gap":
            detail.append("state gap")
        assessment = (fields.get("assessment") or {}).get("tuple") or {}
        for name in ("actor_evidence", "multistep_access"):
            element = assessment.get(name) or {}
            if element.get("warning"):
                detail.append(f"{name}={str(element.get('value')).lower()} ?")
        lines.append("  " + " | ".join(detail))

        focus = fields.get("mitigation_focus") or []
        lines.append(
            "  focus: "
            + (
                ", ".join(
                    f"{m['m_id']} {m['name']} ({m['technique_breadth']})" for m in focus
                )
                or "none narrow enough"
            )
        )
    return lines


def _coverage_totals(nodes: list[NormalizedNode]) -> dict[str, Any]:
    """Estate-level mitigation counts, for the summary and the N4 pack."""
    unresolved: list[str] = []
    covered = total = with_focus = 0
    for node in nodes:
        coverage = node.fields.get("mitigation_coverage") or {}
        covered += coverage.get("covered", 0)
        total += coverage.get("total", 0)
        with_focus += 1 if node.fields.get("mitigation_focus") else 0
        for m_id in coverage.get("unresolved") or []:
            if m_id not in unresolved:
                unresolved.append(m_id)
    return {
        "covered": covered,
        "total": total,
        "nodes_with_focus": with_focus,
        "unresolved": sorted(unresolved),
    }


def _taxonomy_distribution(nodes: list[NormalizedNode]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for node in nodes:
        for name in ("technique_status", "tactic_status"):
            value = node.fields.get(name)
            if value:
                key = f"{name.split('_')[0]}:{value}"
                distribution[key] = distribution.get(key, 0) + 1
    return dict(sorted(distribution.items()))


def _document_with_role(
    first: AdaptedDocument, second: AdaptedDocument | None, role: str
) -> AdaptedDocument | None:
    for document in (first, second):
        if document is not None and document.source.role == role:
            return document
    return None


def _check_path_alignment(
    leader: AdaptedDocument, follower: AdaptedDocument, warnings: list[dict[str, str]]
) -> None:
    leader_paths = {p["path_id"]: p["node_count"] for p in leader.paths}
    follower_paths = {p["path_id"]: p["node_count"] for p in follower.paths}
    for path_id in sorted(set(leader_paths) ^ set(follower_paths)):
        warnings.append(
            _warning(
                "PATH_NOT_IN_BOTH", str(path_id), "path present in one document only"
            )
        )
    for path_id in sorted(set(leader_paths) & set(follower_paths)):
        if leader_paths[path_id] != follower_paths[path_id]:
            warnings.append(
                _warning(
                    "PATH_LENGTH_DIFFERS",
                    str(path_id),
                    f"{leader_paths[path_id]} nodes in {leader.source.role}, "
                    f"{follower_paths[path_id]} in {follower.source.role}",
                )
            )


def _merge_node(
    leader: AdaptedNode,
    follower: AdaptedNode | None,
    leader_source: SourceDocument,
    follower_source: SourceDocument | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    fields: dict[str, Any] = {}
    provenance: dict[str, dict[str, str]] = {}
    conflicts: list[dict[str, Any]] = []
    flags: list[dict[str, str]] = []

    def record(
        name: str, value: Any, origin: str, node: AdaptedNode, source: SourceDocument
    ) -> None:
        fields[name] = value
        provenance[name] = {
            "origin": origin,
            "document": source.filename,
            "role": source.role,
            "pointer": node.pointers.get(name, ""),
        }

    for name, value in leader.fields.items():
        record(name, value, leader.origin, leader, leader_source)

    if follower is None or follower_source is None:
        _flag_transition(fields.get("transition"), flags)
        return {"fields": fields, "provenance_by_field": provenance}, conflicts, flags

    for name, value in follower.fields.items():
        if name not in fields:
            record(name, value, follower.origin, follower, follower_source)
            continue
        if name == "transition":
            continue  # handled below; the graph's object always wins
        if name in ("state_check", "state_note"):
            continue  # handled below, per rule 3a
        if fields[name] == value:
            provenance[name]["origin"] = ORIGIN_PAIR_AGREED
            continue
        if name in SEED_ONLY_FIELDS and leader.origin == ORIGIN_GRAPH:
            record(name, value, follower.origin, follower, follower_source)
            continue
        if name in GRAPH_ONLY_FIELDS and leader.origin == ORIGIN_GRAPH:
            continue  # rule 1: the graph keeps what it alone carries
        conflicts.append(
            {
                "draft_field": name,
                "path_id": leader.path_id,
                "node_index": leader.node_index,
                "kept": fields[name],
                "kept_pointer": leader.pointers.get(name, ""),
                "kept_document": leader_source.filename,
                "rejected": value,
                "rejected_pointer": follower.pointers.get(name, ""),
                "rejected_document": follower_source.filename,
            }
        )

    _merge_state_check(
        leader, follower, leader_source, follower_source, fields, provenance, conflicts
    )
    _merge_transition(
        leader, follower, leader_source, follower_source, fields, provenance, conflicts
    )
    _flag_transition(fields.get("transition"), flags)
    return {"fields": fields, "provenance_by_field": provenance}, conflicts, flags


def _merge_state_check(
    leader: AdaptedNode,
    follower: AdaptedNode,
    leader_source: SourceDocument,
    follower_source: SourceDocument,
    fields: dict[str, Any],
    provenance: dict[str, dict[str, str]],
    conflicts: list[dict[str, Any]],
) -> None:
    """Rule 3a: compare canonical forms, keep the graph's two fields.

    The seed's combined string is retained as the raw value. A difference in
    representation is not a conflict; only a difference in content is.
    """
    graph_node, seed_node = (
        (leader, follower) if leader.origin == ORIGIN_GRAPH else (follower, leader)
    )
    graph_source, seed_source = (
        (leader_source, follower_source)
        if leader.origin == ORIGIN_GRAPH
        else (follower_source, leader_source)
    )
    graph_check = graph_node.fields.get("state_check")
    graph_note = graph_node.fields.get("state_note") or ""
    seed_check = seed_node.fields.get("state_check")
    seed_note = seed_node.fields.get("state_note") or ""

    fields["state_check"] = graph_check
    fields["state_note"] = graph_note
    fields["state_check_raw"] = join_state_check(seed_check, seed_note)

    agreed = (seed_check or "") == (graph_check or "") and seed_note == graph_note
    origin = ORIGIN_PAIR_AGREED if agreed else ORIGIN_GRAPH
    for name in ("state_check", "state_note"):
        provenance[name] = {
            "origin": origin,
            "document": graph_source.filename,
            "role": graph_source.role,
            "pointer": graph_node.pointers.get(name, ""),
        }
    provenance["state_check_raw"] = {
        "origin": ORIGIN_SEED,
        "document": seed_source.filename,
        "role": seed_source.role,
        "pointer": seed_node.pointers.get("state_check", ""),
    }
    if not agreed:
        conflicts.append(
            {
                "draft_field": "state_check",
                "path_id": leader.path_id,
                "node_index": leader.node_index,
                "kept": join_state_check(graph_check, graph_note),
                "kept_pointer": graph_node.pointers.get("state_check", ""),
                "kept_document": graph_source.filename,
                "rejected": join_state_check(seed_check, seed_note),
                "rejected_pointer": seed_node.pointers.get("state_check", ""),
                "rejected_document": seed_source.filename,
            }
        )


def _merge_transition(
    leader: AdaptedNode,
    follower: AdaptedNode,
    leader_source: SourceDocument,
    follower_source: SourceDocument,
    fields: dict[str, Any],
    provenance: dict[str, dict[str, str]],
    conflicts: list[dict[str, Any]],
) -> None:
    """The graph's object wins; the seed's prose is kept as a display string.

    The prose cannot carry crosses_boundary, so a difference between the two
    representations is never a conflict on its own — only a contradiction in
    the fields the prose does carry.
    """
    graph_node, seed_node = (
        (leader, follower) if leader.origin == ORIGIN_GRAPH else (follower, leader)
    )
    graph_source, seed_source = (
        (leader_source, follower_source)
        if leader.origin == ORIGIN_GRAPH
        else (follower_source, leader_source)
    )
    graph_form = graph_node.fields.get("transition") or {}
    seed_form = seed_node.fields.get("transition") or {}

    fields["transition"] = graph_form
    fields["transition_raw"] = seed_form.get("raw")
    agreed = transitions_agree(graph_form, seed_form)
    provenance["transition"] = {
        "origin": ORIGIN_PAIR_AGREED if agreed else ORIGIN_GRAPH,
        "document": graph_source.filename,
        "role": graph_source.role,
        "pointer": graph_node.pointers.get("transition", ""),
    }
    provenance["transition_raw"] = {
        "origin": ORIGIN_SEED,
        "document": seed_source.filename,
        "role": seed_source.role,
        "pointer": seed_node.pointers.get("transition", ""),
    }
    if not agreed:
        conflicts.append(
            {
                "draft_field": "transition",
                "path_id": leader.path_id,
                "node_index": leader.node_index,
                "kept": graph_form,
                "kept_pointer": graph_node.pointers.get("transition", ""),
                "kept_document": graph_source.filename,
                "rejected": seed_form.get("raw"),
                "rejected_pointer": seed_node.pointers.get("transition", ""),
                "rejected_document": seed_source.filename,
            }
        )


def enrich_node(
    node: NormalizedNode,
    component: dict[str, Any] | None,
    component_index: int | None,
    flow_map: FlowMapSource | None,
    lineage: str | None,
    catalogue: list[dict[str, Any]],
    catalogue_source: SourceDocument | None,
) -> None:
    """Stage N3a and N3b: place one node in the estate and attach its controls.

    The map fills only what no export carried (section 4.3 rule 4), so a
    disagreement is recorded rather than applied. Everything written here
    carries the map's lineage, because an edited map is an expected input.
    """
    crown_jewels = set((flow_map.document.get("crown_jewels") or []) if flow_map else ())

    def record(
        name: str,
        value: Any,
        origin: str,
        pointer: str,
        basis: list[str] | None = None,
    ) -> None:
        """Write a field and its origin.

        A derived field has no document to point at, so it names the fields it
        was computed from instead: every field still has to answer "where did
        this come from", which is the N1 gate.
        """
        node.fields[name] = value
        document = ""
        if origin == ORIGIN_FLOW_MAP and flow_map is not None:
            document = flow_map.filename
        elif origin == ORIGIN_SEED and catalogue_source is not None:
            document = catalogue_source.filename
        entry: dict[str, Any] = {
            "origin": origin,
            "document": document,
            "role": "flow_map" if origin == ORIGIN_FLOW_MAP else origin,
            "pointer": pointer,
        }
        if origin == ORIGIN_FLOW_MAP and lineage:
            entry["flow_map_lineage"] = lineage
        if basis is not None:
            entry["basis"] = basis
        node.provenance_by_field[name] = entry

    if component is not None:
        base = f"/components/{component_index}"
        for name, key in (
            ("zone", "zone"),
            ("exposure", "exposure"),
            ("technologies", "technologies"),
            ("authentication", "authentication"),
            ("data_classification", "data_classification"),
        ):
            record(name, component.get(key), ORIGIN_FLOW_MAP, f"{base}/{key}")
        record(
            "crown_jewel",
            component.get("id") in crown_jewels,
            ORIGIN_FLOW_MAP,
            "/crown_jewels",
        )
        record("port", _flow_port(flow_map, node), ORIGIN_FLOW_MAP, "/flows")

        component_name = component.get("name")
        asset_name = node.fields.get("asset_name")
        if component_name and asset_name and component_name != asset_name:
            # Rule 4: the map never overwrites an export value.
            node.input_conflicts.append(
                {
                    "draft_field": "asset_name",
                    "path_id": node.path_id,
                    "node_index": node.node_index,
                    "kept": asset_name,
                    "kept_pointer": node.provenance_by_field["asset_name"]["pointer"],
                    "kept_document": node.provenance_by_field["asset_name"]["document"],
                    "rejected": component_name,
                    "rejected_pointer": f"{base}/name",
                    "rejected_document": flow_map.filename if flow_map else "",
                }
            )

    controls, origin, pointer = _attach_controls(node, component, component_index, catalogue)
    record(
        "control_catalogue",
        controls,
        origin,
        pointer if origin == ORIGIN_FLOW_MAP else _catalogue_pointer(catalogue_source),
    )
    record(
        "monitoring_claim",
        _monitoring_claim(node.fields.get("detecting_controls") or [], controls),
        ORIGIN_DERIVED,
        "",
        basis=["detecting_controls", "control_catalogue"],
    )

    grade, requirements = grade_node(node, component, flow_map is not None)
    grade_basis = ["component_id", "technologies", "authentication"]
    record("context_completeness", grade, ORIGIN_DERIVED, "", basis=grade_basis)
    record("telemetry_requirements", requirements, ORIGIN_DERIVED, "", basis=grade_basis)


def resolve_mitigations(
    node: NormalizedNode, tag_caveat: dict[str, Any] | None, caveat_reason: str
) -> list[dict[str, str]]:
    """Stage N3c, section 1.4b. Names are looked up locally, never asserted.

    The export's own ``mitigations`` and ``uncovered_mitigations`` are left
    exactly as they arrived — they are the provenance. What is added is the
    covered half, the narrow focus cut generation actually reads, and the
    ratio with the tagging caveat that keeps "uncovered" from being read as
    "no control exists".
    """
    warnings: list[dict[str, str]] = []
    mitigations = list(node.fields.get("mitigations") or [])
    uncovered = list(node.fields.get("uncovered_mitigations") or [])
    uncovered_set = set(uncovered)

    names: dict[str, str] = {}
    unresolved: list[str] = []
    for m_id in mitigations:
        entry = _mitigation_entry(m_id)
        if entry is None:
            unresolved.append(m_id)
            continue
        names[m_id] = entry.get("name", "")

    for m_id in unresolved:
        warnings.append(
            _warning(
                "MITIGATION_UNRESOLVED",
                m_id,
                "mitigation id is not in the local ATT&CK reference data; "
                "it is reported rather than named or ranked",
            )
        )

    def record(name: str, value: Any, pointer: str) -> None:
        node.fields[name] = value
        node.provenance_by_field[name] = {
            "origin": ORIGIN_REFERENCE,
            "document": RELATIONSHIPS_DOCUMENT,
            "role": ORIGIN_REFERENCE,
            "pointer": pointer,
        }

    record("mitigation_names", names, "/mitigations")
    record(
        "mitigations_covered",
        [_mitigation_view(m, names) for m in mitigations if m not in uncovered_set],
        "/mitigations",
    )
    record(
        "mitigation_focus",
        _focus_cut([m for m in uncovered if m in names], names),
        "/mitigations",
    )
    coverage = {
        "covered": len([m for m in mitigations if m not in uncovered_set]),
        "total": len(mitigations),
        "unresolved": unresolved,
        "tag_caveat": dict(tag_caveat) if tag_caveat else None,
    }
    if tag_caveat is None:
        # Never silently null: an absent caveat must not read as "every
        # control is tagged".
        coverage["tag_caveat_reason"] = caveat_reason
    record("mitigation_coverage", coverage, "/mitigations")
    return warnings


def _mitigation_entry(m_id: str) -> dict[str, Any] | None:
    entry = get_mitre_relationships().get("mitigations", {}).get(m_id)
    return entry if isinstance(entry, dict) else None


def _technique_breadth(m_id: str) -> int:
    entry = _mitigation_entry(m_id)
    return len(entry.get("techniques") or []) if entry else 0


def _mitigation_view(m_id: str, names: dict[str, str]) -> dict[str, Any]:
    return {
        "m_id": m_id,
        "name": names.get(m_id),
        "technique_breadth": _technique_breadth(m_id),
    }


def _focus_cut(candidates: list[str], names: dict[str, str]) -> list[dict[str, Any]]:
    """The one or two narrowest uncovered mitigations, ties broken by M-ID.

    Breadth is a proxy for specificity, not for detectability: this narrows
    what generation is asked to reason about and never argues that a
    detection should exist. An empty cut is an ordinary outcome.
    """
    ranked = sorted(set(candidates), key=lambda m: (_technique_breadth(m), m))
    return [_mitigation_view(m, names) for m in ranked[:MITIGATION_FOCUS_LIMIT]]


def flow_map_tag_caveat(
    flow_map: FlowMapSource | None,
    components: dict[Any, tuple[dict[str, Any], int]],
    nodes: list[NormalizedNode],
    lineage: str | None,
) -> dict[str, Any] | None:
    """Decision 11: the projector's control_tagging, recomputed from the map.

    Neither export carries those counts — they live in the tool result and the
    run record, and not every run has a record — so they are derived from the
    map the operator supplied, and carry its lineage.
    """
    if flow_map is None:
        return None
    targeted = sorted(
        {
            node.fields.get("component_id")
            for node in nodes
            if node.fields.get("component_id") in components
        }
    )
    controls = [
        control
        for component_id in targeted
        for control in components[component_id][0].get("controls") or []
        if isinstance(control, dict)
    ]
    return {
        "targeted_components": targeted,
        "control_count": len(controls),
        "tagged_control_count": sum(
            1 for control in controls if control.get("mitre_mitigation_id")
        ),
        "components_without_controls": [
            component_id
            for component_id in targeted
            if not (components[component_id][0].get("controls") or [])
        ],
        "flow_map_lineage": lineage,
    }


def reconcile_taxonomy(node: NormalizedNode) -> list[dict[str, str]]:
    """Stage N3d, section 1.6. Record the outcome; never re-decide the export.

    The projector already reconciled these against v19.2, so agreement is the
    expected result. Nothing here rewrites an export value: a retired id gains
    ``technique_id_current`` beside it, the way the seed's raw forms are kept
    beside the graph's, so a remap can always be audited or reversed.
    """
    warnings: list[dict[str, str]] = []
    technique_id = node.fields.get("technique_id") or ""
    technique_name = node.fields.get("technique_name") or ""

    def record(name: str, value: Any, pointer: str) -> None:
        node.fields[name] = value
        node.provenance_by_field[name] = {
            "origin": ORIGIN_REFERENCE,
            "document": TECHNIQUES_DOCUMENT,
            "role": ORIGIN_REFERENCE,
            "pointer": pointer,
        }

    entry = enrich_technique(technique_id)
    if entry:
        record("technique_status", "current", f"/{technique_id}")
    else:
        remap = resolve_retired_technique(technique_id, technique_name)
        if remap is None:
            record("technique_status", "unresolved", f"/{technique_id}")
            warnings.append(
                _warning(
                    "TECHNIQUE_UNRESOLVED",
                    technique_id,
                    "technique id is not in the v19.2 lookup and no unambiguous "
                    "successor exists; it is flagged, never guessed",
                )
            )
        else:
            current_id, basis = remap
            record("technique_status", "retired_remapped", f"/{current_id}")
            record("technique_id_current", current_id, f"/{current_id}")
            record("technique_remap_basis", basis, f"/{current_id}")
            entry = enrich_technique(current_id)
            warnings.append(
                _warning(
                    "TECHNIQUE_RETIRED",
                    technique_id,
                    f"retired id maps to {current_id} by {basis} match; both are "
                    "kept and the export value is not rewritten",
                )
            )

    warnings.extend(_reconcile_tactic(node, entry, record))
    return warnings


def _reconcile_tactic(node: NormalizedNode, entry: dict[str, Any], record) -> list:
    """Canonical spelling, then a retired tactic's successor, then give up."""
    supplied = node.fields.get("tactic") or ""
    allowed = (entry or {}).get("tactics") or []
    canonical = canonical_tactic(supplied)

    if canonical is not None:
        if canonical == supplied:
            record("tactic_status", "as_supplied", "/tactics")
            return []
        # Same tactic, different spelling: reconciled, not a correction.
        record("tactic_status", "reconciled", "/tactics")
        record("tactic_as_supplied", supplied, "/tactics")
        node.fields["tactic"] = canonical
        return []

    successor = resolve_legacy_tactic(supplied, allowed) if supplied else None
    if successor is not None:
        record("tactic_status", "reconciled", "/tactics")
        record("tactic_as_supplied", supplied, "/tactics")
        node.fields["tactic"] = successor
        return []

    record("tactic_status", "unresolved", "/tactics")
    return [
        _warning(
            "TACTIC_UNRESOLVED",
            supplied or "(empty)",
            "tactic is not current in v19.2"
            + (
                " and its retired form has no single successor this technique uses"
                if is_legacy_tactic(supplied)
                else ""
            )
            + "; the export value is kept",
        )
    ]


def attach_telemetry(node: NormalizedNode, component_type: str | None) -> None:
    """Stage G1a. What could observe this node, and how ready that evidence is.

    A separate axis from `context_completeness`: this says what exists to look
    at, not how well the node is bound to the estate.
    """
    for name, value in telemetry.attach(node.fields, component_type).items():
        node.fields[name] = value
        node.provenance_by_field[name] = {
            "origin": ORIGIN_REFERENCE,
            "document": TELEMETRY_DOCUMENT,
            "role": ORIGIN_REFERENCE,
            "pointer": "/sources",
            "basis": ["technologies", "component_id", "transition"],
        }


def ground_node(node: NormalizedNode, actor_attack_id: str) -> None:
    """Stage G1: the assessment tuple and the actor's procedure evidence.

    Derived from the local ATT&CK release and this node's own access fields.
    The export's `actor_support` is left alone - it answers a different
    question from `actor_evidence` and the two may legitimately disagree.
    """
    assessment = grounding.assess_node(node.fields, actor_attack_id)
    for name, value, basis in (
        ("assessment", assessment, ["technique_id", "state_check", "transition"]),
        ("procedure_evidence", assessment.pop("procedure_evidence"), ["technique_id"]),
    ):
        node.fields[name] = value
        node.provenance_by_field[name] = {
            "origin": ORIGIN_REFERENCE,
            "document": RELATIONSHIPS_DOCUMENT,
            "role": ORIGIN_REFERENCE,
            "pointer": "/procedures",
            "basis": basis,
        }


def _flow_port(flow_map: FlowMapSource | None, node: NormalizedNode) -> Any:
    """Port lives on the map's flow, never on a step's transition."""
    if flow_map is None:
        return None
    flow_id = (node.fields.get("transition") or {}).get("flow_id")
    if not flow_id:
        return None
    for flow in flow_map.document.get("flows") or []:
        if isinstance(flow, dict) and flow.get("id") == flow_id:
            return flow.get("port")
    return None


def _attach_controls(
    node: NormalizedNode,
    component: dict[str, Any] | None,
    component_index: int | None,
    catalogue: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], str, str]:
    """Decision 10: structural from the map, else name plus component id.

    A control name alone is not a key — ``WAF`` protects two components in the
    Claims Portal map — so a text match must also find the node's component in
    the catalogue entry's description, and is marked as the weaker evidence it
    is.
    """
    if component is not None:
        attached = [
            {
                "name": control.get("name"),
                "control_type": control.get("control_type"),
                "status": control.get("implementation_status"),
                "bypass_difficulty": control.get("bypass_difficulty"),
                "detection_capability": control.get("detection_capability"),
                "mitre_mitigation_id": control.get("mitre_mitigation_id"),
                "evidence": "structured",
            }
            for control in component.get("controls") or []
            if isinstance(control, dict)
        ]
        return attached, ORIGIN_FLOW_MAP, f"/components/{component_index}/controls"

    component_id = node.fields.get("component_id")
    names = {
        control.get("name")
        for control in node.fields.get("controls_in_play") or []
        if isinstance(control, dict)
    }
    attached = []
    for entry in catalogue:
        if not isinstance(entry, dict) or entry.get("name") not in names:
            continue
        if not component_id or f"({component_id})" not in (entry.get("description") or ""):
            # Written for another component, or nothing to tie it to.
            continue
        attached.append(
            {
                "name": entry.get("name"),
                "control_id": entry.get("control_id"),
                "control_type": entry.get("control_type"),
                "status": entry.get("implementation_status"),
                "bypass_difficulty": entry.get("bypass_difficulty"),
                "detection_capability": entry.get("detection_capability"),
                "evidence": "text",
            }
        )
    return attached, ORIGIN_SEED, ""


def _catalogue_pointer(catalogue_source: SourceDocument | None) -> str:
    return "/scenarios/*/security_controls" if catalogue_source else ""


def _monitoring_claim(
    detecting_controls: list[Any], controls: list[dict[str, Any]]
) -> str:
    """Derived, and never coverage: a listed control is not an event stream."""
    if detecting_controls:
        return "claimed"
    if any(
        (control.get("detection_capability") or "").lower() in _CAPABILITY_CLAIMS
        for control in controls
    ):
        return "partial"
    return "none"


def grade_node(
    node: NormalizedNode, component: dict[str, Any] | None, map_supplied: bool
) -> tuple[str, list[str]]:
    """Section 5. The grade is a property of the inputs, not of the export."""
    component_id = node.fields.get("component_id")
    if not component_id:
        if node.fields.get("asset_name"):
            return GRADE_ASSET_TEXT_ONLY, [
                "no component id: describe the collection required, never a product"
            ]
        return GRADE_UNBOUND, ["no component and no asset: telemetry is a declared gap"]
    if not map_supplied or component is None:
        return GRADE_ASSET_NAMED, [
            "no flow map joined for this component: behaviour-level sources only"
        ]

    missing = []
    if not component.get("technologies"):
        missing.append("technologies")
    # 'none' is a declared absence of authentication, not a value to name.
    if (component.get("authentication") or "none") == "none":
        missing.append("authentication")
    if missing:
        return GRADE_COMPONENT_BOUND_PARTIAL, [
            f"component '{component_id}' declares no {name}; "
            "logsource.product stays unset"
            for name in missing
        ]
    return GRADE_COMPONENT_BOUND, []


def _flag_transition(
    transition: dict[str, Any] | None, flags: list[dict[str, str]]
) -> None:
    if not transition:
        return
    if transition.get("movement") == "undeclared":
        flags.append(
            _review_flag(
                "UNDECLARED_TRANSITION",
                "the component changes with no declared flow: movement "
                "the flow map does not describe",
            )
        )
    elif transition.get("movement") == "unparsed":
        flags.append(
            _review_flag(
                "TRANSITION_UNPARSED",
                "transition text did not match a known form; kept verbatim",
            )
        )
