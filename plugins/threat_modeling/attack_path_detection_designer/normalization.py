"""Normalization of adversary path projector exports into node contexts.

Stage N1 of ``docs/specs/attack_path_detection_normalization.md``: adapters for
the three input shapes, the three identities of section 4.2a, the node
occurrence key, a deterministic ``draft_id``, and the union merge with the
section 4.3 precedence table.

No LLM, no network, no flow map. Enrichment and grading are stage N3; the
``normalize_paths`` action and the context pack artifact are stage N4.

This module is plugin-local by decision 7 of the spec. It is loaded as a
sibling of ``tool.py`` by file location, because the loader imports a plugin
under a flat module name and there is no package to import from.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

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


class NormalizationError(ValueError):
    """Raised when inputs cannot be normalized at all."""


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
                {
                    "code": "STATE_NOTE_ENCODING",
                    "location": f"{path_id}.attack_sequence[{node_index}]",
                    "message": (
                        "state_check separator is not U+2014; the transport did not "
                        "preserve the em dash, so the note cannot be split reliably"
                    ),
                }
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

    @property
    def node_keys(self) -> list[tuple[str, str, int]]:
        return [node.key for node in self.nodes]

    def as_dict(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory,
            "engagement": self.engagement,
            "identities": self.identities,
            "pair": self.pair,
            "nodes": [node.as_dict() for node in self.nodes],
            "warnings": self.warnings,
            "input_conflicts": self.input_conflicts,
        }


def normalize(
    primary: SourceDocument,
    secondary: SourceDocument | None = None,
    *,
    accept_unverified_pair: bool = False,
) -> NormalizationResult:
    """Normalize one document, or a graph and seed of the same projection.

    A refused pair is not an error: the primary source is processed alone and
    the refusal is reported, because half a join is worse than none.
    """
    warnings: list[dict[str, str]] = []
    pair_decision = PairDecision(False, "single_source", "not_attempted")

    if secondary is not None:
        pair_decision = decide_pair(
            primary, secondary, accept_unverified_pair=accept_unverified_pair
        )
        if not pair_decision.join:
            warnings.append(
                {
                    "code": "PAIR_REFUSED",
                    "location": secondary.filename,
                    "message": pair_decision.reason or "pair join refused",
                }
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
                {
                    "code": "NODE_ONLY_IN_SECONDARY",
                    "location": f"{key[0]}.steps[{key[1]}]",
                    "message": (
                        "node present in the secondary document only; not merged"
                    ),
                }
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
            {
                "code": "PAIR_CONTENT_CONFLICT",
                "location": primary.filename,
                "message": (
                    f"{len(conflicts)} field(s) disagree between the paired documents "
                    "after canonicalization; the graph value is kept and the join is "
                    "not reported verified"
                ),
            }
        )

    return NormalizationResult(
        nodes=nodes,
        inventory=inventory,
        engagement=engagement,
        identities=identities,
        pair=pair,
        warnings=warnings,
        input_conflicts=conflicts,
    )


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
            {
                "code": "PATH_NOT_IN_BOTH",
                "location": str(path_id),
                "message": "path present in one document only",
            }
        )
    for path_id in sorted(set(leader_paths) & set(follower_paths)):
        if leader_paths[path_id] != follower_paths[path_id]:
            warnings.append(
                {
                    "code": "PATH_LENGTH_DIFFERS",
                    "location": str(path_id),
                    "message": (
                        f"{leader_paths[path_id]} nodes in {leader.source.role}, "
                        f"{follower_paths[path_id]} in {follower.source.role}"
                    ),
                }
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


def _flag_transition(
    transition: dict[str, Any] | None, flags: list[dict[str, str]]
) -> None:
    if not transition:
        return
    if transition.get("movement") == "undeclared":
        flags.append(
            {
                "code": "UNDECLARED_TRANSITION",
                "message": (
                    "the component changes with no declared flow: movement "
                    "the flow map does not describe"
                ),
            }
        )
    elif transition.get("movement") == "unparsed":
        flags.append(
            {
                "code": "TRANSITION_UNPARSED",
                "message": "transition text did not match a known form; kept verbatim",
            }
        )
