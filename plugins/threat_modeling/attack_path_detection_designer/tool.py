"""Attack Path Detection Designer.

Turns adversary_path_projector exports into a normalized per-node detection
context, then drafts one detection per node. Stages N1-N3 and G1a-G1b of
`docs/specs/attack_path_detection_normalization.md`.

Actions:
    validate_input       Deterministic. Normalizes the supplied sources and
                         returns the context pack: node inventory, identities,
                         pair decision, field-level conflicts, flow-map lineage
                         and fit, grades, controls, mitigations, taxonomy,
                         assessment and telemetry join. No model call. The
                         shell saves the result as a registered artifact.
    digest               The same run, three readable lines per node.
    generate_detections  Normalizes, then drafts one detection per node at
                         heavy tier. It is why this plugin declares
                         safe_for_auto_invoke: false, which is a whole-plugin
                         field with no per-action form (spec decision 7).

Retired:
    normalize_paths      Stage N4, retired 2026-09-23 before it was built.
                         Normalization is byte-identical on repeat, so the pack
                         is re-derived rather than stored; validate_input and
                         digest cover what the action was for.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PLUGIN_DIR = Path(__file__).resolve().parent


def _load_sibling(module_file: str, alias: str):
    """Load a module next to this file.

    The loader imports a plugin under a flat module name with no package, so
    neither a relative import nor a plain `import normalization` can find a
    sibling. Loading it by file location is the only route that works both
    under the loader and under pytest.
    """
    if alias in sys.modules:
        return sys.modules[alias]
    spec = importlib.util.spec_from_file_location(alias, _PLUGIN_DIR / module_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {module_file} beside {__file__}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


nz = _load_sibling("normalization.py", "attack_path_detection_designer_normalization")

ACTIONS = ("validate_input", "digest", "generate_detections")

# Named so validate_inputs can say what replaced them rather than failing
# obscurely.
RETIRED_ACTIONS = {
    "normalize_paths": (
        "retired with stage N4 on 2026-09-23; 'validate_input' returns the same "
        "context pack and the shell saves it as an artifact"
    ),
}

gen = _load_sibling("generation.py", "attack_path_detection_designer_generation")


def _telemetry_fields_by_source() -> dict[str, dict[str, Any]]:
    """The library keyed by source id, for the draft field-closure check.

    Imported here rather than at module scope so the library stays a G1a
    concern: generation takes it as an argument and works without it, which is
    what lets the check be tested against a fixture library.
    """
    from framework.reference_data.telemetry_library import all_sources

    return {str(s["source_id"]): s for s in all_sources()}

# Sized against the provider's content budget, not a guaranteed node limit.
GENERATION_MAX_TOKENS = 32000

# Stated, never left to the client's default of "high": thinking time is what
# runs a generation call into a transport deadline.
DEFAULT_THINKING_LEVEL = "medium"
THINKING_LEVELS = ("minimal", "low", "medium", "high")

# Section 4.4 of the spec. Every failing result carries one of these.
ERROR_CODES = (
    "NO_INPUT",
    "ARTIFACT_NOT_FOUND",
    "ARTIFACT_UNAVAILABLE",
    "INPUT_UNREADABLE",
    "INPUT_UNRECOGNIZED",
    "FLOW_MAP_UNREADABLE",
    "FLOW_MAP_NOT_OBJECT",
    "NORMALIZATION_FAILED",
    "LLM_UNAVAILABLE",
    "GENERATION_INCOMPLETE",
)


@dataclass
class ToolResult:
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    output_artifacts: list[dict[str, Any]] | None = None
    details: dict[str, Any] | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _requested_artifact_ids(payload: dict[str, Any]) -> list[Any]:
    """Artifact ids the caller asked for, in the order given.

    A pair needs two, so `artifact_ids` is the form to use. `artifact_id` is
    also accepted because the shell's own flag handling speaks the singular.
    """
    ids = _as_list(payload.get("artifact_ids")) + _as_list(payload.get("artifact_id"))
    seen: list[Any] = []
    for entry in ids:
        if entry not in seen:
            seen.append(entry)
    return seen


def _requested_paths(payload: dict[str, Any]) -> list[Any]:
    """File paths the caller asked for.

    `file_path` and `path` are here because `do_run` injects both when it
    resolves a singular `artifact_id`. Ignoring them would make that route
    fail with "no input" on a payload the shell believed it had filled in.
    """
    paths = _as_list(payload.get("sources"))
    if not _requested_artifact_ids(payload):
        for key in ("file_path", "path"):
            for entry in _as_list(payload.get(key)):
                if entry not in paths:
                    paths.append(entry)
    return paths


def _resolve_artifact(artifact_id: Any, context: Any) -> tuple[Any, ToolResult | None]:
    """Find a registered artifact and return (display name, local path).

    Resolution goes through `context.artifacts`, which is how every other
    plugin reaches a file: in the container the registry is what knows where
    an export actually landed.
    """
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

    path = Path(artifact.file_path) if artifact.file_path else None
    if path is None or not path.exists():
        storage_uri = getattr(artifact, "storage_uri", None)
        return None, ToolResult(
            ok=False,
            error_code="ARTIFACT_UNAVAILABLE",
            message=(
                f"Artifact '{artifact_id}' is registered but its file is not readable "
                f"at {artifact.file_path!r}"
                + (f"; it is stored at {storage_uri}" if storage_uri else "")
            ),
            details={"artifact_id": artifact_id, "storage_uri": storage_uri},
        )
    return (Path(artifact.file_path).name, path), None


def nz_hints(thinking_level: str = DEFAULT_THINKING_LEVEL):
    """Heavy tier and structured output; the provider stays the operator's choice.

    `thinking_level` is stated rather than left unset: a client that sees
    `needs_reasoning` with no level resolves it to "high", and thinking time
    dominates latency against a client deadline the plugin timeout cannot
    extend. The projector states it for the same reason.

    QueryHints carries no provider field by design - vendor selection belongs
    to `use`, not to plugin code.
    """
    try:
        from framework.plugins.protocol import QueryHints
    except ImportError:  # pragma: no cover - framework always present at runtime
        return None
    return QueryHints(
        tier="heavy",
        needs_reasoning=True,
        needs_structured_output=True,
        thinking_level=thinking_level,
    )


def _read_json(path: Path) -> Any:
    # Always explicit: the default encoding on Windows is cp1252, and these
    # documents contain a U+2014 that a mojibake read turns into a spurious
    # conflict on every gap node.
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _load_flow_map(payload: dict[str, Any], context: Any) -> tuple[Any, ToolResult | None]:
    """The supplied flow map, if any, by artifact id or by local path.

    Never refused for its lineage: an edited map is an expected input (spec
    decision 9). Only a file that is not a flow map at all fails the call.
    """
    artifact_id = payload.get("flow_map_artifact_id")
    path_value = payload.get("flow_map_path")
    if artifact_id:
        resolved, failure = _resolve_artifact(artifact_id, context)
        if failure is not None:
            return None, failure
        name, path = resolved
    elif path_value:
        name, path = Path(path_value).name, Path(path_value)
    else:
        return None, None

    try:
        parsed = _read_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        return None, ToolResult(
            ok=False,
            error_code="FLOW_MAP_UNREADABLE",
            message=(
                f"Could not read flow map {name} as JSON: {exc}. A prose, Markdown "
                "or Mermaid map needs converting first (stage N5)."
            ),
        )
    try:
        return nz.load_flow_map(parsed, name), None
    except nz.FlowMapError as exc:
        return None, ToolResult(
            ok=False,
            error_code="FLOW_MAP_NOT_OBJECT",
            message=str(exc),
            details={"file": name},
        )


class AttackPathDetectionDesigner:
    """Normalize projected attack paths and draft a detection per node."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "attack_path_detection_designer",
            "version": "0.1.0",
            "pillar": "threat_modeling",
            "actions": list(ACTIONS),
            "retired_actions": sorted(RETIRED_ACTIONS),
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        action = payload.get("action", "validate_input")
        if action in RETIRED_ACTIONS:
            errors.append(
                f"Action '{action}' is {RETIRED_ACTIONS[action]}. "
                f"Valid actions: {', '.join(ACTIONS)}"
            )
        elif action not in ACTIONS:
            errors.append(
                f"Unknown action '{action}'. Valid actions: {', '.join(ACTIONS)}"
            )

        artifact_ids = _requested_artifact_ids(payload)
        sources = _requested_paths(payload)

        if not artifact_ids and not sources:
            errors.append(
                "Supply 'artifact_ids' (registered projector exports, the usual route) "
                "or 'sources' (file paths): one document, or a path graph and a "
                "scenario seed of the same run"
            )
        if len(artifact_ids) + len(sources) > 2:
            errors.append(
                "At most two documents: one graph and one seed. "
                f"Got {len(artifact_ids)} artifact id(s) and {len(sources)} path(s)"
            )
        for entry in artifact_ids:
            if not isinstance(entry, str):
                errors.append("each entry in 'artifact_ids' must be an artifact id string")
        for entry in sources:
            if not isinstance(entry, str):
                errors.append("each entry in 'sources' must be a file path string")
            elif not Path(entry).exists():
                # Artifact ids cannot be checked here: resolving one needs the
                # execution context, which validation does not receive.
                errors.append(f"source not found: {entry}")

        flow_map_id = payload.get("flow_map_artifact_id")
        flow_map_path = payload.get("flow_map_path")
        if flow_map_id and flow_map_path:
            errors.append(
                "Supply the flow map once: 'flow_map_artifact_id' or 'flow_map_path'"
            )
        if flow_map_id is not None and not isinstance(flow_map_id, str):
            errors.append("'flow_map_artifact_id' must be an artifact id string")
        if flow_map_path is not None:
            if not isinstance(flow_map_path, str):
                errors.append("'flow_map_path' must be a file path string")
            elif not Path(flow_map_path).exists():
                errors.append(f"flow map not found: {flow_map_path}")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        accept_unverified = bool(payload.get("accept_unverified_pair", False))

        inputs: list[tuple[str, Path]] = []
        for artifact_id in _requested_artifact_ids(payload):
            resolved, failure = _resolve_artifact(artifact_id, context)
            if failure is not None:
                return failure
            inputs.append(resolved)
        for entry in _requested_paths(payload):
            inputs.append((Path(entry).name, Path(entry)))

        if not inputs:
            return ToolResult(
                ok=False,
                error_code="NO_INPUT",
                message="No artifact id or source path supplied.",
            )

        flow_map, failure = _load_flow_map(payload, context)
        if failure is not None:
            return failure

        documents = []
        for name, path in inputs:
            try:
                parsed = _read_json(path)
            except (OSError, json.JSONDecodeError) as exc:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_UNREADABLE",
                    message=f"Could not read {name}: {exc}",
                )
            try:
                documents.append(nz.load_document(parsed, name))
            except nz.NormalizationError as exc:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_UNRECOGNIZED",
                    message=str(exc),
                    details={"file": name},
                )

        primary = documents[0]
        secondary = documents[1] if len(documents) > 1 else None
        try:
            normalized = nz.normalize(
                primary,
                secondary,
                accept_unverified_pair=accept_unverified,
                flow_map=flow_map,
            )
        except nz.NormalizationError as exc:
            return ToolResult(
                ok=False, error_code="NORMALIZATION_FAILED", message=str(exc)
            )

        if payload.get("action") == "generate_detections":
            return self._generate(normalized, context, payload)

        if payload.get("action") == "digest":
            # A reading of the same pack, three lines per node. The pack
            # itself is machine-facing and is not repeated here.
            return ToolResult(
                ok=True,
                result={
                    "digest": nz.digest_lines(normalized),
                    "node_count": len(normalized.nodes),
                    "pair_status": normalized.pair["provenance_status"],
                    "conflict_count": len(normalized.input_conflicts),
                    "flow_map_lineage": normalized.flow_map.get("lineage"),
                    "completeness": normalized.inventory["completeness"],
                    "warnings": normalized.warnings,
                },
            )

        result = normalized.as_dict()
        result["node_count"] = len(normalized.nodes)
        result["pair_status"] = normalized.pair["provenance_status"]
        result["conflict_count"] = len(normalized.input_conflicts)
        result["flow_map_lineage"] = normalized.flow_map.get("lineage")
        result["completeness"] = normalized.inventory["completeness"]
        result["mitigation_coverage"] = normalized.inventory["mitigation_coverage"]
        result["taxonomy"] = normalized.inventory["taxonomy"]
        return ToolResult(ok=True, result=result)

    def _generate(
        self, normalized: Any, context: Any, payload: dict[str, Any]
    ) -> ToolResult:
        """Stage G1b. One heavy-tier call per batch, then a coverage ledger.

        A node is never dropped for weak evidence: `actor_evidence: false`
        lowers confidence and is recorded, because an attacker can change
        tactics and a path the projector produced is still a path.
        """
        if not getattr(context, "llm_query", None):
            return ToolResult(
                ok=False,
                error_code="LLM_UNAVAILABLE",
                message=(
                    "generate_detections needs a connected provider. Run 'connect', "
                    "and 'use <provider> for attack_path_detection_designer' to "
                    "choose one."
                ),
            )

        nodes = [node.as_dict() for node in normalized.nodes]
        engagement = normalized.engagement
        drafts: list[dict[str, Any]] = []
        problems: list[dict[str, Any]] = []
        calls: list[dict[str, Any]] = []

        for batch in gen.batches(nodes, int(payload.get("max_nodes_per_call", 6))):
            outline = gen.path_outline(nodes, batch[0]["path_id"])
            response = context.llm_query.query_text(
                prompt=gen.build_prompt(batch, engagement, outline),
                system_context=gen.SYSTEM_CONTEXT,
                max_tokens=GENERATION_MAX_TOKENS,
                hints=nz_hints(
                    str(payload.get("thinking_level") or DEFAULT_THINKING_LEVEL)
                ),
            )
            calls.append(
                {
                    "path_id": batch[0]["path_id"],
                    "nodes": len(batch),
                    "ok": bool(getattr(response, "ok", False)),
                    "model_used": getattr(response, "model_used", None),
                    "truncated": bool(getattr(response, "truncated", False)),
                    "finish_reason": getattr(response, "finish_reason", None),
                    # An empty reply with tokens spent is thinking starvation,
                    # not a refusal. Only the usage tells the two apart.
                    "token_usage": getattr(response, "token_usage", None),
                    "reply_chars": len(getattr(response, "text", None) or ""),
                }
            )
            if not getattr(response, "ok", False):
                problems.append(
                    {
                        "path_id": batch[0]["path_id"],
                        "problem": getattr(response, "error", None) or "provider call failed",
                        "error_kind": getattr(response, "error_kind", None),
                    }
                )
                continue
            if getattr(response, "truncated", False):
                # A truncated reply is rejected even though transport says ok.
                problems.append(
                    {"path_id": batch[0]["path_id"], "problem": "reply hit the output cap"}
                )
                continue

            batch_drafts, failure = gen.parse_response(getattr(response, "text", None))
            if failure:
                # Without a sample of what actually came back, "no JSON object
                # in response" sends the next person guessing. Bounded, because
                # a reply can be tens of thousands of characters.
                raw = getattr(response, "text", None) or ""
                problems.append(
                    {
                        "path_id": batch[0]["path_id"],
                        "problem": failure,
                        "reply_chars": len(raw),
                        "reply_starts": raw[:300],
                        "reply_ends": raw[-150:] if len(raw) > 450 else "",
                    }
                )
                continue
            if not batch_drafts:
                problems.append(
                    {
                        "path_id": batch[0]["path_id"],
                        "problem": "reply parsed but carried no drafts",
                        "reply_starts": (getattr(response, "text", None) or "")[:300],
                    }
                )
            drafts.extend(batch_drafts)

        by_id = {n["draft_id"]: n for n in nodes}
        valid: list[dict[str, Any]] = []
        for draft in drafts:
            claimed = gen.draft_id_of(draft)
            node = by_id.get(claimed)
            if node is None:
                problems.append(
                    {
                        "problem": "draft does not match any node",
                        "claimed_draft_id": claimed,
                        "title": gen.as_dict(draft).get("title"),
                    }
                )
                continue
            try:
                findings = gen.validate_draft(draft, node) + gen.validate_logsource(
                    draft, node
                )
            except Exception as exc:  # noqa: BLE001 - a bad draft is data, not a crash
                # A reply is untrusted shape as well as untrusted content. One
                # malformed draft must cost its own node, never the whole run
                # and never the money already spent on the other batches.
                findings = [f"draft could not be validated: {type(exc).__name__}: {exc}"]
            if findings:
                problems.append({"draft_id": node["draft_id"], "problems": findings})
                continue
            try:
                gen.annotate(draft, _telemetry_fields_by_source())
            except Exception as exc:  # noqa: BLE001 - annotation never costs a draft
                # A flag that could not be derived is a flag, not a rejection.
                # The draft passed validation; losing it here would discard
                # work over a question about it.
                draft["x_eventmill"].setdefault("review_flags", []).append(
                    {
                        "code": "ANNOTATION_FAILED",
                        "message": f"{type(exc).__name__}: {exc}",
                    }
                )
            valid.append(draft)

        ledger = gen.coverage(nodes, valid)
        result = {
            "drafts": valid,
            "coverage": ledger,
            "rejected": problems,
            "calls": calls,
            # Named apart from engagement.projection_model on purpose: one
            # export carries the model that projected the path and the model
            # that drafted the detections, and a single "model_attribution"
            # let a reader take the first for the second.
            "generation_model": sorted(
                {c["model_used"] for c in calls if c.get("model_used")}
            ),
            "engagement": engagement,
            "prompt_version": gen.PROMPT_VERSION,
            "telemetry_library_version": nodes[0].get("telemetry_library_version") if nodes else None,
        }
        if ledger["generation_status"] != "complete":
            # Never report drafts that do not exist: a partial result is an
            # error with its partial output attached, not a success. The shell
            # persists only a successful result, so the partial one is written
            # here - otherwise the drafts already paid for are lost.
            result["partial_file"] = _persist_partial(result, context)
            return ToolResult(
                ok=False,
                error_code="GENERATION_INCOMPLETE",
                message=_incomplete_message(
                    ledger, problems, calls, result["partial_file"]
                ),
                result=result,
            )
        return ToolResult(ok=True, result=result)

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Status first, then counts. Never the node bodies.

        summarize_for_llm is truncated from the end, so anything a reader needs
        in order to distrust the output goes at the top.
        """
        if not result.ok:
            return f"Normalization failed: {result.error_code} - {result.message}"

        data = result.result or {}
        if "coverage" in data:
            return _generation_summary(data, result)
        if "digest" in data:
            return _bounded_digest(data)

        pair = data.get("pair", {})
        engagement = data.get("engagement", {})
        inventory = data.get("inventory", {})
        conflicts = data.get("conflict_count", 0)
        warnings = data.get("warnings", [])

        lines = [
            f"Normalized {data.get('node_count', 0)} nodes "
            f"across {len(inventory.get('paths', []))} paths.",
            f"Pair: {pair.get('pair_join', 'n/a')} "
            f"(provenance {pair.get('provenance_status', 'n/a')}, "
            f"verified={pair.get('verified', False)}).",
            f"Field conflicts: {conflicts}.",
            _flow_map_line(data.get("flow_map") or {}),
            "Context grades: "
            + ", ".join(
                f"{grade} {count}"
                for grade, count in (data.get("completeness") or {}).items()
            )
            + ".",
            f"Actor {engagement.get('actor_label')} against "
            f"{engagement.get('application')}, "
            f"ATT&CK {engagement.get('attack_version')}.",
        ]

        model = engagement.get("projection_model")
        lines.append(
            f"Projection model: {model.get('provider')} / {model.get('model_served')}."
            if model
            else "Projection model: no attribution in the export."
        )

        for severity in (nz.SEVERITY_BLOCKING, nz.SEVERITY_ADVISORY):
            counts: dict[str, int] = {}
            for warning in warnings:
                if warning.get("severity") == severity:
                    counts[warning["code"]] = counts.get(warning["code"], 0) + 1
            if counts:
                lines.append(
                    f"Warnings ({severity}): "
                    + ", ".join(f"{code} x{n}" for code, n in sorted(counts.items()))
                )

        flagged = sum(1 for node in data.get("nodes", []) if node.get("review_flags"))
        if flagged:
            lines.append(f"{flagged} node(s) carry a review flag.")

        coverage = data.get("mitigation_coverage") or {}
        taxonomy = data.get("taxonomy") or {}
        lines.append(
            f"Mitigations: {coverage.get('covered', 0)} covered of "
            f"{coverage.get('total', 0)}, focus on "
            f"{coverage.get('nodes_with_focus', 0)} node(s)"
            + (
                f", {len(coverage.get('unresolved') or [])} id(s) unresolved."
                if coverage.get("unresolved")
                else "."
            )
        )
        if taxonomy:
            counts = ", ".join(f"{name} {count}" for name, count in taxonomy.items())
            lines.append(f"Taxonomy v19.2: {counts}.")
        return "\n".join(lines)


def _persist_partial(result: dict[str, Any], context: Any) -> dict[str, Any]:
    """Write an incomplete generation result and register it.

    Returns where it went, or why it did not. A write failure is reported in
    the message and never replaces GENERATION_INCOMPLETE as the error.
    """
    workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = workspace / "artifacts" / f"attack_path_detection_designer_partial_{stamp}.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return {"path": None, "artifact_id": None, "error": f"{type(exc).__name__}: {exc}"}

    saved: dict[str, Any] = {"path": str(path), "artifact_id": None, "error": None}
    register = getattr(context, "register_artifact", None)
    if callable(register):
        try:
            ref = register(
                "json_events",
                str(path),
                "attack_path_detection_designer",
                {
                    "kind": "detection_drafts_partial",
                    "generation_status": result["coverage"]["generation_status"],
                },
            )
            saved["artifact_id"] = getattr(ref, "artifact_id", None)
        except Exception as exc:  # noqa: BLE001 - the file is still on disk
            saved["error"] = f"written but not registered: {type(exc).__name__}: {exc}"
    return saved


def _incomplete_message(
    ledger: dict[str, Any],
    problems: list[dict[str, Any]],
    calls: list[dict[str, Any]],
    partial_file: dict[str, Any] | None = None,
) -> str:
    """Say why, not only that.

    A failed run prints its message and little else, so the diagnosis has to
    travel in the message. Without it, "0 of 8" sends the reader to the code.
    """
    lines = [
        f"{ledger['generated_drafts']} of {ledger['expected_nodes']} nodes produced "
        f"a valid draft ({ledger['generation_status']})."
    ]
    if partial_file:
        if partial_file.get("path"):
            lines.append(
                f"  Partial result saved: {partial_file.get('artifact_id') or '(unregistered)'} "
                f"{partial_file['path']}"
            )
        if partial_file.get("error"):
            lines.append(f"  Partial result not fully saved: {partial_file['error']}")
    for call in calls:
        lines.append(
            f"  call {call['path_id']} ({call['nodes']} nodes): ok={call['ok']}, "
            f"truncated={call['truncated']}, finish={call['finish_reason']}, "
            f"model={call['model_used']}"
        )
    for problem in problems[:3]:
        detail = problem.get("problem") or problem.get("problems")
        lines.append(f"  - {str(detail)[:300]}")
        if problem.get("reply_starts"):
            lines.append(f"    reply began: {problem['reply_starts'][:200]!r}")
    if len(problems) > 3:
        lines.append(f"  ... {len(problems) - 3} more; 'show' the result for all.")
    return "\n".join(lines)


def _review_flag_line(drafts: list[dict[str, Any]]) -> str:
    """Which questions the drafts carry, by code and by draft count.

    A flag that only exists in the artifact is a flag nobody acts on: this
    summary is what downstream reasoning sees. Codes and counts only - the
    messages name fields and sources, and nine drafts' worth of them would
    push everything after this line past the budget.
    """
    counts: dict[str, int] = {}
    flagged = 0
    for draft in drafts:
        extension = draft.get("x_eventmill")
        flags = extension.get("review_flags") if isinstance(extension, dict) else None
        if not isinstance(flags, list) or not flags:
            continue
        flagged += 1
        for flag in flags:
            code = flag.get("code") if isinstance(flag, dict) else None
            counts[str(code or "UNCODED")] = counts.get(str(code or "UNCODED"), 0) + 1
    if not counts:
        return f"Review flags: none across {len(drafts)} draft(s)."
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return (
        f"Review flags: {sum(counts.values())} across {flagged} of {len(drafts)} "
        f"draft(s) - " + ", ".join(f"{code} {n}" for code, n in ranked) + "."
    )


def _generation_summary(data: dict[str, Any], result: ToolResult) -> str:
    """Coverage first, then why anything is missing. Never the drafts."""
    ledger = data.get("coverage") or {}
    lines = [
        f"Generation {ledger.get('generation_status')}: "
        f"{ledger.get('generated_drafts', 0)} of {ledger.get('expected_nodes', 0)} "
        "nodes have a valid draft.",
        f"Validation status: {ledger.get('validation_status')} "
        "(schema validity is not operational validation).",
    ]
    for name in ("missing_draft_ids", "unexpected_draft_ids", "duplicate_draft_ids"):
        values = ledger.get(name) or []
        if values:
            lines.append(f"{name.replace('_', ' ')}: {len(values)} - {', '.join(values[:5])}")
    rejected = data.get("rejected") or []
    if rejected:
        lines.append(f"Rejected: {len(rejected)}; first: {str(rejected[0])[:180]}")
    lines.append(_review_flag_line(data.get("drafts") or []))
    calls = data.get("calls") or []
    if calls:
        models = data.get("generation_model") or []
        projection = (data.get("engagement") or {}).get("projection_model") or {}
        lines.append(
            f"{len(calls)} call(s). Generation model: "
            f"{', '.join(models) or 'unknown'}; the path was projected by "
            f"{projection.get('model_served') or 'an unattributed model'}."
        )
    lines.append(
        "Drafts are unvalidated against telemetry; a person still judges detection quality."
    )
    return "\n".join(lines)


def _bounded_digest(data: dict[str, Any], budget: int = 3600) -> str:
    """The digest, cut at whole nodes and saying what it cut.

    summarize_for_llm truncates from the end, so a long corpus must lose whole
    nodes with a stated count rather than stop mid-line.
    """
    header = (
        f"{data.get('node_count', 0)} nodes, pair {data.get('pair_status')}, "
        f"{data.get('conflict_count', 0)} conflict(s), flow map "
        f"{data.get('flow_map_lineage') or 'none'}. "
        + ", ".join(f"{g} {n}" for g, n in (data.get("completeness") or {}).items())
        + "."
    )
    lines = data.get("digest") or []
    out = [header]
    used = len(header)
    for start in range(0, len(lines), 3):
        node_lines = lines[start : start + 3]
        cost = sum(len(line) + 1 for line in node_lines)
        if used + cost > budget:
            remaining = (len(lines) - start) // 3
            out.append(f"... {remaining} more node(s); 'show <artifact_id>' for all.")
            break
        out.extend(node_lines)
        used += cost
    return "\n".join(out)


def _flow_map_line(flow_map: dict[str, Any]) -> str:
    """One line on the flow map. Lineage is reported, never a verdict."""
    if not flow_map.get("supplied"):
        return "Flow map: none supplied."
    resolved = len(flow_map.get("components_resolved") or [])
    total = resolved + len(flow_map.get("components_unresolved") or [])
    line = (
        f"Flow map: {flow_map.get('lineage')} ({flow_map.get('filename')}), "
        f"{resolved} of {total} node components resolve"
    )
    if not flow_map.get("application_matches", True):
        line += f", application {flow_map.get('application')!r} differs"
    return line + "."
