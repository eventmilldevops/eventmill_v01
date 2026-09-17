"""Attack Path Detection Designer.

Turns adversary_path_projector exports into a normalized per-node detection
context. Stage N1 of `docs/specs/attack_path_detection_normalization.md`.

Actions:
    validate_input   Deterministic. Normalizes the supplied sources and reports
                     the node inventory, the identities, the pair decision and
                     every field-level conflict, without writing an artifact
                     and without calling a model.

Planned:
    normalize_paths       stage N4 - the same normalization, persisted as a
                          detection_context_pack artifact.
    generate_detections   the guidance stage - reasons over a pack, costs a
                          heavy-tier call. It is why this plugin declares
                          safe_for_auto_invoke: false, which is a whole-plugin
                          field with no per-action form (spec section 8,
                          decision 7).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
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

ACTIONS = ("validate_input",)

# Named so validate_inputs can say so rather than failing obscurely.
PLANNED_ACTIONS = ("normalize_paths", "generate_detections")


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


class AttackPathDetectionDesigner:
    """Normalize projected attack paths into reviewable node contexts."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "attack_path_detection_designer",
            "version": "0.1.0",
            "pillar": "threat_modeling",
            "actions": list(ACTIONS),
            "planned_actions": list(PLANNED_ACTIONS),
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        action = payload.get("action", "validate_input")
        if action in PLANNED_ACTIONS:
            errors.append(
                f"Action '{action}' is planned but not implemented; "
                f"available now: {', '.join(ACTIONS)}"
            )
        elif action not in ACTIONS:
            errors.append(
                f"Unknown action '{action}'. Valid actions: {', '.join(ACTIONS)}"
            )

        sources = payload.get("sources")
        if not isinstance(sources, list) or not sources:
            errors.append(
                "'sources' must be a non-empty list of file paths to projector exports "
                "(one document, or a path graph and a scenario seed of the same run)"
            )
        elif len(sources) > 2:
            errors.append(
                "'sources' accepts at most two documents: one graph and one seed"
            )
        else:
            for entry in sources:
                if not isinstance(entry, str):
                    errors.append("each entry in 'sources' must be a file path string")
                elif not Path(entry).exists():
                    errors.append(f"source not found: {entry}")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        sources: list[str] = payload.get("sources") or []
        accept_unverified = bool(payload.get("accept_unverified_pair", False))

        documents = []
        for entry in sources:
            path = Path(entry)
            try:
                # Always explicit: the default encoding on Windows is cp1252,
                # and these documents contain a U+2014 that a mojibake read
                # turns into a spurious conflict on every gap node.
                with open(path, encoding="utf-8") as handle:
                    parsed = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_UNREADABLE",
                    message=f"Could not read {path.name}: {exc}",
                )
            try:
                documents.append(nz.load_document(parsed, path.name))
            except nz.NormalizationError as exc:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_UNRECOGNIZED",
                    message=str(exc),
                    details={"file": path.name},
                )

        primary = documents[0]
        secondary = documents[1] if len(documents) > 1 else None
        try:
            normalized = nz.normalize(
                primary, secondary, accept_unverified_pair=accept_unverified
            )
        except nz.NormalizationError as exc:
            return ToolResult(
                ok=False, error_code="NORMALIZATION_FAILED", message=str(exc)
            )

        result = normalized.as_dict()
        result["node_count"] = len(normalized.nodes)
        result["pair_status"] = normalized.pair["provenance_status"]
        result["conflict_count"] = len(normalized.input_conflicts)
        return ToolResult(ok=True, result=result)

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Status first, then counts. Never the node bodies.

        summarize_for_llm is truncated from the end, so anything a reader needs
        in order to distrust the output goes at the top.
        """
        if not result.ok:
            return f"Normalization failed: {result.error_code} - {result.message}"

        data = result.result or {}
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
            f"Actor {engagement.get('actor_label')} against "
            f"{engagement.get('application')}, "
            f"ATT&CK {engagement.get('attack_version')}.",
        ]

        model = engagement.get("model_attribution")
        lines.append(
            f"Model: {model.get('provider')} / {model.get('model_served')}."
            if model
            else "Model: no attribution in the export."
        )

        if warnings:
            counts: dict[str, int] = {}
            for warning in warnings:
                counts[warning["code"]] = counts.get(warning["code"], 0) + 1
            lines.append(
                "Warnings: "
                + ", ".join(f"{code} x{n}" for code, n in sorted(counts.items()))
            )

        flagged = sum(1 for node in data.get("nodes", []) if node.get("review_flags"))
        if flagged:
            lines.append(f"{flagged} node(s) carry a review flag.")

        lines.append(
            "Context is unenriched: no flow map joined, no completeness grade assigned "
            "(stage N3)."
        )
        return "\n".join(lines)
