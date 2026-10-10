"""Logging Standard Profiler.

Reads a logging or audit standard and writes a requirement profile: the short
list of statements that can be tested against log records, each with its
clause, an exact quote, and the record elements it needs, beside the longer
list of statements no log sample can show.

The profile is the input `log_compliance_auditor` grounds on. It is plain JSON
and can equally be written by hand for an internal standard.

Actions:
    extract_profile    One heavy-tier read of the document, native PDF where
                       the provider supports it, document text otherwise.
                       Every quote is then searched for in the locally
                       extracted text. The result is marked draft_unreviewed.
    validate_profile   Deterministic and free. Checks any profile, generated
                       or hand-written, against the contract.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PLUGIN_DIR = Path(__file__).resolve().parent


def _load_sibling(module_file: str, alias: str):
    """Load a module next to this file.

    The loader imports a plugin under a flat module name with no package, so a
    sibling can only be reached by file location.
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


ps = _load_sibling("profile_schema.py", "logging_standard_profiler_profile_schema")
ex = _load_sibling("extraction.py", "logging_standard_profiler_extraction")

TOOL_NAME = "logging_standard_profiler"
ACTIONS = ("extract_profile", "validate_profile")
THINKING_LEVELS = ("minimal", "low", "medium", "high")
DEFAULT_THINKING_LEVEL = "medium"
# Reply content the extraction is sized for; the provider's thinking reserve
# is added on top and the provider's cap bounds the sum.
REPLY_CONTENT_TOKENS = 24_000
# Stop starting new calls this long before the plugin's 600 s limit.
TIME_BUDGET_SECONDS = 480
CALL_ALLOWANCE_SECONDS = 150


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


def _hints(thinking_level: str):
    try:
        from framework.plugins.protocol import QueryHints
    except ImportError:  # pragma: no cover - framework always present at runtime
        return None
    return QueryHints(
        needs_reasoning=True,
        needs_structured_output=True,
        prefers_native_file=True,
        thinking_level=thinking_level,
    )


def _max_tokens(llm_query: Any, thinking_level: str) -> int:
    ask = getattr(llm_query, "output_limits", None)
    if ask is not None:
        try:
            limits = ask(None, thinking_level)
            return min(
                limits.max_output_tokens,
                REPLY_CONTENT_TOKENS + limits.thinking_reserve_tokens,
            )
        except Exception:  # noqa: BLE001 - sizing must never fail the run
            pass
    return REPLY_CONTENT_TOKENS


def _resolve_source(
    payload: dict[str, Any], context: Any
) -> tuple[Path | None, Any, str]:
    """``(path, artifact_ref, problem)`` for the document or profile to read."""
    artifacts = getattr(context, "artifacts", None) or []
    artifact_id = payload.get("artifact_id")
    if artifact_id:
        artifact = next((a for a in artifacts if a.artifact_id == artifact_id), None)
        if (
            artifact is not None
            and artifact.file_path
            and Path(artifact.file_path).exists()
        ):
            return Path(artifact.file_path), artifact, ""
    file_path = payload.get("file_path")
    if file_path:
        path = Path(file_path)
        if path.exists():
            return path, None, ""
        for artifact in artifacts:
            candidate = Path(artifact.file_path) if artifact.file_path else None
            if candidate and candidate.name == path.name and candidate.exists():
                return candidate, artifact, ""
        return None, None, f"File not found: {file_path}"
    if artifact_id:
        return (
            None,
            None,
            (
                f"Artifact '{artifact_id}' not found in session, or its file is not "
                "readable. Use 'artifacts' to list loaded artifacts."
            ),
        )
    return None, None, "No document supplied"


class LoggingStandardProfiler:
    """Turn a logging standard into a requirement profile an audit can test."""

    def metadata(self) -> dict[str, Any]:
        return {"tool_name": TOOL_NAME, "version": "0.1.0", "pillar": "log_analysis"}

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        action = payload.get("action", "extract_profile")
        if action not in ACTIONS:
            errors.append(
                f"Invalid action '{action}'. Must be one of: {', '.join(ACTIONS)}."
            )
        if not payload.get("artifact_id") and not payload.get("file_path"):
            what = (
                "profile JSON" if action == "validate_profile" else "standard document"
            )
            errors.append(f"'artifact_id' (or 'file_path') of the {what} is required")
        level = payload.get("thinking_level")
        if level is not None and level not in THINKING_LEVELS:
            errors.append(
                f"thinking_level must be one of: {', '.join(THINKING_LEVELS)}"
            )
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        action = payload.get("action", "extract_profile")
        path, artifact, problem = _resolve_source(payload, context)
        if path is None:
            return ToolResult(
                ok=False, error_code="ARTIFACT_NOT_FOUND", message=problem
            )
        try:
            if action == "validate_profile":
                return self._validate_profile(path)
            return self._extract_profile(path, artifact, payload, context)
        except (
            Exception
        ) as exc:  # noqa: BLE001 - a plugin returns errors, it does not raise
            return ToolResult(
                ok=False,
                error_code="INTERNAL_ERROR",
                message=f"{action} failed: {type(exc).__name__}: {exc}",
            )

    # -------------------------------------------------------------------
    # validate_profile
    # -------------------------------------------------------------------

    def _validate_profile(self, path: Path) -> ToolResult:
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_UNREADABLE",
                message=f"{path.name} is not readable JSON: {exc}",
            )
        report = ps.validate_profile(profile)
        requirements = (
            profile.get("requirements") if isinstance(profile, dict) else None
        )
        requirements = requirements if isinstance(requirements, list) else []
        return ToolResult(
            ok=True,
            result={
                "action": "validate_profile",
                "profile_file": path.name,
                "valid": not report["errors"],
                "errors": report["errors"],
                "warnings": report["warnings"],
                "counts": _counts([r for r in requirements if isinstance(r, dict)]),
            },
        )

    # -------------------------------------------------------------------
    # extract_profile
    # -------------------------------------------------------------------

    def _extract_profile(
        self, path: Path, artifact: Any, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        llm = getattr(context, "llm_query", None) if context else None
        if llm is None:
            return ToolResult(
                ok=False,
                error_code="LLM_UNAVAILABLE",
                message=(
                    "extract_profile needs a connected model to read the standard. "
                    "Run 'connect' first; validate_profile works without one."
                ),
            )
        started = time.monotonic()
        thinking_level = payload.get("thinking_level") or DEFAULT_THINKING_LEVEL
        catalogue = ps.load_catalogue()
        pages, text_problem = ex.document_pages(path)
        is_pdf = path.suffix.lower() == ".pdf"
        notes: list[str] = []
        if text_problem:
            notes.append(text_problem)

        calls: list[dict[str, Any]] = []
        standard: dict[str, Any] = {}
        raw_requirements: list[Any] = []
        transport = None

        native_ok = False
        if is_pdf and not payload.get("force_text"):
            supports = getattr(llm, "supports_native_document", None)
            try:
                native_ok = bool(supports and supports("application/pdf"))
            except Exception:  # noqa: BLE001
                native_ok = False
        if native_ok:
            ref = artifact or self._artifact_ref(path)
            response = llm.query_with_document(
                prompt=ex.build_prompt(catalogue, None),
                artifact=ref,
                system_context=ex.SYSTEM_CONTEXT,
                max_tokens=_max_tokens(llm, thinking_level),
                hints=_hints(thinking_level),
            )
            call = self._call_record(response, "native document")
            calls.append(call)
            if response.ok and response.text:
                standard, raw_requirements, parse_notes = ex.parse_reply(response.text)
                notes.extend(parse_notes)
                transport = getattr(response, "transport_path", None) or "native"
                if getattr(response, "truncated", False):
                    notes.append(
                        "the reply stopped at the output cap; requirements late "
                        "in the document may be missing"
                    )
            else:
                notes.append(
                    "native document read failed "
                    f"({call['error'] or 'empty reply'}); falling back to extracted text"
                )

        if not raw_requirements:
            if not any(page.strip() for page in pages):
                return ToolResult(
                    ok=False,
                    error_code="ARTIFACT_UNREADABLE",
                    message=(
                        f"Could not read {path.name}: "
                        + "; ".join(notes or ["no text could be extracted"])
                    ),
                    details={"calls": calls},
                )
            parts = ex.text_parts(pages)
            transport = "extracted_text"
            for number, part in enumerate(parts, start=1):
                if (
                    time.monotonic() - started
                    > TIME_BUDGET_SECONDS - CALL_ALLOWANCE_SECONDS
                ):
                    notes.append(
                        f"stopped before part {number} of {len(parts)} to stay inside "
                        f"the time limit; pages {part['first_page']}-{parts[-1]['last_page']} "
                        "were not read"
                    )
                    break
                note = (
                    f" (part {number} of {len(parts)}, pages "
                    f"{part['first_page']}-{part['last_page']})"
                    if len(parts) > 1
                    else ""
                )
                response = llm.query_text(
                    prompt=ex.build_prompt(catalogue, part["text"], note),
                    system_context=ex.SYSTEM_CONTEXT,
                    max_tokens=_max_tokens(llm, thinking_level),
                    hints=_hints(thinking_level),
                )
                call = self._call_record(response, f"text part {number}")
                calls.append(call)
                if not (response.ok and response.text):
                    notes.append(
                        f"part {number}: call failed ({call['error'] or 'empty reply'})"
                    )
                    continue
                part_standard, part_requirements, parse_notes = ex.parse_reply(
                    response.text
                )
                notes.extend(f"part {number}: {n}" for n in parse_notes)
                if getattr(response, "truncated", False):
                    notes.append(f"part {number}: the reply stopped at the output cap")
                standard = standard or part_standard
                raw_requirements.extend(part_requirements)

        requirements: list[dict[str, Any]] = []
        used_ids: set[str] = set()
        for index, raw in enumerate(raw_requirements, start=1):
            requirement, requirement_notes = ps.normalise_requirement(
                raw, catalogue, index
            )
            notes.extend(requirement_notes)
            if requirement is None:
                continue
            base = requirement["requirement_id"]
            suffix = 2
            while requirement["requirement_id"] in used_ids:
                requirement["requirement_id"] = f"{base}#{suffix}"
                suffix += 1
            used_ids.add(requirement["requirement_id"])
            requirements.append(requirement)

        if not requirements:
            failures = [c for c in calls if c["error"]]
            return ToolResult(
                ok=False,
                error_code="LLM_QUERY_FAILED" if failures else "EXTRACTION_EMPTY",
                message=(
                    f"No requirements were extracted from {path.name} after "
                    f"{len(calls)} call(s). " + " | ".join(notes[:4])
                ),
                details={"calls": calls, "notes": notes},
            )

        quote_counts = ex.check_quotes(requirements, pages)
        stamp = datetime.now(timezone.utc)
        last_call = next((c for c in reversed(calls) if not c["error"]), calls[-1])
        profile = {
            "profile_version": ps.PROFILE_VERSION,
            "standard": {
                "title": str(standard.get("title") or path.stem)[:300],
                "version": str(standard.get("version") or "")[:120],
                "source_file": path.name,
                "document_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "pages": len(pages) if is_pdf else None,
            },
            "provenance": {
                "generated_by": TOOL_NAME,
                "generated_at": stamp.isoformat(timespec="seconds"),
                "provider_id": last_call["provider_id"],
                "vendor": last_call["vendor"],
                "model_used": last_call["model_used"],
                "model_version": last_call["model_version"],
                "thinking_level": thinking_level,
                "transport": transport,
                "calls": len(calls),
            },
            "review_status": "draft_unreviewed",
            "catalogue": catalogue,
            "requirements": requirements,
        }
        report = ps.validate_profile(profile)

        workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
        art_dir = workspace / "artifacts"
        art_dir.mkdir(parents=True, exist_ok=True)
        profile_path = (
            art_dir / f"logging_profile_{stamp.strftime('%Y%m%d_%H%M%S')}.json"
        )
        profile_path.write_text(json.dumps(profile, indent=2), encoding="utf-8")

        output_artifacts = None
        profile_artifact_id = None
        metadata = {
            "kind": "logging_requirement_profile",
            "standard": profile["standard"]["title"],
        }
        register = getattr(context, "register_artifact", None)
        if register is not None:
            registered = register("json_events", str(profile_path), TOOL_NAME, metadata)
            profile_artifact_id = getattr(registered, "artifact_id", None)
        else:
            output_artifacts = [
                {"artifact_type": "json_events", "file_path": str(profile_path)}
            ]

        return ToolResult(
            ok=True,
            result={
                "action": "extract_profile",
                "standard": profile["standard"],
                "review_status": profile["review_status"],
                "profile_file": str(profile_path),
                "profile_artifact_id": profile_artifact_id,
                "counts": _counts(requirements),
                "quote_check": quote_counts,
                "validation": report,
                "notes": notes,
                "calls": calls,
                "elapsed_seconds": round(time.monotonic() - started, 1),
            },
            output_artifacts=output_artifacts,
        )

    @staticmethod
    def _artifact_ref(path: Path) -> Any:
        from framework.plugins.protocol import ArtifactRef

        return ArtifactRef(
            artifact_id=f"lsp_{path.name}",
            artifact_type="pdf_report",
            file_path=str(path),
            metadata={"mime_type": "application/pdf"},
        )

    @staticmethod
    def _call_record(response: Any, label: str) -> dict[str, Any]:
        ok = bool(getattr(response, "ok", False))
        return {
            "call": label,
            "ok": ok,
            "error": None if ok else str(getattr(response, "error", None) or "failed"),
            "provider_id": getattr(response, "provider_id", None),
            "vendor": getattr(response, "vendor", None),
            "model_used": getattr(response, "model_used", None),
            "model_version": getattr(response, "model_version", None),
            "transport_path": getattr(response, "transport_path", None),
            "truncated": bool(getattr(response, "truncated", False)),
            "token_usage": getattr(response, "token_usage", None),
        }

    # -------------------------------------------------------------------
    # summary
    # -------------------------------------------------------------------

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"{TOOL_NAME} failed: {result.message}"
        data = result.result or {}
        counts = data.get("counts") or {}
        if data.get("action") == "validate_profile":
            errors = data.get("errors") or []
            warnings = data.get("warnings") or []
            lines = [
                f"Profile {data.get('profile_file')}: "
                + ("valid" if data.get("valid") else f"INVALID, {len(errors)} error(s)")
                + f", {len(warnings)} warning(s).",
                _counts_line(counts),
            ]
            lines += [f"  error: {e}" for e in errors[:8]]
            lines += [f"  warning: {w}" for w in warnings[:6]]
            return "\n".join(lines)

        standard = data.get("standard") or {}
        quotes = data.get("quote_check") or {}
        lines = [
            f"Requirement profile drafted from '{standard.get('title')}' "
            f"{standard.get('version') or ''}".rstrip()
            + f" - {data.get('review_status')}, not yet checked by a person.",
            _counts_line(counts),
            f"Quotes located in the document text: {quotes.get('found', 0)} found, "
            f"{quotes.get('quote_not_found', 0)} not found, "
            f"{quotes.get('not_checked', 0)} not checked.",
        ]
        if data.get("profile_artifact_id"):
            lines.append(
                f"Profile artifact: {data['profile_artifact_id']} "
                "(pass as --profile_artifact_id to log_compliance_auditor)."
            )
        else:
            lines.append(f"Profile file: {data.get('profile_file')}")
        validation = data.get("validation") or {}
        for error in (validation.get("errors") or [])[:4]:
            lines.append(f"  profile error: {error}")
        notes = data.get("notes") or []
        for note in notes[:6]:
            lines.append(f"  note: {note}")
        if len(notes) > 6:
            lines.append(f"  ... and {len(notes) - 6} more notes in the result")
        return "\n".join(lines)


def _counts(requirements: list[dict[str, Any]]) -> dict[str, Any]:
    by_assessable = {key: 0 for key in ps.ASSESSABLE_FROM}
    by_obligation = {key: 0 for key in ps.OBLIGATIONS}
    testable = 0
    for requirement in requirements:
        assessable = requirement.get("assessable_from")
        if assessable in by_assessable:
            by_assessable[assessable] += 1
        obligation = requirement.get("obligation")
        if obligation in by_obligation:
            by_obligation[obligation] += 1
        if assessable in ("record_content", "record_set") and requirement.get(
            "elements"
        ):
            testable += 1
    return {
        "requirements": len(requirements),
        "testable_against_records": testable,
        "by_assessable_from": by_assessable,
        "by_obligation": by_obligation,
    }


def _counts_line(counts: dict[str, Any]) -> str:
    by = counts.get("by_assessable_from") or {}
    return (
        f"{counts.get('requirements', 0)} requirements: "
        f"{counts.get('testable_against_records', 0)} testable against log records, "
        f"{by.get('not_assessable_from_sample', 0)} not assessable from a log sample."
    )
