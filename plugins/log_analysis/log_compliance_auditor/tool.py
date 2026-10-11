"""Log Compliance Auditor.

Checks whether the records in an uploaded log sample contain what a logging
standard requires, and produces tested extraction patterns for ingesting the
same log into a normalized store.

The standard arrives as a requirement profile, the JSON that
`logging_standard_profiler` writes or a person writes by hand. The log can take
any shape: elements in any position and order, custom event codes. A model is
shown a small sample and proposes RE2 patterns; every pattern is then run over
the whole file here, the captured values are checked, and only the failures go
back for another round. The file itself is never uploaded.

Actions:
    survey   Deterministic and free. Record count, container format and the
             record shapes found, with samples. No profile needed.
    audit    The mapping loop, then the alignment report and extraction pack.
             Stops on convergence, round limit, no progress or time budget;
             anything short of converged is reported as such and can be
             continued.
    resume   Continue mapping from a previous run's result artifact.
    assess   Deterministic and free. Re-test saved patterns against a log and
             re-assess, with no model call. For re-checking a new sample of the
             same application, or patterns edited by hand.
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


sv = _load_sibling("survey.py", "log_compliance_auditor_survey")
vd = _load_sibling("validators.py", "log_compliance_auditor_validators")
ml = _load_sibling("mapping_loop.py", "log_compliance_auditor_mapping_loop")
az = _load_sibling("assessment.py", "log_compliance_auditor_assessment")
rn = _load_sibling("renderers.py", "log_compliance_auditor_renderers")

TOOL_NAME = "log_compliance_auditor"
PLUGIN_VERSION = "0.6.0"
ACTIONS = ("survey", "audit", "resume", "assess")
THINKING_LEVELS = ("minimal", "low", "medium", "high")
# The plugin's limit is 600 s. Stop starting model calls well before it, so a
# run ends by saving what it has rather than by being cut off.
DEFAULT_TIME_BUDGET_SECONDS = 480
MAX_SAMPLE_LINES = 200


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
        thinking_level=thinking_level,
    )


def _max_tokens(llm_query: Any, thinking_level: str, content_tokens: int) -> int:
    ask = getattr(llm_query, "output_limits", None)
    if ask is not None:
        try:
            limits = ask(None, thinking_level)
            return min(
                limits.max_output_tokens,
                content_tokens + limits.thinking_reserve_tokens,
            )
        except Exception:  # noqa: BLE001 - sizing must never fail the run
            pass
    return content_tokens


def _resolve(
    payload: dict[str, Any],
    context: Any,
    id_key: str,
    path_keys: tuple[str, ...],
    what: str,
) -> tuple[Path | None, str]:
    """A readable local path for an artifact id or a file path, or why not."""
    artifacts = getattr(context, "artifacts", None) or []
    artifact_id = payload.get(id_key)
    if artifact_id:
        artifact = next((a for a in artifacts if a.artifact_id == artifact_id), None)
        if (
            artifact is not None
            and artifact.file_path
            and Path(artifact.file_path).exists()
        ):
            return Path(artifact.file_path), ""
    for key in path_keys:
        value = payload.get(key)
        if not value:
            continue
        path = Path(value)
        if path.exists():
            return path, ""
        for artifact in artifacts:
            candidate = Path(artifact.file_path) if artifact.file_path else None
            if candidate and candidate.name == path.name and candidate.exists():
                return candidate, ""
        return None, f"{what} not found: {value}"
    if artifact_id:
        return None, (
            f"{what}: artifact '{artifact_id}' not found in session, or its file is "
            "not readable. Use 'artifacts' to list loaded artifacts."
        )
    return None, f"{what} was not supplied"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _fingerprint(parts: dict[str, Any]) -> str:
    body = json.dumps(parts, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(body).hexdigest()[:16]


def _run_record(
    log_info: dict[str, Any],
    profile_path: Path,
    profile: dict[str, Any],
    state: dict[str, Any],
    assessment: dict[str, Any],
    baseline: dict[str, Any] | None,
) -> dict[str, Any]:
    """What this run was, and what it concluded, each reduced to a fingerprint.

    Two runs with the same ``inputs_fingerprint`` were asked the same question;
    if their ``outcome_fingerprint`` differs, the model is what varied.
    """
    calls = [c for c in state.get("calls", []) if c.get("ok")]
    inputs = {
        "log_sha256": log_info["sha256"],
        "profile_sha256": _sha256(profile_path),
        "profile_review_status": profile.get("review_status"),
        "catalogue_version": (profile.get("catalogue") or {}).get("catalogue_version"),
        "baseline_sha256": (baseline or {}).get("sha256"),
        "plugin_version": PLUGIN_VERSION,
        "prompt_version": ml.PROMPT_VERSION,
        "settings": {
            k: state["settings"].get(k)
            for k in (
                "target_coverage",
                "target_pass_rate",
                "target_depth",
                "sample_lines",
                "thinking_level",
            )
        },
        "provider_ids": sorted({str(c.get("provider_id")) for c in calls}),
        "model_versions": sorted(
            {str(c.get("model_version") or c.get("model_used")) for c in calls}
        ),
    }
    outcome = {
        "records": assessment["records"],
        "records_mapped": assessment["records_mapped"],
        "elements": {
            name: entry["signature"] for name, entry in assessment["elements"].items()
        },
        "findings": {
            f["requirement_id"]: [f["state"], f.get("records_with_all_elements")]
            for f in assessment["findings"]
        },
    }
    return {
        **inputs,
        "split_signature": assessment.get("split_signature"),
        "inputs_fingerprint": _fingerprint(inputs),
        "outcome_fingerprint": _fingerprint(outcome),
    }


def _patterns_from_document(document: Any) -> tuple[list[Any], dict[str, Any] | None]:
    """Raw patterns, and the saved state if there is one, from a prior output.

    Accepts a run result (which embeds the mapping state), a bare mapping
    state, or an extraction spec. All three are files a person may have edited,
    so what comes back is raw and goes through ``normalise_pattern`` again.
    """
    if not isinstance(document, dict):
        return [], None
    state = (
        document.get("mapping_state")
        if isinstance(document.get("mapping_state"), dict)
        else None
    )
    if (
        state is None
        and isinstance(document.get("patterns"), list)
        and "settings" in document
    ):
        state = document
    if state is not None:
        patterns = state.get("patterns")
        return (patterns if isinstance(patterns, list) else []), state
    record_types = document.get("record_types")
    if isinstance(record_types, list):
        raw = []
        for record_type in record_types:
            if not isinstance(record_type, dict):
                continue
            fields = {}
            for field in record_type.get("fields") or []:
                if isinstance(field, dict) and isinstance(field.get("name"), str):
                    fields[field["name"]] = {
                        "element": field.get("element"),
                        "format": field.get("format"),
                    }
            raw.append(
                {
                    **{
                        k: record_type.get(k)
                        for k in (
                            "pattern_id",
                            "kind",
                            "regex",
                            "requires",
                            "describes",
                            "envelope",
                            "program",
                            "message_regex",
                        )
                    },
                    "fields": fields,
                }
            )
        return raw, None
    return [], None


class LogComplianceAuditor:
    """Map a log's record elements and report them against a requirement profile."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": TOOL_NAME,
            "version": PLUGIN_VERSION,
            "pillar": "log_analysis",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        action = payload.get("action", "audit")
        if action not in ACTIONS:
            errors.append(
                f"Invalid action '{action}'. Must be one of: {', '.join(ACTIONS)}."
            )
        if not payload.get("artifact_id") and not payload.get("file_path"):
            errors.append("'artifact_id' (or 'file_path') of the log file is required")
        if action in ("audit", "resume", "assess"):
            if not payload.get("profile_artifact_id") and not payload.get(
                "profile_path"
            ):
                errors.append(
                    "'profile_artifact_id' (or 'profile_path') is required: the requirement "
                    "profile from logging_standard_profiler"
                )
        if action in ("resume", "assess"):
            if not payload.get("state_artifact_id") and not payload.get("state_path"):
                errors.append(
                    "'state_artifact_id' (or 'state_path') is required: the result or "
                    "extraction spec of a previous run"
                )
        level = payload.get("thinking_level")
        if level is not None and level not in THINKING_LEVELS:
            errors.append(
                f"thinking_level must be one of: {', '.join(THINKING_LEVELS)}"
            )
        for key, low, high in (
            ("max_rounds", 1, 10),
            ("sample_lines", 20, MAX_SAMPLE_LINES),
            ("max_records", 100, None),
            ("time_budget_seconds", 60, 560),
        ):
            value = payload.get(key)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                errors.append(f"{key} must be an integer")
            elif value < low or (high is not None and value > high):
                errors.append(
                    f"{key} must be at least {low}"
                    + (f" and at most {high}" if high else "")
                )
        coverage = payload.get("target_coverage")
        if coverage is not None and not (
            isinstance(coverage, (int, float))
            and not isinstance(coverage, bool)
            and 0.5 <= coverage <= 1.0
        ):
            errors.append("target_coverage must be a number between 0.5 and 1.0")
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        action = payload.get("action", "audit")
        started = time.monotonic()
        log_path, problem = _resolve(
            payload, context, "artifact_id", ("file_path", "path"), "Log file"
        )
        if log_path is None:
            return ToolResult(
                ok=False, error_code="ARTIFACT_NOT_FOUND", message=problem
            )
        try:
            if action == "survey":
                return self._survey(log_path, payload)
            return self._audit(action, log_path, payload, context, started)
        except (
            Exception
        ) as exc:  # noqa: BLE001 - a plugin returns errors, it does not raise
            return ToolResult(
                ok=False,
                error_code="INTERNAL_ERROR",
                message=f"{action} failed: {type(exc).__name__}: {exc}",
            )

    # -------------------------------------------------------------------
    # survey
    # -------------------------------------------------------------------

    @staticmethod
    def _survey_for_result(survey: dict[str, Any]) -> dict[str, Any]:
        """The survey without most of its raw lines: a result is not a log copy."""
        trimmed = {k: v for k, v in survey.items() if k != "clusters"}
        trimmed["clusters"] = [
            {
                **{
                    k: c[k]
                    for k in ("cluster_id", "kind", "count", "share", "template")
                },
                "samples": [s["text"][:300] for s in c["samples"][:3]],
            }
            for c in survey["clusters"][:25]
        ]
        trimmed["clusters_omitted"] = max(0, len(survey["clusters"]) - 25)
        return trimmed

    def _survey(self, log_path: Path, payload: dict[str, Any]) -> ToolResult:
        survey = sv.survey_file(log_path, payload.get("max_records"))
        if not survey["records"]:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_UNREADABLE",
                message=f"{log_path.name} is empty or contains no readable text.",
            )
        return ToolResult(
            ok=True,
            result={
                "action": "survey",
                "log_file": log_path.name,
                "survey": self._survey_for_result(survey),
            },
        )

    # -------------------------------------------------------------------
    # audit / resume / assess
    # -------------------------------------------------------------------

    def _audit(
        self,
        action: str,
        log_path: Path,
        payload: dict[str, Any],
        context: Any,
        started: float,
    ) -> ToolResult:
        if not ml.re2_available():
            return ToolResult(
                ok=False,
                error_code="DEPENDENCY_MISSING",
                message=(
                    "google-re2 is not installed. Patterns are tested with RE2 so that a "
                    "model-written regex cannot hang the run. Install the "
                    "plugins-log-analysis extra."
                ),
            )
        profile_path, problem = _resolve(
            payload,
            context,
            "profile_artifact_id",
            ("profile_path",),
            "Requirement profile",
        )
        if profile_path is None:
            return ToolResult(
                ok=False, error_code="ARTIFACT_NOT_FOUND", message=problem
            )
        try:
            raw_profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_UNREADABLE",
                message=f"Requirement profile {profile_path.name} is not readable JSON: {exc}",
            )
        profile, problems = az.read_profile(raw_profile)
        if profile is None:
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=(
                    f"{profile_path.name} is not a usable requirement profile: "
                    + "; ".join(problems)
                    + ". Check it with logging_standard_profiler --action validate_profile."
                ),
            )
        catalogue = profile["catalogue"]
        wanted = az.wanted_elements(profile)
        value_elements = az.constrained_value_elements(profile)

        llm = getattr(context, "llm_query", None) if context else None
        if action in ("audit", "resume") and llm is None:
            return ToolResult(
                ok=False,
                error_code="LLM_UNAVAILABLE",
                message=(
                    f"{action} needs a connected model to propose patterns. Run 'connect' "
                    "first. 'survey' and 'assess' work without one."
                ),
            )

        notes: list[str] = []
        prior_state = None
        prior_patterns: list[dict[str, Any]] = []
        if action in ("resume", "assess"):
            state_path, problem = _resolve(
                payload, context, "state_artifact_id", ("state_path",), "Previous run"
            )
            if state_path is None:
                return ToolResult(
                    ok=False, error_code="ARTIFACT_NOT_FOUND", message=problem
                )
            try:
                document = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                return ToolResult(
                    ok=False,
                    error_code="ARTIFACT_UNREADABLE",
                    message=f"{state_path.name} is not readable JSON: {exc}",
                )
            raw_patterns, prior_state = _patterns_from_document(document)
            for index, raw in enumerate(raw_patterns, start=1):
                pattern, pattern_notes = ml.normalise_pattern(
                    raw, catalogue, f"s{index}"
                )
                notes.extend(pattern_notes)
                if pattern is not None:
                    prior_patterns.append(ml.restore_flags(pattern, raw))
            if not prior_patterns and action == "assess":
                return ToolResult(
                    ok=False,
                    error_code="INPUT_VALIDATION_FAILED",
                    message=(
                        f"{state_path.name} holds no usable pattern. 'assess' needs the "
                        "result or extraction spec of a previous audit. "
                        + " | ".join(notes[:3])
                    ),
                )

        max_records = payload.get("max_records")
        survey = sv.survey_file(log_path, max_records)
        if not survey["records"]:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_UNREADABLE",
                message=f"{log_path.name} is empty or contains no readable text.",
            )

        settings = dict(ml.DEFAULTS)
        if prior_state and isinstance(prior_state.get("settings"), dict):
            settings.update(
                {k: v for k, v in prior_state["settings"].items() if k in ml.DEFAULTS}
            )
        for key in ("max_rounds", "target_coverage", "sample_lines", "thinking_level"):
            if payload.get(key) is not None:
                settings[key] = payload[key]
        settings["sample_lines"] = min(int(settings["sample_lines"]), MAX_SAMPLE_LINES)

        log_info = {
            "file": log_path.name,
            "bytes": log_path.stat().st_size,
            "sha256": _sha256(log_path),
        }
        state = ml.new_state(log_info, settings)
        if prior_state:
            for key in ("rounds_run", "history", "calls", "sent"):
                if isinstance(prior_state.get(key), type(state[key])):
                    state[key] = prior_state[key]
            previous = (prior_state.get("log") or {}).get("sha256")
            if previous and previous != log_info["sha256"]:
                notes.append(
                    "the log file differs from the one these patterns were built on; "
                    "they were re-tested against this file"
                )
        state["patterns"] = prior_patterns

        stamp = datetime.now(timezone.utc)
        tag = stamp.strftime("%Y%m%d_%H%M%S")
        art_dir = (
            Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace")) / "artifacts"
        )
        art_dir.mkdir(parents=True, exist_ok=True)
        checkpoint = art_dir / f"{TOOL_NAME}_state_{tag}.json"

        def save_checkpoint() -> None:
            body = {k: v for k, v in state.items() if not k.startswith("_")}
            checkpoint.write_text(
                json.dumps(body, indent=2, default=str), encoding="utf-8"
            )

        if action == "assess":
            test = ml.run_patterns(
                log_path, prior_patterns, sv, vd, max_records, value_elements
            )
            state["patterns"] = ml.order_patterns(prior_patterns)
            state["test"] = ml._strip_test(test)
            state["depth"] = ml.depth(test, prior_patterns)
            state["_residue"] = test["residue"]
            state["status"] = "assessed_without_model"
            state["stop_reason"] = "saved patterns re-tested; no model call was made"
        else:
            thinking_level = settings["thinking_level"]

            def ask(prompt: str) -> dict[str, Any]:
                # Written before each call so that a run cut off mid-call still
                # leaves what earlier rounds learned on disk.
                save_checkpoint()
                response = llm.query_text(
                    prompt=prompt,
                    system_context=ml.SYSTEM_CONTEXT,
                    max_tokens=_max_tokens(
                        llm, thinking_level, settings["reply_content_tokens"]
                    ),
                    hints=_hints(thinking_level),
                )
                ok = bool(getattr(response, "ok", False))
                return {
                    "ok": ok,
                    "text": getattr(response, "text", None),
                    "error": (
                        None
                        if ok
                        else str(getattr(response, "error", None) or "failed")
                    ),
                    "truncated": bool(getattr(response, "truncated", False)),
                    "provider_id": getattr(response, "provider_id", None),
                    "vendor": getattr(response, "vendor", None),
                    "model_used": getattr(response, "model_used", None),
                    "model_version": getattr(response, "model_version", None),
                    "token_usage": getattr(response, "token_usage", None),
                }

            budget = payload.get("time_budget_seconds") or DEFAULT_TIME_BUDGET_SECONDS
            ml.run_loop(
                log_path,
                survey,
                catalogue,
                wanted,
                state,
                ask,
                sv,
                vd,
                deadline=started + budget,
                max_records=max_records,
                value_elements=value_elements,
            )

        residue = state.pop("_residue", [])
        save_checkpoint()
        patterns = state["patterns"]
        test = state["test"]

        if not patterns or not test:
            return ToolResult(
                ok=False,
                error_code="MAPPING_FAILED",
                message=(
                    f"No pattern survived testing against {log_path.name} "
                    f"({state['status']}: {state['stop_reason']}). "
                    + " | ".join(
                        (state["history"][-1]["notes"] if state["history"] else notes)[
                            :3
                        ]
                    )
                    + f" State saved at {checkpoint}."
                ),
                details={"state_file": str(checkpoint), "status": state["status"]},
            )

        assessment = az.assess(profile, patterns, test, vd)
        spec = rn.extraction_spec(patterns, test, log_info, state["status"])
        unmatched = [
            {
                "cluster_id": c["cluster_id"],
                "count": c["count"],
                "samples": [s["text"][:300] for s in c["samples"][:3]],
            }
            for c in sv.cluster_lines(residue)[:10]
        ]
        result = {
            "action": action,
            "status": state["status"],
            "stop_reason": state["stop_reason"],
            "log_file": log_path.name,
            "standard": profile.get("standard") or {},
            "profile_file": profile_path.name,
            "profile_review_status": profile.get("review_status"),
            "run_record": rn.run_record(
                profile, state, stamp.isoformat(timespec="seconds")
            ),
            "run": _run_record(
                log_info, profile_path, profile, state, assessment, None
            ),
            "rounds_run": state["rounds_run"],
            "sent_to_model": state["sent"],
            "envelope": survey.get("envelope"),
            "depth": state.get("depth"),
            "assessment": assessment,
            "unmatched_groups": unmatched,
            "survey": self._survey_for_result(survey),
            "extraction_spec": spec,
            "mapping_state": state,
            "notes": notes,
            "elapsed_seconds": round(time.monotonic() - started, 1),
        }

        files = [
            (
                "json_events",
                art_dir / f"{TOOL_NAME}_result_{tag}.json",
                json.dumps(result, indent=2, default=str),
                "audit_result",
            ),
            (
                "text",
                art_dir / f"{TOOL_NAME}_report_{tag}.md",
                rn.markdown_report(
                    profile,
                    assessment,
                    spec,
                    state,
                    survey,
                    az.standard_clarity(profile),
                    stamp.isoformat(timespec="seconds"),
                ),
                "alignment_report",
            ),
            (
                "json_events",
                art_dir / f"{TOOL_NAME}_extraction_spec_{tag}.json",
                json.dumps(spec, indent=2),
                "extraction_spec",
            ),
            (
                "text",
                art_dir / f"{TOOL_NAME}_bigquery_{tag}.sql",
                rn.bigquery_sql(spec),
                "extraction_bigquery",
            ),
            (
                "text",
                art_dir / f"{TOOL_NAME}_splunk_props_{tag}.conf",
                rn.splunk_conf(spec),
                "extraction_splunk",
            ),
            (
                "json_events",
                art_dir / f"{TOOL_NAME}_elastic_pipeline_{tag}.json",
                json.dumps(rn.elastic_pipeline(spec), indent=2),
                "extraction_elastic",
            ),
        ]
        # The checkpoint's content is inside the result file; keep one copy.
        try:
            checkpoint.unlink()
        except OSError:
            pass
        register = getattr(context, "register_artifact", None) if context else None
        outputs: list[dict[str, Any]] = []
        produced: dict[str, Any] = {}
        for artifact_type, path, body, kind in files:
            path.write_text(body, encoding="utf-8")
            entry = {"kind": kind, "file": str(path), "artifact_id": None}
            if register is not None:
                registered = register(
                    artifact_type, str(path), TOOL_NAME, {"kind": kind}
                )
                entry["artifact_id"] = getattr(registered, "artifact_id", None)
            else:
                outputs.append({"artifact_type": artifact_type, "file_path": str(path)})
            produced[kind] = entry
        result["outputs"] = produced
        return ToolResult(ok=True, result=result, output_artifacts=outputs or None)

    # -------------------------------------------------------------------
    # summary
    # -------------------------------------------------------------------

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"{TOOL_NAME} failed: {result.message}"
        data = result.result or {}
        if data.get("action") == "survey":
            survey = data["survey"]
            lines = [
                f"Survey of {data.get('log_file')}: {survey['records']} records, "
                f"container {survey['container']}, {survey['cluster_count']} record shapes "
                f"({survey['scan']} scan).",
            ]
            if survey.get("continuation_lines"):
                lines.append(
                    f"{survey['continuation_lines']} continuation lines joined to their record."
                )
            for cluster in survey["clusters"][:6]:
                sample = cluster["samples"][0][:140] if cluster["samples"] else ""
                lines.append(
                    f"  [{cluster['share'] * 100:.1f}%] {cluster['count']} x {sample}"
                )
            if survey["cluster_count"] > 6:
                lines.append(f"  ... and {survey['cluster_count'] - 6} smaller shapes")
            return "\n".join(lines)

        assessment = data.get("assessment") or {}
        counts = assessment.get("counts") or {}
        sent = data.get("sent_to_model") or {}
        standard = data.get("standard") or {}
        lead = (
            "Mapping complete"
            if data.get("status") == "converged"
            else (
                "Saved patterns re-tested"
                if data.get("status") == "assessed_without_model"
                else f"MAPPING INCOMPLETE ({data.get('status')}: {data.get('stop_reason')})"
            )
        )
        lines = [
            f"{lead}. {data.get('log_file')} against '{standard.get('title')}': "
            f"{assessment.get('records_mapped')} of {assessment.get('records')} records mapped "
            f"({(assessment.get('coverage') or 0) * 100:.1f}%) into "
            f"{len((data.get('extraction_spec') or {}).get('record_types') or [])} record type(s) "
            f"in {data.get('rounds_run')} round(s).",
        ]
        envelope = data.get("envelope")
        depth = data.get("depth") or {}
        if envelope:
            lines.append(
                f"Envelope: {envelope['kind']}, {envelope['records']} records fit it; "
                f"PRI present in {envelope['with_pri']}, process id in "
                f"{envelope['with_pid']}; {envelope['program_count']} program(s). "
                f"Messages broken down per program for "
                f"{depth.get('records_broken_down', 0)} records "
                f"({(depth.get('share') or 0) * 100:.0f}%); the rest keep the message whole."
            )
        elif depth.get("records_held_as_free_text"):
            lines.append(
                f"{depth['records_held_as_free_text']} records are matched by a pattern "
                "that leaves most of the line in one free-text field."
            )
        if data.get("profile_review_status") != "reviewed":
            lines.append(
                "The requirement profile is draft_unreviewed: findings rest on an "
                "unconfirmed reading of the standard."
            )
        lines.append(
            f"Of {assessment.get('requirements')} requirements, "
            f"{assessment.get('requirements_assessed')} were assessed against records: "
            f"{counts.get('observed', 0)} observed, "
            f"{counts.get('partially_observed', 0)} partially observed, "
            f"{counts.get('not_observed', 0)} not observed. "
            f"{counts.get('not_assessable_from_sample', 0)} cannot be shown by a log sample; "
            f"{counts.get('not_evaluated', 0)} not evaluated."
        )
        coverage = assessment.get("investigation_coverage") or []
        if coverage:
            lines.append(
                "What an investigation needs, share of records carrying it: "
                + ", ".join(
                    f"{c['category']} {c['share'] * 100:.0f}%" for c in coverage
                )
                + "."
            )
        not_counted = assessment.get("not_counted_by_kind") or {}
        if not_counted:
            lines.append(
                "Not counted because they are not rules about an element being "
                "present: "
                + ", ".join(f"{n} {kind}" for kind, n in sorted(not_counted.items()))
                + ". These need a person to look."
            )
        gaps = [
            f
            for f in assessment.get("findings") or []
            if f["state"] in ("not_observed", "partially_observed")
        ]
        gaps.sort(
            key=lambda f: (f["state"] != "not_observed", f["obligation"] != "must")
        )
        for finding in gaps[:8]:
            lines.append(
                f"  {finding['state']} ({finding['obligation']}) {finding['requirement_id']}: "
                f"{finding['summary'][:110]} [{finding['share'] * 100:.0f}% of records]"
            )
        if len(gaps) > 8:
            lines.append(f"  ... and {len(gaps) - 8} more in the report")
        lines.append(
            f"Sent to the model: {sent.get('lines', 0)} log lines "
            f"({sent.get('chars', 0)} chars) in {sent.get('calls', 0)} call(s)."
        )
        outputs = data.get("outputs") or {}
        report = outputs.get("alignment_report") or {}
        lines.append(
            "Outputs: alignment report "
            f"{report.get('artifact_id') or report.get('file')}, extraction spec, and "
            "BigQuery / Splunk / Elastic renderings (Splunk and Elastic not executed)."
        )
        if data.get("status") not in ("converged", "assessed_without_model"):
            result_id = (outputs.get("audit_result") or {}).get("artifact_id")
            lines.append(
                "Continue with --action resume --state_artifact_id "
                f"{result_id or '<the result artifact>'}."
            )
        return "\n".join(lines)
