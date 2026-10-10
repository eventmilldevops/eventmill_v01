"""Joining what the records were found to contain to what the standard asks.

Deterministic. The states say what was seen in this sample and nothing wider:
``observed`` means the element was captured, with values that pass their
check, in nearly every record. It is not a statement that the application is
compliant, and a requirement about retention or access control is reported as
out of reach of a log sample, never as met or unmet.
"""

from __future__ import annotations

from typing import Any

STATES = (
    "observed",
    "partially_observed",
    "not_observed",
    "not_assessable_from_sample",
    "not_evaluated",
)
OBSERVED_THRESHOLD = 0.99


def read_profile(profile: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Take a profile as it comes off disk. ``(profile, problems)``.

    The auditor is a consumer and reads defensively rather than importing the
    profiler's validator. Problems that make an audit meaningless stop it;
    anything else is carried as a requirement the audit could not evaluate.
    """
    problems: list[str] = []
    if not isinstance(profile, dict):
        return None, ["the profile is not a JSON object"]
    catalogue = profile.get("catalogue")
    if not isinstance(catalogue, dict) or not isinstance(
        catalogue.get("elements"), dict
    ):
        problems.append("the profile has no catalogue.elements")
    else:
        for name, spec in catalogue["elements"].items():
            if not isinstance(spec, dict) or not isinstance(
                spec.get("value_type"), str
            ):
                problems.append(f"catalogue element '{name}' has no value_type")
            else:
                spec.setdefault("description", "")
    requirements = profile.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        problems.append("the profile has no requirements")
    if problems:
        return None, problems
    return profile, []


def wanted_elements(profile: dict[str, Any]) -> list[str]:
    """Catalogue elements that some testable requirement needs, in catalogue order."""
    needed: set[str] = set()
    for requirement in profile["requirements"]:
        if not isinstance(requirement, dict):
            continue
        if requirement.get("assessable_from") == "not_assessable_from_sample":
            continue
        for entry in requirement.get("elements") or []:
            if (
                isinstance(entry, dict)
                and entry.get("element") in profile["catalogue"]["elements"]
            ):
                needed.add(entry["element"])
    return [name for name in profile["catalogue"]["elements"] if name in needed]


def _best_field(
    pattern: dict[str, Any], result: dict[str, Any], element: str
) -> tuple[str | None, dict[str, Any] | None]:
    """The field in this pattern that best carries the element, if any does."""
    best_name, best = None, None
    for name, spec in pattern["fields"].items():
        if spec.get("element") != element:
            continue
        summary = result["fields"].get(name)
        if summary is None:
            continue
        if best is None or summary["valid"] > best["valid"]:
            best_name, best = name, summary
    return best_name, best


def _constraint_valid(
    summary: dict[str, Any], constraints: dict[str, Any], validators_module: Any
) -> tuple[int, list[str]]:
    """How many of the field's valid values also meet the constraints."""
    limit = summary["valid"]
    notes: list[str] = []
    if constraints.get("timezone_required") and summary["value_type"] == "timestamp":
        with_tz = summary.get("with_timezone", 0)
        if with_tz < summary["valid"]:
            notes.append(
                f"{summary['valid'] - with_tz} of {summary['valid']} timestamps carry no "
                "timezone or UTC offset"
            )
        limit = min(limit, with_tz)
    precision = constraints.get("min_precision")
    if precision and summary["value_type"] == "timestamp":
        enough = validators_module.meets_precision(
            summary.get("fraction_digits", {}), precision
        )
        if enough < summary["valid"]:
            notes.append(
                f"{summary['valid'] - enough} of {summary['valid']} timestamps are coarser "
                f"than {precision}"
            )
        limit = min(limit, enough)
    allowed = constraints.get("allowed_values")
    if isinstance(allowed, list) and allowed:
        wanted = {str(v).strip().lower() for v in allowed}
        counts = summary.get("value_counts")
        if counts is None:
            # Too many distinct values to have kept them all; count the most
            # common ones, which understates rather than overstates.
            counts = {top["value"]: top["count"] for top in summary["top_values"]}
            notes.append(
                "too many distinct values to check each against allowed_values; "
                "only the most common were counted"
            )
        inside = sum(c for v, c in counts.items() if v.strip().lower() in wanted)
        outside = [v for v in counts if v.strip().lower() not in wanted]
        if outside:
            notes.append(
                "values outside the allowed set, e.g. "
                + ", ".join(repr(v) for v in outside[:3])
            )
        limit = min(limit, inside)
    return limit, notes


def _state(share: float) -> str:
    if share >= OBSERVED_THRESHOLD:
        return "observed"
    if share <= 0:
        return "not_observed"
    return "partially_observed"


def assess(
    profile: dict[str, Any],
    patterns: list[dict[str, Any]],
    test: dict[str, Any],
    validators_module: Any,
) -> dict[str, Any]:
    """One finding per requirement, with the records behind it."""
    total = test["records"]
    by_id = {p["pattern_id"]: p for p in patterns}
    results = [r for r in test["patterns"] if r["records"] and r["pattern_id"] in by_id]
    findings: list[dict[str, Any]] = []

    for index, requirement in enumerate(profile["requirements"], start=1):
        if not isinstance(requirement, dict):
            continue
        finding: dict[str, Any] = {
            "requirement_id": str(requirement.get("requirement_id") or f"#{index}"),
            "section": requirement.get("section") or "",
            "obligation": requirement.get("obligation") or "should",
            "summary": requirement.get("summary") or "",
            "quote": requirement.get("quote") or "",
            "quote_status": requirement.get("quote_status") or "not_checked",
            "assessable_from": requirement.get("assessable_from"),
        }
        elements = [
            e
            for e in (requirement.get("elements") or [])
            if isinstance(e, dict)
            and e.get("element") in profile["catalogue"]["elements"]
        ]
        if requirement.get("assessable_from") == "not_assessable_from_sample":
            finding["state"] = "not_assessable_from_sample"
            finding["basis"] = (
                "the standard's requirement is not something a log file shows"
            )
            findings.append(finding)
            continue
        if not elements:
            finding["state"] = "not_evaluated"
            finding["basis"] = (
                requirement.get("unmapped_reason")
                or "the requirement names no catalogue element to test"
            )
            findings.append(finding)
            continue

        satisfied_records = 0
        per_type: list[dict[str, Any]] = []
        element_totals = {e["element"]: 0 for e in elements}
        for result in results:
            pattern = by_id[result["pattern_id"]]
            type_min = result["records"]
            type_elements: list[dict[str, Any]] = []
            for entry in elements:
                name, summary = _best_field(pattern, result, entry["element"])
                if summary is None:
                    type_elements.append(
                        {
                            "element": entry["element"],
                            "field": None,
                            "records": 0,
                            "notes": [],
                        }
                    )
                    type_min = 0
                    continue
                count, notes = _constraint_valid(
                    summary, entry.get("constraints") or {}, validators_module
                )
                element_totals[entry["element"]] += count
                type_min = min(type_min, count)
                type_elements.append(
                    {
                        "element": entry["element"],
                        "field": name,
                        "records": count,
                        "examples": [t["value"] for t in summary["top_values"][:3]],
                        "flags": summary["flags"],
                        "notes": notes,
                    }
                )
            # A record satisfies the requirement when it carries every element.
            # Per-field counts are all this pass keeps, so the smallest one is
            # the most records that can have carried all of them.
            satisfied_records += type_min
            per_type.append(
                {
                    "pattern_id": result["pattern_id"],
                    "records": result["records"],
                    "records_with_all_elements": type_min,
                    "state": _state(type_min / result["records"]),
                    "elements": type_elements,
                }
            )
        share = satisfied_records / total if total else 0.0
        finding["state"] = _state(share)
        finding["records_with_all_elements"] = satisfied_records
        finding["records"] = total
        finding["share"] = round(share, 4)
        finding["elements"] = [
            {
                "element": name,
                "records": count,
                "share": round(count / total, 4) if total else 0.0,
            }
            for name, count in element_totals.items()
        ]
        finding["by_record_type"] = per_type
        findings.append(finding)

    counts = {state: 0 for state in STATES}
    by_obligation: dict[str, dict[str, int]] = {}
    for finding in findings:
        counts[finding["state"]] += 1
        bucket = by_obligation.setdefault(finding["obligation"], {s: 0 for s in STATES})
        bucket[finding["state"]] += 1
    assessed = (
        counts["observed"] + counts["partially_observed"] + counts["not_observed"]
    )
    return {
        "records": total,
        "records_mapped": test["matched"],
        "records_unmapped": test["unmatched"],
        "coverage": test["coverage"],
        "requirements": len(findings),
        "requirements_assessed": assessed,
        "counts": counts,
        "by_obligation": by_obligation,
        "findings": findings,
    }
