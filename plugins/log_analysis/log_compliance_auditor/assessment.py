"""Joining what the records were found to contain to what the standard asks.

Deterministic. The states say what was seen in this sample and nothing wider:
``observed`` means the element was captured, with values that pass their
check, in nearly every record. It is not a statement that the application is
compliant, and a requirement about retention or access control is reported as
out of reach of a log sample, never as met or unmet.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

STATES = (
    "observed",
    "partially_observed",
    "not_observed",
    "not_assessable_from_sample",
    "not_evaluated",
)
OBSERVED_THRESHOLD = 0.99
# Why a requirement about records is listed without a count. Counting the
# records that carry an element answers a presence rule and nothing else.
KIND_BASIS = {
    "prohibition": (
        "a prohibition: counting records that carry an element cannot show "
        "that something is absent or not exposed"
    ),
    "quality": (
        "a rule about the quality or consistency of values, which an element "
        "being present does not show"
    ),
    "event_selection": (
        "a rule that a kind of event is logged at all: this audit counts "
        "elements in the records it was given and does not look for "
        "particular events"
    ),
    "permission": "a permission, with nothing to fall short of",
}


BINS = 5
# What an investigation needs a record to say. A profile's catalogue carries
# its own copy; this one serves a profile written before the catalogue had it.
DEFAULT_CATEGORIES = [
    {
        "id": "when",
        "question": "When it happened",
        "elements": [
            "timestamp"
        ]
    },
    {
        "id": "what",
        "question": "What happened",
        "elements": [
            "event_type"
        ]
    },
    {
        "id": "who",
        "question": "Who or what did it",
        "elements": [
            "actor_identity"
        ]
    },
    {
        "id": "outcome",
        "question": "How it ended",
        "elements": [
            "outcome"
        ]
    },
    {
        "id": "where",
        "question": "Where it came from",
        "elements": [
            "host",
            "source_component",
            "source_address"
        ]
    },
    {
        "id": "link",
        "question": "What links it to related events",
        "elements": [
            "session_id"
        ]
    },
    {
        "id": "target",
        "question": "What was acted on",
        "elements": [
            "target_object"
        ]
    },
]


def quintile(share: float) -> int:
    """Bin 1 to 5: under 20%, 20s, 40s, 60s, and 80% or better."""
    return min(BINS, int(max(share, 0.0) * BINS) + 1)


def categories(profile: dict[str, Any]) -> list[dict[str, Any]]:
    known = profile["catalogue"]["elements"]
    raw = profile["catalogue"].get("investigation_categories")
    out = []
    for item in raw if isinstance(raw, list) else DEFAULT_CATEGORIES:
        if not isinstance(item, dict):
            continue
        names = [n for n in item.get("elements") or [] if n in known]
        if names:
            out.append(
                {
                    "category": str(item.get("id") or ""),
                    "question": str(item.get("question") or ""),
                    "elements": names,
                }
            )
    return out


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


def _slots(requirement: dict[str, Any], known: dict[str, Any]) -> list[dict[str, Any]]:
    """What a requirement needs, as slots a record must each fill.

    A plain ``{"element": name}`` entry is a slot with one member. An
    ``{"any_of": [...]}`` entry is a slot any one of its members fills. An
    element may sit in more than one slot.
    """
    slots: list[dict[str, Any]] = []
    for entry in requirement.get("elements") or []:
        if not isinstance(entry, dict):
            continue
        grouped = "any_of" in entry
        raw = entry.get("any_of") if grouped else [entry]
        members = []
        for member in raw if isinstance(raw, list) else []:
            if (
                isinstance(member, dict)
                and member.get("element") in known
                and all(m["element"] != member["element"] for m in members)
            ):
                members.append(member)
        if members:
            slots.append(
                {
                    "members": members,
                    "any_of": grouped and len(members) > 1,
                    "label": str(entry.get("label") or "") if grouped else "",
                }
            )
    return slots


def wanted_elements(profile: dict[str, Any]) -> list[str]:
    """Catalogue elements to look for in the log, in catalogue order.

    Those some testable requirement needs, and those of the investigation
    categories whatever the standard says: coverage of the categories is
    reported for the log on its own account.
    """
    needed: set[str] = {
        name for category in categories(profile) for name in category["elements"]
    }
    for requirement in profile["requirements"]:
        if not isinstance(requirement, dict):
            continue
        if requirement.get("assessable_from") == "not_assessable_from_sample":
            continue
        for slot in _slots(requirement, profile["catalogue"]["elements"]):
            needed.update(member["element"] for member in slot["members"])
    return [name for name in profile["catalogue"]["elements"] if name in needed]


def constrained_value_elements(profile: dict[str, Any]) -> frozenset[str]:
    """Elements some requirement restricts with ``allowed_values``."""
    names: set[str] = set()
    for requirement in profile["requirements"]:
        if not isinstance(requirement, dict):
            continue
        for slot in _slots(requirement, profile["catalogue"]["elements"]):
            for entry in slot["members"]:
                if isinstance(
                    (entry.get("constraints") or {}).get("allowed_values"), list
                ):
                    names.add(str(entry.get("element")))
    return frozenset(names)


def _first_field(pattern: dict[str, Any], element: str) -> str | None:
    for name, spec in pattern["fields"].items():
        if spec.get("element") == element:
            return name
    return None


def _meets(
    combination: dict[str, Any], entry: dict[str, Any], validators_module: Any
) -> tuple[bool, str | None]:
    """Whether one record combination carries the element as the entry requires.

    ``(ok, shortfall)``; ``shortfall`` names the constraint that failed when
    the element was there but did not meet it.
    """
    element = entry["element"]
    if element not in combination["elements"]:
        return False, None
    constraints = entry.get("constraints") or {}
    if element == "timestamp":
        if constraints.get("timezone_required") and not combination["timezone"]:
            return False, "timestamps carry no timezone or UTC offset"
        precision = constraints.get("min_precision")
        if precision:
            need = validators_module.PRECISION_DIGITS.get(precision, 0)
            if combination["fraction_digits"] < need:
                return False, f"timestamps are coarser than {precision}"
    allowed = constraints.get("allowed_values")
    if isinstance(allowed, list) and allowed:
        wanted = {str(v).strip().lower() for v in allowed}
        if combination["values"].get(element) not in wanted:
            return False, "values outside the allowed set"
    return True, None


def _state(share: float) -> str:
    if share >= OBSERVED_THRESHOLD:
        return "observed"
    if share <= 0:
        return "not_observed"
    return "partially_observed"


def investigation_coverage(
    profile: dict[str, Any], test: dict[str, Any]
) -> list[dict[str, Any]]:
    """Per category, the records carrying at least one of its elements.

    Counted from the records alone. It does not depend on which requirements
    the profile holds or how they were worded.
    """
    total = test["records"]
    out: list[dict[str, Any]] = []
    for category in categories(profile):
        names = category["elements"]
        records = 0
        each = {name: 0 for name in names}
        exact = True
        for result in test["patterns"]:
            exact = exact and not result.get("combinations_capped")
            for combination in result.get("combinations", []):
                carried = [n for n in names if n in combination["elements"]]
                for name in carried:
                    each[name] += combination["records"]
                if carried:
                    records += combination["records"]
        share = records / total if total else 0.0
        out.append(
            {
                **category,
                "records": records,
                "share": round(share, 4),
                "bin": quintile(share),
                "count_is_exact": exact,
                "by_element": [
                    {"element": name, "records": each[name]} for name in names
                ],
            }
        )
    return out


def standard_clarity(profile: dict[str, Any]) -> dict[str, Any]:
    """The profiler's grade of the standard, and whether it is still current.

    The grade is the profiler's to compute. This only reads it and compares
    the digest it carries with the requirements now in the profile.
    """
    stored = profile.get("standard_clarity")
    if not isinstance(stored, dict) or not isinstance(stored.get("categories"), list):
        return {"status": "absent", "categories": {}}
    text = json.dumps(profile["requirements"], sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {
        "status": (
            "current" if stored.get("requirements_sha256") == digest else "out_of_date"
        ),
        "categories": {
            str(item.get("category")): item
            for item in stored["categories"]
            if isinstance(item, dict)
        },
    }


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
        slots = _slots(requirement, profile["catalogue"]["elements"])
        elements = list(
            {
                member["element"]: member for slot in slots for member in slot["members"]
            }.values()
        )
        if requirement.get("assessable_from") == "not_assessable_from_sample":
            finding["state"] = "not_assessable_from_sample"
            finding["basis"] = (
                "the standard's requirement is not something a log file shows"
            )
            findings.append(finding)
            continue
        kind = requirement.get("kind") or "presence"
        finding["kind"] = kind
        if kind != "presence" and kind not in KIND_BASIS:
            finding["state"] = "not_evaluated"
            finding["basis"] = f"its kind, {kind!r}, is not one this audit knows"
            findings.append(finding)
            continue
        if not elements:
            finding["state"] = "not_evaluated"
            finding["basis"] = KIND_BASIS.get(kind) or (
                requirement.get("unmapped_reason")
                or "the requirement names no catalogue element to test"
            )
            findings.append(finding)
            continue

        satisfied_records = 0
        per_type: list[dict[str, Any]] = []
        element_totals = {e["element"]: 0 for e in elements}
        slot_totals = [0] * len(slots)
        exact = True
        for result in results:
            pattern = by_id[result["pattern_id"]]
            exact = exact and not result.get("combinations_capped")
            type_all = 0
            type_counts = {e["element"]: 0 for e in elements}
            type_slots = [0] * len(slots)
            shortfalls: dict[str, dict[str, int]] = {e["element"]: {} for e in elements}
            for combination in result.get("combinations", []):
                every = True
                carried: set[str] = set()
                for entry in elements:
                    ok, shortfall = _meets(combination, entry, validators_module)
                    if ok:
                        carried.add(entry["element"])
                        type_counts[entry["element"]] += combination["records"]
                    elif shortfall:
                        bucket = shortfalls[entry["element"]]
                        bucket[shortfall] = (
                            bucket.get(shortfall, 0) + combination["records"]
                        )
                for position, slot in enumerate(slots):
                    if any(m["element"] in carried for m in slot["members"]):
                        type_slots[position] += combination["records"]
                    else:
                        every = False
                if every:
                    type_all += combination["records"]
            type_elements: list[dict[str, Any]] = []
            for entry in elements:
                element = entry["element"]
                name = _first_field(pattern, element)
                summary = result["fields"].get(name) if name else None
                element_totals[element] += type_counts[element]
                item: dict[str, Any] = {
                    "element": element,
                    "field": name,
                    "records": type_counts[element],
                    "notes": [
                        f"{count} of {result['records']} {reason}"
                        for reason, count in sorted(shortfalls[element].items())
                    ],
                }
                if summary is not None:
                    item["examples"] = [t["value"] for t in summary["top_values"][:3]]
                    item["flags"] = summary["flags"]
                type_elements.append(item)
            satisfied_records += type_all
            for position, count in enumerate(type_slots):
                slot_totals[position] += count
            per_type.append(
                {
                    "pattern_id": result["pattern_id"],
                    "records": result["records"],
                    "records_with_all_elements": type_all,
                    "state": _state(type_all / result["records"]),
                    "elements": type_elements,
                    "needs": [
                        {
                            "elements": [m["element"] for m in slot["members"]],
                            "records": type_slots[position],
                        }
                        for position, slot in enumerate(slots)
                    ],
                }
            )
        if kind != "presence":
            finding["state"] = "not_evaluated"
            finding["basis"] = KIND_BASIS[kind]
            finding["records"] = total
            finding["reference_elements"] = [
                {"element": name, "records": count}
                for name, count in element_totals.items()
            ]
            findings.append(finding)
            continue
        share = satisfied_records / total if total else 0.0
        finding["state"] = _state(share)
        finding["records_with_all_elements"] = satisfied_records
        finding["records"] = total
        finding["share"] = round(share, 4)
        finding["count_is_exact"] = exact
        finding["elements"] = [
            {
                "element": name,
                "records": count,
                "share": round(count / total, 4) if total else 0.0,
            }
            for name, count in element_totals.items()
        ]
        finding["needs"] = [
            {
                "elements": [m["element"] for m in slot["members"]],
                "any_of": slot["any_of"],
                "label": slot["label"],
                "records": slot_totals[position],
                "share": round(slot_totals[position] / total, 4) if total else 0.0,
            }
            for position, slot in enumerate(slots)
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
    not_counted: dict[str, int] = {}
    for finding in findings:
        if finding["state"] == "not_evaluated" and finding.get("kind") in KIND_BASIS:
            not_counted[finding["kind"]] = not_counted.get(finding["kind"], 0) + 1
    return {
        "records": total,
        "records_mapped": test["matched"],
        "records_unmapped": test["unmatched"],
        "coverage": test["coverage"],
        "split_signature": test.get("split_signature"),
        "elements": test.get("elements", {}),
        "investigation_coverage": investigation_coverage(profile, test),
        "standard_clarity_status": standard_clarity(profile)["status"],
        "requirements": len(findings),
        "requirements_assessed": assessed,
        "counts": counts,
        "not_counted_by_kind": not_counted,
        "by_obligation": by_obligation,
        "findings": findings,
    }
