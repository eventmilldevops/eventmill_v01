"""How clearly a standard asks for what an investigation needs from a record.

Deterministic, no model call. The catalogue names a small set of categories
that are generally accepted as what an event record should say (when, what,
who, and so on). For each one this grades the profile's requirements against
a fixed rubric and lands on one of five bins. A low bin points at a clause to
shore up: a standard that never plainly requires an element cannot be audited
for it, whatever the logs contain.

The grade is of the profile's reading of the standard. A poor extraction
lowers it the same way poor wording does, which is why the clauses behind
each grade are listed.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

BINS = 5
# In the order they are reported. Each is worth one bin above the first.
CRITERIA = ("countable", "mandatory", "specific", "unconditional")
MISSING = {
    "countable": "no clause plainly requires records to carry it",
    "mandatory": "required only as should or may, never shall or must",
    "specific": (
        "only asked for inside a list of alternatives that other information "
        "can satisfy"
    ),
    "unconditional": (
        "every mandatory clause is hedged (where applicable, when needed, "
        "where feasible)"
    ),
}
NOT_ADDRESSED = "no clause about record content names it"
CLAUSES_SHOWN = 8
_HEDGE = re.compile(
    r"\b(?:where|when|if|as|wherever|whenever)\s+(?:technically\s+|reasonably\s+)?"
    r"(?:applicable|appropriate|needed|necessary|supported|possible|practical|"
    r"practicable|feasible|available)\b|\bto the extent\b",
    re.IGNORECASE,
)


def requirements_digest(requirements: Any) -> str:
    """Identify the requirements a grade was computed from.

    A consumer compares this with its own digest of the profile to tell a
    grade that predates a hand edit from a current one.
    """
    text = json.dumps(requirements, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _slots(requirement: dict[str, Any]) -> list[list[dict[str, Any]]]:
    slots = []
    for entry in requirement.get("elements") or []:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("any_of") if "any_of" in entry else [entry]
        members = [
            m
            for m in (raw if isinstance(raw, list) else [])
            if isinstance(m, dict) and isinstance(m.get("element"), str)
        ]
        if members:
            slots.append(members)
    return slots


def grade(profile: dict[str, Any]) -> dict[str, Any] | None:
    """Grade each catalogue category. None when the catalogue defines none."""
    catalogue = profile.get("catalogue")
    categories = (
        catalogue.get("investigation_categories")
        if isinstance(catalogue, dict)
        else None
    )
    requirements = profile.get("requirements")
    if not isinstance(categories, list) or not isinstance(requirements, list):
        return None
    about_records = [
        r
        for r in requirements
        if isinstance(r, dict)
        and r.get("assessable_from") in ("record_content", "record_set")
    ]
    graded: list[dict[str, Any]] = []
    for category in categories:
        if not isinstance(category, dict):
            continue
        members = {str(name) for name in category.get("elements") or []}
        met = {name: False for name in CRITERIA}
        clauses: list[str] = []
        value_rules = 0
        for requirement in about_records:
            slots = _slots(requirement)
            named = [s for s in slots if any(m["element"] in members for m in s)]
            if not named:
                continue
            clauses.append(str(requirement.get("requirement_id") or ""))
            kind = requirement.get("kind") or "presence"
            constrained = any(
                m.get("constraints") for s in named for m in s if m["element"] in members
            )
            if kind in ("quality", "prohibition") or constrained:
                value_rules += 1
            if kind != "presence":
                continue
            must = requirement.get("obligation") == "must"
            pinned = any(all(m["element"] in members for m in s) for s in named)
            met["countable"] = True
            met["mandatory"] = met["mandatory"] or must
            met["specific"] = met["specific"] or pinned
            if must and pinned and not _HEDGE.search(str(requirement.get("quote") or "")):
                met["unconditional"] = True
        if not clauses:
            gaps = [NOT_ADDRESSED]
        else:
            gaps = [MISSING[name] for name in CRITERIA if not met[name]]
        graded.append(
            {
                "category": str(category.get("id") or ""),
                "question": str(category.get("question") or ""),
                "elements": sorted(members),
                "bin": 1 + sum(met.values()),
                "addressed": bool(clauses),
                "criteria": met,
                "gaps": gaps,
                "clauses": clauses[:CLAUSES_SHOWN],
                "clause_count": len(clauses),
                "value_rules": value_rules,
            }
        )
    if not graded:
        return None
    return {
        "bins": BINS,
        "requirements_sha256": requirements_digest(requirements),
        "categories": graded,
    }


def summary_line(clarity: dict[str, Any] | None) -> str:
    if not clarity:
        return ""
    parts = [
        f"{item['category']} {item['bin']}" for item in clarity.get("categories") or []
    ]
    weak = [
        f"{item['category']} ({item['gaps'][0]})"
        for item in clarity.get("categories") or []
        if item["bin"] < BINS and item["gaps"]
    ]
    line = f"Clarity of the standard by category, bin 1 to {BINS}: " + ", ".join(parts) + "."
    if weak:
        line += " To shore up: " + "; ".join(weak[:4]) + "."
    return line
