"""Requirement profile: the contract between the profiler and the auditor.

A profile is plain JSON a person can read and edit. It is produced by
``extract_profile`` from a standard document, or written by hand for an
internal standard; either way it passes through ``validate_profile`` here.

Everything a model supplies is treated as untrusted shape. ``normalise_requirement``
never raises on a malformed record: it returns what it could keep and says what
it dropped, so one bad requirement costs itself and not the run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PROFILE_VERSION = "1.0"

ASSESSABLE_FROM = ("record_content", "record_set", "not_assessable_from_sample")
OBLIGATIONS = ("must", "should", "may")
# What sort of rule a requirement about records is. Only ``presence`` can be
# answered by counting the records that carry an element; the auditor lists
# the others without a count.
KINDS = ("presence", "prohibition", "quality", "event_selection", "permission")
_PROHIBITION = re.compile(
    r"\b(?:shall|must|should|may|will|can)\s+not\b|\bnever\b|\bprohibited\b",
    re.IGNORECASE,
)
REVIEW_STATUSES = ("draft_unreviewed", "reviewed")
QUOTE_STATUSES = ("found", "quote_not_found", "not_checked")
PRECISIONS = ("second", "millisecond", "microsecond")
CONSTRAINT_KEYS = ("timezone_required", "min_precision", "allowed_values")

_CATALOGUE_PATH = Path(__file__).resolve().parent / "catalogue.json"


def load_catalogue() -> dict[str, Any]:
    with open(_CATALOGUE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _text(value: Any, limit: int = 2000) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip()[:limit]


def _normalise_constraints(raw: Any, notes: list[str], where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        if raw not in (None, {}, []):
            notes.append(f"{where}: constraints was not an object and was dropped")
        return {}
    kept: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in CONSTRAINT_KEYS:
            notes.append(f"{where}: unknown constraint '{key}' dropped")
            continue
        if key == "timezone_required":
            if isinstance(value, bool):
                if value:
                    kept[key] = True
            else:
                notes.append(f"{where}: timezone_required must be true or false")
        elif key == "min_precision":
            if value in PRECISIONS:
                kept[key] = value
            else:
                notes.append(
                    f"{where}: min_precision '{value}' is not one of {list(PRECISIONS)}"
                )
        elif key == "allowed_values":
            if isinstance(value, list) and value:
                kept[key] = [_text(item, 200) for item in value if _text(item, 200)]
            else:
                notes.append(f"{where}: allowed_values must be a non-empty list")
    return kept


def _normalise_element(
    entry: Any,
    known: dict[str, Any],
    notes: list[str],
    where: str,
    dropped: list[str],
) -> dict[str, Any] | None:
    """One ``{"element": name}`` entry, or None when it names nothing usable."""
    if isinstance(entry, str):
        entry = {"element": entry}
    if not isinstance(entry, dict):
        notes.append(f"{where}: an element entry was not an object and was dropped")
        return None
    name = _text(entry.get("element"), 60)
    if name not in known:
        dropped.append(name or "<empty>")
        return None
    constraints = _normalise_constraints(entry.get("constraints"), notes, where)
    if constraints and known[name].get("value_type") != "timestamp":
        for key in ("timezone_required", "min_precision"):
            if key in constraints:
                notes.append(f"{where}: {key} only applies to a timestamp, dropped")
                constraints.pop(key)
    item: dict[str, Any] = {"element": name}
    if constraints:
        item["constraints"] = constraints
    return item


def normalise_requirement(
    raw: Any, catalogue: dict[str, Any], index: int
) -> tuple[dict[str, Any] | None, list[str]]:
    """Coerce one model- or hand-written requirement into the profile shape.

    Returns ``(requirement, notes)``. ``requirement`` is None only when the
    record has no usable identity or text at all. An element name outside the
    catalogue is dropped and recorded in ``unmapped_reason`` rather than kept as
    though the auditor could test it.
    """
    notes: list[str] = []
    if not isinstance(raw, dict):
        return None, [f"requirement {index}: not an object, dropped"]

    requirement_id = _text(raw.get("requirement_id"), 80) or f"REQ-{index:03d}"
    where = f"requirement {requirement_id}"
    summary = _text(raw.get("summary"), 600)
    quote = _text(raw.get("quote"), 1500)
    if not summary and not quote:
        return None, [f"{where}: no summary and no quote, dropped"]

    obligation = _text(raw.get("obligation"), 20).lower()
    if obligation not in OBLIGATIONS:
        notes.append(
            f"{where}: obligation '{obligation}' not recognised, set to 'should'"
        )
        obligation = "should"

    assessable = _text(raw.get("assessable_from"), 40)
    known = catalogue.get("elements", {})
    elements: list[dict[str, Any]] = []
    dropped: list[str] = []
    raw_elements = raw.get("elements")
    if not isinstance(raw_elements, list):
        if raw_elements not in (None, ""):
            notes.append(f"{where}: elements was not a list and was ignored")
        raw_elements = []
    seen: set[str] = set()
    for entry in raw_elements:
        if isinstance(entry, dict) and "any_of" in entry:
            raw_members = entry.get("any_of")
            if not isinstance(raw_members, list):
                notes.append(f"{where}: any_of was not a list and was dropped")
                continue
            members: list[dict[str, Any]] = []
            for member in raw_members:
                item = _normalise_element(member, known, notes, where, dropped)
                if item and all(m["element"] != item["element"] for m in members):
                    members.append(item)
            if len(members) >= 2:
                group: dict[str, Any] = {"any_of": members}
                label = _text(entry.get("label"), 60)
                if label:
                    group["label"] = label
                elements.append(group)
                continue
            if not members:
                continue
            notes.append(
                f"{where}: an any_of group had one usable element, "
                f"'{members[0]['element']}', kept as a required element"
            )
            item = members[0]
        else:
            item = _normalise_element(entry, known, notes, where, dropped)
        if item is None or item["element"] in seen:
            continue
        seen.add(item["element"])
        elements.append(item)

    unmapped_reason = _text(raw.get("unmapped_reason"), 400) or None
    if dropped:
        note = "element(s) not in the catalogue: " + ", ".join(sorted(set(dropped)))
        notes.append(f"{where}: {note}")
        unmapped_reason = f"{unmapped_reason}; {note}" if unmapped_reason else note

    if assessable not in ASSESSABLE_FROM:
        fallback = "record_content" if elements else "not_assessable_from_sample"
        notes.append(
            f"{where}: assessable_from '{assessable}' not recognised, set to '{fallback}'"
        )
        assessable = fallback
    if assessable != "not_assessable_from_sample" and not elements:
        if not unmapped_reason:
            unmapped_reason = "no catalogue element expresses this requirement"
    if assessable == "not_assessable_from_sample" and elements:
        notes.append(
            f"{where}: marked not assessable from a sample but lists elements; "
            "elements kept for reference and not tested"
        )

    kind: str | None = None
    if assessable != "not_assessable_from_sample":
        kind = _text(raw.get("kind"), 30).lower()
        if kind not in KINDS:
            if kind:
                notes.append(f"{where}: kind '{kind}' not recognised, set to 'presence'")
            kind = "presence"
        # A sentence worded as a ban is never counted as presence, whatever
        # the model called it: a wrong label here would turn the absence of
        # the banned thing into a reported shortfall.
        if kind == "presence" and _PROHIBITION.search(quote):
            notes.append(
                f"{where}: worded as a prohibition, kind set to 'prohibition'"
            )
            kind = "prohibition"

    page = raw.get("page")
    if isinstance(page, bool) or not isinstance(page, int):
        try:
            page = int(str(page).strip())
        except (TypeError, ValueError):
            page = None

    quote_status = _text(raw.get("quote_status"), 30)
    if quote_status not in QUOTE_STATUSES:
        quote_status = "not_checked"

    return (
        {
            "requirement_id": requirement_id,
            "section": _text(raw.get("section"), 120),
            "page": page,
            "obligation": obligation,
            "assessable_from": assessable,
            "kind": kind,
            "summary": summary,
            "quote": quote,
            "quote_status": quote_status,
            "elements": elements,
            "unmapped_reason": unmapped_reason,
        },
        notes,
    )


def validate_profile(profile: Any) -> dict[str, list[str]]:
    """Check a profile a person or a model wrote. Deterministic, no model call.

    ``errors`` are contract violations that stop an audit. ``warnings`` describe
    the profile and never block: an unreviewed draft, a quote that could not be
    located, a requirement the catalogue cannot express.
    """
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(profile, dict):
        return {"errors": ["profile is not a JSON object"], "warnings": []}

    if profile.get("profile_version") != PROFILE_VERSION:
        errors.append(
            f"profile_version must be '{PROFILE_VERSION}', "
            f"found {profile.get('profile_version')!r}"
        )
    standard = profile.get("standard")
    if not isinstance(standard, dict) or not _text(standard.get("title")):
        errors.append("standard.title is required")

    review = profile.get("review_status")
    if review not in REVIEW_STATUSES:
        errors.append(f"review_status must be one of {list(REVIEW_STATUSES)}")
    elif review == "draft_unreviewed":
        warnings.append(
            "review_status is draft_unreviewed: nobody has confirmed these "
            "requirements against the standard"
        )

    catalogue = profile.get("catalogue")
    if not isinstance(catalogue, dict) or not isinstance(
        catalogue.get("elements"), dict
    ):
        errors.append("catalogue.elements is required (copy it from catalogue.json)")
        catalogue = {"elements": {}}
    else:
        valid_types = set(load_catalogue()["value_types"])
        for name, spec in catalogue["elements"].items():
            value_type = spec.get("value_type") if isinstance(spec, dict) else None
            if value_type not in valid_types:
                errors.append(
                    f"catalogue element '{name}' has value_type {value_type!r}; "
                    f"expected one of {sorted(valid_types)}"
                )

    requirements = profile.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        errors.append("requirements must be a non-empty list")
        return {"errors": errors, "warnings": warnings}

    seen: set[str] = set()
    testable = 0
    for index, raw in enumerate(requirements, start=1):
        if not isinstance(raw, dict):
            errors.append(f"requirement {index}: not an object")
            continue
        rid = raw.get("requirement_id")
        if not isinstance(rid, str) or not rid.strip():
            errors.append(f"requirement {index}: requirement_id is required")
            rid = f"#{index}"
        if rid in seen:
            errors.append(f"requirement {rid}: duplicate requirement_id")
        seen.add(rid)
        if raw.get("obligation") not in OBLIGATIONS:
            errors.append(
                f"requirement {rid}: obligation must be one of {list(OBLIGATIONS)}"
            )
        if raw.get("assessable_from") not in ASSESSABLE_FROM:
            errors.append(
                f"requirement {rid}: assessable_from must be one of {list(ASSESSABLE_FROM)}"
            )
        elements = raw.get("elements")
        if not isinstance(elements, list):
            errors.append(f"requirement {rid}: elements must be a list")
            elements = []
        for entry in elements:
            members = [entry]
            if isinstance(entry, dict) and "any_of" in entry:
                members = entry["any_of"]
                if not isinstance(members, list) or len(members) < 2:
                    errors.append(
                        f"requirement {rid}: any_of must list at least two elements"
                    )
                    continue
            for member in members:
                name = member.get("element") if isinstance(member, dict) else None
                if name not in catalogue["elements"]:
                    errors.append(
                        f"requirement {rid}: element {name!r} is not in the catalogue"
                    )
        kind = raw.get("kind")
        if kind is not None and kind not in KINDS:
            errors.append(f"requirement {rid}: kind must be one of {list(KINDS)}")
        if raw.get("assessable_from") in ("record_content", "record_set"):
            if kind not in (None, "presence"):
                continue
            if elements:
                testable += 1
            else:
                warnings.append(
                    f"requirement {rid}: assessable from records but names no "
                    "catalogue element, so the auditor cannot test it"
                )
        if raw.get("quote_status") == "quote_not_found":
            warnings.append(
                f"requirement {rid}: its quote was not found in the document text"
            )
    if testable == 0:
        warnings.append(
            "no requirement is testable against log records; an audit would "
            "report every requirement as out of reach"
        )
    clarity = profile.get("standard_clarity")
    if clarity is not None and not (
        isinstance(clarity, dict) and isinstance(clarity.get("categories"), list)
    ):
        errors.append("standard_clarity must be an object with a categories list")
    return {"errors": errors, "warnings": warnings}
