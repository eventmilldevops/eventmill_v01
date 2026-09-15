"""Shared MITRE ATT&CK technique lookup for all Event Mill plugins.

The compact technique database is built by ``scripts/build_mitre_lookup.py``
from official MITRE ATT&CK STIX bundles (Enterprise + ICS) and stored as
``mitre_techniques.json`` alongside this module.  The same script builds
``mitre_relationships.json``: groups, campaigns, software and mitigations
with the techniques they use or mitigate, plus procedure examples.

Usage from any plugin::

    from framework.reference_data.mitre_attack import get_mitre_db, validate_technique_id

    db = get_mitre_db()                       # dict[technique_id, metadata]
    entry = db.get("T1190")                   # {'name': '...', 'tactics': [...], 'url': '...'}
    is_valid = validate_technique_id("T1655") # False — not in ATT&CK

    from framework.reference_data.mitre_attack import (
        find_group, techniques_for_group, mitigations_for_technique,
    )
    gid = find_group("Cozy Bear")             # "G0016"
    techniques_for_group(gid)                 # ["T1003.006", "T1021.006", ...]
    mitigations_for_technique("T1566.001")    # ["M1017", "M1021", ...]

The module also owns the tactic vocabulary (``TACTIC_ORDER``,
``LEGACY_TACTIC_ALIASES`` and the helpers below) so that every plugin orders
and validates tactics against the same ATT&CK release as the technique data.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

logger = logging.getLogger("eventmill.reference_data.mitre")

# ---------------------------------------------------------------------------
# Module-level state (loaded at most once per process)
# ---------------------------------------------------------------------------

_DATA_FILE = Path(__file__).parent / "mitre_techniques.json"
_TECHNIQUE_DB: dict[str, dict] | None = None

_RETIRED_FILE = Path(__file__).parent / "mitre_retired_techniques.json"
_RETIRED: dict[str, dict] | None = None
# technique name (normalised) -> ids carrying it, built on first use
_NAME_INDEX: dict[str, list[str]] | None = None

_RELATIONSHIPS_FILE = Path(__file__).parent / "mitre_relationships.json"
_RELATIONSHIPS: dict | None = None
# Reverse indexes over the relationships file, built on first use
_INDEXES: dict[str, dict[str, list[str]]] | None = None


# ---------------------------------------------------------------------------
# Tactic vocabulary (ATT&CK v19)
# ---------------------------------------------------------------------------

# Kill-chain ordering of ATT&CK tactics.  Enterprise tactics follow the v19
# matrix order; the three ICS-only tactics are inserted where the ICS matrix
# places them.  ATT&CK v19 retired "Defense Evasion" in favour of "Stealth"
# and "Defense Impairment" — see LEGACY_TACTIC_ALIASES.
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Stealth",
    "Defense Impairment",
    "Evasion",  # ICS
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Inhibit Response Function",  # ICS
    "Impair Process Control",  # ICS
    "Exfiltration",
    "Impact",
)

# Tactics retired by an ATT&CK release, mapped to their successors.  Older
# artifacts and LLM output trained on earlier releases still use these names.
LEGACY_TACTIC_ALIASES: dict[str, tuple[str, ...]] = {
    "Defense Evasion": ("Stealth", "Defense Impairment"),
}

_TACTIC_BY_LOWER: dict[str, str] = {t.lower(): t for t in TACTIC_ORDER}
_LEGACY_BY_LOWER: dict[str, tuple[str, ...]] = {
    t.lower(): successors for t, successors in LEGACY_TACTIC_ALIASES.items()
}
_ORDINAL: dict[str, int] = {t: i for i, t in enumerate(TACTIC_ORDER, start=1)}


def canonical_tactic(name: str) -> str | None:
    """Return the canonical spelling of a current tactic, or None.

    Comparison is case-insensitive so ``"command And control"`` resolves to
    ``"Command and Control"``.  Retired tactics return None; use
    :func:`resolve_legacy_tactic` for those.
    """
    return _TACTIC_BY_LOWER.get((name or "").strip().lower())


def is_legacy_tactic(name: str) -> bool:
    """Return True if *name* is a tactic retired by a later ATT&CK release."""
    return (name or "").strip().lower() in _LEGACY_BY_LOWER


def tactic_ordinal(name: str) -> int:
    """Return the 1-based kill-chain position of a tactic.

    Retired tactics sort at the position of their first successor.  Unknown
    names sort after every known tactic.
    """
    canonical = canonical_tactic(name)
    if canonical is None:
        successors = _LEGACY_BY_LOWER.get((name or "").strip().lower())
        if successors:
            canonical = successors[0]
    return _ORDINAL.get(canonical or "", len(TACTIC_ORDER) + 1)


def resolve_legacy_tactic(name: str, allowed_tactics: Iterable[str]) -> str | None:
    """Map a retired tactic onto the successor a technique actually uses.

    Returns the single successor of *name* that appears in *allowed_tactics*
    (a technique's ``tactics`` list, compared case-insensitively).  Returns
    None when *name* is not a retired tactic, when no successor is allowed,
    or when more than one is — the caller should leave the value alone and
    let validation flag it.
    """
    successors = _LEGACY_BY_LOWER.get((name or "").strip().lower())
    if not successors:
        return None
    allowed_lower = {t.lower() for t in allowed_tactics}
    matches = [s for s in successors if s.lower() in allowed_lower]
    return matches[0] if len(matches) == 1 else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_mitre_db() -> dict[str, dict]:
    """Load the compact MITRE technique lookup (built by build_mitre_lookup.py).

    Returns an empty dict (with a warning) if the data file has not been
    generated yet.  The file is loaded at most once per process.
    """
    global _TECHNIQUE_DB
    if _TECHNIQUE_DB is not None:
        return _TECHNIQUE_DB

    if not _DATA_FILE.exists():
        logger.warning(
            "MITRE lookup file not found at %s — "
            "run 'python scripts/build_mitre_lookup.py' to build it. "
            "Plugins will use LLM-provided data only.",
            _DATA_FILE,
        )
        _TECHNIQUE_DB = {}
        return _TECHNIQUE_DB

    try:
        with open(_DATA_FILE, "r", encoding="utf-8") as fh:
            _TECHNIQUE_DB = json.load(fh)
        logger.info(
            "Loaded MITRE technique lookup: %d techniques from %s",
            len(_TECHNIQUE_DB), _DATA_FILE,
        )
    except Exception as exc:
        logger.warning("Failed to load MITRE lookup: %s", exc)
        _TECHNIQUE_DB = {}

    return _TECHNIQUE_DB


def validate_technique_id(technique_id: str) -> bool:
    """Return True if *technique_id* exists in the official ATT&CK matrix."""
    return technique_id in get_mitre_db()


def enrich_technique(technique_id: str) -> dict[str, Any]:
    """Return metadata for a technique ID from the local lookup.

    Returns an empty dict if the ID is not found.  Returned keys:
    ``name``, ``tactics`` (list[str]), ``url``.
    """
    return get_mitre_db().get(technique_id, {})


def technique_count() -> int:
    """Return the number of techniques in the loaded database."""
    return len(get_mitre_db())


def _retired_map() -> dict[str, dict]:
    """Curated map of retired technique ids, loaded at most once."""
    global _RETIRED
    if _RETIRED is not None:
        return _RETIRED
    try:
        with open(_RETIRED_FILE, encoding="utf-8") as fh:
            _RETIRED = json.load(fh).get("retired") or {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load retired-technique map: %s", exc)
        _RETIRED = {}
    return _RETIRED


def _normalise_name(name: str) -> str:
    return " ".join(str(name or "").split()).strip().lower()


def _name_index() -> dict[str, list[str]]:
    """Technique name -> every id carrying that name.

    A list, not a single id: 23 enterprise names are shared by two or three
    sub-techniques under different parents ("Botnet" is both T1583.005 and
    T1584.005), so a name alone is not always an identifier.
    """
    global _NAME_INDEX
    if _NAME_INDEX is not None:
        return _NAME_INDEX
    index: dict[str, list[str]] = {}
    for tid, meta in get_mitre_db().items():
        key = _normalise_name(meta.get("name", ""))
        if key:
            index.setdefault(key, []).append(tid)
    _NAME_INDEX = index
    return _NAME_INDEX


def _resolve_by_name(technique_name: str) -> str | None:
    """The one current id carrying this name, or None if that is not unique.

    Tries the whole name first, then the part after the last colon, because a
    retired id often arrives with its old parent attached ("Impair Defenses:
    Disable or Modify Tools" where 19.2 calls it just "Disable or Modify
    Tools"). When the leaf name is ambiguous the old parent name is used to
    choose between the candidates, and anything still ambiguous is refused:
    guessing here would attach a real ATT&CK id to the wrong technique, which
    is worse than leaving the entry flagged.
    """
    index = _name_index()
    whole = _normalise_name(technique_name)
    if not whole:
        return None

    hits = index.get(whole, [])
    if len(hits) == 1:
        return hits[0]

    if ":" not in technique_name:
        return None

    leaf = _normalise_name(technique_name.rsplit(":", 1)[1])
    candidates = index.get(leaf, [])
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) < 2:
        return None

    # Ambiguous leaf: keep only candidates whose parent still carries the
    # parent name the caller supplied.
    parent_name = _normalise_name(technique_name.split(":", 1)[0])
    db = get_mitre_db()
    narrowed = [
        tid for tid in candidates
        if _normalise_name(db.get(tid.split(".")[0], {}).get("name", ""))
        == parent_name
    ]
    return narrowed[0] if len(narrowed) == 1 else None


def resolve_retired_technique(
    technique_id: str, technique_name: str = "",
) -> tuple[str, str] | None:
    """Current id for a retired one, with the basis for the decision.

    Returns ``(current_id, basis)`` where *basis* is "curated" or "name", or
    None when the id needs no remapping, is unknown, or cannot be resolved
    unambiguously. An id already in the database is never remapped.

    This exists because of version skew, not model error: a model emits the
    numbering in its training data and in most published reporting, so a
    correct technique arrives under an id that ATT&CK has since retired. With
    no resolution it is demoted to "non-ATT&CK" — dropped from every
    ATT&CK-keyed view and shown to an analyst as though it were not real.
    """
    tid = (technique_id or "").strip()
    if not tid:
        return None
    db = get_mitre_db()
    if not db or tid in db:
        return None

    entry = _retired_map().get(tid)
    if entry is not None:
        target = entry.get("replaced_by")
        # A split technique records its retirement with replaced_by=null; it
        # has no single successor, so it stays flagged rather than being
        # pointed at whichever successor happens to be listed first.
        if target and target in db:
            return (str(target), "curated")
        return None

    by_name = _resolve_by_name(technique_name)
    if by_name:
        return (by_name, "name")
    return None


def retirement_note(technique_id: str) -> str:
    """What the curated map knows about a retired id, for an error message."""
    entry = _retired_map().get((technique_id or "").strip())
    if not entry:
        return ""
    successors = entry.get("successors") or []
    if successors:
        return (
            f"{technique_id} ({entry.get('former_name', '')}) was retired and "
            f"split across {', '.join(successors)} — pick the successor the "
            f"report actually describes"
        )
    return f"{technique_id} ({entry.get('former_name', '')}) was retired"


# ---------------------------------------------------------------------------
# Groups, campaigns, software, mitigations
# ---------------------------------------------------------------------------

_EMPTY_RELATIONSHIPS: dict = {
    "attack_version": "",
    "matrices": [],
    "groups": {},
    "campaigns": {},
    "software": {},
    "mitigations": {},
    "procedures": [],
}


def get_mitre_relationships() -> dict:
    """Load the relationships lookup (built by build_mitre_lookup.py).

    Returns a dict with ``groups``, ``campaigns``, ``software`` and
    ``mitigations`` sections keyed by ATT&CK id, and a ``procedures`` list of
    ``{"source", "technique", "text"}`` procedure examples.  Returns an empty
    structure (with a warning) if the file has not been generated yet.  The
    file is loaded at most once per process.
    """
    global _RELATIONSHIPS
    if _RELATIONSHIPS is not None:
        return _RELATIONSHIPS

    if not _RELATIONSHIPS_FILE.exists():
        logger.warning(
            "MITRE relationships file not found at %s — "
            "run 'python scripts/build_mitre_lookup.py' to build it. "
            "Group / mitigation lookups will be empty.",
            _RELATIONSHIPS_FILE,
        )
        _RELATIONSHIPS = dict(_EMPTY_RELATIONSHIPS)
        return _RELATIONSHIPS

    try:
        with open(_RELATIONSHIPS_FILE, "r", encoding="utf-8") as fh:
            _RELATIONSHIPS = json.load(fh)
        logger.info(
            "Loaded MITRE relationships (ATT&CK v%s): %d groups, %d campaigns, "
            "%d software, %d mitigations, %d procedures",
            _RELATIONSHIPS.get("attack_version", "?"),
            len(_RELATIONSHIPS.get("groups", {})),
            len(_RELATIONSHIPS.get("campaigns", {})),
            len(_RELATIONSHIPS.get("software", {})),
            len(_RELATIONSHIPS.get("mitigations", {})),
            len(_RELATIONSHIPS.get("procedures", [])),
        )
    except Exception as exc:
        logger.warning("Failed to load MITRE relationships: %s", exc)
        _RELATIONSHIPS = dict(_EMPTY_RELATIONSHIPS)

    return _RELATIONSHIPS


def _indexes() -> dict[str, dict[str, list[str]]]:
    """Reverse indexes: technique -> groups / software / campaigns / mitigations,
    and lower-cased name or alias -> id for groups and software."""
    global _INDEXES
    if _INDEXES is not None:
        return _INDEXES

    rel = get_mitre_relationships()
    by_technique: dict[str, dict[str, set[str]]] = {
        "groups": {}, "software": {}, "campaigns": {}, "mitigations": {},
    }
    for section in by_technique:
        for entity_id, record in rel.get(section, {}).items():
            for tid in record.get("techniques", []):
                by_technique[section].setdefault(tid, set()).add(entity_id)

    names: dict[str, dict[str, str]] = {"groups": {}, "software": {}, "campaigns": {}}
    for section in names:
        for entity_id, record in rel.get(section, {}).items():
            for label in [record.get("name", "")] + list(record.get("aliases", [])):
                if label:
                    names[section].setdefault(label.lower(), entity_id)

    _INDEXES = {
        f"{section}_by_technique": {
            tid: sorted(ids) for tid, ids in mapping.items()
        }
        for section, mapping in by_technique.items()
    }
    for section, mapping in names.items():
        _INDEXES[f"{section}_by_name"] = mapping
    return _INDEXES


def _lookup_entity(section: str, name_or_id: str) -> str | None:
    rel = get_mitre_relationships()
    key = (name_or_id or "").strip()
    if not key:
        return None
    if key.upper() in rel.get(section, {}):
        return key.upper()
    return _indexes()[f"{section}_by_name"].get(key.lower())


def find_group(name_or_id: str) -> str | None:
    """Resolve a group id, name or alias (case-insensitive) to its ATT&CK id."""
    return _lookup_entity("groups", name_or_id)


def find_software(name_or_id: str) -> str | None:
    """Resolve a software id, name or alias (case-insensitive) to its ATT&CK id."""
    return _lookup_entity("software", name_or_id)


def find_campaign(name_or_id: str) -> str | None:
    """Resolve a campaign id, name or alias (case-insensitive) to its ATT&CK id."""
    return _lookup_entity("campaigns", name_or_id)


def techniques_for_group(group_id: str) -> list[str]:
    """Technique ids a group is documented as using (empty if unknown)."""
    return list(get_mitre_relationships()["groups"].get(group_id, {}).get("techniques", []))


def techniques_for_software(software_id: str) -> list[str]:
    """Technique ids a piece of software implements (empty if unknown)."""
    return list(
        get_mitre_relationships()["software"].get(software_id, {}).get("techniques", [])
    )


def techniques_for_campaign(campaign_id: str) -> list[str]:
    """Technique ids observed in a campaign (empty if unknown)."""
    return list(
        get_mitre_relationships()["campaigns"].get(campaign_id, {}).get("techniques", [])
    )


def techniques_for_mitigation(mitigation_id: str) -> list[str]:
    """Technique ids a mitigation addresses (empty if unknown)."""
    return list(
        get_mitre_relationships()["mitigations"].get(mitigation_id, {}).get("techniques", [])
    )


def groups_for_technique(technique_id: str) -> list[str]:
    """Group ids documented as using a technique."""
    return list(_indexes()["groups_by_technique"].get(technique_id, []))


def software_for_technique(technique_id: str) -> list[str]:
    """Software ids that implement a technique."""
    return list(_indexes()["software_by_technique"].get(technique_id, []))


def campaigns_for_technique(technique_id: str) -> list[str]:
    """Campaign ids in which a technique was observed."""
    return list(_indexes()["campaigns_by_technique"].get(technique_id, []))


def mitigations_for_technique(technique_id: str) -> list[str]:
    """Mitigation ids that address a technique."""
    return list(_indexes()["mitigations_by_technique"].get(technique_id, []))


def procedures_for_technique(
    technique_id: str, source_id: str | None = None
) -> list[dict]:
    """Procedure examples for a technique, optionally limited to one source.

    Each item is ``{"source": "G0016", "technique": "T1566.001", "text": ...}``
    where ``source`` is a group, software or campaign id.
    """
    return [
        p for p in get_mitre_relationships().get("procedures", [])
        if p.get("technique") == technique_id
        and (source_id is None or p.get("source") == source_id)
    ]


def _reset() -> None:
    """Reset the cached databases (for testing only)."""
    global _TECHNIQUE_DB, _RELATIONSHIPS, _INDEXES, _RETIRED, _NAME_INDEX
    _TECHNIQUE_DB = None
    _RELATIONSHIPS = None
    _INDEXES = None
    _RETIRED = None
    _NAME_INDEX = None
