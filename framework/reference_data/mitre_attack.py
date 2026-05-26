"""Shared MITRE ATT&CK technique lookup for all Event Mill plugins.

The compact technique database is built by ``scripts/build_mitre_lookup.py``
from official MITRE CTI STIX bundles (Enterprise + ICS) and stored as a single
JSON file alongside this module.

Usage from any plugin::

    from framework.reference_data.mitre_attack import get_mitre_db, validate_technique_id

    db = get_mitre_db()                       # dict[technique_id, metadata]
    entry = db.get("T1190")                   # {'name': '...', 'tactics': [...], 'url': '...'}
    is_valid = validate_technique_id("T1655") # False — not in ATT&CK
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("eventmill.reference_data.mitre")

# ---------------------------------------------------------------------------
# Module-level state (loaded at most once per process)
# ---------------------------------------------------------------------------

_DATA_FILE = Path(__file__).parent / "mitre_techniques.json"
_TECHNIQUE_DB: dict[str, dict] | None = None


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


def _reset() -> None:
    """Reset the cached database (for testing only)."""
    global _TECHNIQUE_DB
    _TECHNIQUE_DB = None
