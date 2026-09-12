#!/usr/bin/env python3
"""Download MITRE ATT&CK STIX bundles and build compact reference lookups.

Downloads the Enterprise and ICS ATT&CK matrices from the official MITRE
``attack-stix-data`` repository (STIX 2.1) and writes two JSON files:

* ``mitre_techniques.json`` — technique_id → name / tactics / matrix / url.
  Used by the threat_intel_ingester plugin for authoritative technique
  name / tactic resolution.
* ``mitre_relationships.json`` — groups (intrusion-set), campaigns, software
  (malware / tool) and mitigations (course-of-action), each with the
  techniques they use or mitigate, plus the procedure examples attached to
  ``uses`` relationships.  This gives actor→technique and
  mitigation→technique maps with no LLM involvement, for scenario building.

The legacy ``mitre/cti`` repository (STIX 2.0) is no longer the primary
distribution channel; ``attack-stix-data`` publishes one versioned bundle per
release, so bumping ATTACK_VERSION is all that is needed for a new release.

Usage:
    python scripts/build_mitre_lookup.py
    python scripts/build_mitre_lookup.py --bundle-dir /path/with/cached/bundles
    python scripts/build_mitre_lookup.py --skip-procedures

Output:
    framework/reference_data/mitre_techniques.json
    framework/reference_data/mitre_relationships.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Pinned ATT&CK release.  Available versions are listed in
# https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json
ATTACK_VERSION = "19.2"

STIX_BASE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
)

MATRICES = ("enterprise", "ics")


def _bundle_filename(matrix: str, version: str) -> str:
    # One versioned STIX 2.1 bundle per matrix, e.g. enterprise-attack-19.2.json
    return f"{matrix}-attack-{version}.json"


def _bundle_url(matrix: str, version: str) -> str:
    return f"{STIX_BASE_URL}/{matrix}-attack/{_bundle_filename(matrix, version)}"


REFERENCE_DIR = Path(__file__).resolve().parent.parent / "framework" / "reference_data"
OUTPUT_PATH = REFERENCE_DIR / "mitre_techniques.json"
RELATIONSHIPS_OUTPUT_PATH = REFERENCE_DIR / "mitre_relationships.json"

# Procedure examples are free text with markdown links and citation markers;
# they are cleaned and capped so the relationships file stays a few MB.
PROCEDURE_MAX_CHARS = 600
DESCRIPTION_MAX_CHARS = 600

# STIX object type -> section of the relationships file
_ENTITY_SECTIONS = {
    "intrusion-set": "groups",
    "campaign": "campaigns",
    "malware": "software",
    "tool": "software",
    "course-of-action": "mitigations",
}

# Section -> regex the ATT&CK external id must match.  Filters out legacy
# Enterprise course-of-action objects that carried technique-style ids.
_ID_PATTERNS = {
    "groups": re.compile(r"^G\d{4}$"),
    "campaigns": re.compile(r"^C\d{4}$"),
    "software": re.compile(r"^S\d{4}$"),
    "mitigations": re.compile(r"^M\d{4}$"),
}

_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((?:https?://)[^)]+\)")
_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_WS_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Shared STIX helpers
# ---------------------------------------------------------------------------


def _attack_ref(obj: dict) -> tuple[str, str]:
    """Return (external_id, url) from the object's mitre-attack reference."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", ""), ref.get("url", "")
    return "", ""


def _is_active(obj: dict) -> bool:
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _clean_text(text: str, limit: int) -> str:
    """Strip markdown links and citation markers, collapse whitespace, cap length."""
    if not text:
        return ""
    text = _MD_LINK_RE.sub(r"\1", text)
    text = _CITATION_RE.sub("", text)
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > limit:
        cut = text[:limit].rsplit(" ", 1)[0]
        text = cut + " ..."
    return text


def _tactic_names(bundle: dict) -> dict[str, str]:
    """Map kill-chain phase shortnames to official tactic names.

    Kill-chain phases only carry the slug (``command-and-control``); the
    ``x-mitre-tactic`` objects in the same bundle carry the display name
    (``Command and Control``).  Using the official name keeps the lookup in
    step with the tactic vocabulary the LLM prompts and plugins use.
    """
    names: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "x-mitre-tactic":
            continue
        shortname = obj.get("x_mitre_shortname", "")
        name = obj.get("name", "")
        if shortname and name:
            names[shortname] = name
    return names


# ---------------------------------------------------------------------------
# Techniques
# ---------------------------------------------------------------------------


def _extract_techniques(bundle: dict, matrix: str) -> dict[str, dict]:
    """Extract technique_id → metadata from a STIX 2.x bundle."""
    techniques: dict[str, dict] = {}
    tactic_names = _tactic_names(bundle)

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if not _is_active(obj):
            continue

        # Technique ID from external references
        ext_id, url = _attack_ref(obj)
        if not ext_id:
            continue

        # Tactics from kill-chain phases, resolved to official tactic names
        # (Title Case of the slug as a fallback if the bundle lacks the
        # tactic object)
        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") in (
                "mitre-attack",
                "mitre-ics-attack",
            ):
                slug = phase["phase_name"]
                tactic = tactic_names.get(slug) or slug.replace("-", " ").title()
                tactics.append(tactic)

        techniques[ext_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "matrix": matrix,
            "url": url,
        }

    return techniques


# ---------------------------------------------------------------------------
# Groups, campaigns, software, mitigations and their relationships
# ---------------------------------------------------------------------------


def _new_entity(section: str, obj: dict, attack_id: str, url: str, matrix: str) -> dict:
    record: dict = {
        "name": obj.get("name", ""),
        "description": _clean_text(obj.get("description", ""), DESCRIPTION_MAX_CHARS),
        "url": url,
        "matrices": {matrix},
        "techniques": set(),
    }
    if section == "groups":
        record["aliases"] = [a for a in obj.get("aliases", []) if a != record["name"]]
        record["software"] = set()
        record["campaigns"] = set()
    elif section == "campaigns":
        record["aliases"] = [a for a in obj.get("aliases", []) if a != record["name"]]
        record["first_seen"] = (obj.get("first_seen") or "")[:10]
        record["last_seen"] = (obj.get("last_seen") or "")[:10]
        record["groups"] = set()
        record["software"] = set()
    elif section == "software":
        record["type"] = obj.get("type", "")
        record["aliases"] = [
            a for a in obj.get("x_mitre_aliases", []) if a != record["name"]
        ]
        record["platforms"] = list(obj.get("x_mitre_platforms", []))
        record["groups"] = set()
        record["campaigns"] = set()
    return record


def _extract_relationships(bundle: dict, matrix: str) -> dict:
    """Extract groups / campaigns / software / mitigations and their edges.

    Only active (non-revoked, non-deprecated) objects are emitted, and an
    edge is kept only when both endpoints are active and known.  Returned
    sets are converted to sorted lists by :func:`_finalize_relationships`.
    """
    result: dict = {
        "groups": {},
        "campaigns": {},
        "software": {},
        "mitigations": {},
        "procedures": [],
    }

    # STIX id -> (section, attack_id) for every active entity; technique
    # STIX id -> technique id for every active technique.
    entity_by_stix: dict[str, tuple[str, str]] = {}
    technique_by_stix: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        if not _is_active(obj):
            continue
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            tid, _ = _attack_ref(obj)
            if tid:
                technique_by_stix[obj["id"]] = tid
            continue
        section = _ENTITY_SECTIONS.get(obj_type)
        if section is None:
            continue
        attack_id, url = _attack_ref(obj)
        if not attack_id or not _ID_PATTERNS[section].match(attack_id):
            continue
        entity_by_stix[obj["id"]] = (section, attack_id)
        result[section][attack_id] = _new_entity(section, obj, attack_id, url, matrix)

    seen_procedures: set[tuple[str, str, str]] = set()

    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship" or not _is_active(obj):
            continue
        rel_type = obj.get("relationship_type")
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")

        if rel_type == "uses":
            src_entity = entity_by_stix.get(src)
            if src_entity is None:
                continue
            src_section, src_id = src_entity
            tid = technique_by_stix.get(tgt)
            if tid is not None:
                result[src_section][src_id]["techniques"].add(tid)
                text = _clean_text(obj.get("description", ""), PROCEDURE_MAX_CHARS)
                if text and (src_id, tid, text) not in seen_procedures:
                    seen_procedures.add((src_id, tid, text))
                    result["procedures"].append(
                        {"source": src_id, "technique": tid, "text": text}
                    )
                continue
            tgt_entity = entity_by_stix.get(tgt)
            if tgt_entity is None:
                continue
            tgt_section, tgt_id = tgt_entity
            if tgt_section == "software" and src_section in ("groups", "campaigns"):
                result[src_section][src_id]["software"].add(tgt_id)
                result["software"][tgt_id][src_section].add(src_id)

        elif rel_type == "mitigates":
            src_entity = entity_by_stix.get(src)
            tid = technique_by_stix.get(tgt)
            if src_entity is None or tid is None:
                continue
            src_section, src_id = src_entity
            if src_section == "mitigations":
                result["mitigations"][src_id]["techniques"].add(tid)

        elif rel_type == "attributed-to":
            src_entity = entity_by_stix.get(src)
            tgt_entity = entity_by_stix.get(tgt)
            if src_entity is None or tgt_entity is None:
                continue
            if src_entity[0] == "campaigns" and tgt_entity[0] == "groups":
                result["campaigns"][src_entity[1]]["groups"].add(tgt_entity[1])
                result["groups"][tgt_entity[1]]["campaigns"].add(src_entity[1])

    return result


def _merge_relationships(acc: dict, part: dict) -> dict:
    """Union *part* into *acc*.  Cross-domain objects share ATT&CK ids."""
    for section in ("groups", "campaigns", "software", "mitigations"):
        for attack_id, record in part[section].items():
            existing = acc[section].get(attack_id)
            if existing is None:
                acc[section][attack_id] = record
                continue
            for key, value in record.items():
                if isinstance(value, set):
                    existing.setdefault(key, set()).update(value)
                elif isinstance(value, list):
                    merged = list(existing.get(key, []))
                    merged.extend(v for v in value if v not in merged)
                    existing[key] = merged
                elif not existing.get(key):
                    existing[key] = value
    seen = {(p["source"], p["technique"], p["text"]) for p in acc["procedures"]}
    for proc in part["procedures"]:
        key = (proc["source"], proc["technique"], proc["text"])
        if key not in seen:
            seen.add(key)
            acc["procedures"].append(proc)
    return acc


def _finalize_relationships(
    data: dict, version: str, include_procedures: bool
) -> dict:
    """Convert working sets to sorted lists and add file metadata."""
    out: dict = {
        "attack_version": version,
        "matrices": list(MATRICES),
    }
    for section in ("groups", "campaigns", "software", "mitigations"):
        out[section] = {}
        for attack_id in sorted(data[section]):
            record = data[section][attack_id]
            out[section][attack_id] = {
                key: (sorted(value) if isinstance(value, set) else value)
                for key, value in record.items()
            }
    out["procedures"] = (
        sorted(data["procedures"], key=lambda p: (p["source"], p["technique"], p["text"]))
        if include_procedures
        else []
    )
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _load_bundle(matrix: str, version: str, bundle_dir: Path | None) -> dict:
    if bundle_dir is not None:
        path = bundle_dir / _bundle_filename(matrix, version)
        print(f"Reading {matrix} ATT&CK v{version} STIX bundle from {path} …")
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    try:
        import requests
    except ImportError:
        print("ERROR: 'requests' package required.  Install with:  pip install requests")
        sys.exit(1)

    url = _bundle_url(matrix, version)
    print(f"Downloading {matrix} ATT&CK v{version} STIX bundle …")
    resp = requests.get(url, timeout=300)
    resp.raise_for_status()
    return resp.json()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--version", default=ATTACK_VERSION,
        help=f"ATT&CK release to build from (default: {ATTACK_VERSION})",
    )
    parser.add_argument(
        "--bundle-dir", type=Path, default=None,
        help="Directory holding already-downloaded <matrix>-attack-<version>.json bundles",
    )
    parser.add_argument(
        "--skip-procedures", action="store_true",
        help="Omit procedure example text from mitre_relationships.json (much smaller file)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    all_techniques: dict[str, dict] = {}
    relationships: dict = {
        "groups": {}, "campaigns": {}, "software": {}, "mitigations": {}, "procedures": [],
    }

    for matrix in MATRICES:
        bundle = _load_bundle(matrix, args.version, args.bundle_dir)

        techniques = _extract_techniques(bundle, matrix)
        print(f"  Extracted {len(techniques)} active techniques from {matrix}")
        all_techniques.update(techniques)

        part = _extract_relationships(bundle, matrix)
        print(
            f"  Extracted {len(part['groups'])} groups, {len(part['campaigns'])} campaigns, "
            f"{len(part['software'])} software, {len(part['mitigations'])} mitigations, "
            f"{len(part['procedures'])} procedures from {matrix}"
        )
        relationships = _merge_relationships(relationships, part)

    REFERENCE_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(all_techniques, fh, indent=2, sort_keys=True)
    print(f"\n✓ Wrote {len(all_techniques)} techniques to {OUTPUT_PATH}")

    final = _finalize_relationships(
        relationships, args.version, include_procedures=not args.skip_procedures
    )
    with open(RELATIONSHIPS_OUTPUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(final, fh, indent=1, sort_keys=True)
    size_mb = RELATIONSHIPS_OUTPUT_PATH.stat().st_size / (1024 * 1024)
    print(
        f"✓ Wrote {len(final['groups'])} groups, {len(final['campaigns'])} campaigns, "
        f"{len(final['software'])} software, {len(final['mitigations'])} mitigations, "
        f"{len(final['procedures'])} procedures to {RELATIONSHIPS_OUTPUT_PATH} "
        f"({size_mb:.1f} MB)"
    )


if __name__ == "__main__":
    main()
