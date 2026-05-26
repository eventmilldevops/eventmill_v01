#!/usr/bin/env python3
"""Download MITRE ATT&CK STIX bundles and build a compact technique lookup.

Downloads the Enterprise and ICS ATT&CK matrices from the official MITRE
GitHub repository, extracts technique metadata, and writes a compact JSON
file used by the threat_intel_ingester plugin for authoritative technique
name / tactic resolution.

Usage:
    python scripts/build_mitre_lookup.py

Output:
    framework/reference_data/mitre_techniques.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required.  Install with:  pip install requests")
    sys.exit(1)


# ATT&CK STIX bundles on GitHub (pinned to ATT&CK v18.1)
STIX_URLS = {
    "enterprise": (
        "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v18.1/"
        "enterprise-attack/enterprise-attack.json"
    ),
    "ics": (
        "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v18.1/"
        "ics-attack/ics-attack.json"
    ),
}

OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "framework"
    / "reference_data"
    / "mitre_techniques.json"
)


def _extract_techniques(bundle: dict, matrix: str) -> dict[str, dict]:
    """Extract technique_id → metadata from a STIX 2.x bundle."""
    techniques: dict[str, dict] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Technique ID from external references
        ext_id = ""
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        if not ext_id:
            continue

        # Tactics from kill-chain phases (normalised to Title Case)
        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") in (
                "mitre-attack",
                "mitre-ics-attack",
            ):
                tactic = phase["phase_name"].replace("-", " ").title()
                tactics.append(tactic)

        techniques[ext_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "matrix": matrix,
            "url": url,
        }

    return techniques


def main() -> None:
    all_techniques: dict[str, dict] = {}

    for matrix, url in STIX_URLS.items():
        print(f"Downloading {matrix} ATT&CK STIX bundle …")
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        bundle = resp.json()

        techniques = _extract_techniques(bundle, matrix)
        print(f"  Extracted {len(techniques)} active techniques from {matrix}")
        all_techniques.update(techniques)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(all_techniques, fh, indent=2, sort_keys=True)

    print(f"\n✓ Wrote {len(all_techniques)} techniques to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
