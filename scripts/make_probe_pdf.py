#!/usr/bin/env python3
"""Generate the model-interchange probe report and its exact ground truth.

The probe answers one question that a side-by-side comparison of two models
cannot: *how much did each one actually find*. That needs a document whose
indicator inventory is known exactly, which no real threat report provides.

Emits two files:

    <out>.pdf                 3-page synthetic threat report
    <out>.ground_truth.json   every indicator in it, by type

The inventory is 94 unique indicators — 24 IPv4, 20 domain, 16 sha256, 12 URL,
10 CVE, 12 ATT&CK technique. The 12 URLs carry hostnames that appear nowhere in
the 20-domain set, so a regex sweep finds more candidates than there are
indicators and the refinement stage has real discrimination to do rather than
echoing the extractor.

Everything is deterministic: the same inputs produce a byte-identical PDF, so
two runs differ only by the model.

Why this file exists
--------------------
The 2026-09-12 Gemini 3.8 Flash comparison used a script of this name that was
never committed — only its output survived, in the change log. A model-
interchange claim that can only be checked by re-deriving the instrument from a
prose description is not a claim anyone will check. See
``docs/specs/multi_provider_llm_clients.md``.

Deliberate choices, and what they cost
--------------------------------------
- **Reserved names throughout.** IPv4 comes from the RFC 5737 documentation
  ranges; domains sit under the RFC 2606 reserved TLDs. Nothing here names real
  infrastructure, which is the right default for a fixture committed to a
  security repository. The cost is that a model may rank a ``.invalid`` host as
  obvious test data and decline to report it as an indicator. That would depress
  absolute recall equally for every provider, so a comparison still holds — but
  if a baseline run cannot reproduce the 82/82 non-technique recall recorded on
  2026-09-12, this is the first knob to turn.
- **Real technique IDs.** These are reconciled against the repo's own ATT&CK
  lookup, so they have to exist in it. Names and tactics in the ground truth are
  read from ``framework/reference_data/mitre_techniques.json`` rather than
  hardcoded, so they track the lookup version (currently v19.2, in which
  Defense Evasion is gone).
- **No PDF dependency.** ``fpdf2`` lives in the network-forensics extra and
  ``reportlab`` is not a dependency at all. A fixture generator that only runs
  under one optional extra is a fixture generator that stops being run, so this
  writes the PDF itself: uncompressed Helvetica text, which is what the
  extraction path reads anyway.

Usage
-----
    python scripts/make_probe_pdf.py --out probe
    python scripts/make_probe_pdf.py --check      # counts only, writes nothing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TECHNIQUE_LOOKUP = REPO_ROOT / "framework" / "reference_data" / "mitre_techniques.json"

PAGES = 3

# ---------------------------------------------------------------------------
# The inventory
# ---------------------------------------------------------------------------

# RFC 5737 documentation ranges. 8 from each, 24 total.
IPV4 = [f"192.0.2.{n}" for n in (11, 24, 37, 48, 59, 66, 77, 88)] + [
    f"198.51.100.{n}" for n in (14, 23, 35, 41, 58, 69, 72, 91)
] + [f"203.0.113.{n}" for n in (17, 26, 33, 45, 54, 63, 79, 84)]

# RFC 2606 reserved TLDs. 20 total.
DOMAINS = [
    "cdn-update-svc.example",
    "mail-secure-login.example",
    "static-assets-eu.example",
    "vpn-gateway-node.example",
    "telemetry-collect.example",
    "docs-share-portal.example",
    "auth-token-relay.test",
    "patch-delivery-01.test",
    "metrics-ingest-b.test",
    "backup-sync-node.test",
    "identity-federate.test",
    "software-mirror-3.test",
    "billing-notices.invalid",
    "hr-onboarding-doc.invalid",
    "conference-invite.invalid",
    "payroll-statements.invalid",
    "shipping-tracker-9.invalid",
    "license-renewal-hub.invalid",
    "remote-support-dsk.invalid",
    "quarterly-reports.invalid",
]

# Hostnames that appear ONLY inside URLs. Disjoint from DOMAINS by construction
# (asserted below), so a regex sweep over the document yields 12 candidates that
# are not indicators in their own right.
URL_HOSTS = [
    "files-dl-node1.example",
    "pkg-repo-mirror.example",
    "img-host-cache.example",
    "form-submit-api.test",
    "upload-relay-7.test",
    "session-keepalive.test",
    "invoice-viewer.invalid",
    "secure-doc-open.invalid",
    "account-verify-now.invalid",
    "delivery-notice-uk.invalid",
    "cloud-drive-share.invalid",
    "update-installer.invalid",
]

URL_PATHS = [
    "/dl/stage2.bin",
    "/repo/pool/main/agent.deb",
    "/assets/loader.js",
    "/api/v2/collect",
    "/upload/chunk",
    "/keepalive/ping",
    "/view/INV-40182.pdf",
    "/open/document.hta",
    "/verify/session",
    "/track/GB88213",
    "/share/archive.zip",
    "/setup/update.msi",
]

CVES = [
    "CVE-2025-41001",
    "CVE-2025-41118",
    "CVE-2025-41227",
    "CVE-2025-41336",
    "CVE-2025-41445",
    "CVE-2024-40554",
    "CVE-2024-40663",
    "CVE-2024-40772",
    "CVE-2024-40881",
    "CVE-2024-40990",
]

# Real ATT&CK IDs — the ingester reconciles these against the repo lookup, so a
# fabricated id would be reported as an extraction failure rather than a miss.
TECHNIQUES = [
    "T1566.001",
    "T1204.002",
    "T1059.001",
    "T1547.001",
    "T1053.005",
    "T1078",
    "T1003.001",
    "T1055",
    "T1021.001",
    "T1071.001",
    "T1567.002",
    "T1486",
]

EXPECTED_COUNTS = {
    "ipv4": 24,
    "domain": 20,
    "sha256": 16,
    "url": 12,
    "cve": 10,
    "technique": 12,
}
EXPECTED_TOTAL = 94


def sha256_indicators(count: int = 16) -> list[str]:
    """Deterministic sha256 digests, stable across runs and machines."""
    return [
        hashlib.sha256(f"eventmill-probe-sample-{i:02d}".encode()).hexdigest()
        for i in range(count)
    ]


def urls() -> list[str]:
    return [f"https://{h}{p}" for h, p in zip(URL_HOSTS, URL_PATHS)]


def load_technique_details() -> list[dict[str, Any]]:
    """Name and tactics for each probe technique, read from the repo lookup.

    Hardcoding these would let the fixture drift away from the lookup the
    ingester actually reconciles against — the v19 tactic restructure is exactly
    the kind of change that would make a hardcoded copy silently wrong.
    """
    with open(TECHNIQUE_LOOKUP, encoding="utf-8") as f:
        lookup = json.load(f)
    table = lookup.get("techniques", lookup)

    details: list[dict[str, Any]] = []
    missing: list[str] = []
    for tid in TECHNIQUES:
        entry = table.get(tid)
        if not isinstance(entry, dict):
            missing.append(tid)
            continue
        details.append({
            "id": tid,
            "name": entry.get("name", ""),
            "tactics": list(entry.get("tactics") or []),
        })
    if missing:
        raise SystemExit(
            f"Technique ids absent from {TECHNIQUE_LOOKUP.name}: "
            f"{', '.join(missing)} — the probe would score a real extraction "
            "as a miss. Pick ids the lookup carries."
        )
    return details


# ---------------------------------------------------------------------------
# The report text
# ---------------------------------------------------------------------------


def _bullets(label: str, values: list[str], per_line: int = 1) -> list[str]:
    lines = [label]
    for i in range(0, len(values), per_line):
        lines.append("    " + "   ".join(values[i:i + per_line]))
    return lines


def build_pages() -> list[list[str]]:
    """Three pages of report prose carrying the whole inventory."""
    sha = sha256_indicators()
    url_list = urls()
    techs = load_technique_details()

    def tech(idx: int) -> str:
        return f"{techs[idx]['id']} ({techs[idx]['name']})"

    page1 = [
        "THREAT ACTIVITY REPORT — OPERATION PAPER LANTERN",
        "Synthetic corpus. Reference number PL-2026-0913. Distribution: internal.",
        "",
        "1. SUMMARY",
        "",
        "Between 4 and 22 August an intrusion set staged access to three business",
        "units through a mail-delivered lure and sustained it with scheduled",
        "execution and a reused service credential. Initial access was",
        f"{tech(0)}, relying on {tech(1)} to run the",
        "first stage. The operator then established persistence and moved toward",
        "credential material before exfiltrating archives to third-party storage.",
        "",
        "2. INITIAL ACCESS AND DELIVERY",
        "",
        "Lure messages resolved sender infrastructure to the following hosts.",
        "Each was observed in message headers or in an embedded link target.",
        "",
    ]
    page1 += _bullets("Sender and staging domains:", DOMAINS[:10])
    page1 += [
        "",
        "Delivery URLs recovered from message bodies and from the browser cache",
        "of two affected workstations:",
        "",
    ]
    page1 += _bullets("", url_list[:6])
    page1 += [
        "",
        f"Execution of the retrieved payload proceeded via {tech(2)},",
        "invoked from a macro-enabled attachment. Three hosts recorded the same",
        "parent-child chain within ninety seconds of message delivery.",
    ]

    page2 = [
        "3. INFRASTRUCTURE",
        "",
        "Command-and-control and staging addresses observed in flow records and",
        "proxy logs across the reporting period:",
        "",
    ]
    page2 += _bullets("Command and control:", IPV4[:12], per_line=3)
    page2 += [
        "",
    ]
    page2 += _bullets("Secondary staging and retrieval:", IPV4[12:], per_line=3)
    page2 += [
        "",
        "Remaining domains seen in DNS telemetry, none of which appeared in the",
        "original delivery set:",
        "",
    ]
    page2 += _bullets("", DOMAINS[10:])
    page2 += [
        "",
        "Additional retrieval URLs, recovered from the proxy after the first",
        "containment action:",
        "",
    ]
    page2 += _bullets("", url_list[6:])
    page2 += [
        "",
        f"Beaconing matched {tech(9)}, at a 300-second interval with",
        "jitter, carrying task output in POST bodies.",
    ]

    page3 = [
        "4. FILE INDICATORS",
        "",
        "Payload, loader and tooling hashes confirmed on disk or in memory:",
        "",
    ]
    page3 += _bullets("", sha[:8])
    page3 += [
        "",
        "Second-stage and post-exploitation tooling:",
        "",
    ]
    page3 += _bullets("", sha[8:])
    page3 += [
        "",
        "5. TECHNIQUES AND VULNERABILITIES",
        "",
        f"Persistence was established with {tech(3)} on four hosts and",
        f"with {tech(4)} on two servers. The operator then reused an",
        f"administrative credential, {tech(5)}, rather than escalating",
        f"locally. Credential material was taken through {tech(6)} on",
        f"the first domain controller reached. {tech(7)} was used to",
        "run the collection tooling inside a signed process.",
        "",
        f"Movement between segments used {tech(8)}, authenticated with",
        "the reused account. Staged archives left the environment through",
        f"{tech(10)}. On 22 August the operator executed",
        f"{tech(11)} against two file servers before access was cut.",
        "",
        "Vulnerabilities referenced in the intrusion set's tooling or observed",
        "being probed against external services:",
        "",
    ]
    page3 += _bullets("", CVES, per_line=2)
    page3 += [
        "",
        "6. NOTE ON THIS DOCUMENT",
        "",
        "All addresses, hostnames and identifiers above are reserved or synthetic",
        "and name no real infrastructure. The document exists to measure indicator",
        "recall, and its inventory is published alongside it.",
    ]

    return [page1, page2, page3]


# ---------------------------------------------------------------------------
# Minimal PDF writer
# ---------------------------------------------------------------------------

PAGE_WIDTH, PAGE_HEIGHT = 612, 792
MARGIN_X, TOP_Y = 54, 738
FONT_SIZE, LEADING = 9, 11.0


# WinAnsiEncoding places the typographic punctuation in 0x91-0x97, where
# latin-1 has control characters. Map before encoding so an em dash in the
# report text renders rather than raising.
_WINANSI = {
    0x2018: 0x91, 0x2019: 0x92, 0x201C: 0x93, 0x201D: 0x94,
    0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97,
}


def _escape(text: str) -> str:
    text = text.translate(_WINANSI)
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _content_stream(lines: list[str]) -> bytes:
    max_lines = int((TOP_Y - MARGIN_X) / LEADING)
    if len(lines) > max_lines:
        raise SystemExit(
            f"Page overflows: {len(lines)} lines against {max_lines} that fit. "
            "Indicators would be written off the page and scored as misses."
        )
    out = [
        "BT",
        f"/F1 {FONT_SIZE} Tf",
        f"{LEADING} TL",
        f"1 0 0 1 {MARGIN_X} {TOP_Y} Tm",
    ]
    for line in lines:
        out.append(f"({_escape(line)}) Tj")
        out.append("T*")
    out.append("ET")
    return "\n".join(out).encode("latin-1")


def write_pdf(path: Path, pages: list[list[str]]) -> None:
    """Write an uncompressed single-font PDF.

    Deliberately plain: the extraction path reads text, and an uncompressed
    stream also means a diff on this file is readable when the corpus changes.
    """
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog_num = add(b"")   # placeholder, filled once the page ids are known
    pages_num = add(b"")
    font_num = add(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>"
    )

    page_nums: list[int] = []
    for lines in pages:
        stream = _content_stream(lines)
        content_num = add(
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
            + stream + b"\nendstream"
        )
        page_num = add(
            f"<< /Type /Page /Parent {pages_num} 0 R "
            f"/MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {font_num} 0 R >> >> "
            f"/Contents {content_num} 0 R >>".encode()
        )
        page_nums.append(page_num)

    kids = " ".join(f"{n} 0 R" for n in page_nums)
    objects[pages_num - 1] = (
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_nums)} >>".encode()
    )
    objects[catalog_num - 1] = (
        f"<< /Type /Catalog /Pages {pages_num} 0 R >>".encode()
    )

    buf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, body in enumerate(objects, start=1):
        offsets.append(len(buf))
        buf += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_at = len(buf)
    buf += f"xref\n0 {len(objects) + 1}\n".encode()
    buf += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        buf += f"{off:010d} 00000 n \n".encode()
    buf += (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_num} 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode()

    path.write_bytes(bytes(buf))


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


def build_ground_truth() -> dict[str, Any]:
    sha = sha256_indicators()
    url_list = urls()
    techs = load_technique_details()

    overlap = set(URL_HOSTS) & set(DOMAINS)
    if overlap:
        raise SystemExit(
            f"URL hostnames overlap the domain set: {sorted(overlap)} — the "
            "derived-hostname count would be wrong."
        )

    indicators = {
        "ipv4": IPV4,
        "domain": DOMAINS,
        "sha256": sha,
        "url": url_list,
        "cve": CVES,
        "technique": [t["id"] for t in techs],
    }

    counts = {kind: len(values) for kind, values in indicators.items()}
    for kind, values in indicators.items():
        if len(set(values)) != len(values):
            raise SystemExit(f"Duplicate {kind} indicator in the fixture")
    if counts != EXPECTED_COUNTS:
        raise SystemExit(f"Inventory drifted: {counts} != {EXPECTED_COUNTS}")

    non_technique = sum(v for k, v in counts.items() if k != "technique")

    return {
        "generator": "scripts/make_probe_pdf.py",
        "schema_version": 1,
        "pages": PAGES,
        "total_unique_indicators": sum(counts.values()),
        "non_technique_indicators": non_technique,
        "counts": counts,
        "indicators": indicators,
        "techniques": techs,
        "derived_hostnames": URL_HOSTS,
        "_derived_hostnames_note": (
            "Hostnames that appear only inside the url indicators and are not "
            "indicators themselves. A regex sweep finds these as extra "
            "candidates; keeping or dropping them is a refinement decision, not "
            "a recall miss either way."
        ),
        "_recall_note": (
            "Non-technique recall is the headline number: it is exact and does "
            "not depend on how a model chooses to infer. Techniques split into "
            "documented (all of them, listed here) and inferred-beyond-the-"
            "document, which is a judgement measure and is reported separately."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", default="probe",
        help="output stem; writes <out>.pdf and <out>.ground_truth.json",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="validate the inventory and page layout, write nothing",
    )
    args = parser.parse_args(argv)

    truth = build_ground_truth()
    pages = build_pages()
    for lines in pages:
        _content_stream(lines)  # raises if a page overflows

    if args.check:
        print(f"  inventory   {truth['total_unique_indicators']} unique indicators")
        for kind, n in truth["counts"].items():
            print(f"    {kind:<10} {n}")
        print(f"  non-technique {truth['non_technique_indicators']}")
        print(f"  derived hostnames {len(truth['derived_hostnames'])}")
        print(f"  pages       {len(pages)}, longest {max(len(p) for p in pages)} lines")
        return 0

    stem = Path(args.out)
    pdf_path = stem.with_suffix(".pdf")
    truth_path = stem.with_name(stem.name + ".ground_truth.json")

    write_pdf(pdf_path, pages)
    truth_path.write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")

    print(f"  wrote {pdf_path} ({pdf_path.stat().st_size:,} bytes, {len(pages)} pages)")
    print(f"  wrote {truth_path} ({truth['total_unique_indicators']} indicators)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
