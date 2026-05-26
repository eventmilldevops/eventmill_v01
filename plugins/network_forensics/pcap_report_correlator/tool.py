"""
PCAP Report Correlator — Three-stage IOC extraction and PCAP correlation.

Ported from Event Mill v1.0 pcap_hunting.py (sync_pcap, _extract_iocs_from_md)
with improvements:
- Conforms to EventMillToolProtocol
- Stage 1: Regex IOC extraction (IP, domain, MAC, port, timestamp)
- Stage 2: Match extracted IOCs against PcapSession data
- Stage 3: Produce correlated output with evidence chains
- Optional AI-enhanced extraction via LLM
- Pre-extracted IOC input for pipeline composition
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("eventmill.plugins.pcap_report_correlator")


@dataclass
class ToolResult:
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    output_artifacts: list[str] | None = None
    details: dict[str, Any] | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


# ---------------------------------------------------------------------------
# IOC extraction regexes
# ---------------------------------------------------------------------------

# IPv4 — defanged or normal
_RE_IPV4 = re.compile(
    r"(?:(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3})",
    re.ASCII,
)
# Domain — basic pattern, excludes common false positives
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|uk|de|fr|br|jp|au|ca|edu|gov)\b",
    re.IGNORECASE,
)
# MAC address
_RE_MAC = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
)
# Port reference
_RE_PORT = re.compile(
    r"(?:port|dst\.port|src\.port|dport|sport)\s*(?:=|:)\s*(\d{1,5})",
    re.IGNORECASE,
)
# MD5/SHA1/SHA256 hashes
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# False positive suppression
_FP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
_FP_DOMAINS = {"example.com", "example.org", "example.net", "localhost"}


def _refang(text: str) -> str:
    """Convert defanged IOCs back to standard form."""
    return text.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http")


def _extract_iocs(text: str) -> list[dict[str, str]]:
    """Extract IOCs from text using regex patterns."""
    iocs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    clean = _refang(text)

    # SHA256 first (longest), then SHA1, then MD5
    for match in _RE_SHA256.finditer(clean):
        val = match.group(0).lower()
        key = ("sha256", val)
        if key not in seen:
            seen.add(key)
            iocs.append({"type": "sha256", "value": val})

    for match in _RE_SHA1.finditer(clean):
        val = match.group(0).lower()
        # Skip if already captured as sha256 substring
        if ("sha256", val) not in seen and ("sha1", val) not in seen:
            seen.add(("sha1", val))
            iocs.append({"type": "sha1", "value": val})

    for match in _RE_MD5.finditer(clean):
        val = match.group(0).lower()
        if all((t, val) not in seen for t in ("sha256", "sha1", "md5")):
            seen.add(("md5", val))
            iocs.append({"type": "md5", "value": val})

    # IPs
    for match in _RE_IPV4.finditer(clean):
        val = match.group(0)
        if val not in _FP_IPS and ("ip", val) not in seen:
            seen.add(("ip", val))
            iocs.append({"type": "ip", "value": val})

    # Domains
    for match in _RE_DOMAIN.finditer(clean):
        val = match.group(0).lower()
        if val not in _FP_DOMAINS and ("domain", val) not in seen:
            seen.add(("domain", val))
            iocs.append({"type": "domain", "value": val})

    # MACs
    for match in _RE_MAC.finditer(clean):
        val = match.group(0).upper()
        if ("mac", val) not in seen:
            seen.add(("mac", val))
            iocs.append({"type": "mac", "value": val})

    # Ports
    for match in _RE_PORT.finditer(clean):
        val = match.group(1)
        port = int(val)
        if 1 <= port <= 65535 and ("port", val) not in seen:
            seen.add(("port", val))
            iocs.append({"type": "port", "value": val})

    return iocs


class PcapReportCorrelator:
    """Correlates threat report IOCs against loaded PCAP data."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_report_correlator",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        mode = payload.get("mode", "full")
        valid_modes = ("extract", "correlate", "full")
        if mode not in valid_modes:
            errors.append(f"Invalid mode '{mode}'. Must be one of: {', '.join(valid_modes)}")

        if mode in ("extract", "full"):
            if not payload.get("report_text") and not payload.get("report_file"):
                if not payload.get("iocs"):
                    errors.append(
                        "One of 'report_text', 'report_file', or 'iocs' is required."
                    )

        if mode == "correlate":
            if not payload.get("iocs"):
                errors.append("'iocs' is required for mode 'correlate'.")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        mode = payload.get("mode", "full")

        try:
            # Stage 1: Extract IOCs
            iocs = payload.get("iocs")
            if not iocs and mode in ("extract", "full"):
                report_text = payload.get("report_text", "")
                if not report_text and payload.get("report_file"):
                    report_text = self._read_report(payload["report_file"], context)
                if not report_text:
                    return ToolResult(
                        ok=False,
                        error_code="INVALID_INPUT",
                        message="No report text provided and could not read report file.",
                    )
                iocs = _extract_iocs(report_text)

                # Optional AI-enhanced extraction
                if (
                    payload.get("use_ai_extraction")
                    and context
                    and hasattr(context, "llm_query")
                    and context.llm_query
                ):
                    ai_iocs = self._ai_extract(report_text, context)
                    # Merge AI IOCs (deduplicated)
                    existing_keys = {(i["type"], i["value"]) for i in iocs}
                    for ai_ioc in ai_iocs:
                        key = (ai_ioc["type"], ai_ioc["value"])
                        if key not in existing_keys:
                            existing_keys.add(key)
                            iocs.append(ai_ioc)

            if not iocs:
                return ToolResult(
                    ok=True,
                    result={
                        "extracted_iocs": [],
                        "matches": [],
                        "unmatched_iocs": [],
                        "summary_text": "No IOCs extracted from report.",
                    },
                )

            if mode == "extract":
                lines = [f"📋 EXTRACTED IOCs — {len(iocs)} total", "-" * 50]
                for ioc in iocs:
                    lines.append(f"  [{ioc['type'].upper():<8}]  {ioc['value']}")
                return ToolResult(
                    ok=True,
                    result={
                        "extracted_iocs": iocs,
                        "matches": [],
                        "unmatched_iocs": [],
                        "summary_text": "\n".join(lines),
                    },
                )

            # Stage 2: Correlate against PCAP
            from plugins.network_forensics.pcap_metadata_summary.tool import get_pcap_session

            session = get_pcap_session()
            if not session:
                return ToolResult(
                    ok=False,
                    error_code="ARTIFACT_NOT_FOUND",
                    message="No PCAP loaded. Use pcap_metadata_summary (mode=load) first.",
                )

            matches, unmatched = self._correlate(iocs, session)

            # Stage 3: Format output
            lines = self._format_correlation(iocs, matches, unmatched)

            return ToolResult(
                ok=True,
                result={
                    "extracted_iocs": iocs,
                    "matches": matches,
                    "unmatched_iocs": unmatched,
                    "summary_text": "\n".join(lines),
                },
            )

        except Exception as e:
            logger.error("Correlation failed: %s", e, exc_info=True)
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"pcap_report_correlator failed: {result.message}"

        data = result.result or {}
        summary = data.get("summary_text", "")
        if summary:
            return summary[:3000] if len(summary) > 3000 else summary

        matches = data.get("matches", [])
        iocs = data.get("extracted_iocs", [])
        return f"Correlation: {len(matches)} of {len(iocs)} IOCs matched in PCAP."

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _read_report(file_path: str, context: Any) -> str:
        """Read report from file via artifact registry, filesystem, or GCS."""
        import os
        path = file_path

        # Try artifact registry first
        if context and hasattr(context, "artifact_registry"):
            try:
                artifact = context.artifact_registry.get(file_path)
                if artifact and hasattr(artifact, "content"):
                    return artifact.content
            except Exception:
                pass

        # Try workspace directory
        if context and hasattr(context, "config"):
            workspace = context.config.get("workspace_dir", "workspace")
            candidate = os.path.join(workspace, file_path)
            if os.path.isfile(candidate):
                path = candidate

        # Try workspace artifacts
        if not os.path.isfile(path):
            workspace = os.environ.get("EVENTMILL_WORKSPACE", "/app/workspace")
            candidate = os.path.join(workspace, "artifacts", os.path.basename(file_path))
            if os.path.isfile(candidate):
                path = candidate

        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()

        # Try GCS download
        try:
            from plugins.network_forensics.pcap_metadata_summary.tool import _download_from_gcs
            downloaded = _download_from_gcs(file_path, context)
            if downloaded:
                with open(downloaded, encoding="utf-8", errors="replace") as f:
                    return f.read()
        except Exception:
            pass

        return ""

    @staticmethod
    def _correlate(
        iocs: list[dict[str, str]], session: Any
    ) -> tuple[list[dict], list[dict]]:
        """Match IOCs against PcapSession data."""
        matches: list[dict] = []
        unmatched: list[dict] = []

        for ioc in iocs:
            ioc_type = ioc["type"]
            ioc_value = ioc["value"]
            evidence: list[dict] = []

            if ioc_type == "ip":
                # Check conversations
                for (src, dst, dport, proto), stats in session.conversations.items():
                    if src == ioc_value or dst == ioc_value:
                        evidence.append({
                            "source": "conversation",
                            "detail": f"{src} → {dst}:{dport}/{proto}",
                            "packets": stats["packets"],
                            "bytes": stats["bytes_out"],
                        })
                # Check DNS answers
                for q in session.dns_queries:
                    if q.get("answer") == ioc_value:
                        evidence.append({
                            "source": "dns_answer",
                            "detail": f"{q['query']} → {ioc_value}",
                        })

            elif ioc_type == "domain":
                # Check DNS queries
                for q in session.dns_queries:
                    if ioc_value in q["query"].lower():
                        evidence.append({
                            "source": "dns_query",
                            "detail": f"{q['src']} queried {q['query']}",
                        })
                # Check TLS SNI
                for h in session.tls_handshakes:
                    sni = (h.get("sni") or "").lower()
                    if ioc_value in sni:
                        evidence.append({
                            "source": "tls_sni",
                            "detail": f"{h['src']} → {h['dst']}:{h.get('dport', 443)} SNI={sni}",
                        })
                # Check HTTP Host headers
                for r in session.http_requests:
                    host = (r.get("host") or "").lower()
                    if ioc_value in host:
                        evidence.append({
                            "source": "http_host",
                            "detail": f"{r['method']} {host}{r.get('uri', '')}",
                        })

            elif ioc_type == "port":
                port_int = int(ioc_value)
                for (src, dst, dport, proto), stats in session.conversations.items():
                    if dport == port_int:
                        evidence.append({
                            "source": "conversation",
                            "detail": f"{src} → {dst}:{dport}/{proto}",
                            "packets": stats["packets"],
                        })
                # Limit evidence for common ports
                if len(evidence) > 20:
                    total = len(evidence)
                    evidence = evidence[:20]
                    evidence.append({
                        "source": "truncated",
                        "detail": f"... {total - 20} more matches",
                    })

            elif ioc_type == "mac":
                # MAC addresses would be in Ethernet frames — not tracked in sessions
                # currently. Mark as not searchable.
                pass

            elif ioc_type in ("md5", "sha1", "sha256"):
                # Hash IOCs cannot be matched against PCAP metadata
                # (would require payload inspection). Note this limitation.
                pass

            if evidence:
                matches.append({
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "match_count": len(evidence),
                    "evidence": evidence,
                })
            else:
                unmatched.append(ioc)

        return matches, unmatched

    @staticmethod
    def _format_correlation(
        iocs: list, matches: list, unmatched: list
    ) -> list[str]:
        """Format correlation results as human-readable text."""
        lines = [
            f"📊 CORRELATION RESULTS — {len(matches)}/{len(iocs)} IOCs matched",
            "=" * 60,
        ]

        if matches:
            lines.append("\n✅ MATCHED IOCs:")
            lines.append("-" * 50)
            for m in matches:
                lines.append(
                    f"\n  [{m['ioc_type'].upper():<8}]  {m['ioc_value']}  "
                    f"— {m['match_count']} hit(s)"
                )
                for ev in m["evidence"][:5]:
                    lines.append(f"    📌 {ev['source']}: {ev['detail']}")
                if m["match_count"] > 5:
                    lines.append(f"    ... +{m['match_count'] - 5} more")

        if unmatched:
            lines.append("\n❌ UNMATCHED IOCs:")
            lines.append("-" * 50)
            for u in unmatched:
                note = ""
                if u["type"] in ("md5", "sha1", "sha256"):
                    note = " (hash IOCs cannot be matched against PCAP metadata)"
                elif u["type"] == "mac":
                    note = " (MAC-layer data not tracked in current session)"
                lines.append(f"  [{u['type'].upper():<8}]  {u['value']}{note}")

        return lines

    @staticmethod
    def _ai_extract(text: str, context: Any) -> list[dict[str, str]]:
        """Use LLM to extract IOCs that regex might miss."""
        prompt = (
            "Extract ALL Indicators of Compromise (IOCs) from this threat report.\n"
            "Return ONLY a JSON array of objects with 'type' and 'value' keys.\n"
            "Types: ip, domain, md5, sha1, sha256, port, mac, url, email, cve\n"
            "Be thorough — include defanged, obfuscated, and contextually implied IOCs.\n\n"
            f"REPORT TEXT:\n{text[:8000]}"
        )
        try:
            response = context.llm_query.query_text(
                prompt=prompt,
                max_tokens=2048,
            )
            if response.ok and response.text:
                import json
                # Try to parse JSON from LLM response
                raw = response.text.strip()
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
                return json.loads(raw)
        except Exception as e:
            logger.warning("AI IOC extraction failed: %s", e)
        return []
