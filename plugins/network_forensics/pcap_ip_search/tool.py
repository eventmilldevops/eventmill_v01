"""
PCAP IP/IOC Search — Search loaded PCAP data for indicators of compromise.

Ported from Event Mill v1.0 pcap_parser.py (pcap_ioc + pcap_timeline) with improvements:
- Conforms to EventMillToolProtocol
- Structured JSON output
- Combined IOC search across all data stores
- Chronological timeline reconstruction by IP
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


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


class PcapIpSearch:
    """Search loaded PCAP data for IPs, domains, ports, or generate IP timelines."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_ip_search",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        mode = payload.get("mode", "ioc")
        if mode not in ("ioc", "timeline"):
            errors.append(f"Invalid mode '{mode}'. Must be 'ioc' or 'timeline'.")

        if mode == "ioc" and not payload.get("query"):
            errors.append("'query' is required for IOC search mode.")

        if mode == "timeline" and not payload.get("ip"):
            errors.append("'ip' is required for timeline mode.")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute IOC search or timeline reconstruction."""
        from plugins.network_forensics.pcap_metadata_summary.tool import get_pcap_session

        session = get_pcap_session()
        if not session:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message="No PCAP loaded. Use pcap_metadata_summary (mode=load) first.",
            )

        mode = payload.get("mode", "ioc")

        try:
            if mode == "ioc":
                return self._ioc_search(session, payload)
            elif mode == "timeline":
                return self._timeline(session, payload)
            else:
                return ToolResult(ok=False, error_code="INPUT_VALIDATION_FAILED",
                                  message=f"Unknown mode: {mode}")
        except Exception as e:
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context."""
        if not result.ok:
            return f"pcap_ip_search failed: {result.message}"

        data = result.result or {}
        mode = data.get("mode", "unknown")

        if mode == "ioc":
            query = data.get("query", "?")
            matches = data.get("matches", {})
            conv_count = len(matches.get("conversations", []))
            dns_count = len(matches.get("dns_queries", []))
            http_count = len(matches.get("http_requests", []))
            tls_count = len(matches.get("tls_handshakes", []))
            total = conv_count + dns_count + http_count + tls_count
            return (
                f"IOC search for '{query}': {total} matches "
                f"(conversations={conv_count}, dns={dns_count}, "
                f"http={http_count}, tls={tls_count})"
            )

        if mode == "timeline":
            ip = data.get("ip", "?")
            events = data.get("timeline", [])
            return f"Timeline for {ip}: {len(events)} events"

        return f"pcap_ip_search completed mode '{mode}'."

    # -------------------------------------------------------------------
    # IOC search
    # -------------------------------------------------------------------

    def _ioc_search(self, session: Any, payload: dict[str, Any]) -> ToolResult:
        """Search all PCAP data stores for an IOC."""
        query = payload["query"].strip()

        # Determine IOC type
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query))
        is_port = query.isdigit() and 1 <= int(query) <= 65535
        # Otherwise treat as domain

        conv_matches = []
        dns_matches = []
        http_matches = []
        tls_matches = []

        # Search conversations
        for (src, dst, dport, proto), stats in session.conversations.items():
            matched = False
            if is_ip and (src == query or dst == query):
                matched = True
            elif is_port and dport == int(query):
                matched = True

            if matched:
                conv_matches.append({
                    "src": src,
                    "dst": dst,
                    "dport": dport,
                    "proto": proto,
                    "packets": stats["packets"],
                    "bytes_out": stats["bytes_out"],
                    "first_seen": stats["first_seen"],
                    "last_seen": stats["last_seen"],
                })

        # Search DNS
        query_lower = query.lower()
        for q in session.dns_queries:
            if (
                (is_ip and (q["src"] == query or q["dst"] == query))
                or (not is_ip and not is_port and query_lower in q["query"].lower())
                or (is_ip and query in q.get("resolved", []))
            ):
                dns_matches.append(q)

        # Search HTTP
        for r in session.http_requests:
            if (
                (is_ip and (r["src"] == query or r["dst"] == query))
                or (not is_ip and not is_port and query_lower in r.get("host", "").lower())
                or (not is_ip and not is_port and query_lower in r.get("path", "").lower())
            ):
                http_matches.append(r)

        # Search TLS
        for h in session.tls_handshakes:
            if (
                (is_ip and (h["src"] == query or h["dst"] == query))
                or (is_port and h.get("dport") == int(query))
                or (not is_ip and not is_port and query_lower in (h.get("sni") or "").lower())
            ):
                tls_matches.append(h)

        return ToolResult(
            ok=True,
            result={
                "mode": "ioc",
                "query": query,
                "ioc_type": "ip" if is_ip else ("port" if is_port else "domain"),
                "matches": {
                    "conversations": conv_matches[:100],
                    "dns_queries": dns_matches[:100],
                    "http_requests": http_matches[:100],
                    "tls_handshakes": tls_matches[:100],
                },
            },
        )

    # -------------------------------------------------------------------
    # Timeline
    # -------------------------------------------------------------------

    def _timeline(self, session: Any, payload: dict[str, Any]) -> ToolResult:
        """Build a chronological timeline of all activity for an IP."""
        ip = payload["ip"].strip()

        events: list[dict[str, Any]] = []

        # Conversations involving this IP
        for (src, dst, dport, proto), stats in session.conversations.items():
            if src == ip or dst == ip:
                ts = stats["first_seen"]
                if ts:
                    events.append({
                        "timestamp": ts,
                        "type": "connection",
                        "direction": "outbound" if src == ip else "inbound",
                        "peer": dst if src == ip else src,
                        "dport": dport,
                        "proto": proto,
                        "packets": stats["packets"],
                        "bytes": stats["bytes_out"],
                    })

        # DNS queries from/to this IP
        for q in session.dns_queries:
            if q["src"] == ip or q["dst"] == ip:
                events.append({
                    "timestamp": q["timestamp"],
                    "type": "dns",
                    "query": q["query"],
                    "dns_type": q.get("type", "query"),
                    "resolved": q.get("resolved", []),
                })

        # HTTP requests from/to this IP
        for r in session.http_requests:
            if r["src"] == ip or r["dst"] == ip:
                events.append({
                    "timestamp": r["timestamp"],
                    "type": "http",
                    "method": r["method"],
                    "host": r["host"],
                    "path": r["path"],
                })

        # TLS handshakes from/to this IP
        for h in session.tls_handshakes:
            if h["src"] == ip or h["dst"] == ip:
                events.append({
                    "timestamp": h["timestamp"],
                    "type": "tls",
                    "sni": h.get("sni", ""),
                    "dport": h.get("dport", 443),
                })

        events.sort(key=lambda e: e.get("timestamp", 0))

        return ToolResult(
            ok=True,
            result={
                "mode": "timeline",
                "ip": ip,
                "total_events": len(events),
                "timeline": events[:500],
            },
        )
