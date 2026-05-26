"""
PCAP Flow Analyzer — Deep-dive TCP/UDP flow analysis with protocol reconstruction.

Ported from Event Mill v1.0 pcap_parser.py (conversation analysis) with improvements:
- Conforms to EventMillToolProtocol
- Bidirectional flow aggregation (merges A→B and B→A)
- Long-duration connection detection
- Per-protocol breakdown (DNS, HTTP, TLS activity per flow)
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict


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


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"


class PcapFlowAnalyzer:
    """Deep-dive flow analysis with bidirectional aggregation."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_flow_analyzer",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        mode = payload.get("mode", "bidirectional")
        valid = ("bidirectional", "long_connections", "protocol_breakdown")
        if mode not in valid:
            errors.append(f"Invalid mode '{mode}'. Must be one of: {', '.join(valid)}")
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            get_pcap_session, is_internal,
        )

        session = get_pcap_session()
        if not session:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message="No PCAP loaded. Use pcap_metadata_summary (mode=load) first.",
            )

        mode = payload.get("mode", "bidirectional")
        filter_ip = payload.get("filter_ip")

        try:
            if mode == "bidirectional":
                return self._bidirectional(session, payload, filter_ip)
            elif mode == "long_connections":
                return self._long_connections(session, payload, filter_ip)
            elif mode == "protocol_breakdown":
                return self._protocol_breakdown(session, filter_ip)
            else:
                return ToolResult(ok=False, error_code="INPUT_VALIDATION_FAILED",
                                  message=f"Unknown mode: {mode}")
        except Exception as e:
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"pcap_flow_analyzer failed: {result.message}"

        data = result.result or {}
        mode = data.get("mode", "unknown")
        flows = data.get("flows", [])

        if mode == "bidirectional":
            parts = [f"Bidirectional flows: {data.get('total_flows', 0)} pairs"]
            for f in flows[:10]:
                parts.append(
                    f"  {f['host_a']} ↔ {f['host_b']} "
                    f"out={_format_bytes(f['bytes_a_to_b'])} "
                    f"in={_format_bytes(f['bytes_b_to_a'])} "
                    f"ratio={f.get('ratio', 0):.1f}x"
                )
            return "\n".join(parts)

        if mode == "long_connections":
            parts = [f"Long connections (>{data.get('min_duration', 300)}s): {len(flows)}"]
            for f in flows[:10]:
                dur = f.get("duration", 0)
                dur_str = f"{dur/60:.0f}m" if dur < 3600 else f"{dur/3600:.1f}h"
                parts.append(
                    f"  {f['src']} → {f['dst']}:{f['dport']} "
                    f"duration={dur_str} {_format_bytes(f['bytes_out'])}"
                )
            return "\n".join(parts)

        if mode == "protocol_breakdown":
            parts = [f"Protocol breakdown: {len(flows)} entries"]
            for f in flows[:10]:
                parts.append(
                    f"  {f.get('host', '?')}: dns={f.get('dns_count', 0)} "
                    f"http={f.get('http_count', 0)} tls={f.get('tls_count', 0)}"
                )
            return "\n".join(parts)

        return f"pcap_flow_analyzer completed mode '{mode}'."

    # -------------------------------------------------------------------
    # Bidirectional flow aggregation
    # -------------------------------------------------------------------

    def _bidirectional(self, session: Any, payload: dict, filter_ip: str | None) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal

        top_n = payload.get("top_n", 20)

        pair_stats: Dict[tuple, dict] = defaultdict(lambda: {
            "bytes_a_to_b": 0,
            "bytes_b_to_a": 0,
            "packets_a_to_b": 0,
            "packets_b_to_a": 0,
            "ports": set(),
            "protos": set(),
            "first_seen": None,
            "last_seen": None,
        })

        for (src, dst, dport, proto), stats in session.conversations.items():
            if filter_ip and filter_ip not in (src, dst):
                continue

            # Canonical key: sorted IPs
            key = tuple(sorted([src, dst]))
            ps = pair_stats[key]

            if src == key[0]:
                ps["bytes_a_to_b"] += stats["bytes_out"]
                ps["packets_a_to_b"] += stats["packets"]
            else:
                ps["bytes_b_to_a"] += stats["bytes_out"]
                ps["packets_b_to_a"] += stats["packets"]

            ps["ports"].add(dport)
            ps["protos"].add(proto)

            if stats["first_seen"]:
                if ps["first_seen"] is None or stats["first_seen"] < ps["first_seen"]:
                    ps["first_seen"] = stats["first_seen"]
            if stats["last_seen"]:
                if ps["last_seen"] is None or stats["last_seen"] > ps["last_seen"]:
                    ps["last_seen"] = stats["last_seen"]

        flows = []
        for (host_a, host_b), ps in pair_stats.items():
            total_bytes = ps["bytes_a_to_b"] + ps["bytes_b_to_a"]
            min_bytes = max(ps["bytes_a_to_b"], ps["bytes_b_to_a"], 1)
            max_bytes = max(ps["bytes_a_to_b"], ps["bytes_b_to_a"])
            ratio = max_bytes / max(min(ps["bytes_a_to_b"], ps["bytes_b_to_a"]), 1)

            duration = 0.0
            if ps["first_seen"] and ps["last_seen"]:
                duration = ps["last_seen"] - ps["first_seen"]

            a_type = "INT" if is_internal(host_a) else "EXT"
            b_type = "INT" if is_internal(host_b) else "EXT"

            flows.append({
                "host_a": host_a,
                "host_b": host_b,
                "direction": f"{a_type}↔{b_type}",
                "bytes_a_to_b": ps["bytes_a_to_b"],
                "bytes_b_to_a": ps["bytes_b_to_a"],
                "total_bytes": total_bytes,
                "packets_a_to_b": ps["packets_a_to_b"],
                "packets_b_to_a": ps["packets_b_to_a"],
                "ratio": ratio,
                "ports": sorted(ps["ports"]),
                "protocols": sorted(ps["protos"]),
                "duration": duration,
                "first_seen": ps["first_seen"],
                "last_seen": ps["last_seen"],
            })

        flows.sort(key=lambda f: f["total_bytes"], reverse=True)

        return ToolResult(
            ok=True,
            result={
                "mode": "bidirectional",
                "total_flows": len(flows),
                "flows": flows[:top_n],
            },
        )

    # -------------------------------------------------------------------
    # Long-duration connections
    # -------------------------------------------------------------------

    def _long_connections(self, session: Any, payload: dict, filter_ip: str | None) -> ToolResult:
        min_duration = payload.get("min_duration_seconds", 300)
        top_n = payload.get("top_n", 20)

        long_conns = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            if filter_ip and filter_ip not in (src, dst):
                continue

            if stats["first_seen"] and stats["last_seen"]:
                duration = stats["last_seen"] - stats["first_seen"]
                if duration >= min_duration:
                    long_conns.append({
                        "src": src,
                        "dst": dst,
                        "dport": dport,
                        "proto": proto,
                        "duration": duration,
                        "packets": stats["packets"],
                        "bytes_out": stats["bytes_out"],
                        "first_seen": stats["first_seen"],
                        "last_seen": stats["last_seen"],
                    })

        long_conns.sort(key=lambda c: c["duration"], reverse=True)

        return ToolResult(
            ok=True,
            result={
                "mode": "long_connections",
                "min_duration": min_duration,
                "total_flows": len(long_conns),
                "flows": long_conns[:top_n],
            },
        )

    # -------------------------------------------------------------------
    # Per-host protocol breakdown
    # -------------------------------------------------------------------

    def _protocol_breakdown(self, session: Any, filter_ip: str | None) -> ToolResult:
        host_stats: Dict[str, dict] = defaultdict(lambda: {
            "dns_count": 0,
            "http_count": 0,
            "tls_count": 0,
            "conversation_count": 0,
            "total_bytes": 0,
        })

        for (src, dst, dport, proto), stats in session.conversations.items():
            if filter_ip and filter_ip not in (src, dst):
                continue
            host_stats[src]["conversation_count"] += 1
            host_stats[src]["total_bytes"] += stats["bytes_out"]

        for q in session.dns_queries:
            if filter_ip and filter_ip != q["src"]:
                continue
            host_stats[q["src"]]["dns_count"] += 1

        for r in session.http_requests:
            if filter_ip and filter_ip != r["src"]:
                continue
            host_stats[r["src"]]["http_count"] += 1

        for h in session.tls_handshakes:
            if filter_ip and filter_ip != h["src"]:
                continue
            host_stats[h["src"]]["tls_count"] += 1

        flows = []
        for host, stats in host_stats.items():
            flows.append({
                "host": host,
                **stats,
            })

        flows.sort(key=lambda f: f["total_bytes"], reverse=True)

        return ToolResult(
            ok=True,
            result={
                "mode": "protocol_breakdown",
                "total_hosts": len(flows),
                "flows": flows[:50],
            },
        )
