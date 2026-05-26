"""
PCAP Threat Hunter — Threat hunting across loaded PCAP data with ICS awareness.

Ported from Event Mill v1.0 pcap_hunting.py with improvements:
- Conforms to EventMillToolProtocol
- All 7 hunt tools: talkers, ports, beacons, dns, tls, lateral, exfil
- ICS protocol awareness (Modbus, S7comm, DNP3, BACnet, OPC-UA, IEC-104)
- Suspicious port knowledge base (Metasploit, Cobalt Strike, RATs)
- C2 beaconing detection via inter-arrival jitter analysis
- DNS anomaly detection via Shannon entropy (DGA)
- Structured JSON output with severity classification
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
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


# ---------------------------------------------------------------------------
# Port knowledge bases
# ---------------------------------------------------------------------------

KNOWN_SERVICES: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DG",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-Sub", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM-S", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch", 27017: "MongoDB",
}

ICS_PORTS: dict[int, str] = {
    502: "Modbus", 102: "S7comm", 44818: "EtherNet/IP",
    20000: "DNP3", 4840: "OPC-UA", 47808: "BACnet",
    2404: "IEC-104", 789: "Red Lion", 1911: "Niagara Fox",
    9600: "OMRON-FINS", 18245: "GE-SRTP",
}

SUSPICIOUS_PORTS: dict[int, str] = {
    4444: "Metasploit", 5555: "Android-ADB", 6667: "IRC-C2",
    6697: "IRC-TLS", 8291: "MikroTik-Winbox", 31337: "Back-Orifice",
    50050: "Cobalt-Strike", 1080: "SOCKS-Proxy", 9050: "Tor-SOCKS",
    9051: "Tor-Control", 3128: "Squid-Proxy", 8888: "HTTP-Alt",
    12345: "NetBus", 27374: "Sub7", 65535: "ReservedMax",
}


def _service_name(port: int) -> str:
    """Return a human-readable service name for a port."""
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    if port in ICS_PORTS:
        return f"ICS:{ICS_PORTS[port]}"
    if port in SUSPICIOUS_PORTS:
        return f"SUSPECT:{SUSPICIOUS_PORTS[port]}"
    return str(port)


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"


def _shannon_entropy(label: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not label:
        return 0.0
    freq = Counter(label)
    length = len(label)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


class PcapThreatHunter:
    """Threat hunting across loaded PCAP data with ICS awareness."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_threat_hunter",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        hunt = payload.get("hunt")
        valid_hunts = ("talkers", "ports", "beacons", "dns", "tls", "lateral", "exfil")
        if not hunt:
            errors.append("'hunt' is required.")
        elif hunt not in valid_hunts:
            errors.append(f"Invalid hunt '{hunt}'. Must be one of: {', '.join(valid_hunts)}")
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import get_pcap_session

        session = get_pcap_session()
        if not session:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message="No PCAP loaded. Use 'load <file>' or 'run pcap_metadata_summary {\"mode\": \"load\", ...}' first.",
            )

        hunt = payload["hunt"]
        dispatch = {
            "talkers": self._hunt_talkers,
            "ports": self._hunt_ports,
            "beacons": self._hunt_beacons,
            "dns": self._hunt_dns,
            "tls": self._hunt_tls,
            "lateral": self._hunt_lateral,
            "exfil": self._hunt_exfil,
        }

        try:
            return dispatch[hunt](session, payload)
        except Exception as e:
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"pcap_threat_hunter failed: {result.message}"

        data = result.result or {}
        hunt = data.get("hunt", "?")
        summary = data.get("summary_text", "")
        if summary:
            # Truncate for LLM context
            return summary[:3000] if len(summary) > 3000 else summary

        findings = data.get("findings", [])
        severity = data.get("severity", "info")
        return f"Hunt '{hunt}' ({severity}): {len(findings)} finding(s)"

    # ===================================================================
    # hunt_talkers
    # ===================================================================

    def _hunt_talkers(self, session: Any, payload: dict) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal

        top_n = payload.get("top_n", 20)
        sort_by = payload.get("sort_by", "bytes")

        # Aggregate per host
        host_stats: Dict[str, dict] = defaultdict(lambda: {
            "bytes_out": 0,
            "bytes_in": 0,
            "connections": 0,
            "packets": 0,
            "peers": set(),
        })

        for (src, dst, dport, proto), stats in session.conversations.items():
            host_stats[src]["bytes_out"] += stats["bytes_out"]
            host_stats[src]["connections"] += 1
            host_stats[src]["packets"] += stats["packets"]
            host_stats[src]["peers"].add(dst)

            host_stats[dst]["bytes_in"] += stats["bytes_out"]
            host_stats[dst]["peers"].add(src)

        sort_key = {
            "bytes": lambda x: x["bytes_out"] + x["bytes_in"],
            "connections": lambda x: x["connections"],
            "packets": lambda x: x["packets"],
        }.get(sort_by, lambda x: x["bytes_out"] + x["bytes_in"])

        sorted_hosts = sorted(host_stats.items(), key=lambda kv: sort_key(kv[1]), reverse=True)

        findings = []
        lines = [f"Top {min(top_n, len(sorted_hosts))} talkers by {sort_by}:", "-" * 70]

        for i, (host, hs) in enumerate(sorted_hosts[:top_n], 1):
            loc = "INT" if is_internal(host) else "EXT"
            total_bytes = hs["bytes_out"] + hs["bytes_in"]
            peer_count = len(hs["peers"])

            findings.append({
                "rank": i,
                "host": host,
                "location": loc,
                "bytes_out": hs["bytes_out"],
                "bytes_in": hs["bytes_in"],
                "total_bytes": total_bytes,
                "connections": hs["connections"],
                "packets": hs["packets"],
                "peer_count": peer_count,
            })
            lines.append(
                f"  {i:<4} {host:<18} ({loc})  "
                f"Out: {_format_bytes(hs['bytes_out'])}  "
                f"In: {_format_bytes(hs['bytes_in'])}  "
                f"Conns: {hs['connections']}  "
                f"Peers: {peer_count}"
            )

        return ToolResult(
            ok=True,
            result={
                "hunt": "talkers",
                "sort_by": sort_by,
                "findings": findings,
                "summary_text": "\n".join(lines),
                "severity": "info",
            },
        )

    # ===================================================================
    # hunt_ports
    # ===================================================================

    def _hunt_ports(self, session: Any, payload: dict) -> ToolResult:
        port_stats: Dict[int, dict] = defaultdict(lambda: {
            "count": 0,
            "sources": set(),
            "destinations": set(),
            "bytes": 0,
        })

        for (src, dst, dport, proto), stats in session.conversations.items():
            if dport > 0:
                port_stats[dport]["count"] += 1
                port_stats[dport]["sources"].add(src)
                port_stats[dport]["destinations"].add(dst)
                port_stats[dport]["bytes"] += stats["bytes_out"]

        findings = []
        lines = []
        severity = "info"

        # Standard services
        standard = [(p, s) for p, s in port_stats.items() if p in KNOWN_SERVICES]
        if standard:
            lines.append("📋 STANDARD SERVICES")
            lines.append("-" * 60)
            for port, stats in sorted(standard, key=lambda x: x[1]["count"], reverse=True)[:20]:
                svc = KNOWN_SERVICES[port]
                lines.append(
                    f"  {port:<6} {svc:<16} flows={stats['count']}  "
                    f"sources={len(stats['sources'])}  "
                    f"{_format_bytes(stats['bytes'])}"
                )
                findings.append({
                    "port": port,
                    "service": svc,
                    "category": "standard",
                    "flow_count": stats["count"],
                    "source_count": len(stats["sources"]),
                    "bytes": stats["bytes"],
                })
            lines.append("")

        # ICS ports
        ics_found = [(p, s) for p, s in port_stats.items() if p in ICS_PORTS]
        if ics_found:
            severity = "high"
            lines.append("🔶 ICS/SCADA PROTOCOLS DETECTED")
            lines.append("-" * 60)
            for port, stats in sorted(ics_found, key=lambda x: x[1]["count"], reverse=True):
                svc = ICS_PORTS[port]
                lines.append(
                    f"  {port:<6} {svc:<16} flows={stats['count']}  "
                    f"sources={len(stats['sources'])}"
                )
                findings.append({
                    "port": port,
                    "service": svc,
                    "category": "ics",
                    "flow_count": stats["count"],
                    "source_count": len(stats["sources"]),
                    "bytes": stats["bytes"],
                })
            lines.append("")

        # Suspicious ports
        suspicious = [(p, s) for p, s in port_stats.items() if p in SUSPICIOUS_PORTS]
        if suspicious:
            severity = "critical" if severity != "high" else severity
            lines.append("🔴 SUSPICIOUS PORTS DETECTED")
            lines.append("-" * 60)
            for port, stats in sorted(suspicious, key=lambda x: x[1]["count"], reverse=True):
                svc = SUSPICIOUS_PORTS[port]
                lines.append(
                    f"  {port:<6} {svc:<16} flows={stats['count']}  "
                    f"sources={len(stats['sources'])}"
                )
                findings.append({
                    "port": port,
                    "service": svc,
                    "category": "suspicious",
                    "flow_count": stats["count"],
                    "source_count": len(stats["sources"]),
                    "bytes": stats["bytes"],
                })
            lines.append("")

        # Unknown high ports
        unknown_high = [
            (p, s) for p, s in port_stats.items()
            if p not in KNOWN_SERVICES and p not in ICS_PORTS
            and p not in SUSPICIOUS_PORTS and p > 1024
        ]
        if unknown_high:
            lines.append(f"❓ UNKNOWN HIGH PORTS — {len(unknown_high)} port(s)")
            lines.append("-" * 60)
            for port, stats in sorted(unknown_high, key=lambda x: x[1]["count"], reverse=True)[:15]:
                lines.append(
                    f"  {port:<6} flows={stats['count']}  "
                    f"sources={len(stats['sources'])}  "
                    f"{_format_bytes(stats['bytes'])}"
                )
                findings.append({
                    "port": port,
                    "service": "unknown",
                    "category": "unknown_high",
                    "flow_count": stats["count"],
                    "source_count": len(stats["sources"]),
                    "bytes": stats["bytes"],
                })

        if not findings:
            lines.append("✅ No notable port activity detected")

        return ToolResult(
            ok=True,
            result={
                "hunt": "ports",
                "findings": findings,
                "summary_text": "\n".join(lines),
                "severity": severity,
            },
        )

    # ===================================================================
    # hunt_beacons — C2 beaconing detection
    # ===================================================================

    def _hunt_beacons(self, session: Any, payload: dict) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal

        min_connections = payload.get("min_connections", 10)
        max_jitter_pct = payload.get("max_jitter_pct", 15.0)

        # Group timestamps by (internal_src, external_dst, dport)
        conn_times: Dict[tuple, list] = defaultdict(list)
        for (src, dst, dport, proto), stats in session.conversations.items():
            if is_internal(src) and not is_internal(dst):
                if stats["first_seen"]:
                    conn_times[(src, dst, dport)].append(stats["first_seen"])

        findings = []
        lines = []
        severity = "info"

        for (src, dst, dport), timestamps in conn_times.items():
            if len(timestamps) < min_connections:
                continue

            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0:
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            jitter_pct = (std_dev / mean_interval) * 100

            if jitter_pct <= max_jitter_pct:
                total_duration = timestamps[-1] - timestamps[0]
                confidence = "HIGH" if jitter_pct < 5 else "MEDIUM"

                if confidence == "HIGH":
                    severity = "critical"
                elif severity != "critical":
                    severity = "high"

                finding = {
                    "src": src,
                    "dst": dst,
                    "dport": dport,
                    "service": _service_name(dport),
                    "connections": len(timestamps),
                    "mean_interval": round(mean_interval, 2),
                    "std_deviation": round(std_dev, 2),
                    "jitter_pct": round(jitter_pct, 1),
                    "duration": round(total_duration, 1),
                    "confidence": confidence,
                }
                findings.append(finding)

        findings.sort(key=lambda f: f["jitter_pct"])

        if findings:
            lines.append(f"🔴 POTENTIAL C2 BEACONING — {len(findings)} candidate(s)")
            lines.append("-" * 70)
            for f in findings:
                dur = f["duration"]
                dur_str = f"{dur / 60:.0f}min" if dur < 3600 else f"{dur / 3600:.1f}hrs"
                lines.append(
                    f"  {f['src']} → {f['dst']}:{f['dport']} ({f['service']})"
                )
                lines.append(
                    f"    Connections: {f['connections']} | "
                    f"Mean interval: {f['mean_interval']:.1f}s | "
                    f"Jitter: {f['jitter_pct']:.1f}%"
                )
                lines.append(
                    f"    Duration: {dur_str} | "
                    f"Assessment: {f['confidence']} CONFIDENCE beacon"
                )
                lines.append("")
        else:
            lines.append("✅ No C2 beaconing indicators detected")

        return ToolResult(
            ok=True,
            result={
                "hunt": "beacons",
                "findings": findings,
                "summary_text": "\n".join(lines),
                "severity": severity,
            },
        )

    # ===================================================================
    # hunt_dns — DNS anomaly analysis
    # ===================================================================

    def _hunt_dns(self, session: Any, payload: dict) -> ToolResult:
        findings = []
        lines = []
        severity = "info"

        # 1. DGA detection via Shannon entropy
        domain_entropy = []
        seen_domains = set()
        for q in session.dns_queries:
            domain = q["query"]
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            parts = domain.split(".")
            if len(parts) < 2:
                continue

            # Analyze the subdomain labels (exclude TLD and base)
            label = parts[0] if len(parts) >= 3 else domain
            if len(label) > 10:
                entropy = _shannon_entropy(label)
                if entropy > 3.5:
                    domain_entropy.append({
                        "domain": domain,
                        "label": label,
                        "entropy": round(entropy, 2),
                        "label_length": len(label),
                    })

        if domain_entropy:
            domain_entropy.sort(key=lambda d: d["entropy"], reverse=True)
            severity = "high"
            lines.append(f"🟡 DGA CANDIDATES — {len(domain_entropy)} high-entropy domain(s)")
            lines.append("-" * 60)
            for d in domain_entropy[:20]:
                lines.append(
                    f"  {d['domain']}  entropy={d['entropy']}  len={d['label_length']}"
                )
            lines.append("")
            findings.extend([{**d, "type": "dga_candidate"} for d in domain_entropy[:50]])

        # 2. DNS tunneling indicators — high unique subdomain count per base
        domain_subs: Dict[str, set] = defaultdict(set)
        for q in session.dns_queries:
            parts = q["query"].split(".")
            if len(parts) >= 3:
                base = ".".join(parts[-2:])
                subdomain = ".".join(parts[:-2])
                domain_subs[base].add(subdomain)

        tunnel_candidates = [
            (base, subs) for base, subs in domain_subs.items()
            if len(subs) > 20
        ]
        tunnel_candidates.sort(key=lambda x: len(x[1]), reverse=True)

        if tunnel_candidates:
            severity = "high" if severity != "critical" else severity
            lines.append(f"🟡 DNS TUNNELING INDICATORS — {len(tunnel_candidates)} domain(s)")
            lines.append("-" * 60)
            for base, subs in tunnel_candidates[:10]:
                lines.append(f"  {base} — {len(subs)} unique subdomains")
                for sub in list(subs)[:3]:
                    lines.append(f"    {sub}.{base}")
                if len(subs) > 3:
                    lines.append(f"    ... +{len(subs) - 3} more")
            lines.append("")
            findings.extend([
                {"type": "tunnel_candidate", "base_domain": base,
                 "unique_subdomains": len(subs)}
                for base, subs in tunnel_candidates
            ])

        # 3. TXT record queries (often used for tunneling/C2)
        txt_queries = [
            q for q in session.dns_queries
            if q.get("type") == "query" and "TXT" in str(q.get("query_type", ""))
        ]
        if txt_queries:
            lines.append(f"🟡 TXT RECORD QUERIES — {len(txt_queries)}")
            lines.append("-" * 60)
            for q in txt_queries[:10]:
                lines.append(f"  {q['src']} → {q['query']}")
            lines.append("")

        # 4. High-frequency queries
        domain_freq = Counter(q["query"] for q in session.dns_queries)
        high_freq = [(d, c) for d, c in domain_freq.most_common(20) if c > 50]
        if high_freq:
            lines.append(f"📊 HIGH-FREQUENCY DNS QUERIES")
            lines.append("-" * 60)
            for domain, count in high_freq:
                lines.append(f"  {domain} — {count} queries")
            lines.append("")
            findings.extend([
                {"type": "high_frequency", "domain": d, "count": c}
                for d, c in high_freq
            ])

        if not findings:
            lines.append("✅ No DNS anomalies detected")

        return ToolResult(
            ok=True,
            result={
                "hunt": "dns",
                "findings": findings,
                "summary_text": "\n".join(lines),
                "severity": severity,
            },
        )

    # ===================================================================
    # hunt_tls — TLS fingerprinting
    # ===================================================================

    def _hunt_tls(self, session: Any, payload: dict) -> ToolResult:
        findings = []
        lines = []
        severity = "info"

        if not session.tls_handshakes:
            return ToolResult(
                ok=True,
                result={
                    "hunt": "tls",
                    "findings": [],
                    "summary_text": "No TLS handshakes in PCAP.",
                    "severity": "info",
                },
            )

        # SNI distribution
        sni_counts: Counter = Counter()
        no_sni = []
        for h in session.tls_handshakes:
            sni = h.get("sni") or ""
            if sni:
                sni_counts[sni] += 1
            else:
                no_sni.append(h)

        lines.append(f"📋 TLS HANDSHAKES — {len(session.tls_handshakes)} total, "
                     f"{len(sni_counts)} unique SNIs")
        lines.append("-" * 70)

        for sni, count in sni_counts.most_common(20):
            matching = [h for h in session.tls_handshakes if h.get("sni") == sni]
            dst_ips = sorted(set(h["dst"] for h in matching))
            ips_str = ", ".join(dst_ips[:5])
            if len(dst_ips) > 5:
                ips_str += "..."
            lines.append(f"  {sni:<45} {count:<8} {ips_str}")
            findings.append({
                "type": "sni",
                "sni": sni,
                "count": count,
                "dst_ips": dst_ips,
            })
        lines.append("")

        # Connections without SNI — suspicious
        if no_sni:
            severity = "medium"
            lines.append(f"🟡 TLS WITHOUT SNI — {len(no_sni)} connection(s)")
            lines.append("-" * 60)
            no_sni_by_dst: Dict[str, int] = Counter()
            for h in no_sni:
                no_sni_by_dst[f"{h['dst']}:{h.get('dport', 443)}"] += 1
            for target, count in no_sni_by_dst.most_common(15):
                lines.append(f"  {target} — {count} handshake(s) without SNI")
            lines.append("")
            findings.extend([
                {"type": "no_sni", "target": t, "count": c}
                for t, c in no_sni_by_dst.most_common(15)
            ])

        return ToolResult(
            ok=True,
            result={
                "hunt": "tls",
                "findings": findings,
                "summary_text": "\n".join(lines),
                "severity": severity,
            },
        )

    # ===================================================================
    # hunt_lateral — Lateral movement detection
    # ===================================================================

    def _hunt_lateral(self, session: Any, payload: dict) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal

        findings = []
        lines = []
        severity = "info"

        # Management/lateral movement ports
        lateral_ports = {
            22: "SSH", 135: "RPC", 139: "NetBIOS",
            445: "SMB", 3389: "RDP", 5985: "WinRM",
            5986: "WinRM-S", 23: "Telnet",
        }

        # ICS lateral ports
        ics_lateral = {
            502: "Modbus", 102: "S7comm", 44818: "EtherNet/IP",
            20000: "DNP3", 4840: "OPC-UA", 47808: "BACnet",
            2404: "IEC-104",
        }

        # 1. Internal→Internal on management ports
        mgmt_lateral = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            if is_internal(src) and is_internal(dst) and dport in lateral_ports:
                mgmt_lateral.append({
                    "src": src,
                    "dst": dst,
                    "port": dport,
                    "service": lateral_ports[dport],
                    "packets": stats["packets"],
                    "bytes": stats["bytes_out"],
                })

        if mgmt_lateral:
            severity = "high"
            lines.append(f"🟡 INTERNAL LATERAL MOVEMENT — {len(mgmt_lateral)} flow(s)")
            lines.append("-" * 70)

            by_src: Dict[str, list] = defaultdict(list)
            for m in mgmt_lateral:
                by_src[m["src"]].append(m)

            for src, flows in sorted(by_src.items(), key=lambda x: len(x[1]), reverse=True):
                dsts = set(f["dst"] for f in flows)
                ports = set(f["service"] for f in flows)
                flag = " 🔴 SCAN?" if len(dsts) > 5 else ""
                lines.append(
                    f"  {src} → {len(dsts)} targets ({', '.join(ports)}){flag}"
                )
                for f in flows[:5]:
                    lines.append(
                        f"    → {f['dst']}:{f['port']} ({f['service']}) "
                        f"{f['packets']} pkts {_format_bytes(f['bytes'])}"
                    )
                if len(flows) > 5:
                    lines.append(f"    ... +{len(flows) - 5} more")

                findings.append({
                    "type": "mgmt_lateral",
                    "src": src,
                    "target_count": len(dsts),
                    "services": sorted(ports),
                    "potential_scan": len(dsts) > 5,
                    "flows": flows[:10],
                })
            lines.append("")

        # 2. Port scan patterns (internal→internal)
        src_dst_per_port: Dict[tuple, set] = defaultdict(set)
        for (src, dst, dport, proto), stats in session.conversations.items():
            if is_internal(src) and is_internal(dst) and dport > 0:
                src_dst_per_port[(src, dport)].add(dst)

        scanners = [
            (src, dport, len(dsts))
            for (src, dport), dsts in src_dst_per_port.items()
            if len(dsts) >= 5
        ]

        if scanners:
            severity = "critical" if severity != "critical" else severity
            scanners.sort(key=lambda x: x[2], reverse=True)
            lines.append(f"🔴 PORT SCAN PATTERNS — {len(scanners)} pattern(s)")
            lines.append("-" * 60)
            for src, dport, dst_count in scanners[:15]:
                svc = _service_name(dport)
                lines.append(f"  {src} → {dst_count} hosts on port {dport} ({svc})")
                findings.append({
                    "type": "port_scan",
                    "src": src,
                    "dport": dport,
                    "service": svc,
                    "target_count": dst_count,
                })
            lines.append("")

        # 3. ICS cross-zone traffic
        ics_cross = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            if dport in ics_lateral:
                if not is_internal(src) or not is_internal(dst):
                    ics_cross.append({
                        "src": src,
                        "dst": dst,
                        "port": dport,
                        "service": ics_lateral[dport],
                        "packets": stats["packets"],
                        "src_location": "INT" if is_internal(src) else "EXT",
                        "dst_location": "INT" if is_internal(dst) else "EXT",
                    })

        if ics_cross:
            severity = "critical"
            lines.append("🔴 ICS PROTOCOL CROSS-ZONE TRAFFIC")
            lines.append("-" * 60)
            for c in ics_cross:
                lines.append(
                    f"  {c['src']} ({c['src_location']}) → "
                    f"{c['dst']} ({c['dst_location']}):{c['port']} "
                    f"({c['service']}) — {c['packets']} pkts"
                )
                findings.append({
                    "type": "ics_cross_zone",
                    **c,
                })
            lines.append("")

        if not findings:
            lines.append("✅ No lateral movement indicators detected")

        return ToolResult(
            ok=True,
            result={
                "hunt": "lateral",
                "findings": findings,
                "summary_text": "\n".join(lines),
                "severity": severity,
            },
        )

    # ===================================================================
    # hunt_exfil — Data exfiltration detection
    # ===================================================================

    def _hunt_exfil(self, session: Any, payload: dict) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal

        min_ratio = payload.get("min_ratio", 10.0)
        min_bytes_out = payload.get("min_bytes_out", 1048576)

        findings = []
        lines = []
        severity = "info"

        # 1. Asymmetric outbound flows
        pair_stats: Dict[tuple, dict] = defaultdict(lambda: {
            "bytes_out": 0,
            "bytes_in": 0,
            "packets": 0,
            "ports": set(),
            "first": None,
            "last": None,
        })

        for (src, dst, dport, proto), stats in session.conversations.items():
            if is_internal(src) and not is_internal(dst):
                key = (src, dst)
                ps = pair_stats[key]
                ps["bytes_out"] += stats["bytes_out"]
                ps["packets"] += stats["packets"]
                ps["ports"].add(dport)
                if stats["first_seen"]:
                    if ps["first"] is None or stats["first_seen"] < ps["first"]:
                        ps["first"] = stats["first_seen"]
                    if ps["last"] is None or stats["last_seen"] > ps["last"]:
                        ps["last"] = stats["last_seen"]

        # Count reverse flows as inbound
        for (src, dst, dport, proto), stats in session.conversations.items():
            if not is_internal(src) and is_internal(dst):
                key = (dst, src)
                if key in pair_stats:
                    pair_stats[key]["bytes_in"] += stats["bytes_out"]

        asymmetric = []
        for (src, dst), ps in pair_stats.items():
            if ps["bytes_out"] < min_bytes_out:
                continue
            bytes_in = max(ps["bytes_in"], 1)
            ratio = ps["bytes_out"] / bytes_in
            if ratio >= min_ratio:
                duration = 0.0
                if ps["first"] and ps["last"]:
                    duration = ps["last"] - ps["first"]
                asymmetric.append({
                    "src": src,
                    "dst": dst,
                    "bytes_out": ps["bytes_out"],
                    "bytes_in": ps["bytes_in"],
                    "ratio": round(ratio, 1),
                    "packets": ps["packets"],
                    "ports": sorted(ps["ports"]),
                    "duration": duration,
                })

        if asymmetric:
            severity = "critical"
            asymmetric.sort(key=lambda a: a["bytes_out"], reverse=True)
            lines.append(
                f"🔴 ASYMMETRIC OUTBOUND FLOWS — {len(asymmetric)} suspect pair(s)"
            )
            lines.append("-" * 70)
            for a in asymmetric[:15]:
                dur_str = (
                    f"{a['duration'] / 60:.0f}min" if a["duration"] < 3600
                    else f"{a['duration'] / 3600:.1f}hrs"
                )
                ports = ", ".join(str(p) for p in a["ports"])
                lines.append(f"  {a['src']} → {a['dst']}")
                lines.append(
                    f"    Out: {_format_bytes(a['bytes_out'])}  "
                    f"In: {_format_bytes(a['bytes_in'])}  "
                    f"Ratio: {a['ratio']}x  Duration: {dur_str}"
                )
                lines.append(f"    Ports: {ports}  Packets: {a['packets']:,}")
                lines.append("")
            findings.extend([{**a, "type": "asymmetric_outbound"} for a in asymmetric])

        # 2. DNS-based exfiltration
        domain_subs: Dict[str, set] = defaultdict(set)
        for q in session.dns_queries:
            parts = q["query"].split(".")
            if len(parts) >= 3:
                base = ".".join(parts[-2:])
                subdomain = ".".join(parts[:-2])
                domain_subs[base].add(subdomain)

        dns_exfil = [
            (base, subs) for base, subs in domain_subs.items()
            if len(subs) > 20
        ]
        dns_exfil.sort(key=lambda x: len(x[1]), reverse=True)

        if dns_exfil:
            if severity != "critical":
                severity = "high"
            lines.append("🟡 DNS EXFIL INDICATORS — high unique subdomain count")
            lines.append("-" * 60)
            for base, subs in dns_exfil[:10]:
                lines.append(f"  {base} — {len(subs)} unique subdomains queried")
                for sub in list(subs)[:3]:
                    lines.append(f"    {sub}.{base}")
                if len(subs) > 3:
                    lines.append(f"    ... +{len(subs) - 3} more")
            lines.append("")
            findings.extend([
                {"type": "dns_exfil", "base_domain": base,
                 "unique_subdomains": len(subs)}
                for base, subs in dns_exfil
            ])

        if not findings:
            lines.append("✅ No data exfiltration indicators detected")

        return ToolResult(
            ok=True,
            result={
                "hunt": "exfil",
                "findings": findings,
                "summary_text": "\n".join(lines),
                "severity": severity,
            },
        )
