"""
Zeek Log Parser — Converts Zeek JSON logs into PcapSession

Reads Zeek's JSON-format log files (conn.log, dns.log, ssl.log,
http.log, files.log, notice.log, weird.log) and populates a
PcapSession object identical to what the scapy/dpkt parsers produce.

This allows all downstream tools (pcap_threat_hunter, pcap_ai_analyzer,
pcap_ip_search, pcap_flow_analyzer, pcap_report_correlator) to work
on Zeek output with zero changes.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("eventmill.plugins.network_forensics.zeek_loader")

# Protocol name mapping: Zeek proto field → EventMill protocol names
_PROTO_MAP = {
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
}

# OT/ICS service names that Zeek may identify
_OT_SERVICES = {
    "modbus", "dnp3", "bacnet", "enip", "cip", "s7comm",
    "opcua", "iec104", "goose", "mms",
}


def parse_zeek_logs(log_dir: str | Path) -> "PcapSession":
    """Parse all Zeek JSON log files in a directory into a PcapSession.

    Args:
        log_dir: Directory containing Zeek .log files (JSON format).

    Returns:
        Populated PcapSession instance.
    """
    # Import PcapSession and helpers from the canonical location
    from plugins.network_forensics.pcap_metadata_summary.tool import PcapSession

    log_dir = Path(log_dir)
    session = PcapSession()
    session.filename = f"zeek:{log_dir.name}"
    session.file_path = str(log_dir)

    # Parse each log type
    conn_path = log_dir / "conn.log"
    if conn_path.exists():
        _parse_conn_log(conn_path, session)

    dns_path = log_dir / "dns.log"
    if dns_path.exists():
        _parse_dns_log(dns_path, session)

    ssl_path = log_dir / "ssl.log"
    if ssl_path.exists():
        _parse_ssl_log(ssl_path, session)

    http_path = log_dir / "http.log"
    if http_path.exists():
        _parse_http_log(http_path, session)

    notice_path = log_dir / "notice.log"
    if notice_path.exists():
        _parse_notice_log(notice_path, session)

    weird_path = log_dir / "weird.log"
    if weird_path.exists():
        _parse_weird_log(weird_path, session)

    # Estimate packet count from connection metadata
    if session.packet_count == 0:
        # Sum orig_pkts + resp_pkts from conversations if we tracked them
        for conv_stats in session.conversations.values():
            session.packet_count += conv_stats.get("packets", 0)

    files_parsed = [
        f.name for f in log_dir.glob("*.log")
        if f.name in ("conn.log", "dns.log", "ssl.log", "http.log", "notice.log", "weird.log")
    ]
    logger.info(
        "Zeek logs parsed: %d files, %d conversations, %d IPs, duration %s",
        len(files_parsed),
        len(session.conversations),
        len(session.unique_ips),
        session.duration_str,
    )

    return session


def _read_zeek_json(path: Path):
    """Yield parsed JSON objects from a Zeek JSON log file.

    Handles both Zeek's one-JSON-object-per-line format and
    lines that start with '#' (Zeek header comments in some formats).
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _ts_to_epoch(ts_val) -> float | None:
    """Convert Zeek timestamp to epoch float.

    Zeek JSON timestamps can be epoch floats or ISO strings.
    """
    if ts_val is None:
        return None
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str):
        try:
            return float(ts_val)
        except ValueError:
            pass
        # Try ISO format
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, TypeError):
            pass
    return None


def _update_time_range(session, ts: float | None):
    """Update session start/end time bounds."""
    if ts is None:
        return
    if session.start_time is None or ts < session.start_time:
        session.start_time = ts
    if session.end_time is None or ts > session.end_time:
        session.end_time = ts


def _parse_conn_log(path: Path, session) -> None:
    """Parse conn.log — the core connection log.

    Maps to PcapSession.conversations, src/dst_ips, src/dst_ports, protocols.
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        src_ip = entry.get("id.orig_h", "")
        dst_ip = entry.get("id.resp_h", "")
        src_port = int(entry.get("id.orig_p", 0))
        dst_port = int(entry.get("id.resp_p", 0))
        proto = entry.get("proto", "tcp").lower()
        service = entry.get("service", "")

        proto_upper = _PROTO_MAP.get(proto, proto.upper())

        # Update IP counters
        if src_ip:
            session.src_ips[src_ip] += 1
        if dst_ip:
            session.dst_ips[dst_ip] += 1

        # Update port counters
        if dst_port:
            session.dst_ports[dst_port] += 1
            session.port_proto[dst_port] = proto_upper
        if src_port:
            session.src_ports[src_port] += 1

        # Protocol distribution
        session.protocols[proto_upper] += 1
        if service:
            session.protocols[service.upper()] += 1

        # Build conversation key (matches scapy/dpkt parser format)
        conv_key = (src_ip, dst_ip, dst_port, proto_upper)

        orig_bytes = int(entry.get("orig_bytes") or entry.get("orig_ip_bytes") or 0)
        resp_bytes = int(entry.get("resp_bytes") or entry.get("resp_ip_bytes") or 0)
        orig_pkts = int(entry.get("orig_pkts", 0))
        resp_pkts = int(entry.get("resp_pkts", 0))

        conv = session.conversations[conv_key]
        conv["packets"] += orig_pkts + resp_pkts
        conv["bytes_out"] += orig_bytes
        conv["bytes_in"] += resp_bytes

        if ts:
            if conv["first_seen"] is None or ts < conv["first_seen"]:
                conv["first_seen"] = ts
            if conv["last_seen"] is None or ts > conv["last_seen"]:
                conv["last_seen"] = ts

            # Timestamps for beacon detection (capped to avoid memory blow-up)
            if len(conv["timestamps"]) < 2000:
                conv["timestamps"].append(ts)

        duration = entry.get("duration")
        if duration is not None:
            try:
                conv["duration"] = float(duration)
            except (ValueError, TypeError):
                pass

        # Track connection state for threat hunting
        conn_state = entry.get("conn_state", "")
        if conn_state:
            conv["conn_state"] = conn_state

        # Detect OT/ICS services
        if service and service.lower() in _OT_SERVICES:
            session.ot_transactions.append({
                "protocol": service.upper(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "timestamp": ts,
                "function_code": None,
                "description": f"Zeek-detected {service} connection",
            })


def _parse_dns_log(path: Path, session) -> None:
    """Parse dns.log — DNS queries and responses."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        query_name = entry.get("query", "")
        qtype = entry.get("qtype_name", entry.get("qtype", ""))
        rcode = entry.get("rcode_name", entry.get("rcode", ""))
        answers = entry.get("answers", [])
        src_ip = entry.get("id.orig_h", "")
        dst_ip = entry.get("id.resp_h", "")

        if query_name:
            session.dns_queries.append({
                "query": query_name,
                "type": str(qtype),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": ts,
            })

        if answers and isinstance(answers, list):
            for answer in answers:
                session.dns_responses.append({
                    "query": query_name,
                    "type": str(qtype),
                    "answer": str(answer),
                    "rcode": str(rcode),
                    "src_ip": dst_ip,  # DNS server responds
                    "dst_ip": src_ip,
                    "timestamp": ts,
                })


def _parse_ssl_log(path: Path, session) -> None:
    """Parse ssl.log — TLS handshake metadata."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        session.tls_handshakes.append({
            "src_ip": entry.get("id.orig_h", ""),
            "dst_ip": entry.get("id.resp_h", ""),
            "src_port": int(entry.get("id.orig_p", 0)),
            "dst_port": int(entry.get("id.resp_p", 0)),
            "server_name": entry.get("server_name", ""),
            "version": entry.get("version", ""),
            "cipher": entry.get("cipher", ""),
            "ja3": entry.get("ja3", ""),
            "ja3s": entry.get("ja3s", ""),
            "subject": entry.get("subject", ""),
            "issuer": entry.get("issuer", ""),
            "validation_status": entry.get("validation_status", ""),
            "timestamp": ts,
        })


def _parse_http_log(path: Path, session) -> None:
    """Parse http.log — HTTP request/response metadata."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        session.http_requests.append({
            "src_ip": entry.get("id.orig_h", ""),
            "dst_ip": entry.get("id.resp_h", ""),
            "src_port": int(entry.get("id.orig_p", 0)),
            "dst_port": int(entry.get("id.resp_p", 0)),
            "method": entry.get("method", ""),
            "host": entry.get("host", ""),
            "uri": entry.get("uri", ""),
            "user_agent": entry.get("user_agent", ""),
            "status_code": entry.get("status_code"),
            "content_type": entry.get("resp_mime_types", [None])[0] if isinstance(entry.get("resp_mime_types"), list) else entry.get("resp_mime_types"),
            "request_body_len": int(entry.get("request_body_len", 0)),
            "response_body_len": int(entry.get("response_body_len", 0)),
            "timestamp": ts,
        })


def _parse_notice_log(path: Path, session) -> None:
    """Parse notice.log — Zeek-generated security notices.

    These map conceptually to cleartext_creds and other anomaly detections.
    Stored as cleartext_creds entries for compatibility with threat_hunter.
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        note = entry.get("note", "")
        msg = entry.get("msg", "")
        src_ip = entry.get("src", entry.get("id.orig_h", ""))
        dst_ip = entry.get("dst", entry.get("id.resp_h", ""))

        # Cleartext password notices
        if "Password" in note or "Cleartext" in note or "HTTP::Basic" in note:
            session.cleartext_creds.append({
                "protocol": note,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "username": "[redacted by Zeek]",
                "service": entry.get("sub", ""),
                "timestamp": ts,
            })


def _parse_weird_log(path: Path, session) -> None:
    """Parse weird.log — protocol anomalies.

    Stored in a session attribute for the AI analyzer to reference.
    """
    weirdness: list[dict] = []
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        weirdness.append({
            "name": entry.get("name", ""),
            "src_ip": entry.get("id.orig_h", ""),
            "dst_ip": entry.get("id.resp_h", ""),
            "addl": entry.get("addl", ""),
            "timestamp": ts,
        })

    # Store as an extra attribute — downstream tools can check for it
    session._zeek_weird = weirdness  # type: ignore[attr-defined]
    if weirdness:
        logger.info("Parsed %d weird entries from Zeek", len(weirdness))
