"""
Zeek Log Parser — Converts Zeek JSON logs into PcapSession

Reads Zeek's JSON-format log files (conn.log, dns.log, ssl.log,
http.log, files.log, notice.log, weird.log) and populates a
PcapSession object identical to what the scapy/dpkt parsers produce.
OT/ICS protocol support:
  Parses dedicated Zeek OT analyzer logs produced by the icsnpp
  package family — modbus.log, dnp3.log, bacnet.log, s7comm.log,
  enip.log / cip.log, opcua_binary.log.  Falls back to service-field
  detection in conn.log when dedicated logs are absent.
This allows all downstream tools (pcap_threat_hunter, pcap_ai_analyzer,
pcap_ip_search, pcap_flow_analyzer, pcap_report_correlator) to work
on Zeek output with zero changes.

Note: STP (Spanning Tree Protocol) is Layer 2 — standard Zeek cannot
see STP BPDUs.  However, the zeek-stp packet analyzer plugin
(cloud_install/zeek-stp/) adds a custom LLC-level analyzer that
produces stp.log with full BPDU field extraction.  When stp.log is
present, _parse_stp_log() populates all STP fields in PcapSession.
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
    "profinet", "ethercat", "hart_ip", "bsap",
    "genisys", "ge_srtp", "c1222", "synchrophasor",
    "omron_fins", "roc_plus",
}

# Modbus function code names (matches scapy/dpkt parser)
_MODBUS_FUNC_NAMES: Dict[int, str] = {
    1: "Read Coils", 2: "Read Discrete Inputs",
    3: "Read Holding Registers", 4: "Read Input Registers",
    5: "Write Single Coil", 6: "Write Single Register",
    8: "Diagnostics", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers", 43: "Read Device ID",
}
_MODBUS_WRITE_FUNCS = {5, 6, 15, 16, 22, 23}
_MODBUS_DIAG_FUNCS = {8, 43}

# DNP3 function code names
_DNP3_FUNC_NAMES: Dict[int, str] = {
    0: "Confirm", 1: "Read", 2: "Write",
    3: "Select", 4: "Operate", 5: "Direct-Operate",
    13: "Cold-Restart", 14: "Warm-Restart",
    18: "Stop-Application", 19: "Start-Application",
    129: "Response", 130: "Unsolicited-Response",
}
_DNP3_WRITE_FUNCS = {2, 3, 4, 5}
_DNP3_CONTROL_FUNCS = {5, 13, 14, 18, 19}

# S7comm PDU type names
_S7_PDU_NAMES: Dict[int, str] = {1: "Job", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}
_S7_FUNC_NAMES: Dict[int, str] = {
    4: "Read", 5: "Write", 0x28: "PLC-Stop",
    0x29: "PLC-Start", 0x1A: "Upload", 0x1B: "Download",
}

# Dedicated OT log files produced by icsnpp packages
_OT_LOG_FILES = (
    "modbus.log", "modbus_detailed.log",
    "dnp3.log", "dnp3_objects.log",
    "bacnet.log",
    "s7comm.log", "s7comm_plus.log", "s7comm_read_szl.log",
    "enip.log", "cip.log", "cip_identity.log",
    "opcua_binary.log",
    "profinet_io_cm.log",
    "ethercat.log",
    "hart_ip.log",
    "bsap_ip.log", "bsap_serial.log",
    "genisys.log",
    "ge_srtp.log",
    "c1222.log",
    "synchrophasor.log",
    "omron_fins.log",
    "roc_plus.log",
)


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

    # --- STP/RSTP/MSTP BPDU log (zeek-stp plugin) ---
    stp_path = log_dir / "stp.log"
    if stp_path.exists():
        _parse_stp_log(stp_path, session)

    # --- CDP / LLDP switch identity logs ---
    cdp_path = log_dir / "cdp.log"
    if cdp_path.exists():
        _parse_cdp_log(cdp_path, session)
    lldp_path = log_dir / "lldp.log"
    if lldp_path.exists():
        _parse_lldp_log(lldp_path, session)

    # --- Network discovery: ARP and DHCP logs ---
    arp_path = log_dir / "arp.log"
    if arp_path.exists():
        _parse_arp_log_networks(arp_path, session)
    dhcp_path = log_dir / "dhcp.log"
    if dhcp_path.exists():
        _parse_dhcp_log_networks(dhcp_path, session)

    # --- OT/ICS dedicated protocol logs (icsnpp packages) ---
    _ot_log_parsers: Dict[str, Any] = {
        "modbus.log": _parse_modbus_log,
        "modbus_detailed.log": _parse_modbus_detailed_log,
        "dnp3.log": _parse_dnp3_log,
        "bacnet.log": _parse_bacnet_log,
        "s7comm.log": _parse_s7comm_log,
        "s7comm_plus.log": _parse_s7comm_log,
        "enip.log": _parse_enip_log,
        "cip.log": _parse_cip_log,
        "cip_identity.log": _parse_cip_log,
        "opcua_binary.log": _parse_opcua_log,
        "profinet_io_cm.log": _parse_profinet_log,
        "ethercat.log": _parse_ethercat_log,
        "hart_ip.log": _parse_hart_ip_log,
        "bsap_ip.log": _parse_bsap_log,
        "bsap_serial.log": _parse_bsap_log,
        "genisys.log": _parse_genisys_log,
        "ge_srtp.log": _parse_ge_srtp_log,
        "c1222.log": _parse_c1222_log,
        "synchrophasor.log": _parse_synchrophasor_log,
        "omron_fins.log": _parse_omron_fins_log,
        "roc_plus.log": _parse_roc_plus_log,
    }
    ot_files_parsed: List[str] = []
    for log_name, parser_fn in _ot_log_parsers.items():
        ot_path = log_dir / log_name
        if ot_path.exists():
            parser_fn(ot_path, session)
            ot_files_parsed.append(log_name)

    if ot_files_parsed:
        logger.info("Zeek OT/ICS logs parsed: %s", ", ".join(ot_files_parsed))

    # --- IT security / infrastructure protocol logs ---
    _it_log_parsers: Dict[str, Any] = {
        "kerberos.log": _parse_kerberos_log,
        "smb_mapping.log": _parse_smb_mapping_log,
        "smb_files.log": _parse_smb_files_log,
        "dce_rpc.log": _parse_dce_rpc_log,
        "syslog.log": _parse_syslog_log,
        "ldap.log": _parse_ldap_log,
        "ntlm.log": _parse_ntlm_log,
        "ssh.log": _parse_ssh_log,
        "snmp.log": _parse_snmp_log,
    }
    it_files_parsed: List[str] = []
    for log_name, parser_fn in _it_log_parsers.items():
        it_path = log_dir / log_name
        if it_path.exists():
            parser_fn(it_path, session)
            it_files_parsed.append(log_name)

    if it_files_parsed:
        logger.info("Zeek IT/security logs parsed: %s", ", ".join(it_files_parsed))

    # Estimate packet count from connection metadata
    if session.packet_count == 0:
        # Sum orig_pkts + resp_pkts from conversations if we tracked them
        for conv_stats in session.conversations.values():
            session.packet_count += conv_stats.get("packets", 0)

    _ALL_KNOWN_LOGS = {
        "conn.log", "dns.log", "ssl.log", "http.log", "notice.log", "weird.log",
        "stp.log",
        "kerberos.log", "smb_mapping.log", "smb_files.log", "dce_rpc.log",
        "syslog.log", "ldap.log", "ntlm.log", "ssh.log", "snmp.log",
    } | set(_OT_LOG_FILES)
    files_parsed = [
        f.name for f in log_dir.glob("*.log")
        if f.name in _ALL_KNOWN_LOGS
    ]
    logger.info(
        "Zeek logs parsed: %d files, %d conversations, %d IPs, duration %s",
        len(files_parsed),
        len(session.conversations),
        len(session.unique_ips),
        session.duration_str,
    )

    # --- Post-process: infer networks from collected evidence ---
    from plugins.network_forensics.pcap_metadata_summary.tool import _infer_networks_from_evidence
    _infer_networks_from_evidence(session)

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

        # Connection byte/packet counts
        orig_bytes = int(entry.get("orig_bytes") or entry.get("orig_ip_bytes") or 0)
        resp_bytes = int(entry.get("resp_bytes") or entry.get("resp_ip_bytes") or 0)
        orig_pkts = int(entry.get("orig_pkts", 0))
        resp_pkts = int(entry.get("resp_pkts", 0))
        total_pkts = orig_pkts + resp_pkts

        # Protocol distribution — count by packets (not connections) to
        # match scapy/dpkt behaviour where protocols += 1 per packet.
        if total_pkts > 0:
            session.protocols[proto_upper] += total_pkts
            if service:
                session.protocols[service.upper()] += total_pkts
        else:
            # Fallback: count at least 1 so the protocol appears
            session.protocols[proto_upper] += 1
            if service:
                session.protocols[service.upper()] += 1

        # Accumulate total payload bytes transferred (NOT the PCAP file size)
        session.bytes_transferred += orig_bytes + resp_bytes

        # Build conversation key (matches scapy/dpkt parser format)
        conv_key = (src_ip, dst_ip, dst_port, proto_upper)

        conv = session.conversations[conv_key]
        conv["packets"] += orig_pkts + resp_pkts
        conv["bytes_out"] += orig_bytes
        conv["bytes_in"] += resp_bytes

        if ts:
            if conv["first_seen"] is None or ts < conv["first_seen"]:
                conv["first_seen"] = ts
            if conv["last_seen"] is None or ts > conv["last_seen"]:
                conv["last_seen"] = ts

            # Timestamps for beacon detection
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

        # -----------------------------------------------------------
        # TCP health from conn.log fields (retransmit, RST, etc.)
        # -----------------------------------------------------------
        if proto == "tcp":
            # Retransmission detection from Zeek's history field:
            #   'T' = originator retransmitted, 't' = responder retransmitted
            history = entry.get("history", "")
            retx_count = history.count("T") + history.count("t")
            if retx_count > 0:
                session.tcp_retransmissions += retx_count
                session.conv_health[conv_key]["retransmit"] += retx_count

            # RST detection from conn_state:
            #   RSTO = originator sent RST, RSTR = responder sent RST
            #   Also check history for 'R'/'r'
            rst_count = history.count("R") + history.count("r")
            if rst_count > 0:
                session.tcp_rst_count += rst_count
                session.conv_health[conv_key]["rst"] += rst_count

            # SYN / FIN counting from history
            if "S" in history or "s" in history:
                session.tcp_syn_count += 1
            if "F" in history or "f" in history:
                session.tcp_fin_count += 1

            # Zero-window: Zeek doesn't track this directly, skip

        # Detect OT/ICS services
        if service and service.lower() in _OT_SERVICES:
            session.ot_transactions.append({
                "protocol": service.upper(),
                "port": dst_port,
                "src": src_ip,
                "dst": dst_ip,
                "ts": ts,
                "function_code": None,
                "description": f"Zeek-detected {service} connection",
            })

        # -----------------------------------------------------------
        # Control plane protocol detection from conn.log
        # Zeek sees OSPF/EIGRP/VRRP/HSRP as connections; we can count
        # them even though Zeek doesn't deeply parse them.
        # -----------------------------------------------------------
        proto_lower = proto.lower()

        # HSRP: UDP port 1985 or 2029
        if proto_lower == "udp" and dst_port in (1985, 2029):
            session.hsrp_hello_count += 1
            session.hsrp_events.append({
                "src": src_ip, "group": 0, "state": "Unknown",
                "priority": 0, "vip": dst_ip, "ts": ts,
            })

        # VRRP: IP protocol 112 — Zeek may log as proto="vrrp" or service="vrrp"
        if proto_lower == "vrrp" or (service and service.lower() == "vrrp"):
            session.vrrp_advert_count += 1
            session.vrrp_events.append({
                "src": src_ip, "vrid": 0,
                "priority": 0, "ts": ts,
            })

        # OSPF: IP protocol 89 — Zeek may log as proto="ospf"
        if proto_lower == "ospf" or (service and service.lower() == "ospf"):
            session.ospf_total_count += 1
            session.ospf_hello_count += 1  # best approximation
            session.ospf_router_ids.add(src_ip)
            neighbor_key = (src_ip, dst_ip)
            if ts:
                session.ospf_neighbor_hellos[neighbor_key].append(ts)

        # EIGRP: IP protocol 88 — Zeek may log as proto="eigrp"
        if proto_lower == "eigrp" or (service and service.lower() == "eigrp"):
            session.eigrp_total_count += 1
            session.eigrp_hello_count += 1  # best approximation

        # -----------------------------------------------------------
        # VLAN extraction from conn.log fields
        # Zeek populates 'vlan' and 'inner_vlan' when 802.1Q tags are
        # present in the capture.
        # -----------------------------------------------------------
        vlan_val = entry.get("vlan")
        if vlan_val is not None:
            try:
                vlan_id = int(vlan_val)
                # Count once per connection (not per packet, since conn.log
                # aggregates); weight by packet count for proportional stats
                weight = max(total_pkts, 1)
                session.vlan_ids[vlan_id] += weight
                if vlan_id == 1:
                    session.vlan_1_detected = True
                if src_ip:
                    session.vlan_to_ips[vlan_id].add(src_ip)
                if dst_ip:
                    session.vlan_to_ips[vlan_id].add(dst_ip)
            except (ValueError, TypeError):
                pass
        else:
            # No VLAN field = untagged traffic
            weight = max(total_pkts, 1)
            session.untagged_frame_count += weight

        inner_vlan_val = entry.get("inner_vlan")
        if inner_vlan_val is not None:
            try:
                inner_vlan_id = int(inner_vlan_val)
                weight = max(total_pkts, 1)
                session.vlan_ids[inner_vlan_id] += weight
                if inner_vlan_id == 1:
                    session.vlan_1_detected = True
                if src_ip:
                    session.vlan_to_ips[inner_vlan_id].add(src_ip)
                if dst_ip:
                    session.vlan_to_ips[inner_vlan_id].add(dst_ip)
            except (ValueError, TypeError):
                pass


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
                "src": src_ip,
                "dst": dst_ip,
                "ts": ts,
            })

        if answers and isinstance(answers, list):
            for answer in answers:
                session.dns_responses.append({
                    "query": query_name,
                    "type": str(qtype),
                    "answer": str(answer),
                    "rcode": str(rcode),
                    "src": dst_ip,  # DNS server responds
                    "dst": src_ip,
                    "ts": ts,
                })


def _parse_ssl_log(path: Path, session) -> None:
    """Parse ssl.log — TLS handshake metadata."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        session.tls_handshakes.append({
            "src": entry.get("id.orig_h", ""),
            "dst": entry.get("id.resp_h", ""),
            "sport": int(entry.get("id.orig_p", 0)),
            "dport": int(entry.get("id.resp_p", 0)),
            "sni": entry.get("server_name", ""),
            "type": "ClientHello",
            "version": entry.get("version", ""),
            "cipher": entry.get("cipher", ""),
            "ja3": entry.get("ja3", ""),
            "ja3s": entry.get("ja3s", ""),
            "subject": entry.get("subject", ""),
            "issuer": entry.get("issuer", ""),
            "validation_status": entry.get("validation_status", ""),
            "ts": ts,
        })


def _parse_http_log(path: Path, session) -> None:
    """Parse http.log — HTTP request/response metadata."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        session.http_requests.append({
            "src": entry.get("id.orig_h", ""),
            "dst": entry.get("id.resp_h", ""),
            "sport": int(entry.get("id.orig_p", 0)),
            "dport": int(entry.get("id.resp_p", 0)),
            "method": entry.get("method", ""),
            "host": entry.get("host", ""),
            "path": entry.get("uri", ""),
            "user_agent": entry.get("user_agent", ""),
            "status_code": entry.get("status_code"),
            "content_type": entry.get("resp_mime_types", [None])[0] if isinstance(entry.get("resp_mime_types"), list) else entry.get("resp_mime_types"),
            "request_body_len": int(entry.get("request_body_len", 0)),
            "response_body_len": int(entry.get("response_body_len", 0)),
            "ts": ts,
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
                "src": src_ip,
                "dst": dst_ip,
                "username": "[redacted by Zeek]",
                "service": entry.get("sub", ""),
                "ts": ts,
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
            "src": entry.get("id.orig_h", ""),
            "dst": entry.get("id.resp_h", ""),
            "addl": entry.get("addl", ""),
            "ts": ts,
        })

    # Store as an extra attribute — downstream tools can check for it
    session._zeek_weird = weirdness  # type: ignore[attr-defined]
    if weirdness:
        logger.info("Parsed %d weird entries from Zeek", len(weirdness))


# ---------------------------------------------------------------------------
# STP / BPDU log parser (zeek-stp plugin)
# ---------------------------------------------------------------------------

def _parse_stp_log(path: Path, session) -> None:
    """Parse stp.log — STP/RSTP/MSTP BPDU data from zeek-stp plugin.

    Populates all STP fields in PcapSession: counts, flags, root/bridge
    tracking, port roles/states, timers, VLANs, root changes, and src MACs.
    """
    last_root_per_vlan: Dict[int, str] = {}
    count = 0
    for entry in _read_zeek_json(path):
        count += 1
        session.stp_bpdu_count += 1

        ts = _ts_to_epoch(entry.get("ts")) or 0.0
        session._stp_timestamps.append(ts)
        _update_time_range(session, ts)

        # Source MAC of the switch sending this BPDU
        src_mac = entry.get("src_mac", "")
        if src_mac:
            session.stp_src_macs[src_mac] += 1
            session._stp_per_port_ts[src_mac].append(ts)

        # Protocol version
        version = entry.get("version")
        if version is not None:
            version_name = {0: "STP", 2: "RSTP", 3: "MSTP"}.get(version, f"v{version}")
            session.stp_version_counts[version_name] += 1

        # BPDU type
        bpdu_type = entry.get("bpdu_type", "")
        if bpdu_type == "TCN":
            session.stp_tcn_count += 1
            session.stp_tcn_events.append(ts)

        # Flags (pre-decoded by Zeek script)
        if entry.get("tc", False):
            session.stp_tc_flag_count += 1
            session.stp_tc_events.append(ts)
        if entry.get("tca", False):
            session.stp_tca_count += 1
        if entry.get("proposal", False):
            session.stp_proposal_count += 1
        if entry.get("agreement", False):
            session.stp_agreement_count += 1

        # Port role
        port_role = entry.get("port_role", "Unknown")
        if port_role:
            session.stp_port_roles[port_role] += 1

        # Port state from learning/forwarding flags
        learning = entry.get("learning", False)
        forwarding = entry.get("forwarding", False)
        if forwarding and learning:
            session.stp_port_states["Forwarding"] += 1
        elif learning:
            session.stp_port_states["Learning"] += 1
        elif not forwarding and not learning:
            session.stp_port_states["Blocking/Discarding"] += 1

        # Root bridge tracking (PVST+-aware: per-VLAN)
        root_prio = entry.get("root_priority")
        root_mac = entry.get("root_mac", "")
        if root_prio is not None and root_mac:
            root_key = f"{root_prio}:{root_mac}"
            session.stp_root_bridges[root_key].append(ts)
            # Detect root bridge changes within same VLAN
            root_vlan = root_prio & 0x0FFF
            prev_root = last_root_per_vlan.get(root_vlan)
            if prev_root and root_key != prev_root:
                session.stp_root_changes.append((ts, root_vlan, prev_root, root_key))
            last_root_per_vlan[root_vlan] = root_key

        # Bridge tracking + path cost
        bridge_prio = entry.get("bridge_priority")
        bridge_mac = entry.get("bridge_mac", "")
        if bridge_prio is not None and bridge_mac:
            bridge_key = f"{bridge_prio}:{bridge_mac}"
            session.stp_bridges[bridge_key] += 1
            path_cost = entry.get("root_path_cost")
            if path_cost is not None:
                session.stp_path_costs[bridge_key].append((ts, path_cost))

            # MAC mismatch detection (spoofing indicator)
            if src_mac and bridge_mac and src_mac.lower() != bridge_mac.lower():
                eth_base = src_mac.lower().rsplit(':', 1)[0]
                bpdu_base = bridge_mac.lower().rsplit(':', 1)[0]
                if eth_base != bpdu_base:
                    if len(session.stp_mac_mismatches) < 50:
                        session.stp_mac_mismatches.append((ts, src_mac, bridge_mac))

        # VLAN from System ID Extension (lower 12 bits of bridge priority)
        sys_id_ext = entry.get("bridge_sys_id_ext")
        if sys_id_ext and sys_id_ext > 0:
            session.stp_vlans[sys_id_ext] += 1

        # Port ID
        port_id = entry.get("port_id")
        if port_id is not None:
            session.stp_port_ids[f"0x{port_id:04x}"] += 1

        # Timers
        hello = entry.get("hello_time")
        if hello is not None:
            session.stp_timers["hello"][hello] += 1
        max_age = entry.get("max_age")
        if max_age is not None:
            session.stp_timers["max_age"][max_age] += 1
        fwd_delay = entry.get("forward_delay")
        if fwd_delay is not None:
            session.stp_timers["fwd_delay"][fwd_delay] += 1

    if count:
        session._stp_last_root_per_vlan = last_root_per_vlan
        # Detect BPDU starvation (gaps > max_age per source port)
        max_age = 20
        if session.stp_timers.get('max_age'):
            max_age = session.stp_timers['max_age'].most_common(1)[0][0] or 20
        for mac, timestamps in session._stp_per_port_ts.items():
            if len(timestamps) < 3:
                continue
            ts_sorted = sorted(timestamps)
            for i in range(1, len(ts_sorted)):
                gap = ts_sorted[i] - ts_sorted[i - 1]
                if gap > max_age:
                    session.stp_bpdu_gaps.append((mac, ts_sorted[i - 1], round(gap, 1)))
        logger.info("Parsed %d STP BPDUs from Zeek stp.log", count)


def _parse_cdp_log(path: Path, session) -> None:
    """Parse cdp.log — CDP neighbor identity from Zeek (if available).

    Expected fields: ts, src_mac, device_id, platform, port_id,
    software_version, mgmt_ip, capabilities, native_vlan, vtp_domain, duplex.
    """
    count = 0
    for entry in _read_zeek_json(path):
        count += 1
        session.cdp_frame_count += 1
        src_mac = entry.get("src_mac", "")
        if not src_mac:
            continue
        info = session.cdp_neighbors.get(src_mac, {})
        if entry.get("device_id"):
            info['device_id'] = entry["device_id"]
        if entry.get("platform"):
            info['platform'] = entry["platform"]
        if entry.get("port_id"):
            info['port_id'] = entry["port_id"]
        if entry.get("software_version"):
            raw_ver = entry["software_version"]
            info['software_version'] = raw_ver.split('\n')[0].strip()
        if entry.get("mgmt_ip"):
            info['mgmt_ip'] = entry["mgmt_ip"]
        if entry.get("capabilities"):
            info['capabilities'] = entry["capabilities"]
        if entry.get("native_vlan"):
            info['native_vlan'] = entry["native_vlan"]
        if entry.get("vtp_domain"):
            info['vtp_domain'] = entry["vtp_domain"]
        if entry.get("duplex"):
            info['duplex'] = entry["duplex"]
        session.cdp_neighbors[src_mac] = info
    if count:
        logger.info("Parsed %d CDP frames from Zeek cdp.log", count)


def _parse_lldp_log(path: Path, session) -> None:
    """Parse lldp.log — LLDP neighbor identity from Zeek (if available).

    Expected fields: ts, src_mac, system_name, system_desc, chassis_id,
    port_id, port_desc, mgmt_ip, capabilities.
    """
    count = 0
    for entry in _read_zeek_json(path):
        count += 1
        session.lldp_frame_count += 1
        src_mac = entry.get("src_mac", "")
        if not src_mac:
            continue
        info = session.lldp_neighbors.get(src_mac, {})
        if entry.get("system_name"):
            info['system_name'] = entry["system_name"]
        if entry.get("system_desc"):
            raw_desc = entry["system_desc"]
            info['system_desc'] = raw_desc.split('\n')[0].strip()
        if entry.get("chassis_id"):
            info['chassis_id'] = entry["chassis_id"]
        if entry.get("port_id"):
            info['port_id'] = entry["port_id"]
        if entry.get("port_desc"):
            info['port_desc'] = entry["port_desc"]
        if entry.get("mgmt_ip"):
            info['mgmt_ip'] = entry["mgmt_ip"]
        if entry.get("capabilities"):
            info['capabilities'] = entry["capabilities"]
        session.lldp_neighbors[src_mac] = info
    if count:
        logger.info("Parsed %d LLDP frames from Zeek lldp.log", count)


# ---------------------------------------------------------------------------
# OT / ICS dedicated protocol log parsers (icsnpp Zeek packages)
# ---------------------------------------------------------------------------
# Output format matches the ot_transactions entries produced by scapy/dpkt
# parsers so all downstream tools (pcap_threat_hunter, pcap_ai_analyzer)
# work identically.
# ---------------------------------------------------------------------------

def _ot_entry_base(entry: dict, protocol: str, port: int) -> Dict[str, Any]:
    """Build the base OT transaction dict matching scapy/dpkt format."""
    return {
        "protocol": protocol,
        "port": port,
        "src": entry.get("id.orig_h", ""),
        "dst": entry.get("id.resp_h", ""),
        "ts": _ts_to_epoch(entry.get("ts")),
    }


def _parse_modbus_log(path: Path, session) -> None:
    """Parse modbus.log — icsnpp-modbus Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    func, exception, track_address, request_len, response_len, unit_id, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "Modbus", 502)

        # Function code — icsnpp stores as string name or integer
        func_raw = entry.get("func", entry.get("function_code", ""))
        func_code: Optional[int] = None
        func_name: str = str(func_raw)

        if isinstance(func_raw, (int, float)):
            func_code = int(func_raw)
            func_name = _MODBUS_FUNC_NAMES.get(func_code, f"FC-{func_code}")
        elif isinstance(func_raw, str) and func_raw.strip():
            # icsnpp often stores the function name as a string
            # e.g. "READ_HOLDING_REGISTERS" or "READ_HOLDING_REGISTERS_EXCEPTION"
            func_name = func_raw

            # Strip _EXCEPTION suffix for lookup (still flag as exception separately)
            lookup_str = func_raw
            if lookup_str.upper().endswith("_EXCEPTION"):
                lookup_str = lookup_str[:-10]  # remove "_EXCEPTION"

            # Try to reverse-map to a numeric code
            normalized = lookup_str.lower().replace("_", " ")
            for code, name in _MODBUS_FUNC_NAMES.items():
                if name.lower() == normalized:
                    func_code = code
                    break

        ot["function_code"] = func_code
        ot["function_name"] = func_name
        ot["unit_id"] = _safe_int(entry.get("unit_id"))

        # Exception detection — from explicit field OR from _EXCEPTION suffix in func name
        exception_raw = entry.get("exception", "")
        has_exception_field = bool(exception_raw and exception_raw != "-")
        has_exception_suffix = isinstance(func_raw, str) and func_raw.upper().endswith("_EXCEPTION")
        ot["is_exception"] = has_exception_field or has_exception_suffix
        if has_exception_field:
            ot["exception_code"] = exception_raw
        elif has_exception_suffix:
            ot["exception_code"] = "EXCEPTION (from func name)"

        ot["is_write"] = func_code in _MODBUS_WRITE_FUNCS if func_code else False
        ot["is_diagnostic"] = func_code in _MODBUS_DIAG_FUNCS if func_code else False

        # Register address tracking (icsnpp-modbus provides this)
        track_addr = entry.get("track_address")
        if track_addr and track_addr != "-":
            ot["register_address"] = track_addr

        session.ot_transactions.append(ot)

    logger.info("Parsed Modbus log: %s", path.name)


def _parse_modbus_detailed_log(path: Path, session) -> None:
    """Parse modbus_detailed.log — register-level detail from icsnpp-modbus.

    Provides per-register read/write values. We merge notable entries
    into ot_transactions with register detail.
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "Modbus", 502)
        ot["function_code"] = _safe_int(entry.get("func", entry.get("function_code")))
        ot["function_name"] = str(entry.get("func", "detailed"))

        # Register-level detail
        ot["register_type"] = entry.get("register_type", "")
        ot["register_addr"] = _safe_int(entry.get("register_addr"))
        ot["register_value"] = entry.get("register_value")
        ot["is_write"] = ot["function_code"] in _MODBUS_WRITE_FUNCS if ot["function_code"] else False
        ot["is_diagnostic"] = False
        ot["is_exception"] = False

        session.ot_transactions.append(ot)


def _parse_dnp3_log(path: Path, session) -> None:
    """Parse dnp3.log — icsnpp-dnp3 Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    fc_request, fc_reply, iin, obj_type, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "DNP3", 20000)

        # Function code — icsnpp-dnp3 logs fc_request / fc_reply as strings
        fc_req = entry.get("fc_request", "")
        fc_rep = entry.get("fc_reply", "")
        func_str = fc_req or fc_rep or entry.get("function_code", "")

        func_code: Optional[int] = None
        func_name: str = str(func_str) if func_str else "Unknown"

        if isinstance(func_str, (int, float)):
            func_code = int(func_str)
            func_name = _DNP3_FUNC_NAMES.get(func_code, f"FC-{func_code}")
        elif isinstance(func_str, str) and func_str.strip():
            func_name = func_str
            for code, name in _DNP3_FUNC_NAMES.items():
                if name.lower() == func_str.lower().replace("_", " ").replace("-", " "):
                    func_code = code
                    break

        ot["function_code"] = func_code
        ot["function_name"] = func_name
        ot["is_write"] = func_code in _DNP3_WRITE_FUNCS if func_code else False
        ot["is_control"] = func_code in _DNP3_CONTROL_FUNCS if func_code else False

        # IIN (Internal Indications) — important for DNP3 health
        iin = entry.get("iin")
        if iin and iin != "-":
            ot["iin"] = iin

        # Object type / count
        obj_type = entry.get("obj_type", entry.get("object_type"))
        if obj_type and obj_type != "-":
            ot["object_type"] = obj_type

        session.ot_transactions.append(ot)

    logger.info("Parsed DNP3 log: %s", path.name)


def _parse_bacnet_log(path: Path, session) -> None:
    """Parse bacnet.log — icsnpp-bacnet Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    bvlc_function, pdu_type, pdu_service, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "BACnet", 47808)

        bvlc_func = entry.get("bvlc_function", "")
        pdu_type = entry.get("pdu_type", "")
        pdu_service = entry.get("pdu_service", "")

        func_name = pdu_service or pdu_type or bvlc_func or "Unknown"
        ot["function_name"] = func_name
        ot["function_code"] = None  # BACnet doesn't use numeric codes like Modbus
        ot["pdu_type"] = pdu_type
        ot["bvlc_function"] = bvlc_func
        ot["is_write"] = any(
            w in func_name.lower()
            for w in ("write", "create", "delete", "reinitialize")
        )
        ot["is_control"] = any(
            c in func_name.lower()
            for c in ("reinitialize", "device-communication-control", "restart")
        )

        # Object / property info
        obj_type = entry.get("object_type")
        if obj_type and obj_type != "-":
            ot["object_type"] = obj_type
        prop_id = entry.get("property_identifier", entry.get("property"))
        if prop_id and prop_id != "-":
            ot["property"] = prop_id

        session.ot_transactions.append(ot)

    logger.info("Parsed BACnet log: %s", path.name)


def _parse_s7comm_log(path: Path, session) -> None:
    """Parse s7comm.log / s7comm_plus.log — icsnpp-s7comm Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    rosctr, pdu_type, func_code, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "S7comm", 102)

        # PDU type / ROSCTR
        rosctr = entry.get("rosctr", entry.get("pdu_type"))
        pdu_type_int = _safe_int(rosctr)
        if pdu_type_int is not None:
            ot["pdu_type"] = _S7_PDU_NAMES.get(pdu_type_int, f"0x{pdu_type_int:02x}")
        else:
            ot["pdu_type"] = str(rosctr) if rosctr else "Unknown"

        # Function code
        func_raw = entry.get("func_code", entry.get("function_code", entry.get("parameter_code")))
        func_code = _safe_int(func_raw)
        if func_code is not None:
            ot["function"] = _S7_FUNC_NAMES.get(func_code, f"0x{func_code:02x}")
            ot["function_code"] = func_code
            ot["is_write"] = func_code in (5, 0x1B)
            ot["is_control"] = func_code in (0x28, 0x29)
        else:
            func_str = str(func_raw) if func_raw else ""
            ot["function"] = func_str
            ot["function_code"] = None
            ot["is_write"] = "write" in func_str.lower() or "download" in func_str.lower()
            ot["is_control"] = "stop" in func_str.lower() or "start" in func_str.lower()

        # Sub-function / item details
        sub_func = entry.get("sub_func_code", entry.get("item_area"))
        if sub_func and sub_func != "-":
            ot["sub_function"] = sub_func

        session.ot_transactions.append(ot)

    logger.info("Parsed S7comm log: %s", path.name)


def _parse_enip_log(path: Path, session) -> None:
    """Parse enip.log — icsnpp-enip Zeek package output.

    EtherNet/IP encapsulation layer.
    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    command, length, session_handle, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "EtherNet/IP-CIP", 44818)

        command = entry.get("command", entry.get("enip_command", ""))
        ot["function_name"] = str(command) if command else "Unknown"
        ot["function_code"] = _safe_int(entry.get("command_code"))
        ot["session_handle"] = entry.get("session_handle")
        ot["is_write"] = False
        ot["is_control"] = False

        session.ot_transactions.append(ot)

    logger.info("Parsed ENIP log: %s", path.name)


def _parse_cip_log(path: Path, session) -> None:
    """Parse cip.log / cip_identity.log — icsnpp-enip Zeek package.

    CIP (Common Industrial Protocol) layer inside EtherNet/IP.
    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    service, cip_class_id, cip_instance_id, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "EtherNet/IP-CIP", 44818)

        service = entry.get("service", "")
        service_code = _safe_int(entry.get("service_code"))
        ot["function_name"] = str(service) if service else "Unknown"
        ot["function_code"] = service_code

        class_id = entry.get("cip_class_id", entry.get("class_id"))
        instance_id = entry.get("cip_instance_id", entry.get("instance_id"))
        if class_id and class_id != "-":
            ot["class_id"] = class_id
        if instance_id and instance_id != "-":
            ot["instance_id"] = instance_id

        ot["is_write"] = any(
            w in str(service).lower() for w in ("set", "write", "reset", "create", "delete")
        )
        ot["is_control"] = any(
            c in str(service).lower() for c in ("reset", "stop", "start", "change")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed CIP log: %s", path.name)


def _parse_opcua_log(path: Path, session) -> None:
    """Parse opcua_binary.log — icsnpp-opcua-binary Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    msg_type, msg_size, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "OPC-UA", 4840)

        msg_type = entry.get("msg_type", entry.get("opcua_msg_type", ""))
        ot["function_name"] = str(msg_type) if msg_type else "Unknown"
        ot["function_code"] = None  # OPC-UA uses message types, not numeric FCs

        service = entry.get("service", entry.get("opcua_service", ""))
        if service and service != "-":
            ot["function_name"] = str(service)

        ot["is_write"] = any(
            w in str(service).lower() for w in ("write", "create", "delete", "call")
        )
        ot["is_control"] = any(
            c in str(service).lower() for c in ("call", "transfer", "close")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed OPC-UA log: %s", path.name)


def _parse_profinet_log(path: Path, session) -> None:
    """Parse profinet_io_cm.log — icsnpp-profinet-io-cm Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    operation, block_type, slot_number, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "PROFINET", 34964)

        operation = entry.get("operation", entry.get("pnio_operation", ""))
        ot["function_name"] = str(operation) if operation else "Unknown"
        ot["function_code"] = None

        block_type = entry.get("block_type", "")
        if block_type:
            ot["description"] = f"Block: {block_type}"

        ot["is_write"] = any(
            w in str(operation).lower() for w in ("write", "control", "connect")
        )
        ot["is_control"] = any(
            c in str(operation).lower()
            for c in ("control", "release", "abort", "param_end")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed PROFINET IO CM log: %s", path.name)


def _parse_ethercat_log(path: Path, session) -> None:
    """Parse ethercat.log — icsnpp-ethercat Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    cmd, slave_addr, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "EtherCAT", 34980)

        cmd = entry.get("cmd", entry.get("command", ""))
        ot["function_name"] = str(cmd) if cmd else "Unknown"
        ot["function_code"] = None

        slave_addr = entry.get("slave_addr", entry.get("slave_address", ""))
        if slave_addr:
            ot["description"] = f"Slave: {slave_addr}"

        # EtherCAT write commands
        ot["is_write"] = any(
            w in str(cmd).upper() for w in ("BWR", "AWR", "LWR", "FPRW", "APRW", "FPWR", "APWR")
        )
        ot["is_control"] = any(
            c in str(cmd).upper() for c in ("BWR", "LWR", "INIT", "PREOP", "SAFEOP", "OP")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed EtherCAT log: %s", path.name)


def _parse_hart_ip_log(path: Path, session) -> None:
    """Parse hart_ip.log — icsnpp-hart-ip Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    command, device_status, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "HART-IP", 5094)

        command = entry.get("command", entry.get("hart_command", ""))
        ot["function_name"] = str(command) if command else "Unknown"
        try:
            ot["function_code"] = int(command)
        except (ValueError, TypeError):
            ot["function_code"] = None

        device_status = entry.get("device_status", "")
        if device_status:
            ot["description"] = f"Status: {device_status}"

        # HART write commands (command numbers for writes)
        ot["is_write"] = any(
            w in str(command).lower()
            for w in ("write", "set", "configure", "trim")
        )
        ot["is_control"] = "reset" in str(command).lower()

        session.ot_transactions.append(ot)

    logger.info("Parsed HART-IP log: %s", path.name)


def _parse_bsap_log(path: Path, session) -> None:
    """Parse bsap_ip.log — icsnpp-bsap Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    func_code, type_name, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "BSAP", 1234)

        func_code = entry.get("func_code", entry.get("app_func_code", ""))
        type_name = entry.get("type_name", entry.get("msg_type", ""))
        ot["function_name"] = str(type_name) if type_name else str(func_code)
        try:
            ot["function_code"] = int(func_code)
        except (ValueError, TypeError):
            ot["function_code"] = None

        ot["is_write"] = any(
            w in str(type_name).lower()
            for w in ("write", "download", "transmit")
        )
        ot["is_control"] = any(
            c in str(type_name).lower()
            for c in ("control", "reset", "abort", "initialize")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed BSAP log: %s", path.name)


def _parse_genisys_log(path: Path, session) -> None:
    """Parse genisys.log — icsnpp-genisys Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    header, server, direction, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "Genisys", 10001)

        header = entry.get("header", "")
        direction = entry.get("direction", "")
        ot["function_name"] = str(header) if header else "Data"
        ot["function_code"] = None

        if direction:
            ot["description"] = f"Direction: {direction}"

        ot["is_write"] = "write" in str(header).lower()
        ot["is_control"] = any(
            c in str(header).lower() for c in ("control", "command")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed Genisys log: %s", path.name)


def _parse_ge_srtp_log(path: Path, session) -> None:
    """Parse ge_srtp.log — icsnpp-ge-srtp Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    service_request_code, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "GE-SRTP", 18245)

        svc_code = entry.get("service_request_code",
                             entry.get("service_code", ""))
        ot["function_name"] = str(svc_code) if svc_code else "Unknown"
        try:
            ot["function_code"] = int(svc_code)
        except (ValueError, TypeError):
            ot["function_code"] = None

        ot["is_write"] = any(
            w in str(svc_code).lower()
            for w in ("write", "store", "download", "program")
        )
        ot["is_control"] = any(
            c in str(svc_code).lower()
            for c in ("start", "stop", "init", "reset", "run", "halt")
        )
        ot["is_diagnostic"] = "status" in str(svc_code).lower()

        session.ot_transactions.append(ot)

    logger.info("Parsed GE-SRTP log: %s", path.name)


def _parse_c1222_log(path: Path, session) -> None:
    """Parse c1222.log — icsnpp-c1222 Zeek package (ANSI C12.22 Smart Meter).

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    service, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "C12.22", 1153)

        service = entry.get("service", entry.get("acse_service", ""))
        ot["function_name"] = str(service) if service else "Unknown"
        ot["function_code"] = None

        ot["is_write"] = any(
            w in str(service).lower()
            for w in ("write", "program", "logon")
        )
        ot["is_control"] = any(
            c in str(service).lower()
            for c in ("disconnect", "terminate", "logoff")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed C12.22 log: %s", path.name)


def _parse_synchrophasor_log(path: Path, session) -> None:
    """Parse synchrophasor.log — icsnpp-synchrophasor Zeek package (C37.118).

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    frame_type, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "Synchrophasor", 4712)

        frame_type = entry.get("frame_type", entry.get("frameType", ""))
        ot["function_name"] = str(frame_type) if frame_type else "Data"
        ot["function_code"] = None

        # Frame types: data, header, cfg1, cfg2, cfg3, cmd
        ot["is_write"] = False
        ot["is_control"] = "cmd" in str(frame_type).lower()

        session.ot_transactions.append(ot)

    logger.info("Parsed Synchrophasor log: %s", path.name)


def _parse_omron_fins_log(path: Path, session) -> None:
    """Parse omron_fins.log — icsnpp-omron-fins Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    command_code, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "Omron-FINS", 9600)

        cmd_code = entry.get("command_code", entry.get("icf_command", ""))
        ot["function_name"] = str(cmd_code) if cmd_code else "Unknown"
        try:
            ot["function_code"] = int(cmd_code, 16) if isinstance(cmd_code, str) else int(cmd_code)
        except (ValueError, TypeError):
            ot["function_code"] = None

        # Omron FINS write/control command codes
        ot["is_write"] = any(
            w in str(cmd_code).lower()
            for w in ("write", "0102", "transfer")
        )
        ot["is_control"] = any(
            c in str(cmd_code).lower()
            for c in ("run", "stop", "reset", "0401", "0402")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed Omron FINS log: %s", path.name)


def _parse_roc_plus_log(path: Path, session) -> None:
    """Parse roc_plus.log — icsnpp-roc-plus Zeek package (Emerson ROC).

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    opcode, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "ROC-Plus", 4000)

        opcode = entry.get("opcode", entry.get("type_code", ""))
        ot["function_name"] = str(opcode) if opcode else "Unknown"
        try:
            ot["function_code"] = int(opcode)
        except (ValueError, TypeError):
            ot["function_code"] = None

        ot["is_write"] = any(
            w in str(opcode).lower()
            for w in ("write", "set", "store", "download")
        )
        ot["is_control"] = any(
            c in str(opcode).lower()
            for c in ("reset", "restart", "cold_start")
        )

        session.ot_transactions.append(ot)

    logger.info("Parsed ROC-Plus log: %s", path.name)


# ---------------------------------------------------------------------------
# IT / Security protocol log parsers
# ---------------------------------------------------------------------------

def _parse_kerberos_log(path: Path, session) -> None:
    """Parse kerberos.log — Zeek built-in Kerberos analyzer.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    request_type, client, service, success, error_msg, cipher, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        session.kerberos_tickets.append({
            "src": id_info.get("orig_h", ""),
            "dst": id_info.get("resp_h", ""),
            "client": entry.get("client", ""),
            "service": entry.get("service", ""),
            "request_type": entry.get("request_type", ""),
            "cipher": entry.get("cipher", ""),
            "success": entry.get("success", ""),
            "error_msg": entry.get("error_msg", ""),
            "ts": ts,
        })
    logger.info("Parsed Kerberos log: %d tickets from %s", len(session.kerberos_tickets), path.name)


def _parse_smb_mapping_log(path: Path, session) -> None:
    """Parse smb_mapping.log — Zeek SMB tree connect/disconnect.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    path, share_type, native_file_system, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        share_path = entry.get("path", "")
        session.smb_mappings.append({
            "src": id_info.get("orig_h", ""),
            "dst": id_info.get("resp_h", ""),
            "share": share_path,
            "share_type": entry.get("share_type", ""),
            "ts": ts,
        })
    logger.info("Parsed SMB mapping log: %d entries from %s", len(session.smb_mappings), path.name)


def _parse_smb_files_log(path: Path, session) -> None:
    """Parse smb_files.log — Zeek SMB file operations.

    Fields: ts, uid, id.orig_h, id.resp_h, action, path, name, size, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        session.smb_files.append({
            "src": id_info.get("orig_h", ""),
            "dst": id_info.get("resp_h", ""),
            "action": entry.get("action", ""),
            "name": entry.get("name", ""),
            "path": entry.get("path", ""),
            "size": _safe_int(entry.get("size")),
            "ts": ts,
        })
    logger.info("Parsed SMB files log: %d entries from %s", len(session.smb_files), path.name)


def _parse_dce_rpc_log(path: Path, session) -> None:
    """Parse dce_rpc.log — Zeek DCE/RPC analyzer.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    rtt, named_pipe, endpoint, operation, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        session.dce_rpc_calls.append({
            "src": id_info.get("orig_h", ""),
            "dst": id_info.get("resp_h", ""),
            "endpoint": entry.get("endpoint", ""),
            "operation": entry.get("operation", ""),
            "named_pipe": entry.get("named_pipe", ""),
            "ts": ts,
        })
    logger.info("Parsed DCE/RPC log: %d calls from %s", len(session.dce_rpc_calls), path.name)


def _parse_syslog_log(path: Path, session) -> None:
    """Parse syslog.log — Zeek syslog analyzer (summary stats only).

    Fields: ts, uid, id.orig_h, id.resp_h, proto, facility, severity, message
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        src = id_info.get("orig_h", "")

        session.syslog_total += 1
        session.syslog_sources[src] += 1

        sev = entry.get("severity")
        if sev is not None and sev != "-":
            sev_int = _safe_int(sev)
            if sev_int is not None:
                session.syslog_severity[sev_int] += 1

        fac = entry.get("facility")
        if fac is not None and fac != "-":
            fac_int = _safe_int(fac)
            if fac_int is not None:
                session.syslog_facilities[fac_int] += 1

        msg = entry.get("message", "")
        if msg and msg != "-":
            msg_lower = msg.lower()
            if any(w in msg_lower for w in ("fail", "denied", "invalid", "reject", "unauthorized")):
                session.syslog_patterns["auth_failure"] += 1
            if any(w in msg_lower for w in ("config", "changed", "modified", "reload")):
                session.syslog_patterns["config_change"] += 1
            if any(w in msg_lower for w in ("up", "down", "link ")):
                session.syslog_patterns["interface_state"] += 1
            if any(w in msg_lower for w in ("login", "logged in", "session open")):
                session.syslog_patterns["login_event"] += 1
            if any(w in msg_lower for w in ("blocked", "drop", "firewall")):
                session.syslog_patterns["firewall_event"] += 1

    logger.info("Parsed syslog log: %d messages from %s", session.syslog_total, path.name)


def _parse_ldap_log(path: Path, session) -> None:
    """Parse ldap.log — Zeek LDAP analyzer (requires zeek-ldap plugin).

    Fields: ts, uid, id.orig_h, id.resp_h, message_type,
    base_object, result_code, result, diagnostic_message, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        session.ldap_operations.append({
            "src": id_info.get("orig_h", ""),
            "dst": id_info.get("resp_h", ""),
            "message_type": entry.get("message_type", entry.get("operation", "")),
            "base_object": entry.get("base_object", entry.get("object", "")),
            "result": entry.get("result", entry.get("result_code", "")),
            "ts": ts,
        })
    logger.info("Parsed LDAP log: %d operations from %s", len(session.ldap_operations), path.name)


def _parse_ntlm_log(path: Path, session) -> None:
    """Parse ntlm.log — Zeek NTLM analyzer.

    Fields: ts, uid, id.orig_h, id.resp_h, username, hostname,
    domainname, success, status, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        session.ntlm_auths.append({
            "src": id_info.get("orig_h", ""),
            "dst": id_info.get("resp_h", ""),
            "hostname": entry.get("hostname", ""),
            "domain": entry.get("domainname", entry.get("domain", "")),
            "username": entry.get("username", ""),
            "success": entry.get("success", ""),
            "ts": ts,
        })
    logger.info("Parsed NTLM log: %d auths from %s", len(session.ntlm_auths), path.name)


def _parse_ssh_log(path: Path, session) -> None:
    """Parse ssh.log — Zeek SSH analyzer.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    version, auth_success, auth_attempts, direction, client, server, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        banner_parts = []
        client = entry.get("client", "")
        server = entry.get("server", "")
        if client and client != "-":
            banner_parts.append(f"client={client}")
        if server and server != "-":
            banner_parts.append(f"server={server}")
        session.ssh_sessions.append({
            "src": id_info.get("orig_h", ""),
            "dst": id_info.get("resp_h", ""),
            "src_port": _safe_int(id_info.get("orig_p")) or 0,
            "ts": ts,
            "banner": "; ".join(banner_parts) if banner_parts else "",
            "auth_success": entry.get("auth_success", ""),
            "auth_attempts": _safe_int(entry.get("auth_attempts")),
            "version": _safe_int(entry.get("version")),
        })
    logger.info("Parsed SSH log: %d sessions from %s", len(session.ssh_sessions), path.name)


def _parse_snmp_log(path: Path, session) -> None:
    """Parse snmp.log — Zeek SNMP analyzer.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    duration, version, community, get_requests, get_bulk_requests,
    get_responses, set_requests, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)
        id_info = entry.get("id", {})
        src = id_info.get("orig_h", "")
        session.snmp_sources[src] += 1
        community = entry.get("community", "")
        if community and community != "-":
            session.snmp_communities[community] += 1
    logger.info("Parsed SNMP log from %s", path.name)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(val) -> Optional[int]:
    """Convert a value to int, returning None on failure."""
    if val is None or val == "-" or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Network discovery: ARP and DHCP log parsing for subnet inference
# ---------------------------------------------------------------------------


def _parse_arp_log_networks(path: Path, session) -> None:
    """Parse arp.log for network evidence.

    Zeek's arp.log (if present) has fields:
      ts, src_mac, dst_mac, src_addr (IP), dst_addr (IP), who_has, is_at, operation

    We use ARP request/reply IPs to infer broadcast domains. IPs that ARP
    for each other are on the same L2 segment (same subnet).
    """
    arp_ips: set = set()
    count = 0
    for entry in _read_zeek_json(path):
        count += 1
        src_addr = entry.get("src_addr") or entry.get("orig_h", "")
        dst_addr = entry.get("dst_addr") or entry.get("who_has", "")
        if src_addr and src_addr != "0.0.0.0":
            arp_ips.add(src_addr)
        if dst_addr and dst_addr != "0.0.0.0":
            arp_ips.add(dst_addr)

    # Group ARP IPs into inferred subnets based on common /24
    import ipaddress
    seen_nets: set = set()
    for ip_str in arp_ips:
        try:
            iface = ipaddress.IPv4Interface(f"{ip_str}/24")
            net_key = str(iface.network)
            if net_key not in seen_nets:
                seen_nets.add(net_key)
                session.network_evidence.append({
                    "network": str(iface.network.network_address),
                    "mask": 24,
                    "source": "arp",
                    "evidence": f"ARP activity in {net_key} ({count} ARP frames)",
                    "confidence": "medium",
                })
        except Exception:
            pass

    if count:
        logger.info("Parsed ARP log for network discovery: %d frames, %d IPs", count, len(arp_ips))


def _parse_dhcp_log_networks(path: Path, session) -> None:
    """Parse dhcp.log for explicit subnet mask evidence.

    Zeek's dhcp.log fields include:
      ts, uids, client_addr, server_addr, mac, host_name, assigned_addr,
      lease_time, subnet_mask, ...

    The subnet_mask field gives us authoritative subnet information.
    """
    import ipaddress
    count = 0
    for entry in _read_zeek_json(path):
        subnet_mask = entry.get("subnet_mask", "")
        assigned_addr = entry.get("assigned_addr", "")
        msg_types = entry.get("msg_types", [])

        # Only trust Offer/ACK (not Request/Discover)
        is_server_response = False
        if isinstance(msg_types, list):
            is_server_response = any(t in ("OFFER", "ACK") for t in msg_types)
        elif isinstance(msg_types, str):
            is_server_response = "OFFER" in msg_types or "ACK" in msg_types

        if subnet_mask and assigned_addr and assigned_addr != "0.0.0.0" and is_server_response:
            try:
                mask_int = int(ipaddress.IPv4Address(subnet_mask))
                prefix_len = bin(mask_int).count('1')
                iface = ipaddress.IPv4Interface(f"{assigned_addr}/{prefix_len}")
                net_str = str(iface.network.network_address)
                session.network_evidence.append({
                    "network": net_str,
                    "mask": prefix_len,
                    "source": "dhcp",
                    "evidence": f"DHCP mask={subnet_mask} for {assigned_addr}",
                    "confidence": "high",
                })
                count += 1
            except Exception:
                pass

    if count:
        logger.info("Parsed DHCP log for network discovery: %d subnet assignments", count)
