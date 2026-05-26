"""
PCAP Metadata Summary — Load, parse, and summarize network captures.

Faithful port of Event Mill v1.0 tools/pcap_parser.py.
All modes operate on a module-level PcapSession singleton shared
across every network-forensics plugin in the same process.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import ipaddress
import atexit
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("eventmill.plugins.pcap_metadata_summary")

MAX_PCAP_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB

# RFC 1918 private ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_internal(ip_str: str) -> bool:
    """Check if an IP is in RFC1918 private ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Result types (match framework protocol)
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field


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
# PcapSession — singleton holding ALL parsed state (matches event_mill v1)
# ---------------------------------------------------------------------------

class PcapSession:
    """Stores parsed PCAP metadata for hunt queries.

    Mirrors event_mill v1 PcapSession exactly so all downstream
    tools (threat hunter, AI analyzer, report correlator) work
    identically.
    """

    def __init__(self) -> None:
        self.filename: str = ""
        self.file_path: str = ""
        self._temp_path: Optional[str] = None
        self.file_size: int = 0
        self.packet_count: int = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        # Conversations: (src, dst, dport, proto) -> stats
        self.conversations: Dict[
            Tuple[str, str, int, str], Dict
        ] = defaultdict(lambda: {
            "packets": 0,
            "bytes_out": 0,
            "bytes_in": 0,
            "first_seen": None,
            "last_seen": None,
            "timestamps": [],
        })

        # Port counters
        self.dst_ports: Counter = Counter()
        self.src_ports: Counter = Counter()
        self.port_proto: Dict[int, str] = {}

        # Protocol distribution
        self.protocols: Counter = Counter()

        # DNS records
        self.dns_queries: List[Dict] = []
        self.dns_responses: List[Dict] = []

        # HTTP transactions
        self.http_requests: List[Dict] = []

        # TLS metadata
        self.tls_handshakes: List[Dict] = []

        # OT / ICS protocol transactions
        self.ot_transactions: List[Dict] = []

        # Cleartext credential detections (values are redacted)
        self.cleartext_creds: List[Dict] = []

        # Unique IPs
        self.src_ips: Counter = Counter()
        self.dst_ips: Counter = Counter()

        # --- Netops / infrastructure health attributes ---

        # TCP health counters
        self.tcp_retransmissions: int = 0
        self.tcp_rst_count: int = 0
        self.tcp_syn_count: int = 0
        self.tcp_fin_count: int = 0
        self.tcp_zero_window_count: int = 0

        # Per-conversation health: (src, dst, dport, proto) -> {rst, retransmit, zero_window}
        self.conv_health: Dict[Tuple[str, str, int, str], Dict] = defaultdict(
            lambda: {"rst": 0, "retransmit": 0, "zero_window": 0}
        )

        # ICMP errors
        self.icmp_errors: List[Dict] = []

        # Routing loop detection
        self.ttl_exceeded_by_dest: Dict[str, List[Dict]] = defaultdict(list)
        self.suspected_loop_packets: List[Dict] = []

        # ARP health
        self.arp_request_count: int = 0
        self.arp_reply_count: int = 0
        self.arp_gratuitous_count: int = 0
        self._arp_timestamps: List[float] = []
        self.arp_requests_by_src: Counter = Counter()
        self.arp_ip_to_macs: Dict[str, set] = defaultdict(set)
        self._arp_request_targets: Counter = Counter()
        self._arp_reply_targets: Counter = Counter()

        # Control plane — STP
        self.stp_bpdu_count: int = 0
        self.stp_tcn_count: int = 0
        self.stp_tc_flag_count: int = 0
        self.stp_root_bridges: Dict[str, List] = defaultdict(list)
        self._stp_timestamps: List[float] = []
        self.stp_bridges: Counter = Counter()

        # Control plane — HSRP
        self.hsrp_hello_count: int = 0
        self.hsrp_events: List[Dict] = []
        self.hsrp_state_changes: List[Dict] = []

        # Control plane — VRRP
        self.vrrp_advert_count: int = 0
        self.vrrp_events: List[Dict] = []
        self.vrrp_priority_changes: List[Dict] = []

        # Control plane — OSPF
        self.ospf_total_count: int = 0
        self.ospf_hello_count: int = 0
        self.ospf_dbd_count: int = 0
        self.ospf_lsrequest_count: int = 0
        self.ospf_lsupdate_count: int = 0
        self.ospf_lsack_count: int = 0
        self.ospf_areas: set = set()
        self.ospf_router_ids: set = set()
        self.ospf_neighbor_hellos: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._ospf_lsupdate_timestamps: List[float] = []

        # Control plane — EIGRP
        self.eigrp_total_count: int = 0
        self.eigrp_hello_count: int = 0
        self.eigrp_update_count: int = 0
        self.eigrp_query_count: int = 0
        self.eigrp_reply_count: int = 0
        self.eigrp_as_numbers: set = set()

        # IP fragmentation & TTL
        self.ip_fragment_count: int = 0
        self.ttl_distribution: Counter = Counter()

    @property
    def unique_ips(self) -> set:
        """All unique IPs seen (src + dst)."""
        return set(self.src_ips.keys()) | set(self.dst_ips.keys())

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def duration_str(self) -> str:
        secs = self.duration_seconds
        if secs < 60:
            return f"{secs:.1f}s"
        if secs < 3600:
            return f"{secs / 60:.1f}min"
        return f"{secs / 3600:.1f}hrs"


# ---------------------------------------------------------------------------
# Process-global session storage — survives module reimport / loader aliasing
# ---------------------------------------------------------------------------
# The plugin loader imports this file as 'eventmill_plugin_network_forensics_
# pcap_metadata_summary' while the shell imports it via the normal package path.
# A module-level global would be invisible across those two sys.modules entries.
# Storing the session on 'sys' makes it truly process-wide.

if not hasattr(sys, '_eventmill_pcap_sessions'):
    sys._eventmill_pcap_sessions = {}  # type: ignore[attr-defined]


def get_pcap_session() -> Optional[PcapSession]:
    """Return the active PcapSession (process-global)."""
    return sys._eventmill_pcap_sessions.get('active')  # type: ignore[attr-defined]


def set_pcap_session(session: Optional[PcapSession]) -> None:
    """Store the active PcapSession (process-global)."""
    sys._eventmill_pcap_sessions['active'] = session  # type: ignore[attr-defined]


def _cleanup_pcap_temp():
    """Clean up any temporary PCAP files on exit."""
    s = get_pcap_session()
    if s and getattr(s, "_temp_path", None):
        try:
            if os.path.exists(s._temp_path):
                os.unlink(s._temp_path)
        except OSError:
            pass


atexit.register(_cleanup_pcap_temp)


def _format_bytes(n: int) -> str:
    """Human-readable byte sizes."""
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KB"
    if n < 1024**3:
        return f"{n / (1024**2):.1f} MB"
    return f"{n / (1024**3):.1f} GB"


def _format_duration(secs: float) -> str:
    if secs < 60:
        return f"{secs:.1f}s"
    if secs < 3600:
        return f"{secs / 60:.1f}min"
    return f"{secs / 3600:.1f}hrs"


# ---------------------------------------------------------------------------
# Scapy import with IPv6 monkey-patch (mirrors event_mill v1)
# ---------------------------------------------------------------------------

SCAPY_AVAILABLE = False
SCAPY_TLS_AVAILABLE = False

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Monkey-patch scapy to handle missing IPv6 'scope' key in
    # containers with limited network namespaces (Cloud Run, Docker).
    import scapy.arch
    _orig_read_routes6 = getattr(scapy.arch, "read_routes6", None)
    if _orig_read_routes6:
        def _safe_read_routes6():
            try:
                return _orig_read_routes6()
            except KeyError:
                return []
        scapy.arch.read_routes6 = _safe_read_routes6

    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True

    try:
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
        from scapy.layers.tls.extensions import ServerName
        SCAPY_TLS_AVAILABLE = True
    except Exception:
        TLS = None
        TLSClientHello = None
        TLSServerHello = None
        ServerName = None
        SCAPY_TLS_AVAILABLE = False
except Exception as e:
    logger.warning("scapy not available: %s — PCAP parsing disabled", e)


# ---------------------------------------------------------------------------
# Core parser (streaming, packet-by-packet) — identical to event_mill v1
# ---------------------------------------------------------------------------

def parse_pcap_file(file_path: str) -> PcapSession:
    """Parse a PCAP file using scapy streaming PcapReader."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for PCAP parsing. Install with: pip install scapy")

    session = PcapSession()
    session.filename = os.path.basename(file_path)
    session.file_path = file_path
    session.file_size = os.path.getsize(file_path)

    _seen_ip_ids: Dict[Tuple[str, str, int, int], int] = {}  # (src, dst, proto, ip_id) -> ttl

    with PcapReader(file_path) as reader:
        for pkt in reader:
            session.packet_count += 1
            ts = float(pkt.time)

            if session.start_time is None or ts < session.start_time:
                session.start_time = ts
            if session.end_time is None or ts > session.end_time:
                session.end_time = ts

            # --- ARP extraction (L2, before IP check) ---
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if arp.op == 1:  # request
                    session.arp_request_count += 1
                    session._arp_timestamps.append(ts)
                    psrc_mac = arp.hwsrc if hasattr(arp, 'hwsrc') else ""
                    if psrc_mac:
                        session.arp_requests_by_src[psrc_mac] += 1
                    target_ip = arp.pdst if hasattr(arp, 'pdst') else ""
                    if target_ip:
                        session._arp_request_targets[target_ip] += 1
                    src_ip_arp = arp.psrc if hasattr(arp, 'psrc') else ""
                    if src_ip_arp and psrc_mac:
                        session.arp_ip_to_macs[src_ip_arp].add(psrc_mac)
                    # Gratuitous ARP: src == target
                    if src_ip_arp and target_ip and src_ip_arp == target_ip:
                        session.arp_gratuitous_count += 1
                elif arp.op == 2:  # reply
                    session.arp_reply_count += 1
                    session._arp_timestamps.append(ts)
                    src_ip_arp = arp.psrc if hasattr(arp, 'psrc') else ""
                    psrc_mac = arp.hwsrc if hasattr(arp, 'hwsrc') else ""
                    if src_ip_arp:
                        session._arp_reply_targets[src_ip_arp] += 1
                    if src_ip_arp and psrc_mac:
                        session.arp_ip_to_macs[src_ip_arp].add(psrc_mac)

            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_len = len(pkt)

            session.src_ips[src_ip] += 1
            session.dst_ips[dst_ip] += 1

            # --- IP fragmentation & TTL ---
            if ip_layer.frag > 0 or (ip_layer.flags & 0x1):  # MF flag or offset
                session.ip_fragment_count += 1
            ttl = ip_layer.ttl
            session.ttl_distribution[ttl] += 1

            # Duplicate packet / loop detection via IP ID
            ip_id = ip_layer.id
            if ip_id != 0:
                loop_key = (src_ip, dst_ip, ip_layer.proto, ip_id)
                if loop_key in _seen_ip_ids:
                    prev_ttl = _seen_ip_ids[loop_key]
                    if prev_ttl != ttl:
                        session.suspected_loop_packets.append({
                            "src": src_ip, "dst": dst_ip,
                            "proto": "TCP" if ip_layer.proto == 6 else "UDP" if ip_layer.proto == 17 else "OTHER",
                            "ip_id": ip_id, "ttl": ttl, "prev_ttls": [prev_ttl],
                        })
                _seen_ip_ids[loop_key] = ttl

            # Protocol & ports
            proto = "OTHER"
            sport = 0
            dport = 0

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                tcp_flags = pkt[TCP].flags
                if tcp_flags & 0x02:  # SYN
                    session.tcp_syn_count += 1
                if tcp_flags & 0x01:  # FIN
                    session.tcp_fin_count += 1
                if tcp_flags & 0x04:  # RST
                    session.tcp_rst_count += 1
                if pkt[TCP].window == 0:
                    session.tcp_zero_window_count += 1
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            session.protocols[proto] += 1

            if dport:
                session.dst_ports[dport] += 1
                session.port_proto[dport] = proto
            if sport:
                session.src_ports[sport] += 1

            # Conversation tracking
            conv_key = (src_ip, dst_ip, dport, proto)
            conv = session.conversations[conv_key]
            conv["packets"] += 1
            conv["bytes_out"] += pkt_len
            if conv["first_seen"] is None or ts < conv["first_seen"]:
                conv["first_seen"] = ts
            if conv["last_seen"] is None or ts > conv["last_seen"]:
                conv["last_seen"] = ts
            if len(conv["timestamps"]) < 2000:
                conv["timestamps"].append(ts)

            # DNS extraction
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace")
                    qname = qname.rstrip(".")
                    session.dns_queries.append({
                        "query": qname, "type": pkt[DNSQR].qtype,
                        "src": src_ip, "ts": ts,
                    })
                elif dns.qr == 1 and pkt.haslayer(DNSRR):
                    qname = ""
                    if pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="replace")
                        qname = qname.rstrip(".")
                    rdata = pkt[DNSRR].rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", errors="replace")
                    session.dns_responses.append({
                        "query": qname, "answer": str(rdata),
                        "type": pkt[DNSRR].type, "src": src_ip, "ts": ts,
                    })

            # HTTP extraction
            if pkt.haslayer(HTTPRequest):
                req = pkt[HTTPRequest]
                method = req.Method.decode("utf-8", errors="replace") if isinstance(req.Method, bytes) else str(req.Method)
                path = req.Path.decode("utf-8", errors="replace") if isinstance(req.Path, bytes) else str(req.Path)
                host = req.Host.decode("utf-8", errors="replace") if isinstance(req.Host, bytes) else str(req.Host)
                session.http_requests.append({
                    "method": method, "host": host, "path": path,
                    "src": src_ip, "dst": dst_ip, "ts": ts,
                })

            # TLS Client Hello extraction
            if SCAPY_TLS_AVAILABLE and pkt.haslayer(TLS):
                try:
                    if pkt.haslayer(TLSClientHello):
                        ch = pkt[TLSClientHello]
                        sni = ""
                        if hasattr(ch, "ext") and ch.ext:
                            for ext in ch.ext:
                                if hasattr(ext, "servernames"):
                                    for sn in ext.servernames:
                                        name = sn.servername
                                        if isinstance(name, bytes):
                                            name = name.decode("utf-8", errors="replace")
                                        sni = name
                                        break
                        session.tls_handshakes.append({
                            "type": "ClientHello", "sni": sni,
                            "src": src_ip, "dst": dst_ip,
                            "dport": dport, "ts": ts,
                        })
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # OT / ICS protocol extraction (port-based heuristic)
            # ---------------------------------------------------------------
            _extract_ot_transaction(pkt, session, src_ip, dst_ip, sport, dport, proto, ts)

            # ---------------------------------------------------------------
            # Cleartext credential detection (redacted values)
            # ---------------------------------------------------------------
            _extract_cleartext_creds(pkt, session, src_ip, dst_ip, dport, ts)

            # ---------------------------------------------------------------
            # Netops: TCP conversation health (RST / retransmit per conv)
            # ---------------------------------------------------------------
            if proto == "TCP":
                tcp_flags = pkt[TCP].flags
                if tcp_flags & 0x04:  # RST
                    session.conv_health[conv_key]["rst"] += 1
                if pkt[TCP].window == 0:
                    session.conv_health[conv_key]["zero_window"] += 1

            # ---------------------------------------------------------------
            # Netops: ICMP error extraction
            # ---------------------------------------------------------------
            if proto == "ICMP":
                icmp_layer = pkt[ICMP]
                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code
                _ICMP_DESCS = {
                    (3, 0): "Destination network unreachable",
                    (3, 1): "Destination host unreachable",
                    (3, 3): "Destination port unreachable",
                    (3, 4): "Fragmentation needed (DF set)",
                    (3, 13): "Communication administratively prohibited",
                    (11, 0): "TTL exceeded in transit",
                    (11, 1): "Fragment reassembly time exceeded",
                    (5, 0): "Redirect for network",
                    (5, 1): "Redirect for host",
                }
                desc = _ICMP_DESCS.get((icmp_type, icmp_code))
                if desc is None and icmp_type in (3, 5, 11):
                    desc = f"ICMP type={icmp_type} code={icmp_code}"
                if desc:
                    session.icmp_errors.append({
                        "type": icmp_type, "code": icmp_code,
                        "description": desc,
                        "src": src_ip, "dst": dst_ip, "ts": ts,
                    })
                # TTL exceeded tracking for loop detection
                if icmp_type == 11:
                    session.ttl_exceeded_by_dest[dst_ip].append({
                        "router": src_ip, "original_src": dst_ip,
                        "ts": ts,
                    })

    return session


# ---------------------------------------------------------------------------
# dpkt-based fast parser (--fast mode) — 5-10x faster than scapy
# ---------------------------------------------------------------------------

DPKT_AVAILABLE = False
try:
    import dpkt
    import socket
    import struct
    DPKT_AVAILABLE = True
except ImportError:
    dpkt = None  # type: ignore[assignment]


def parse_pcap_file_dpkt(file_path: str) -> PcapSession:
    """Parse a PCAP file using dpkt (fast, C-backed struct unpacking).

    Produces an identical PcapSession to ``parse_pcap_file`` but runs
    5-10x faster on large captures (>100 MB / >500K packets).
    """
    if not DPKT_AVAILABLE:
        raise RuntimeError("dpkt is required for --fast mode. Install with: pip install dpkt")

    _build_cred_patterns()

    session = PcapSession()
    session.filename = os.path.basename(file_path)
    session.file_path = file_path
    session.file_size = os.path.getsize(file_path)

    def _ip_to_str(packed: bytes) -> str:
        return socket.inet_ntoa(packed)

    _seen_ip_ids_dpkt: Dict[Tuple[str, str, int, int], int] = {}

    with open(file_path, "rb") as f:
        try:
            reader: Any = dpkt.pcap.Reader(f)
        except ValueError:
            # Try pcapng format
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for ts, buf in reader:
            session.packet_count += 1

            if session.start_time is None or ts < session.start_time:
                session.start_time = ts
            if session.end_time is None or ts > session.end_time:
                session.end_time = ts

            # Parse Ethernet frame
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            # --- ARP extraction (L2, before IP check) ---
            if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                try:
                    arp = dpkt.arp.ARP(bytes(eth.data))
                    psrc_ip = socket.inet_ntoa(arp.spa)
                    pdst_ip = socket.inet_ntoa(arp.tpa)
                    psrc_mac = ':'.join(f'{b:02x}' for b in arp.sha)
                    if arp.op == 1:  # request
                        session.arp_request_count += 1
                        session._arp_timestamps.append(ts)
                        session.arp_requests_by_src[psrc_mac] += 1
                        session._arp_request_targets[pdst_ip] += 1
                        session.arp_ip_to_macs[psrc_ip].add(psrc_mac)
                        if psrc_ip == pdst_ip:
                            session.arp_gratuitous_count += 1
                    elif arp.op == 2:  # reply
                        session.arp_reply_count += 1
                        session._arp_timestamps.append(ts)
                        session._arp_reply_targets[psrc_ip] += 1
                        session.arp_ip_to_macs[psrc_ip].add(psrc_mac)
                except Exception:
                    pass

            # Only process IPv4
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            src_ip = _ip_to_str(ip.src)
            dst_ip = _ip_to_str(ip.dst)
            pkt_len = len(buf)

            session.src_ips[src_ip] += 1
            session.dst_ips[dst_ip] += 1

            # --- IP fragmentation & TTL ---
            if ip.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK):
                session.ip_fragment_count += 1
            session.ttl_distribution[ip.ttl] += 1

            # Duplicate packet / loop detection via IP ID
            if ip.id != 0:
                loop_key = (src_ip, dst_ip, ip.p, ip.id)
                if loop_key in _seen_ip_ids_dpkt:
                    prev_ttl = _seen_ip_ids_dpkt[loop_key]
                    if prev_ttl != ip.ttl:
                        session.suspected_loop_packets.append({
                            "src": src_ip, "dst": dst_ip,
                            "proto": "TCP" if ip.p == 6 else "UDP" if ip.p == 17 else "OTHER",
                            "ip_id": ip.id, "ttl": ip.ttl, "prev_ttls": [prev_ttl],
                        })
                _seen_ip_ids_dpkt[loop_key] = ip.ttl

            # Protocol & ports
            proto = "OTHER"
            sport = 0
            dport = 0
            tcp_data = b""

            if isinstance(ip.data, dpkt.tcp.TCP):
                proto = "TCP"
                tcp_obj = ip.data
                sport = tcp_obj.sport
                dport = tcp_obj.dport
                tcp_data = bytes(tcp_obj.data)
                # TCP flag tracking
                if tcp_obj.flags & dpkt.tcp.TH_SYN:
                    session.tcp_syn_count += 1
                if tcp_obj.flags & dpkt.tcp.TH_FIN:
                    session.tcp_fin_count += 1
                if tcp_obj.flags & dpkt.tcp.TH_RST:
                    session.tcp_rst_count += 1
                if tcp_obj.win == 0:
                    session.tcp_zero_window_count += 1
            elif isinstance(ip.data, dpkt.udp.UDP):
                proto = "UDP"
                udp_obj = ip.data
                sport = udp_obj.sport
                dport = udp_obj.dport
                tcp_data = bytes(udp_obj.data)  # reuse var for payload
            elif ip.p == 1:  # ICMP
                proto = "ICMP"

            session.protocols[proto] += 1

            if dport:
                session.dst_ports[dport] += 1
                session.port_proto[dport] = proto
            if sport:
                session.src_ports[sport] += 1

            # Conversation tracking
            conv_key = (src_ip, dst_ip, dport, proto)
            conv = session.conversations[conv_key]
            conv["packets"] += 1
            conv["bytes_out"] += pkt_len
            if conv["first_seen"] is None or ts < conv["first_seen"]:
                conv["first_seen"] = ts
            if conv["last_seen"] is None or ts > conv["last_seen"]:
                conv["last_seen"] = ts
            if len(conv["timestamps"]) < 2000:
                conv["timestamps"].append(ts)

            # DNS extraction
            if dport == 53 or sport == 53:
                try:
                    dns = dpkt.dns.DNS(tcp_data)
                    if dns.qr == dpkt.dns.DNS_Q:  # query
                        for q in dns.qd:
                            qname = q.name.rstrip(".")
                            session.dns_queries.append({
                                "query": qname, "type": q.type,
                                "src": src_ip, "ts": ts,
                            })
                    elif dns.qr == dpkt.dns.DNS_R:  # response
                        qname = dns.qd[0].name.rstrip(".") if dns.qd else ""
                        for rr in dns.an:
                            rdata = ""
                            if rr.type == dpkt.dns.DNS_A:
                                try:
                                    rdata = _ip_to_str(rr.rdata)
                                except Exception:
                                    rdata = repr(rr.rdata)
                            elif rr.type == dpkt.dns.DNS_CNAME:
                                rdata = rr.cname if hasattr(rr, "cname") else str(rr.rdata)
                            else:
                                rdata = str(rr.rdata)
                            session.dns_responses.append({
                                "query": qname, "answer": rdata,
                                "type": rr.type, "src": src_ip, "ts": ts,
                            })
                except Exception:
                    pass

            # HTTP extraction (port 80 or payload starts with HTTP method)
            if tcp_data and (dport == 80 or sport == 80 or dport == 8080):
                try:
                    if tcp_data[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"):
                        req = dpkt.http.Request(tcp_data)
                        session.http_requests.append({
                            "method": req.method, "host": req.headers.get("host", ""),
                            "path": req.uri, "src": src_ip, "dst": dst_ip, "ts": ts,
                        })
                except Exception:
                    pass

            # TLS ClientHello / SNI extraction
            if tcp_data and len(tcp_data) > 5 and tcp_data[0] == 0x16:
                try:
                    tls_records = dpkt.ssl.TLSRecord(tcp_data)
                    # ClientHello: handshake type 1
                    if (hasattr(tls_records, "data") and len(tls_records.data) > 0
                            and tls_records.data[0] == 1):
                        sni = _extract_sni_from_client_hello(tls_records.data)
                        session.tls_handshakes.append({
                            "type": "ClientHello", "sni": sni,
                            "src": src_ip, "dst": dst_ip,
                            "dport": dport, "ts": ts,
                        })
                except Exception:
                    pass

            # OT / ICS protocol extraction (port-based, same logic)
            _extract_ot_transaction_dpkt(
                session, src_ip, dst_ip, sport, dport, proto, ts, tcp_data,
            )

            # Cleartext credential detection
            _extract_cleartext_creds_dpkt(
                session, src_ip, dst_ip, sport, dport, ts, tcp_data,
            )

            # ---------------------------------------------------------------
            # Netops: TCP conversation health (RST / retransmit per conv)
            # ---------------------------------------------------------------
            if proto == "TCP":
                if tcp_obj.flags & dpkt.tcp.TH_RST:
                    session.conv_health[conv_key]["rst"] += 1
                if tcp_obj.win == 0:
                    session.conv_health[conv_key]["zero_window"] += 1

            # ---------------------------------------------------------------
            # Netops: ICMP error extraction
            # ---------------------------------------------------------------
            if proto == "ICMP" and isinstance(ip.data, dpkt.icmp.ICMP):
                icmp_obj = ip.data
                icmp_type = icmp_obj.type
                icmp_code = icmp_obj.code
                _ICMP_DESCS_DPKT = {
                    (3, 0): "Destination network unreachable",
                    (3, 1): "Destination host unreachable",
                    (3, 3): "Destination port unreachable",
                    (3, 4): "Fragmentation needed (DF set)",
                    (3, 13): "Communication administratively prohibited",
                    (11, 0): "TTL exceeded in transit",
                    (11, 1): "Fragment reassembly time exceeded",
                    (5, 0): "Redirect for network",
                    (5, 1): "Redirect for host",
                }
                desc = _ICMP_DESCS_DPKT.get((icmp_type, icmp_code))
                if desc is None and icmp_type in (3, 5, 11):
                    desc = f"ICMP type={icmp_type} code={icmp_code}"
                if desc:
                    session.icmp_errors.append({
                        "type": icmp_type, "code": icmp_code,
                        "description": desc,
                        "src": src_ip, "dst": dst_ip, "ts": ts,
                    })
                if icmp_type == 11:
                    session.ttl_exceeded_by_dest[dst_ip].append({
                        "router": src_ip, "original_src": dst_ip,
                        "ts": ts,
                    })

    return session


def _extract_sni_from_client_hello(handshake_data: bytes) -> str:
    """Extract SNI from a TLS ClientHello handshake payload."""
    try:
        # Skip handshake header (1 type + 3 length)
        if len(handshake_data) < 44:
            return ""
        offset = 4  # skip type + length
        # Skip client version (2) + random (32) = 34
        offset += 34
        # Session ID length
        if offset >= len(handshake_data):
            return ""
        sid_len = handshake_data[offset]
        offset += 1 + sid_len
        # Cipher suites length (2 bytes)
        if offset + 2 > len(handshake_data):
            return ""
        cs_len = struct.unpack("!H", handshake_data[offset:offset + 2])[0]
        offset += 2 + cs_len
        # Compression methods length (1 byte)
        if offset >= len(handshake_data):
            return ""
        cm_len = handshake_data[offset]
        offset += 1 + cm_len
        # Extensions length (2 bytes)
        if offset + 2 > len(handshake_data):
            return ""
        ext_len = struct.unpack("!H", handshake_data[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", handshake_data[offset:offset + 2])[0]
            ext_data_len = struct.unpack("!H", handshake_data[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == 0 and ext_data_len > 5:  # SNI extension
                # Server Name List length (2), type (1), name length (2), name
                sni_offset = offset + 3  # skip list_len + type
                if sni_offset + 2 <= offset + ext_data_len:
                    name_len = struct.unpack("!H", handshake_data[sni_offset:sni_offset + 2])[0]
                    sni_offset += 2
                    if sni_offset + name_len <= len(handshake_data):
                        return handshake_data[sni_offset:sni_offset + name_len].decode("ascii", errors="replace")
            offset += ext_data_len
    except Exception:
        pass
    return ""


def _extract_ot_transaction_dpkt(
    session: PcapSession,
    src_ip: str, dst_ip: str,
    sport: int, dport: int, proto: str, ts: float,
    payload: bytes,
) -> None:
    """Extract OT/ICS protocol metadata (dpkt version — uses raw bytes directly)."""
    ot_port = 0
    ot_proto = ""
    if dport in _OT_PORT_PROTOCOL:
        ot_port = dport
        ot_proto = _OT_PORT_PROTOCOL[dport]
    elif sport in _OT_PORT_PROTOCOL:
        ot_port = sport
        ot_proto = _OT_PORT_PROTOCOL[sport]
    else:
        return

    entry: Dict[str, Any] = {
        "protocol": ot_proto, "port": ot_port,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": sport, "dst_port": dport,
        "ts": ts,
    }

    raw = payload

    if ot_proto == "Modbus" and proto == "TCP" and len(raw) >= 8:
        try:
            unit_id = raw[6]
            func_code = raw[7]
            is_exception = bool(func_code & 0x80)
            base_func = func_code & 0x7F
            entry["unit_id"] = unit_id
            entry["function_code"] = base_func
            entry["function_name"] = _MODBUS_FUNC_NAMES.get(base_func, f"FC-{base_func}")
            entry["is_exception"] = is_exception
            entry["is_write"] = base_func in _MODBUS_WRITE_FUNCS
            entry["is_diagnostic"] = base_func in _MODBUS_DIAG_FUNCS
            if is_exception and len(raw) >= 9:
                entry["exception_code"] = raw[8]
        except Exception:
            pass

    if ot_proto == "S7comm" and proto == "TCP":
        try:
            s7_idx = raw.find(b'\x32')
            if s7_idx >= 0 and s7_idx + 2 < len(raw):
                pdu_type = raw[s7_idx + 1]
                pdu_names = {1: "Job", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}
                entry["pdu_type"] = pdu_names.get(pdu_type, f"0x{pdu_type:02x}")
                if s7_idx + 8 < len(raw):
                    func = raw[s7_idx + 7] if pdu_type in (1, 3) else None
                    if func is not None:
                        s7_funcs = {
                            4: "Read", 5: "Write", 0x28: "PLC-Stop",
                            0x29: "PLC-Start", 0x1A: "Upload", 0x1B: "Download",
                        }
                        entry["function"] = s7_funcs.get(func, f"0x{func:02x}")
                        entry["is_write"] = func in (5, 0x1B)
                        entry["is_control"] = func in (0x28, 0x29)
        except Exception:
            pass

    if ot_proto == "DNP3" and proto == "TCP":
        try:
            if len(raw) >= 12 and raw[0:2] == b'\x05\x64':
                if len(raw) > 13:
                    func_code = raw[13]
                    dnp3_funcs = {
                        0: "Confirm", 1: "Read", 2: "Write",
                        3: "Select", 4: "Operate", 5: "Direct-Operate",
                        13: "Cold-Restart", 14: "Warm-Restart",
                        18: "Stop-Application", 19: "Start-Application",
                        129: "Response", 130: "Unsolicited-Response",
                    }
                    entry["function_code"] = func_code
                    entry["function_name"] = dnp3_funcs.get(func_code, f"FC-{func_code}")
                    entry["is_write"] = func_code in (2, 3, 4, 5)
                    entry["is_control"] = func_code in (5, 13, 14, 18, 19)
        except Exception:
            pass

    if len(session.ot_transactions) < 50000:
        session.ot_transactions.append(entry)


def _extract_cleartext_creds_dpkt(
    session: PcapSession,
    src_ip: str, dst_ip: str,
    sport: int, dport: int, ts: float,
    payload: bytes,
) -> None:
    """Detect cleartext credentials from raw payload bytes (dpkt version)."""
    if not payload or len(payload) < 4:
        return
    if len(session.cleartext_creds) >= 500:
        return

    for proto_name, ports, pattern, description in _CRED_PATTERNS:
        if ports is not None and dport not in ports and sport not in ports:
            continue
        if pattern is None:
            session.cleartext_creds.append({
                "protocol": proto_name, "description": description,
                "src": src_ip, "dst": dst_ip,
                "port": dport if (ports and dport in ports) else sport,
                "ts": ts,
            })
            return
        if pattern.search(payload):
            session.cleartext_creds.append({
                "protocol": proto_name, "description": description,
                "src": src_ip, "dst": dst_ip, "port": dport, "ts": ts,
            })
            return


# ---------------------------------------------------------------------------
# OT / ICS protocol port map
# ---------------------------------------------------------------------------

_OT_PORT_PROTOCOL: Dict[int, str] = {
    502: "Modbus",
    102: "S7comm",
    44818: "EtherNet/IP-CIP",
    20000: "DNP3",
    4840: "OPC-UA",
    47808: "BACnet",
    2404: "IEC-104",
    789: "Red-Lion",
    1911: "Niagara-Fox",
    9600: "OMRON-FINS",
    18245: "GE-SRTP",
}

# Modbus function code names
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


def _extract_ot_transaction(
    pkt: Any, session: "PcapSession",
    src_ip: str, dst_ip: str,
    sport: int, dport: int, proto: str, ts: float,
) -> None:
    """Extract OT/ICS protocol metadata from a packet via port heuristics."""
    # Determine if either port matches a known OT service
    ot_port = 0
    ot_proto = ""
    if dport in _OT_PORT_PROTOCOL:
        ot_port = dport
        ot_proto = _OT_PORT_PROTOCOL[dport]
    elif sport in _OT_PORT_PROTOCOL:
        ot_port = sport
        ot_proto = _OT_PORT_PROTOCOL[sport]
    else:
        return

    entry: Dict[str, Any] = {
        "protocol": ot_proto,
        "port": ot_port,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sport,
        "dst_port": dport,
        "ts": ts,
    }

    # Attempt deeper Modbus parsing from raw payload
    if ot_proto == "Modbus" and proto == "TCP":
        try:
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                # Modbus/TCP: 7-byte MBAP header + at least 1 byte PDU
                if len(raw) >= 8:
                    unit_id = raw[6]
                    func_code = raw[7]
                    is_exception = bool(func_code & 0x80)
                    base_func = func_code & 0x7F
                    entry["unit_id"] = unit_id
                    entry["function_code"] = base_func
                    entry["function_name"] = _MODBUS_FUNC_NAMES.get(base_func, f"FC-{base_func}")
                    entry["is_exception"] = is_exception
                    entry["is_write"] = base_func in _MODBUS_WRITE_FUNCS
                    entry["is_diagnostic"] = base_func in _MODBUS_DIAG_FUNCS
                    if is_exception and len(raw) >= 9:
                        entry["exception_code"] = raw[8]
        except Exception:
            pass

    # S7comm — extract PDU type from TPKT/COTP payload
    if ot_proto == "S7comm" and proto == "TCP":
        try:
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                # Look for S7comm magic 0x32 after TPKT(4)+COTP(variable)
                s7_idx = raw.find(b'\x32')
                if s7_idx >= 0 and s7_idx + 2 < len(raw):
                    pdu_type = raw[s7_idx + 1]
                    pdu_names = {1: "Job", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}
                    entry["pdu_type"] = pdu_names.get(pdu_type, f"0x{pdu_type:02x}")
                    if s7_idx + 8 < len(raw):
                        func = raw[s7_idx + 7] if pdu_type in (1, 3) else None
                        if func is not None:
                            s7_funcs = {
                                4: "Read", 5: "Write", 0x28: "PLC-Stop",
                                0x29: "PLC-Start", 0x1A: "Upload", 0x1B: "Download",
                            }
                            entry["function"] = s7_funcs.get(func, f"0x{func:02x}")
                            entry["is_write"] = func in (5, 0x1B)
                            entry["is_control"] = func in (0x28, 0x29)
        except Exception:
            pass

    # DNP3 — extract function code from transport/application layer
    if ot_proto == "DNP3" and proto == "TCP":
        try:
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                # DNP3 starts with 0x0564
                if len(raw) >= 12 and raw[0:2] == b'\x05\x64':
                    # Application layer function code at offset 12+
                    if len(raw) > 12:
                        app_ctrl = raw[12] if len(raw) > 12 else None
                        if app_ctrl is not None and len(raw) > 13:
                            func_code = raw[13]
                            dnp3_funcs = {
                                0: "Confirm", 1: "Read", 2: "Write",
                                3: "Select", 4: "Operate", 5: "Direct-Operate",
                                13: "Cold-Restart", 14: "Warm-Restart",
                                18: "Stop-Application", 19: "Start-Application",
                                129: "Response", 130: "Unsolicited-Response",
                            }
                            entry["function_code"] = func_code
                            entry["function_name"] = dnp3_funcs.get(func_code, f"FC-{func_code}")
                            entry["is_write"] = func_code in (2, 3, 4, 5)
                            entry["is_control"] = func_code in (5, 13, 14, 18, 19)
        except Exception:
            pass

    # Cap stored OT transactions at 50,000 to limit memory
    if len(session.ot_transactions) < 50000:
        session.ot_transactions.append(entry)


# ---------------------------------------------------------------------------
# Cleartext credential patterns (values are REDACTED for safety)
# ---------------------------------------------------------------------------

import re as _re

_CRED_PATTERNS: List[tuple] = [
    # (protocol, port_set, compiled_regex_on_payload, description)
]

# Built lazily on first call
_CRED_PATTERNS_BUILT = False


def _build_cred_patterns() -> None:
    global _CRED_PATTERNS, _CRED_PATTERNS_BUILT
    if _CRED_PATTERNS_BUILT:
        return
    _CRED_PATTERNS = [
        ("FTP", {21}, _re.compile(rb'^(USER |PASS )', _re.IGNORECASE), "FTP login command"),
        ("Telnet", {23}, _re.compile(rb'(login:|password:|username:)', _re.IGNORECASE), "Telnet login prompt"),
        # HTTP Basic Auth / Form — match on ANY port (services run on 15672, 9200, 8161, etc.)
        ("HTTP-BasicAuth", None, _re.compile(rb'Authorization:\s*Basic\s+', _re.IGNORECASE), "HTTP Basic Auth header"),
        ("HTTP-FormPost", None, _re.compile(rb'(password=|passwd=|pwd=|user=|username=|login=)', _re.IGNORECASE), "HTTP form credential field"),
        ("SMTP", {25, 587}, _re.compile(rb'^(AUTH LOGIN|AUTH PLAIN)', _re.IGNORECASE), "SMTP authentication"),
        ("SNMPv1/v2c", {161, 162}, None, "SNMP community string (unauthenticated)"),
        ("LDAP-SimpleBind", {389}, _re.compile(rb'\x80.{0,4}(\x04)', _re.DOTALL), "LDAP simple bind"),
        ("POP3", {110}, _re.compile(rb'^(USER |PASS )', _re.IGNORECASE), "POP3 login"),
        ("IMAP", {143}, _re.compile(rb'LOGIN\s+', _re.IGNORECASE), "IMAP LOGIN command"),
        ("VNC", {5900, 5901, 5902}, None, "VNC authentication handshake"),
    ]
    _CRED_PATTERNS_BUILT = True


def _extract_cleartext_creds(
    pkt: Any, session: "PcapSession",
    src_ip: str, dst_ip: str,
    dport: int, ts: float,
) -> None:
    """Detect cleartext credentials in packet payloads. Values are REDACTED."""
    if not pkt.haslayer(Raw):
        return

    _build_cred_patterns()

    try:
        raw_payload = bytes(pkt[Raw].load)
    except Exception:
        return

    if len(raw_payload) < 4:
        return

    # Cap stored detections at 500
    if len(session.cleartext_creds) >= 500:
        return

    sport = 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport

    for proto_name, ports, pattern, description in _CRED_PATTERNS:
        # ports=None means match any port (pattern-only detection like HTTP Basic Auth)
        if ports is not None and dport not in ports and sport not in ports:
            continue
        # For SNMP and VNC, any traffic on the port is flagged (no pattern needed)
        if pattern is None:
            session.cleartext_creds.append({
                "protocol": proto_name,
                "description": description,
                "src": src_ip,
                "dst": dst_ip,
                "port": dport if (ports and dport in ports) else sport,
                "ts": ts,
            })
            return
        if pattern.search(raw_payload):
            session.cleartext_creds.append({
                "protocol": proto_name,
                "description": description,
                "src": src_ip,
                "dst": dst_ip,
                "port": dport,
                "ts": ts,
            })
            return


# ---------------------------------------------------------------------------
# GCS download helper
# ---------------------------------------------------------------------------

def _get_bucket_name(context: Any, pillar_slug: str) -> Optional[str]:
    """Derive bucket name from context config or env."""
    prefix = os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
    return f"{prefix}-{pillar_slug}"


def _download_from_gcs(file_path: str, context: Any) -> Optional[str]:
    """Try to download a file from GCS. Returns local path or None."""
    try:
        from google.cloud import storage as gcs_storage
    except ImportError:
        return None

    client = gcs_storage.Client()
    filename = os.path.basename(file_path)

    # Try pillar bucket first, then common bucket
    prefix = os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
    buckets_to_try = [f"{prefix}-network-forensics", f"{prefix}-common"]
    if file_path.startswith("gs://"):
        parts = file_path.replace("gs://", "").split("/", 1)
        buckets_to_try = [parts[0]]
        filename = parts[1] if len(parts) > 1 else parts[0]

    for bucket_name in buckets_to_try:
        try:
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(filename)
            if not blob.exists():
                continue
            blob.reload()
            if blob.size and blob.size > MAX_PCAP_SIZE_BYTES:
                logger.warning("File %s too large (%s)", filename, _format_bytes(blob.size))
                return None
            tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            blob.download_to_filename(tmp.name)
            tmp.close()
            logger.info("Downloaded %s from gs://%s/%s", filename, bucket_name, filename)
            return tmp.name
        except Exception as exc:
            logger.debug("Bucket %s: %s", bucket_name, exc)
            continue

    return None


# ---------------------------------------------------------------------------
# File resolution (filesystem → artifact registry → workspace → GCS)
# ---------------------------------------------------------------------------

def _resolve_file(file_path: str, context: Any) -> Optional[str]:
    """Resolve a file path through multiple fallback layers."""
    # 1. Direct filesystem
    if os.path.exists(file_path):
        return file_path

    filename = os.path.basename(file_path)

    # 2. Artifact registry
    if hasattr(context, "artifacts"):
        for art in context.artifacts:
            if os.path.basename(art.file_path) == filename and os.path.exists(art.file_path):
                return art.file_path

    # 3. Workspace artifacts directory
    workspace = os.environ.get("EVENTMILL_WORKSPACE", "/workspace")
    candidates = [
        os.path.join(workspace, "artifacts", filename),
        os.path.join(workspace, filename),
    ]
    for cand in candidates:
        if os.path.exists(cand):
            return cand

    # 4. GCS download
    local = _download_from_gcs(file_path, context)
    if local:
        return local

    return None


# =========================================================================
# EventMillToolProtocol implementation
# =========================================================================

class PcapMetadataSummary:
    """Load, parse, and summarize PCAP network captures.

    Modes: load, summary, conversations, dns, http, tls, timeline, ioc
    """

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_metadata_summary",
            "version": "1.0.0",
            "pillar": "network_forensics",
            "description": "Load, parse, and summarize PCAP network captures.",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        mode = payload.get("mode", "load")
        valid_modes = ("load", "summary", "conversations", "dns", "http", "tls", "timeline", "ioc")
        if mode not in valid_modes:
            errors.append(f"Invalid mode '{mode}'. Must be one of: {', '.join(valid_modes)}")
        if mode == "load" and "file_path" not in payload:
            errors.append("'file_path' is required for load mode")
        elif mode not in ("load",):
            if get_pcap_session() is None:
                errors.append(f"No PCAP loaded. Use mode 'load' first before '{mode}'.")
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        mode = payload.get("mode", "load")
        try:
            if mode == "load":
                return self._load_pcap(payload, context)
            elif mode == "summary":
                return self._summary()
            elif mode == "conversations":
                return self._conversations(payload)
            elif mode == "dns":
                return self._dns_summary(payload)
            elif mode == "http":
                return self._http_summary(payload)
            elif mode == "tls":
                return self._tls_summary()
            elif mode == "timeline":
                return self._timeline(payload)
            elif mode == "ioc":
                return self._ioc_search(payload)
            else:
                return ToolResult(ok=False, error_code="INVALID_MODE", message=f"Unknown mode: {mode}")
        except Exception as e:
            logger.error("PCAP error: %s", e, exc_info=True)
            return ToolResult(ok=False, error_code="EXECUTION_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"Error: {result.message}"
        if not result.result:
            return "No result data."
        return result.result.get("text", str(result.result))

    # ----- load -----
    def _load_pcap(self, payload: dict[str, Any], context: Any) -> ToolResult:
        if not SCAPY_AVAILABLE:
            return ToolResult(ok=False, error_code="MISSING_DEP", message="scapy not installed")

        file_path = payload["file_path"]
        resolved = _resolve_file(file_path, context)
        if not resolved:
            return ToolResult(ok=False, error_code="FILE_NOT_FOUND", message=f"File not found: {file_path}")

        fsize = os.path.getsize(resolved)
        if fsize > MAX_PCAP_SIZE_BYTES:
            return ToolResult(ok=False, error_code="FILE_TOO_LARGE", message=f"File ({_format_bytes(fsize)}) exceeds 50 MB limit")

        # Clean up previous temp
        old = get_pcap_session()
        if old and getattr(old, "_temp_path", None):
            try:
                if os.path.exists(old._temp_path):
                    os.unlink(old._temp_path)
            except OSError:
                pass

        set_pcap_session(parse_pcap_file(resolved))

        s = get_pcap_session()
        lines = []
        lines.append("✅ PCAP Loaded Successfully")
        lines.append("")
        lines.append(f"  File:      {s.filename}")
        lines.append(f"  Size:      {_format_bytes(s.file_size)}")
        lines.append(f"  Packets:   {s.packet_count:,}")
        lines.append(f"  Duration:  {s.duration_str}")
        if s.start_time:
            t0 = datetime.utcfromtimestamp(s.start_time)
            t1 = datetime.utcfromtimestamp(s.end_time)
            lines.append(f"  Time:      {t0:%Y-%m-%d %H:%M:%S} → {t1:%H:%M:%S} UTC")
        lines.append(f"  Unique Src IPs:  {len(s.src_ips)}")
        lines.append(f"  Unique Dst IPs:  {len(s.dst_ips)}")
        lines.append("")
        lines.append("  Protocols:")
        for proto, cnt in s.protocols.most_common(10):
            lines.append(f"    {proto:<8} {cnt:>8,} packets")
        lines.append("")
        lines.append(f"  Conversations:   {len(s.conversations):,}")
        lines.append(f"  DNS queries:     {len(s.dns_queries):,}")
        lines.append(f"  HTTP requests:   {len(s.http_requests):,}")
        lines.append(f"  TLS handshakes:  {len(s.tls_handshakes):,}")
        if s.ot_transactions:
            ot_protos = Counter(t["protocol"] for t in s.ot_transactions)
            lines.append("")
            lines.append("  OT/ICS Protocols:")
            for p, c in ot_protos.most_common():
                lines.append(f"    {p:<16} {c:>6,} transactions")
        if s.cleartext_creds:
            lines.append(f"")
            lines.append(f"  ⚠️  Cleartext credentials detected: {len(s.cleartext_creds)}")

        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- summary -----
    def _summary(self) -> ToolResult:
        s = get_pcap_session()
        lines = []
        lines.append("=== PCAP Summary ===")
        lines.append(f"  File:      {s.filename}")
        lines.append(f"  Size:      {_format_bytes(s.file_size)}")
        lines.append(f"  Packets:   {s.packet_count:,}")
        lines.append(f"  Duration:  {s.duration_str}")
        if s.start_time:
            t0 = datetime.utcfromtimestamp(s.start_time)
            t1 = datetime.utcfromtimestamp(s.end_time)
            lines.append(f"  Time:      {t0:%Y-%m-%d %H:%M:%S} → {t1:%H:%M:%S} UTC")
        lines.append("")
        lines.append("  Protocols:")
        for proto, cnt in s.protocols.most_common(10):
            pct = cnt / s.packet_count * 100 if s.packet_count else 0
            lines.append(f"    {proto:<8} {cnt:>8,} pkts  ({pct:.1f}%)")
        lines.append("")
        lines.append(f"  Unique Src IPs:    {len(s.src_ips)}")
        lines.append(f"  Unique Dst IPs:    {len(s.dst_ips)}")
        lines.append(f"  Conversations:     {len(s.conversations):,}")
        lines.append(f"  DNS queries:       {len(s.dns_queries):,}")
        lines.append(f"  HTTP requests:     {len(s.http_requests):,}")
        lines.append(f"  TLS handshakes:    {len(s.tls_handshakes):,}")
        if s.ot_transactions:
            lines.append("")
            lines.append("  OT/ICS Protocols:")
            ot_protos = Counter(t["protocol"] for t in s.ot_transactions)
            for p, c in ot_protos.most_common():
                lines.append(f"    {p:<16} {c:>6,} transactions")
            # Write vs read breakdown for protocols that support it
            writes = [t for t in s.ot_transactions if t.get("is_write")]
            controls = [t for t in s.ot_transactions if t.get("is_control")]
            exceptions = [t for t in s.ot_transactions if t.get("is_exception")]
            if writes:
                lines.append(f"    ⚠️  Write operations:   {len(writes):,}")
            if controls:
                lines.append(f"    🔴 Control commands:   {len(controls):,}")
            if exceptions:
                lines.append(f"    ⚠️  Exception responses: {len(exceptions):,}")
        if s.cleartext_creds:
            lines.append("")
            lines.append(f"  ⚠️  CLEARTEXT CREDENTIALS: {len(s.cleartext_creds)} detection(s)")
            cred_protos = Counter(c["protocol"] for c in s.cleartext_creds)
            for p, c in cred_protos.most_common():
                lines.append(f"    {p:<20} {c:>4} occurrence(s)")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- conversations -----
    def _conversations(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        top_n = payload.get("top_n", 20)
        sort_by = payload.get("sort_by", "bytes")

        convs = []
        for (src, dst, dport, proto), stats in s.conversations.items():
            duration = 0
            if stats["first_seen"] and stats["last_seen"]:
                duration = stats["last_seen"] - stats["first_seen"]
            convs.append({
                "src": src, "dst": dst, "dport": dport, "proto": proto,
                "packets": stats["packets"], "bytes_out": stats["bytes_out"],
                "first": stats["first_seen"], "last": stats["last_seen"],
                "duration": duration,
            })

        if sort_by == "packets":
            convs.sort(key=lambda c: c["packets"], reverse=True)
        elif sort_by == "duration":
            convs.sort(key=lambda c: c["duration"], reverse=True)
        else:
            convs.sort(key=lambda c: c["bytes_out"], reverse=True)

        lines = []
        lines.append(f"=== Top {top_n} Conversations (by {sort_by}) ===")
        lines.append(f"{'#':<4} {'Source':<18} {'Destination':<18} {'Port':<7} {'Proto':<6} {'Bytes':<10} {'Pkts':<8} {'Duration':<10} {'Dir'}")
        lines.append("-" * 95)
        for i, c in enumerate(convs[:top_n], 1):
            src_int = "INT" if is_internal(c["src"]) else "EXT"
            dst_int = "INT" if is_internal(c["dst"]) else "EXT"
            direction = f"{src_int}→{dst_int}"
            dur = f"{c['duration']:.1f}s" if c["duration"] < 60 else f"{c['duration'] / 60:.1f}m"
            lines.append(f"{i:<4} {c['src']:<18} {c['dst']:<18} {c['dport']:<7} {c['proto']:<6} {_format_bytes(c['bytes_out']):<10} {c['packets']:<8,} {dur:<10} {direction}")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- dns -----
    def _dns_summary(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        top_n = payload.get("top_n", 30)

        if not s.dns_queries and not s.dns_responses:
            return ToolResult(ok=True, result={"text": "No DNS activity found in PCAP."})

        domain_counts: Counter = Counter()
        domain_sources: Dict[str, set] = defaultdict(set)
        for q in s.dns_queries:
            domain_counts[q["query"]] += 1
            domain_sources[q["query"]].add(q["src"])

        domain_answers: Dict[str, set] = defaultdict(set)
        for r in s.dns_responses:
            if r["query"]:
                domain_answers[r["query"]].add(r["answer"])

        lines = []
        lines.append(f"=== DNS Activity ({len(s.dns_queries)} queries, {len(s.dns_responses)} responses) ===")
        lines.append(f"{'#':<4} {'Domain':<40} {'Queries':<9} {'Sources':<9} {'Resolved To'}")
        lines.append("-" * 90)
        for i, (domain, cnt) in enumerate(domain_counts.most_common(top_n), 1):
            sources = len(domain_sources[domain])
            answers = ", ".join(list(domain_answers.get(domain, set()))[:3])
            if len(domain_answers.get(domain, set())) > 3:
                answers += "..."
            lines.append(f"{i:<4} {domain:<40} {cnt:<9} {sources:<9} {answers}")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- http -----
    def _http_summary(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        top_n = payload.get("top_n", 30)

        if not s.http_requests:
            return ToolResult(ok=True, result={"text": "No HTTP requests found in PCAP."})

        lines = []
        lines.append(f"=== HTTP Requests ({len(s.http_requests)} total) ===")
        lines.append(f"{'#':<4} {'Time':<12} {'Source':<18} {'Method':<8} {'Host':<30} {'Path'}")
        lines.append("-" * 100)
        for i, req in enumerate(s.http_requests[:top_n], 1):
            ts = datetime.utcfromtimestamp(req["ts"])
            lines.append(f"{i:<4} {ts:%H:%M:%S}    {req['src']:<18} {req['method']:<8} {req['host']:<30} {req['path'][:50]}")
        if len(s.http_requests) > top_n:
            lines.append(f"\n... {len(s.http_requests) - top_n} more requests not shown")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- tls -----
    def _tls_summary(self) -> ToolResult:
        s = get_pcap_session()
        if not s.tls_handshakes:
            return ToolResult(ok=True, result={"text": "No TLS handshakes found in PCAP."})

        sni_counts: Counter = Counter()
        no_sni = []
        sni_details: Dict[str, List] = defaultdict(list)
        for th in s.tls_handshakes:
            sni = th.get("sni", "")
            if sni:
                sni_counts[sni] += 1
                sni_details[sni].append(th)
            else:
                no_sni.append(th)

        lines = []
        lines.append(f"=== TLS Analysis ({len(s.tls_handshakes)} handshakes) ===")
        if no_sni:
            lines.append(f"\n🟡 TLS WITHOUT SNI — {len(no_sni)} connection(s)")
            lines.append("-" * 60)
            seen = set()
            for th in no_sni[:20]:
                key = (th["src"], th["dst"], th["dport"])
                if key not in seen:
                    seen.add(key)
                    dst_loc = "INT" if is_internal(th["dst"]) else "EXT"
                    lines.append(f"  {th['src']} → {th['dst']}:{th['dport']} ({dst_loc})")
        lines.append("\n=== TLS Server Names (SNI) ===")
        lines.append(f"{'#':<4} {'SNI':<45} {'Count':<8} {'Dest IPs'}")
        lines.append("-" * 80)
        for i, (sni, cnt) in enumerate(sni_counts.most_common(30), 1):
            dst_ips = set(th["dst"] for th in sni_details[sni])
            ips_str = ", ".join(list(dst_ips)[:3])
            if len(dst_ips) > 3:
                ips_str += "..."
            lines.append(f"{i:<4} {sni:<45} {cnt:<8} {ips_str}")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- timeline -----
    def _timeline(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        ip_address = payload.get("ip_address", "")
        top_n = payload.get("top_n", 50)

        events = []
        for (src, dst, dport, proto), stats in s.conversations.items():
            if ip_address and ip_address not in (src, dst):
                continue
            if stats["first_seen"]:
                events.append({
                    "ts": stats["first_seen"], "type": "CONN",
                    "detail": f"{src} → {dst}:{dport}/{proto} ({stats['packets']} pkts, {_format_bytes(stats['bytes_out'])})",
                })
        for q in s.dns_queries:
            if ip_address and q["src"] != ip_address:
                continue
            events.append({"ts": q["ts"], "type": "DNS", "detail": f"{q['src']} queried {q['query']}"})
        for req in s.http_requests:
            if ip_address and req["src"] != ip_address:
                continue
            events.append({"ts": req["ts"], "type": "HTTP", "detail": f"{req['src']} → {req['method']} {req['host']}{req['path'][:40]}"})

        events.sort(key=lambda e: e["ts"])
        title = f"=== Timeline for {ip_address} ===" if ip_address else "=== Network Timeline ==="
        lines = [title, f"{'Time':<12} {'Type':<6} {'Detail'}", "-" * 80]
        for ev in events[:top_n]:
            ts = datetime.utcfromtimestamp(ev["ts"])
            lines.append(f"{ts:%H:%M:%S}    {ev['type']:<6} {ev['detail']}")
        if len(events) > top_n:
            lines.append(f"\n... {len(events) - top_n} more events not shown")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- ioc -----
    def _ioc_search(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        indicator = payload.get("indicator", "")
        if not indicator:
            return ToolResult(ok=False, error_code="MISSING_PARAM", message="'indicator' required for ioc mode")

        results = []

        # Port?
        try:
            port = int(indicator)
            cnt = s.dst_ports.get(port, 0)
            if cnt:
                results.append(f"Port {port}: {cnt} connections as destination")
                for (src, dst, dport, proto), stats in s.conversations.items():
                    if dport == port:
                        results.append(f"  {src} → {dst}:{dport}/{proto} ({stats['packets']} pkts, {_format_bytes(stats['bytes_out'])})")
            else:
                results.append(f"Port {port}: not found in PCAP")
            return ToolResult(ok=True, result={"text": "\n".join(results)})
        except ValueError:
            pass

        # IP?
        if indicator.count(".") == 3:
            found = False
            src_cnt = s.src_ips.get(indicator, 0)
            dst_cnt = s.dst_ips.get(indicator, 0)
            if src_cnt or dst_cnt:
                found = True
                loc = "Internal" if is_internal(indicator) else "External"
                results.append(f"IP {indicator} ({loc}):")
                results.append(f"  As source: {src_cnt:,} packets")
                results.append(f"  As destination: {dst_cnt:,} packets")
                results.append("")
                results.append("  Conversations:")
                for (src, dst, dport, proto), stats in s.conversations.items():
                    if indicator in (src, dst):
                        results.append(f"    {src} → {dst}:{dport}/{proto}  {stats['packets']} pkts  {_format_bytes(stats['bytes_out'])}")
            for r in s.dns_responses:
                if r["answer"] == indicator:
                    results.append(f"  DNS: {r['query']} → {indicator}")
                    found = True
            if not found:
                results.append(f"IP {indicator}: not found in PCAP")
            return ToolResult(ok=True, result={"text": "\n".join(results)})

        # Domain
        indicator_lower = indicator.lower()
        found = False
        for q in s.dns_queries:
            if indicator_lower in q["query"].lower():
                if not found:
                    results.append(f"Domain matching '{indicator}':")
                    found = True
                results.append(f"  DNS query: {q['query']} from {q['src']}")
        for r in s.dns_responses:
            if indicator_lower in r["query"].lower():
                results.append(f"  DNS answer: {r['query']} → {r['answer']}")
        for req in s.http_requests:
            if indicator_lower in req["host"].lower():
                if not found:
                    results.append(f"Domain matching '{indicator}':")
                    found = True
                results.append(f"  HTTP: {req['method']} {req['host']}{req['path'][:40]}")
        for th in s.tls_handshakes:
            if indicator_lower in th.get("sni", "").lower():
                if not found:
                    results.append(f"Domain matching '{indicator}':")
                    found = True
                results.append(f"  TLS SNI: {th['sni']} ({th['src']} → {th['dst']}:{th['dport']})")
        if not found:
            results.append(f"IOC '{indicator}': not found in PCAP")
        return ToolResult(ok=True, result={"text": "\n".join(results)})
