"""
PCAP Metadata Summary — Load, parse, and summarize network captures.

Faithful port of Event Mill v1.0 tools/pcap_parser.py.
All modes operate on a module-level PcapSession singleton shared
across every network-forensics plugin in the same process.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import tempfile
import ipaddress
import atexit
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("eventmill.plugins.pcap_metadata_summary")

# RFC 1918 private ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Organization-owned public IP ranges (populated from investigation context).
# When a loaded context .md contains a section like
#   # Known Organization Public IP Ranges
#   161.141.0.0/16
# those ranges are registered here so every tool treats them as internal.
KNOWN_ORG_NETWORKS: list[ipaddress.IPv4Network] = []


def register_org_networks(networks: list[ipaddress.IPv4Network]) -> None:
    """Register organization-owned public IP ranges as internal."""
    KNOWN_ORG_NETWORKS.clear()
    KNOWN_ORG_NETWORKS.extend(networks)


def is_known_org(ip_str: str) -> bool:
    """Check if IP belongs to a known organization public range (non-RFC1918)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in KNOWN_ORG_NETWORKS)
    except ValueError:
        return False


def is_internal(ip_str: str) -> bool:
    """Check if an IP is in RFC1918 private ranges or known organization ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (any(addr in net for net in PRIVATE_NETWORKS)
                or any(addr in net for net in KNOWN_ORG_NETWORKS))
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
        self.bytes_transferred: int = 0  # total payload bytes from conn.log (Zeek)
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

        # SCADA message-bus tag data (JSON payloads from OASyS / AMQP-like)
        self.scada_tags: Dict[str, Dict] = {}  # tag_name -> {src, dst, count, values_sample, quality}
        self.scada_tag_sources: Counter = Counter()  # src_ip -> message count

        # Syslog summary (condensed stats, not raw messages)
        self.syslog_sources: Counter = Counter()      # src_ip -> message count
        self.syslog_severity: Counter = Counter()     # severity_int -> count
        self.syslog_facilities: Counter = Counter()   # facility_int -> count
        self.syslog_patterns: Counter = Counter()     # pattern keyword -> count
        self.syslog_total: int = 0

        # IT security protocol activity (port-level detection + basic extraction)
        self.ssh_sessions: List[Dict] = []            # {src, dst, src_port, ts, banner}
        self.snmp_communities: Counter = Counter()    # community_string -> count
        self.snmp_sources: Counter = Counter()        # src_ip -> count

        # AD / Windows protocol activity (Zeek-populated)
        self.kerberos_tickets: List[Dict] = []        # {client, service, cipher, success, src, dst, ts}
        self.smb_mappings: List[Dict] = []            # {src, dst, share, path, ts}
        self.smb_files: List[Dict] = []               # {src, dst, action, name, path, size, ts}
        self.dce_rpc_calls: List[Dict] = []           # {src, dst, endpoint, operation, ts}
        self.ldap_operations: List[Dict] = []         # {src, dst, message_type, base_object, result, ts}
        self.ntlm_auths: List[Dict] = []              # {src, dst, hostname, domain, username, success, ts}

        # Cleartext credential detections (values are redacted)
        self.cleartext_creds: List[Dict] = []
        self.cleartext_creds_total: int = 0

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
        self.stp_tca_count: int = 0                          # TC Acknowledgment flag
        self.stp_root_bridges: Dict[str, List] = defaultdict(list)  # root_key -> [timestamps]
        self._stp_timestamps: List[float] = []
        self.stp_bridges: Counter = Counter()                # bridge_key -> BPDU count
        self.stp_version_counts: Counter = Counter()         # {STP, RSTP, MSTP} -> count
        self.stp_port_roles: Counter = Counter()             # {Root, Designated, Alternate, Backup, Unknown} -> count
        self.stp_port_states: Counter = Counter()            # {Learning, Forwarding, Blocking, ...} -> count
        self.stp_proposal_count: int = 0                     # RSTP proposal flag count
        self.stp_agreement_count: int = 0                    # RSTP agreement flag count
        self.stp_tc_events: List[float] = []                 # timestamps when TC flag set
        self.stp_tcn_events: List[float] = []                # timestamps when TCN BPDU sent
        self.stp_root_changes: List[tuple] = []              # (timestamp, vlan, old_root, new_root)
        self._stp_last_root_per_vlan: Dict[int, str] = {}    # PVST+: track root per VLAN
        self.stp_path_costs: Dict[str, List] = defaultdict(list)   # bridge_key -> [(ts, cost)]
        self.stp_port_ids: Counter = Counter()               # port_id_hex -> count
        self.stp_vlans: Counter = Counter()                  # VLAN ID -> count (from System ID Extension)
        self.stp_timers: Dict[str, Counter] = {              # timer value distribution
            'hello': Counter(), 'max_age': Counter(), 'fwd_delay': Counter()
        }
        self.stp_src_macs: Counter = Counter()               # source MAC -> count (which switches send BPDUs)
        self._stp_per_port_ts: Dict[str, List[float]] = defaultdict(list)  # src_mac -> [timestamps] for gap detection
        self.stp_bpdu_gaps: List[tuple] = []                 # (src_mac, gap_start_ts, gap_seconds) gaps > max_age
        self.stp_mac_mismatches: List[tuple] = []            # (ts, eth_src_mac, bpdu_bridge_mac) spoofing indicator

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

        # VLAN tracking
        self.vlan_ids: Counter = Counter()
        self.vlan_to_ips: Dict[int, set] = defaultdict(set)
        self.vlan_1_detected: bool = False
        self.untagged_frame_count: int = 0

        # CDP / LLDP neighbor discovery
        self.cdp_frame_count: int = 0
        self.cdp_neighbors: Dict[str, Dict] = {}
        self.lldp_frame_count: int = 0
        self.lldp_neighbors: Dict[str, Dict] = {}

        # Network discovery evidence (OSPF, DHCP, ARP, broadcast-inferred)
        self.network_evidence: List[Dict] = []

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

    def merge_into(self, other: "PcapSession") -> None:
        """Merge *other* session data into this session (cumulative load)."""
        # Filename / metadata
        if other.filename:
            if self.filename:
                self.filename += f", {other.filename}"
            else:
                self.filename = other.filename
        if other.file_path:
            if self.file_path:
                self.file_path += f", {other.file_path}"
            else:
                self.file_path = other.file_path
        self.file_size += other.file_size
        self.bytes_transferred += other.bytes_transferred
        self.packet_count += other.packet_count

        # Time range — take the widest window
        if other.start_time is not None:
            if self.start_time is None or other.start_time < self.start_time:
                self.start_time = other.start_time
        if other.end_time is not None:
            if self.end_time is None or other.end_time > self.end_time:
                self.end_time = other.end_time

        # Conversations — merge per-flow stats
        for key, oconv in other.conversations.items():
            sconv = self.conversations[key]
            sconv["packets"] += oconv["packets"]
            sconv["bytes_out"] += oconv["bytes_out"]
            sconv["bytes_in"] += oconv["bytes_in"]
            # Cap timestamps to avoid OOM on large multi-file merges.
            # Keep first/last 500 per flow — enough for beacon detection.
            _TS_CAP = 1000
            combined = sconv["timestamps"]
            combined.extend(oconv["timestamps"])
            if len(combined) > _TS_CAP:
                combined.sort()
                sconv["timestamps"] = combined[:500] + combined[-500:]
            if oconv["first_seen"] is not None:
                if sconv["first_seen"] is None or oconv["first_seen"] < sconv["first_seen"]:
                    sconv["first_seen"] = oconv["first_seen"]
            if oconv["last_seen"] is not None:
                if sconv["last_seen"] is None or oconv["last_seen"] > sconv["last_seen"]:
                    sconv["last_seen"] = oconv["last_seen"]

        # Counters — add
        self.dst_ports += other.dst_ports
        self.src_ports += other.src_ports
        self.port_proto.update(other.port_proto)
        self.protocols += other.protocols
        self.src_ips += other.src_ips
        self.dst_ips += other.dst_ips

        # Lists — extend
        self.dns_queries.extend(other.dns_queries)
        self.dns_responses.extend(other.dns_responses)
        self.http_requests.extend(other.http_requests)
        self.tls_handshakes.extend(other.tls_handshakes)
        self.ot_transactions.extend(other.ot_transactions)
        self.cleartext_creds.extend(other.cleartext_creds)
        self.cleartext_creds_total += other.cleartext_creds_total

        # TCP health
        self.tcp_retransmissions += other.tcp_retransmissions
        self.tcp_rst_count += other.tcp_rst_count
        self.tcp_syn_count += other.tcp_syn_count
        self.tcp_fin_count += other.tcp_fin_count
        self.tcp_zero_window_count += other.tcp_zero_window_count

        for key, ohealth in other.conv_health.items():
            shealth = self.conv_health[key]
            shealth["rst"] += ohealth["rst"]
            shealth["retransmit"] += ohealth["retransmit"]
            shealth["zero_window"] += ohealth["zero_window"]

        # ICMP
        self.icmp_errors.extend(other.icmp_errors)
        for dest, entries in other.ttl_exceeded_by_dest.items():
            self.ttl_exceeded_by_dest[dest].extend(entries)
        self.suspected_loop_packets.extend(other.suspected_loop_packets)

        # ARP
        self.arp_request_count += other.arp_request_count
        self.arp_reply_count += other.arp_reply_count
        self.arp_gratuitous_count += other.arp_gratuitous_count
        self._arp_timestamps.extend(other._arp_timestamps)
        self.arp_requests_by_src += other.arp_requests_by_src
        for ip, macs in other.arp_ip_to_macs.items():
            self.arp_ip_to_macs[ip].update(macs)
        self._arp_request_targets += other._arp_request_targets
        self._arp_reply_targets += other._arp_reply_targets

        # STP
        self.stp_bpdu_count += other.stp_bpdu_count
        self.stp_tcn_count += other.stp_tcn_count
        self.stp_tc_flag_count += other.stp_tc_flag_count
        self.stp_tca_count += other.stp_tca_count
        for bridge, entries in other.stp_root_bridges.items():
            self.stp_root_bridges[bridge].extend(entries)
        self._stp_timestamps.extend(other._stp_timestamps)
        self.stp_bridges += other.stp_bridges
        self.stp_version_counts += other.stp_version_counts
        self.stp_port_roles += other.stp_port_roles
        self.stp_port_states += other.stp_port_states
        self.stp_proposal_count += other.stp_proposal_count
        self.stp_agreement_count += other.stp_agreement_count
        self.stp_tc_events.extend(other.stp_tc_events)
        self.stp_tcn_events.extend(other.stp_tcn_events)
        self.stp_root_changes.extend(other.stp_root_changes)
        for bridge, entries in other.stp_path_costs.items():
            self.stp_path_costs[bridge].extend(entries)
        self.stp_port_ids += other.stp_port_ids
        self.stp_vlans += other.stp_vlans
        for timer_name in ('hello', 'max_age', 'fwd_delay'):
            self.stp_timers[timer_name] += other.stp_timers[timer_name]
        self.stp_src_macs += other.stp_src_macs

        # HSRP
        self.hsrp_hello_count += other.hsrp_hello_count
        self.hsrp_events.extend(other.hsrp_events)
        self.hsrp_state_changes.extend(other.hsrp_state_changes)

        # VRRP
        self.vrrp_advert_count += other.vrrp_advert_count
        self.vrrp_events.extend(other.vrrp_events)
        self.vrrp_priority_changes.extend(other.vrrp_priority_changes)

        # OSPF
        self.ospf_total_count += other.ospf_total_count
        self.ospf_hello_count += other.ospf_hello_count
        self.ospf_dbd_count += other.ospf_dbd_count
        self.ospf_lsrequest_count += other.ospf_lsrequest_count
        self.ospf_lsupdate_count += other.ospf_lsupdate_count
        self.ospf_lsack_count += other.ospf_lsack_count
        self.ospf_areas.update(other.ospf_areas)
        self.ospf_router_ids.update(other.ospf_router_ids)
        for pair, ts_list in other.ospf_neighbor_hellos.items():
            self.ospf_neighbor_hellos[pair].extend(ts_list)
        self._ospf_lsupdate_timestamps.extend(other._ospf_lsupdate_timestamps)

        # EIGRP
        self.eigrp_total_count += other.eigrp_total_count
        self.eigrp_hello_count += other.eigrp_hello_count
        self.eigrp_update_count += other.eigrp_update_count
        self.eigrp_query_count += other.eigrp_query_count
        self.eigrp_reply_count += other.eigrp_reply_count
        self.eigrp_as_numbers.update(other.eigrp_as_numbers)

        # IP fragmentation & TTL
        self.ip_fragment_count += other.ip_fragment_count
        self.ttl_distribution += other.ttl_distribution

        # VLAN tracking
        self.vlan_ids += other.vlan_ids
        for vid, ips in other.vlan_to_ips.items():
            self.vlan_to_ips[vid].update(ips)
        if other.vlan_1_detected:
            self.vlan_1_detected = True
        self.untagged_frame_count += other.untagged_frame_count

        # CDP / LLDP
        self.cdp_frame_count += other.cdp_frame_count
        for mac, info in other.cdp_neighbors.items():
            if mac not in self.cdp_neighbors:
                self.cdp_neighbors[mac] = dict(info)
        self.lldp_frame_count += other.lldp_frame_count
        for mac, info in other.lldp_neighbors.items():
            if mac not in self.lldp_neighbors:
                self.lldp_neighbors[mac] = dict(info)

        # Network discovery evidence
        self.network_evidence.extend(other.network_evidence)

        # --- New protocol fields ---

        # SCADA tags — merge dicts (add counts, extend samples)
        for tag, info in other.scada_tags.items():
            if tag in self.scada_tags:
                self.scada_tags[tag]["count"] += info["count"]
                samples = self.scada_tags[tag]["values_sample"]
                for v in info.get("values_sample", []):
                    if len(samples) < 10:
                        samples.append(v)
                self.scada_tags[tag]["quality"] = info.get("quality", self.scada_tags[tag]["quality"])
            else:
                self.scada_tags[tag] = dict(info)  # copy
        self.scada_tag_sources += other.scada_tag_sources

        # Syslog summary
        self.syslog_sources += other.syslog_sources
        self.syslog_severity += other.syslog_severity
        self.syslog_facilities += other.syslog_facilities
        self.syslog_patterns += other.syslog_patterns
        self.syslog_total += other.syslog_total

        # SSH sessions (cap at 500)
        remaining = max(0, 500 - len(self.ssh_sessions))
        self.ssh_sessions.extend(other.ssh_sessions[:remaining])

        # SNMP
        self.snmp_communities += other.snmp_communities
        self.snmp_sources += other.snmp_sources

        # AD / Windows protocols (cap at 1000 each)
        for attr, cap in (
            ("kerberos_tickets", 1000),
            ("smb_mappings", 1000),
            ("smb_files", 1000),
            ("dce_rpc_calls", 1000),
            ("ldap_operations", 1000),
            ("ntlm_auths", 1000),
        ):
            mine = getattr(self, attr)
            remaining = max(0, cap - len(mine))
            mine.extend(getattr(other, attr)[:remaining])

        # Cap unbounded lists accumulated across files
        _LIST_CAP = 50_000
        for attr in ("dns_queries", "dns_responses", "http_requests",
                      "tls_handshakes", "ot_transactions", "icmp_errors"):
            lst = getattr(self, attr)
            if len(lst) > _LIST_CAP:
                setattr(self, attr, lst[:_LIST_CAP])


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
    from scapy.layers.l2 import ARP, SNAP, STP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.hsrp import HSRP as ScapyHSRP
    from scapy.layers.vrrp import VRRP as ScapyVRRP
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
    _seen_tcp_seqs: Dict[Tuple[str, str, int, int, int], int] = {}  # (src, dst, sport, dport, seq) -> payload_len

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

            # --- STP / BPDU extraction (L2, before IP check) ---
            stp = None
            if pkt.haslayer(STP):
                stp = pkt[STP]
            elif pkt.haslayer(SNAP):
                _snap = pkt[SNAP]
                if _snap.OUI == 0x00000c and _snap.code == 0x010b:
                    try:
                        stp = STP(bytes(_snap.payload))
                    except Exception:
                        pass
            if stp is not None:
                try:
                    session.stp_bpdu_count += 1
                    session._stp_timestamps.append(ts)

                    # Source MAC of the switch sending this BPDU
                    eth_src = ''
                    if hasattr(pkt, 'src'):
                        eth_src = pkt.src
                        session.stp_src_macs[eth_src] += 1
                        session._stp_per_port_ts[eth_src].append(ts)

                    # STP version: 0=STP, 2=RSTP, 3=MSTP
                    version = getattr(stp, 'version', 0) or 0
                    version_name = {0: 'STP', 2: 'RSTP', 3: 'MSTP'}.get(version, f'v{version}')
                    session.stp_version_counts[version_name] += 1

                    # Extract bridge ID (priority + MAC)
                    bridge_mac = getattr(stp, 'bridgemac', '') or ''
                    bridge_id = getattr(stp, 'bridgeid', 0) or 0
                    bridge_key = f"{bridge_id}:{bridge_mac}"
                    if bridge_key:
                        session.stp_bridges[bridge_key] += 1

                    # MAC mismatch detection (spoofing indicator)
                    if eth_src and bridge_mac and eth_src.lower() != bridge_mac.lower():
                        # Different base MACs (ignore port offset in last octet)
                        eth_base = eth_src.lower().rsplit(':', 1)[0]
                        bpdu_base = bridge_mac.lower().rsplit(':', 1)[0]
                        if eth_base != bpdu_base:
                            if len(session.stp_mac_mismatches) < 50:
                                session.stp_mac_mismatches.append((ts, eth_src, bridge_mac))

                    # VLAN from System ID Extension (lower 12 bits of bridge priority)
                    vlan_id = bridge_id & 0x0FFF
                    if vlan_id > 0:
                        session.stp_vlans[vlan_id] += 1

                    # Root bridge tracking (PVST+-aware: per-VLAN)
                    root_mac = getattr(stp, 'rootmac', '') or ''
                    root_id = getattr(stp, 'rootid', 0) or 0
                    root_key = f"{root_id}:{root_mac}"
                    if root_key:
                        session.stp_root_bridges[root_key].append(ts)
                    # Detect root bridge changes within same VLAN
                    root_vlan = root_id & 0x0FFF
                    prev_root = session._stp_last_root_per_vlan.get(root_vlan)
                    if prev_root and root_key != prev_root:
                        session.stp_root_changes.append((ts, root_vlan, prev_root, root_key))
                    session._stp_last_root_per_vlan[root_vlan] = root_key

                    # Root path cost
                    path_cost = getattr(stp, 'pathcost', None)
                    if path_cost is not None and bridge_key:
                        session.stp_path_costs[bridge_key].append((ts, path_cost))

                    # Port ID
                    port_id = getattr(stp, 'portid', None)
                    if port_id is not None:
                        session.stp_port_ids[f"0x{port_id:04x}"] += 1

                    # Timer values
                    hello = getattr(stp, 'hellotime', None)
                    maxage = getattr(stp, 'maxage', None)
                    fwddelay = getattr(stp, 'fwddelay', None)
                    if hello is not None:
                        session.stp_timers['hello'][hello // 256 if hello > 255 else hello] += 1
                    if maxage is not None:
                        session.stp_timers['max_age'][maxage // 256 if maxage > 255 else maxage] += 1
                    if fwddelay is not None:
                        session.stp_timers['fwd_delay'][fwddelay // 256 if fwddelay > 255 else fwddelay] += 1

                    # BPDU type and flags
                    bpdu_type = getattr(stp, 'bpdutype', 0)
                    bpdu_flags = getattr(stp, 'bpduflags', 0) or 0
                    if bpdu_type == 0x80:  # TCN BPDU
                        session.stp_tcn_count += 1
                        session.stp_tcn_events.append(ts)
                    # Flags parsing (RSTP flags byte)
                    if bpdu_flags & 0x01:  # Bit 0: Topology Change
                        session.stp_tc_flag_count += 1
                        session.stp_tc_events.append(ts)
                    if bpdu_flags & 0x80:  # Bit 7: TC Acknowledgment
                        session.stp_tca_count += 1
                    if bpdu_flags & 0x02:  # Bit 1: Proposal (RSTP)
                        session.stp_proposal_count += 1
                    if bpdu_flags & 0x40:  # Bit 6: Agreement (RSTP)
                        session.stp_agreement_count += 1
                    # Bits 2-3: Port Role (RSTP)
                    port_role_bits = (bpdu_flags >> 2) & 0x03
                    port_role = {0: 'Unknown', 1: 'Alternate/Backup',
                                 2: 'Root', 3: 'Designated'}.get(port_role_bits, 'Unknown')
                    session.stp_port_roles[port_role] += 1
                    # Bits 4-5: Learning/Forwarding state (RSTP)
                    learning = bool(bpdu_flags & 0x10)
                    forwarding = bool(bpdu_flags & 0x20)
                    if forwarding and learning:
                        session.stp_port_states['Forwarding'] += 1
                    elif learning:
                        session.stp_port_states['Learning'] += 1
                    elif not forwarding and not learning:
                        session.stp_port_states['Blocking/Discarding'] += 1
                except Exception:
                    pass

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
                # Retransmission detection: same (src, dst, sport, dport, seq)
                # with payload seen before (exclude SYN/FIN-only retransmits)
                seq = pkt[TCP].seq
                payload_len = len(pkt[TCP].payload)
                if payload_len > 0 and not (tcp_flags & 0x02):  # skip SYN
                    retx_key = (src_ip, dst_ip, sport, dport, seq)
                    if retx_key in _seen_tcp_seqs:
                        session.tcp_retransmissions += 1
                        conv_key_retx = (src_ip, dst_ip, dport, proto)
                        session.conv_health[conv_key_retx]["retransmit"] += 1
                    else:
                        _seen_tcp_seqs[retx_key] = payload_len
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
            # SCADA JSON tag data (port 5672 / OASyS message bus)
            # ---------------------------------------------------------------
            if (dport in _SCADA_MQ_PORTS or sport in _SCADA_MQ_PORTS) and pkt.haslayer(Raw):
                _extract_scada_json(pkt[Raw].load, session, src_ip, dst_ip, ts)

            # ---------------------------------------------------------------
            # Syslog (UDP 514 summary stats)
            # ---------------------------------------------------------------
            if proto == "UDP" and (dport == 514 or sport == 514) and pkt.haslayer(Raw):
                _extract_syslog(pkt[Raw].load, session, src_ip)

            # ---------------------------------------------------------------
            # SNMP community strings (UDP 161/162)
            # ---------------------------------------------------------------
            if proto == "UDP" and dport in (161, 162) and pkt.haslayer(Raw):
                _extract_snmp_community(pkt[Raw].load, session, src_ip)

            # ---------------------------------------------------------------
            # SSH banner (port 22)
            # ---------------------------------------------------------------
            if proto == "TCP" and (dport == 22 or sport == 22) and pkt.haslayer(Raw):
                _extract_ssh_banner(pkt[Raw].load, session, src_ip, dst_ip, sport, ts)

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

            # ---------------------------------------------------------------
            # Netops: HSRP extraction (UDP port 1985)
            # ---------------------------------------------------------------
            if pkt.haslayer(ScapyHSRP):
                try:
                    hsrp = pkt[ScapyHSRP]
                    state = getattr(hsrp, 'state', 0)
                    group = getattr(hsrp, 'group', 0)
                    priority = getattr(hsrp, 'priority', 0)
                    vip = getattr(hsrp, 'virtualIP', '') or ''
                    _HSRP_STATES = {0: "Initial", 1: "Learn", 2: "Listen",
                                    4: "Speak", 8: "Standby", 16: "Active"}
                    state_name = _HSRP_STATES.get(state, f"Unknown({state})")
                    if state in (0, 4):  # Hello-like states
                        session.hsrp_hello_count += 1
                    session.hsrp_events.append({
                        "src": src_ip, "group": group, "state": state_name,
                        "priority": priority, "vip": str(vip), "ts": ts,
                    })
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # Netops: VRRP extraction (IP protocol 112)
            # ---------------------------------------------------------------
            if pkt.haslayer(ScapyVRRP):
                try:
                    vrrp = pkt[ScapyVRRP]
                    vrid = getattr(vrrp, 'vrid', 0)
                    priority = getattr(vrrp, 'priority', 0)
                    session.vrrp_advert_count += 1
                    session.vrrp_events.append({
                        "src": src_ip, "vrid": vrid,
                        "priority": priority, "ts": ts,
                    })
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # Netops: OSPF extraction (IP protocol 89)
            # ---------------------------------------------------------------
            if ip_layer.proto == 89:
                try:
                    ospf_data = bytes(ip_layer.payload)
                    if len(ospf_data) >= 24:
                        ospf_type = ospf_data[1]
                        router_id = f"{ospf_data[4]}.{ospf_data[5]}.{ospf_data[6]}.{ospf_data[7]}"
                        area_raw = ospf_data[8:12]
                        area_id = f"{area_raw[0]}.{area_raw[1]}.{area_raw[2]}.{area_raw[3]}"
                        session.ospf_total_count += 1
                        session.ospf_router_ids.add(router_id)
                        session.ospf_areas.add(area_id)
                        if ospf_type == 1:  # Hello
                            session.ospf_hello_count += 1
                            neighbor_key = (src_ip, dst_ip)
                            session.ospf_neighbor_hellos[neighbor_key].append(ts)
                        elif ospf_type == 2:  # DB Description
                            session.ospf_dbd_count += 1
                        elif ospf_type == 3:  # LS Request
                            session.ospf_lsrequest_count += 1
                        elif ospf_type == 4:  # LS Update
                            session.ospf_lsupdate_count += 1
                            session._ospf_lsupdate_timestamps.append(ts)
                        elif ospf_type == 5:  # LS Ack
                            session.ospf_lsack_count += 1
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # Netops: EIGRP extraction (IP protocol 88)
            # ---------------------------------------------------------------
            if ip_layer.proto == 88:
                try:
                    eigrp_data = bytes(ip_layer.payload)
                    if len(eigrp_data) >= 20:
                        opcode = eigrp_data[1]
                        # AS number at bytes 8-11 (big-endian)
                        as_num = int.from_bytes(eigrp_data[8:12], 'big')
                        session.eigrp_total_count += 1
                        if as_num > 0:
                            session.eigrp_as_numbers.add(as_num)
                        if opcode == 1:    # Update
                            session.eigrp_update_count += 1
                        elif opcode == 3:  # Query
                            session.eigrp_query_count += 1
                        elif opcode == 4:  # Reply
                            session.eigrp_reply_count += 1
                        elif opcode == 5:  # Hello
                            session.eigrp_hello_count += 1
                except Exception:
                    pass

    # --- Post-process: detect BPDU starvation (gaps > max_age per source port) ---
    _compute_stp_bpdu_gaps(session)

    return session


def _compute_stp_bpdu_gaps(session) -> None:
    """Detect BPDU starvation: gaps in per-port BPDU stream exceeding max_age.

    A switch port that was steadily receiving BPDUs every 2s (hello interval)
    and then stops for >20s (max_age) is a critical loop risk — the port will
    transition to Forwarding and may create a bridging loop.
    """
    # Determine max_age from captured timers (default 20s)
    max_age = 20
    if session.stp_timers.get('max_age'):
        max_age = session.stp_timers['max_age'].most_common(1)[0][0] or 20

    for src_mac, timestamps in session._stp_per_port_ts.items():
        if len(timestamps) < 3:
            continue  # need at least a few BPDUs to establish a stream
        ts_sorted = sorted(timestamps)
        for i in range(1, len(ts_sorted)):
            gap = ts_sorted[i] - ts_sorted[i - 1]
            if gap > max_age:
                session.stp_bpdu_gaps.append((src_mac, ts_sorted[i - 1], round(gap, 1)))


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
    import warnings

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
    _seen_tcp_seqs_dpkt: Dict[Tuple[str, str, int, int, int], int] = {}  # retransmission detection

    # Suppress dpkt's internal deprecation warning about IP.off
    warnings.filterwarnings("ignore", message="IP.off is deprecated", category=UserWarning)

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

            # --- STP / BPDU extraction (L2, before IP check) ---
            # STP BPDUs: standard LLC (DSAP=0x42) or Cisco PVST+ (SNAP)
            try:
                raw = bytes(eth.data) if not isinstance(eth.data, bytes) else eth.data
                # STP detection: standard LLC or Cisco PVST+ (SNAP)
                if len(raw) >= 4 and eth.type <= 1500:  # 802.3 length field
                    _is_std_stp = raw[0] == 0x42 and raw[1] == 0x42
                    _is_pvst = (len(raw) >= 12
                                and raw[0] == 0xAA and raw[1] == 0xAA
                                and raw[2] == 0x03
                                and raw[3:6] == b'\x00\x00\x0c'
                                and raw[6:8] == b'\x01\x0b')
                    if _is_std_stp or _is_pvst:
                        stp_data = raw[8:] if _is_pvst else raw[3:]
                        if len(stp_data) >= 4:
                            session.stp_bpdu_count += 1
                            session._stp_timestamps.append(ts)

                            # Source MAC of the switch sending this BPDU
                            src_mac = ':'.join(f'{b:02x}' for b in eth.src)
                            session.stp_src_macs[src_mac] += 1
                            session._stp_per_port_ts[src_mac].append(ts)

                            # STP version byte at offset 1
                            version = stp_data[1]
                            version_name = {0: 'STP', 2: 'RSTP', 3: 'MSTP'}.get(version, f'v{version}')
                            session.stp_version_counts[version_name] += 1

                            bpdu_type = stp_data[3]
                            if bpdu_type == 0x80:  # TCN BPDU
                                session.stp_tcn_count += 1
                                session.stp_tcn_events.append(ts)
                            elif len(stp_data) >= 35:
                                # Config/RSTP BPDU — full field extraction
                                bpdu_flags = stp_data[4]
                                # TC flag (bit 0)
                                if bpdu_flags & 0x01:
                                    session.stp_tc_flag_count += 1
                                    session.stp_tc_events.append(ts)
                                # TCA flag (bit 7)
                                if bpdu_flags & 0x80:
                                    session.stp_tca_count += 1
                                # Proposal (bit 1, RSTP)
                                if bpdu_flags & 0x02:
                                    session.stp_proposal_count += 1
                                # Agreement (bit 6, RSTP)
                                if bpdu_flags & 0x40:
                                    session.stp_agreement_count += 1
                                # Port Role (bits 2-3, RSTP)
                                port_role_bits = (bpdu_flags >> 2) & 0x03
                                port_role = {0: 'Unknown', 1: 'Alternate/Backup',
                                             2: 'Root', 3: 'Designated'}.get(port_role_bits, 'Unknown')
                                session.stp_port_roles[port_role] += 1
                                # Port State (bits 4-5, RSTP)
                                learning = bool(bpdu_flags & 0x10)
                                forwarding = bool(bpdu_flags & 0x20)
                                if forwarding and learning:
                                    session.stp_port_states['Forwarding'] += 1
                                elif learning:
                                    session.stp_port_states['Learning'] += 1
                                elif not forwarding and not learning:
                                    session.stp_port_states['Blocking/Discarding'] += 1

                                # Root bridge: priority (2 bytes) + MAC (6 bytes) at offset 5-12
                                root_prio = int.from_bytes(stp_data[5:7], 'big')
                                root_mac = ':'.join(f'{b:02x}' for b in stp_data[7:13])
                                root_key = f"{root_prio}:{root_mac}"
                                session.stp_root_bridges[root_key].append(ts)
                                # Detect root bridge changes (PVST+-aware: per-VLAN)
                                root_vlan = root_prio & 0x0FFF
                                prev_root = session._stp_last_root_per_vlan.get(root_vlan)
                                if prev_root and root_key != prev_root:
                                    session.stp_root_changes.append((ts, root_vlan, prev_root, root_key))
                                session._stp_last_root_per_vlan[root_vlan] = root_key

                                # Root path cost: 4 bytes at offset 13-16
                                path_cost = int.from_bytes(stp_data[13:17], 'big')
                                # Bridge ID: priority (2 bytes) + MAC (6 bytes) at offset 17-24
                                bridge_prio = int.from_bytes(stp_data[17:19], 'big')
                                bridge_mac = ':'.join(f'{b:02x}' for b in stp_data[19:25])
                                bridge_key = f"{bridge_prio}:{bridge_mac}"
                                session.stp_bridges[bridge_key] += 1
                                session.stp_path_costs[bridge_key].append((ts, path_cost))

                                # MAC mismatch detection (spoofing indicator)
                                if src_mac and bridge_mac and src_mac != bridge_mac:
                                    eth_base = src_mac.rsplit(':', 1)[0]
                                    bpdu_base = bridge_mac.rsplit(':', 1)[0]
                                    if eth_base != bpdu_base:
                                        if len(session.stp_mac_mismatches) < 50:
                                            session.stp_mac_mismatches.append((ts, src_mac, bridge_mac))

                                # VLAN from System ID Extension (lower 12 bits of bridge priority)
                                vlan_id = bridge_prio & 0x0FFF
                                if vlan_id > 0:
                                    session.stp_vlans[vlan_id] += 1

                                # Port ID: 2 bytes at offset 25-26
                                port_id = int.from_bytes(stp_data[25:27], 'big')
                                session.stp_port_ids[f"0x{port_id:04x}"] += 1

                                # Timers at offsets 27-34 (each 2 bytes, in 1/256s units)
                                if len(stp_data) >= 35:
                                    msg_age = int.from_bytes(stp_data[27:29], 'big') // 256
                                    max_age = int.from_bytes(stp_data[29:31], 'big') // 256
                                    hello_time = int.from_bytes(stp_data[31:33], 'big') // 256
                                    fwd_delay = int.from_bytes(stp_data[33:35], 'big') // 256
                                    session.stp_timers['hello'][hello_time] += 1
                                    session.stp_timers['max_age'][max_age] += 1
                                    session.stp_timers['fwd_delay'][fwd_delay] += 1
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
                # Retransmission detection: same (src, dst, sport, dport, seq)
                # with payload seen before (exclude SYN-only)
                payload_len = len(tcp_data)
                if payload_len > 0 and not (tcp_obj.flags & dpkt.tcp.TH_SYN):
                    retx_key = (src_ip, dst_ip, sport, dport, tcp_obj.seq)
                    if retx_key in _seen_tcp_seqs_dpkt:
                        session.tcp_retransmissions += 1
                        conv_key_retx = (src_ip, dst_ip, dport, proto)
                        session.conv_health[conv_key_retx]["retransmit"] += 1
                    else:
                        _seen_tcp_seqs_dpkt[retx_key] = payload_len
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

            # SCADA JSON tag data (port 5672 / OASyS message bus)
            if (dport in _SCADA_MQ_PORTS or sport in _SCADA_MQ_PORTS) and tcp_data:
                _extract_scada_json_dpkt(tcp_data, session, src_ip, dst_ip, ts)

            # Syslog (UDP 514 summary stats)
            if proto == "UDP" and (dport == 514 or sport == 514) and tcp_data:
                _extract_syslog(tcp_data, session, src_ip)

            # SNMP community strings (UDP 161/162)
            if proto == "UDP" and dport in (161, 162) and tcp_data:
                _extract_snmp_community(tcp_data, session, src_ip)

            # SSH banner (port 22)
            if proto == "TCP" and (dport == 22 or sport == 22) and tcp_data:
                _extract_ssh_banner(tcp_data, session, src_ip, dst_ip, sport, ts)

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

            # ---------------------------------------------------------------
            # Netops: HSRP extraction (UDP port 1985)
            # ---------------------------------------------------------------
            if proto == "UDP" and dport == 1985:
                try:
                    hsrp_data = tcp_data  # reused var for UDP payload
                    if len(hsrp_data) >= 20:
                        _HSRP_STATES_DPKT = {0: "Initial", 1: "Learn", 2: "Listen",
                                             4: "Speak", 8: "Standby", 16: "Active"}
                        state = hsrp_data[2]
                        group = hsrp_data[5]
                        priority = hsrp_data[7]
                        vip = f"{hsrp_data[16]}.{hsrp_data[17]}.{hsrp_data[18]}.{hsrp_data[19]}"
                        state_name = _HSRP_STATES_DPKT.get(state, f"Unknown({state})")
                        if state in (0, 4):
                            session.hsrp_hello_count += 1
                        session.hsrp_events.append({
                            "src": src_ip, "group": group, "state": state_name,
                            "priority": priority, "vip": vip, "ts": ts,
                        })
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # Netops: VRRP extraction (IP protocol 112)
            # ---------------------------------------------------------------
            if ip.p == 112:
                try:
                    vrrp_data = bytes(ip.data)
                    if len(vrrp_data) >= 8:
                        vrid = vrrp_data[1]
                        priority = vrrp_data[2]
                        session.vrrp_advert_count += 1
                        session.vrrp_events.append({
                            "src": src_ip, "vrid": vrid,
                            "priority": priority, "ts": ts,
                        })
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # Netops: OSPF extraction (IP protocol 89)
            # ---------------------------------------------------------------
            if ip.p == 89:
                try:
                    ospf_data = bytes(ip.data)
                    if len(ospf_data) >= 24:
                        ospf_type = ospf_data[1]
                        router_id = f"{ospf_data[4]}.{ospf_data[5]}.{ospf_data[6]}.{ospf_data[7]}"
                        area_raw = ospf_data[8:12]
                        area_id = f"{area_raw[0]}.{area_raw[1]}.{area_raw[2]}.{area_raw[3]}"
                        session.ospf_total_count += 1
                        session.ospf_router_ids.add(router_id)
                        session.ospf_areas.add(area_id)
                        if ospf_type == 1:  # Hello
                            session.ospf_hello_count += 1
                            neighbor_key = (src_ip, dst_ip)
                            session.ospf_neighbor_hellos[neighbor_key].append(ts)
                        elif ospf_type == 2:  # DB Description
                            session.ospf_dbd_count += 1
                        elif ospf_type == 3:  # LS Request
                            session.ospf_lsrequest_count += 1
                        elif ospf_type == 4:  # LS Update
                            session.ospf_lsupdate_count += 1
                            session._ospf_lsupdate_timestamps.append(ts)
                        elif ospf_type == 5:  # LS Ack
                            session.ospf_lsack_count += 1
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # Netops: EIGRP extraction (IP protocol 88)
            # ---------------------------------------------------------------
            if ip.p == 88:
                try:
                    eigrp_data = bytes(ip.data)
                    if len(eigrp_data) >= 20:
                        opcode = eigrp_data[1]
                        as_num = int.from_bytes(eigrp_data[8:12], 'big')
                        session.eigrp_total_count += 1
                        if as_num > 0:
                            session.eigrp_as_numbers.add(as_num)
                        if opcode == 1:    # Update
                            session.eigrp_update_count += 1
                        elif opcode == 3:  # Query
                            session.eigrp_query_count += 1
                        elif opcode == 4:  # Reply
                            session.eigrp_reply_count += 1
                        elif opcode == 5:  # Hello
                            session.eigrp_hello_count += 1
                except Exception:
                    pass

    # --- Post-process: detect BPDU starvation (gaps > max_age per source port) ---
    _compute_stp_bpdu_gaps(session)

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
        "src": src_ip, "dst": dst_ip,
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

    for proto_name, ports, pattern, description in _CRED_PATTERNS:
        if ports is not None and dport not in ports and sport not in ports:
            continue
        if pattern is None:
            session.cleartext_creds_total += 1
            session.cleartext_creds.append({
                "protocol": proto_name, "description": description,
                "src": src_ip, "dst": dst_ip,
                "port": dport if (ports and dport in ports) else sport,
                "ts": ts,
            })
            return
        if pattern.search(payload):
            session.cleartext_creds_total += 1
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

# IT/OT service port labels (for flow enrichment, not deep parsing)
_SERVICE_PORTS: Dict[int, str] = {
    22: "SSH", 53: "DNS", 88: "Kerberos", 135: "DCE/RPC",
    139: "NetBIOS", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP",
    445: "SMB", 514: "Syslog", 636: "LDAPS", 3389: "RDP",
    5432: "PostgreSQL", 5672: "SCADA-MQ", 5985: "WinRM",
    5986: "WinRM-TLS",
}

# SCADA message-bus ports (JSON-over-TCP tag data, e.g., OASyS)
_SCADA_MQ_PORTS = {5672}

# Syslog severity names (RFC 5424)
_SYSLOG_SEVERITY = {
    0: "emerg", 1: "alert", 2: "crit", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# Syslog security-relevant pattern keywords
_SYSLOG_PATTERNS = [
    (re.compile(rb'(?i)fail|denied|invalid|reject|unauthorized'), "auth_failure"),
    (re.compile(rb'(?i)config|changed|modified|reload'), "config_change"),
    (re.compile(rb'(?i)up|down|link\s'), "interface_state"),
    (re.compile(rb'(?i)login|logged\s?in|session\s?open'), "login_event"),
    (re.compile(rb'(?i)blocked|drop|firewall'), "firewall_event"),
]

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
        "src": src_ip,
        "dst": dst_ip,
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

    session.ot_transactions.append(entry)


# ---------------------------------------------------------------------------
# SCADA message-bus JSON extraction (OASyS tag data on TCP port 5672 etc.)
# ---------------------------------------------------------------------------

_SCADA_JSON_RE = re.compile(rb'"ScadaDataSource"\s*:\s*"([^"]*)"')
_SCADA_TAG_RE = re.compile(rb'"Tag"\s*:\s*"([^"]*)"')
_SCADA_VAL_RE = re.compile(rb'"Value"\s*:\s*"([^"]*)"')
_SCADA_QUAL_RE = re.compile(rb'"Quality"\s*:\s*"([^"]*)"')
_MAX_SCADA_TAGS = 500
_MAX_VALUE_SAMPLES = 10


def _extract_scada_json(payload: bytes, session: Any,
                        src_ip: str, dst_ip: str, ts: float) -> None:
    """Extract SCADA tag data from JSON-over-TCP payloads."""
    if b'"ScadaDataSource"' not in payload:
        return
    tag_m = _SCADA_TAG_RE.search(payload)
    if not tag_m:
        return
    tag_name = tag_m.group(1).decode("utf-8", errors="replace")
    val_m = _SCADA_VAL_RE.search(payload)
    qual_m = _SCADA_QUAL_RE.search(payload)
    value = val_m.group(1).decode("utf-8", errors="replace") if val_m else None
    quality = qual_m.group(1).decode("utf-8", errors="replace") if qual_m else None

    session.scada_tag_sources[src_ip] += 1

    if tag_name in session.scada_tags:
        entry = session.scada_tags[tag_name]
        entry["count"] += 1
        if value and len(entry["values_sample"]) < _MAX_VALUE_SAMPLES:
            entry["values_sample"].append(value)
        if quality and quality != entry.get("quality"):
            entry["quality"] = quality  # track latest
    elif len(session.scada_tags) < _MAX_SCADA_TAGS:
        session.scada_tags[tag_name] = {
            "src": src_ip,
            "dst": dst_ip,
            "count": 1,
            "values_sample": [value] if value else [],
            "quality": quality or "unknown",
            "first_ts": ts,
        }


def _extract_scada_json_dpkt(tcp_data: bytes, session: Any,
                             src_ip: str, dst_ip: str, ts: float) -> None:
    """dpkt version — identical logic, different caller."""
    _extract_scada_json(tcp_data, session, src_ip, dst_ip, ts)


# ---------------------------------------------------------------------------
# Syslog extraction (condensed summary only — UDP 514)
# ---------------------------------------------------------------------------


def _extract_syslog(payload: bytes, session: Any, src_ip: str) -> None:
    """Extract syslog severity/facility and pattern counts from raw message."""
    session.syslog_total += 1
    session.syslog_sources[src_ip] += 1

    # RFC 5424 / RFC 3164: message starts with <PRI> where PRI = facility*8+severity
    if payload and payload[0:1] == b'<':
        end = payload.find(b'>', 1, 6)
        if end > 0:
            try:
                pri = int(payload[1:end])
                severity = pri & 0x07
                facility = pri >> 3
                session.syslog_severity[severity] += 1
                session.syslog_facilities[facility] += 1
            except (ValueError, IndexError):
                pass

    # Match security-relevant patterns
    for pattern, label in _SYSLOG_PATTERNS:
        if pattern.search(payload):
            session.syslog_patterns[label] += 1


# ---------------------------------------------------------------------------
# SSH banner extraction (port 22)
# ---------------------------------------------------------------------------

_SSH_BANNER_RE = re.compile(rb'^SSH-\d+\.\d+-\S+')


def _extract_ssh_banner(payload: bytes, session: Any,
                        src_ip: str, dst_ip: str, sport: int,
                        ts: float) -> None:
    """Capture SSH version banners from the first packet of a session."""
    if len(session.ssh_sessions) >= 200:
        return
    m = _SSH_BANNER_RE.match(payload)
    if m:
        banner = m.group(0).decode("utf-8", errors="replace")
        session.ssh_sessions.append({
            "src": src_ip, "dst": dst_ip, "src_port": sport,
            "ts": ts, "banner": banner,
        })


# ---------------------------------------------------------------------------
# SNMP community string extraction (UDP 161/162)
# ---------------------------------------------------------------------------


def _extract_snmp_community(payload: bytes, session: Any,
                            src_ip: str) -> None:
    """Extract SNMPv1/v2c community strings from raw payload."""
    session.snmp_sources[src_ip] += 1
    # SNMPv1/v2c: SEQUENCE → INTEGER(version) → OCTET STRING(community)
    # Minimal ASN.1 parse: look for version 0 or 1, then next octet-string
    if len(payload) < 10:
        return
    try:
        # payload[0] should be 0x30 (SEQUENCE)
        if payload[0] != 0x30:
            return
        # Find version field (INTEGER tag = 0x02)
        idx = 2  # skip SEQUENCE tag + length
        if payload[1] & 0x80:
            idx += (payload[1] & 0x7F)
        if idx >= len(payload) or payload[idx] != 0x02:
            return
        ver_len = payload[idx + 1]
        idx += 2 + ver_len
        # Next should be OCTET STRING (0x04) = community
        if idx >= len(payload) or payload[idx] != 0x04:
            return
        comm_len = payload[idx + 1]
        idx += 2
        if idx + comm_len <= len(payload):
            community = payload[idx:idx + comm_len].decode("ascii", errors="replace")
            if community and len(community) < 64:
                session.snmp_communities[community] += 1
    except (IndexError, ValueError):
        pass


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
            session.cleartext_creds_total += 1
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
            session.cleartext_creds_total += 1
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

    Modes: load, summary, conversations, dns, http, tls, timeline, ioc, networks
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
        valid_modes = ("load", "summary", "conversations", "dns", "http", "tls", "timeline", "ioc", "networks")
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
            elif mode == "networks":
                return self._networks(payload)
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
        if s.file_size:
            lines.append(f"  Size:      {_format_bytes(s.file_size)}")
        if s.bytes_transferred and s.bytes_transferred != s.file_size:
            lines.append(f"  Transferred: {_format_bytes(s.bytes_transferred)}")
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
        if s.file_size:
            lines.append(f"  Size:      {_format_bytes(s.file_size)}")
        if s.bytes_transferred and s.bytes_transferred != s.file_size:
            lines.append(f"  Transferred: {_format_bytes(s.bytes_transferred)}")
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
    # ----- networks -----
    def _networks(self, payload: dict[str, Any]) -> ToolResult:
        """List all /24 networks observed in the PCAP."""
        s = get_pcap_session()
        sort_by = payload.get("sort_by", "bytes")  # bytes | hosts | flows
        filter_type = payload.get("filter", "")     # int | ext | ot | ""

        net_stats: dict[str, dict] = defaultdict(lambda: {
            "ips": set(), "bytes": 0, "flows": 0,
        })
        for (src, dst, dport, proto), stats in s.conversations.items():
            for ip in (src, dst):
                parts = ip.rsplit(".", 1)
                if len(parts) == 2:
                    sn = f"{parts[0]}.0/24"
                    net_stats[sn]["ips"].add(ip)
            src_sn = ".".join(src.split(".")[:3]) + ".0/24"
            net_stats[src_sn]["bytes"] += stats.get("bytes_out", 0)
            net_stats[src_sn]["flows"] += 1

        # Filter
        if filter_type == "int":
            net_stats = {sn: s for sn, s in net_stats.items()
                         if is_internal(sn.split("/")[0])}
        elif filter_type == "ext":
            net_stats = {sn: s for sn, s in net_stats.items()
                         if not is_internal(sn.split("/")[0])}
        elif filter_type == "ot":
            ot_ips = set()
            for t in s.ot_transactions:
                ot_ips.add(t.get("src", ""))
                ot_ips.add(t.get("dst", ""))
            ot_nets = set()
            for ip in ot_ips:
                parts = ip.rsplit(".", 1)
                if len(parts) == 2:
                    ot_nets.add(f"{parts[0]}.0/24")
            net_stats = {sn: s for sn, s in net_stats.items()
                         if sn in ot_nets}

        # Sort
        sort_key = {
            "bytes": lambda x: x[1]["bytes"],
            "hosts": lambda x: len(x[1]["ips"]),
            "flows": lambda x: x[1]["flows"],
            "subnet": lambda x: tuple(int(o) for o in x[0].split("/")[0].split(".")),
        }.get(sort_by, lambda x: x[1]["bytes"])
        sorted_nets = sorted(net_stats.items(), key=sort_key, reverse=(sort_by != "subnet"))

        int_count = sum(1 for sn, _ in sorted_nets if is_internal(sn.split("/")[0]))
        ext_count = len(sorted_nets) - int_count

        lines = [
            f"=== Active /24 Networks ({len(sorted_nets)} total) ===",
            f"  Internal: {int_count}  |  External: {ext_count}",
            f"  Sorted by: {sort_by}"
            + (f"  |  Filter: {filter_type}" if filter_type else ""),
            "",
            f"  {'Subnet':<20} {'Hosts':<7} {'Flows':<8} {'Bytes':<12} {'Type'}",
            "  " + "-" * 60,
        ]

        for sn, st in sorted_nets:
            ip_base = sn.split("/")[0]
            if is_known_org(ip_base):
                loc = "ORG"
            elif is_internal(ip_base):
                loc = "INT"
            else:
                loc = "EXT"
            lines.append(
                f"  {sn:<20} {len(st['ips']):<7} {st['flows']:<8} "
                f"{_format_bytes(st['bytes']):<12} {loc}"
            )

        return ToolResult(ok=True, result={"text": "\n".join(lines)})

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
