# Network Forensics Analysis with Event Mill

A comprehensive guide covering PCAP ingestion, multi-layer analysis,
threat hunting, AI-driven insights, and Condition Orange alerting
within the Event Mill network forensics pillar.

---

## Prerequisites

- Event Mill installed and configured (`eventmill` command available)
- PCAP files (`.pcap` / `.pcapng`) uploaded to a GCS pillar bucket
  under a workspace folder, **or** available on the local filesystem
- A pillar bucket provisioned for `network_forensics`
  (e.g. `evtm_v01-network-forensics`)
- **Optional**: LLM connection via the `connect` command for AI-enhanced analysis tools

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [PCAP Processing — Ingestion & Parsing](#2-pcap-processing--ingestion--parsing)
3. [Zeek Cloud Build — Large PCAP Processing](#3-zeek-cloud-build--large-pcap-processing)
4. [Analysis Layer 1 — Static Summary Tools](#4-analysis-layer-1--static-summary-tools)
5. [Analysis Layer 2 — Threat Hunt Tools](#5-analysis-layer-2--threat-hunt-tools)
6. [Analysis Layer 3 — AI-Driven Insights](#6-analysis-layer-3--ai-driven-insights)
7. [OT/ICS Analysis Modes](#7-otics-analysis-modes)
8. [NetOps Infrastructure Health Modes](#8-netops-infrastructure-health-modes)
9. [Condition Orange — Heightened Alert Mode](#9-condition-orange--heightened-alert-mode)
10. [PCAP–Report Correlation (sync_pcap)](#10-pcapreport-correlation-sync_pcap)
11. [Export & Artifact System](#11-export--artifact-system)
12. [Plugin Mapping to eventmill_v01](#12-plugin-mapping-to-eventmill_v01)
13. [Example Investigation Workflow](#13-example-investigation-workflow)

---

## 1. Architecture Overview

The network forensics pillar operates in three analysis layers that
progressively deepen an investigation:

```text
┌──────────────────────────────────────────────────────────────────────┐
│                    NETWORK FORENSICS PILLAR                          │
│                                                                      │
│  Ingestion (3 paths — all produce identical PcapSession)             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────┐    │
│  │ Scapy Parser │  │ dpkt Parser  │  │ Zeek Cloud Build        │    │
│  │ (default)    │  │ (--fast,     │  │ (E2_HIGHCPU_32,         │    │
│  │ < 50 MB      │  │  5-10x fast) │  │  500GB, GCS → JSON logs)│    │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬──────────────┘    │
│         └────────────┬─────┘                     │                   │
│                      ▼                           ▼                   │
│         ┌─────────────────────────────────────────────┐              │
│         │          PcapSession (process-global)        │              │
│         │  conversations, DNS, HTTP, TLS, OT, ARP,    │              │
│         │  TCP health, ICMP, control plane, TTL        │              │
│         └──────────────────┬──────────────────────────┘              │
│                            │                                         │
│  Layer 1: Static Summary   │   Layer 2: Threat Hunt                  │
│  ┌────────────────────────┐│   ┌────────────────────────┐           │
│  │ pcap_metadata_summary  ││   │ pcap_threat_hunter     │           │
│  │  - Protocol stats      ││   │  - hunt_talkers        │           │
│  │  - IP endpoint map     ││   │  - hunt_ports          │           │
│  │  - DNS / HTTP / TLS    ││   │  - hunt_beacons (C2)   │           │
│  │  - Conversation table  ││   │  - hunt_dns (DGA)      │           │
│  │  - IOC search          ││   │  - hunt_tls            │           │
│  │  - Timeline by IP      ││   │  - hunt_lateral        │           │
│  └────────────┬───────────┘│   │  - hunt_exfil          │           │
│               │ chains_to  │   │  - sync_pcap           │           │
│               ▼            │   └────────────┬───────────┘           │
│  ┌────────────────────────┐│                │                        │
│  │ pcap_ip_search         ││   Layer 3: AI-Enhanced (14 modes)      │
│  │  - Filter by IP/port   ││   ┌────────────▼───────────┐           │
│  │  - Flow extraction     ││   │ pcap_ai_analyzer       │           │
│  └────────────┬───────────┘│   │                        │           │
│               │ chains_to  │   │  SOC:    triage_summary │           │
│               ▼            │   │          hunt_* (6)     │           │
│  ┌────────────────────────┐│   │          report         │           │
│  │ pcap_flow_analyzer     ││   │                        │           │
│  │  - TCP reconstruction  ││   │  OT/ICS: ot_triage     │           │
│  │  - DNS/HTTP/TLS detail ││   │          ot_threat_hunt │           │
│  │  - Protocol deep-dive  ││   │          ot_report      │           │
│  └────────────────────────┘│   │                        │           │
│                            │   │  NetOps: netops_triage  │           │
│                            │   │          netops_health  │           │
│                            │   │          netops_report  │           │
│                            │   └────────────────────────┘           │
│                                                                      │
│  Cross-cutting: Condition Orange (heightened alert toggle)            │
│  Artifact flow: pcap → json_events → text (reports) → PDF export     │
│  LLM routing: Flash (light tier) ↔ Pro (heavy tier)                  │
└──────────────────────────────────────────────────────────────────────┘
```

**Artifact types consumed**: `pcap`, `log_stream`, `text`
**Artifact types produced**: `json_events`, `text`

---

## 2. PCAP Processing — Ingestion & Parsing

### 2.1 The PcapSession Singleton

All PCAP data flows through a process-global session stored in
`sys._eventmill_pcap_sessions`. This avoids module-singleton
diverge issues between the plugin loader and the CLI shell. The
session is populated once during `load` and then queried by every
subsequent analysis tool via `get_pcap_session()`.

**Data structures stored in PcapSession:**

| Field | Type | Description |
|-------|------|-------------|
| `filename` | `str` | Name of the loaded PCAP file |
| `file_size` | `int` | Raw file size in bytes |
| `packet_count` | `int` | Total packets parsed |
| `start_time` / `end_time` | `float` | Capture time window |
| `duration_seconds` | `property` | Computed `end_time - start_time` |
| `protocols` | `Counter` | Protocol distribution (TCP, UDP, ICMP, ARP, …) |
| `conversations` | `dict` | Keyed by `(src_ip, dst_ip, dst_port, proto)` with byte/packet/time stats |
| `unique_ips` | `property` | All IP addresses observed (union of `src_ips` + `dst_ips`) |
| `src_ips` / `dst_ips` | `Counter` | Per-direction IP frequency |
| `src_ports` / `dst_ports` | `Counter` | Per-direction port frequency |
| `port_proto` | `dict` | Maps port numbers to protocol names |
| `dns_queries` | `list[dict]` | DNS query records: domain, source IP, resolved IPs, timestamps |
| `http_requests` | `list[dict]` | HTTP method, host, path, source/destination IPs, timestamps |
| `tls_handshakes` | `list[dict]` | TLS ClientHello: SNI, cipher suites, source/destination IPs |
| `ot_transactions` | `list[dict]` | OT/ICS protocol transactions (Modbus, DNP3, S7comm, BACnet, etc.) |
| `cleartext_creds` | `list[dict]` | Detected cleartext credentials (values redacted) |
| **TCP Health** | | |
| `tcp_syn_count` / `tcp_fin_count` | `int` | SYN and FIN packet counts |
| `tcp_rst_count` | `int` | RST packet count |
| `tcp_retransmissions` | `int` | Retransmitted TCP packets |
| `tcp_zero_window_count` | `int` | Zero-window events |
| `conv_health` | `dict` | Per-conversation RST, retransmit, zero-window counts |
| **ICMP & Routing** | | |
| `icmp_errors` | `list[dict]` | ICMP error messages (unreachable, TTL exceeded, redirects) |
| `ttl_exceeded_by_dest` | `dict` | TTL exceeded messages grouped by destination (loop detection) |
| `suspected_loop_packets` | `list[dict]` | Duplicate packets with different TTLs (loop evidence) |
| **ARP Health** | | |
| `arp_request_count` / `arp_reply_count` | `int` | ARP packet counts |
| `arp_gratuitous_count` | `int` | Gratuitous ARP count |
| `arp_ip_to_macs` | `dict` | IP → MAC mapping (detects IP conflicts) |
| `arp_requests_by_src` | `Counter` | ARP requests per source MAC (detects ARP floods) |
| **Control Plane** | | |
| `stp_bpdu_count` / `stp_tcn_count` | `int` | STP BPDU and Topology Change counts |
| `hsrp_hello_count` / `hsrp_state_changes` | `int` / `list` | HSRP events |
| `vrrp_advert_count` / `vrrp_priority_changes` | `int` / `list` | VRRP events |
| `ospf_total_count` / `ospf_hello_count` | `int` | OSPF packet counts |
| `eigrp_total_count` / `eigrp_query_count` | `int` | EIGRP packet counts |
| **IP Layer** | | |
| `ip_fragment_count` | `int` | Fragmented IP packets |
| `ttl_distribution` | `Counter` | TTL value distribution (OS fingerprinting) |

### 2.2 Three Parser Tiers

EventMill provides three parsers that all produce identical
`PcapSession` objects. Downstream analysis tools work the same
regardless of which parser loaded the data.

| Parser | When to Use | Speed | Invocation |
|--------|-------------|-------|------------|
| **Scapy** (streaming) | Default, < 50 MB | Baseline | `load captures/file.pcap` |
| **dpkt** (C-backed) | 50–500 MB | 5-10× faster | `load captures/file.pcap --fast` |
| **Zeek Cloud Build** | 500 MB+ / multi-GB | 32-vCPU VM | `zeek file.pcap` → `zeek load` |

#### Scapy Parser (default)

#### Scapy Parser (default)

The parser uses **scapy** to iterate packets in a single pass,
extracting metadata without holding full packet payloads in memory.
This allows analysis of large captures within the 50 MB file-size
limit (`MAX_PCAP_SIZE_BYTES`).

In addition to protocol metadata, the scapy parser extracts:

- **TCP flags** (SYN/FIN/RST/zero-window) for health analysis
- **ARP** requests/replies with MAC-to-IP mapping
- **ICMP errors** (unreachable, TTL exceeded, redirects)
- **IP fragmentation** and **TTL distribution**
- **Routing loop detection** via duplicate IP IDs with different TTLs
- **OT/ICS transactions** (Modbus function codes, DNP3, S7comm)
- **Cleartext credentials** (FTP, Telnet, HTTP Basic — values redacted)

**Key extraction logic:**

```python
# Pseudo-code — streaming parse loop
for packet in PcapReader(pcap_path):
    packet_count += 1
    ts = float(packet.time)

    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
        unique_ips.update([src, dst])

        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            key = (src, dst, dport, "TCP")
            conversations[key]["packets"] += 1
            conversations[key]["bytes_out"] += len(packet)

        # DNS layer extraction
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            query_name = packet[DNSQR].qname.decode()
            dns_queries.append({"query": query_name, "src": src, ...})

        # HTTP detection (port 80 or Raw payload starts with method)
        if packet.haslayer(Raw) and dport in (80, 8080):
            payload = packet[Raw].load.decode(errors="ignore")
            if payload.startswith(("GET ", "POST ", "PUT ", ...)):
                http_requests.append(parse_http(payload, src, dst))

        # TLS ClientHello (handshake type 0x01)
        if packet.haslayer(Raw) and dport == 443:
            raw = bytes(packet[Raw].load)
            if len(raw) > 5 and raw[0] == 0x16 and raw[5] == 0x01:
                sni = extract_sni(raw)
                tls_handshakes.append({"sni": sni, "src": src, ...})
```

**Internal IP classification** uses RFC 1918 ranges:

```python
def is_internal(ip: str) -> bool:
    """Check if IP is in private RFC 1918 space."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
    )
```

### 2.3 dpkt Parser (fast mode)

For PCAPs between 50–500 MB, the dpkt parser provides identical
output 5-10× faster using C-backed struct unpacking:

```
eventmill (network_forensics) > load large_capture.pcap --fast
  Using dpkt fast parser...
  ✓ 1,247,891 packets, 842 IPs, duration 8h 22m
```

The dpkt parser extracts the same metadata as scapy including
TCP health, ARP, ICMP errors, OT transactions, and credentials.

### 2.4 Loading a PCAP

The `load` command is the primary way to load PCAPs. It resolves
the file (local path, GCS URI, or pillar bucket lookup), registers
it as an artifact, and **auto-parses** it with scapy in a single
atomic operation:

```
eventmill (network_forensics) > load captures/incident.pcap
  Loaded artifact: art_7b2e9a4f
  Type: pcap
  File: incident.pcap
  Parsing PCAP with scapy...
  ✓ 48,293 packets, 142 IPs (18 internal, 124 external), duration 2h 14m 43s
  PCAP ready — use 'run pcap_metadata_summary {"mode": "summary"}' or any pcap tool.
```

Alternatively, use the `run` command directly:

```
eventmill (network_forensics) > run pcap_metadata_summary {"mode": "load", "file_path": "captures/incident.pcap"}
```

The loader handles both local filesystem paths and GCS URIs
(`gs://bucket/path/file.pcap`), downloading to a temp file for GCS
sources. A scapy monkey-patch is applied for IPv6 compatibility in
Docker/Cloud Run environments.

---

## 3. Zeek Cloud Build — Large PCAP Processing

For PCAPs larger than 500 MB (common in OT/ICS environments and
full packet captures from span ports), EventMill offloads processing
to Google Cloud Build with a dedicated Zeek container.

### 3.1 Architecture

```text
┌─────────────────┐     ┌──────────────────────┐     ┌───────────────┐
│ CLI: zeek submit │────▶│ Cloud Build           │────▶│ GCS Bucket    │
│ (gs:// or bare   │     │ E2_HIGHCPU_32         │     │ zeek-output/  │
│  filename)       │     │ 500GB disk            │     │ ├─ conn.log   │
└─────────────────┘     │ Zeek container         │     │ ├─ dns.log    │
                        │ 30–60 min timeout      │     │ ├─ ssl.log    │
                        └──────────────────────┘     │ ├─ http.log   │
                                                      │ ├─ notice.log │
                                                      │ └─ weird.log  │
                                                      └───────┬───────┘
                                                              │
                        ┌──────────────────────┐              │
                        │ CLI: zeek load        │◀─────────────┘
                        │ parse_zeek_logs()     │
                        │ → PcapSession         │
                        │ (identical to scapy)  │
                        └──────────────────────┘
```

### 3.2 CLI Commands

**Submit a PCAP for Zeek processing:**

```
eventmill (network_forensics) > zeek example_site.pcap
  Resolved: gs://gcp-project-id-eventmill-network-forensics/example_site.pcap
  ✓ Submitted Cloud Build job: 12a4b5c6-...
  Use 'zeek status' to monitor progress.
```

Bare filenames are auto-resolved from the default NF pillar bucket.
Full `gs://` URIs are also accepted.

**Submit asynchronously (don't wait):**

```
eventmill (network_forensics) > zeek massive_capture.pcap --async
  ✓ Submitted. Build ID: 12a4b5c6-...
  Monitor with: zeek status 12a4b5c6-...
```

**Check job status:**

```
eventmill (network_forensics) > zeek status
  Build 12a4b5c6: WORKING (elapsed: 4m 22s)
```

**Load Zeek output into PcapSession:**

```
eventmill (network_forensics) > zeek load
  Downloading Zeek logs from latest output...
  Parsing: conn.log, dns.log, ssl.log, http.log, notice.log, weird.log
  ✓ 29 log files parsed: 702 connections, 124 Modbus transactions, duration 45m
  PCAP session ready — all analysis tools available.
```

Optionally specify a folder: `zeek load example_site_20260518`

**List available Zeek outputs:**

```
eventmill (network_forensics) > zeek list
  example_site_20260518/   29 files   2.1 MB
  plant_b_20260510/       18 files   890 KB
```

**List submitted jobs:**

```
eventmill (network_forensics) > zeek jobs
  12a4b5c6  example_site.pcap     SUCCESS   7m 12s
  9f8e7d6c  plant_b.pcap         SUCCESS   3m 45s
```

### 3.3 Zeek Log Parsing

The Zeek loader (`zeek_loader.py`) reads JSON-format Zeek logs and
populates the same `PcapSession` object. All downstream tools
(threat hunter, AI analyzer, flow analyzer) work identically.

**Log files parsed:**

| Zeek Log | PcapSession Fields Populated |
|----------|------------------------------|
| `conn.log` | `conversations`, `src/dst_ips`, `protocols`, `ports`, `ot_transactions` |
| `dns.log` | `dns_queries`, `dns_responses` |
| `ssl.log` | `tls_handshakes` (includes JA3, cipher, cert info) |
| `http.log` | `http_requests` (includes user-agent, content-type) |
| `notice.log` | `cleartext_creds` (Zeek password/cleartext notices) |
| `weird.log` | `_zeek_weird` (protocol anomalies) |

**Note:** Zeek logs do not contain raw packet-level data (TCP flags,
ARP frames, ICMP raw headers), so netops health sections that rely
on these fields (TCP health indicators, ARP health, STP/OSPF/EIGRP)
will show "No traffic detected" when using Zeek-loaded sessions.
Conversations, DNS, bandwidth, and port distribution analysis work
fully.

### 3.4 Cost

Cloud Build charges only for actual **build time** (not queued time):

| Resource | Rate |
|----------|------|
| E2_HIGHCPU_32 build time | ~$0.016/min |
| GCS storage (Zeek output) | ~$0.020/GB/month |
| Minimum charge | 1 build-minute |

A typical OT PCAP (500 MB–2 GB) runs 5–15 minutes → **$0.08–$0.24**.

---

## 4. Analysis Layer 1 — Static Summary Tools

These tools provide deterministic, zero-LLM views of the parsed PCAP
data. They are fast, reproducible, and form the baseline for deeper
analysis.

### 4.1 pcap_summary — Protocol & Endpoint Overview

Returns protocol distribution, unique IP counts, top conversations
by bytes, and summary statistics for DNS/HTTP/TLS layers.

**Output structure:**

```
📊 PCAP Summary: incident.pcap
  Size: 12.4 MB | Packets: 48,293 | Duration: 2h 14m
  First: 2025-01-15 08:22:01 | Last: 2025-01-15 10:36:44

  Protocols:
    TCP     38,201 (79.1%)
    UDP      8,442 (17.5%)
    ICMP     1,290 (2.7%)
    ARP        360 (0.7%)

  Endpoints: 142 unique IPs (18 internal, 124 external)
  DNS: 2,841 queries to 1,204 unique domains
  HTTP: 847 requests
  TLS: 1,293 handshakes (948 unique SNIs)
```

### 4.2 pcap_conversations — Top Talkers Table

Displays the top N conversations sorted by bytes, packets, or
duration. Each row includes directional classification (INT→EXT,
INT→INT, EXT→INT).

```
#    Source IP        Dest IP          Port   Proto  Direction   Bytes        Packets
──── ──────────────── ──────────────── ────── ────── ─────────── ──────────── ────────
1    192.168.1.105    185.220.101.34   443    TCP    INT→EXT     4.2 GB       28,401
2    10.0.0.50        10.0.0.12        445    TCP    INT→INT     892.1 MB     12,044
3    192.168.1.22     8.8.8.8          53     UDP    INT→EXT     124.3 MB     8,201
```

### 4.3 pcap_dns — DNS Activity Aggregation

Groups DNS queries by domain, source IP, and resolved addresses.
Useful for baseline validation and spotting anomalous resolution
patterns.

### 4.4 pcap_http — HTTP Request Extraction

Lists all observed HTTP requests with method, host, path, and
timestamps. Highlights unusual methods (`PROPFIND`, `CONNECT`,
`TRACE`) that may indicate reconnaissance.

### 4.5 pcap_timeline — Chronological Activity by IP

Filters all activity for a specific IP address and presents a
chronological timeline of connections, DNS queries, and HTTP/TLS
events. Essential for reconstructing attacker movement.

### 4.6 pcap_ioc — Indicator of Compromise Search

Searches the parsed PCAP data for a specific IOC (IP address, domain
name, or port number) across all data stores — conversations, DNS
queries, HTTP requests, and TLS handshakes. Returns every match.

---

## 5. Analysis Layer 2 — Threat Hunt Tools

These tools apply security-specific heuristics to detect threats
that raw summaries miss. They use curated knowledge bases and
statistical analysis — no LLM required.

### 5.1 hunt_talkers — Volume-Based Anomaly Detection

Identifies the top N hosts by data volume, connection count, or
packet count. Classifies each as internal or external and flags
directional patterns that may indicate data exfiltration or C2.

### 5.2 hunt_ports — Port Analysis with ICS Awareness

Analyzes port usage against three knowledge bases:

| Knowledge Base | Contents |
|----------------|----------|
| **KNOWN_SERVICES** | Standard ports (22/SSH, 80/HTTP, 443/HTTPS, 53/DNS, …) |
| **ICS_PORTS** | Industrial protocol ports (502/Modbus, 102/S7comm, 44818/EtherNet-IP, 20000/DNP3, 47808/BACnet, 4840/OPC-UA, 2404/IEC-104) |
| **SUSPICIOUS_PORTS** | Known malware/tool ports (4444/Metasploit, 50050/Cobalt Strike, 1080/SOCKS proxy, 5555/Android ADB, 31337/Back Orifice, 6667/IRC C2) |

Output flags ports in each category with usage counts and associated
hosts.

### 5.3 hunt_beacons — C2 Beaconing Detection

Detects Command & Control beaconing patterns by analyzing
inter-arrival times between connections from the same internal host
to the same external destination.

**Detection algorithm:**

```
For each (internal_src, external_dst) pair with ≥ min_connections:
    1. Sort connection timestamps chronologically
    2. Calculate inter-arrival intervals
    3. Compute: mean_interval, std_deviation, jitter_percentage
    4. If jitter_pct ≤ max_jitter_pct → FLAG as potential beacon

    Jitter % = (std_deviation / mean_interval) × 100

    Low jitter (< 15%) = machine-generated timing = likely C2
```

Output example:

```
🔴 POTENTIAL C2 BEACONING — 3 candidate(s)

  192.168.1.105 → 185.220.101.34:443
    Connections: 142 | Mean interval: 60.2s | Jitter: 3.1%
    Duration: 2h 14m | Assessment: HIGH CONFIDENCE beacon

  10.0.0.22 → 91.195.240.94:8080
    Connections: 87 | Mean interval: 300.1s | Jitter: 8.7%
    Duration: 7h 15m | Assessment: MEDIUM CONFIDENCE beacon
```

### 5.4 hunt_dns — DNS Anomaly Analysis

Detects DNS-based threats using multiple heuristics:

- **DGA Detection**: Shannon entropy calculation on domain names.
  High-entropy labels (> 3.5 bits) suggest algorithmically generated
  domains.
- **DNS Tunneling Indicators**: Unusually long subdomain labels,
  high query rates to a single base domain, TXT record queries.
- **Frequency Analysis**: Domains queried more than a threshold
  number of times in the capture window.

```python
# Shannon entropy for DGA detection
def shannon_entropy(label: str) -> float:
    freq = Counter(label)
    length = len(label)
    return -sum(
        (count / length) * log2(count / length)
        for count in freq.values()
    )

# Flag if entropy > 3.5 and label length > 10
```

### 5.5 hunt_tls — TLS Fingerprinting

Analyzes TLS ClientHello messages for:

- SNI (Server Name Indication) distribution and anomalies
- Connections with **no SNI** — often indicates non-browser traffic
  or tunneling
- Cipher suite analysis and JA3 hash potential
- Certificate chain anomalies

### 5.6 hunt_lateral — Lateral Movement Detection

Detects east-west movement within the network:

1. **Management Port Scanning**: Internal-to-internal connections on
   SSH (22), RPC (135), NetBIOS (139), SMB (445), RDP (3389),
   WinRM (5985/5986), Telnet (23). Flags sources hitting > 5
   unique internal targets as potential scan activity.

2. **Port Scan Patterns**: Identifies single internal sources
   connecting to ≥ 5 internal hosts on the same destination port.

3. **ICS Cross-Zone Traffic**: Detects ICS protocol traffic
   (Modbus, S7comm, EtherNet/IP, DNP3, OPC-UA, BACnet, IEC-104)
   crossing the internal/external boundary — a critical violation
   in OT environments.

```
🟡 INTERNAL LATERAL MOVEMENT — 4 flow(s) on management ports
──────────────────────────────────────────────────────────────
  10.0.0.50 → 3 targets (SMB, RDP)
    → 10.0.0.12:445 (SMB) 12,044 pkts 892.1 MB
    → 10.0.0.15:445 (SMB) 1,201 pkts 45.2 MB
    → 10.0.0.20:3389 (RDP) 892 pkts 12.8 MB

🔴 ICS PROTOCOL CROSS-ZONE TRAFFIC
──────────────────────────────────────────────────────────
  185.220.101.34 (EXT) → 10.0.1.100 (INT):502 (Modbus) — 47 pkts
```

### 5.7 hunt_exfil — Data Exfiltration Detection

Identifies potential data exfiltration using:

1. **Asymmetric Flow Analysis**: Internal→external flows where
   outbound bytes exceed inbound by a configurable ratio (default
   10×) and outbound volume exceeds a minimum threshold (default
   1 MB). Reports byte counts, ratio, duration, and ports used.

2. **DNS Exfiltration**: Domains with an unusually high number
   of unique subdomain queries (> 20), suggesting data encoded
   in DNS query labels.

```
🔴 ASYMMETRIC OUTBOUND FLOWS — 2 suspect pair(s)
──────────────────────────────────────────────────────────────
  192.168.1.105 → 185.220.101.34
    Out: 4.2 GB  In: 12.3 MB  Ratio: 341x  Duration: 2h14m
    Ports: 443  Packets: 28,401

🟡 DNS EXFIL INDICATORS — high unique subdomain count
──────────────────────────────────────────────────────────────
  suspicious-c2.example.com — 847 unique subdomains queried
    a3f8b2c1.suspicious-c2.example.com
    7e4d9f01.suspicious-c2.example.com
    ... +845 more
```

---

## 6. Analysis Layer 3 — AI-Driven Insights

Every Layer 2 hunt tool has an AI-enhanced counterpart that pipes
the static output through a Gemini LLM with a role-appropriate system
prompt. AI tools require the `GEMINI_API_KEY` environment variable.

### 6.1 The AI Enhancement Pattern

All AI modes follow the same internal pattern in `pcap_ai_analyzer`:

```python
def execute(self, payload, context):
    mode = payload["mode"]
    condition_orange = payload.get("condition_orange", False)

    # Step 1: Build static output (runs threat hunts, builds PCAP header)
    static_output = self._get_static_output(session, mode, payload)

    # Step 2: Build prompt from template + alert condition
    prompt_template, _ = MODE_CONFIG[mode]
    alert_condition = self._get_alert_condition(condition_orange)
    prompt = prompt_template.format(
        system_identity=PCAP_SYSTEM_IDENTITY,
        alert_condition=alert_condition,
        pcap_summary_data=static_output,
    )

    # Step 3: Query LLM via the framework's client
    response = context.llm_query.query_text(
        prompt=prompt,
        system_context=PCAP_SYSTEM_IDENTITY,
        max_tokens=4096,
    )

    # Step 4: Combine static output + AI analysis
    combined = static_output + "\n\n" + AI_SEPARATOR + "\n" + response
```

The `context.llm_query` is an `MCPLLMClient` instance provided by the
framework. It uses the LLM Dispatcher for tiered routing — light
models (Flash) for small prompts, heavy models (Pro) for large ones.
Connect with the `connect` command before running AI tools.

### 6.2 Three Prompt Tiers

Each AI mode is routed to one of three analyst prompt constants
defined in `pcap_ai_analyzer/tool.py`:

| Prompt Constant | Persona | Used By |
|-----------------|---------|---------|
| `TRIAGE_PROMPT` | Tier 1/2 SOC Analyst — initial triage, priority ranking, C2 beacon hunting | `triage_summary`, `hunt_talkers` |
| `THREAT_HUNT_PROMPT` | Threat Hunter — MITRE ATT&CK mapping, hypothesis generation, evidence gathering | `hunt_beacons`, `hunt_dns`, `hunt_tls`, `hunt_lateral` |
| `REPORTING_PROMPT` | Senior Incident Responder — executive summary, IOC extraction, shift handover | `hunt_exfil`, `report` |
| `OT_TRIAGE_PROMPT` | OT/ICS Security Analyst — zone violations, unsafe operations, safety impact | `ot_triage`, `ot_threat_hunt` |
| `OT_REPORTING_PROMPT` | OT Incident Responder — MITRE ATT&CK for ICS, IEC 62443, remediation | `ot_report` |
| `NETOPS_TRIAGE_PROMPT` | Network Engineer — TCP health, DNS health, capacity anomalies | `netops_triage` |
| `NETOPS_HEALTH_PROMPT` | Infrastructure Analyst — routing, ARP, STP, OSPF/EIGRP deep analysis | `netops_health` |
| `NETOPS_REPORTING_PROMPT` | Ops Team Lead — health scorecard, recommendations, shift handover | `netops_report` |

### 6.3 AI Mode Catalog

All modes are accessed via `pcap_ai_analyzer` with a `mode` parameter:

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "<mode_name>"}
```

| Mode | Static Data Source | Prompt Tier | Purpose |
|------|-----------|-------------|---------|
| `triage_summary` | Comprehensive summary (all hunts) | Triage | AI-prioritized overview of entire PCAP |
| `hunt_talkers` | threat_hunter talkers | Triage | Anomaly detection across top talkers |
| `hunt_beacons` | threat_hunter beacons | Threat Hunt | C2 likelihood assessment, MITRE mapping |
| `hunt_dns` | threat_hunter dns | Threat Hunt | DGA classification, tunneling assessment |
| `hunt_tls` | threat_hunter tls | Threat Hunt | Suspicious SNI/cert pattern analysis |
| `hunt_lateral` | threat_hunter lateral | Threat Hunt | Kill chain stage mapping, response priority |
| `hunt_exfil` | threat_hunter exfil | Reporting | Severity assessment, IOC extraction, handover |
| `report` | Comprehensive summary (all hunts) | Reporting | Executive summary, IOC list, shift handover |
| `ot_triage` | OT static output | OT Triage | Zone violations, protocol anomalies, safety impact |
| `ot_threat_hunt` | OT static output | OT Triage | Unauthorized writes, rogue devices, IEC 62443 |
| `ot_report` | OT static output | OT Reporting | MITRE ATT&CK for ICS, remediation alignment |
| `netops_triage` | NetOps static output | NetOps Triage | TCP health, DNS health, capacity anomalies |
| `netops_health` | NetOps static output | NetOps Health | Routing, ARP, STP, OSPF/EIGRP deep analysis |
| `netops_report` | NetOps static output | NetOps Reporting | Health scorecard, recommendations |

### 6.4 Prompt Structure

Each prompt includes:

1. **PCAP System Identity** — establishes the AI as a SOC analyst
   working with exported network captures (read-only forensic data)
2. **Session Context** — recent analysis history for cross-tool
   continuity
3. **Alert Condition** — Normal or Condition Orange (see §6)
4. **Role-Specific Task** — analysis instructions for the specific
   prompt tier
5. **TL;DR Requirement** — every AI response must end with a
   prioritized summary

---

## 7. OT/ICS Analysis Modes

EventMill includes dedicated OT/ICS (Operational Technology /
Industrial Control Systems) analysis modes for environments running
Modbus, DNP3, S7comm, OPC-UA, BACnet, EtherNet/IP, or IEC-104.

### 7.1 OT Protocol Parsing

The PCAP parser extracts OT/ICS transactions at the application
layer, including:

| Protocol | Port | Extracted Fields |
|----------|------|-----------------|
| Modbus TCP | 502 | Unit ID, function code, read/write classification, exception status |
| DNP3 | 20000 | Function code, object headers |
| S7comm | 102 | PDU type, function code |
| EtherNet/IP | 44818 | Command code, session handle |
| BACnet | 47808 | Service choice |
| OPC-UA | 4840 | Message type |
| IEC-104 | 2404 | Type ID, cause of transmission |

OT transactions are stored in `PcapSession.ot_transactions` and
used by all three OT analysis modes.

### 7.2 OT System Identity

OT modes use a specialized `PCAP_OT_SYSTEM_IDENTITY` persona that
understands:

- Purdue Model zone classification (Level 0–5)
- ICS protocol semantics (read vs. write operations)
- Safety Instrumented Systems (SIS) impact
- IEC 62443 zone/conduit model
- MITRE ATT&CK for ICS framework

### 7.3 OT Analysis Modes

**ot_triage — Initial OT Incident Triage:**

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "ot_triage"}
```

Static output includes:
- Unique OT endpoints and protocols
- Write operations (function codes 5, 6, 15, 16 for Modbus)
- Control commands and diagnostics
- Zone violation detection (OT traffic crossing IT/OT boundary)

The LLM then assesses: safety impact, unauthorized device detection,
protocol anomalies, and immediate containment actions.

**ot_threat_hunt — OT Threat Hypothesis Generation:**

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "ot_threat_hunt"}
```

Generates three OT-specific threat hypotheses with evidence
gathering tasks, mapped to MITRE ATT&CK for ICS techniques.

**ot_report — OT Shift Handover:**

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "ot_report"}
```

Produces an executive summary with IEC 62443 alignment,
remediation recommendations, and safety impact assessment
suitable for OT operations teams.

### 7.4 Example: Modbus Write Detection

```
eventmill (network_forensics:example_site) > run pcap_ai_analyzer {"mode": "ot_triage"}

  ════════════════════════════════════════════════════════════
  OT / ICS PROTOCOL ANALYSIS
  ════════════════════════════════════════════════════════════

  Unique OT Endpoints:
    10.1.5.22 ↔ 10.1.5.100 (Modbus, port 502)
    10.1.5.22 ↔ 10.1.5.101 (Modbus, port 502)

  Write Operations (Modbus):
    FC6 (Write Single Register): 12 transactions
    FC16 (Write Multiple Registers): 3 transactions
    Source: 10.1.5.22 → 10.1.5.100, 10.1.5.101

  Control Commands:
    FC8 (Diagnostics): 2 transactions

  🔍 AI ANALYSIS
  [OT-specific assessment with safety impact, MITRE ICS mapping]
```

---

## 8. NetOps Infrastructure Health Modes

NetOps modes analyze network infrastructure health — TCP
performance, routing stability, ARP health, and control plane
protocols. These are designed for network engineering teams rather
than security analysts.

### 8.1 NetOps Static Analysis

The `_get_netops_static_output()` method produces deterministic
health analysis covering:

| Section | What It Analyzes |
|---------|-----------------|
| TCP Health Indicators | SYN/FIN/RST ratios, retransmissions, zero-window events, connection completion rate |
| Top Problem Conversations | Conversations ranked by RST + retransmit + zero-window count |
| ICMP Error Messages | Unreachable, TTL exceeded, redirects — grouped by type |
| Routing Loop Detection | ICMP TTL exceeded patterns, duplicate packets with different TTLs |
| ARP Health | Request/reply ratio, gratuitous ARP, IP conflicts, ARP storms, unanswered targets |
| Control Plane: STP | BPDUs, TCN count, root bridge stability, bridge enumeration |
| Control Plane: HSRP | Hello count, state transitions, group/VIP mapping |
| Control Plane: VRRP | Advertisement count, priority changes, VRID mapping |
| Control Plane: OSPF | Hello/DBD/LSUpdate counts, area/router IDs, neighbor gap detection, LSUpdate bursts |
| Control Plane: EIGRP | Hello/Update/Query/Reply counts, AS numbers, Stuck-In-Active detection |
| IP Fragmentation | Fragment count and percentage (MTU mismatch detection) |
| TTL Distribution | OS fingerprinting (Linux ~64, Windows ~128, network devices ~255), low-TTL alerts |
| DNS Health | Unanswered queries, top DNS clients |
| Top Bandwidth Consumers | Conversations ranked by bytes transferred |
| Long-Lived Connections | Connections > 5 minutes with duration and volume |
| Service Port Distribution | Known services, ICS ports, and unknown high ports |
| Subnet Anomaly Summary | Subnets ranked by composite health score (RSTs, retransmits, ICMP errors, loops, IP conflicts) |

### 8.2 NetOps Analysis Modes

**netops_triage — Quick Health Assessment:**

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "netops_triage"}
```

Provides a rapid assessment of network health: TCP performance,
DNS issues, and capacity anomalies. Best for initial triage of
network complaints.

**netops_health — Full Infrastructure Report:**

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "netops_health"}
```

Deep analysis of all infrastructure health indicators. The LLM
correlates issues across sections (e.g., "high OSPF LSUpdate bursts
coincide with elevated TCP retransmissions in subnet 10.1.5.0/24").

**netops_report — Ops Team Handover:**

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "netops_report"}
```

Produces a structured handover report with health scorecard,
prioritized recommendations, and root cause hypotheses.

### 8.3 Example: Infrastructure Health Check

```
eventmill (network_forensics:example_site) > run pcap_ai_analyzer {"mode": "netops_triage"}

  ════════════════════════════════════════════════════════════
  TCP HEALTH INDICATORS
  ════════════════════════════════════════════════════════════
  Overall TCP Health: HEALTHY
    Total TCP packets: 48,293
    SYN packets: 1,204
    FIN packets: 1,180
    RST packets: 24 (0.05%)
    Retransmissions: 147 (0.30%)
    Connection completion rate (FIN/SYN): 98.0%

  ════════════════════════════════════════════════════════════
  ARP HEALTH
  ════════════════════════════════════════════════════════════
    Total ARP packets: 360
    ARP Requests: 245
    ARP Replies: 115
    Request/Reply ratio: 2.1:1
    No IP address conflicts detected.

  ════════════════════════════════════════════════════════════
  SUBNET ANOMALY SUMMARY (ranked by impact)
  ════════════════════════════════════════════════════════════
    10.1.5.0/24    Score=42  RSTs=12  Retx=30  ICMP=0  IPs=8
    10.1.10.0/24   Score=8   RSTs=4   Retx=4   ICMP=0  IPs=3

  🔍 AI ANALYSIS
  [Network health assessment with root cause hypotheses]
```

### 8.4 Data Availability by Parser

| Health Section | Scapy/dpkt | Zeek |
|---------------|------------|------|
| TCP Health (SYN/FIN/RST) | ✅ Full | ❌ Not available |
| Conversation Health | ✅ Full | ❌ Not available |
| ICMP Errors | ✅ Full | ❌ Not available |
| Routing Loop Detection | ✅ Full | ❌ Not available |
| ARP Health | ✅ Full | ❌ Not available |
| STP/HSRP/VRRP | ✅ Full | ❌ Not available |
| OSPF/EIGRP | ✅ Full | ❌ Not available |
| IP Fragmentation / TTL | ✅ Full | ❌ Not available |
| DNS Health | ✅ Full | ✅ Full |
| Bandwidth Consumers | ✅ Full | ✅ Full |
| Long-Lived Connections | ✅ Full | ✅ Full |
| Service Port Distribution | ✅ Full | ✅ Full |
| Subnet Anomaly Summary | ✅ Full | Partial (no RST/retransmit data) |

For full netops analysis, load PCAPs with the scapy or dpkt parser.
Zeek-loaded sessions provide conversation-level and DNS analysis but
lack raw packet-level health metrics.

---

## 9. Condition Orange — Heightened Alert Mode

Condition Orange is a toggle that modifies the AI analysis posture
from evidence-based to paranoid. It is designed for active incident
response where false negatives are more costly than false positives.

### 9.1 How It Works

When `condition_orange=True` is passed to any AI-enhanced tool, the
system prompt receives this injection:

```
🚨 CONDITION ORANGE ACTIVE: The organization is in a heightened
state of alert. Be highly paranoid. Flag even slightly anomalous
behavior as potentially malicious. Connect weak signals and assume
the worst-case scenario.
```

When `condition_orange=False` (default), the prompt instead includes:

```
✅ NORMAL CONDITION: Base your analysis strictly on clear evidence.
Do not be overly cautious. If there is no solid evidence of a
threat, state so clearly.
```

### 9.2 Behavioral Difference

| Aspect | Normal Mode | Condition Orange |
|--------|-------------|-----------------|
| **Threshold** | High — require clear evidence | Low — flag anomalies aggressively |
| **Weak signals** | Noted but not escalated | Connected and escalated |
| **False positives** | Minimized | Accepted trade-off |
| **Tone** | Measured, evidence-based | Urgent, assume-breach |
| **Use case** | Routine triage, baseline | Active incident, known breach |

### 9.3 CLI Usage

Condition Orange is activated by setting `condition_orange` to `true`
in the JSON payload:

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "triage_summary", "condition_orange": true}
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "hunt_beacons", "condition_orange": true}
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "report", "condition_orange": true}
```

All fourteen AI modes accept the `condition_orange` flag:
`triage_summary`, `hunt_talkers`, `hunt_beacons`,
`hunt_dns`, `hunt_tls`, `hunt_lateral`, `hunt_exfil`,
`report`, `ot_triage`, `ot_threat_hunt`, `ot_report`,
`netops_triage`, `netops_health`, `netops_report`.

### 9.4 Implementation in eventmill_v01

In the plugin architecture, Condition Orange is passed through the
JSON payload or the `ExecutionContext.config` dictionary:

```python
# In pcap_ai_analyzer's execute() method:
def execute(self, payload: dict, context: ExecutionContext) -> ToolResult:
    condition_orange = payload.get("condition_orange", False)

    # Also check context.config (for future CLI flag support)
    if not condition_orange and hasattr(context, "config"):
        condition_orange = context.config.get("condition_orange", False)

    # Static analysis (Layer 2)
    static_output = self._get_static_output(session, mode, payload)

    # AI enhancement (Layer 3)
    if context.llm_enabled and context.llm_query:
        alert_condition = self._get_alert_condition(condition_orange)

        prompt = prompt_template.format(
            system_identity=PCAP_SYSTEM_IDENTITY,
            alert_condition=alert_condition,
            pcap_summary_data=static_output,
        )
        response = context.llm_query.query_text(
            prompt=prompt,
            system_context=PCAP_SYSTEM_IDENTITY,
            max_tokens=4096,
        )
        # Combine static output + AI analysis
        ...
```

---

## 10. PCAP–Report Correlation (sync_pcap)

The `sync_pcap` tool is a three-stage correlation engine that
bridges the gap between written incident reports (Markdown) and
raw network evidence (PCAP data).

### 10.1 Stage 1 — IOC Extraction from Markdown

Scans selected Markdown files (threat reports, analyst notes) and
extracts IOCs using regex patterns:

| IOC Type | Regex Pattern | Example Match |
|----------|---------------|---------------|
| IPv4 | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | `185.220.101.34` |
| MAC | `[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}` | `00:1a:2b:3c:4d:5e` |
| Domain | `[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | `malware-c2.example.com` |
| Port | `port\s*:?\s*(\d{1,5})` | `port 4444` |
| Timestamp | `\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}` | `2025-01-15T08:22:01` |

An optional AI-enhanced extraction mode
(`_extract_iocs_from_md_with_ai`) uses Gemini to perform semantic
IOC extraction that understands negative context (e.g., "this IP is
NOT malicious" will be excluded).

### 10.2 Stage 2 — PCAP Stream Matching

Re-streams through the loaded PCAP, matching each packet against the
extracted IOC set:

- **IP match**: Source or destination matches an extracted IP
- **MAC match**: Ethernet frame source/destination matches
- **Port match**: Destination port matches an extracted port
- **Domain match**: DNS query name matches an extracted domain
- **Temporal match**: Packet timestamp falls within ±5 minutes of
  an extracted timestamp

### 10.3 Stage 3 — Correlated Output

Results can be output in two modes:

- **Summary mode** (default): Grouped by IOC with match counts
  and first/last seen timestamps
- **Detailed mode** (`detailed=True`): Packet-by-packet correlation
  log showing each matched packet with its IOC match reason

```
📋 PCAP–REPORT CORRELATION RESULTS
════════════════════════════════════

IOC: 185.220.101.34 (IP)
  Matches: 142 packets
  First seen: 2025-01-15 08:22:15
  Last seen:  2025-01-15 10:36:41
  Ports: 443 (139), 80 (3)

IOC: suspicious-c2.example.com (Domain)
  Matches: 47 DNS queries
  First seen: 2025-01-15 08:23:01
  Sources: 192.168.1.105
```

---

## 11. Export & Artifact System

All analysis output can be exported as PDF, Markdown, or JSON
artifacts and stored locally or in GCS pillar buckets.

### 11.1 Export Types

| Export Type | Format | Usage |
|-------------|--------|-------|
| `pdf` | PDF document | `{"mode": "triage_summary", "export_type": "pdf"}` |
| `markdown` | Markdown text | Default output format |
| `json` | Structured JSON | Machine-readable results |
| `mermaid` | Mermaid diagram | Attack path / flow visualizations |

### 11.2 CLI Usage

**Export to PDF:**

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "report", "export_type": "pdf"}
  ✓ PDF exported: workspace/artifacts/sess_7b2e/art_a1b2c3d4.pdf
```

**Export to GCS:**

```
eventmill (network_forensics) > export art_a1b2c3d4
  Uploading to gs://gcp-project-id-eventmill-common/exports/pcap_ai_analyzer/art_a1b2c3d4.pdf
  ✓ Exported successfully.
```

**Export with subfolder:**

```
eventmill (network_forensics) > export art_a1b2c3d4 site_investigation
  → gs://.../exports/pcap_ai_analyzer/site_investigation/art_a1b2c3d4.pdf
```

### 11.3 Artifact Registry

Every tool run produces artifacts tracked in the session:

```
eventmill (network_forensics) > artifacts
  art_7b2e9a4f  pcap         incident.pcap                 12.4 MB
  art_a1b2c3d4  text         pcap_ai_analyzer_triage.md    24 KB
  art_f8e7d6c5  json_events  pcap_threat_hunter_beacons    8 KB
  art_3c4d5e6f  pdf_report   pcap_ai_analyzer_report.pdf   156 KB
```

---

## 12. Plugin Mapping to eventmill_v01

The following table maps the original `event_mill` network forensics
functions to the planned `eventmill_v01` plugin architecture:

| Original Tool | eventmill_v01 Plugin | Pillar | `requires_llm` | Status |
|----------------|---------------------|--------|-----------------|--------|
| `load_pcap` | `pcap_metadata_summary` | `network_forensics` | `false` | Implemented |
| `pcap_summary` | `pcap_metadata_summary` | `network_forensics` | `false` | Implemented |
| `pcap_conversations` | `pcap_metadata_summary` | `network_forensics` | `false` | Implemented |
| `pcap_dns` | `pcap_metadata_summary` | `network_forensics` | `false` | Implemented |
| `pcap_http` | `pcap_metadata_summary` | `network_forensics` | `false` | Implemented |
| `pcap_timeline` | `pcap_metadata_summary` | `network_forensics` | `false` | Implemented |
| `pcap_ioc` | `pcap_metadata_summary` | `network_forensics` | `false` | Implemented |
| `pcap_conversations` (flow) | `pcap_flow_analyzer` | `network_forensics` | `false` | Implemented |
| `hunt_talkers` | `pcap_threat_hunter` | `network_forensics` | `false` | Implemented |
| `hunt_ports` | `pcap_threat_hunter` | `network_forensics` | `false` | Implemented |
| `hunt_beacons` | `pcap_threat_hunter` | `network_forensics` | `false` | Implemented |
| `hunt_dns` | `pcap_threat_hunter` | `network_forensics` | `false` | Implemented |
| `hunt_tls` | `pcap_threat_hunter` | `network_forensics` | `false` | Implemented |
| `hunt_lateral` | `pcap_threat_hunter` | `network_forensics` | `false` | Implemented |
| `hunt_exfil` | `pcap_threat_hunter` | `network_forensics` | `false` | Implemented |
| `sync_pcap` | `pcap_report_correlator` | `network_forensics` | `false` | Implemented |
| `ai_pcap_summary` | `pcap_ai_analyzer` | `network_forensics` | `true` | Implemented |
| `ai_hunt_*` | `pcap_ai_analyzer` | `network_forensics` | `true` | Implemented |
| `ai_sync_pcap` | `pcap_ai_analyzer` | `network_forensics` | `true` | Implemented |
| Firewall logs | `firewall_log_aggregator` | `network_forensics` | `false` | Planned |

### 12.1 Proposed Plugin Manifest (pcap_threat_hunter)

```json
{
  "tool_name": "pcap_threat_hunter",
  "version": "1.0.0",
  "pillar": "network_forensics",
  "display_name": "PCAP Threat Hunter",
  "description_short": "Threat hunting across loaded PCAP data with ICS awareness.",
  "description_long": "Comprehensive threat hunting toolkit for parsed PCAP data. Includes top talker analysis, port classification with ICS/suspicious knowledge bases, C2 beaconing detection via jitter analysis, DNS anomaly detection (DGA, tunneling), TLS fingerprinting, lateral movement detection, and data exfiltration indicators. All tools operate on the in-memory PcapSession without LLM dependency.",
  "author": "Event Mill Contributors",
  "entry_point": "tool.py",
  "class_name": "PcapThreatHunter",
  "artifacts_consumed": ["pcap"],
  "artifacts_produced": ["json_events"],
  "capabilities": [
    "network_forensics:threat_hunt",
    "network_forensics:c2_detection",
    "network_forensics:lateral_movement",
    "network_forensics:exfil_detection",
    "network_forensics:ics_awareness"
  ],
  "input_schema": "schemas/input.schema.json",
  "output_schema": "schemas/output.schema.json",
  "timeout_class": "medium",
  "cost_hint": "low",
  "model_tier": "light",
  "safe_for_auto_invoke": true,
  "requires_llm": false,
  "dependencies": ["pcap_metadata_summary"],
  "stability": "stable",
  "tags": ["threat_hunt", "c2", "beaconing", "lateral", "exfil", "ics", "dga"],
  "chains_to": ["pcap_ai_analyzer"],
  "chains_from": ["pcap_metadata_summary", "pcap_ip_search"]
}
```

### 12.2 Proposed Plugin Manifest (pcap_ai_analyzer)

```json
{
  "tool_name": "pcap_ai_analyzer",
  "version": "1.0.0",
  "pillar": "network_forensics",
  "display_name": "PCAP AI Analyzer",
  "description_short": "AI-enhanced PCAP analysis with Condition Orange support.",
  "description_long": "Wraps all static PCAP analysis and threat hunt tools with Gemini LLM intelligence. Provides three analysis tiers: triage (prioritization), threat hunt (MITRE ATT&CK mapping, hypothesis generation), and reporting (IOC extraction, shift handover). Supports Condition Orange mode for heightened alert investigations.",
  "author": "Event Mill Contributors",
  "entry_point": "tool.py",
  "class_name": "PcapAiAnalyzer",
  "artifacts_consumed": ["pcap", "json_events"],
  "artifacts_produced": ["json_events", "text"],
  "capabilities": [
    "network_forensics:ai_analysis",
    "network_forensics:triage",
    "network_forensics:mitre_mapping",
    "network_forensics:ioc_extraction",
    "network_forensics:condition_orange"
  ],
  "input_schema": "schemas/input.schema.json",
  "output_schema": "schemas/output.schema.json",
  "timeout_class": "long",
  "cost_hint": "medium",
  "model_tier": "heavy",
  "safe_for_auto_invoke": false,
  "requires_llm": true,
  "dependencies": ["pcap_metadata_summary", "pcap_threat_hunter"],
  "stability": "stable",
  "tags": ["ai", "triage", "mitre", "ioc", "condition_orange", "report"],
  "chains_to": [],
  "chains_from": ["pcap_threat_hunter", "pcap_metadata_summary"]
}
```

---

## 13. Example Investigation Workflow

### Step 1 — Session & Pillar Setup

```
eventmill > new Investigate suspicious PCAP from DMZ firewall
  Created session: sess_7b2e9a4f1c08

eventmill (no-pillar) > pillar network_forensics
  Pillar set to: network_forensics (7 tools available)
```

### Step 2 — Load and Survey the Capture

```
eventmill (network_forensics) > load dmz_capture.pcap
  Loaded artifact: art_7b2e9a4f
  Type: pcap
  File: dmz_capture.pcap
  Parsing PCAP with scapy...
  ✓ 124,891 packets, 142 IPs (18 internal, 124 external), duration 2h 14m 43s
  PCAP ready — use 'run pcap_metadata_summary {"mode": "summary"}' or any pcap tool.

eventmill (network_forensics) > run pcap_metadata_summary {"mode": "summary"}
  📊 124,891 packets | 142 unique IPs | 2,841 DNS queries
```

### Step 3 — Threat Hunt Sweep

```
eventmill (network_forensics) > run pcap_threat_hunter {"hunt": "beacons"}
  🔴 POTENTIAL C2 BEACONING — 3 candidate(s)
  ...

eventmill (network_forensics) > run pcap_threat_hunter {"hunt": "lateral"}
  🟡 INTERNAL LATERAL MOVEMENT — 4 flow(s) on management ports
  ...

eventmill (network_forensics) > run pcap_threat_hunter {"hunt": "dns"}
  🟡 DGA CANDIDATES — 12 high-entropy domains
  ...
```

### Step 4 — AI-Enhanced Deep Dive

```
eventmill (network_forensics) > connect
  ✓ Connected to Gemini Flash (gemini-2.5-flash)

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "hunt_beacons"}
  [PCAP header + beaconing data + 🔍 AI ANALYSIS with MITRE ATT&CK mapping]

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "hunt_beacons", "condition_orange": true}
  [Same but with Condition Orange — paranoid assessment]
```

### Step 5 — Correlate with Threat Report

```
eventmill (network_forensics) > run pcap_report_correlator {"files": ["dragos_report.md"]}
  📋 PCAP–REPORT CORRELATION RESULTS
  IOC: 185.220.101.34 — 142 packets matched
  IOC: suspicious-c2.example.com — 47 DNS queries matched
```

### Step 6 — Generate Shift Handover

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "report", "condition_orange": true}
  [Executive summary, IOC list, immediate actions, caveats]
```

### Step 7 — Export PDF Report

```
eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "report", "export_type": "pdf"}
  ✓ PDF exported: workspace/artifacts/sess_7b2e/art_f1e2d3c4.pdf

eventmill (network_forensics) > export art_f1e2d3c4
  ✓ Uploaded to GCS.
```

---

### Alternative: OT/ICS Investigation (Zeek + OT modes)

For large OT PCAPs from span ports or network taps:

```
eventmill (network_forensics) > zeek example_site_capture.pcap
  ✓ Submitted Cloud Build job. Use 'zeek status' to monitor.

  [... wait for completion ...]

eventmill (network_forensics) > zeek load
  ✓ 29 log files parsed: 702 connections, 124 Modbus transactions

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "ot_triage"}
  [OT endpoints, write operations, zone violations, AI assessment]

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "ot_threat_hunt"}
  [Three OT threat hypotheses with MITRE ICS mapping]

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "ot_report", "export_type": "pdf"}
  [OT shift handover with IEC 62443 alignment, exported as PDF]
```

### Alternative: Network Health Check (NetOps modes)

For network performance troubleshooting:

```
eventmill (network_forensics) > load span_port_capture.pcap
  ✓ 248,000 packets, 45 IPs, duration 1h 15m

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "netops_triage"}
  [TCP health, ARP health, DNS health, subnet anomaly summary]

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "netops_health"}
  [Full infrastructure report: OSPF, STP, HSRP, routing loops, fragmentation]

eventmill (network_forensics) > run pcap_ai_analyzer {"mode": "netops_report", "export_type": "pdf"}
  [Health scorecard with prioritized recommendations]
```

---

## Reference: Source File Mapping

For developers porting logic from the original `event_mill`
codebase:

| Original File | Key Functions | Target Plugin |
|----------------|---------------|---------------|
| `tools/pcap_parser.py` | `PcapSession`, `parse_pcap_file()`, `load_pcap`, `pcap_summary`, `pcap_conversations`, `pcap_dns`, `pcap_http`, `pcap_timeline`, `pcap_ioc`, `ai_pcap_summary` | `pcap_metadata_summary`, `pcap_ip_search`, `pcap_ai_analyzer` |
| `tools/pcap_hunting.py` | `hunt_talkers`, `hunt_ports`, `hunt_beacons`, `hunt_dns`, `hunt_tls`, `hunt_lateral`, `hunt_exfil`, `sync_pcap`, `ai_hunt_*` | `pcap_threat_hunter`, `pcap_report_correlator`, `pcap_ai_analyzer` |
| `system_context.py` | `PCAP_TRIAGE_PROMPT`, `PCAP_THREAT_HUNT_PROMPT`, `PCAP_REPORTING_AND_IOC_PROMPT`, `get_pcap_triage_prompt()`, `get_pcap_threat_hunt_prompt()`, `get_pcap_reporting_prompt()` | `pcap_ai_analyzer` (embedded or `data/` dir) |
| `conversational_client.py` | `--orange` flag parsing, tool dispatch | CLI shell (`framework/cli/shell.py`) |
