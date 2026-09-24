# PCAP Metadata Summary

**Core PCAP ingestion and summary — the entry point for every other network forensics tool.**

## What It Does

Parses a `.pcap`/`.pcapng` capture (via `scapy`, or `dpkt` in `--fast` mode) into an in-memory `PcapSession` singleton that every other tool in this pillar reads from. Extracts:

- Protocol distribution, IP endpoints, conversations (bidirectional flows)
- DNS queries/responses, HTTP requests, TLS handshakes (with SNI)
- OT/ICS protocol transactions — Modbus, DNP3, S7comm, EtherNet/IP-CIP, OPC-UA, BACnet, IEC-104
- Cleartext credential exposure (FTP, Telnet, HTTP basic auth, etc.)

Modes: `load`, `summary`, `conversations`, `dns`, `http`, `tls`, `timeline`, `ioc`, `networks`.

## Loading a Capture

The shell's `load` command is the normal entry point — it auto-detects `.pcap`/`.pcapng` and parses immediately:

```
load capture.pcap
load capture.pcap --fast          # dpkt parser, 5-10x faster for large captures
load /path/to/folder/ --merge     # cumulative load: merge every pcap in a folder into one session
load another.pcap --merge         # merge into the already-loaded session
```

Running `run pcap_metadata_summary --mode load --file_path <path>` directly does the same parse but skips the shell's auto-summary print.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `pcap` | Local file path or GCS URI |
| Produced | `json_events` | Summary / query results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/pcap_metadata_summary_<YYYYMMDD_HHMMSS>.json
```
Use `artifacts` to get its ID for downstream tools.

## Example Usage

Arguments are passed as `--key value` flags.

### Summary
```
run pcap_metadata_summary --mode summary
```

### Top Conversations
```
run pcap_metadata_summary --mode conversations --top_n 10 --sort_by bytes
```

### DNS / HTTP / TLS activity
```
run pcap_metadata_summary --mode dns
run pcap_metadata_summary --mode http
run pcap_metadata_summary --mode tls
```

### Timeline
```
run pcap_metadata_summary --mode timeline --top_n 50
```

**JSON alternative.**
```
run pcap_metadata_summary {"mode": "conversations", "top_n": 10, "sort_by": "bytes"}
```

## Chains

- **To**: `pcap_ip_search`, `pcap_flow_analyzer`, `pcap_threat_hunter` (all read the `PcapSession` this tool creates)

## Notes

- No LLM dependency — `model_tier: light`, `safe_for_auto_invoke: true`
- Every other network_forensics tool requires a PCAP to already be loaded via this tool (or the shell's `load`/`zeek load` commands) before they can run
- `--merge` accumulates packet counts, conversations, DNS/HTTP/TLS records, and OT transactions across multiple capture files into one session — useful for splitting a large capture or combining captures from multiple collection points
