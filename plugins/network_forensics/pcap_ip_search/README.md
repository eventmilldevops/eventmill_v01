# PCAP IP/IOC Search

**Search loaded PCAP data for IPs, domains, ports, or IOCs.**

## What It Does

Searches the in-memory `PcapSession` for indicators of compromise across conversations, DNS queries, HTTP requests, and TLS handshakes. Two modes:

1. **ioc** — Look up a single indicator (IP, domain, or port) and show every conversation, DNS record, HTTP request, or TLS SNI it appears in.
2. **timeline** — Chronological activity reconstruction for a host, with optional filters on source/destination IP, port, and protocol.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `pcap` | Requires a PCAP already loaded via `pcap_metadata_summary` |
| Produced | `json_events` | Search / timeline results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/pcap_ip_search_<YYYYMMDD_HHMMSS>.json
```

## Example Usage

Arguments are passed as `--key value` flags.

### IOC Lookup
```
run pcap_ip_search --mode ioc --query 192.168.1.100
run pcap_ip_search --mode ioc --query evil-domain.com
```

### Host Timeline
```
run pcap_ip_search --mode timeline --ip 10.0.0.55
```

### Filtered Timeline
```
run pcap_ip_search --mode timeline --src_ip 10.0.0.55 --dst_port 443 --proto TCP
```

**JSON alternative.**
```
run pcap_ip_search {"mode": "timeline", "ip": "10.0.0.55", "dst_port": 443}
```

## Chains

- **From**: `pcap_metadata_summary` (requires a loaded session)
- **To**: `pcap_flow_analyzer` (deep-dive a flow found here), `pcap_threat_hunter`

## Notes

- No LLM dependency — `model_tier: light`, `safe_for_auto_invoke: true`
- `timeout_class: fast` — this is the quickest of the pillar's tools, suited for interactive back-and-forth during an investigation
