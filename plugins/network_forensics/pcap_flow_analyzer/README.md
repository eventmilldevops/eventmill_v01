# PCAP Flow Analyzer

**Deep-dive TCP/UDP flow analysis with protocol reconstruction.**

## What It Does

Analyzes network flows in the loaded `PcapSession` with protocol-aware reconstruction:

1. **bidirectional** — Aggregates flows between host pairs, computes byte ratios (useful for spotting asymmetric/exfil-shaped traffic).
2. **long_connections** — Flags connections that stayed open beyond a duration threshold.
3. **protocol_breakdown** — Per-protocol breakdown (DNS, HTTP, TLS) for a scoped view of the capture.

Designed for detailed forensic examination of specific conversations already flagged by `pcap_metadata_summary` or `pcap_ip_search`.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `pcap`, `json_events` | Requires a PCAP already loaded via `pcap_metadata_summary` |
| Produced | `json_events` | Flow analysis results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/pcap_flow_analyzer_<YYYYMMDD_HHMMSS>.json
```

## Example Usage

Arguments are passed as `--key value` flags.

### Bidirectional Flows
```
run pcap_flow_analyzer --mode bidirectional --top_n 20
```

### Long-Duration Connections
```
run pcap_flow_analyzer --mode long_connections --min_duration_seconds 600
```

### Protocol Breakdown Scoped to One Host
```
run pcap_flow_analyzer --mode protocol_breakdown --filter_ip 10.0.0.55
```

**JSON alternative.**
```
run pcap_flow_analyzer {"mode": "long_connections", "min_duration_seconds": 600}
```

## Chains

- **From**: `pcap_metadata_summary`, `pcap_ip_search`
- **To**: `pcap_threat_hunter`, `pcap_ai_analyzer`

## Notes

- No LLM dependency — `model_tier: light`, `safe_for_auto_invoke: true`
- `filter_ip` scopes any mode to a single host's traffic — combine with a wide `top_n` for a full picture of one endpoint
