# PCAP Threat Hunter

**Threat hunting across loaded PCAP data with ICS awareness — no LLM required.**

## What It Does

A deterministic threat-hunting toolkit that operates entirely on the in-memory `PcapSession`:

| `hunt` | Detects |
|---|---|
| `talkers` | Top talkers by bytes/connections/packets |
| `ports` | Port classification against ICS/suspicious-port knowledge bases |
| `beacons` | C2 beaconing via inter-arrival time jitter analysis |
| `dns` | DGA domains (Shannon entropy) and DNS tunneling indicators |
| `tls` | TLS fingerprinting and certificate/SNI anomalies |
| `lateral` | Lateral movement — management port abuse, port scans, ICS cross-zone traffic |
| `exfil` | Data exfiltration indicators — asymmetric flows, DNS exfil |

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `pcap` | Requires a PCAP already loaded via `pcap_metadata_summary` |
| Produced | `json_events` | Hunt results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/pcap_threat_hunter_<YYYYMMDD_HHMMSS>.json
```

## Example Usage

Arguments are passed as `--key value` flags. `hunt` is required.

### Top Talkers
```
run pcap_threat_hunter --hunt talkers --top_n 15 --sort_by bytes
```

### C2 Beacon Detection
```
run pcap_threat_hunter --hunt beacons --min_connections 15 --max_jitter_pct 10
```

### DNS Anomalies (DGA / Tunneling)
```
run pcap_threat_hunter --hunt dns
```

### Exfiltration Indicators
```
run pcap_threat_hunter --hunt exfil --min_ratio 20 --min_bytes_out 5242880
```

**JSON alternative.**
```
run pcap_threat_hunter {"hunt": "beacons", "min_connections": 15, "max_jitter_pct": 10}
```

## Chains

- **From**: `pcap_metadata_summary`, `pcap_ip_search`
- **To**: `pcap_ai_analyzer` (wraps these hunts with LLM-driven MITRE ATT&CK mapping and hypothesis generation)

## Notes

- No LLM dependency — `model_tier: light`, `safe_for_auto_invoke: true`
- Every hunt is fully deterministic; `pcap_ai_analyzer` is the tool to reach for when you need narrative analysis or MITRE mapping on top of these results
