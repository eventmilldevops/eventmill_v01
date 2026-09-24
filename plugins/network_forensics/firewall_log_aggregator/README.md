# Firewall Log Aggregator

**Parses and aggregates firewall logs for statistical analysis.**

## What It Does

Ingests firewall logs (syslog, CSV, JSON) from Palo Alto, Fortinet, pfSense, iptables, and Windows Firewall. Aggregates traffic by source/destination, port, action (allow/deny), and time window.

Modes: `load`, `summary`, `top_talkers`, `deny_hotspots`, `port_scan`.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `log_file`, `text` | Firewall log file |
| Produced | `json_events`, `text` | Aggregated statistics |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/firewall_log_aggregator_<YYYYMMDD_HHMMSS>.json
```

## Example Usage

Arguments are passed as `--key value` flags.

### Load and Summarize
```
run firewall_log_aggregator --mode summary --file_path /workspace/artifacts/pa-firewall.log
```

### Force a Specific Log Format
```
run firewall_log_aggregator --mode summary --file_path /workspace/artifacts/fw.log --log_format fortinet_syslog
```

### Top Talkers
```
run firewall_log_aggregator --mode top_talkers --file_path /workspace/artifacts/fw.log --top_n 15
```

### Deny Hotspots / Port Scan Indicators
```
run firewall_log_aggregator --mode deny_hotspots --file_path /workspace/artifacts/fw.log --time_window_minutes 30
run firewall_log_aggregator --mode port_scan --file_path /workspace/artifacts/fw.log
```

**JSON alternative.**
```
run firewall_log_aggregator {"mode": "top_talkers", "file_path": "/workspace/artifacts/fw.log", "top_n": 15}
```

## Chains

- **To**: `pcap_threat_hunter`, `pcap_ai_analyzer`

## Notes

- No LLM dependency — `model_tier: none`, `safe_for_auto_invoke: true`
- `log_format: auto` (default) attempts vendor detection; set it explicitly if detection picks the wrong parser
- Unlike the `pcap_*` tools, this one does not depend on a loaded `PcapSession` — it reads the firewall log file directly
