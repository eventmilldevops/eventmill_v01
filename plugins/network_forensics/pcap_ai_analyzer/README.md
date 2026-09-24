# PCAP AI Analyzer

**AI-enhanced PCAP analysis — triage, threat hunting, reporting, plus OT/ICS and NetOps specialist modes.**

## What It Does

Wraps every static PCAP tool in this pillar with LLM intelligence, across four families of mode:

| Family | Modes | Purpose |
|---|---|---|
| General | `triage_summary`, `report` | SOC Tier 1/2 prioritization, C2 beacon hunting, executive summary, IOC extraction, shift handover |
| Hunt | `hunt_talkers`, `hunt_beacons`, `hunt_dns`, `hunt_tls`, `hunt_lateral`, `hunt_exfil` | LLM narrative + MITRE ATT&CK mapping on top of `pcap_threat_hunter`'s deterministic hunts |
| OT/ICS | `ot_triage`, `ot_threat_hunt`, `ot_report` | Specialized ICS security analyst persona — MITRE ATT&CK for ICS, Purdue Model zone-violation detection, safety impact assessment, IEC 62443 compliance |
| NetOps | `netops_triage`, `netops_health`, `netops_report` | Network performance/infrastructure health — TCP retransmissions, RST patterns, zero-window events, ICMP errors, IP fragmentation, TTL anomalies, DNS health, capacity indicators |

Supports **Condition Orange** mode (`condition_orange: true`) for heightened-alert investigations where false negatives are more costly than false positives. If a markdown/text file is loaded in the session (`load notes.md`), its content is auto-injected as investigation context. A network reference file loaded with `load --networks ipam.md` overrides port-based heuristics with real subnet-to-zone mappings in the Purdue traffic flow graph.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `pcap`, `json_events`, `text` | Requires a PCAP already loaded via `pcap_metadata_summary` |
| Produced | `json_events`, `text` | AI-generated analysis / report |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/pcap_ai_analyzer_<YYYYMMDD_HHMMSS>.json
```
Add `--export_type pdf` to also render the report as a PDF (the markdown report is always written regardless).

## Example Usage

Arguments are passed as `--key value` flags. `mode` is required.

### Triage Summary
```
run pcap_ai_analyzer --mode triage_summary
```

### Condition Orange Threat Hunt
```
run pcap_ai_analyzer --mode hunt_beacons --condition_orange
```

### OT/ICS Threat Hunt
```
run pcap_ai_analyzer --mode ot_threat_hunt
```

### NetOps Health Report With PDF Export
```
run pcap_ai_analyzer --mode netops_report --export_type pdf
```

### Passing Extra Parameters Through to a Hunt
```
run pcap_ai_analyzer {"mode": "hunt_exfil", "hunt_payload": {"min_ratio": 20, "min_bytes_out": 5242880}}
```

## Chains

- **From**: `pcap_threat_hunter`, `pcap_metadata_summary`

## Notes

- Requires an active LLM connection — `model_tier: heavy`, `requires_llm: true`, `safe_for_auto_invoke: false` (analyst-initiated only)
- `dependencies`: `pcap_metadata_summary`, `pcap_threat_hunter` must have data available first
- OT modes analyze Modbus, DNP3, S7comm, EtherNet/IP-CIP, OPC-UA, BACnet, and IEC-104 protocol data, plus cleartext credential exposure
- The `posture` command (see [framework/llm/postures/README.md](../../../framework/llm/postures/README.md)) changes the analysis stance this tool's LLM calls reason with — e.g. `posture paranoid for pcap_ai_analyzer`
