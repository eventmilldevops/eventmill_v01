# PCAP Report Correlator

**Correlates threat report IOCs against loaded PCAP data.**

## What It Does

A three-stage correlation engine (`sync_pcap`):

1. **extract** — Pulls IOCs (IPs, domains, hashes, etc.) out of a threat report (Markdown/text) using regex, or LLM-enhanced extraction with `use_ai_extraction`.
2. **correlate** — Matches extracted (or pre-supplied) IOCs against the loaded `PcapSession` — conversations, DNS, HTTP, TLS.
3. **full** — Runs both stages and returns a correlated result showing which IOCs were actually observed in the capture, with a full evidence chain per hit.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `pcap`, `text`, `markdown` | Requires a PCAP already loaded; report as inline text or a file |
| Produced | `json_events`, `text` | Correlation results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/pcap_report_correlator_<YYYYMMDD_HHMMSS>.json
```

## Example Usage

Arguments are passed as `--key value` flags.

### Full Pipeline From a Report File
```
run pcap_report_correlator --mode full --report_file /workspace/artifacts/threat_report.md
```

### Extract Only
```
run pcap_report_correlator --mode extract --report_text "C2 server observed at 45.33.12.9, domain evil-c2.net"
```

### Correlate Pre-Extracted IOCs
```
run pcap_report_correlator {"mode": "correlate", "iocs": [{"type": "ip", "value": "45.33.12.9"}, {"type": "domain", "value": "evil-c2.net"}]}
```

### AI-Enhanced Extraction
```
run pcap_report_correlator --mode full --report_file /workspace/artifacts/threat_report.md --use_ai_extraction
```

## Chains

- **From**: `pcap_metadata_summary`, `threat_report_analyzer` (threat_modeling pillar)
- **To**: `pcap_ai_analyzer`

## Notes

- `model_tier: light` — LLM use is opt-in via `use_ai_extraction`, otherwise fully deterministic regex extraction
- `iocs` (pre-extracted, structured) skips the extraction stage entirely — use this when IOCs already came from another tool
