# Log Investigator

**AI-powered threat investigation and SOC analyst workflows.**

## What It Does

Two modes for security-focused log analysis:

1. **investigate** — Targeted search for a term (IP, user, error) combined with LLM-powered threat intelligence analysis including MITRE ATT&CK mapping, severity assessment, and recommended actions.

2. **workflow** — Predefined SOC analyst workflows:
   - `top_talkers` — Frequency analysis of IPs, HTTP methods, status codes
   - `investigate_ip` — Find all activity for a specific IP address
   - `security_events` — Scan for HTTP errors, suspicious methods, SQLi, XSS attempts
   - `attack_patterns` — Auto-discover structural log patterns

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `log_stream` | Log files to investigate |
| Produced | `json_events` | Investigation results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/log_investigator_<YYYYMMDD_HHMMSS>.json
```
The file is registered as a `json_events` session artifact. Use `artifacts` to get its ID, then pass it as `artifact_id` to downstream tools such as `attack_path_visualizer`. Use `export <artifact_id>` to push the JSON to `common/exports/log_investigator/` in cloud storage for external access or troubleshooting.

## Example Usage

### AI Investigation
```json
{"mode": "investigate", "file_path": "/workspace/artifacts/access.log", "search_term": "192.168.1.100"}
```

### SOC Workflow — Top Talkers
```json
{"mode": "workflow", "file_path": "/workspace/artifacts/access.log", "workflow_type": "top_talkers"}
```

### SOC Workflow — Investigate IP
```json
{"mode": "workflow", "file_path": "/workspace/artifacts/access.log", "workflow_type": "investigate_ip", "target": "10.0.0.55"}
```

## Chains

- **From**: `log_navigator`, `log_searcher`, `log_pattern_analyzer`

## Notes

- Full AI investigation requires an active LLM connection via ExecutionContext
- Without LLM, investigate mode still returns matched log lines
- `safe_for_auto_invoke` is false — investigation should be analyst-initiated
