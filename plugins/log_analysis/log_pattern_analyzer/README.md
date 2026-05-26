# Log Pattern Analyzer

**GROK/regex frequency analysis and automatic log structure discovery.**

## What It Does

Three analysis modes for investigating unfamiliar log files:

1. **GROK mode** — Named pattern frequency analysis (e.g., "show me top IPs" or "count HTTP status codes") using built-in GROK aliases like `IP`, `HTTPSTATUS`, `LOGLEVEL`.

2. **Regex mode** — Custom regex with capture group for advanced extraction and frequency counting.

3. **Discover mode** — Automatic structural signature generation that abstracts variable data (IPs, dates, UUIDs) into tokens. Solves the "blind analyst" problem when you don't know what kind of log you're looking at.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `log_stream` | Log files to analyze |
| Produced | `json_events` | Structured analysis results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/log_pattern_analyzer_<YYYYMMDD_HHMMSS>.json
```
The file is registered as a `json_events` session artifact. Use `artifacts` to get its ID. The discover mode result includes AI-identified log type and recommended next steps. Use `export <artifact_id>` to push the JSON to `common/exports/log_pattern_analyzer/` in cloud storage for external access or troubleshooting.

## Available GROK Patterns

`IP`, `IPV4`, `IPV6`, `MAC`, `EMAIL`, `UUID`, `HTTPSTATUS`, `HTTPMETHOD`, `LOGLEVEL`, `USER`, `USERNAME`, `PORT`, `PATH`, `URI`, `URIPATH`, `URL`, `TIMESTAMP`, `DATE`, `TIME`, `INT`, `NUMBER`, `WORD`, `HOSTNAME`, `SID`

## Example Usage

### Top Talkers (GROK)
```json
{"mode": "grok", "file_path": "/workspace/artifacts/access.log", "pattern": "IP", "limit": 10}
```

### Custom Regex
```json
{"mode": "regex", "file_path": "/workspace/artifacts/app.log", "pattern": "user=(\\w+)", "limit": 5}
```

### Discover Unknown Log
```json
{"mode": "discover", "file_path": "/workspace/artifacts/mystery.log", "ai_analysis": true}
```

## Chains

- **From**: `log_navigator` (file discovery and loading)
- **To**: `log_searcher` (search specific values found), `log_investigator` (deep-dive AI analysis)

## Limitations

- Processes local files only (cloud storage access via artifact registry)
- Regex mode requires a capture group for frequency counting
- AI analysis in discover mode requires an active LLM connection
