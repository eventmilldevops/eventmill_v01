# Log Searcher

**Search log files for text or regex patterns with context lines.**

## What It Does

Searches log files for matching lines using case-insensitive text or regex patterns. Returns matching lines with line numbers and optional surrounding context. Supports invert mode for exclusion filtering.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `log_stream` | Log files to search |
| Produced | `json_events` | Structured search results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/log_searcher_<YYYYMMDD_HHMMSS>.json
```
The file is registered as a `json_events` session artifact containing matched lines, line numbers, context, and match count. Use `artifacts` to get its ID, then pass it to `log_investigator` or `log_pattern_analyzer` for deeper analysis. Use `export <artifact_id>` to push the JSON to `common/exports/log_searcher/` in cloud storage for external access or troubleshooting.

## Example Usage

### Simple Text Search
```json
{"file_path": "/workspace/artifacts/app.log", "query": "ERROR", "max_results": 50}
```

### Regex Search with Context
```json
{"file_path": "/workspace/artifacts/app.log", "query": "ERROR.*(timeout|refused)", "mode": "regex", "context_lines": 2}
```

### Invert (Exclusion) Search
```json
{"file_path": "/workspace/artifacts/app.log", "query": "INFO", "invert": true}
```

## Chains

- **From**: `log_navigator`, `log_pattern_analyzer`
- **To**: `log_pattern_analyzer`, `log_investigator`
