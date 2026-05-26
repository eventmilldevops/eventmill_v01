# Log Navigator

**List, read, and inspect log files from local or cloud storage.**

## What It Does

Entry point for the analyst workflow. Three actions:

1. **list** — List files and subdirectories at a path, sorted with directories first
2. **read** — Read paginated segments of a log file with offset/limit
3. **metadata** — Get file size, modification time, and line count

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | — | — |
| Produced | `text`, `log_stream` | Log files for downstream tools |

## Output Persistence

On successful completion the framework automatically writes the result to:
```
workspace/artifacts/log_navigator_<YYYYMMDD_HHMMSS>.md
```
- **list** action: directory listing saved as markdown
- **read** action: the extracted file segment saved as markdown (useful for passing to `log_investigator` or `log_pattern_analyzer`)
- **metadata** action: file stats saved as markdown

The file is registered as a `text` session artifact. Use `artifacts` to get its ID.

## Example Usage

### List Directory
```json
{"action": "list", "path": "/workspace/artifacts", "prefix": "access", "max_results": 50}
```

### Read Segment (Pagination)
```json
{"action": "read", "path": "/workspace/artifacts/access.log", "offset_lines": 0, "line_limit": 100}
```

### Get Metadata
```json
{"action": "metadata", "path": "/workspace/artifacts/access.log"}
```

## Chains

- **To**: `log_pattern_analyzer`, `log_searcher`, `log_investigator`
