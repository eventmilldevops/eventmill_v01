# Threat Report Analyzer

**Summarize threat intelligence reports from the common bucket into context for analysis tools.**

## What It Does

Reads threat intelligence reports (MITRE ATT&CK, CAPEC, CISA advisories, vendor bulletins, vendor PDFs) from the common bucket and generates 1500-2000 word markdown summaries for use as context in other analysis tools.

Handles large files (up to 50 MB / ~1,000 pages) using a chunked processing approach — content is split into segments, each summarized independently, then merged into a single coherent output.

Three actions:

1. **list_reports** — List available threat reports in the common bucket
2. **summarize** — Generate LLM-powered markdown summary of a specific report
3. **search_reports** — Search across report content for keywords

## Common Bucket Structure

Expected directory structure in the common bucket:

```
{prefix}-common/
├── mitre/                    # MITRE ATT&CK framework data
├── capec/                    # CAPEC attack patterns
├── cisa/                     # CISA advisories and KEV catalog
├── vendor_advisories/        # Vendor security bulletins
├── threat_actors/           # Threat actor profiles
├── campaigns/               # Threat campaign reports
└── vulnerabilities/         # CVE/vulnerability data
```

## Supported Input Formats

| Format | Extensions | Notes |
|--------|-----------|-------|
| PDF | `.pdf` | Full text extraction via pdfplumber; chunked for large reports |
| Word | `.docx`, `.doc` | Extracted via python-docx |
| JSON / STIX | `.json` | MITRE ATT&CK bundles, STIX 2.x |
| XML | `.xml` | CAPEC, CVRF, STIX 1.x |
| Markdown | `.md`, `.markdown` | Pre-processed summaries |
| Plain text | `.txt` | Raw advisories, bulletins |
| CSV | `.csv` | Structured IOC/vulnerability lists |

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | — | — (reads directly from common bucket or local reference data) |
| Produced | `text` | Markdown summaries for use by other tools |

## Output Persistence

The plugin writes summary files to the common bucket mirror path:
```
workspace/storage/<bucket>/generated/<report_name>.summary.md
```
For multi-chunk large files, individual chunk summaries are also written:
```
workspace/storage/<bucket>/generated/<report_name>.chunk_NNN.summary.md
```
The framework additionally registers the final summary as a `text` session artifact. Use `artifacts` to get its ID, then `load` it or pass it as input to `risk_assessment_analyzer` or `threat_model_analyzer`.

## Example Usage

### List Available Reports
```json
{"action": "list_reports"}
```

### Summarize a Report
```json
{"action": "summarize", "report_path": "mitre/enterprise-attack.json", "max_word_count": 2000}
```

### Summarize with Focus Areas
```json
{"action": "summarize", "report_path": "capec/capec-stix.xml", "focus_areas": ["attack_techniques", "mitigations"]}
```

### Search Reports
```json
{"action": "search_reports", "query": "ransomware"}
```

## LLM Integration

The summarize action requires an active LLM connection via `connect`. Without LLM, it returns the raw report content truncated to the first 50KB.

When LLM is connected, it generates structured markdown summaries with:
- Executive Summary
- Key Threat Actors/Techniques
- Relevant ATT&CK Techniques (with IDs)
- Detection Opportunities
- Recommended Security Controls

## Chains

- **To**: `risk_assessment_analyzer`, `attack_path_visualizer`
- **From**: — (entry point for threat intel workflow)

## Notes

- Supports PDF, DOCX, JSON, XML, Markdown, TXT, CSV, and STIX file formats
- Large files (up to 50 MB / ~1,000 pages) processed in chunks; each chunk is summarized individually and results merged
- Falls back to local `framework/reference_data/` directory when common bucket unavailable
- Extracts MITRE ATT&CK technique IDs (T1234 format) from summaries
- Maximum content passed to LLM per chunk: 50 KB (truncated for token limits)
