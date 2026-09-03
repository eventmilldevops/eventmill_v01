# Threat Intel Ingester

Event Mill plugin for ingesting threat intelligence reports and extracting structured IOC data.

## Purpose

Ingests threat intelligence reports (PDF, HTML, STIX, CSV/JSON IOC lists) and extracts structured IOC data with MITRE ATT&CK mapping.

For **PDF reports**, the plugin now supports **native PDF ingestion via the Gemini API** — the full PDF document is sent directly to the model, preserving tables, formatting, and cross-page context that text extraction loses. The plugin automatically selects the best ingestion path and falls back to chunked text extraction when native ingestion is unavailable.

## How to Run

### Prerequisites

1. **Gemini API keys** — set in your environment or deploy config:
   ```bash
   export GEMINI_FLASH_API_KEY="your-flash-key"
   export GEMINI_PRO_API_KEY="your-pro-key"
   ```
2. **Python dependencies** — installed via `pip install ".[plugins-log-analysis]"` from the project root.
3. **MITRE ATT&CK lookup** (one-time setup) — build the shared technique database:
   ```bash
   python scripts/build_mitre_lookup.py
   ```
   This downloads the Enterprise and ICS ATT&CK STIX bundles from the
   [MITRE CTI repository](https://github.com/mitre/cti) (currently pinned
   to **ATT&CK v19.2**) and writes a compact lookup file to
   `framework/reference_data/mitre_techniques.json` (~794 techniques).
   The shared MITRE module (`framework.reference_data.mitre_attack`) is
   used by this plugin and others to:
   - **Enrich** LLM output with authoritative technique names and tactics
   - **Backfill** technique IDs referenced in attack graphs but missing from mappings
   - **Validate** every technique ID and mark non-ATT&CK IDs with `(non-ATT&CK ID)`
     and `"mitre_validated": false` so analysts know when an ID was LLM-generated
   - **Validate tactics** against each technique's allowed tactics. Case
     differences are auto-corrected to the official spelling (e.g.
     "Command And Control" → "Command and Control"). Genuine mismatches
     are flagged with `"tactic_mismatch": true` in the output entry (see
     below).
   - **Migrate retired tactics.** ATT&CK v19 replaced "Defense Evasion"
     with "Stealth" and "Defense Impairment". When the LLM or an older
     artifact still says "Defense Evasion", the reconciler rewrites it to
     whichever successor the technique actually lists (T1027 → Stealth,
     T1553 → Defense Impairment). Occurrences it cannot resolve — an ID not
     in ATT&CK, or a technique allowing both successors — are left as-is
     and flagged as a mismatch. The tactic vocabulary and kill-chain order
     live in `framework.reference_data.mitre_attack` (`TACTIC_ORDER`,
     `LEGACY_TACTIC_ALIASES`) so every plugin shares one definition.

   ### Multi-Role Tactic Mappings

   The `mitre_mappings` array uses **`(technique_id, tactic)` as the identity
   key**. Consumers **must** consider both fields together — filtering or
   grouping by `technique_id` alone flattens the tactical context and loses
   the per-path role distinctions that the attack graph encodes.

   When the same technique serves different roles in different attack paths
   (e.g., T1078 as "Initial Access" in one path and "Persistence" in another),
   it appears as multiple entries with a `context_paths` field listing the
   attack-graph path IDs where each role was observed. Techniques with a
   single role produce a single entry as before — the change is purely additive.

   A **kill-chain progression rule** automatically reassigns entry-point-only
   tactics (Initial Access, Reconnaissance, Resource Development) on non-first
   attack-graph steps to the best alternative from the technique's valid
   tactics, preventing the MITRE matrix from being artificially flattened by
   repeated "Initial Access" labels.

   ### Tactic Correction and Mismatch Labeling

   After the LLM assigns tactics, the reconciler checks every label against
   the technique's official ATT&CK tactic list and resolves it in one of
   three ways. Only the last one needs a person.

   1. **Corrected automatically** — the entry gets `tactic_corrected_from`
      holding the LLM's original label. This happens when the label is
      unambiguously wrong:
      - a retired tactic ("Defense Evasion") whose technique lists exactly
        one of the v19 successors (T1027 → Stealth, T1553 → Defense
        Impairment);
      - one of the Stealth / Defense Impairment pair where the technique
        only allows the other (T1578.002 labelled Stealth → Defense
        Impairment);
      - a technique with a single valid tactic (T1490 labelled Defense
        Impairment → Impact). 633 of 794 techniques are single-tactic.
      Attack-graph steps are corrected the same way so nodes and mappings
      agree.
   2. **Case fixed** — "Command And Control" becomes "Command and Control".
   3. **Needs analyst review** — the technique has several valid tactics and
      the LLM chose none of them. The label is kept (it may describe the
      role the report gives the technique), and the entry is flagged with the
      options:

      ```json
      {
        "technique_id": "T1078",
        "tactic": "Lateral Movement",
        "mitre_validated": true,
        "tactic_mismatch": true,
        "allowed_tactics": ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"]
      }
      ```

      The run summary prints an `ACTION:` line listing these entries with
      their allowed tactics, `summary.tactic_mismatch_count` counts them, and
      `attack_path_visualizer` marks the node "tactic unconfirmed". To
      resolve one, read the report context for that step and either accept
      the label as the role described or pick one of `allowed_tactics`.

   - `mitre_validated: true` — the technique ID exists in ATT&CK.
   - `mitre_validated: false` — the ID is not in ATT&CK; the name is suffixed
     "(non-ATT&CK ID)". Treat as an LLM guess.

   Re-run the script after a new ATT&CK version is released to pick up new
   techniques. The plugin works without the file but skips enrichment and
   validation — a warning is logged on first use.

### Running in Event Mill

Arguments are passed as `--key value` flags.

```bash
# Start Event Mill
eventmill

# Load an artifact (PDF, HTML, or text file)
load /path/to/threat_report.pdf

# Check loaded artifacts — this prints the artifact ID to use below
artifacts

# Run the ingester on the loaded artifact
run threat_intel_ingester --artifact_id <artifact_id>

# With source context and a page cap
run threat_intel_ingester --artifact_id <artifact_id> --source_context "Mandiant M-Trends 2025" --max_pages 50

# Restrict the IOC types extracted (comma-separated list)
run threat_intel_ingester --artifact_id <artifact_id> --ioc_types ip,domain,cve

# Chain to attack_path_visualizer using the output artifact
run attack_path_visualizer --artifact_id <output_artifact_id> --format mermaid

# Export the JSON output to cloud storage
export <output_artifact_id>
```

The run summary prints the output artifact ID and the path it was written to.
`artifacts` lists them again at any time.

### Input Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `artifact_id` | **Yes** | — | ID of the loaded artifact to process |
| `source_context` | No | `""` | Describes the report source (e.g. "Mandiant M-Trends 2025") |
| `ioc_types` | No | ip, domain, hash_sha256, url, cve, mitre_technique | Which IOC types to extract |
| `confidence_threshold` | No | `"low"` | Minimum confidence to include: `low`, `medium`, `high` |
| `max_pages` | No | `50` | Maximum PDF pages to process (1–200) |

### Example Request

```
run threat_intel_ingester --artifact_id art_0001 --source_context "Mandiant M-Trends 2025 Report" --ioc_types ip,domain,hash_sha256,url,cve,mitre_technique --confidence_threshold low --max_pages 50
```

**JSON alternative.** Every tool also accepts a JSON payload. It is only
needed for list or object arguments that a flag cannot express:
```
run threat_intel_ingester {"artifact_id": "art_0001", "source_context": "Mandiant M-Trends 2025 Report", "ioc_types": ["ip", "domain", "hash_sha256", "url", "cve", "mitre_technique"], "confidence_threshold": "low", "max_pages": 50}
```

## Supported Artifact Types

**Consumed:**
- `pdf_report` — PDF threat intel reports, vendor advisories (**native Gemini ingestion**)
- `html_report` — HTML blog posts, advisories, CERT bulletins
- `text` — Plain text, CSV, STIX bundles

**Produced:**
- `json_events` — Structured IOC records

## PDF Processing Paths

The plugin uses a dual-path architecture for PDFs:

### Path 1: Native PDF Ingestion (preferred)

When the Gemini API is connected and supports native PDF, the full document is sent
directly to the model via `query_with_document()`. The dispatcher resolves the transport
automatically:

- **GCS URI** (`gs://...`) — zero-copy, the model reads directly from cloud storage
- **Inline bytes** — local file uploaded as raw bytes

The native path uses `QueryHints(tier="heavy", prefers_native_file=True)` and a single
LLM call with `max_tokens=8192`, eliminating the context loss from chunking.

The `LLMResponse.transport_path` field records which ingestion method was used.

### Path 2: Chunked Text Extraction (fallback)

If native ingestion is unavailable (no API connection, model doesn't support PDFs, or
the native call fails), the plugin falls back to:

1. Text extraction via `pdfplumber`
2. Paragraph-bounded chunking (~6000 chars per chunk)
3. Multiple `query_text()` calls with `QueryHints(tier="light")`
4. Result merging and deduplication across chunks

This path always works but may lose table formatting and cross-page context.

### Regex Pre-Scan

Both paths are preceded by a regex extraction pass that identifies IOC candidates.
For the native path, these candidates are included in the prompt so the model can
validate them against the full document. For the chunked path, candidates are batched
per chunk.

## Output Persistence

On successful completion the plugin writes the full IOC dataset to:
```
workspace/artifacts/<artifact_id>_ti_iocs.json
```
The file is registered as a `json_events` session artifact with the ID shown in the run summary (e.g., `Output artifact: art_04d30b48 (json_events)`). Use that ID directly as input to `attack_path_visualizer` via `artifact_id`. Use `export <artifact_id>` to push the JSON to `common/exports/threat_intel_ingester/` in cloud storage for external access or troubleshooting.

## LLM Dependency

**requires_llm: true**

This plugin uses the `LLMQueryInterface` from the execution context for:
- **Native PDF analysis** — full-document ingestion via `query_with_document()`
- **Capability detection** — `supports_native_document("application/pdf")` to choose path
- **Contextual IOC extraction** beyond regex patterns
- **Confidence scoring** and priority assessment
- **MITRE ATT&CK technique inference** and attack graph construction
- **False positive filtering**

All LLM calls pass `QueryHints` to guide model selection:
- Native PDF: `tier="heavy"`, `prefers_native_file=True`, `needs_structured_output=True`
- Chunked text: `tier="light"`, `needs_structured_output=True`

If the LLM connection is unavailable, the plugin falls back to regex-only extraction with low confidence scores.

## Example summarize_for_llm() Output

```
Ingested pdf_report (12 pages): APT29 Campaign Analysis. Attributed to APT29 (high confidence), campaign: SolarWinds Follow-on. Extracted 47 IOCs: 23 ips, 12 domains, 8 hash_sha256s, 4 cves. 3 IOCs flagged as high-priority. Mapped to 5 unique techniques across 7 tactical roles: T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1078 (Initial Access, Persistence), T1486 (Data Encrypted for Impact), T1048.003 (Exfiltration Over Unencrypted Protocol). Attack graph: 2 path(s) identified, converging at T1059.001. Output artifact: art_0002 (json_events). Quick chart: run attack_path_visualizer --artifact_id art_0002 --format mermaid
```

The **Quick chart** command at the end lets an analyst immediately generate a
Mermaid attack path diagram from the ingester output. Copy the command, adjust
the artifact ID if needed, and paste it into the Event Mill shell.

## Limitations

- Native PDF ingestion requires a live Gemini API connection with `GEMINI_PRO_API_KEY`
- Chunked fallback path may lose table formatting and cross-page context
- Maximum 200 pages per PDF (Gemini native limit: 1000 pages / 50 MB)
- LLM refinement adds latency (~5-15 seconds chunked, ~10-30 seconds native for large PDFs)
- STIX 2.1 parsing not yet implemented

## Safety Notes

**safe_for_auto_invoke: true**

This tool is read-only and low-risk. It processes local artifacts and makes external calls only to the Gemini API via the framework's LLM dispatcher.

## Dependencies

Beyond framework baseline:
- `pdfplumber>=0.10.0` (text extraction fallback)
- `beautifulsoup4>=4.12.0` (HTML processing)
- `stix2>=3.0.0` (for future STIX support)
- `google-genai>=1.0.0` (provided by framework — native PDF ingestion)

## Reference Data Overrides

- **`framework/reference_data/mitre_techniques.json`** — Shared ATT&CK technique
  lookup (Enterprise + ICS). Built by `scripts/build_mitre_lookup.py`. Accessed
  via `framework.reference_data.mitre_attack.get_mitre_db()`. See Prerequisites
  step 3 for setup instructions.
