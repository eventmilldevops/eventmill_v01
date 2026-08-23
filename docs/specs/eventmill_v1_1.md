# Event Mill V1 — Coding Agent Grounding Document

Version: 0.2.0-draft
Last updated: 2026-03-14

---

## 1. Strategic Context

This section provides positioning context. It is not actionable by the coding agent directly but establishes the boundaries of what Event Mill is and is not.

Event Mill is an open-source event record analysis platform for Security Operations and Detection Engineering teams. It does not try to be an open-source SIEM. It lives upstream of the SIEM — in the gap between "we just got access to a new event source" and "we have a parser, field mappings, and detection rules in production."

In the detection engineering lifecycle this is the **analysis-before-commitment phase**, currently handled ad hoc with Python scripts, jq, Wireshark, CyberChef, and manual reading. No open-source project cleanly owns this problem.

Event Mill's two value propositions:

1. **New source triage**: Speed up the initial analysis of an unfamiliar event source to determine whether it contains enough security-relevant information to warrant investing engineering resources in parsing, ingestion, and detection rule development.

2. **Incident-time analysis**: During an incident, analysts and investigators frequently receive event artifacts (logs, PCAPs, audit exports) for systems they are not deeply familiar with. Event Mill helps them gain context quickly without requiring full knowledge of the event record structure.

The tool is fashioned after the Metasploit CLI: a technician's workbench, not a dashboard product. There may be a commercial opportunity later but for now this is an open-source platform built in a modular fashion to allow forking and extension.

---

## 2. Architecture Overview

Event Mill uses a three-layer separation. Each layer has a distinct responsibility. Code in one layer MUST NOT contain logic belonging to another layer.

### 2.1 Framework Layer

The framework layer provides the runtime environment. It contains:

- **CLI interface**: Metasploit-style command shell with tab completion, help screens, and user input handling. The CLI supports both interactive commands (selecting files, choosing tools, setting options) and conversational LLM interaction for guided interrogation of loaded artifacts.
- **Session management**: Tracks the current investigation state including active pillar, loaded artifacts, tool execution history, and conversation context. Session state is persisted to local SQLite (see section 6).
- **LLM orchestration**: Manages the MCP client connection, constructs prompts from tool context and common reference data, and routes LLM responses back to the user or to tool inputs (see section 5).
- **Common reference data**: Shared dictionaries and knowledge bases available to all tools. These are loaded at startup from JSON files stored in a `framework/reference_data/` directory. Initial reference data includes:
  - MITRE ATT&CK taxonomy (Enterprise, ICS)
  - Common attack chain patterns
  - Curated URL lists for vetted threat intelligence sources, security research blogs, and regulatory bodies
  - Any other context artifacts that are useful across multiple tools rather than specific to one plugin
- **Artifact registry**: Tracks all investigation artifacts in the current session (see section 7).
- **Plugin lifecycle**: Discovery, validation, loading, and execution of plugins (see `tool_plugin_spec.md` for the normative contract).
- **Logging**: Structured investigation logging for audit and review (see section 8).

The framework layer MUST NOT contain tool-specific analysis logic.

### 2.2 Plugin Layer

Plugins are small, purpose-built tools following the UNIX philosophy: do one thing well. Each plugin performs a specific analysis function and conforms to the EventMillToolProtocol contract defined in `tool_plugin_spec.md` (normative specification).

Key plugin characteristics:

- Plugins declare their capabilities, supported artifact types, and pillar membership via `manifest.json`.
- Plugins define strict input and output JSON schemas to ensure interoperability and to support compressed LLM context generation.
- Plugins MAY ship supplementary reference data in a `data/` directory within their plugin folder. This data extends or overrides entries from the framework's common reference data when that plugin is active. The plugin manifest SHOULD document any overrides.
- Plugins MUST implement `summarize_for_llm()` to produce a compressed, human-readable summary of results suitable for the reasoning model's context window. This method is a critical differentiator — most MCP-based projects skip explicit output compression.

Refer to `tool_plugin_spec.md` for the complete contract, packaging requirements, and acceptance checklist.

### 2.3 Routing Layer

The routing layer controls which plugins are visible to the LLM at any point in the investigation. Its purpose is to prevent context bloat from exposing the entire tool catalog to the model.

Routing can be triggered:

- **Manually**: The user selects a pillar or specific tool.
- **Automatically**: Based on loaded artifact type, keyword signals in the user's query, or session continuity from prior analysis steps.

The routing implementation order for MVP is:

1. Manual pillar selection
2. Artifact-type inference
3. Deterministic keyword scoring
4. Capability filtering against plugin manifests
5. Simple ranking (see `router_design.md` for the scoring formula)

Semantic classification and LLM-assisted routing are deferred to a future release.

Refer to `router_design.md` for the complete routing specification.

---

## 3. Technology Stack

| Concern | Decision | Notes |
|---|---|---|
| Language | Python 3.11+ | Minimum version, no legacy support |
| Packaging | `pyproject.toml` | PEP 621 compliant |
| Testing | `pytest` | Plugins require contract tests per `tool_plugin_spec.md` |
| Dependency management | `pip` with pinned `requirements.txt` for deployment | Generated from `pyproject.toml` optional groups |
| CLI framework | TBD — evaluate `cmd2` or `prompt_toolkit` | Must support tab completion, help screens, command history |
| Session persistence | SQLite (local file) | One database per session, stored in workspace directory |
| LLM integration | Model Context Protocol (MCP) | See section 5 |
| Primary cloud target | Google Cloud Platform (GCP) | See section 4 |
| Logging | Python `logging` module | See section 8 |

---

## 4. Deployment and Cloud Architecture

### 4.1 Containerized delivery

Event Mill is intended to run in cloud environments to minimize infrastructure overhead and enable rapid deployment for SOC teams or emergency incident response. The initial deployment target is:

- **Storage**: Google Cloud Storage (GCS) buckets for event artifacts
- **Compute**: Google Cloud Run for the application runtime
- **LLM access**: Via MCP protocol to configurable model providers (see section 5)

Credentials, API keys, and external storage references MUST be mounted at runtime and accessed via environment variables. No secrets in code or config files.

### 4.2 Cloud portability

Initial development targets GCP only. However, cloud-provider-specific code MUST be isolated behind abstract interfaces to enable future portability.

Required abstractions:

| Concern | Interface name | GCP implementation |
|---|---|---|
| Object storage | `StorageBackend` | `GCSStorageBackend` using `google.cloud.storage` |
| Secret management | `SecretProvider` | `GCPSecretProvider` using Secret Manager |
| Temporary file handling | `WorkspaceManager` | Local filesystem within the container |

All other framework and plugin code MUST be cloud-agnostic. Direct imports of `google.cloud.*` are prohibited outside the named implementation modules.

Forking the project to support AWS or Azure should require implementing these interfaces only, with no changes to framework, plugin, or routing code.

### 4.3 Local development mode

For development and CTF/workshop use, Event Mill MUST also run locally without any cloud dependency. Local mode uses:

- Local filesystem for artifact storage
- Environment variables or `.env` file for configuration
- Same MCP protocol connection for LLM access

The `StorageBackend` interface has a `LocalStorageBackend` implementation as the default.

---

## 5. LLM Integration via MCP

Event Mill uses the Model Context Protocol (MCP) as its LLM integration layer. This provides model interchangeability — the analyst can connect to Gemini, Claude, GPT, or any MCP-compatible model provider without changes to framework or plugin code.

### 5.1 Analysis model

The analysis pattern for all LLM interactions follows a consistent three-source grounding approach:

1. **Local predefined content first**: Common reference data from the framework (MITRE, attack chains, curated sources) and plugin-specific reference data are always included as grounding context before the LLM is queried.
2. **Web search second**: When local content is insufficient or when current threat intelligence is needed, the LLM is directed to perform web search against vetted sources.
3. **LLM reasoning third**: The model synthesizes local context, search results, and the analyst's query to produce analysis output.

This layered approach ensures that analysis is grounded in curated, trusted content before falling back to broader model knowledge.

### 5.2 System context

The LLM system prompt establishes the persona of an experienced cybersecurity technologist combining deep expertise in SOC operations, risk assessment, detection engineering, and threat hunting. This system context is owned by the framework and MUST NOT be overridden by plugins. Plugins contribute tool-specific context through their `description_llm` manifest field and `summarize_for_llm()` output.

### 5.3 MCP client configuration

The framework owns a single MCP client instance per session. Configuration is via environment variables:

| Variable | Purpose | Example |
|---|---|---|
| `EVENTMILL_MCP_TRANSPORT` | MCP transport type | `stdio`, `sse` |
| `EVENTMILL_MCP_ENDPOINT` | Model provider endpoint | Provider-specific |
| `EVENTMILL_MODEL_LIGHT` / `EVENTMILL_MODEL_HEAVY` | Per-tier model id override | `gemini-3.5-flash`, `gemini-3.1-pro-preview` |

Additional provider-specific variables (API keys, project IDs) are documented per provider.

---

## 6. Session State Management

Session state is persisted to a SQLite database within the working directory. One database file per investigation session.

### 6.1 Minimum session state schema

```
sessions
  session_id        TEXT PRIMARY KEY
  created_at        TEXT (ISO 8601)
  updated_at        TEXT (ISO 8601)
  active_pillar     TEXT
  description       TEXT

artifacts
  artifact_id       TEXT PRIMARY KEY
  session_id        TEXT REFERENCES sessions
  artifact_type     TEXT (pcap, json_events, log_stream, etc.)
  file_path         TEXT
  source_tool       TEXT (nullable — null for user-provided artifacts)
  created_at        TEXT (ISO 8601)
  metadata          TEXT (JSON blob for flexible key-value pairs)

tool_executions
  execution_id      TEXT PRIMARY KEY
  session_id        TEXT REFERENCES sessions
  tool_name         TEXT
  started_at        TEXT (ISO 8601)
  completed_at      TEXT (ISO 8601, nullable)
  status            TEXT (running, completed, failed, timed_out)
  input_artifact_id TEXT REFERENCES artifacts (nullable)
  output_artifact_id TEXT REFERENCES artifacts (nullable)
  summary           TEXT (from summarize_for_llm output)
```

Plugins MUST NOT write to the session database directly. All state updates go through the framework's session manager.

---

## 7. Artifact Registry

The artifact registry is part of the session state (see `artifacts` table above) and provides the mechanism for tracking investigation inputs and outputs.

### 7.1 Artifact lifecycle

1. **Registration**: When a user loads a file or a tool produces output, the framework registers an artifact with a unique ID, type classification, file path, and source metadata.
2. **Reference**: Tools receive artifact references (ID + file path) via the execution context, never raw file contents in prompts. Tools access artifact files directly from the storage backend.
3. **Chaining**: When a tool produces output that becomes input for another tool (e.g., `pcap_flow_summary` output feeds `mitre_technique_lookup`), the output is registered as a new artifact with `source_tool` set, creating a traceable analysis chain.
4. **Immutability**: Artifacts are read-only after registration. Tools MUST NOT modify input artifacts. New analysis results are registered as new artifacts.

### 7.2 Artifact types

The initial supported artifact types are defined in `manifest_schema.json`:

`pcap`, `json_events`, `log_stream`, `risk_model`, `cloud_audit_log`, `pdf_report`, `html_report`, `image`, `text`, `none`

Note: `manifest_schema.json` must be updated to include `html_report` and `image` in the `artifacts_supported` enum.

Additional types may be added by updating the schema. Plugin manifests declare which types they support.

---

## 8. Logging

Event Mill uses Python's built-in `logging` module configured at framework startup. Logs serve two audiences: the analyst reviewing their own investigation workflow, and the developer debugging tool behavior.

### 8.1 Log levels and their purpose

| Level | Audience | Content | Example |
|---|---|---|---|
| `INFO` | Analyst / reviewer | High-level investigation workflow: which tools ran, which artifacts were processed, what pillar was selected, session lifecycle events. This is the "audit trail" of an analysis session. | `Loaded artifact capture.pcap (type=pcap, id=art_0017)` |
| `INFO` | Analyst / reviewer | Tool execution steps and transitions. | `Running pcap_ip_search on artifact art_0017` |
| `INFO` | Analyst / reviewer | Pillar and routing decisions. | `Router selected pillar=network_forensics (reason=artifact_type_inference)` |
| `DEBUG` | Developer / troubleshooter | Tool input payloads (first 100 characters, truncated). | `pcap_ip_search input: {"pcap_file": "capture.pcap", "ip_address": "10.1.2.3", "proto...` |
| `DEBUG` | Developer / troubleshooter | Tool output payloads (first 100 characters, truncated). | `pcap_ip_search output: {"ok": true, "matches": 42, "flows": [{"src": "10.1.2.3", "ds...` |
| `DEBUG` | Developer / troubleshooter | LLM prompt construction details, MCP message payloads, routing score calculations. | `Router scores: pcap_ip_search=90, pcap_flow_summary=80` |
| `WARNING` | Both | Non-fatal issues: plugin validation warnings, truncated outputs, degraded performance. | `Plugin risk_model_v2 manifest missing optional field: cost_hint` |
| `ERROR` | Both | Failures: tool execution errors, LLM timeouts, artifact read failures, schema validation failures. | `pcap_ip_search failed: FileNotFoundError on artifact art_0017` |

### 8.2 Log format

All log entries MUST include a timestamp. The format is:

```
%(asctime)s [%(levelname)s] %(name)s — %(message)s
```

Timestamps use ISO 8601 format with timezone: `2026-05-25T14:30:00-06:00`

The `%(name)s` field uses a hierarchical logger namespace:

- `eventmill.framework.session` — session lifecycle
- `eventmill.framework.router` — routing decisions
- `eventmill.framework.artifacts` — artifact registry operations
- `eventmill.framework.mcp` — MCP client interactions
- `eventmill.plugin.<tool_name>` — per-plugin execution logging

### 8.3 Verbosity control

The application exposes a verbosity flag at startup and via a CLI command:

- Default: `INFO` level — analyst workflow audit trail
- `--verbose` or CLI command `set loglevel debug`: `DEBUG` level — full diagnostic output including truncated tool I/O

Log output goes to both the console (filtered by current level) and a session log file in the workspace directory (always captures `DEBUG` level regardless of console setting). This ensures full diagnostic data is available for post-incident review without cluttering the analyst's interactive session.

### 8.4 Truncation rules for DEBUG payloads

To manage log file size, tool input and output payloads logged at `DEBUG` level are truncated:

- String values: first 100 characters, suffixed with `...` if truncated
- Lists/arrays: first 3 elements, suffixed with `... (N total)`
- Nested objects: first level of keys only

Binary artifacts (PCAPs, PDFs, images) are never logged inline — only their artifact ID and file path.

---

## 9. Error Handling

### 9.1 Plugin errors

Plugins return structured error envelopes as defined in `tool_plugin_spec.md`:

```json
{
  "ok": false,
  "error_code": "INPUT_VALIDATION_FAILED",
  "message": "ip_address is required",
  "details": {}
}
```

The framework MUST:

- Log plugin errors at `ERROR` level with the tool name and error code.
- Present a human-readable error message to the analyst via the CLI.
- NOT crash or exit the session. The analyst should be able to retry, adjust inputs, or pivot to another tool.
- Record the failed execution in the `tool_executions` table with `status=failed`.

### 9.2 LLM errors

When the MCP connection fails or the model returns unparseable output:

- Log at `ERROR` level with the MCP transport details and response payload (truncated per section 8.4 rules).
- Inform the analyst that the LLM query failed and suggest retry or fallback to deterministic tool analysis.
- Do not retry automatically — the analyst controls the investigation flow.

### 9.3 Artifact errors

When an artifact file is missing, corrupt, or unreadable:

- Log at `ERROR` level with the artifact ID and file path.
- Return a structured error from the artifact registry, not an unhandled exception.
- The tool receiving the error MUST return a structured failure envelope, not raise.

### 9.4 Timeout handling

Tools declare a `timeout_class` in their manifest (`fast`, `medium`, `slow`). The framework enforces execution timeouts:

| Timeout class | Default limit |
|---|---|
| `fast` | 30 seconds |
| `medium` | 120 seconds |
| `slow` | 600 seconds |

On timeout: log at `ERROR`, record `status=timed_out` in `tool_executions`, inform the analyst. Do not retry automatically.

---

## 10. MVP Investigation Pillars

Each pillar groups a set of related plugins and constrains the routing layer's tool selection. Pillar paths are intentional organizational boundaries with the acknowledged limitation that some tools may be useful across multiple investigation types. Cross-pillar access is controlled by the routing layer's expansion modes (see `router_design.md`).

### 10.1 Log and Digital Event Analysis

**Pillar name**: `log_analysis`

**Purpose**: Analyze unfamiliar digital event sources to determine security relevance, extract structured data, and apply threat intelligence context.

**MVP tools**:

1. **Event source profiler** — Given a set of event records (JSON, CSV, syslog, or other structured/semi-structured formats), identify what security-relevant information exists. Produce a field inventory with data type classification, value distributions, and a security relevance assessment. Not every data source justifies the investment of persistent collection — this tool helps make that determination.

2. **Pattern extractor** — Recommend and apply regex patterns and parsing techniques for extracting structured fields from event records. Reference known existing pattern libraries following the GROK model used by Logstash. Produce reusable parsing templates that could feed into a SIEM ingestion pipeline.

3. **Threat intel ingester** — Accept threat intelligence reports and IOC data in common distribution formats and produce a compressed, structured summary optimized for LLM context window usage. The primary intake formats are PDF reports and HTML pages (blog posts, vendor advisories, CERT bulletins) since these are how threat intelligence is most commonly distributed to operational teams. Structured formats (IOC lists in CSV or JSON, STIX 2.1 bundles) are also supported. For PDF and HTML inputs, the tool extracts text content, identifies and normalizes embedded IOCs (IPs, domains, hashes, CVEs, MITRE technique IDs), maps findings to MITRE ATT&CK where applicable, and produces a structured JSON summary. The summary format must be compact enough to fit within LLM context alongside other analysis artifacts while preserving the actionable content from the original report.

4. **Context-enriched analyzer** — Apply compressed threat intel context from the ingester to loaded event records. Cross-reference event fields against IOC lists and produce enriched output highlighting matches, near-matches, and potential investigation leads.

5. **Image analyzer** — Accept JPG and PNG image files associated with an investigation and produce LLM-driven analysis output. This tool supports physical intrusion scenarios where photographs of the scene, equipment, or premises are collected alongside digital evidence. The tool ingests the raw image bytes, passes them to the LLM with task-specific instructions, and presents the output to the analyst. Three analysis modes are supported:
   - **Describe**: Produce a detailed textual description of the image contents with emphasis on security-relevant observations (open access panels, disconnected cables, unfamiliar devices, tamper indicators, badge placements, screen contents).
   - **Highlight**: Re-render the image with items of interest annotated or highlighted based on analyst-specified criteria (e.g., "highlight any USB devices" or "mark network ports that appear to have cables connected"). Output is a new image artifact registered in the artifact registry.
   - **Extract text**: Identify and extract all readable text visible in the image — equipment serial numbers, asset tags, MAC addresses printed on stickers, screen contents, whiteboard notes, badge text, warning labels. Output is structured text with location context (e.g., "serial number on rear panel sticker: SN-2847X-R3").

   This tool is entirely dependent on the connected LLM's vision capabilities. The tool itself performs no image processing — it prepares the multimodal prompt, submits to the model via MCP, and formats the response. If the connected model does not support image input, the tool MUST return a structured error indicating the capability gap rather than failing silently. Quality of results will vary by model. The tool's `summarize_for_llm()` output includes only the extracted text and description, never the image bytes.

### 10.2 Network Traffic Analysis

**Pillar name**: `network_forensics`

**Purpose**: Triage network artifacts collected during an incident. The goal is not to replace Wireshark but to provide rapid initial analysis when multiple PCAPs or firewall exports land on the analyst's desk and focus is needed quickly.

**MVP tools** (separate plugins following UNIX philosophy):

1. **PCAP metadata and conversation summary** — Parse a PCAP file and produce a high-level summary: capture duration, packet count, protocol distribution, unique endpoints, and top conversations by volume. Equivalent to Wireshark's "Conversations" and "Protocol Hierarchy" views.

2. **PCAP IP/protocol search** — Search a PCAP for packets matching a source or destination IP, protocol, port, or time range. Return matching flows with packet counts and byte volumes.

3. **PCAP flow analyzer** — For a selected flow or set of flows, produce detailed analysis: TCP stream reconstruction summary, DNS query/response pairs, HTTP request/response metadata, TLS certificate details. Focus on attributes useful for IOC identification.

4. **Firewall log aggregator** — Parse firewall log exports (common formats: Palo Alto, Fortinet, iptables) and provide SIEM-style aggregation: top talkers, protocol distribution, blocked vs. allowed ratios, subnet range analysis, frequency analysis over time windows. Designed for the scenario where firewall logs are provided during an IR but no central collection exists.

Additional network traffic formats (NetFlow, sFlow) are candidates for future plugins.

### 10.3 Threat Modeling and Attack Path Visualization

**Pillar name**: `threat_modeling`

**Purpose**: Guide an analyst through structured threat modeling using the [Shostack 4-question framework](https://github.com/adamshostack/4QuestionFrame) and produce visualized attack paths enriched with current threat intelligence.

**MVP tools**:

1. **Threat model builder** — Interactive tool that prompts the analyst through the four questions (What are we working on? What can go wrong? What are we going to do about it? Did we do a good enough job?). Uses LLM queries grounded in MITRE ATT&CK, CVE knowledge bases, and web search for emerging threats relevant to the described environment. Responses are validated against framework reference data before being presented. Session state is persisted to SQLite to support multi-session threat modeling exercises.

2. **Attack path generator** — Given a completed or partial threat model, generate attack path visualizations showing discrete stages: initial compromise, privilege escalation, lateral movement, data exfiltration, persistence. Each stage indicates:
   - Applicable MITRE ATT&CK techniques
   - Controls in place (derived from analyst input during threat modeling)
   - Perceived control strength (user-assessed, on a defined scale)
   - Gaps or weaknesses identified by LLM analysis

3. **Attack path renderer** — Produce attack path diagrams as Mermaid diagram markup (text output, renderable in any markdown viewer). Accept user input to adjust control effectiveness ratings and impact assessments, then re-render on request. HTML rendering with interactive elements is a stretch goal, not MVP.

**State management note**: This pillar requires the most complex user interaction patterns — multi-turn elicitation, LLM reflection on analyst responses, and iterative refinement. The session SQLite database (section 6) provides persistence. The framework's conversation context manager handles the LLM turn tracking. Plugin developers for this pillar MUST use the framework's session API for state, not maintain their own persistence.

---

## 11. Current Constraints and Known Limitations

- **Single active pillar**: The routing layer defaults to one active pillar at a time. Cross-pillar tool access is controlled by expansion modes (`strict`, `adjacent`, `broad`) defined in `router_design.md`. MVP ships with `strict` and `adjacent` modes only.

- **Artifact lifecycle**: The artifact registry (section 7) provides the MVP mechanism. Future releases may add artifact versioning, provenance graphs, or integration with external evidence management systems.

- **Context window degradation**: LLM performance degrades as context window usage increases. The routing layer, `summarize_for_llm()` contract, and truncation rules are all mitigations. Plugins MUST be designed with context efficiency as a first-class concern.

- **Single cloud provider**: GCP only for MVP. The abstraction interfaces (section 4.2) are the escape hatch for portability.

- **No real-time collection**: Event Mill processes files and event batches. It does not run collectors, manage retention, or perform real-time alerting. This boundary is intentional and permanent — crossing it leads to building a SIEM, which is explicitly out of scope.

---

## 12. Reference Documents

| Document | Purpose | Authority |
|---|---|---|
| `tool_plugin_spec.md` | Normative plugin contract specification | Authoritative for plugin development |
| `manifest_schema.json` | JSON Schema for plugin manifests | Authoritative for manifest validation |
| `router_design.md` | Router architecture and scoring model | Authoritative for routing behavior |
| `eventmill_tool_platform_design.md` | High-level platform architecture | Reference — this grounding document supersedes where conflicts exist |
| This document (`eventmill_v1.md`) | Coding agent grounding and MVP scope | Authoritative for implementation decisions not covered by the above specs |
