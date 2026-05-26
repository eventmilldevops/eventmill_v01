# Event Mill Framework Architecture and Tool Communication

Version: 0.2.0
Aligned with: eventmill_v1_1.md (v0.2.0-draft), tool_plugin_spec.md (v0.3.0)

---

## Purpose

This document provides the structural view of Event Mill that sits between the high-level grounding document (`eventmill_v1_1.md`) and the normative plugin contract (`tool_plugin_spec.md`). It covers:

- Repository directory structure
- Component responsibilities and boundaries
- Inter-component communication contracts
- Data flow through the system
- Pillar interface patterns
- MCP integration architecture
- Artifact lifecycle mechanics

This is a **reference** document. Where it conflicts with `tool_plugin_spec.md` (for plugin behavior) or `router_design.md` (for routing behavior), the normative documents take precedence.

---

## 1. Repository Directory Structure

```text
event_mill/
├── README.md
├── LICENSE
├── pyproject.toml
├── requirements.txt                    # Pinned from pyproject.toml
├── Dockerfile
├── docker-compose.yml                  # Local dev with MCP endpoint
├── .env.example
│
├── framework/                          # Framework Layer
│   ├── __init__.py
│   ├── cli/                            # CLI interface (Metasploit-style shell)
│   │   ├── __init__.py
│   │   ├── shell.py                    # Main REPL: cmd2 or prompt_toolkit
│   │   ├── commands.py                 # Built-in commands: use, load, info, run, set, etc.
│   │   └── completers.py              # Tab completion for pillars, tools, artifacts
│   │
│   ├── session/                        # Session management
│   │   ├── __init__.py
│   │   ├── manager.py                  # Session lifecycle: create, resume, close
│   │   ├── database.py                 # SQLite operations (schema from §6 of grounding doc)
│   │   └── models.py                   # Dataclasses: Session, ArtifactRef, ToolExecution
│   │
│   ├── routing/                        # Routing Layer
│   │   ├── __init__.py
│   │   ├── router.py                   # Core routing engine (per router_design.md)
│   │   ├── rules.py                    # Deterministic keyword and artifact rules
│   │   ├── scorer.py                   # Ranking formula
│   │   └── config/
│   │       ├── pillars.json            # Pillar definitions and enabled state
│   │       ├── keywords.json           # Keyword-to-pillar scoring maps
│   │       ├── artifact_rules.json     # Artifact type to pillar strength
│   │       └── adjacency.json          # Cross-pillar adjacency map
│   │
│   ├── llm/                            # LLM Orchestration
│   │   ├── __init__.py
│   │   ├── client.py                   # MCPLLMClient, LLMDispatcher (routes by QueryHints)
│   │   ├── backends/                   # Provider-specific backend implementations
│   │   │   ├── __init__.py             # Explicit BACKEND_REGISTRY
│   │   │   ├── base.py                 # LLMBackend ABC, ModelCapabilities, DocumentPart
│   │   │   └── gemini.py               # GeminiBackend (GCS URI + inline bytes)
│   │   └── providers/                  # Declarative capability manifests
│   │       ├── __init__.py
│   │       └── gcp_gemini.json         # Gemini tiers, file handling, document strategies
│   │
│   ├── artifacts/                      # Artifact Registry
│   │   ├── __init__.py
│   │   ├── registry.py                 # Register, lookup, chain tracking
│   │   └── storage.py                  # StorageBackend interface + LocalStorageBackend
│   │
│   ├── plugins/                        # Plugin Lifecycle
│   │   ├── __init__.py
│   │   ├── loader.py                   # Discovery, validation, import
│   │   ├── registry.py                 # In-memory plugin catalog
│   │   ├── executor.py                 # Timeout enforcement, context injection, logging
│   │   └── protocol.py                 # EventMillToolProtocol, ToolResult, ExecutionContext
│   │
│   ├── reference_data/                 # Common Reference Data (loaded at startup)
│   │   ├── mitre_attack_enterprise.json
│   │   ├── mitre_attack_ics.json
│   │   ├── attack_chain_patterns.json
│   │   ├── vetted_sources.json         # Curated URLs for threat intel, research, regulatory
│   │   └── README.md
│   │
│   ├── logging/                        # Structured Logging
│   │   ├── __init__.py
│   │   └── config.py                   # Logger setup, formatters, truncation rules
│   │
│   └── cloud/                          # Cloud Abstraction Layer
│       ├── __init__.py
│       ├── interfaces.py               # StorageBackend, SecretProvider, WorkspaceManager ABCs
│       ├── gcp/                        # GCP implementations
│       │   ├── storage.py              # GCSStorageBackend
│       │   └── secrets.py              # GCPSecretProvider
│       └── local/                      # Local development implementations
│           ├── storage.py              # LocalStorageBackend (filesystem)
│           └── secrets.py              # EnvVarSecretProvider
│
├── plugins/                            # Plugin Layer
│   ├── log_analysis/
│   │   ├── event_source_profiler/
│   │   ├── pattern_extractor/
│   │   ├── threat_intel_ingester/
│   │   ├── context_enriched_analyzer/
│   │   └── image_analyzer/
│   ├── network_forensics/
│   │   ├── pcap_metadata_summary/
│   │   ├── pcap_ip_search/
│   │   ├── pcap_flow_analyzer/
│   │   └── firewall_log_aggregator/
│   ├── cloud_investigation/            # Post-MVP
│   ├── risk_assessment/                # Post-MVP
│   └── threat_modeling/
│       ├── threat_model_builder/
│       ├── attack_path_generator/
│       └── attack_path_renderer/
│
├── tests/
│   ├── framework/                      # Framework unit and integration tests
│   ├── plugins/                        # Plugin contract test runners
│   └── fixtures/                       # Shared test data (sample PCAPs, logs, reports)
│
├── scripts/                            # Build, deployment, utility scripts
│   ├── validate_manifests.py           # CI: validate all plugin manifests
│   ├── validate_schemas.py             # CI: validate all JSON schemas
│   └── generate_tool_catalog.py        # Generate human-readable tool listing
│
├── docs/                               # Documentation
│   ├── specs/                          # Normative specifications
│   │   ├── tool_plugin_spec.md
│   │   ├── manifest_schema.json
│   │   ├── router_design.md
│   │   └── framework_architecture.md   # This document
│   ├── guides/
│   │   ├── plugin_development.md       # How to write a new plugin
│   │   ├── ctf_scenario_design.md      # BSides Calgary CTF design guide
│   │   └── local_development.md        # Getting started locally
│   └── reference/
│       └── cli_commands.md             # CLI command reference
│
└── workspace/                          # Runtime workspace (gitignored)
    ├── sessions/                       # SQLite databases per session
    ├── artifacts/                      # Loaded and produced artifacts
    └── logs/                           # Session log files
```

---

## 2. Component Responsibility Matrix

| Component | Owns | Reads | Writes |
|-----------|------|-------|--------|
| **CLI** | User I/O, command dispatch | Session state, tool catalog | User commands to session manager |
| **Session Manager** | Session lifecycle, SQLite | — | Session DB (sessions, artifacts, tool_executions) |
| **Router** | Pillar selection, tool filtering | Plugin registry, session state, config | Routing decisions (logged, not persisted) |
| **LLM Dispatcher** | Model routing, native doc dispatch | QueryHints, provider manifest | GenAI SDK calls (external) |
| **LLM Backend** | Provider SDK connection, retry logic | API keys, model capabilities | API requests (external) |
| **Artifact Registry** | Artifact tracking, immutability | Storage backend | Session DB (artifacts table) |
| **Plugin Loader** | Discovery, validation, import | Plugin directories, manifest files | Plugin registry (in-memory) |
| **Plugin Executor** | Timeout enforcement, context injection | Plugin registry, session state | Session DB (tool_executions), artifact registry |
| **Storage Backend** | File I/O abstraction | Filesystem or cloud storage | Artifact files |
| **Plugins** | Analysis logic | Execution context (read-only) | ToolResult (returned, not written directly) |

---

## 3. Data Flow Architecture

### 3.1 Request-to-Result Flow

```text
Analyst Input
      │
      ▼
┌──────────┐   command   ┌──────────────┐
│   CLI    │────────────▶│   Session    │
│  Shell   │             │   Manager    │
└──────────┘             └──────┬───────┘
      │                         │ session context
      │                         ▼
      │                  ┌──────────────┐
      │   query text     │    Router    │◀─── Plugin Registry
      │ ────────────────▶│              │◀─── Routing Config
      │                  └──────┬───────┘
      │                         │ candidate tools + chain recommendations
      │                         ▼
      │                  ┌──────────────┐
      │   tool selection │   Plugin     │
      │ ────────────────▶│  Executor    │
      │                  └──────┬───────┘
      │                         │ ExecutionContext
      │                         ▼
      │                  ┌──────────────┐
      │                  │   Plugin     │──── LLMQueryInterface ──▶ LLM Dispatcher ──▶ Backend ──▶ Model
      │                  │  (tool.py)   │──── StorageBackend ─────▶ Artifact files
      │                  └──────┬───────┘
      │                         │ ToolResult
      │                         ▼
      │                  ┌──────────────┐
      │                  │   Plugin     │──▶ Session DB (tool_executions)
      │                  │  Executor    │──▶ Artifact Registry (output artifacts)
      │                  └──────┬───────┘
      │                         │ summarize_for_llm() output
      │                         ▼
      │                  ┌──────────────┐
      │                  │   LLM        │──▶ Analyst-facing response
      │                  │  Context     │
      │                  │  Builder     │
      │                  └──────────────┘
      │                         │
      ▼                         ▼
Analyst sees:           CLI displays:
- LLM-synthesized      - Tool execution status
  analysis              - Summary table
- Follow-up options     - Chain recommendations
```

### 3.2 Artifact Lifecycle Flow

```text
User loads file         Plugin produces output
      │                         │
      ▼                         ▼
┌──────────────┐        ┌──────────────┐
│  Artifact    │        │  Plugin      │
│  Registry    │        │  Executor    │
│  .register() │        │  registers   │
└──────┬───────┘        │  via context │
       │                └──────┬───────┘
       │                       │
       ▼                       ▼
┌─────────────────────────────────────┐
│         Session SQLite DB           │
│  artifacts table                    │
│  ┌──────────────────────────────┐   │
│  │ artifact_id: art_0001       │   │
│  │ artifact_type: pdf_report   │   │
│  │ file_path: /workspace/...   │   │
│  │ source_tool: NULL (user)    │   │
│  │ metadata: {pages: 12, ...}  │   │
│  └──────────────────────────────┘   │
│  ┌──────────────────────────────┐   │
│  │ artifact_id: art_0002       │   │
│  │ artifact_type: json_events  │   │
│  │ file_path: /workspace/...   │   │
│  │ source_tool: ti_ingester    │   │
│  │ metadata: {ioc_count: 47}   │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘

Chain traceability:
  art_0001 (user pdf) ──▶ ti_ingester ──▶ art_0002 (extracted IOCs)
                                              │
                                              ▼
                         context_enriched_analyzer ──▶ art_0003 (enriched events)
```

---

## 4. Pillar Interface Patterns

Each pillar is a logical grouping of plugins with shared artifact types and investigation patterns. The framework treats all pillars identically — the differences are in the plugins, not the framework code.

### 4.1 Log Analysis Pillar

```text
┌─────────────────────────────────────────────────────────┐
│                    LOG ANALYSIS PILLAR                   │
│                                                         │
│  Artifacts consumed: json_events, log_stream,           │
│    pdf_report, html_report, image, text                 │
│  Artifacts produced: json_events, text                  │
│                                                         │
│  ┌─────────────────┐   ┌─────────────────┐             │
│  │ Event Source     │   │ Pattern         │             │
│  │ Profiler         │   │ Extractor       │             │
│  │                  │   │                 │             │
│  │ IN:  json_events │   │ IN:  log_stream │             │
│  │      log_stream  │   │      json_events│             │
│  │      text        │   │      text       │             │
│  │ OUT: json_events │   │ OUT: json_events│             │
│  │      (field      │   │      (parsing   │             │
│  │       inventory) │   │       templates)│             │
│  └─────────────────┘   └─────────────────┘             │
│                                                         │
│  ┌─────────────────┐   ┌─────────────────┐             │
│  │ Threat Intel     │   │ Context-Enriched│             │
│  │ Ingester         │   │ Analyzer        │             │
│  │                  │   │                 │             │
│  │ IN:  pdf_report  │   │ IN:  json_events│             │
│  │      html_report │   │      (events +  │             │
│  │      text (CSV,  │   │       TI context│             │
│  │       STIX)      │   │       from      │             │
│  │ OUT: json_events │   │       ingester) │             │
│  │      (IOC list,  │   │ OUT: json_events│             │
│  │       MITRE      │   │      (enriched  │             │
│  │       mappings)  │   │       matches)  │             │
│  └────────┬────────┘   └────────▲────────┘             │
│           │                      │                      │
│           └──── chains_to ───────┘                      │
│                                                         │
│  ┌─────────────────┐                                    │
│  │ Image Analyzer   │  requires_llm: true               │
│  │                  │                                   │
│  │ IN:  image       │                                   │
│  │ OUT: text        │                                   │
│  │      image (if   │                                   │
│  │       highlight  │                                   │
│  │       mode)      │                                   │
│  └─────────────────┘                                    │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Network Forensics Pillar

```text
┌─────────────────────────────────────────────────────────┐
│                 NETWORK FORENSICS PILLAR                 │
│                                                         │
│  Artifacts consumed: pcap, log_stream, text             │
│  Artifacts produced: json_events, text                  │
│                                                         │
│  ┌─────────────────┐   ┌─────────────────┐             │
│  │ PCAP Metadata    │   │ PCAP IP/Protocol│             │
│  │ Summary          │   │ Search          │             │
│  │                  │   │                 │             │
│  │ IN:  pcap        │   │ IN:  pcap       │             │
│  │ OUT: json_events │   │ OUT: json_events│             │
│  │      (protocol   │   │      (matching  │             │
│  │       hierarchy, │   │       flows)    │             │
│  │       endpoints) │   │                 │             │
│  └────────┬────────┘   └────────┬────────┘             │
│           │                      │                      │
│           └──── chains_to ───────┼── pcap_flow_analyzer │
│                                  │                      │
│  ┌─────────────────┐   ┌────────▼────────┐             │
│  │ Firewall Log     │   │ PCAP Flow       │             │
│  │ Aggregator       │   │ Analyzer        │             │
│  │                  │   │                 │             │
│  │ IN:  log_stream  │   │ IN:  pcap +     │             │
│  │      text        │   │      json_events│             │
│  │ OUT: json_events │   │      (flow ref) │             │
│  │      (aggregated │   │ OUT: json_events│             │
│  │       stats)     │   │      (TCP recon,│             │
│  └─────────────────┘   │       DNS, HTTP, │             │
│                         │       TLS detail)│             │
│                         └─────────────────┘             │
└─────────────────────────────────────────────────────────┘
```

### 4.3 Threat Modeling Pillar

```text
┌─────────────────────────────────────────────────────────┐
│                 THREAT MODELING PILLAR                   │
│                                                         │
│  All tools require LLM. Session state is critical.      │
│                                                         │
│  ┌─────────────────┐                                    │
│  │ Threat Model     │  requires_llm: true               │
│  │ Builder          │  Multi-session stateful            │
│  │                  │                                   │
│  │ IN:  none (user  │                                   │
│  │      interaction)│                                   │
│  │ OUT: risk_model  │                                   │
│  │      (Shostack   │                                   │
│  │       4Q output) │                                   │
│  └────────┬────────┘                                    │
│           │ chains_to                                   │
│           ▼                                             │
│  ┌─────────────────┐                                    │
│  │ Attack Path      │  requires_llm: true               │
│  │ Generator        │                                   │
│  │                  │                                   │
│  │ IN:  risk_model  │                                   │
│  │ OUT: json_events │                                   │
│  │      (attack     │                                   │
│  │       paths with │                                   │
│  │       MITRE map) │                                   │
│  └────────┬────────┘                                    │
│           │ chains_to                                   │
│           ▼                                             │
│  ┌─────────────────┐                                    │
│  │ Attack Path      │                                   │
│  │ Renderer         │                                   │
│  │                  │                                   │
│  │ IN:  json_events │                                   │
│  │      (attack     │                                   │
│  │       paths)     │                                   │
│  │ OUT: text        │                                   │
│  │      (Mermaid    │                                   │
│  │       markup)    │                                   │
│  └─────────────────┘                                    │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Tool Communication Contract

### 5.1 Communication Boundaries

Plugins **never** communicate directly with each other. All inter-tool data exchange follows this pattern:

```text
Tool A ──▶ ToolResult ──▶ Framework (Executor) ──▶ Artifact Registry ──▶ Tool B (via context)
```

This is enforced by design:

1. Tool A produces output and registers artifacts via `context.register_artifact()`
2. The framework records the artifact in the session database
3. The router may recommend Tool B based on `artifacts_produced`/`artifacts_consumed` matching
4. If Tool B is invoked, it receives the artifact reference in its `ExecutionContext.artifacts` list
5. Tool B reads the artifact file from the storage backend

### 5.2 Data Exchange Formats

All inter-tool data passes through registered artifacts. The serialization contract:

| Artifact Type | On-Disk Format | Schema Requirement |
|--------------|----------------|-------------------|
| `json_events` | JSON file, array of objects or NDJSON | Output schema MUST define the event object shape |
| `risk_model` | JSON file | Output schema MUST define the model structure |
| `text` | UTF-8 text file | No schema requirement; metadata SHOULD describe format |
| `pcap` | Binary PCAP/PCAPNG | No schema; metadata includes capture stats |
| `log_stream` | Text file (one record per line) | No schema; metadata SHOULD describe delimiter/format |
| `image` | JPEG or PNG binary | No schema; metadata includes dimensions, format |
| `pdf_report` | PDF binary | No schema; metadata includes page count |
| `html_report` | HTML text file | No schema; metadata includes source URL if known |
| `cloud_audit_log` | JSON file | Output schema MUST define the log record shape |

### 5.3 The summarize_for_llm() Contract in Detail

This is the most important communication interface in Event Mill. Every tool result that flows into LLM context passes through this compression step.

**Why this matters**: Without explicit output compression, a single tool execution can consume 50-80% of the LLM's context window with raw JSON output. The `summarize_for_llm()` method forces plugin authors to make editorial decisions about what information is essential for the LLM's reasoning.

**Contract rules**:

1. Output MUST be a plain text string (no JSON, no markdown code blocks)
2. Target length: 200-500 tokens (approximately 150-400 words)
3. Hard maximum: 2000 characters
4. MUST include: key findings, counts, notable anomalies
5. MUST NOT include: raw data arrays, full IP lists, complete field inventories
6. MUST NOT invent findings not present in the result
7. SHOULD use a consistent structure: summary line, then key findings, then notable items
8. SHOULD reference artifact IDs for cross-referencing

**Example output** (from `threat_intel_ingester`):

```text
Ingested PDF threat report (12 pages). Extracted 47 IOCs: 23 IP addresses,
12 domains, 8 file hashes (SHA-256), 4 CVE references. Mapped to 6 MITRE
ATT&CK techniques: T1566.001 (Spearphishing Attachment), T1059.001
(PowerShell), T1053.005 (Scheduled Task), T1071.001 (Web Protocols),
T1486 (Data Encrypted for Impact), T1048.003 (Exfiltration Over
Unencrypted Protocol). Report attributes campaign to APT group with
medium confidence. 3 IOCs flagged as high-priority (active C2
infrastructure). Output artifact: art_0002 (json_events, 47 IOC records).
```

### 5.4 MCP Message Flow

Event Mill's MCP integration follows the three-source grounding model from the design doc:

```text
┌─────────────────────────────────────────────┐
│              MCP Message Construction       │
│                                             │
│  1. System Context (framework-owned)        │
│     ├── Persona prompt                      │
│     └── Session state summary               │
│                                             │
│  2. Grounding Data (layered)                │
│     ├── Framework reference data            │
│     │   (MITRE, attack chains, sources)     │
│     ├── Plugin reference data overrides     │
│     ├── Prior tool summaries                │
│     │   (from summarize_for_llm())          │
│     └── Active artifact metadata            │
│                                             │
│  3. Tool Descriptions                       │
│     └── description_llm from routed tools   │
│         (only candidates, not full catalog) │
│                                             │
│  4. User Query                              │
│     └── Analyst's natural language request  │
└─────────────────────────────────────────────┘
         │
         ▼
    MCP Transport (stdio or SSE)
         │
         ▼
    Model Provider (Gemini, Claude, GPT, etc.)
         │
         ▼
    Response: tool selection, parameters, or natural language analysis
```

**Context budget management**: The framework maintains a running token estimate for the MCP message. If the combined context exceeds a configurable threshold (default: 60% of the model's context window), the framework truncates in this order:

1. Oldest tool summaries (keep most recent 3)
2. Reference data sections not relevant to the active pillar
3. Artifact metadata (keep IDs and types, drop extended metadata)

The framework MUST log truncation decisions at DEBUG level.

---

## 6. CLI Command Model

The CLI follows Metasploit conventions. Core commands for MVP:

| Command | Description |
|---------|-------------|
| `use <pillar>` | Select active investigation pillar |
| `load <file>` | Load an artifact file into the session |
| `artifacts` | List registered artifacts with IDs and types |
| `tools` | List available tools for the current pillar |
| `info <tool_name>` | Show tool details (description, input schema, examples) |
| `run <tool_name> [options]` | Execute a tool with the given options |
| `set <option> <value>` | Set a tool option before running |
| `options` | Show current option values for the selected tool |
| `results` | Show results from the last tool execution |
| `chain` | Show recommended next tools based on current results |
| `history` | Show tool execution history for the current session |
| `ask <question>` | Send a natural language question to the LLM with current context |
| `session [new|list|resume|close]` | Session management |
| `set loglevel [info|debug]` | Change log verbosity |
| `help` | Show available commands |
| `exit` | Close session and exit |

---

## 7. Error Propagation Model

Errors flow upward through the stack without crashing the session:

```text
Plugin raises exception
    │
    ▼
Plugin Executor catches, wraps in ToolResult(ok=False)
    │
    ▼
Session Manager records status=failed in tool_executions
    │
    ▼
CLI displays human-readable error message
    │
    ▼
Analyst can retry, adjust, or pivot

LLM/MCP connection fails
    │
    ▼
LLM Client returns LLMResponse(ok=False)
    │
    ▼
Plugin receives error via LLMQueryInterface
    │
    ▼
Plugin returns ToolResult(ok=False, error_code="LLM_QUERY_FAILED")
    │
    ▼
Normal error propagation continues
```

The session MUST survive any individual tool or LLM failure. No error should require restarting the application.

---

## 8. Security Considerations for CTF Design

Event Mill is designed for analysis, not active exploitation. For the BSides Calgary CTF:

- Plugins process artifacts locally — no outbound connections except MCP and vetted URL lists
- The `safe_for_auto_invoke` flag prevents unintended tool execution
- The `external_connectivity` flag in manifests makes network behavior explicit
- Session SQLite databases provide a full audit trail of analyst actions
- Artifact immutability prevents evidence tampering
- The plugin sandbox (no direct framework state mutation) limits blast radius of malicious plugins

For CTF scenario design, the framework provides:

- Controlled artifact injection (load curated PCAPs, logs, reports)
- Deterministic tool behavior for reproducible challenges
- Session replay via the SQLite audit trail
- Pluggable scoring hooks (future) via the plugin extension mechanism

---

## 9. Competitive Positioning Notes

Event Mill occupies a specific niche relative to existing open-source projects:

| Project | What it does | Event Mill's gap it does NOT fill |
|---------|-------------|-----------------------------------|
| **Security Onion** | Full NSM/IDS platform (Suricata, Zeek, Elastic) | Runtime collection, persistent monitoring |
| **Wazuh** | XDR + SIEM with agent-based collection | Endpoint agents, real-time alerting |
| **OpenTide/CoreTide** | Detection-as-code framework, threat/detection modeling | Rule deployment, CI/CD pipeline for detections |
| **Sigma** | Vendor-agnostic detection rule format | Rule authoring, cross-SIEM translation |
| **TheHive/Cortex** | IR case management + automated analysis | Case tracking, multi-analyst collaboration |
| **MISP** | Threat intelligence sharing platform | IOC exchange, community feeds |
| **Shannon (Keygraph)** | Autonomous AI pentesting (white-box) | Offensive testing, exploit generation |

**Event Mill's unique position**: The analysis-before-commitment phase. None of these tools help an analyst quickly determine whether an unfamiliar event source contains enough security-relevant information to justify building parsers, field mappings, and detection rules. None provide rapid incident-time context for unfamiliar artifact formats with LLM-assisted analysis. Event Mill sits upstream of the SIEM and downstream of raw artifact collection.

Closest relatives are ad hoc Python scripts + jq + CyberChef workflows that every SOC team builds internally. Event Mill formalizes that workflow into a reusable, extensible platform.
