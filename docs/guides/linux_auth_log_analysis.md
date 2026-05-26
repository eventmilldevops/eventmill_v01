# Analyzing Linux Auth Logs with Event Mill

A step-by-step guide for SOC analysts investigating Linux authentication
events using the Event Mill CLI.

---

## Prerequisites

- Event Mill installed and configured (`eventmill` command available)
- Log files uploaded to a GCS pillar bucket under a workspace folder,
  **or** available on the local filesystem
- A pillar bucket provisioned for `log_analysis`
  (e.g. `evtm_v01-log-analysis`)

---

## 1. Start Event Mill and Create a Session

Launch the CLI and create a new investigation session with a description:

```
eventmill > new Investigate Linux auth anomalies on droplet
  Created session: sess_aa39c14f5e26
```

Every investigation lives inside a session. Sessions persist across
restarts and track artifacts, tool executions, and findings.

---

## 2. Select the Log Analysis Pillar

Set the active pillar to `log_analysis` to scope tools and storage:

```
eventmill (no-pillar) > pillar log_analysis
  Pillar set to: log_analysis (5 tools available)
```

To see what tools are available in this pillar:

```
eventmill (log_analysis) > tools
  Tool                           Pillar               Stability    Description
  ────────────────────────────── ──────────────────── ──────────── ──────────────────────────────
  Log Investigator               log_analysis         stable       AI-powered threat investigation and SOC
  Log Navigator                  log_analysis         stable       List, read, and inspect log files from l
  Log Pattern Analyzer           log_analysis         stable       Analyze log files using GROK/regex patte
  Log Searcher                   log_analysis         stable       Search log files for text patterns with
  Threat Intel Ingester          log_analysis         core         Ingest threat intelligence reports (PDF,
```

---

## 3. Discover Available Workspaces

Before setting a workspace, run `files` to see everything in the
pillar bucket. The file paths reveal which workspace folders exist:

```
eventmill (log_analysis) > files
  Filename                                 Source     Path
  ──────────────────────────────────────── ────────── ────────────────────────────────────────
  auth.log                                 pillar     linuxdroplettest/auth.log
  auth.log.1                               pillar     linuxdroplettest/auth.log.1
  auth.log.2                               pillar     linuxdroplettest/auth.log.2
  auth.log.3                               pillar     linuxdroplettest/auth.log.3
  auth.log.4                               pillar     linuxdroplettest/auth.log.4
```

The **Path** column shows that all files live under the
`linuxdroplettest/` folder. This is the workspace you need.

---

## 4. Set the Workspace Folder

Workspace folders scope file resolution to a specific incident or
dataset subfolder within the pillar bucket. Set it to the folder
you identified in the previous step:

```
eventmill (log_analysis) > workspace linuxdroplettest
  Workspace set to: linuxdroplettest
```

The prompt updates to show both pillar and workspace context.

---

## 5. List Files in the Workspace

Use the `files` command to see what log files are available in the
current pillar bucket and workspace:

```
eventmill (log_analysis:linuxdroplettest) > files
  Filename                                 Source     Path
  ──────────────────────────────────────── ────────── ────────────────────────────────────────
  auth.log                                 pillar     linuxdroplettest/auth.log
  auth.log.1                               pillar     linuxdroplettest/auth.log.1
  auth.log.2                               pillar     linuxdroplettest/auth.log.2
  auth.log.3                               pillar     linuxdroplettest/auth.log.3
  auth.log.4                               pillar     linuxdroplettest/auth.log.4
```

Files are resolved from the pillar bucket first, then the common bucket.
The **Source** column tells you where each file lives.

---

## 6. Load a Log File as an Artifact

Load the most recent auth log into the session. Event Mill downloads
the file from GCS and registers it as an artifact:

```
eventmill (log_analysis:linuxdroplettest) > load auth.log
  Loaded artifact: art_6e9d7524
  Type: log_stream
  File: auth.log
  Source: pillar bucket (workspace: linuxdroplettest): gs://evtm_v01-log-analysis/linuxdroplettest/auth.log
```

Key points:
- **Type** is inferred from the file extension (`.log` → `log_stream`)
- **Source** confirms the file was pulled from the workspace folder
  inside the pillar bucket
- The artifact ID (`art_6e9d7524`) is used to reference this file in
  subsequent tool runs

Load additional rotated logs as needed:

```
eventmill (log_analysis:linuxdroplettest) > load auth.log.1
eventmill (log_analysis:linuxdroplettest) > load auth.log.2
```

---

## 7. Verify Session State

Check the current investigation status at any time:

```
eventmill (log_analysis:linuxdroplettest) > status
  Session:    sess_aa39c14f5e26
  Pillar:     log_analysis
  Workspace:  linuxdroplettest
  Artifacts:  1
  Executions: 0 (0 completed)
  Created:    2026-03-29 22:55
  Updated:    2026-03-29 22:56
  Description: Investigate Linux auth anomalies on droplet
```

List all loaded artifacts:

```
eventmill (log_analysis:linuxdroplettest) > artifacts
  ID           Type             Source           File
  ──────────── ──────────────── ──────────────── ──────────────────────────────
  art_6e9d7524 log_stream       user             auth.log
```

---

## 8. Run Analysis Tools

### 8a. Discover Log Patterns (Recommended First Step)

Identify the log format and structural patterns before writing any
regex. Abstracts variable data (IPs, timestamps, numbers) into tokens
to reveal the underlying log structure:

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "discover", "artifact_id": "art_6e9d7524"}
```

To analyze the entire file instead of sampling (default samples 50,000
lines):

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "discover", "artifact_id": "art_6e9d7524", "full_log": true}
```

Add AI interpretation of the discovered patterns (requires LLM
connection via `connect`):

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "discover", "artifact_id": "art_6e9d7524", "full_log": true, "ai_analysis": true}
```

### 8b. GROK Pattern Analysis (Named Patterns)

Use built-in named patterns for frequency analysis without writing
regex. Available patterns include: `IP`, `USER`, `HTTPSTATUS`,
`HTTPMETHOD`, `LOGLEVEL`, `PORT`, `PATH`, `URL`, `TIMESTAMP`,
`EMAIL`, `UUID`, `HOSTNAME`, and more.

Extract and count all source IPs:

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "grok", "artifact_id": "art_6e9d7524", "pattern": "IP"}
```

Extract usernames from auth logs:

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "grok", "artifact_id": "art_6e9d7524", "pattern": "USER"}
```

Control how many top results to return (default 10, max 100):

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "grok", "artifact_id": "art_6e9d7524", "pattern": "IP", "limit": 20}
```

### 8c. Custom Regex Analysis

Use a custom regex with a capture group for targeted extraction:

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "regex", "artifact_id": "art_6e9d7524", "pattern": "Failed password for .* from (?P<src_ip>\\S+)"}
```

Analyze the full file instead of sampling:

```
eventmill (log_analysis:linuxdroplettest) > run log_pattern_analyzer {"mode": "regex", "artifact_id": "art_6e9d7524", "pattern": "Invalid user (\\S+)", "full_log": true}
```

### 8d. Search for Specific Events

Search for authentication failures, brute-force indicators, or
specific usernames using `log_searcher`:

```
eventmill (log_analysis:linuxdroplettest) > run log_searcher {"artifact_id": "art_6e9d7524", "query": "Failed password"}
```

```
eventmill (log_analysis:linuxdroplettest) > run log_searcher {"artifact_id": "art_6e9d7524", "query": "Invalid user"}
```

Use regex mode for more precise matching:

```
eventmill (log_analysis:linuxdroplettest) > run log_searcher {"artifact_id": "art_6e9d7524", "query": "Failed password.*root", "mode": "regex"}
```

### 8e. Read Log Segments

Navigate to specific sections of the log for manual review:

```
eventmill (log_analysis:linuxdroplettest) > run log_navigator {"action": "read", "artifact_id": "art_6e9d7524", "offset_lines": 0, "line_limit": 50}
```

### 8f. AI-Powered Investigation

If an LLM is connected, run the investigator for automated threat
assessment:

```
eventmill (log_analysis:linuxdroplettest) > connect
  ✓ Connected to Gemini Flash (gemini-2.0-flash)

eventmill (log_analysis:linuxdroplettest) > run log_investigator {"mode": "investigate", "artifact_id": "art_6e9d7524", "search_term": "Failed password"}
```

Run a predefined SOC workflow for top-talker analysis:

```
eventmill (log_analysis:linuxdroplettest) > run log_investigator {"mode": "workflow", "artifact_id": "art_6e9d7524", "workflow_type": "top_talkers"}
```

### 8g. Conversational Analysis (ask)

Once an LLM is connected, you can ask questions in natural language
about the investigation. The LLM receives full context: loaded
artifacts, all prior tool execution summaries, and conversation
history for multi-turn refinement.

Use the `ask:` command to query the LLM (the colon signals conscious
intent to invoke the LLM):

```
eventmill (log_analysis:linuxdroplettest) > ask: what were the usernames targeted in this log file?
```

```
eventmill (log_analysis:linuxdroplettest) > ask: what IPs had the most failed login attempts?
```

Refine the threat assessment with new information:

```
eventmill (log_analysis:linuxdroplettest) > ask: root login is disabled on this server. Search for known instances of this SSH hardening being defeated, and if nothing is found, downgrade the threat rating.
```

Ask follow-up questions — the conversation carries context:

```
eventmill (log_analysis:linuxdroplettest) > ask: based on the patterns found, what SIEM detection rules would you recommend?
```

View or clear conversation history:

```
eventmill (log_analysis:linuxdroplettest) > history
eventmill (log_analysis:linuxdroplettest) > history clear
```

---

## 9. Review Execution History

After running several tools, review what has been done:

```
eventmill (log_analysis:linuxdroplettest) > history
  ID             Tool                     Status       Time
  ────────────── ──────────────────────── ──────────── ────────────────────
  exec_a1b2c3d4  log_pattern_analyzer     completed    2026-03-29 22:57:01
  exec_e5f6a7b8  log_searcher             completed    2026-03-29 22:58:15
```

---

## 10. Confirm Storage Bucket Configuration

If file resolution isn't working as expected, verify the bucket mapping:

```
eventmill (log_analysis:linuxdroplettest) > buckets
  Pillar                    Bucket                                   Type
  ───────────────────────── ──────────────────────────────────────── ──────────
  cloud_investigation       evtm_v01-cloud-investigation             pillar
  log_analysis              evtm_v01-log-analysis                    pillar
  network_forensics         evtm_v01-network-forensics               pillar
  risk_assessment           evtm_v01-risk-assessment                 pillar
  threat_modeling           evtm_v01-threat-modeling                 pillar
  common                    evtm_v01-common                          common
```

Each pillar has a dedicated bucket. The **common** bucket holds shared
reference data (threat intel feeds, IoC lists) accessible from any
pillar.

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `new [description]` | Create a new investigation session |
| `pillar log_analysis` | Set the active pillar |
| `workspace <folder>` | Scope file resolution to a subfolder |
| `files` | List available files in pillar + common buckets |
| `load <filename>` | Download and register a file as an artifact |
| `artifacts` | List loaded artifacts |
| `tools` | List available tools |
| `run <tool> <json>` | Execute a tool with a JSON payload |
| `status` | Show current session state |
| `history` | Show tool execution history |
| `buckets` | Show bucket configuration |
| `connect [model]` | Connect to an LLM for AI-powered analysis |

---

## Recommended Workflow for Linux Auth Logs

```
new → pillar log_analysis → files (discover workspaces)
  → workspace <incident_id> → files (scoped listing) → load auth.log
  → run log_pattern_analyzer (discover)
  → run log_searcher (Failed password / Invalid user / Accepted publickey)
  → run log_pattern_analyzer (regex: extract source IPs)
  → run log_investigator (AI summary if LLM connected)
```

Start broad (pattern discovery), narrow down (search), extract
structured data (regex), then synthesize (AI investigation).
