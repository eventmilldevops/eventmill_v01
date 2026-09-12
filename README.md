# Event Mill

**Event record analysis platform for Security Operations and Detection Engineering teams.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

---

## What is Event Mill?

Event Mill is an open-source platform for analyzing unfamiliar event sources before committing to full SIEM integration. It lives upstream of the SIEM — in the gap between "we just got access to a new event source" and "we have a parser, field mappings, and detection rules in production."

### Value Propositions

1. **New source triage**: Speed up initial analysis of unfamiliar event sources to determine whether they contain enough security-relevant information to warrant engineering investment.

2. **Incident-time analysis**: During incidents, analysts receive event artifacts (logs, PCAPs, audit exports) for unfamiliar systems. Event Mill helps gain context quickly without requiring full knowledge of the event record structure.

### What Event Mill is NOT

- Not a SIEM replacement
- Not a real-time collection system
- Not an alerting platform

---

## Architecture

Event Mill uses a three-layer architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                     FRAMEWORK LAYER                          │
│  CLI • Session Management • LLM Orchestration • Routing     │
│  Artifact Registry • Plugin Lifecycle • Cloud Abstraction   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      PLUGIN LAYER                            │
│  Self-describing tools following EventMillToolProtocol      │
│  Organized by investigation pillar                          │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     ROUTING LAYER                            │
│  Controls which plugins are visible to LLM per request      │
│  Prevents context bloat from full tool catalog              │
└─────────────────────────────────────────────────────────────┘
```

### Investigation Pillars

| Pillar | Purpose | Status |
|--------|---------|--------|
| `log_analysis` | Event source triage, threat intel ingestion, image analysis | MVP |
| `network_forensics` | PCAP triage, firewall log analysis | MVP |
| `threat_modeling` | Shostack 4-question framework, attack path visualization | MVP |
| `cloud_investigation` | Cloud audit log analysis | Post-MVP |
| `risk_assessment` | Risk scoring, control effectiveness | Post-MVP |

### Model Tiers

Every LLM call is routed to one of two tiers, declared per plugin as
`model_tier` in its manifest:

| Tier | Model | Used for |
|------|-------|----------|
| `light` | `gemini-3.5-flash` | Bulk work — pattern summarization, IOC extraction, chunked reads |
| `heavy` | `gemini-3.1-pro-preview` | Deep reasoning — threat modeling, risk assessment, synthesis |

Both models accept 1,048,576 input and 65,536 output tokens, so the tier is a
choice about reasoning depth and cost, not about how much fits. A plugin can
override its manifest default per call with `QueryHints`, and the framework
clamps output requests to what the selected model can actually emit.

Model ids, token limits, and per-tier capabilities live in
`framework/llm/providers/gcp_gemini.json` — one declarative source rather than
values scattered through the code.

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/eventmilldevops/eventmill_v01.git
cd eventmill_v01

# Install with pip
pip install -e ".[all]"

# Or install specific components
pip install -e ".[dev,plugins-log-analysis]"
```

### Configuration

```bash
# Copy example environment file
cp .env.example .env
```

Event Mill talks to Google Gemini. Set one API key per tier so high-volume
light-tier traffic cannot exhaust the heavy tier's quota:

```bash
GEMINI_FLASH_API_KEY=...   # light tier
GEMINI_PRO_API_KEY=...     # heavy tier
```

A single `GEMINI_API_KEY` also works and binds to the light tier. Keys are
available from [Google AI Studio](https://aistudio.google.com/apikey).

### Running

```bash
# Start the CLI
eventmill

# Or run directly
python -m framework.cli.shell
```

Inside the shell:

```
models              # list configured models and their tier
connect             # bind every available model (tiered auto-routing)
new                 # start an investigation session
pillar <name>       # set the investigation pillar
files [filters]     # list files in the pillar and common buckets
load <file|#N>      # register a file as an artifact
tools               # list available plugins and the name to invoke them by
help <tool_name>    # show a tool's arguments
run <tool_name> ... # run a tool
ask: <question>     # ask the LLM about the current session
```

`files` lists what a pillar can reach. On a large store, narrow it rather than
scrolling it — `--path <prefix>`, `--ext .log,.json`, `--newer 24h`,
`--match "*auth*"`, `--sort time|size|name`, and `--limit N`:

```
files --ext .log --newer 24h
    #  Path                                     Source       Size  Modified
  ───  ──────────────────────────────────────── ─────── ─────────  ────────────
    1  linuxdroplettest/auth.log                pillar     2.1 MB  3h ago
    2  linuxdroplettest/auth.log.1              pillar   878.9 KB  9h ago
```

Rows are numbered, and `#N` stands in for a file wherever one is expected, so
paths never have to be retyped:

```
load #2
run log_navigator --action read --path #2 --line_limit 100
```

`#N` refers to the listing you last saw. It is refused rather than guessed at if
the pillar or workspace changed since, and `run` requires the file to be loaded
first — downloading it is `load`'s job, not a side effect of running a tool.

Tools are always invoked through `run`, with arguments as `--key value` flags:

```
run threat_report_analyzer --action list_reports
run log_navigator --action read --path access.log --line_limit 100
run log_searcher --file_path access.log --query "Failed password" --context_lines 2
```

Flag values are typed from the tool's input schema, so numbers and booleans
arrive as numbers and booleans. A flag given without a value is a boolean and
sets it true (`--ai_analysis`). A comma-separated value becomes a list
(`--ioc_types ip,domain`).

Arguments that are lists of objects, or otherwise nested, cannot be expressed as
flags. For those, pass a JSON payload instead — still after `run <tool_name>`:

```
run attack_path_visualizer {"format": "ascii", "stages": [{"name": "Initial Access"}]}
```

`help <tool_name>` lists every argument a tool accepts, with its type, default,
and allowed values.

---

## Directory Structure

```
eventmill_v01/
├── framework/              # Framework layer
│   ├── cli/               # Metasploit-style command shell
│   ├── session/           # Session management (SQLite)
│   ├── routing/           # Plugin routing and filtering
│   ├── llm/               # MCP client and LLM orchestration
│   ├── artifacts/         # Artifact registry
│   ├── plugins/           # Plugin lifecycle management
│   ├── reference_data/    # MITRE ATT&CK, attack chains, vetted sources
│   ├── logging/           # Structured logging
│   └── cloud/             # Cloud abstraction (GCP, local)
├── plugins/               # Plugin layer
│   ├── log_analysis/
│   ├── network_forensics/
│   ├── cloud_investigation/
│   ├── risk_assessment/
│   └── threat_modeling/
├── cloud_install/         # GCP provisioning + Cloud Run deployment
├── tests/                 # Test suites
├── scripts/               # CI and utility scripts
├── docs/                  # Documentation
│   ├── specs/            # Normative specifications
│   ├── guides/           # User guides
│   ├── change_log/       # Dated records of significant changes
│   └── reference/        # Reference documentation
├── AGENTS.md              # Day-one operational briefing
└── workspace/             # Runtime data (gitignored)
```

---

## Deployment

Event Mill runs in production on Cloud Run, exposed as a browser terminal
(ttyd). Provisioning and deployment are scripted:

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export CLOUD_RUN_REGION="us-central1"      # required — no default

bash cloud_install/provision-gcp-project.sh   # once per project
bash cloud_install/provision-secrets.sh       # set real secret values
bash cloud_install/deploy-cloudrun-secrets.sh # deploy
```

Provisioning is the only step that writes IAM, so the deploy path can run under
a CI service account with no permission to change it. See
[cloud_install/README.md](cloud_install/README.md) for the full guide, and
[AGENTS.md](AGENTS.md) for the failure modes worth knowing before you start.

---

## Plugin Development

Plugins are self-describing tools following the `EventMillToolProtocol`. Each plugin provides:

- `manifest.json` — Metadata, capabilities, schemas
- `tool.py` — Protocol implementation
- `schemas/` — Input/output JSON schemas
- `examples/` — Request/response examples
- `tests/` — Contract tests

See [Plugin Development Guide](docs/guides/plugin_development.md) and [Tool Plugin Spec](docs/specs/tool_plugin_spec.md).

---

## Documentation

| Document | Purpose |
|----------|---------|
| [Grounding Document](docs/specs/eventmill_v1_1.md) | Strategic context and MVP scope |
| [Framework Architecture](docs/specs/framework_architecture.md) | Component responsibilities and data flow |
| [Tool Plugin Spec](docs/specs/tool_plugin_spec.md) | Normative plugin contract |
| [Router Design](docs/specs/router_design.md) | Routing architecture and scoring |
| [LLM Dispatcher](docs/specs/llm-dispatcher-native-document-handling.md) | Tiered routing and native document handling |
| [Plugin Development Guide](docs/guides/plugin_development.md) | How to build a plugin, including model tier selection |
| [Cloud Installation](cloud_install/README.md) | GCP provisioning and Cloud Run deployment |
| [AGENTS.md](AGENTS.md) | Operational briefing — commands, layout, deployment traps |
| [Change Log](docs/change_log/) | Dated records of significant changes |

---

## Contributing

Contributions welcome! Please read the plugin development guide before submitting new tools.

```bash
pip install -e ".[all]"              # dev + gcp + all plugin extras

pytest                               # collects tests/ and plugins/
ruff check .                         # line-length 88
black .
mypy framework plugins

python scripts/validate_manifests.py # plugin manifests
python scripts/validate_schemas.py   # JSON schemas
```

---
## Maintainers

Event Mill is maintained by a small group of security practitioners focused on detection engineering, incident response, and cyber threat informed detection.

Current maintainers:

- Doug Leece (dleecefft)
- Veljko Mojic (veljkomojic7-mamba)

Please use GitHub Issues for bug reports, feature requests, and design discussions. Pull Requests are welcome, especially for new plugins, artifact parsers, investigation workflows, documentation improvements, and test coverage.

---
## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
