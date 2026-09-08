# Event Mill Router Design

Version: 0.2.0
Aligned with: eventmill_v1_1.md (v0.2.0-draft)

---

## Purpose

The router decides which subset of the tool catalog is visible for a user request. It is a **control plane** component, not an investigative tool. Its job is to reduce LLM prompt size, improve tool relevance, and make a growing plugin ecosystem manageable.

---

## Core Goals

- Minimize LLM context consumption by exposing only relevant tool descriptions
- Prefer deterministic routing before semantic routing
- Expose a small, focused set of tools per request (target: 3-5 tools maximum)
- Support manual pillar selection and automatic recommendation
- Allow controlled cross-pillar expansion
- Keep routing decisions explainable and logged
- Support tool chaining by understanding artifact production/consumption relationships

---

## Routing Model

Routing occurs in four phases. Each phase narrows the candidate set.

### Phase 1: Pillar Selection

The router determines the most relevant investigation pillar.

Supported pillars:

| Pillar | Scope |
|--------|-------|
| `network_forensics` | PCAP triage, firewall log analysis, network artifact investigation |
| `cloud_investigation` | Cloud audit log analysis, cloud resource investigation |
| `log_analysis` | New event source triage, threat intel ingestion, image analysis, event enrichment |
| `risk_assessment` | Risk scoring, control effectiveness, compliance gap analysis |
| `threat_modeling` | Shostack 4-question framework, attack path generation and visualization |

Pillar selection inputs (in precedence order per section below):

1. Explicit analyst choice
2. Artifact type inference
3. Deterministic keyword scoring
4. Session continuity
5. Fallback heuristic

### Phase 2: Capability Derivation

After pillar selection, the router derives candidate capabilities from the request.

Example request:
> Ingest this PDF threat report and extract IOCs.

Derived capabilities:
- `artifact:pdf_report`
- `operation:parse`
- `operation:extract`
- `entity:ioc`

Capability derivation MUST begin with deterministic rules. Semantic enrichment is deferred to a future release.

### Phase 3: Tool Filtering and Ranking

The plugin registry is filtered to tools where:

- plugin pillar matches the selected pillar, or the plugin names it in `also_useful_in`
  (or an adjacent pillar in `adjacent` mode)
- plugin `artifacts_consumed` includes the active artifact type (if one exists)
- plugin capabilities intersect the derived capability set
- plugin stability is allowed by current policy
- plugin safety and cost fit the current execution mode

Matching tools are ranked per the scoring model below.

### Phase 4: Chain Recommendation (New)

After primary tool selection, the router evaluates potential downstream tools by matching:

- primary tool's `artifacts_produced` against other tools' `artifacts_consumed`
- primary tool's `chains_to` advisory field
- adjacency map for cross-pillar chains

Chain recommendations are informational. They appear in the routing output but do not automatically invoke. The analyst or LLM decides whether to follow a chain.

---

## Routing Precedence

Recommended order for pillar selection:

1. **Analyst or UI-selected pillar** — explicit `use <pillar>` CLI command
2. **Artifact-type inference** — loaded artifact type maps to pillar
3. **Deterministic keyword rules** — query text matches keyword patterns
4. **Session continuity** — current session pillar carries forward on ambiguous requests
5. **Fallback heuristic** — choose the highest-confidence match, provide explanation

Semantic classification and LLM-assisted routing are **not in MVP scope**.

---

## Deterministic Rule Sets

### Artifact-First Rules

| Artifact Type | Implied Pillar | Strength |
|--------------|----------------|----------|
| `pcap` | `network_forensics` | strong |
| `cloud_audit_log` | `cloud_investigation` | strong |
| `risk_model` | `risk_assessment` | strong |
| `json_events` | `log_analysis` | moderate |
| `log_stream` | `log_analysis` | moderate |
| `pdf_report` | `log_analysis` | moderate (likely threat intel) |
| `html_report` | `log_analysis` | moderate (likely threat intel) |
| `image` | `log_analysis` | weak (could be physical intrusion or unrelated) |
| `text` | ambiguous | none — requires keyword or session context |

### Keyword Rules

| Keywords | Boosted Pillar |
|----------|---------------|
| `pcap`, `packet`, `flow`, `dns query`, `tcp`, `udp`, `tls`, `wireshark` | `network_forensics` |
| `firewall`, `palo alto`, `fortinet`, `iptables`, `blocked`, `allowed` | `network_forensics` |
| `azure`, `aws`, `gcp`, `blob`, `s3`, `cloudtrail`, `audit log`, `iam` | `cloud_investigation` |
| `log`, `event`, `syslog`, `session`, `alert`, `parse`, `field`, `grok` | `log_analysis` |
| `threat intel`, `ioc`, `indicator`, `stix`, `cve`, `advisory`, `report` | `log_analysis` |
| `image`, `photo`, `camera`, `physical`, `badge`, `serial number` | `log_analysis` |
| `risk`, `impact`, `likelihood`, `control`, `residual`, `compliance` | `risk_assessment` |
| `mitre`, `attack path`, `technique`, `lateral movement`, `exfiltration` | `threat_modeling` |
| `threat model`, `four questions`, `shostack`, `what can go wrong` | `threat_modeling` |

### Session Continuity Rule

If the current session already selected a pillar and the new request is ambiguous, prefer the current session pillar **unless** there is strong conflicting evidence from artifact type or keywords.

---

## Cross-Pillar Behavior

### Expansion Modes

| Mode | Behavior |
|------|----------|
| `strict` | Only selected pillar tools. Default. |
| `adjacent` | Selected pillar plus approved adjacent pillars. |
| `broad` | All matched tools regardless of pillar. Future mode. |

MVP ships with `strict` and `adjacent` modes only.

A plugin's `also_useful_in` is **not** governed by the expansion mode. Adjacency is a
blanket pillar-to-pillar relation an operator may switch off; `also_useful_in` is one
plugin author naming one pillar deliberately, and applies in every mode. It widens where
a tool is *offered*, never which pillar Phase 1 selects.

### Adjacency Map

| Source Pillar | Adjacent Pillars |
|--------------|-----------------|
| `network_forensics` | `threat_modeling`, `log_analysis` |
| `cloud_investigation` | `log_analysis`, `threat_modeling` |
| `log_analysis` | `cloud_investigation`, `threat_modeling`, `network_forensics` |
| `risk_assessment` | `threat_modeling` |
| `threat_modeling` | `risk_assessment`, `log_analysis`, `network_forensics` |

Note: `log_analysis` has the broadest adjacency because threat intel ingestion and context enrichment are relevant to nearly all investigation types.

---

## Ranking Model

After filtering, tools are ranked using a weighted score:

```text
score =
  pillar_match * 50 +
  artifact_consumed_match * 30 +
  capability_overlap_count * 10 +
  stability_weight +
  auto_invoke_weight -
  timeout_penalty -
  cost_penalty +
  chain_bonus
```

Weights:

| Factor | Weight | Notes |
|--------|--------|-------|
| `pillar_match` | 50 | 1 if pillar matches, 0.75 if the tool declares the pillar in `also_useful_in`, 0.5 if adjacent, 0 otherwise |
| `artifact_consumed_match` | 30 | 1 if tool consumes the active artifact type |
| `capability_overlap_count` | 10 per match | Number of derived capabilities matching tool capabilities |
| `stability_weight` | core=10, verified=5, experimental=0, deprecated=-10 | |
| `auto_invoke_weight` | 5 if safe_for_auto_invoke=true | |
| `timeout_penalty` | fast=0, medium=-5, slow=-10 | |
| `cost_penalty` | low=0, moderate=-5, high=-10 | |
| `chain_bonus` | 10 | If a previously executed tool's output feeds this tool |

This scoring is intentionally simple and explainable. A future version may introduce learned weights.

---

## Routing Output Contract

The router returns a structured decision object:

```json
{
  "selected_pillar": "log_analysis",
  "expansion_mode": "strict",
  "requested_capabilities": [
    "artifact:pdf_report",
    "operation:parse",
    "operation:extract",
    "entity:ioc"
  ],
  "candidate_tools": [
    {
      "tool_name": "threat_intel_ingester",
      "score": 130,
      "match_reasons": [
        "pillar_match",
        "artifact_consumed_match:pdf_report",
        "capability:operation:parse",
        "capability:entity:ioc"
      ]
    }
  ],
  "chain_recommendations": [
    {
      "tool_name": "context_enriched_analyzer",
      "reason": "threat_intel_ingester produces json_events, context_enriched_analyzer consumes json_events",
      "pillar": "log_analysis"
    }
  ],
  "excluded_tools": [
    {
      "tool_name": "pcap_ip_search",
      "reason": "pillar_mismatch"
    }
  ],
  "explanation": [
    "Detected pdf_report artifact",
    "Keyword match: threat intel, ioc",
    "Matched log_analysis pillar",
    "Chain recommendation: threat_intel_ingester -> context_enriched_analyzer"
  ]
}
```

---

## Router Modes

| Mode | Description |
|------|-------------|
| `manual` | Analyst explicitly selected pillar via CLI |
| `deterministic` | Artifact and rules selected pillar |
| `assisted` | Deterministic result with optional semantic recommendation (future) |
| `learning` | Telemetry-informed ranking (future) |

---

## Failure Handling

If the router cannot determine a strong match:

1. Choose the highest-confidence pillar
2. Provide an explanation of the decision
3. Include a small fallback set of generic discovery tools if they exist
4. Log the low-confidence decision at WARNING level
5. Do NOT load the full catalog — this defeats the purpose of routing

---

## Telemetry and Explainability

The router MUST emit logs at the following levels:

| Level | Content |
|-------|---------|
| `INFO` | Selected pillar, expansion mode, candidate tool count |
| `DEBUG` | Artifact hints, keyword hits, derived capabilities, per-tool scores, excluded tools with reasons |
| `WARNING` | Low-confidence decisions, fallback selections |

Logger namespace: `eventmill.framework.router`

---

## Configuration Model

The router SHOULD be config-driven. Suggested config areas:

- available pillars and their enabled state
- keyword-to-pillar maps (JSON, hot-reloadable)
- artifact-to-pillar strength maps
- adjacency map
- default expansion mode
- maximum candidate tools to expose (default: 5)
- stability policy (e.g., exclude experimental in production)
- cost and timeout thresholds for auto-invoke filtering

---

## Implementation Order for MVP

1. Manual pillar selection (`use <pillar>` CLI command)
2. Artifact-driven pillar inference
3. Deterministic keyword scoring
4. Capability filtering against plugin manifests
5. Simple ranking (score formula above)
6. Structured routing result with explanation
7. Adjacency expansion (adjacent mode)
8. Chain recommendation based on artifacts_produced/consumed

Semantic recommendation, learning mode, and broad expansion are post-MVP.
