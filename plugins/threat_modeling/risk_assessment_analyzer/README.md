# Risk Assessment Analyzer

**Validate attack paths against MITRE ATT&CK stages with control effectiveness scoring.**

## What It Does

Three actions for risk assessment analysis:

1. **analyze** — AI-powered analysis of risk assessment documents, extracting attack stages, controls, and confidence scores
2. **list_attack_types** — List available attack types with required/optional stage mappings
3. **validate_stages** — Deterministic validation of provided stages against attack type requirements (no LLM needed)

## Attack Types

`ddos`, `ransomware`, `data_theft`, `apt`, `insider_threat`, `web_attack`, `generic`

## Confidence Scoring

- **Structural Completeness** — Percentage of required stages covered
- **Evidence Strength** — Percentage of controls with tested/benchmark evidence
- **Assumption Density** — Percentage of analysis relying on assumptions (lower is better)

## Cross-Stage Analysis

- **Independence Violations** — Controls that depend on other controls in the attack path
- **Duplicate Controls** — Same control appearing across multiple stages (single point of failure risk)

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `pdf` | Risk assessment documents |
| Produced | `json_events`, `text` | Structured assessment results |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/risk_assessment_analyzer_<YYYYMMDD_HHMMSS>.json
```
The file is registered as a `json_events` session artifact. Use `artifacts` to get its ID. The `analyze` action result includes extracted attack stages, which can be passed directly to `attack_path_visualizer`. Use `export <artifact_id>` to push the JSON to `common/exports/risk_assessment_analyzer/` in cloud storage for external access or troubleshooting.

## Example Usage

Arguments are passed as `--key value` flags.

### List Attack Types
```
run risk_assessment_analyzer --action list_attack_types
```

### Analyze a Risk Assessment Document
```
run risk_assessment_analyzer --action analyze --attack_type ransomware --document_content "Backups are tested quarterly; EDR covers 80% of endpoints..."
```
`--document_content` is the document text, not a path. Quote it. For anything
longer than a line or two, summarize the source with `threat_report_analyzer`
first and pass the resulting summary text.

### Validate Stages
```
run risk_assessment_analyzer {"action": "validate_stages", "attack_type": "ransomware", "stages": [{"name": "Initial Access", "mitre_technique_id": "T1566", "stage_present": true, "controls": [{"control_name": "mail filtering", "control_type": "preventive", "effectiveness_rating": "moderate", "evidence_basis": "benchmark"}]}]}
```

`stages` is a list of objects, so `validate_stages` is the one action that needs
the JSON form — flags cannot express nested structures. Every tool accepts a
JSON payload for exactly this reason; flags cover everything else.

## Chains

- **From**: `threat_model_analyzer`
- **To**: `attack_path_visualizer`
