# Threat Model Analyzer

**Analyze threat models, track scenarios, controls, attack events, and identify defense gaps.**

## What It Does

Seven actions for comprehensive threat modeling:

1. **analyze_document** — AI-powered analysis of threat model documents or tabletop exercise minutes
2. **create_scenario** — Create a trackable threat scenario with actor, objectives, assets
3. **add_control** — Add security controls with defense layer, bypass difficulty, implementation status
4. **add_event** — Add attack sequence events with MITRE ATT&CK mapping and control references
5. **list_scenarios** — List all tracked scenarios with summary stats
6. **gap_analysis** — Identify unprotected steps, weak controls, and easy bypasses
7. **export** — Generate markdown report with full scenario details

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `pdf` | Threat model documents |
| Produced | `json_events`, `text` | Analysis results, markdown reports |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/threat_model_analyzer_<YYYYMMDD_HHMMSS>.json
```
The file is registered as a `json_events` session artifact. Use `artifacts` to get its ID.
- The `export` action additionally produces a markdown report — its `output` field is extracted and saved as `.md`
- Scenario and gap analysis results can be loaded into `attack_path_visualizer` via the artifact ID
- Use `export <artifact_id>` to push the JSON to `common/exports/threat_model_analyzer/` in cloud storage for external access or troubleshooting

## Defense Layers

`perimeter`, `network`, `endpoint`, `application`, `data`, `identity`, `monitoring`

## Example Workflow

```
1. analyze_document → AI extracts attack paths from document
2. create_scenario → Track the scenario with ID
3. add_control (x N) → Map existing security controls
4. add_event (x N) → Map attack sequence with MITRE ATT&CK
5. gap_analysis → Identify defense weaknesses
6. export → Generate markdown report
```

## Example Usage

Arguments are passed as `--key value` flags.

### Analyze a Document
```
run threat_model_analyzer --action analyze_document --source_type tabletop_exercise --document_content "Attackers phished a finance user, then pivoted to the ERP host..."
```
Quote the text — anything with spaces has to be quoted. For a document longer
than a line or two, summarize it with `threat_report_analyzer` first and pass
the summary text.

### Create a Scenario
```
run threat_model_analyzer --action create_scenario --name "ERP ransomware" --description "Phish to encryption on the ERP estate" --threat_actor "financially motivated crimeware" --objective "encrypt ERP data" --target_assets erp_db,file_server --entry_vectors phishing,vpn
```
`--target_assets` and `--entry_vectors` take comma-separated lists. Repeating a
list flag appends to it.

### Add a Control
```
run threat_model_analyzer --action add_control --scenario_id <scenario_id> --name "EDR on ERP hosts" --control_type endpoint --implementation_status partial --bypass_difficulty high --detection_capability high --bypass_requirements "signed driver,kernel access"
```

### Add an Attack Event
```
run threat_model_analyzer --action add_event --scenario_id <scenario_id> --name "Spearphishing attachment" --sequence_order 1 --technique_name "Spearphishing Attachment" --technique_id T1566.001 --required_access none --resulting_access user --blocking_controls "mail filtering" --detecting_controls "EDR on ERP hosts"
```

### List, Analyze Gaps, Export
```
run threat_model_analyzer --action list_scenarios
run threat_model_analyzer --action gap_analysis --scenario_id <scenario_id>
run threat_model_analyzer --action export --scenario_id <scenario_id> --output_path workspace/artifacts/erp_threat_model.md
```

**JSON alternative.** Every tool also accepts a JSON payload. It is only
needed for list or object arguments that a flag cannot express, or when a
text value is long enough that quoting becomes unwieldy:
```
run threat_model_analyzer {"action": "create_scenario", "name": "ERP ransomware", "description": "Phish to encryption", "target_assets": ["erp_db", "file_server"]}
```

## Chains

- **From**: `log_investigator`
- **To**: `attack_path_visualizer`
