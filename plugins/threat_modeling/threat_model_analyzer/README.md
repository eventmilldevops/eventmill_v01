# Threat Model Analyzer

**Analyze threat models, track scenarios, controls, attack events, and identify defense gaps.**

## What It Does

Nine actions for threat modeling:

1. **analyze_document** — Summarize what a threat model document or tabletop exercise minutes state: assets, threats named, controls documented, gaps recorded. It does not construct attack paths or assign ATT&CK techniques the document does not cite.
2. **create_scenario** — Create a trackable threat scenario with actor, objectives, assets
3. **add_control** — Add security controls with defense layer, bypass difficulty, implementation status
4. **add_event** — Add attack sequence events with MITRE ATT&CK mapping and control references
5. **list_scenarios** — List all tracked scenarios with summary stats
6. **gap_analysis** — Identify steps with no implemented control, weak controls, and easy bypasses
7. **export** — Generate markdown report with full scenario details
8. **export_scenario** — Save scenarios in full (controls and events included) so they can be reloaded
9. **import_scenario** — Load an `adversary_path_projector` scenario seed, or a saved `export_scenario` result

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `pdf` | Threat model documents |
| Consumed | `json_events` | Scenario seeds from `adversary_path_projector`; `export_scenario` results |
| Produced | `json_events`, `text` | Analysis results, full scenario exports, markdown reports |

## Output Persistence

On successful completion the framework automatically writes the full result to:
```
workspace/artifacts/threat_model_analyzer_<YYYYMMDD_HHMMSS>.json
```
The file is registered as a `json_events` session artifact. Use `artifacts` to get its ID.
- The `export` action additionally produces a markdown report — its `output` field is extracted and saved as `.md`
- Scenario and gap analysis results can be loaded into `attack_path_visualizer` via the artifact ID
- Use `export <artifact_id>` to push the JSON to `common/exports/threat_model_analyzer/` in cloud storage for external access or troubleshooting

**Scenarios live in memory until exported.** The tracker does not survive a
shell restart and is not reset by `new`. Run `export_scenario` to keep a
half-built threat model; the auto-persisted artifact is exactly what
`import_scenario` reads back.

## Defense Layers

`perimeter`, `network`, `endpoint`, `application`, `data`, `identity`, `monitoring`

## Example Workflows

Built by hand:
```
1. analyze_document → Summarize what the document states
2. create_scenario → Track the scenario with ID
3. add_control (x N) → Map existing security controls
4. add_event (x N) → Map attack sequence with MITRE ATT&CK
5. gap_analysis → Identify defense weaknesses
6. export → Generate markdown report
```

From a threat actor projection:
```
1. adversary_path_projector project_paths → attack graph + scenario seed artifact
2. import_scenario --artifact_id <seed>  → one scenario per projected path
3. gap_analysis --scenario_id <id>       → steps with no implemented control
4. export --scenario_id <id>             → markdown report
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
run threat_model_analyzer --action add_event --scenario_id <scenario_id> --name "Spearphishing attachment" --sequence_order 1 --technique_name "Spearphishing Attachment" --technique_id T1566.001 --tactic "Initial Access" --required_access none --resulting_access user --blocking_controls "mail filtering" --detecting_controls "EDR on ERP hosts"
```

### List, Analyze Gaps, Export
```
run threat_model_analyzer --action list_scenarios
run threat_model_analyzer --action gap_analysis --scenario_id <scenario_id>
run threat_model_analyzer --action export --scenario_id <scenario_id> --output_path workspace/artifacts/erp_threat_model.md
```

### Save and Reload Scenarios
```
run threat_model_analyzer --action export_scenario --scenario_id <scenario_id>
run threat_model_analyzer --action export_scenario
run threat_model_analyzer --action import_scenario --artifact_id <artifact_id>
```
Omit `--scenario_id` to export every scenario in the tracker.

### Import a Projection
```
run threat_model_analyzer --action import_scenario --artifact_id <seed_artifact_id>
run threat_model_analyzer --action import_scenario --artifact_id <seed_artifact_id> --path_id s3-session-exfil
run threat_model_analyzer --action import_scenario --artifact_id <seed_artifact_id> --max_paths 3
```
Use the **scenario seed** artifact (`adversary_scenario_seed_*.json`), not the
attack graph. Each projected path becomes its own scenario, up to `--max_paths`
(default 6, maximum 10) — every path is something an analyst has to review, so
paths over the limit are listed by id and not imported. `--path_id` imports one.

Imported scenarios are marked `source_type: actor_projection`. Each step keeps
its ATT&CK tactic and its evidence — `documented` when ATT&CK attributes the
technique to the actor, `via_software` when only the actor's tooling implements
it — and the markdown report states that placement is modelled, not observed.

A document is checked in full before anything is created: an invalid control
type, enum value or sequence order imports nothing and lists every problem.
Control and event ids are reissued by the tracker, and event references to the
old control ids follow.

**What "blocking" means for a projected step.** A control counts as blocking
when it is implemented, on a preventive layer, and on the component the step
lands on — whether or not it addresses that particular technique. That answers
triage's first question, *is there a control there at all*, which is why the
markdown report labels such a step `CONTROL_PRESENT` rather than "protected".
How good the control is against the technique is a separate assessment.

**JSON alternative.** Every tool also accepts a JSON payload. It is only
needed for list or object arguments that a flag cannot express, or when a
text value is long enough that quoting becomes unwieldy:
```
run threat_model_analyzer {"action": "create_scenario", "name": "ERP ransomware", "description": "Phish to encryption", "target_assets": ["erp_db", "file_server"]}
```

## Chains

- **From**: `log_investigator`, `adversary_path_projector`
- **To**: `attack_path_visualizer`
