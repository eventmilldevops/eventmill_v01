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

## Chains

- **From**: `log_investigator`
- **To**: `attack_path_visualizer`
