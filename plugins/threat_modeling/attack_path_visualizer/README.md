# Attack Path Visualizer

**Generate ASCII art, Mermaid diagrams, and compact flow visualizations of attack paths.**

## What It Does

Four output formats for attack path visualization:

1. **ascii** — Detailed box-and-arrow diagrams with control effectiveness bars, gaps, and MITRE ATT&CK technique IDs
2. **mermaid** — Flowchart syntax for markdown/GitHub rendering with color-coded protection status and control coverage matrix
3. **compact** — Single-line flow diagram with stage/control/gap counts
4. **both** — Combined ASCII + Mermaid output

## How to Run

### Usage Syntax

```bash
# From threat_intel_ingester output (most common — generates graph from MITRE mappings)
run attack_path_visualizer {"artifact_id": "<artifact_id>", "format": "mermaid"}

# ASCII art (terminal-friendly)
run attack_path_visualizer {"artifact_id": "<artifact_id>", "format": "ascii"}

# Compact single-line flow
run attack_path_visualizer {"artifact_id": "<artifact_id>", "format": "compact"}

# Both ASCII + Mermaid
run attack_path_visualizer {"artifact_id": "<artifact_id>", "format": "both"}

# Inline stages (no artifact needed)
run attack_path_visualizer {"format": "ascii", "attack_type": "ransomware", "stages": [...]}
```

### Input Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `artifact_id` | One of `artifact_id` or `stages` | — | ID of a `json_events` artifact from `threat_intel_ingester` |
| `format` | No | `"ascii"` | Output format: `ascii`, `mermaid`, `compact`, `both` |
| `attack_type` | No | `"unknown"` | Attack type label for the diagram header |
| `attack_narrative` | No | — | Brief narrative description of the attack path |
| `stages` | One of `artifact_id` or `stages` | — | Inline stage objects (see schema) |
| `include_controls` | No | `true` | Include control coverage matrix in mermaid output |

### Quick Start from Ingester

The `threat_intel_ingester` summary includes a ready-to-paste command:
```
Quick chart: run attack_path_visualizer {"artifact_id": "art_XXXX", "format": "mermaid"}
```
Copy, adjust the artifact ID, and paste into the Event Mill shell.

## Color Coding (Mermaid)

- **Green** — Stage has controls
- **Yellow** — Stage has no controls (unprotected)
- **Red** — Stage has detected gaps

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `json_events` | IOC/MITRE data from `threat_intel_ingester`, or stage data from `risk_assessment_analyzer`/`threat_model_analyzer` |
| Produced | `text` | Rendered visualization |

## Output Persistence

The tool writes the visualization directly to a format-specific file:

| Format | Output file |
|--------|-------------|
| `mermaid` | `workspace/artifacts/attack_path_mermaid_<ts>.mmd` |
| `ascii` | `workspace/artifacts/attack_path_ascii_<ts>.txt` |
| `compact` | `workspace/artifacts/attack_path_compact_<ts>.txt` |
| `both` | `workspace/artifacts/attack_path_both_<ts>.txt` |

The file is registered as a `text` session artifact. The artifact ID and full path are shown in the run summary. `.mmd` files can be rendered directly in GitHub, VS Code, or any Mermaid-compatible viewer.

## Example — Direct from threat_intel_ingester

```json
{"artifact_id": "art_04d30b48", "format": "mermaid"}
```

Stages are automatically derived from the MITRE technique mappings in the `json_events` artifact, ordered by kill-chain sequence.

### Composite Node Keys: `(technique_id, tactic)`

The visualizer uses **`(technique_id, tactic)` as the node identity**, matching
the ingester's composite key. When the same technique appears with different
tactics (e.g., T1078 as "Initial Access" and T1078 as "Persistence"), each
combination renders as a **separate node** in the graph. This preserves the
multi-role context that the attack graph encodes.

Consumers should **never** collapse nodes by `technique_id` alone — doing so
flattens the tactical context and loses per-path role distinctions.

### Tactic Mismatch Indicators

Entries from `threat_intel_ingester` may carry `"tactic_mismatch": true` when
the assigned tactic is not in the technique's official ATT&CK tactic list.
These nodes represent real attacker behavior described in the report, but the
tactic label may be an LLM inference rather than an exact MITRE matrix mapping.
Analysts should treat them with appropriate scrutiny.

## Example — Inline stages

```json
{
  "format": "ascii",
  "attack_type": "ransomware",
  "stages": [
    {"name": "Initial Access", "mitre_technique_id": "T1566", "stage_present": true, "controls": [...]}
  ]
}
```

## Chains

- **From**: `threat_model_analyzer`, `risk_assessment_analyzer`

## Notes

- No LLM required — purely deterministic rendering
- Safe for auto-invoke
- Use `help attack_path_visualizer` in the Event Mill shell to see usage syntax
