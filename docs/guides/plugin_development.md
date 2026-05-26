# Plugin Development Guide

This guide walks through creating a new Event Mill plugin from scratch.

## Prerequisites

- Python 3.11+
- Event Mill installed (`pip install -e .` from project root)
- Familiarity with the [Tool Plugin Spec](../specs/tool_plugin_spec.md)

## Plugin Structure

Every plugin lives under `plugins/<pillar>/<tool_name>/` and contains:

```
plugins/
  log_analysis/
    my_new_tool/
      tool.py                  # Implementation (required)
      manifest.json            # Metadata contract (required)
      README.md                # Documentation (required)
      schemas/
        input.schema.json      # JSON Schema for inputs (required)
        output.schema.json     # JSON Schema for outputs (required)
      examples/
        request.example.json   # Sample request (required)
        response.example.json  # Sample response (required)
      tests/
        test_contract.py       # Contract compliance tests (required)
```

## Step 1: Create the Directory

```bash
mkdir -p plugins/log_analysis/my_new_tool/{schemas,examples,tests}
```

## Step 2: Write the Manifest

Create `manifest.json` with your plugin's metadata:

```json
{
  "tool_name": "my_new_tool",
  "version": "1.0.0",
  "pillar": "log_analysis",
  "display_name": "My New Tool",
  "description_short": "One-line description of what this tool does.",
  "description_long": "Detailed explanation of the tool's purpose and behavior.",
  "author": "Your Name",
  "entry_point": "tool.py",
  "class_name": "MyNewTool",
  "artifacts_consumed": ["text", "log_stream"],
  "artifacts_produced": ["json_events"],
  "capabilities": ["log_analysis:parse", "log_analysis:extract"],
  "input_schema": "schemas/input.schema.json",
  "output_schema": "schemas/output.schema.json",
  "timeout_class": "medium",
  "cost_hint": "low",
  "safe_for_auto_invoke": false,
  "requires_llm": false,
  "dependencies": [],
  "stability": "experimental",
  "tags": ["parsing", "extraction"],
  "chains_to": [],
  "chains_from": []
}
```

### Key Fields

| Field | Description |
|-------|-------------|
| `pillar` | Must match the parent directory name |
| `timeout_class` | `fast` (30s), `medium` (120s), or `slow` (300s) |
| `safe_for_auto_invoke` | `true` only if the tool has no side effects |
| `artifacts_consumed` | Types this tool can read as input |
| `artifacts_produced` | Types this tool registers as output |
| `capabilities` | Routing hints in `pillar:action` format |

## Step 3: Define Schemas

### `schemas/input.schema.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "log_file": {
      "type": "string",
      "description": "Path to the log file to analyze"
    },
    "max_lines": {
      "type": "integer",
      "default": 1000,
      "description": "Maximum lines to process"
    }
  },
  "required": ["log_file"]
}
```

### `schemas/output.schema.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "events": {
      "type": "array",
      "items": { "type": "object" }
    },
    "total_count": {
      "type": "integer"
    }
  }
}
```

## Step 4: Implement the Plugin

Create `tool.py` implementing the `EventMillToolProtocol`:

```python
"""My New Tool — parses logs into structured events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ToolResult:
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    output_artifacts: list[str] | None = None
    details: dict[str, Any] | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


class MyNewTool:
    """Parses log files into structured security events."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "my_new_tool",
            "version": "1.0.0",
            "pillar": "log_analysis",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        """Validate the input payload."""
        errors = []

        if "log_file" not in payload:
            errors.append("'log_file' is required")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute the tool.

        Args:
            payload: Validated input matching input.schema.json.
            context: ExecutionContext provided by the framework.
                     Contains session_id, artifacts, llm_query, etc.
        """
        log_file = payload["log_file"]
        max_lines = payload.get("max_lines", 1000)

        try:
            # --- Your analysis logic here ---
            events = self._parse_log(log_file, max_lines)

            # Register output artifact if context supports it
            if context and hasattr(context, "register_artifact") and context.register_artifact:
                # Write output to file, then register
                pass

            return ToolResult(
                ok=True,
                result={
                    "events": events,
                    "total_count": len(events),
                },
            )
        except FileNotFoundError:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Log file not found: {log_file}",
            )
        except Exception as e:
            return ToolResult(
                ok=False,
                error_code="INTERNAL_ERROR",
                message=str(e),
            )

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context (max 2000 chars).

        This is critical for Event Mill's context optimization.
        Return only the information the LLM needs to decide
        the next investigation step.
        """
        if not result.ok:
            return f"my_new_tool failed: {result.message}"

        data = result.result or {}
        count = data.get("total_count", 0)

        lines = [
            f"Parsed {count} events from log file.",
        ]

        # Add top-level findings only — no raw data
        events = data.get("events", [])
        if events:
            lines.append(f"First event: {events[0]}")

        return "\n".join(lines)

    def _parse_log(self, path: str, max_lines: int) -> list[dict]:
        """Internal: parse the log file."""
        # Implementation details...
        return []
```

### Important Conventions

1. **`summarize_for_llm()`** must return ≤ 2000 characters. The framework will truncate if you exceed this, but aim for ~500-1000 chars with the most actionable findings.

2. **Error codes** should use the standard set: `INPUT_VALIDATION_FAILED`, `ARTIFACT_NOT_FOUND`, `TIMEOUT`, `LLM_QUERY_FAILED`, `INTERNAL_ERROR`, `DEPENDENCY_ERROR`.

3. **Never import framework internals** in your plugin. The `context` object is your only interface to the framework.

4. **Artifact registration** happens through `context.register_artifact()`, not by writing files directly.

## Using LLM Capabilities

### QueryHints for Model Selection

When calling the LLM, pass `QueryHints` to guide the dispatcher toward the right model tier:

```python
from framework.plugins.protocol import QueryHints

# Light model (default) — fast, cheap, good for bulk extraction
response = context.llm_query.query_text(
    prompt=my_prompt,
    max_tokens=3000,
    hints=QueryHints(tier="light"),
)

# Heavy model with reasoning — for complex analysis
response = context.llm_query.query_text(
    prompt=my_prompt,
    max_tokens=8192,
    hints=QueryHints(tier="heavy", needs_reasoning=True),
)
```

If you omit `hints`, the dispatcher falls back to token-count-based routing (same behavior as before).

### Native Document Ingestion

For plugins that process PDFs or other document artifacts, use `query_with_document()` instead of manually extracting text and chunking it:

```python
from framework.plugins.protocol import QueryHints

# Find the PDF artifact
pdf_artifact = next(
    (a for a in context.artifacts if a.artifact_type == "pdf_report"),
    None,
)

if pdf_artifact and context.llm_query.supports_native_document("application/pdf"):
    # Native path — the dispatcher sends the full PDF to the model
    response = context.llm_query.query_with_document(
        prompt="Extract all IOCs from this threat intel report...",
        artifact=pdf_artifact,
        hints=QueryHints(tier="heavy", prefers_native_file=True),
    )
    # response.transport_path tells you how it was ingested:
    #   "gs_uri"        — zero-copy from GCS
    #   "inline_bytes"  — uploaded as raw bytes
else:
    # Fallback — extract text yourself and use query_text()
    text = extract_text_from_pdf(pdf_artifact.file_path)
    response = context.llm_query.query_text(
        prompt=f"Extract IOCs from:\n{text}",
        max_tokens=3000,
    )
```

This eliminates the chunking-and-reassembly pattern that loses document context.

### Artifact storage_uri

Artifacts loaded from cloud storage have a `storage_uri` field (e.g. `gs://bucket/path.pdf`). The framework uses this for zero-copy ingestion. Plugins do **not** need to handle this field directly — just pass the artifact to `query_with_document()`.

## Step 5: Add Examples

### `examples/request.example.json`

```json
{
  "log_file": "/workspace/artifacts/sample.log",
  "max_lines": 500
}
```

### `examples/response.example.json`

```json
{
  "ok": true,
  "result": {
    "events": [
      {"timestamp": "2025-01-15T10:30:00Z", "source_ip": "192.168.1.100", "action": "login_failed"}
    ],
    "total_count": 1
  }
}
```

## Step 6: Write Contract Tests

Create `tests/test_contract.py`:

```python
"""Contract compliance tests for my_new_tool."""

import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_DIR))


@pytest.fixture
def manifest():
    with open(PLUGIN_DIR / "manifest.json") as f:
        return json.load(f)


@pytest.fixture
def plugin_instance():
    from tool import MyNewTool
    return MyNewTool()


class TestManifest:
    def test_required_fields(self, manifest):
        required = ["tool_name", "version", "pillar", "entry_point", "class_name"]
        for field in required:
            assert field in manifest

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert "tool_name" in meta
        assert "version" in meta

    def test_validate_inputs_accepts_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({"log_file": "/tmp/test.log"})
        assert result.ok

    def test_validate_inputs_rejects_invalid(self, plugin_instance):
        result = plugin_instance.validate_inputs({})
        assert not result.ok

    def test_summarize_length(self, plugin_instance):
        from tool import ToolResult
        result = ToolResult(ok=True, result={"events": [], "total_count": 0})
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
```

## Step 7: Write the README

Create `README.md` documenting:
- What the tool does
- Input/output artifact types
- Example usage
- Limitations and known issues

## Step 8: Validate

Run the validation scripts from the project root:

```bash
# Validate manifest against schema
python scripts/validate_manifests.py

# Validate input/output schemas
python scripts/validate_schemas.py

# Run your contract tests
python -m pytest plugins/log_analysis/my_new_tool/tests/ -v

# Generate updated tool catalog
python scripts/generate_tool_catalog.py
```

## Available Pillars

| Pillar | Description |
|--------|-------------|
| `log_analysis` | Log parsing, pattern detection, event extraction |
| `network_forensics` | PCAP analysis, flow reconstruction, DNS investigation |
| `threat_modeling` | MITRE ATT&CK mapping, threat intelligence correlation |
| `cloud_investigation` | Cloud audit log analysis, IAM review, resource forensics |
| `risk_assessment` | Risk scoring, compliance mapping, impact analysis |

## Artifact Types

| Type | Description |
|------|-------------|
| `pcap` | Network packet capture files |
| `json_events` | Structured JSON event data |
| `log_stream` | Raw or semi-structured log text |
| `risk_model` | Risk assessment model output |
| `cloud_audit_log` | Cloud provider audit logs |
| `pdf_report` | PDF format reports |
| `html_report` | HTML format reports |
| `image` | Screenshot or diagram images |
| `text` | Plain text files |

## LLMResponse Diagnostics

The `LLMResponse` includes diagnostic fields that help with debugging:

- **`model_used`** — which model actually ran the query (e.g. `gemini-2.5-flash`)
- **`transport_path`** — how the document was ingested (`gs_uri`, `inline_bytes`, `text`)
- **`fallback_reason`** — why the preferred path wasn’t used (if applicable)

Plugins MAY log these for diagnostics but MUST NOT branch on specific model names.

## Routing Integration

The router uses your manifest to determine when your tool should be suggested:

- **`capabilities`**: Primary routing signal. Format: `pillar:action`.
- **`artifacts_consumed`**: Tools are suggested when matching artifacts are loaded.
- **`tags`**: Secondary signal for keyword-based routing.
- **`chains_to` / `chains_from`**: Suggests tool sequences to the LLM.

## Troubleshooting

- **Plugin not discovered**: Ensure `manifest.json` exists and `pillar` matches the directory name.
- **Import errors**: Check that `entry_point` and `class_name` in manifest match your `tool.py`.
- **Validation failures**: Run `python scripts/validate_manifests.py` for detailed errors.
- **Timeout**: Adjust `timeout_class` in manifest or optimize your `execute()` method.
