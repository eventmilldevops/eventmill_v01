"""
Event Mill Test Configuration

Shared pytest fixtures for framework and plugin tests.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_workspace() -> Generator[Path, None, None]:
    """Create a temporary workspace directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        (workspace / "sessions").mkdir()
        (workspace / "artifacts").mkdir()
        (workspace / "logs").mkdir()
        yield workspace


@pytest.fixture
def temp_plugins_dir(temp_workspace: Path) -> Path:
    """Create a temporary plugins directory with test plugin."""
    plugins_dir = temp_workspace / "plugins"
    plugins_dir.mkdir()
    
    # Create a minimal test plugin
    test_pillar = plugins_dir / "log_analysis"
    test_pillar.mkdir()
    
    test_plugin = test_pillar / "test_plugin"
    test_plugin.mkdir()
    
    # Create manifest
    manifest = {
        "tool_name": "test_plugin",
        "version": "1.0.0",
        "pillar": "log_analysis",
        "display_name": "Test Plugin",
        "description_short": "A test plugin for unit tests",
        "entry_point": "tool.py",
        "class_name": "TestPlugin",
        "artifacts_consumed": ["text"],
        "artifacts_produced": ["json_events"],
        "capabilities": ["test:basic"],
        "timeout_class": "fast",
        "safe_for_auto_invoke": True,
        "requires_llm": False,
        "stability": "experimental",
        "tags": ["test"],
    }
    
    with open(test_plugin / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    
    # Create tool.py
    tool_code = '''
"""Test plugin implementation."""

from dataclasses import dataclass
from typing import Any


@dataclass
class ToolResult:
    ok: bool
    result: dict | None = None
    error_code: str | None = None
    message: str | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


class TestPlugin:
    """Test plugin for unit tests."""
    
    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "test_plugin",
            "version": "1.0.0",
        }
    
    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        if "test_input" not in payload:
            return ValidationResult(ok=False, errors=["Missing test_input"])
        return ValidationResult(ok=True)
    
    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        return ToolResult(
            ok=True,
            result={"processed": payload.get("test_input", "")},
        )
    
    def summarize_for_llm(self, result: ToolResult) -> str:
        if result.ok:
            return f"Test plugin processed input successfully."
        return f"Test plugin failed: {result.message}"
'''
    
    with open(test_plugin / "tool.py", "w") as f:
        f.write(tool_code)
    
    # Create schemas directory
    schemas_dir = test_plugin / "schemas"
    schemas_dir.mkdir()
    
    input_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "test_input": {"type": "string"}
        },
        "required": ["test_input"]
    }
    
    with open(schemas_dir / "input.schema.json", "w") as f:
        json.dump(input_schema, f, indent=2)
    
    output_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "processed": {"type": "string"}
        }
    }
    
    with open(schemas_dir / "output.schema.json", "w") as f:
        json.dump(output_schema, f, indent=2)
    
    return plugins_dir


@pytest.fixture
def routing_config_dir(temp_workspace: Path) -> Path:
    """Create routing configuration files."""
    config_dir = temp_workspace / "routing_config"
    config_dir.mkdir()
    
    pillars = {
        "pillars": {
            "log_analysis": {
                "enabled": True,
                "display_name": "Log Analysis",
                "description": "Test pillar"
            }
        }
    }
    
    with open(config_dir / "pillars.json", "w") as f:
        json.dump(pillars, f)
    
    keywords = {
        "keyword_rules": {
            "log_analysis": ["log", "event", "parse"]
        }
    }
    
    with open(config_dir / "keywords.json", "w") as f:
        json.dump(keywords, f)
    
    artifact_rules = {
        "artifact_pillar_mapping": {
            "text": {"pillar": "log_analysis", "strength": "moderate"}
        }
    }
    
    with open(config_dir / "artifact_rules.json", "w") as f:
        json.dump(artifact_rules, f)
    
    return config_dir


@pytest.fixture
def sample_artifact_file(temp_workspace: Path) -> Path:
    """Create a sample artifact file."""
    artifacts_dir = temp_workspace / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    
    sample_file = artifacts_dir / "sample.txt"
    sample_file.write_text("Sample artifact content for testing.")
    
    return sample_file
