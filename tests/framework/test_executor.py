"""
Tests for plugin executor.
"""

import time
from typing import Any

import pytest
from pathlib import Path

from framework.plugins.protocol import (
    ErrorCodes,
    ExecutionContext,
    ReferenceDataView,
    ToolResult,
    ValidationResult,
)
from framework.plugins.executor import PluginExecutor, ExecutionResult
from framework.plugins.loader import DEFAULT_SUMMARY_BUDGET, PluginLoader


# ---------------------------------------------------------------------------
# Helpers — minimal plugin classes for testing executor behavior
# ---------------------------------------------------------------------------


class GoodPlugin:
    """Plugin that succeeds."""

    def metadata(self) -> dict[str, Any]:
        return {"tool_name": "good_plugin", "version": "1.0.0"}

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        return ToolResult(ok=True, result={"answer": 42})

    def summarize_for_llm(self, result: ToolResult) -> str:
        return "Good plugin returned answer 42."


class BadValidationPlugin:
    """Plugin that fails validation."""

    def metadata(self) -> dict[str, Any]:
        return {"tool_name": "bad_val", "version": "1.0.0"}

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(ok=False, errors=["missing required field"])

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        raise RuntimeError("Should not be called")

    def summarize_for_llm(self, result: ToolResult) -> str:
        return ""


class CrashingPlugin:
    """Plugin that raises during execute."""

    def metadata(self) -> dict[str, Any]:
        return {"tool_name": "crasher", "version": "1.0.0"}

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        raise ValueError("Unexpected data format")

    def summarize_for_llm(self, result: ToolResult) -> str:
        return ""


class SlowPlugin:
    """Plugin that takes too long."""

    def metadata(self) -> dict[str, Any]:
        return {"tool_name": "slow_plugin", "version": "1.0.0"}

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        time.sleep(10)  # Will exceed timeout
        return ToolResult(ok=True)

    def summarize_for_llm(self, result: ToolResult) -> str:
        return "Slow plugin done."


class BadSummaryPlugin:
    """Plugin whose summarize_for_llm raises."""

    def metadata(self) -> dict[str, Any]:
        return {"tool_name": "bad_summary", "version": "1.0.0"}

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        return ToolResult(ok=True, result={"data": "ok"})

    def summarize_for_llm(self, result: ToolResult) -> str:
        raise RuntimeError("Summary generation failed")


class LongSummaryPlugin:
    """Plugin that returns an oversized summary."""

    def metadata(self) -> dict[str, Any]:
        return {"tool_name": "long_summary", "version": "1.0.0"}

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        return ToolResult(ok=True, result={"data": "ok"})

    def summarize_for_llm(self, result: ToolResult) -> str:
        return "A" * 9000  # Way over any manifest's summary_budget


# ---------------------------------------------------------------------------
# Fake LoadedPlugin wrapper
# ---------------------------------------------------------------------------


class FakeManifest:
    def __init__(
        self,
        tool_name: str,
        timeout_class: str = "fast",
        summary_budget: int = DEFAULT_SUMMARY_BUDGET,
    ):
        self.tool_name = tool_name
        self.timeout_class = timeout_class
        self.summary_budget = summary_budget


class FakeLoadedPlugin:
    """Minimal stand-in for LoadedPlugin for executor tests."""

    def __init__(self, instance, tool_name: str = "test", timeout_class: str = "fast"):
        self._instance = instance
        self.tool_name = tool_name
        self.manifest = FakeManifest(tool_name, timeout_class)
        self.pillar = "log_analysis"

    def get_instance(self):
        return self._instance


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def executor() -> PluginExecutor:
    return PluginExecutor()


@pytest.fixture
def context() -> ExecutionContext:
    return ExecutionContext(
        session_id="sess_test123",
        selected_pillar="log_analysis",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPluginExecutor:
    """Tests for PluginExecutor."""

    def test_successful_execution(self, executor: PluginExecutor, context: ExecutionContext):
        """Test normal successful execution."""
        plugin = FakeLoadedPlugin(GoodPlugin(), "good_plugin")
        result = executor.execute(plugin, {}, context)

        assert result.ok
        assert result.result.ok
        assert result.result.result == {"answer": 42}
        assert result.summary == "Good plugin returned answer 42."
        assert result.duration_ms >= 0
        assert result.tool_name == "good_plugin"

    def test_validation_failure(self, executor: PluginExecutor, context: ExecutionContext):
        """Test that validation failure stops execution."""
        plugin = FakeLoadedPlugin(BadValidationPlugin(), "bad_val")
        result = executor.execute(plugin, {}, context)

        assert not result.ok
        assert result.result.error_code == ErrorCodes.INPUT_VALIDATION_FAILED
        assert result.summary == ""

    def test_execution_crash(self, executor: PluginExecutor, context: ExecutionContext):
        """Test that execution exceptions are caught cleanly."""
        plugin = FakeLoadedPlugin(CrashingPlugin(), "crasher")
        result = executor.execute(plugin, {}, context)

        assert not result.ok
        assert result.result.error_code == ErrorCodes.INTERNAL_ERROR
        assert "Unexpected data format" in result.result.message

    def test_timeout_enforcement(self, executor: PluginExecutor, context: ExecutionContext):
        """Test that slow plugins are timed out."""
        # Override timeout to 1 second for test speed
        executor.timeout_overrides["slow_plugin"] = 1
        plugin = FakeLoadedPlugin(SlowPlugin(), "slow_plugin")

        result = executor.execute(plugin, {}, context)

        assert not result.ok
        assert result.result.error_code == ErrorCodes.TIMEOUT

    def test_summary_failure_fallback(self, executor: PluginExecutor, context: ExecutionContext):
        """Test that a crashing summarize_for_llm produces a fallback."""
        plugin = FakeLoadedPlugin(BadSummaryPlugin(), "bad_summary")
        result = executor.execute(plugin, {}, context)

        assert result.ok
        assert "bad_summary" in result.summary
        assert "completed successfully" in result.summary

    def test_summary_truncation(self, executor: PluginExecutor, context: ExecutionContext):
        """An oversized summary is cut to the manifest's summary_budget."""
        plugin = FakeLoadedPlugin(LongSummaryPlugin(), "long_summary")
        result = executor.execute(plugin, {}, context)

        assert result.ok
        assert len(result.summary) <= DEFAULT_SUMMARY_BUDGET
        assert result.summary.endswith("...")

    def test_the_budget_comes_from_the_manifest(
        self, executor: PluginExecutor, context: ExecutionContext,
    ):
        """A tool that reads a 154-page report has more to say than one that
        lists files, so the ceiling travels with the tool rather than being a
        constant every plugin shares."""
        plugin = FakeLoadedPlugin(LongSummaryPlugin(), "long_summary")
        plugin.manifest.summary_budget = 8000
        result = executor.execute(plugin, {}, context)

        assert len(result.summary) == 8000
        assert result.summary.endswith("...")

    def test_a_manifest_without_a_budget_falls_back_to_the_default(
        self, executor: PluginExecutor, context: ExecutionContext,
    ):
        """And does not report the missing field as summarize_for_llm failing
        - that sends whoever reads the log to the wrong file."""
        plugin = FakeLoadedPlugin(LongSummaryPlugin(), "long_summary")
        del plugin.manifest.summary_budget
        result = executor.execute(plugin, {}, context)

        assert len(result.summary) == DEFAULT_SUMMARY_BUDGET
        assert result.summary.startswith("A")

    def test_a_summary_inside_the_budget_is_untouched(
        self, executor: PluginExecutor, context: ExecutionContext,
    ):
        plugin = FakeLoadedPlugin(GoodPlugin(), "good_plugin")
        result = executor.execute(plugin, {}, context)

        assert not result.summary.endswith("...")

    def test_to_dict(self, executor: PluginExecutor, context: ExecutionContext):
        """Test ExecutionResult serialization."""
        plugin = FakeLoadedPlugin(GoodPlugin(), "good_plugin")
        result = executor.execute(plugin, {}, context)

        data = result.to_dict()
        assert data["tool_name"] == "good_plugin"
        assert data["ok"] is True
        assert data["result"] == {"answer": 42}
        assert isinstance(data["duration_ms"], int)
        assert data["summary"] == "Good plugin returned answer 42."

    def test_execution_with_real_plugin(
        self, temp_plugins_dir: Path, context: ExecutionContext
    ):
        """Test executor with a real plugin loaded from disk."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()

        plugin = loader.get("test_plugin")
        assert plugin is not None

        executor = PluginExecutor()
        result = executor.execute(plugin, {"test_input": "hello"}, context)

        assert result.ok
        assert result.result.result["processed"] == "hello"
        assert "successfully" in result.summary
