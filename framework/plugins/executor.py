"""
Event Mill Plugin Executor

Wraps plugin execution with timeout enforcement, error handling,
structured logging, and artifact registration coordination.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from typing import Any

from .protocol import (
    ErrorCodes,
    EventMillToolProtocol,
    ExecutionContext,
    TimeoutClass,
    ToolResult,
)
from .loader import DEFAULT_SUMMARY_BUDGET, LoadedPlugin
from ..logging.structured import LogContext

logger = logging.getLogger("eventmill.framework.plugins.executor")


class ExecutionError(Exception):
    """Raised when plugin execution fails at the framework level."""

    def __init__(self, error_code: str, message: str):
        self.error_code = error_code
        self.message = message
        super().__init__(message)


class PluginExecutor:
    """Orchestrates plugin execution with safety guardrails.
    
    Responsibilities:
    - Input validation before execution
    - Timeout enforcement per timeout_class
    - Structured logging of execution lifecycle
    - Error capture and normalization
    - Summary extraction via summarize_for_llm()
    """

    def __init__(
        self,
        timeout_overrides: dict[str, int] | None = None,
    ):
        """Initialize executor.
        
        Args:
            timeout_overrides: Optional per-tool timeout overrides in seconds.
        """
        self.timeout_overrides = timeout_overrides or {}

    def execute(
        self,
        plugin: LoadedPlugin,
        payload: dict[str, Any],
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute a plugin with full lifecycle management.
        
        Args:
            plugin: The loaded plugin to execute.
            payload: The input payload.
            context: The execution context.
        
        Returns:
            ExecutionResult with tool result, summary, and timing.
        """
        tool_name = plugin.tool_name
        timeout = self._get_timeout(plugin)

        with LogContext(tool_name=tool_name, session_id=context.session_id):
            logger.info("Starting execution (timeout=%ds)", timeout)
            start_time = time.monotonic()

            # Phase 1: Get instance
            try:
                instance = plugin.get_instance()
            except Exception as e:
                logger.error("Failed to instantiate plugin: %s", e)
                return ExecutionResult(
                    tool_name=tool_name,
                    result=ToolResult(
                        ok=False,
                        error_code=ErrorCodes.INTERNAL_ERROR,
                        message=f"Plugin instantiation failed: {e}",
                    ),
                    summary="",
                    duration_ms=0,
                )

            # Phase 2: Validate inputs
            try:
                validation = instance.validate_inputs(payload)
                if not validation.ok:
                    errors = validation.errors or ["Unknown validation error"]
                    logger.warning("Input validation failed: %s", errors)
                    return ExecutionResult(
                        tool_name=tool_name,
                        result=ToolResult(
                            ok=False,
                            error_code=ErrorCodes.INPUT_VALIDATION_FAILED,
                            message="Input validation failed",
                            details={"errors": errors},
                        ),
                        summary="",
                        duration_ms=_elapsed_ms(start_time),
                    )
            except Exception as e:
                logger.error("Validation raised exception: %s", e)
                return ExecutionResult(
                    tool_name=tool_name,
                    result=ToolResult(
                        ok=False,
                        error_code=ErrorCodes.INTERNAL_ERROR,
                        message=f"Validation error: {e}",
                    ),
                    summary="",
                    duration_ms=_elapsed_ms(start_time),
                )

            # Phase 3: Execute with timeout
            try:
                result = self._execute_with_timeout(
                    instance, payload, context, timeout
                )
            except TimeoutError:
                logger.error("Execution timed out after %ds", timeout)
                return ExecutionResult(
                    tool_name=tool_name,
                    result=ToolResult(
                        ok=False,
                        error_code=ErrorCodes.TIMEOUT,
                        message=f"Execution timed out after {timeout}s",
                    ),
                    summary="",
                    duration_ms=_elapsed_ms(start_time),
                )
            except Exception as e:
                logger.error("Execution failed: %s", e, exc_info=True)
                return ExecutionResult(
                    tool_name=tool_name,
                    result=ToolResult(
                        ok=False,
                        error_code=ErrorCodes.INTERNAL_ERROR,
                        message=str(e),
                    ),
                    summary="",
                    duration_ms=_elapsed_ms(start_time),
                )

            duration_ms = _elapsed_ms(start_time)

            # Phase 4: Extract summary
            summary = ""
            if result.ok:
                # Read outside the try: a manifest that cannot supply a budget
                # is not the plugin's summarize_for_llm failing, and reporting
                # it as one sends the reader to the wrong file.
                budget = getattr(
                    plugin.manifest, "summary_budget", DEFAULT_SUMMARY_BUDGET,
                )
                try:
                    summary = instance.summarize_for_llm(result)
                    # The manifest's ceiling, not a constant: a tool that reads
                    # a 154-page report has more to say than one that lists
                    # files. Truncation here is a last resort and loses
                    # whatever the plugin put last, so a plugin that can run
                    # long is expected to budget its own summary rather than
                    # arrive here over the line.
                    if budget and len(summary) > budget:
                        original = len(summary)
                        summary = summary[: budget - 3] + "..."
                        logger.warning(
                            "Summary truncated to %d chars (was %d) - %s is "
                            "over its manifest summary_budget",
                            budget, original, tool_name,
                        )
                except Exception as e:
                    logger.warning("summarize_for_llm failed: %s", e)
                    summary = f"{tool_name} completed successfully."

            logger.info(
                "Execution %s (duration=%dms, ok=%s)",
                "completed" if result.ok else "failed",
                duration_ms,
                result.ok,
            )

            return ExecutionResult(
                tool_name=tool_name,
                result=result,
                summary=summary,
                duration_ms=duration_ms,
            )

    def _get_timeout(self, plugin: LoadedPlugin) -> int:
        """Get timeout for a plugin."""
        # Check overrides first
        if plugin.tool_name in self.timeout_overrides:
            return self.timeout_overrides[plugin.tool_name]

        # Use manifest timeout class
        timeout_class = plugin.manifest.timeout_class
        return TimeoutClass.get_limit(timeout_class)

    def _execute_with_timeout(
        self,
        instance: EventMillToolProtocol,
        payload: dict[str, Any],
        context: ExecutionContext,
        timeout: int,
    ) -> ToolResult:
        """Execute plugin with timeout enforcement using a thread.
        
        Uses threading rather than signals for Windows compatibility.
        """
        result_holder: list[ToolResult | None] = [None]
        error_holder: list[Exception | None] = [None]

        def target():
            try:
                result_holder[0] = instance.execute(payload, context)
            except Exception as e:
                error_holder[0] = e

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            # Thread still running — timed out
            raise TimeoutError(f"Plugin execution exceeded {timeout}s timeout")

        if error_holder[0] is not None:
            raise error_holder[0]

        if result_holder[0] is None:
            raise ExecutionError(
                ErrorCodes.INTERNAL_ERROR,
                "Plugin returned None instead of ToolResult",
            )

        return result_holder[0]


class ExecutionResult:
    """Result of a managed plugin execution."""

    def __init__(
        self,
        tool_name: str,
        result: ToolResult,
        summary: str,
        duration_ms: int,
    ):
        self.tool_name = tool_name
        self.result = result
        self.summary = summary
        self.duration_ms = duration_ms

    @property
    def ok(self) -> bool:
        return self.result.ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "ok": self.result.ok,
            "result": self.result.result,
            "error_code": self.result.error_code,
            "message": self.result.message,
            "summary": self.summary,
            "duration_ms": self.duration_ms,
            "output_artifacts": self.result.output_artifacts,
        }


def _elapsed_ms(start: float) -> int:
    """Calculate elapsed milliseconds from a monotonic start time."""
    return int((time.monotonic() - start) * 1000)
