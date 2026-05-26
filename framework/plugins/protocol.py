"""
Event Mill Tool Protocol

Defines the runtime contract for Event Mill plugins.
This is the normative implementation of tool_plugin_spec.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


# ---------------------------------------------------------------------------
# Result Types
# ---------------------------------------------------------------------------


@dataclass
class ToolResult:
    """Standard tool execution result.
    
    All plugin execute() methods must return this type.
    """
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    details: dict[str, Any] | None = None
    output_artifacts: list[dict[str, Any]] | None = None


@dataclass
class ValidationResult:
    """Input validation result.
    
    Returned by validate_inputs() before execution.
    """
    ok: bool
    errors: list[str] | None = None


@dataclass
class QueryHints:
    """Plugin hints to the LLMDispatcher about what kind of query this is.
    
    Plugins pass these to guide model selection without knowing provider details.
    All fields are optional — the dispatcher uses sensible defaults.
    """
    tier: str = "light"                    # "light" | "heavy"
    needs_reasoning: bool = False          # biases toward deep-reasoning models
    needs_structured_output: bool = False  # ensures JSON-mode capable model
    prefers_native_file: bool = False      # prefer native file > text extraction
    max_budget_cents: float | None = None  # cost ceiling per call (safety net)


@dataclass
class LLMResponse:
    """Response from LLM query.
    
    Returned by LLMQueryInterface methods.
    """
    ok: bool
    text: str | None = None
    error: str | None = None
    token_usage: dict[str, int] | None = None
    model_used: str | None = None          # which model actually ran
    transport_path: str | None = None      # "gs_uri", "inline_bytes", "text_fallback"
    fallback_reason: str | None = None     # why preferred path wasn't used


# ---------------------------------------------------------------------------
# Reference Types
# ---------------------------------------------------------------------------


@dataclass
class ArtifactRef:
    """Reference to a registered artifact.
    
    Immutable after creation. Plugins receive these via ExecutionContext.
    """
    artifact_id: str
    artifact_type: str
    file_path: str
    storage_uri: str | None = None
    source_tool: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ReferenceDataView:
    """Read-only view of framework reference data.
    
    Provides access to MITRE ATT&CK, attack chains, vetted sources, etc.
    Plugin-specific reference data is merged when the plugin is active.
    """
    
    def __init__(self, data: dict[str, Any] | None = None):
        self._data = data or {}
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a reference data entry by key."""
        return self._data.get(key, default)
    
    def keys(self) -> list[str]:
        """List available reference data keys."""
        return list(self._data.keys())
    
    def __contains__(self, key: str) -> bool:
        return key in self._data


# ---------------------------------------------------------------------------
# LLM Query Interface
# ---------------------------------------------------------------------------


class LLMQueryInterface(Protocol):
    """Protocol for LLM queries via MCP.
    
    Plugins use this interface for all LLM interactions.
    The framework owns the MCP client; plugins must not create their own.
    """
    
    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Send a text prompt to the connected LLM via MCP.
        
        Args:
            prompt: The user prompt to send.
            system_context: Optional system context override.
            max_tokens: Maximum tokens in response.
            grounding_data: Additional context strings injected before prompt.
            hints: Optional routing hints for model selection.
        
        Returns:
            LLMResponse with text or error.
        """
        ...
    
    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a multimodal (text + image) prompt to the connected LLM.
        
        Args:
            prompt: The text prompt.
            image_data: Raw image bytes.
            image_format: Image format (jpeg, png).
            system_context: Optional system context override.
            max_tokens: Maximum tokens in response.
        
        Returns:
            LLMResponse with text or error. If the model doesn't support
            vision, returns ok=False with error indicating capability gap.
        """
        ...
    
    def query_with_document(
        self,
        prompt: str,
        artifact: ArtifactRef,
        system_context: str | None = None,
        max_tokens: int = 8192,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Query with a document artifact.
        
        The dispatcher resolves the best ingestion path automatically:
          1. Native document + remote URI (gs:// for Gemini) — zero-copy
          2. Native document + inline bytes from local file
          3. Fallback: returns ok=False so plugin can use text extraction
        
        The response's transport_path field records which path was used.
        
        Args:
            prompt: Analysis instructions.
            artifact: Reference to the document artifact.
            system_context: Optional system context override.
            max_tokens: Maximum tokens in response.
            grounding_data: Additional context strings injected before prompt.
            hints: Optional routing hints for model selection.
        
        Returns:
            LLMResponse with text or error.
        """
        ...
    
    def supports_native_document(self, mime_type: str) -> bool:
        """Check if any connected model handles this MIME type natively.
        
        Args:
            mime_type: MIME type to check (e.g. "application/pdf").
        
        Returns:
            True if at least one connected model supports native ingestion.
        """
        ...


# ---------------------------------------------------------------------------
# Execution Context
# ---------------------------------------------------------------------------


@dataclass
class ExecutionContext:
    """Read-only execution context supplied by the framework.
    
    Passed to plugin execute() methods. Plugins must treat this as read-only
    except for the register_artifact callback.
    """
    
    # Session identity
    session_id: str
    selected_pillar: str
    
    # Artifact access
    artifacts: list[ArtifactRef] = field(default_factory=list)
    
    # Framework services (read-only interfaces)
    config: dict[str, Any] = field(default_factory=dict)
    logger: logging.Logger | None = None
    reference_data: ReferenceDataView = field(default_factory=ReferenceDataView)
    
    # LLM capabilities
    llm_enabled: bool = False
    llm_query: LLMQueryInterface | None = None
    
    # Artifact registration (the one write operation plugins may perform)
    register_artifact: Callable[[str, str, str, dict], ArtifactRef] | None = None
    
    # Execution limits
    limits: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tool Protocol
# ---------------------------------------------------------------------------


class EventMillToolProtocol(Protocol):
    """Protocol that all Event Mill plugins must implement.
    
    This is the normative contract from tool_plugin_spec.md.
    """
    
    def metadata(self) -> dict[str, Any]:
        """Return runtime metadata.
        
        Reflects manifest plus derived runtime values.
        Used for diagnostics, registry inspection, and debugging.
        
        Must include at minimum: tool_name, version
        """
        ...
    
    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        """Validate the request payload against the input schema.
        
        Must NOT perform any analysis work or side effects.
        
        Args:
            payload: The input payload to validate.
        
        Returns:
            ValidationResult indicating success or listing errors.
        """
        ...
    
    def execute(
        self,
        payload: dict[str, Any],
        context: ExecutionContext,
    ) -> ToolResult:
        """Perform the tool's analysis work and return a structured result.
        
        Rules:
        - MUST NOT mutate framework state directly
        - MUST NOT call other plugins directly
        - MUST treat context as read-only (except register_artifact)
        - SHOULD prefer deterministic logic
        - MUST raise predictable exceptions or return structured errors
        - MUST register output artifacts via context.register_artifact()
        
        Args:
            payload: Validated input payload.
            context: Execution context with artifacts, config, LLM access.
        
        Returns:
            ToolResult with success data or error information.
        """
        ...
    
    def summarize_for_llm(self, result: ToolResult) -> str:
        """Return a compressed, human-readable summary for LLM context.
        
        This method is a critical differentiator for Event Mill.
        Most MCP-based projects skip explicit output compression,
        leading to context window bloat and degraded LLM reasoning.
        
        Rules:
        - MUST be brief (target: under 500 tokens)
        - SHOULD include only the most important findings
        - MUST NOT repeat the full structured output
        - MUST NOT invent facts not present in result
        - MUST NOT include binary data references
        - Hard maximum: 2000 characters
        
        Args:
            result: The ToolResult from execute().
        
        Returns:
            Plain text summary string.
        """
        ...


# ---------------------------------------------------------------------------
# Error Codes
# ---------------------------------------------------------------------------


class ErrorCodes:
    """Standard error codes for plugin errors.
    
    Plugins should use these codes in ToolResult.error_code.
    """
    
    INPUT_VALIDATION_FAILED = "INPUT_VALIDATION_FAILED"
    ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
    ARTIFACT_UNREADABLE = "ARTIFACT_UNREADABLE"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    LLM_CAPABILITY_GAP = "LLM_CAPABILITY_GAP"
    LLM_QUERY_FAILED = "LLM_QUERY_FAILED"
    TIMEOUT = "TIMEOUT"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# ---------------------------------------------------------------------------
# Timeout Classes
# ---------------------------------------------------------------------------


class TimeoutClass:
    """Timeout class constants and their default limits in seconds."""
    
    FAST = "fast"
    MEDIUM = "medium"
    SLOW = "slow"
    
    LIMITS = {
        FAST: 30,
        "short": 30,
        MEDIUM: 120,
        SLOW: 600,
        "long": 600,
    }
    
    @classmethod
    def get_limit(cls, timeout_class: str) -> int:
        """Get the timeout limit for a class."""
        return cls.LIMITS.get(timeout_class, cls.LIMITS[cls.MEDIUM])
