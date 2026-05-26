"""
Event Mill Framework Layer

The framework layer provides the runtime environment for Event Mill.
It contains CLI interface, session management, LLM orchestration,
artifact registry, plugin lifecycle, and cloud abstraction.
"""

__version__ = "0.1.0"

from .plugins import (
    ArtifactRef,
    ErrorCodes,
    EventMillToolProtocol,
    ExecutionContext,
    LLMQueryInterface,
    LLMResponse,
    LoadedPlugin,
    PluginLoader,
    PluginManifest,
    ReferenceDataView,
    TimeoutClass,
    ToolResult,
    ValidationResult,
)
from .session import (
    Artifact,
    ArtifactType,
    Pillar,
    Session,
    SessionDatabase,
    SessionManager,
    ToolExecution,
    ToolExecutionStatus,
)
from .artifacts import ArtifactRegistry, create_artifact_registration_callback
from .routing import Router, RouterConfig, RoutingResult, RoutingScore
from .cloud import (
    ConfigProvider,
    ResolvedPath,
    SecretProvider,
    StorageBackend,
    StorageResolver,
    StorageResolverConfig,
)

__all__ = [
    # Version
    "__version__",
    # Plugins
    "ArtifactRef",
    "ErrorCodes",
    "EventMillToolProtocol",
    "ExecutionContext",
    "LLMQueryInterface",
    "LLMResponse",
    "LoadedPlugin",
    "PluginLoader",
    "PluginManifest",
    "ReferenceDataView",
    "TimeoutClass",
    "ToolResult",
    "ValidationResult",
    # Session
    "Artifact",
    "ArtifactType",
    "Pillar",
    "Session",
    "SessionDatabase",
    "SessionManager",
    "ToolExecution",
    "ToolExecutionStatus",
    # Artifacts
    "ArtifactRegistry",
    "create_artifact_registration_callback",
    # Routing
    "Router",
    "RouterConfig",
    "RoutingResult",
    "RoutingScore",
    # Cloud
    "ConfigProvider",
    "ResolvedPath",
    "SecretProvider",
    "StorageBackend",
    "StorageResolver",
    "StorageResolverConfig",
]
