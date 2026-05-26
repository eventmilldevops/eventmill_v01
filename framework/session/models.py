"""
Event Mill Session Models

Dataclasses for session state management.
These models map to the SQLite schema defined in the grounding document.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ToolExecutionStatus(Enum):
    """Status of a tool execution."""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass
class Session:
    """Investigation session state."""
    
    session_id: str
    created_at: datetime
    updated_at: datetime
    active_pillar: str | None = None
    workspace_folder: str | None = None
    description: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "active_pillar": self.active_pillar,
            "workspace_folder": self.workspace_folder,
            "description": self.description,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        return cls(
            session_id=data["session_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            active_pillar=data.get("active_pillar"),
            workspace_folder=data.get("workspace_folder"),
            description=data.get("description", ""),
        )


@dataclass
class Artifact:
    """Registered artifact in a session."""
    
    artifact_id: str
    session_id: str
    artifact_type: str
    file_path: str
    storage_uri: str | None = None
    source_tool: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "session_id": self.session_id,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "storage_uri": self.storage_uri,
            "source_tool": self.source_tool,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Artifact:
        return cls(
            artifact_id=data["artifact_id"],
            session_id=data["session_id"],
            artifact_type=data["artifact_type"],
            file_path=data["file_path"],
            storage_uri=data.get("storage_uri"),
            source_tool=data.get("source_tool"),
            created_at=datetime.fromisoformat(data["created_at"]),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ToolExecution:
    """Record of a tool execution."""
    
    execution_id: str
    session_id: str
    tool_name: str
    started_at: datetime
    completed_at: datetime | None = None
    status: ToolExecutionStatus = ToolExecutionStatus.RUNNING
    input_artifact_id: str | None = None
    output_artifact_id: str | None = None
    summary: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status.value,
            "input_artifact_id": self.input_artifact_id,
            "output_artifact_id": self.output_artifact_id,
            "summary": self.summary,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolExecution:
        return cls(
            execution_id=data["execution_id"],
            session_id=data["session_id"],
            tool_name=data["tool_name"],
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=(
                datetime.fromisoformat(data["completed_at"])
                if data.get("completed_at")
                else None
            ),
            status=ToolExecutionStatus(data["status"]),
            input_artifact_id=data.get("input_artifact_id"),
            output_artifact_id=data.get("output_artifact_id"),
            summary=data.get("summary", ""),
        )


# Artifact type constants (from manifest_schema.json)
class ArtifactType:
    """Valid artifact types."""
    
    PCAP = "pcap"
    JSON_EVENTS = "json_events"
    LOG_STREAM = "log_stream"
    RISK_MODEL = "risk_model"
    CLOUD_AUDIT_LOG = "cloud_audit_log"
    PDF_REPORT = "pdf_report"
    HTML_REPORT = "html_report"
    IMAGE = "image"
    TEXT = "text"
    NONE = "none"
    
    ALL = {
        PCAP, JSON_EVENTS, LOG_STREAM, RISK_MODEL, CLOUD_AUDIT_LOG,
        PDF_REPORT, HTML_REPORT, IMAGE, TEXT, NONE
    }
    
    @classmethod
    def is_valid(cls, artifact_type: str) -> bool:
        return artifact_type in cls.ALL


# Pillar constants
class Pillar:
    """Investigation pillars."""
    
    LOG_ANALYSIS = "log_analysis"
    NETWORK_FORENSICS = "network_forensics"
    CLOUD_INVESTIGATION = "cloud_investigation"
    RISK_ASSESSMENT = "risk_assessment"
    THREAT_MODELING = "threat_modeling"
    
    ALL = {
        LOG_ANALYSIS, NETWORK_FORENSICS, CLOUD_INVESTIGATION,
        RISK_ASSESSMENT, THREAT_MODELING
    }
    
    @classmethod
    def is_valid(cls, pillar: str) -> bool:
        return pillar in cls.ALL
