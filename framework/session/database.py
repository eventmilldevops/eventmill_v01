"""
Event Mill Session Database

SQLite operations for session persistence.
Schema follows the grounding document section 6.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator

from .models import Artifact, Session, ToolExecution, ToolExecutionStatus

logger = logging.getLogger("eventmill.framework.session")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    active_pillar TEXT,
    workspace_folder TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    artifact_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    source_tool TEXT,
    created_at TEXT NOT NULL,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    tool_name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    input_artifact_id TEXT REFERENCES artifacts(artifact_id),
    output_artifact_id TEXT REFERENCES artifacts(artifact_id),
    summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_executions_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_executions_tool ON tool_executions(tool_name);
"""


# ---------------------------------------------------------------------------
# Database Connection
# ---------------------------------------------------------------------------


class SessionDatabase:
    """SQLite database for session persistence."""
    
    def __init__(self, db_path: str | Path):
        """Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
    
    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
    
    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    # -----------------------------------------------------------------------
    # Session Operations
    # -----------------------------------------------------------------------
    
    def create_session(self, session: Session) -> None:
        """Create a new session."""
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id, created_at, updated_at, active_pillar, workspace_folder, description)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.created_at.isoformat(),
                    session.updated_at.isoformat(),
                    session.active_pillar,
                    session.workspace_folder,
                    session.description,
                ),
            )
            conn.commit()
        logger.info("Created session %s", session.session_id)
    
    def get_session(self, session_id: str) -> Session | None:
        """Get a session by ID."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            
            if row is None:
                return None
            
            return Session(
                session_id=row["session_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                active_pillar=row["active_pillar"],
                workspace_folder=row["workspace_folder"] if "workspace_folder" in row.keys() else None,
                description=row["description"] or "",
            )
    
    def update_session(self, session: Session) -> None:
        """Update an existing session."""
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET updated_at = ?, active_pillar = ?, workspace_folder = ?, description = ?
                WHERE session_id = ?
                """,
                (
                    session.updated_at.isoformat(),
                    session.active_pillar,
                    session.workspace_folder,
                    session.description,
                    session.session_id,
                ),
            )
            conn.commit()
    
    def list_sessions(self) -> list[Session]:
        """List all sessions."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY updated_at DESC"
            ).fetchall()
            
            return [
                Session(
                    session_id=row["session_id"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    updated_at=datetime.fromisoformat(row["updated_at"]),
                    active_pillar=row["active_pillar"],
                    workspace_folder=row["workspace_folder"] if "workspace_folder" in row.keys() else None,
                    description=row["description"] or "",
                )
                for row in rows
            ]
    
    def delete_session(self, session_id: str) -> None:
        """Delete a session and all related data."""
        with self._connection() as conn:
            conn.execute(
                "DELETE FROM tool_executions WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM artifacts WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM sessions WHERE session_id = ?",
                (session_id,),
            )
            conn.commit()
        logger.info("Deleted session %s", session_id)
    
    # -----------------------------------------------------------------------
    # Artifact Operations
    # -----------------------------------------------------------------------
    
    def create_artifact(self, artifact: Artifact) -> None:
        """Register a new artifact."""
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO artifacts 
                (artifact_id, session_id, artifact_type, file_path, source_tool, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.artifact_id,
                    artifact.session_id,
                    artifact.artifact_type,
                    artifact.file_path,
                    artifact.source_tool,
                    artifact.created_at.isoformat(),
                    json.dumps(artifact.metadata),
                ),
            )
            conn.commit()
        logger.info(
            "Registered artifact %s (type=%s, source=%s)",
            artifact.artifact_id,
            artifact.artifact_type,
            artifact.source_tool or "user",
        )
    
    def get_artifact(self, artifact_id: str) -> Artifact | None:
        """Get an artifact by ID."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            
            if row is None:
                return None
            
            return Artifact(
                artifact_id=row["artifact_id"],
                session_id=row["session_id"],
                artifact_type=row["artifact_type"],
                file_path=row["file_path"],
                source_tool=row["source_tool"],
                created_at=datetime.fromisoformat(row["created_at"]),
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            )
    
    def list_artifacts(self, session_id: str) -> list[Artifact]:
        """List all artifacts in a session."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE session_id = ? ORDER BY created_at",
                (session_id,),
            ).fetchall()
            
            return [
                Artifact(
                    artifact_id=row["artifact_id"],
                    session_id=row["session_id"],
                    artifact_type=row["artifact_type"],
                    file_path=row["file_path"],
                    source_tool=row["source_tool"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                )
                for row in rows
            ]
    
    def list_artifacts_by_type(
        self, session_id: str, artifact_type: str
    ) -> list[Artifact]:
        """List artifacts of a specific type in a session."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM artifacts 
                WHERE session_id = ? AND artifact_type = ?
                ORDER BY created_at
                """,
                (session_id, artifact_type),
            ).fetchall()
            
            return [
                Artifact(
                    artifact_id=row["artifact_id"],
                    session_id=row["session_id"],
                    artifact_type=row["artifact_type"],
                    file_path=row["file_path"],
                    source_tool=row["source_tool"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                )
                for row in rows
            ]
    
    # -----------------------------------------------------------------------
    # Tool Execution Operations
    # -----------------------------------------------------------------------
    
    def create_execution(self, execution: ToolExecution) -> None:
        """Record a new tool execution."""
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO tool_executions
                (execution_id, session_id, tool_name, started_at, completed_at, 
                 status, input_artifact_id, output_artifact_id, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution.execution_id,
                    execution.session_id,
                    execution.tool_name,
                    execution.started_at.isoformat(),
                    execution.completed_at.isoformat() if execution.completed_at else None,
                    execution.status.value,
                    execution.input_artifact_id,
                    execution.output_artifact_id,
                    execution.summary,
                ),
            )
            conn.commit()
        logger.info(
            "Started execution %s (tool=%s)",
            execution.execution_id,
            execution.tool_name,
        )
    
    def update_execution(self, execution: ToolExecution) -> None:
        """Update an existing tool execution."""
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE tool_executions
                SET completed_at = ?, status = ?, output_artifact_id = ?, summary = ?
                WHERE execution_id = ?
                """,
                (
                    execution.completed_at.isoformat() if execution.completed_at else None,
                    execution.status.value,
                    execution.output_artifact_id,
                    execution.summary,
                    execution.execution_id,
                ),
            )
            conn.commit()
        logger.info(
            "Completed execution %s (status=%s)",
            execution.execution_id,
            execution.status.value,
        )
    
    def get_execution(self, execution_id: str) -> ToolExecution | None:
        """Get a tool execution by ID."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM tool_executions WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
            
            if row is None:
                return None
            
            return ToolExecution(
                execution_id=row["execution_id"],
                session_id=row["session_id"],
                tool_name=row["tool_name"],
                started_at=datetime.fromisoformat(row["started_at"]),
                completed_at=(
                    datetime.fromisoformat(row["completed_at"])
                    if row["completed_at"]
                    else None
                ),
                status=ToolExecutionStatus(row["status"]),
                input_artifact_id=row["input_artifact_id"],
                output_artifact_id=row["output_artifact_id"],
                summary=row["summary"] or "",
            )
    
    def list_executions(self, session_id: str) -> list[ToolExecution]:
        """List all tool executions in a session."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_executions WHERE session_id = ? ORDER BY started_at",
                (session_id,),
            ).fetchall()
            
            return [
                ToolExecution(
                    execution_id=row["execution_id"],
                    session_id=row["session_id"],
                    tool_name=row["tool_name"],
                    started_at=datetime.fromisoformat(row["started_at"]),
                    completed_at=(
                        datetime.fromisoformat(row["completed_at"])
                        if row["completed_at"]
                        else None
                    ),
                    status=ToolExecutionStatus(row["status"]),
                    input_artifact_id=row["input_artifact_id"],
                    output_artifact_id=row["output_artifact_id"],
                    summary=row["summary"] or "",
                )
                for row in rows
            ]
    
    def get_recent_summaries(self, session_id: str, limit: int = 3) -> list[str]:
        """Get the most recent tool execution summaries.
        
        Used for LLM context construction.
        """
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT summary FROM tool_executions
                WHERE session_id = ? AND status = 'completed' AND summary != ''
                ORDER BY completed_at DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
            
            return [row["summary"] for row in rows]
