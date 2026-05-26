"""
Event Mill Session Manager

High-level session management API.
Coordinates database, artifact registry, and execution tracking.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from .database import SessionDatabase
from .models import Artifact, Session, ToolExecution, ToolExecutionStatus

logger = logging.getLogger("eventmill.framework.session")


class SessionManager:
    """High-level session management API."""
    
    def __init__(self, workspace_path: str | Path):
        """Initialize session manager.
        
        Args:
            workspace_path: Path to workspace directory.
        """
        self.workspace_path = Path(workspace_path)
        self.workspace_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        db_path = self.workspace_path / "sessions" / "eventmill.db"
        self.db = SessionDatabase(db_path)
        
        # Artifact storage
        self.artifacts_path = self.workspace_path / "artifacts"
        self.artifacts_path.mkdir(parents=True, exist_ok=True)
        
        # Current session
        self._current_session: Session | None = None
    
    # -----------------------------------------------------------------------
    # Session Lifecycle
    # -----------------------------------------------------------------------
    
    def new_session(self, description: str = "") -> Session:
        """Create a new investigation session.
        
        Args:
            description: Optional description of the investigation.
        
        Returns:
            The new Session object.
        """
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        now = datetime.now()
        
        session = Session(
            session_id=session_id,
            created_at=now,
            updated_at=now,
            description=description,
        )
        
        self.db.create_session(session)
        self._current_session = session
        
        # Create session artifact directory
        session_artifacts = self.artifacts_path / session_id
        session_artifacts.mkdir(parents=True, exist_ok=True)
        
        logger.info("Created new session: %s", session_id)
        return session
    
    def load_session(self, session_id: str) -> Session | None:
        """Load an existing session.
        
        Args:
            session_id: The session ID to load.
        
        Returns:
            The Session object, or None if not found.
        """
        session = self.db.get_session(session_id)
        if session:
            self._current_session = session
            logger.info("Loaded session: %s", session_id)
        return session
    
    def get_current_session(self) -> Session | None:
        """Get the current active session."""
        return self._current_session
    
    def set_pillar(self, pillar: str) -> None:
        """Set the active pillar for the current session.
        
        Args:
            pillar: The pillar to activate.
        
        Raises:
            ValueError: If no session is active.
        """
        if not self._current_session:
            raise ValueError("No active session")
        
        self._current_session.active_pillar = pillar
        self._current_session.updated_at = datetime.now()
        self.db.update_session(self._current_session)
        logger.info("Set pillar to: %s", pillar)
    
    def set_workspace(self, workspace_folder: str | None) -> None:
        """Set the active workspace folder for the current session.
        
        The workspace folder scopes file resolution to a subfolder
        within the pillar and common storage buckets (e.g. an incident
        identifier like ``incident-2024-03``).  Set to *None* to clear.
        
        Args:
            workspace_folder: Folder name, or None to clear.
        
        Raises:
            ValueError: If no session is active.
        """
        if not self._current_session:
            raise ValueError("No active session")
        
        self._current_session.workspace_folder = workspace_folder
        self._current_session.updated_at = datetime.now()
        self.db.update_session(self._current_session)
        if workspace_folder:
            logger.info("Set workspace folder to: %s", workspace_folder)
        else:
            logger.info("Cleared workspace folder")
    
    def list_sessions(self) -> list[Session]:
        """List all sessions."""
        return self.db.list_sessions()
    
    def delete_session(self, session_id: str) -> None:
        """Delete a session and all its data.
        
        Args:
            session_id: The session ID to delete.
        """
        # Delete artifact files
        session_artifacts = self.artifacts_path / session_id
        if session_artifacts.exists():
            import shutil
            shutil.rmtree(session_artifacts)
        
        # Delete database records
        self.db.delete_session(session_id)
        
        # Clear current session if it was deleted
        if self._current_session and self._current_session.session_id == session_id:
            self._current_session = None
        
        logger.info("Deleted session: %s", session_id)
    
    # -----------------------------------------------------------------------
    # Artifact Management
    # -----------------------------------------------------------------------
    
    def register_artifact(
        self,
        artifact_type: str,
        file_path: str,
        source_tool: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Artifact:
        """Register a new artifact in the current session.
        
        Args:
            artifact_type: Type of artifact (from ArtifactType).
            file_path: Path to the artifact file.
            source_tool: Tool that produced this artifact (None for user-loaded).
            metadata: Optional metadata dictionary.
        
        Returns:
            The registered Artifact object.
        
        Raises:
            ValueError: If no session is active.
        """
        if not self._current_session:
            raise ValueError("No active session")
        
        artifact_id = f"art_{uuid.uuid4().hex[:8]}"
        
        artifact = Artifact(
            artifact_id=artifact_id,
            session_id=self._current_session.session_id,
            artifact_type=artifact_type,
            file_path=file_path,
            source_tool=source_tool,
            metadata=metadata or {},
        )
        
        self.db.create_artifact(artifact)
        
        # Update session timestamp
        self._current_session.updated_at = datetime.now()
        self.db.update_session(self._current_session)
        
        return artifact
    
    def get_artifact(self, artifact_id: str) -> Artifact | None:
        """Get an artifact by ID."""
        return self.db.get_artifact(artifact_id)
    
    def list_artifacts(self, artifact_type: str | None = None) -> list[Artifact]:
        """List artifacts in the current session.
        
        Args:
            artifact_type: Optional filter by artifact type.
        
        Returns:
            List of Artifact objects.
        
        Raises:
            ValueError: If no session is active.
        """
        if not self._current_session:
            raise ValueError("No active session")
        
        if artifact_type:
            return self.db.list_artifacts_by_type(
                self._current_session.session_id, artifact_type
            )
        return self.db.list_artifacts(self._current_session.session_id)
    
    def get_artifact_path(self, artifact_id: str) -> Path | None:
        """Get the file path for an artifact.
        
        Args:
            artifact_id: The artifact ID.
        
        Returns:
            Path to the artifact file, or None if not found.
        """
        artifact = self.db.get_artifact(artifact_id)
        if artifact:
            return Path(artifact.file_path)
        return None
    
    # -----------------------------------------------------------------------
    # Execution Tracking
    # -----------------------------------------------------------------------
    
    def start_execution(
        self,
        tool_name: str,
        input_artifact_id: str | None = None,
    ) -> ToolExecution:
        """Record the start of a tool execution.
        
        Args:
            tool_name: Name of the tool being executed.
            input_artifact_id: Optional input artifact ID.
        
        Returns:
            The ToolExecution record.
        
        Raises:
            ValueError: If no session is active.
        """
        if not self._current_session:
            raise ValueError("No active session")
        
        execution_id = f"exec_{uuid.uuid4().hex[:8]}"
        
        execution = ToolExecution(
            execution_id=execution_id,
            session_id=self._current_session.session_id,
            tool_name=tool_name,
            started_at=datetime.now(),
            input_artifact_id=input_artifact_id,
        )
        
        self.db.create_execution(execution)
        return execution
    
    def complete_execution(
        self,
        execution: ToolExecution,
        status: ToolExecutionStatus,
        output_artifact_id: str | None = None,
        summary: str = "",
    ) -> None:
        """Record the completion of a tool execution.
        
        Args:
            execution: The ToolExecution to update.
            status: Final status.
            output_artifact_id: Optional output artifact ID.
            summary: LLM-friendly summary of results.
        """
        execution.completed_at = datetime.now()
        execution.status = status
        execution.output_artifact_id = output_artifact_id
        execution.summary = summary
        
        self.db.update_execution(execution)
        
        # Update session timestamp
        if self._current_session:
            self._current_session.updated_at = datetime.now()
            self.db.update_session(self._current_session)
    
    def list_executions(self) -> list[ToolExecution]:
        """List all executions in the current session.
        
        Raises:
            ValueError: If no session is active.
        """
        if not self._current_session:
            raise ValueError("No active session")
        
        return self.db.list_executions(self._current_session.session_id)
    
    def get_recent_summaries(self, limit: int = 3) -> list[str]:
        """Get recent tool execution summaries for LLM context.
        
        Args:
            limit: Maximum number of summaries to return.
        
        Returns:
            List of summary strings.
        
        Raises:
            ValueError: If no session is active.
        """
        if not self._current_session:
            raise ValueError("No active session")
        
        return self.db.get_recent_summaries(
            self._current_session.session_id, limit
        )
