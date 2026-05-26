"""
Event Mill Structured Logging

JSON-structured logging for audit, review, and debugging.
Follows the grounding document section 8 requirements.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# Module-level user activity logger (configured by setup_logging)
_activity_logger: logging.Logger | None = None
_user_id: str | None = None
_session_id: str | None = None


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging.
    
    Produces one JSON object per log line for easy parsing
    by log aggregation tools.
    """
    
    FIELDS = {
        "timestamp",
        "level",
        "logger",
        "message",
        "session_id",
        "tool_name",
        "execution_id",
        "artifact_id",
        "pillar",
        "duration_ms",
        "error",
    }
    
    def __init__(self, cloud_logging: bool = False):
        """Initialize JSON formatter.
        
        Args:
            cloud_logging: If True, use 'severity' instead of 'level'
                          for GCP Cloud Logging auto-parsing.
        """
        super().__init__()
        self.cloud_logging = cloud_logging
    
    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON."""
        log_entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Cloud Logging parses 'severity'; local tools expect 'level'
        if self.cloud_logging:
            log_entry["severity"] = record.levelname
        else:
            log_entry["level"] = record.levelname
        
        # Add extra fields if present
        for field in self.FIELDS:
            if field not in log_entry and hasattr(record, field):
                value = getattr(record, field)
                if value is not None:
                    log_entry[field] = value
        
        # Add exception info
        if record.exc_info and record.exc_info[1]:
            log_entry["error"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        
        return json.dumps(log_entry, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable console formatter with color support."""
    
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        """Format a log record for console display."""
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if color else ""
        
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        
        # Build prefix with optional context fields
        prefix_parts = [f"{color}{record.levelname:8s}{reset}", timestamp]
        
        if hasattr(record, "tool_name") and record.tool_name:
            prefix_parts.append(f"[{record.tool_name}]")
        elif record.name.startswith("eventmill."):
            short_name = record.name.replace("eventmill.", "")
            prefix_parts.append(f"[{short_name}]")
        
        prefix = " ".join(prefix_parts)
        return f"{prefix} {record.getMessage()}"


def setup_logging(
    log_level: str = "INFO",
    log_file: str | Path | None = None,
    console: bool = True,
    json_format: bool = True,
    cloud_json: bool = False,
    console_level: str | None = None,
) -> logging.Logger:
    """Configure Event Mill logging.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
        log_file: Path to log file (None for no file logging).
        console: Whether to log to console (stderr).
        json_format: Whether to use JSON format for file logging.
        cloud_json: If True, use JSON format on stderr with 'severity'
                    field for GCP Cloud Logging auto-parsing. User activity
                    logs always go to stderr in this mode.
        console_level: Separate log level for console. Defaults to WARNING
                       to suppress noisy INFO logs from framework internals.
    
    Returns:
        Root Event Mill logger.
    """
    global _activity_logger, _user_id
    
    root_logger = logging.getLogger("eventmill")
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Console level for framework logs - always suppress INFO by default
    # to avoid noisy plugin loading messages. User can override with console_level.
    if console_level:
        effective_console_level = getattr(logging, console_level.upper(), logging.WARNING)
    else:
        # Default: suppress INFO, show only WARNING+ on console
        # (INFO still goes to file for debugging)
        effective_console_level = logging.WARNING
    
    # Console handler for framework logs
    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(effective_console_level)
        if cloud_json:
            # JSON to stderr — Cloud Logging auto-parses severity + fields
            console_handler.setFormatter(JSONFormatter(cloud_logging=True))
        else:
            console_handler.setFormatter(ConsoleFormatter())
        root_logger.addHandler(console_handler)
    
    # File handler - always logs at configured level (captures INFO for debugging)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(str(log_path))
        file_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s %(name)s %(message)s"
                )
            )
        
        root_logger.addHandler(file_handler)
    
    # Setup user activity logger (separate from main logger)
    # Activity logs are audit records — they go to:
    # - Cloud Logging API (in cloud mode) for immutable, tamper-proof audit trail
    # - Local file (in local mode) for debugging
    # NEVER to console (stdout/stderr) to keep interactive shell clean
    _activity_logger = logging.getLogger("eventmill.activity")
    _activity_logger.setLevel(logging.INFO)
    _activity_logger.handlers.clear()
    _activity_logger.propagate = False  # Don't propagate to root
    
    if cloud_json:
        # In Cloud Run: send activity logs directly to Cloud Logging API
        # This bypasses stdout/stderr entirely, keeping console clean
        # Audit logs are immutable and separate from user-accessible GCS bucket
        try:
            import google.cloud.logging
            from google.cloud.logging.handlers import CloudLoggingHandler
            
            # Use workload identity credentials (no key file needed)
            client = google.cloud.logging.Client()
            cloud_handler = CloudLoggingHandler(
                client,
                name="eventmill-activity",  # Creates log: projects/PROJECT/logs/eventmill-activity
            )
            cloud_handler.setFormatter(ActivityJSONFormatter(cloud_logging=True))
            _activity_logger.addHandler(cloud_handler)
        except Exception as e:
            # If Cloud Logging fails, fall back to file (but log the error)
            root_logger.warning("Cloud Logging unavailable for activity logs: %s", e)
            if log_file:
                activity_file = Path(log_file).parent / "activity.log"
                activity_handler = logging.FileHandler(str(activity_file))
                activity_handler.setFormatter(ActivityJSONFormatter(cloud_logging=True))
                _activity_logger.addHandler(activity_handler)
    elif log_file:
        # Local mode: activity logs go to file only
        activity_file = Path(log_file).parent / "activity.log"
        activity_handler = logging.FileHandler(str(activity_file))
        activity_handler.setFormatter(ActivityJSONFormatter(cloud_logging=False))
        _activity_logger.addHandler(activity_handler)
    
    # Generate user ID for this session
    _user_id = os.environ.get("EVENTMILL_USER_ID", f"user_{uuid.uuid4().hex[:8]}")
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a named Event Mill logger.
    
    Args:
        name: Logger name (will be prefixed with 'eventmill.').
    
    Returns:
        Logger instance.
    """
    if not name.startswith("eventmill."):
        name = f"eventmill.{name}"
    return logging.getLogger(name)


def set_user_context(user_id: str | None = None, session_id: str | None = None) -> None:
    """Set user context for activity logging.
    
    Args:
        user_id: User identifier (updates only if provided).
        session_id: Current session ID.
    """
    global _user_id, _session_id
    if user_id is not None:
        _user_id = user_id
    if session_id is not None:
        _session_id = session_id


def log_user_activity(
    action: str,
    details: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> None:
    """Log user activity for audit trail.
    
    This logs to cloud/file but NOT to console.
    
    Args:
        action: The action performed (e.g., 'new_session', 'set_pillar').
        details: Optional details about the action.
        session_id: Session ID (uses global if not provided).
    """
    if not _activity_logger:
        return
    
    extra = {
        "activity_type": "user_action",
        "action": action,
        "user_id": _user_id or "anonymous",
        "session_id": session_id or _session_id,
    }
    if details:
        extra["details"] = details
    
    _activity_logger.info(
        "User action: %s",
        action,
        extra=extra,
    )


def log_llm_interaction(
    prompt: str,
    response_text: str | None,
    model_id: str | None = None,
    history_turns: int = 0,
    session_id: str | None = None,
    error: str | None = None,
) -> None:
    """Log LLM conversational interaction for audit trail.
    
    Captures the analyst's prompt and a truncated LLM response.
    Uses activity_type 'user_llm' to distinguish from regular
    user actions in monitoring and cost tracking.
    
    Args:
        prompt: The analyst's question/prompt (logged in full).
        response_text: LLM response (truncated to 500 chars in log).
        model_id: The LLM model used.
        history_turns: Number of conversation turns so far.
        session_id: Session ID (uses global if not provided).
        error: Error message if the query failed.
    """
    if not _activity_logger:
        return
    
    # Truncate response for log storage — full response lives in conversation history
    truncated_response = None
    if response_text:
        truncated_response = (
            response_text[:500] + "..." if len(response_text) > 500 else response_text
        )
    
    extra: dict[str, Any] = {
        "activity_type": "user_llm",
        "action": "llm_query",
        "user_id": _user_id or "anonymous",
        "session_id": session_id or _session_id,
        "details": {
            "prompt": prompt,
            "response_preview": truncated_response,
            "response_length": len(response_text) if response_text else 0,
            "model_id": model_id,
            "history_turns": history_turns,
        },
    }
    if error:
        extra["details"]["error"] = error
    
    _activity_logger.info(
        "LLM query: %s",
        prompt[:80] + "..." if len(prompt) > 80 else prompt,
        extra=extra,
    )


class ActivityJSONFormatter(logging.Formatter):
    """JSON formatter for user activity logs.
    
    Includes all extra fields for comprehensive audit trail.
    """
    
    def __init__(self, cloud_logging: bool = False):
        super().__init__()
        self.cloud_logging = cloud_logging
    
    def format(self, record: logging.LogRecord) -> str:
        """Format activity log as JSON."""
        log_entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        if self.cloud_logging:
            log_entry["severity"] = record.levelname
        else:
            log_entry["level"] = record.levelname
        
        # Include all extra fields
        for key in ("activity_type", "action", "user_id", "session_id", "details"):
            if hasattr(record, key):
                value = getattr(record, key)
                if value is not None:
                    log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


class LogContext:
    """Context manager for adding structured fields to log records.
    
    Usage:
        with LogContext(session_id="sess_abc", tool_name="threat_intel_ingester"):
            logger.info("Processing artifact")
            # Log record will include session_id and tool_name
    """
    
    def __init__(self, **kwargs: Any):
        """Initialize with extra log fields.
        
        Args:
            **kwargs: Extra fields to add to log records.
        """
        self.extra = kwargs
        self._old_factory = None
    
    def __enter__(self) -> LogContext:
        self._old_factory = logging.getLogRecordFactory()
        extra = self.extra
        old_factory = self._old_factory
        
        def record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = old_factory(*args, **kwargs)
            for key, value in extra.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, *args: Any) -> None:
        if self._old_factory:
            logging.setLogRecordFactory(self._old_factory)
