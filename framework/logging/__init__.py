"""
Event Mill Structured Logging

JSON-structured audit and debug logging.
"""

from .structured import (
    ActivityJSONFormatter,
    ConsoleFormatter,
    JSONFormatter,
    LogContext,
    get_logger,
    log_llm_interaction,
    log_user_activity,
    set_user_context,
    setup_logging,
)

__all__ = [
    "ActivityJSONFormatter",
    "ConsoleFormatter",
    "JSONFormatter",
    "LogContext",
    "get_logger",
    "log_llm_interaction",
    "log_user_activity",
    "set_user_context",
    "setup_logging",
]
