"""
Event Mill CLI Interface

Metasploit-style command shell with tab completion, help screens,
and user input handling.
"""


def __getattr__(name: str):
    """Lazy imports to avoid RuntimeWarning when run via python -m."""
    if name == "EventMillShell":
        from .shell import EventMillShell
        return EventMillShell
    if name == "main":
        from .shell import main
        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "EventMillShell",
    "main",
]
