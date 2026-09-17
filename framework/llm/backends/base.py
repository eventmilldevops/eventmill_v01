"""
Event Mill LLM Backend — Document Parts

Provider-neutral description of a document to include in an LLM request.
The dispatcher (framework/llm/dispatcher.py) resolves the artifact into one of
these; the provider client picks the ingestion path its own API supports.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DocumentPart:
    """A document to include in an LLM request.

    Exactly one of storage_uri, file_path, or inline_bytes should be set.
    Which one a client prefers is the client's call — Gemini reads a gs:// URI
    zero-copy and so tries storage_uri > inline_bytes > file_path; a provider
    that cannot read remote URIs needs bytes regardless of what is set.
    """
    mime_type: str
    storage_uri: str | None = None     # gs://, s3:// — preferred (zero-copy)
    file_path: str | None = None       # local filesystem path — fallback
    inline_bytes: bytes | None = None  # raw bytes — last resort
