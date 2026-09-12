"""
Event Mill LLM Backend — Document Parts

Provider-neutral description of a document to include in an LLM request.
The dispatcher (framework/llm/client.py) resolves the ingestion path.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DocumentPart:
    """A document to include in an LLM request.

    Exactly one of storage_uri, file_path, or inline_bytes should be set.
    The dispatcher tries them in priority order: storage_uri > inline_bytes >
    file_path.
    """
    mime_type: str
    storage_uri: str | None = None     # gs://, s3:// — preferred (zero-copy)
    file_path: str | None = None       # local filesystem path — fallback
    inline_bytes: bytes | None = None  # raw bytes — last resort
