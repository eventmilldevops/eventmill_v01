"""
Event Mill LLM Backend — Document Parts

Provider-neutral description of a document to include in an LLM request.
The dispatcher (framework/llm/dispatcher.py) resolves the artifact into one of
these; the provider client picks the ingestion path its own API supports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class DocumentUnavailable(Exception):
    """A document's bytes could not be read from any source it names."""


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

    def read_bytes(self, allow_remote: bool = True) -> bytes:
        """The document's bytes: inline first, then the local file, then GCS.

        For a provider that cannot read a remote URI. Raises
        DocumentUnavailable rather than returning empty or partial bytes: an
        empty document sent to a model comes back as a confident answer about
        nothing.

        allow_remote=False skips the GCS fetch. A provider client passes it,
        because fetching from storage is a framework concern (the dispatcher
        materialises before the client is called), not an SDK one.
        """
        if self.inline_bytes:
            return self.inline_bytes
        if self.file_path and os.path.isfile(self.file_path):
            with open(self.file_path, "rb") as f:
                data = f.read()
            if data:
                return data
            raise DocumentUnavailable(f"document is empty: {self.file_path}")
        if allow_remote and self.storage_uri and self.storage_uri.startswith("gs://"):
            return _read_gcs(self.storage_uri)
        named = self.file_path or self.storage_uri or "no source"
        raise DocumentUnavailable(f"document bytes not readable from {named}")


def _read_gcs(uri: str) -> bytes:
    """Fetch a gs://bucket/object URI whole, or raise DocumentUnavailable."""
    bucket, _, obj = uri[len("gs://"):].partition("/")
    if not bucket or not obj:
        raise DocumentUnavailable(f"not a gs://bucket/object URI: {uri}")
    try:
        from framework.cloud.gcp.storage import GCSStorageBackend

        with GCSStorageBackend(bucket, prefix="").open_read(obj) as f:
            data = f.read()
    except Exception as e:  # noqa: BLE001 - every failure is the same answer
        raise DocumentUnavailable(f"could not read {uri}: {e}") from e
    if not data:
        raise DocumentUnavailable(f"document is empty: {uri}")
    return data
