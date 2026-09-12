"""
GCP Storage Backend

Google Cloud Storage implementation of StorageBackend.
Requires: google-cloud-storage
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import BinaryIO

from ..interfaces import StorageBackend, StoredObject

logger = logging.getLogger("eventmill.framework.cloud.gcp")


class GCSStorageBackend(StorageBackend):
    """Google Cloud Storage backend.
    
    Stores artifacts in a GCS bucket. Requires the
    google-cloud-storage package and appropriate credentials.
    """
    
    def __init__(
        self,
        bucket_name: str,
        prefix: str = "eventmill/",
        project_id: str | None = None,
    ):
        """Initialize GCS storage backend.
        
        Args:
            bucket_name: GCS bucket name.
            prefix: Key prefix for all stored objects.
            project_id: GCP project ID (uses default if None).
        """
        self.bucket_name = bucket_name
        self.prefix = prefix
        self.project_id = project_id
        self._client = None
        self._bucket = None
    
    def _get_bucket(self):
        """Lazy initialization of GCS client and bucket."""
        if self._bucket is None:
            try:
                from google.cloud import storage
                self._client = storage.Client(project=self.project_id)
                self._bucket = self._client.bucket(self.bucket_name)
                logger.info("Connected to GCS bucket: %s", self.bucket_name)
            except ImportError:
                raise ImportError(
                    "google-cloud-storage package required for GCS backend. "
                    "Install with: pip install google-cloud-storage"
                )
        return self._bucket
    
    def _full_path(self, remote_path: str) -> str:
        """Build full GCS object path with prefix."""
        return f"{self.prefix}{remote_path}"
    
    def upload(
        self,
        local_path: Path,
        remote_path: str,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Upload a file to GCS."""
        bucket = self._get_bucket()
        blob = bucket.blob(self._full_path(remote_path))
        
        if metadata:
            blob.metadata = metadata
        
        blob.upload_from_filename(str(local_path))
        
        uri = f"gs://{self.bucket_name}/{self._full_path(remote_path)}"
        logger.debug("Uploaded to GCS: %s", uri)
        return uri
    
    def download(
        self,
        remote_path: str,
        local_path: Path,
    ) -> Path:
        """Download a file from GCS."""
        bucket = self._get_bucket()
        blob = bucket.blob(self._full_path(remote_path))
        
        local_path.parent.mkdir(parents=True, exist_ok=True)
        blob.download_to_filename(str(local_path))
        
        return local_path
    
    def open_read(self, remote_path: str) -> BinaryIO:
        """Open a GCS object for streaming read."""
        bucket = self._get_bucket()
        blob = bucket.blob(self._full_path(remote_path))
        return blob.open("rb")
    
    def exists(self, remote_path: str) -> bool:
        """Check if a GCS object exists."""
        bucket = self._get_bucket()
        blob = bucket.blob(self._full_path(remote_path))
        return blob.exists()
    
    def delete(self, remote_path: str) -> None:
        """Delete a GCS object."""
        bucket = self._get_bucket()
        blob = bucket.blob(self._full_path(remote_path))
        if blob.exists():
            blob.delete()
    
    def list_files(
        self,
        prefix: str = "",
        max_results: int = 1000,
    ) -> list[str]:
        """List objects in GCS."""
        bucket = self._get_bucket()
        full_prefix = self._full_path(prefix)
        
        blobs = bucket.list_blobs(prefix=full_prefix, max_results=max_results)
        
        results = []
        for blob in blobs:
            # Remove the base prefix to return relative paths
            rel_path = blob.name
            if rel_path.startswith(self.prefix):
                rel_path = rel_path[len(self.prefix):]
            results.append(rel_path)

        return results

    def list_files_detailed(
        self,
        prefix: str = "",
        max_results: int = 1000,
    ) -> list[StoredObject]:
        """List objects in GCS with size and modification time.

        Size and timestamps are already present on the blobs returned by
        list_blobs, so this costs no additional API calls.
        """
        bucket = self._get_bucket()
        full_prefix = self._full_path(prefix)

        blobs = bucket.list_blobs(prefix=full_prefix, max_results=max_results)

        results = []
        for blob in blobs:
            rel_path = blob.name
            if rel_path.startswith(self.prefix):
                rel_path = rel_path[len(self.prefix):]
            results.append(
                StoredObject(
                    path=rel_path,
                    size_bytes=blob.size,
                    modified=blob.updated or blob.time_created,
                )
            )

        return results
