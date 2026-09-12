"""
Local Storage Backend

Local filesystem implementation of StorageBackend for development.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from ..interfaces import StorageBackend, StoredObject


class LocalStorageBackend(StorageBackend):
    """Local filesystem storage backend.
    
    Used for local development and testing.
    """
    
    def __init__(self, base_path: Path):
        """Initialize local storage.
        
        Args:
            base_path: Base directory for storage.
        """
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def _resolve_path(self, remote_path: str) -> Path:
        """Resolve a remote path to a local path."""
        # Ensure path doesn't escape base directory
        resolved = (self.base_path / remote_path).resolve()
        if not str(resolved).startswith(str(self.base_path.resolve())):
            raise ValueError(f"Path escapes base directory: {remote_path}")
        return resolved
    
    def upload(
        self,
        local_path: Path,
        remote_path: str,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Upload (copy) a file to local storage."""
        dest = self._resolve_path(remote_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_path, dest)
        
        # Store metadata in sidecar file if provided
        if metadata:
            import json
            meta_path = dest.with_suffix(dest.suffix + ".meta.json")
            with open(meta_path, "w") as f:
                json.dump(metadata, f)
        
        return f"file://{dest}"
    
    def download(
        self,
        remote_path: str,
        local_path: Path,
    ) -> Path:
        """Download (copy) a file from local storage."""
        src = self._resolve_path(remote_path)
        if not src.exists():
            raise FileNotFoundError(f"File not found: {remote_path}")
        
        local_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, local_path)
        return local_path
    
    def open_read(self, remote_path: str) -> BinaryIO:
        """Open a file for streaming read."""
        path = self._resolve_path(remote_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {remote_path}")
        return open(path, "rb")
    
    def exists(self, remote_path: str) -> bool:
        """Check if a file exists."""
        return self._resolve_path(remote_path).exists()
    
    def delete(self, remote_path: str) -> None:
        """Delete a file."""
        path = self._resolve_path(remote_path)
        if path.exists():
            path.unlink()
            
            # Also delete metadata sidecar if present
            meta_path = path.with_suffix(path.suffix + ".meta.json")
            if meta_path.exists():
                meta_path.unlink()
    
    def list_files(
        self,
        prefix: str = "",
        max_results: int = 1000,
    ) -> list[str]:
        """List files in storage."""
        base = self._resolve_path(prefix) if prefix else self.base_path
        
        if not base.exists():
            return []
        
        if base.is_file():
            return [prefix]
        
        files = []
        for path in base.rglob("*"):
            if path.is_file() and not path.name.endswith(".meta.json"):
                rel_path = path.relative_to(self.base_path)
                files.append(str(rel_path))
                if len(files) >= max_results:
                    break

        return files

    def list_files_detailed(
        self,
        prefix: str = "",
        max_results: int = 1000,
    ) -> list[StoredObject]:
        """List files with size and modification time.

        Paths are returned with forward slashes and mtimes as aware UTC so
        results are comparable with those from other backends.

        A prefix that is not a directory is matched against the start of
        each relative path, so ``inc`` matches ``inc-1/`` and ``inc-2/``
        the way an object-store prefix does.
        """
        base = self.base_path
        path_filter = ""

        if prefix:
            try:
                candidate = self._resolve_path(prefix)
            except ValueError:
                return []
            if candidate.is_dir():
                base = candidate
            elif candidate.is_file():
                base = candidate
            else:
                path_filter = prefix.replace("\\", "/").lstrip("/")

        if not base.exists():
            return []

        if base.is_file():
            return [self._stored_object(base)]

        results: list[StoredObject] = []
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.name.endswith(".meta.json"):
                continue
            obj = self._stored_object(path)
            if path_filter and not obj.path.startswith(path_filter):
                continue
            results.append(obj)
            if len(results) >= max_results:
                break

        return results

    def _stored_object(self, path: Path) -> StoredObject:
        """Build a StoredObject for a file, tolerating a failed stat()."""
        rel_path = str(path.relative_to(self.base_path)).replace("\\", "/")
        try:
            stat = path.stat()
        except OSError:
            return StoredObject(path=rel_path)
        return StoredObject(
            path=rel_path,
            size_bytes=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
        )
