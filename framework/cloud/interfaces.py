"""
Event Mill Cloud Abstraction Interfaces

Abstract interfaces for cloud-provider-specific functionality.
Implementations live in provider-specific subdirectories (gcp/, local/).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO


@dataclass
class StoredObject:
    """One object in storage, with metadata where the backend knows it.

    ``modified`` is always timezone-aware UTC. Backends normalize at their
    own boundary so callers can compare values from any backend directly.
    """

    path: str
    size_bytes: int | None = None
    modified: datetime | None = None


class StorageBackend(ABC):
    """Abstract interface for artifact storage.
    
    Implementations handle the specifics of storing and retrieving
    artifacts from different storage systems (local filesystem, GCS, S3, etc.).
    """
    
    @abstractmethod
    def upload(
        self,
        local_path: Path,
        remote_path: str,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Upload a file to storage.
        
        Args:
            local_path: Path to the local file.
            remote_path: Destination path in storage.
            metadata: Optional metadata to attach.
        
        Returns:
            The storage URI of the uploaded file.
        """
        ...
    
    @abstractmethod
    def download(
        self,
        remote_path: str,
        local_path: Path,
    ) -> Path:
        """Download a file from storage.
        
        Args:
            remote_path: Path in storage.
            local_path: Destination local path.
        
        Returns:
            Path to the downloaded file.
        """
        ...
    
    @abstractmethod
    def open_read(self, remote_path: str) -> BinaryIO:
        """Open a file for streaming read.
        
        Args:
            remote_path: Path in storage.
        
        Returns:
            File-like object for reading.
        """
        ...
    
    @abstractmethod
    def exists(self, remote_path: str) -> bool:
        """Check if a file exists in storage.
        
        Args:
            remote_path: Path in storage.
        
        Returns:
            True if file exists.
        """
        ...
    
    @abstractmethod
    def delete(self, remote_path: str) -> None:
        """Delete a file from storage.
        
        Args:
            remote_path: Path in storage.
        """
        ...
    
    @abstractmethod
    def list_files(
        self,
        prefix: str = "",
        max_results: int = 1000,
    ) -> list[str]:
        """List files in storage.
        
        Args:
            prefix: Path prefix to filter by.
            max_results: Maximum number of results.
        
        Returns:
            List of file paths.
        """
        ...

    def list_files_detailed(
        self,
        prefix: str = "",
        max_results: int = 1000,
    ) -> list[StoredObject]:
        """List files with size and modification time.

        Concrete rather than abstract so a backend that does not override
        it still works, degraded to name-only entries.

        Args:
            prefix: Path prefix to filter by.
            max_results: Maximum number of results.

        Returns:
            List of StoredObject, ordered as the backend returns them.
        """
        return [
            StoredObject(path=p)
            for p in self.list_files(prefix=prefix, max_results=max_results)
        ]


class SecretProvider(ABC):
    """Abstract interface for secret management.
    
    Implementations handle retrieving secrets from different sources
    (environment variables, GCP Secret Manager, AWS Secrets Manager, etc.).
    """
    
    @abstractmethod
    def get_secret(self, secret_name: str) -> str | None:
        """Get a secret value by name.
        
        Args:
            secret_name: Name of the secret.
        
        Returns:
            Secret value, or None if not found.
        """
        ...
    
    @abstractmethod
    def get_secret_version(
        self,
        secret_name: str,
        version: str = "latest",
    ) -> str | None:
        """Get a specific version of a secret.
        
        Args:
            secret_name: Name of the secret.
            version: Version identifier.
        
        Returns:
            Secret value, or None if not found.
        """
        ...


class ConfigProvider(ABC):
    """Abstract interface for configuration management.
    
    Implementations handle loading configuration from different sources
    (files, environment, remote config services, etc.).
    """
    
    @abstractmethod
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            key: Configuration key (dot-separated for nested values).
            default: Default value if key not found.
        
        Returns:
            Configuration value.
        """
        ...
    
    @abstractmethod
    def get_all(self) -> dict[str, Any]:
        """Get all configuration values.
        
        Returns:
            Dictionary of all configuration.
        """
        ...
    
    @abstractmethod
    def reload(self) -> None:
        """Reload configuration from source."""
        ...
