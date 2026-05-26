"""
Event Mill Cloud Abstraction Layer

Cloud-provider-specific code is isolated behind abstract interfaces
to enable future portability (GCP, AWS, Azure).
"""

from .interfaces import ConfigProvider, SecretProvider, StorageBackend
from .resolver import (
    StorageResolver,
    StorageResolverConfig,
    ResolvedPath,
    create_gcs_resolver,
    create_local_resolver,
)

__all__ = [
    "ConfigProvider",
    "ResolvedPath",
    "SecretProvider",
    "StorageBackend",
    "StorageResolver",
    "StorageResolverConfig",
    "create_gcs_resolver",
    "create_local_resolver",
]
