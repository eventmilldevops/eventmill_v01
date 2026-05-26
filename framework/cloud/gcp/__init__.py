"""
Google Cloud Platform Implementations

GCS storage backend, Secret Manager, and Zeek Cloud Build integration.
"""

from .storage import GCSStorageBackend
from .secrets import GCPSecretProvider

__all__ = [
    "GCPSecretProvider",
    "GCSStorageBackend",
]

# Lazy imports for optional heavy dependencies
def get_zeek_client():
    """Get ZeekCloudBuildClient (requires google-cloud-build)."""
    from .zeek import ZeekCloudBuildClient
    return ZeekCloudBuildClient
