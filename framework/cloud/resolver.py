"""
Event Mill Storage Resolver

Maps (pillar, workspace_folder, filename) to concrete storage paths.
Implements the pillar-default-bucket + common-bucket resolution strategy.

Naming Convention:
    {prefix}-{pillar_slug}     — per-pillar bucket (e.g. eventmill-log-analysis)
    {prefix}-common            — shared cross-pillar bucket

Resolution Order:
    1. Explicit path override   — caller provides full gs:// or file:// URI
    2. Pillar bucket + workspace — gs://{pillar-bucket}/{workspace}/{filename}
    3. Pillar bucket root        — gs://{pillar-bucket}/{filename}
    4. Common bucket + workspace — gs://{prefix}-common/{workspace}/{filename}
    5. Common bucket root        — gs://{prefix}-common/{filename}

If both pillar and common have the file, pillar wins (investigation-specific
data is more relevant than shared reference data).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..session.models import Pillar
from .interfaces import StorageBackend, StoredObject

logger = logging.getLogger("eventmill.framework.cloud.resolver")


# ---------------------------------------------------------------------------
# Pillar slug mapping (pillar constant → bucket name segment)
# ---------------------------------------------------------------------------

PILLAR_SLUGS: dict[str, str] = {
    Pillar.LOG_ANALYSIS: "log-analysis",
    Pillar.NETWORK_FORENSICS: "network-forensics",
    Pillar.THREAT_MODELING: "threat-modeling",
    Pillar.CLOUD_INVESTIGATION: "cloud-investigation",
    Pillar.RISK_ASSESSMENT: "risk-assessment",
}

COMMON_SLUG = "common"

# Ceiling on objects fetched per bucket for a listing. Filters run over what
# comes back, so a low cap would turn a display limit into a false negative.
LIST_MAX_RESULTS = 5000


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class StorageResolverConfig:
    """Configuration for the storage resolver.

    Attributes:
        bucket_prefix: Shared prefix for all Event Mill buckets.
            Convention: ``{prefix}-{pillar-slug}`` and ``{prefix}-common``.
        pillar_bucket_overrides: Optional per-pillar bucket name overrides.
            Keyed by pillar constant (e.g. ``log_analysis``).
            If provided, overrides the convention for that pillar.
        common_bucket_override: Optional override for the common bucket name.
        enabled_pillars: Set of pillar constants that have buckets.
            Defaults to all five pillars.
    """

    bucket_prefix: str = "eventmill"
    pillar_bucket_overrides: dict[str, str] = field(default_factory=dict)
    common_bucket_override: str | None = None
    enabled_pillars: set[str] = field(default_factory=lambda: set(Pillar.ALL))

    def bucket_for_pillar(self, pillar: str) -> str:
        """Return the bucket name for a pillar."""
        if pillar in self.pillar_bucket_overrides:
            return self.pillar_bucket_overrides[pillar]
        slug = PILLAR_SLUGS.get(pillar, pillar.replace("_", "-"))
        return f"{self.bucket_prefix}-{slug}"

    def common_bucket(self) -> str:
        """Return the common bucket name."""
        if self.common_bucket_override:
            return self.common_bucket_override
        return f"{self.bucket_prefix}-{COMMON_SLUG}"

    @classmethod
    def from_environment(cls) -> StorageResolverConfig:
        """Build configuration from environment variables.

        Reads:
            EVENTMILL_BUCKET_PREFIX        — shared prefix (default: eventmill)
            EVENTMILL_BUCKET_COMMON        — override common bucket name
            EVENTMILL_BUCKET_LOG_ANALYSIS  — override log_analysis bucket
            EVENTMILL_BUCKET_NETWORK_FORENSICS
            EVENTMILL_BUCKET_THREAT_MODELING
            EVENTMILL_BUCKET_CLOUD_INVESTIGATION
            EVENTMILL_BUCKET_RISK_ASSESSMENT

        Falls back to ``GCS_LOG_BUCKET`` for backward compatibility:
        if set and no prefix is provided, it is used as the log_analysis
        bucket override.
        """
        prefix = os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
        common = os.environ.get("EVENTMILL_BUCKET_COMMON")

        overrides: dict[str, str] = {}
        for pillar in Pillar.ALL:
            env_key = f"EVENTMILL_BUCKET_{pillar.upper()}"
            val = os.environ.get(env_key)
            if val:
                overrides[pillar] = val

        # Backward compatibility: GCS_LOG_BUCKET → log_analysis override
        # Only apply when no explicit prefix has been set, so that a custom
        # prefix (e.g. evtm_v01) isn't silently overridden by a stale legacy var.
        prefix_explicitly_set = "EVENTMILL_BUCKET_PREFIX" in os.environ
        legacy = os.environ.get("GCS_LOG_BUCKET")
        if legacy and Pillar.LOG_ANALYSIS not in overrides and not prefix_explicitly_set:
            overrides[Pillar.LOG_ANALYSIS] = legacy

        return cls(
            bucket_prefix=prefix,
            pillar_bucket_overrides=overrides,
            common_bucket_override=common,
        )


# ---------------------------------------------------------------------------
# Resolved path result
# ---------------------------------------------------------------------------


@dataclass
class ResolvedPath:
    """Result of a storage resolution."""

    bucket: str
    object_path: str
    source: str  # "pillar", "common", or "explicit"
    workspace_folder: str | None = None

    @property
    def uri(self) -> str:
        """Full gs:// URI."""
        return f"gs://{self.bucket}/{self.object_path}"

    @property
    def display(self) -> str:
        """Human-readable description of where the file was found."""
        if self.source == "explicit":
            return f"explicit: {self.uri}"
        label = f"{self.source} bucket"
        if self.workspace_folder:
            label += f" (workspace: {self.workspace_folder})"
        return f"{label}: {self.uri}"


@dataclass
class WorkspaceFile:
    """One file visible to a pillar, as listed by ``list_workspace``."""

    filename: str
    bucket: str
    source: str  # "pillar" or "common"
    object_path: str
    size_bytes: int | None = None
    modified: datetime | None = None

    @property
    def uri(self) -> str:
        """Full gs:// URI, resolvable without re-running the lookup."""
        return f"gs://{self.bucket}/{self.object_path}"


@dataclass
class WorkspaceListing:
    """Result of ``list_workspace``.

    ``truncated`` is True when a bucket returned as many objects as were
    asked for, meaning filters downstream only saw part of the store.
    """

    files: list[WorkspaceFile] = field(default_factory=list)
    truncated: bool = False


# ---------------------------------------------------------------------------
# Storage Resolver
# ---------------------------------------------------------------------------


class StorageResolver:
    """Resolves file references to concrete storage locations.

    Wraps one ``StorageBackend`` per bucket and performs the multi-location
    lookup described in the module docstring.

    For local development the resolver maps each pillar to a subdirectory
    under a common base path, mirroring the bucket-per-pillar layout.
    """

    def __init__(
        self,
        config: StorageResolverConfig,
        backend_factory: callable | None = None,
    ):
        """Initialise the resolver.

        Args:
            config: Bucket naming and override configuration.
            backend_factory: Callable ``(bucket_name) -> StorageBackend``.
                If *None*, backends are created lazily on first access
                and the caller must register them with :meth:`register_backend`.
        """
        self.config = config
        self._backend_factory = backend_factory
        self._backends: dict[str, StorageBackend] = {}

        logger.info(
            "StorageResolver initialised (prefix=%s, common=%s)",
            config.bucket_prefix,
            config.common_bucket(),
        )

    # ------------------------------------------------------------------
    # Backend management
    # ------------------------------------------------------------------

    def register_backend(self, bucket_name: str, backend: StorageBackend) -> None:
        """Register a pre-built backend for a bucket."""
        self._backends[bucket_name] = backend

    def _get_backend(self, bucket_name: str) -> StorageBackend:
        """Return the backend for *bucket_name*, creating it lazily."""
        if bucket_name not in self._backends:
            if self._backend_factory:
                self._backends[bucket_name] = self._backend_factory(bucket_name)
            else:
                raise ValueError(
                    f"No backend registered for bucket '{bucket_name}' "
                    "and no backend_factory provided."
                )
        return self._backends[bucket_name]

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(
        self,
        filename: str,
        pillar: str,
        workspace_folder: str | None = None,
        explicit_path: str | None = None,
    ) -> ResolvedPath | None:
        """Resolve a filename to a concrete storage location.

        Args:
            filename: Bare filename (e.g. ``auth.log``).
            pillar: Active pillar constant (e.g. ``log_analysis``).
            workspace_folder: Optional workspace/incident folder.
            explicit_path: If provided, returned immediately as-is.

        Returns:
            A :class:`ResolvedPath` if the file exists, else *None*.
        """
        # 1. Explicit override
        if explicit_path:
            return self._resolve_explicit(explicit_path)

        pillar_bucket = self.config.bucket_for_pillar(pillar)
        common_bucket = self.config.common_bucket()

        # 2. Pillar bucket + workspace folder
        if workspace_folder:
            obj = f"{workspace_folder}/{filename}"
            if self._exists(pillar_bucket, obj):
                return ResolvedPath(
                    bucket=pillar_bucket,
                    object_path=obj,
                    source="pillar",
                    workspace_folder=workspace_folder,
                )

        # 3. Pillar bucket root
        if self._exists(pillar_bucket, filename):
            return ResolvedPath(
                bucket=pillar_bucket,
                object_path=filename,
                source="pillar",
            )

        # 4. Common bucket + workspace folder
        if workspace_folder:
            obj = f"{workspace_folder}/{filename}"
            if self._exists(common_bucket, obj):
                return ResolvedPath(
                    bucket=common_bucket,
                    object_path=obj,
                    source="common",
                    workspace_folder=workspace_folder,
                )

        # 5. Common bucket root
        if self._exists(common_bucket, filename):
            return ResolvedPath(
                bucket=common_bucket,
                object_path=filename,
                source="common",
            )

        return None

    def list_workspace(
        self,
        pillar: str,
        workspace_folder: str | None = None,
        include_common: bool = True,
        prefix: str = "",
        max_results: int = LIST_MAX_RESULTS,
    ) -> WorkspaceListing:
        """List files available to a pillar, optionally within a workspace.

        Deduplication follows the two rules resolution itself uses. Within
        a bucket, objects are distinct by ``object_path``, so files sharing
        a basename in different folders are all listed. Across buckets, a
        common-bucket file is hidden by a pillar-bucket file of the same
        name, mirroring the pillar-wins precedence of :meth:`resolve`.
        """
        files: list[WorkspaceFile] = []
        truncated = False
        seen_paths: set[str] = set()
        pillar_basenames: set[str] = set()

        pillar_bucket = self.config.bucket_for_pillar(pillar)
        common_bucket = self.config.common_bucket()

        base_prefix = f"{workspace_folder}/" if workspace_folder else ""
        full_prefix = f"{base_prefix}{prefix}" if prefix else base_prefix

        # Pillar bucket (takes precedence)
        objects = self._list_detailed(pillar_bucket, full_prefix, max_results)
        truncated = truncated or len(objects) >= max_results
        for obj in objects:
            obj_path = obj.path.replace("\\", "/")
            fname = obj_path.rsplit("/", 1)[-1] if "/" in obj_path else obj_path
            if not fname or obj_path in seen_paths:
                continue
            seen_paths.add(obj_path)
            pillar_basenames.add(fname)
            files.append(
                WorkspaceFile(
                    filename=fname,
                    bucket=pillar_bucket,
                    source="pillar",
                    object_path=obj_path,
                    size_bytes=obj.size_bytes,
                    modified=obj.modified,
                )
            )

        # Common bucket
        if include_common:
            objects = self._list_detailed(common_bucket, full_prefix, max_results)
            truncated = truncated or len(objects) >= max_results
            for obj in objects:
                obj_path = obj.path.replace("\\", "/")
                fname = obj_path.rsplit("/", 1)[-1] if "/" in obj_path else obj_path
                if not fname or obj_path in seen_paths:
                    continue
                if fname in pillar_basenames:
                    continue
                seen_paths.add(obj_path)
                files.append(
                    WorkspaceFile(
                        filename=fname,
                        bucket=common_bucket,
                        source="common",
                        object_path=obj_path,
                        size_bytes=obj.size_bytes,
                        modified=obj.modified,
                    )
                )

        return WorkspaceListing(files=files, truncated=truncated)

    def upload(
        self,
        local_path: Path,
        filename: str,
        pillar: str,
        workspace_folder: str | None = None,
        target: str = "pillar",
        metadata: dict[str, str] | None = None,
    ) -> ResolvedPath:
        """Upload a file to the appropriate bucket.

        Args:
            local_path: Local file to upload.
            filename: Destination filename.
            pillar: Active pillar.
            workspace_folder: Optional workspace/incident folder.
            target: ``"pillar"`` (default) or ``"common"``.
            metadata: Optional object metadata.

        Returns:
            A :class:`ResolvedPath` for the uploaded object.
        """
        if target == "common":
            bucket = self.config.common_bucket()
        else:
            bucket = self.config.bucket_for_pillar(pillar)

        obj_path = f"{workspace_folder}/{filename}" if workspace_folder else filename

        backend = self._get_backend(bucket)
        backend.upload(local_path, obj_path, metadata=metadata)

        logger.info("Uploaded %s → %s/%s", local_path.name, bucket, obj_path)

        return ResolvedPath(
            bucket=bucket,
            object_path=obj_path,
            source=target,
            workspace_folder=workspace_folder,
        )

    def download(
        self,
        resolved: ResolvedPath,
        local_path: Path,
    ) -> Path:
        """Download a previously resolved file to a local path."""
        backend = self._get_backend(resolved.bucket)
        return backend.download(resolved.object_path, local_path)

    # ------------------------------------------------------------------
    # Informational
    # ------------------------------------------------------------------

    def describe_buckets(self) -> list[dict[str, str]]:
        """Return a summary of configured buckets for display."""
        buckets = []
        for pillar in sorted(self.config.enabled_pillars):
            buckets.append({
                "pillar": pillar,
                "bucket": self.config.bucket_for_pillar(pillar),
                "type": "pillar",
            })
        buckets.append({
            "pillar": "common",
            "bucket": self.config.common_bucket(),
            "type": "common",
        })
        return buckets

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_explicit(self, path: str) -> ResolvedPath:
        """Parse an explicit gs:// path into a ResolvedPath."""
        if path.startswith("gs://"):
            # gs://bucket/object/path
            without_scheme = path[5:]
            parts = without_scheme.split("/", 1)
            bucket = parts[0]
            obj = parts[1] if len(parts) > 1 else ""
            return ResolvedPath(bucket=bucket, object_path=obj, source="explicit")
        # Treat as local/relative — return as-is with empty bucket
        return ResolvedPath(bucket="", object_path=path, source="explicit")

    def _exists(self, bucket: str, object_path: str) -> bool:
        """Check if an object exists in a bucket."""
        try:
            backend = self._get_backend(bucket)
            return backend.exists(object_path)
        except (ValueError, Exception) as exc:
            logger.debug("exists check failed for %s/%s: %s", bucket, object_path, exc)
            return False

    def _list_detailed(
        self,
        bucket: str,
        prefix: str = "",
        max_results: int = LIST_MAX_RESULTS,
    ) -> list[StoredObject]:
        """List objects in a bucket under a prefix, with metadata."""
        try:
            backend = self._get_backend(bucket)
            return backend.list_files_detailed(
                prefix=prefix,
                max_results=max_results,
            )
        except (ValueError, Exception) as exc:
            logger.debug("list failed for %s/%s: %s", bucket, prefix, exc)
            return []


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def create_gcs_resolver(
    config: StorageResolverConfig | None = None,
    project_id: str | None = None,
) -> StorageResolver:
    """Create a StorageResolver backed by GCS buckets.

    Each pillar + common gets its own ``GCSStorageBackend`` instance.
    The ``prefix`` parameter of ``GCSStorageBackend`` is set to empty
    string because the resolver manages paths directly.
    """
    from .gcp.storage import GCSStorageBackend

    if config is None:
        config = StorageResolverConfig.from_environment()

    def factory(bucket_name: str) -> StorageBackend:
        return GCSStorageBackend(
            bucket_name=bucket_name,
            prefix="",
            project_id=project_id,
        )

    return StorageResolver(config=config, backend_factory=factory)


def create_local_resolver(
    base_path: Path,
    config: StorageResolverConfig | None = None,
) -> StorageResolver:
    """Create a StorageResolver backed by local directories.

    Each "bucket" maps to a subdirectory under *base_path*::

        base_path/
            eventmill-log-analysis/
            eventmill-threat-modeling/
            eventmill-common/
    """
    from .local.storage import LocalStorageBackend

    if config is None:
        config = StorageResolverConfig(bucket_prefix="eventmill")

    def factory(bucket_name: str) -> StorageBackend:
        bucket_dir = base_path / bucket_name
        bucket_dir.mkdir(parents=True, exist_ok=True)
        return LocalStorageBackend(base_path=bucket_dir)

    return StorageResolver(config=config, backend_factory=factory)
