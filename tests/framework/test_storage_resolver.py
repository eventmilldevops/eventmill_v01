"""
Tests for the StorageResolver module.

Validates pillar-based bucket resolution, common bucket fallback,
workspace folder scoping, and local backend integration.
"""

import tempfile
from pathlib import Path

import pytest

from framework.cloud.resolver import (
    StorageResolver,
    StorageResolverConfig,
    ResolvedPath,
    create_local_resolver,
    PILLAR_SLUGS,
)
from framework.session.models import Pillar


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def storage_base() -> Path:
    """Create a temporary base directory for local storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def config() -> StorageResolverConfig:
    """Default resolver config for tests."""
    return StorageResolverConfig(bucket_prefix="testmill")


@pytest.fixture
def resolver(storage_base: Path, config: StorageResolverConfig) -> StorageResolver:
    """Create a local-backed StorageResolver."""
    return create_local_resolver(base_path=storage_base, config=config)


def _write_file(storage_base: Path, bucket: str, object_path: str, content: str = "test") -> Path:
    """Helper to write a file into a local 'bucket' directory."""
    full = storage_base / bucket / object_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content)
    return full


# ---------------------------------------------------------------------------
# StorageResolverConfig
# ---------------------------------------------------------------------------


class TestStorageResolverConfig:
    """Tests for config construction and bucket name derivation."""

    def test_default_pillar_bucket_name(self, config: StorageResolverConfig):
        assert config.bucket_for_pillar(Pillar.LOG_ANALYSIS) == "testmill-log-analysis"
        assert config.bucket_for_pillar(Pillar.NETWORK_FORENSICS) == "testmill-network-forensics"
        assert config.bucket_for_pillar(Pillar.THREAT_MODELING) == "testmill-threat-modeling"

    def test_common_bucket_name(self, config: StorageResolverConfig):
        assert config.common_bucket() == "testmill-common"

    def test_pillar_override(self):
        cfg = StorageResolverConfig(
            bucket_prefix="testmill",
            pillar_bucket_overrides={Pillar.LOG_ANALYSIS: "custom-logs"},
        )
        assert cfg.bucket_for_pillar(Pillar.LOG_ANALYSIS) == "custom-logs"
        # Other pillars still use convention
        assert cfg.bucket_for_pillar(Pillar.THREAT_MODELING) == "testmill-threat-modeling"

    def test_common_override(self):
        cfg = StorageResolverConfig(
            bucket_prefix="testmill",
            common_bucket_override="my-shared",
        )
        assert cfg.common_bucket() == "my-shared"

    def test_from_environment(self, monkeypatch):
        monkeypatch.setenv("EVENTMILL_BUCKET_PREFIX", "myorg")
        monkeypatch.setenv("EVENTMILL_BUCKET_LOG_ANALYSIS", "myorg-special-logs")
        monkeypatch.setenv("EVENTMILL_BUCKET_COMMON", "myorg-shared")

        cfg = StorageResolverConfig.from_environment()
        assert cfg.bucket_prefix == "myorg"
        assert cfg.bucket_for_pillar(Pillar.LOG_ANALYSIS) == "myorg-special-logs"
        assert cfg.common_bucket() == "myorg-shared"
        # Non-overridden pillar uses convention
        assert cfg.bucket_for_pillar(Pillar.NETWORK_FORENSICS) == "myorg-network-forensics"

    def test_legacy_gcs_log_bucket(self, monkeypatch):
        monkeypatch.setenv("GCS_LOG_BUCKET", "legacy-intake")
        monkeypatch.delenv("EVENTMILL_BUCKET_LOG_ANALYSIS", raising=False)

        cfg = StorageResolverConfig.from_environment()
        assert cfg.bucket_for_pillar(Pillar.LOG_ANALYSIS) == "legacy-intake"

    def test_explicit_override_beats_legacy(self, monkeypatch):
        monkeypatch.setenv("GCS_LOG_BUCKET", "legacy-intake")
        monkeypatch.setenv("EVENTMILL_BUCKET_LOG_ANALYSIS", "new-logs")

        cfg = StorageResolverConfig.from_environment()
        assert cfg.bucket_for_pillar(Pillar.LOG_ANALYSIS) == "new-logs"

    def test_legacy_ignored_when_prefix_set(self, monkeypatch):
        """Regression: GCS_LOG_BUCKET must not override when a custom prefix is active."""
        monkeypatch.setenv("EVENTMILL_BUCKET_PREFIX", "evtm_v01")
        monkeypatch.setenv("GCS_LOG_BUCKET", "defaultevtintake2")
        monkeypatch.delenv("EVENTMILL_BUCKET_LOG_ANALYSIS", raising=False)

        cfg = StorageResolverConfig.from_environment()
        assert cfg.bucket_for_pillar(Pillar.LOG_ANALYSIS) == "evtm_v01-log-analysis"


# ---------------------------------------------------------------------------
# Resolution logic
# ---------------------------------------------------------------------------


class TestResolve:
    """Tests for the multi-location file resolution."""

    def test_explicit_gs_path(self, resolver: StorageResolver):
        result = resolver.resolve(
            filename="",
            pillar=Pillar.LOG_ANALYSIS,
            explicit_path="gs://other-bucket/some/file.log",
        )
        assert result is not None
        assert result.source == "explicit"
        assert result.bucket == "other-bucket"
        assert result.object_path == "some/file.log"

    def test_pillar_bucket_root(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-log-analysis", "auth.log")

        result = resolver.resolve(filename="auth.log", pillar=Pillar.LOG_ANALYSIS)
        assert result is not None
        assert result.source == "pillar"
        assert result.bucket == "testmill-log-analysis"
        assert result.object_path == "auth.log"

    def test_common_bucket_fallback(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-common", "iocs.json")

        result = resolver.resolve(filename="iocs.json", pillar=Pillar.LOG_ANALYSIS)
        assert result is not None
        assert result.source == "common"
        assert result.bucket == "testmill-common"

    def test_pillar_wins_over_common(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-log-analysis", "data.json", content="pillar")
        _write_file(storage_base, "testmill-common", "data.json", content="common")

        result = resolver.resolve(filename="data.json", pillar=Pillar.LOG_ANALYSIS)
        assert result is not None
        assert result.source == "pillar"

    def test_workspace_folder_pillar(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-log-analysis", "inc-42/auth.log")

        result = resolver.resolve(
            filename="auth.log",
            pillar=Pillar.LOG_ANALYSIS,
            workspace_folder="inc-42",
        )
        assert result is not None
        assert result.source == "pillar"
        assert result.object_path == "inc-42/auth.log"
        assert result.workspace_folder == "inc-42"

    def test_workspace_folder_common(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-common", "inc-42/iocs.json")

        result = resolver.resolve(
            filename="iocs.json",
            pillar=Pillar.LOG_ANALYSIS,
            workspace_folder="inc-42",
        )
        assert result is not None
        assert result.source == "common"
        assert result.workspace_folder == "inc-42"

    def test_workspace_falls_through_to_root(self, resolver: StorageResolver, storage_base: Path):
        # File only in pillar root, not in workspace folder
        _write_file(storage_base, "testmill-log-analysis", "auth.log")

        result = resolver.resolve(
            filename="auth.log",
            pillar=Pillar.LOG_ANALYSIS,
            workspace_folder="inc-42",
        )
        assert result is not None
        assert result.source == "pillar"
        assert result.object_path == "auth.log"
        assert result.workspace_folder is None

    def test_not_found(self, resolver: StorageResolver):
        result = resolver.resolve(filename="nope.log", pillar=Pillar.LOG_ANALYSIS)
        assert result is None


# ---------------------------------------------------------------------------
# list_workspace
# ---------------------------------------------------------------------------


class TestListWorkspace:
    """Tests for listing files in pillar and common buckets."""

    def test_lists_pillar_and_common(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-log-analysis", "a.log")
        _write_file(storage_base, "testmill-common", "shared.json")

        listing = resolver.list_workspace(pillar=Pillar.LOG_ANALYSIS)
        filenames = {f.filename for f in listing.files}
        assert "a.log" in filenames
        assert "shared.json" in filenames

    def test_pillar_shadows_common(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-log-analysis", "dup.txt", content="pillar")
        _write_file(storage_base, "testmill-common", "dup.txt", content="common")

        listing = resolver.list_workspace(pillar=Pillar.LOG_ANALYSIS)
        dup_entries = [f for f in listing.files if f.filename == "dup.txt"]
        assert len(dup_entries) == 1
        assert dup_entries[0].source == "pillar"

    def test_workspace_filter(self, resolver: StorageResolver, storage_base: Path):
        _write_file(storage_base, "testmill-log-analysis", "inc-1/a.log")
        _write_file(storage_base, "testmill-log-analysis", "inc-2/b.log")

        listing = resolver.list_workspace(
            pillar=Pillar.LOG_ANALYSIS,
            workspace_folder="inc-1",
        )
        filenames = {f.filename for f in listing.files}
        assert "a.log" in filenames
        assert "b.log" not in filenames

    def test_empty_bucket(self, resolver: StorageResolver):
        listing = resolver.list_workspace(pillar=Pillar.NETWORK_FORENSICS)
        assert listing.files == []
        assert listing.truncated is False

    def test_same_basename_in_different_folders_both_listed(
        self, resolver: StorageResolver, storage_base: Path
    ):
        """Distinct files sharing a basename must not collapse into one row."""
        _write_file(storage_base, "testmill-log-analysis", "inc-1/auth.log")
        _write_file(storage_base, "testmill-log-analysis", "inc-2/auth.log")

        listing = resolver.list_workspace(pillar=Pillar.LOG_ANALYSIS)
        paths = {f.object_path for f in listing.files}
        assert paths == {"inc-1/auth.log", "inc-2/auth.log"}

    def test_prefix_narrows_listing(
        self, resolver: StorageResolver, storage_base: Path
    ):
        _write_file(storage_base, "testmill-log-analysis", "inc-1/a.log")
        _write_file(storage_base, "testmill-log-analysis", "inc-2/b.log")

        listing = resolver.list_workspace(
            pillar=Pillar.LOG_ANALYSIS,
            prefix="inc-1/",
        )
        assert {f.filename for f in listing.files} == {"a.log"}

    def test_partial_segment_prefix_matches_like_object_store(
        self, resolver: StorageResolver, storage_base: Path
    ):
        """A prefix need not be a whole directory name, as on GCS."""
        _write_file(storage_base, "testmill-log-analysis", "inc-1/a.log")
        _write_file(storage_base, "testmill-log-analysis", "inc-2/b.log")
        _write_file(storage_base, "testmill-log-analysis", "other/c.log")

        listing = resolver.list_workspace(pillar=Pillar.LOG_ANALYSIS, prefix="inc")
        assert {f.filename for f in listing.files} == {"a.log", "b.log"}

    def test_prefix_composes_with_workspace(
        self, resolver: StorageResolver, storage_base: Path
    ):
        _write_file(storage_base, "testmill-log-analysis", "inc-1/web/a.log")
        _write_file(storage_base, "testmill-log-analysis", "inc-1/db/b.log")

        listing = resolver.list_workspace(
            pillar=Pillar.LOG_ANALYSIS,
            workspace_folder="inc-1",
            prefix="web/",
        )
        assert {f.filename for f in listing.files} == {"a.log"}

    def test_size_and_mtime_populated(
        self, resolver: StorageResolver, storage_base: Path
    ):
        _write_file(storage_base, "testmill-log-analysis", "a.log", content="hello")

        listing = resolver.list_workspace(pillar=Pillar.LOG_ANALYSIS)
        entry = next(f for f in listing.files if f.filename == "a.log")
        assert entry.size_bytes == 5
        assert entry.modified is not None
        # Aware UTC, so it is comparable with values from other backends
        assert entry.modified.tzinfo is not None

    def test_truncated_flag_set_at_cap(
        self, resolver: StorageResolver, storage_base: Path
    ):
        for i in range(4):
            _write_file(storage_base, "testmill-log-analysis", f"f{i}.log")

        listing = resolver.list_workspace(pillar=Pillar.LOG_ANALYSIS, max_results=2)
        assert listing.truncated is True

    def test_uri_round_trips_to_resolve(
        self, resolver: StorageResolver, storage_base: Path
    ):
        """A listed file's uri must resolve without re-running the lookup."""
        _write_file(storage_base, "testmill-log-analysis", "inc-1/auth.log")

        listing = resolver.list_workspace(pillar=Pillar.LOG_ANALYSIS)
        entry = listing.files[0]

        resolved = resolver.resolve(
            filename="",
            pillar=Pillar.LOG_ANALYSIS,
            explicit_path=entry.uri,
        )
        assert resolved is not None
        assert resolved.object_path == "inc-1/auth.log"


# ---------------------------------------------------------------------------
# Upload / download round-trip
# ---------------------------------------------------------------------------


class TestUploadDownload:
    """Tests for upload and download via the resolver."""

    def test_upload_to_pillar(self, resolver: StorageResolver, storage_base: Path, tmp_path: Path):
        src = tmp_path / "test.log"
        src.write_text("hello")

        rp = resolver.upload(
            local_path=src,
            filename="test.log",
            pillar=Pillar.LOG_ANALYSIS,
        )
        assert rp.source == "pillar"
        assert rp.bucket == "testmill-log-analysis"

        # Verify file exists via resolve
        found = resolver.resolve(filename="test.log", pillar=Pillar.LOG_ANALYSIS)
        assert found is not None

    def test_upload_to_common(self, resolver: StorageResolver, storage_base: Path, tmp_path: Path):
        src = tmp_path / "shared.json"
        src.write_text("{}")

        rp = resolver.upload(
            local_path=src,
            filename="shared.json",
            pillar=Pillar.LOG_ANALYSIS,
            target="common",
        )
        assert rp.source == "common"
        assert rp.bucket == "testmill-common"

    def test_upload_with_workspace(self, resolver: StorageResolver, tmp_path: Path):
        src = tmp_path / "inc.log"
        src.write_text("data")

        rp = resolver.upload(
            local_path=src,
            filename="inc.log",
            pillar=Pillar.LOG_ANALYSIS,
            workspace_folder="inc-99",
        )
        assert rp.object_path == "inc-99/inc.log"
        assert rp.workspace_folder == "inc-99"

    def test_download_roundtrip(self, resolver: StorageResolver, tmp_path: Path):
        src = tmp_path / "original.log"
        src.write_text("content123")

        resolver.upload(local_path=src, filename="original.log", pillar=Pillar.LOG_ANALYSIS)

        resolved = resolver.resolve(filename="original.log", pillar=Pillar.LOG_ANALYSIS)
        assert resolved is not None

        dest = tmp_path / "downloaded.log"
        resolver.download(resolved, dest)
        assert dest.read_text() == "content123"


# ---------------------------------------------------------------------------
# describe_buckets
# ---------------------------------------------------------------------------


class TestDescribeBuckets:
    """Tests for the informational bucket listing."""

    def test_lists_all_pillars_and_common(self, resolver: StorageResolver):
        buckets = resolver.describe_buckets()
        types = {b["type"] for b in buckets}
        assert "pillar" in types
        assert "common" in types

        # Should have one entry per enabled pillar + common
        pillar_entries = [b for b in buckets if b["type"] == "pillar"]
        assert len(pillar_entries) == len(Pillar.ALL)

        common_entries = [b for b in buckets if b["type"] == "common"]
        assert len(common_entries) == 1
        assert common_entries[0]["bucket"] == "testmill-common"


# ---------------------------------------------------------------------------
# ResolvedPath
# ---------------------------------------------------------------------------


class TestResolvedPath:
    """Tests for ResolvedPath properties."""

    def test_uri(self):
        rp = ResolvedPath(bucket="mybucket", object_path="folder/file.log", source="pillar")
        assert rp.uri == "gs://mybucket/folder/file.log"

    def test_display_explicit(self):
        rp = ResolvedPath(bucket="mybucket", object_path="file.log", source="explicit")
        assert "explicit" in rp.display

    def test_display_with_workspace(self):
        rp = ResolvedPath(
            bucket="mybucket",
            object_path="inc/file.log",
            source="pillar",
            workspace_folder="inc",
        )
        assert "workspace: inc" in rp.display
