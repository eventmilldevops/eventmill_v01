"""
Tests for the 'files' CLI command.

Covers filtering, ordering and the '#N' references that let a listed row
be used in place of a path. The reference behaviour spans commands and
depends on shell state, so it cannot be reached from the resolver tests.
"""

import os
import time
from pathlib import Path

import pytest

from framework.cli.shell import (
    EventMillShell,
    _format_bytes,
    _parse_duration,
    _split_flags,
)
from framework.cloud.resolver import StorageResolverConfig, create_local_resolver
from framework.session.models import Pillar


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


PILLAR_BUCKET = "testmill-log-analysis"
COMMON_BUCKET = "testmill-common"


def _seed(
    storage_base: Path,
    bucket: str,
    object_path: str,
    content: str = "x",
    age_hours: float | None = None,
) -> Path:
    """Write a file into a local 'bucket', optionally backdating its mtime."""
    full = storage_base / bucket / object_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content)
    if age_hours is not None:
        stamp = time.time() - (age_hours * 3600)
        os.utime(full, (stamp, stamp))
    return full


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EventMillShell:
    """A shell with a session, a pillar, and a local storage resolver."""
    monkeypatch.delenv("K_SERVICE", raising=False)

    sh = EventMillShell(workspace_path=tmp_path)
    sh.storage_resolver = create_local_resolver(
        base_path=tmp_path / "storage",
        config=StorageResolverConfig(bucket_prefix="testmill"),
    )
    sh.session_manager.new_session("test")
    sh.session_manager.set_pillar(Pillar.LOG_ANALYSIS)
    return sh


@pytest.fixture
def storage_base(tmp_path: Path) -> Path:
    return tmp_path / "storage"


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestParseDuration:
    """Tests for the --newer duration grammar."""

    @pytest.mark.parametrize(
        "text,seconds",
        [
            ("30s", 30),
            ("90m", 5400),
            ("24h", 86400),
            ("7d", 604800),
            ("2w", 1209600),
            ("24H", 86400),
        ],
    )
    def test_valid(self, text: str, seconds: int):
        delta = _parse_duration(text)
        assert delta is not None
        assert delta.total_seconds() == seconds

    @pytest.mark.parametrize("text", ["24", "1d12h", "yesterday", "", "-1h", "1y"])
    def test_rejected_rather_than_guessed(self, text: str):
        assert _parse_duration(text) is None


class TestFormatBytes:
    """Tests for byte rendering."""

    @pytest.mark.parametrize(
        "size,expected",
        [
            (None, "-"),
            (0, "0 B"),
            (512, "512 B"),
            (1536, "1.5 KB"),
            (5 * 1024**2, "5.0 MB"),
        ],
    )
    def test_units(self, size, expected):
        assert _format_bytes(size) == expected


class TestSplitFlags:
    """Tests for the shared --key value tokenizer."""

    def test_forms(self):
        pairs, error = _split_flags(["--a", "1", "--b=2", "--c"])
        assert error is None
        assert pairs == [("a", "1"), ("b", "2"), ("c", True)]

    def test_rejects_bare_token(self):
        pairs, error = _split_flags(["oops"])
        assert error is not None


# ---------------------------------------------------------------------------
# files command
# ---------------------------------------------------------------------------


class TestFilesFiltering:
    """Tests for narrowing a listing."""

    def test_lists_and_numbers_rows(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "inc-1/a.log")
        _seed(storage_base, PILLAR_BUCKET, "inc-1/b.log")

        shell.onecmd("files")
        out = capsys.readouterr().out
        assert "inc-1/a.log" in out
        assert "inc-1/b.log" in out
        assert shell._last_file_listing is not None
        assert [e.index for e in shell._last_file_listing.entries] == [1, 2]

    def test_ext_filter(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "a.log")
        _seed(storage_base, PILLAR_BUCKET, "b.json")

        shell.onecmd("files --ext .log")
        out = capsys.readouterr().out
        assert "a.log" in out
        assert "b.json" not in out

    def test_ext_matches_rotated_logs(self, shell, storage_base, capsys):
        """--ext .log must match auth.log.1, which is not its final suffix."""
        _seed(storage_base, PILLAR_BUCKET, "auth.log")
        _seed(storage_base, PILLAR_BUCKET, "auth.log.1")

        shell.onecmd("files --ext .log")
        out = capsys.readouterr().out
        assert "auth.log.1" in out

    def test_path_filter(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "inc-1/a.log")
        _seed(storage_base, PILLAR_BUCKET, "other/b.log")

        shell.onecmd("files --path inc-1")
        out = capsys.readouterr().out
        assert "a.log" in out
        assert "b.log" not in out

    def test_newer_filter(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "fresh.log", age_hours=1)
        _seed(storage_base, PILLAR_BUCKET, "stale.log", age_hours=72)

        shell.onecmd("files --newer 24h")
        out = capsys.readouterr().out
        assert "fresh.log" in out
        assert "stale.log" not in out

    def test_match_substring_and_glob(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "auth.log")
        _seed(storage_base, PILLAR_BUCKET, "access.log")

        shell.onecmd("files --match auth")
        assert "access.log" not in capsys.readouterr().out

        shell.onecmd("files --match *cess*")
        assert "access.log" in capsys.readouterr().out

    def test_sort_time_newest_first(self, shell, storage_base):
        _seed(storage_base, PILLAR_BUCKET, "old.log", age_hours=48)
        _seed(storage_base, PILLAR_BUCKET, "new.log", age_hours=1)

        shell.onecmd("files --sort time")
        names = [e.file.filename for e in shell._last_file_listing.entries]
        assert names == ["new.log", "old.log"]

    def test_limit_and_footer(self, shell, storage_base, capsys):
        for i in range(5):
            _seed(storage_base, PILLAR_BUCKET, f"f{i}.log")

        shell.onecmd("files --limit 2")
        out = capsys.readouterr().out
        assert len(shell._last_file_listing.entries) == 2
        assert "and 3 more" in out

    def test_limit_zero_shows_all(self, shell, storage_base):
        for i in range(5):
            _seed(storage_base, PILLAR_BUCKET, f"f{i}.log")

        shell.onecmd("files --limit 0")
        assert len(shell._last_file_listing.entries) == 5

    def test_bad_flag_reports_without_listing(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "a.log")

        shell.onecmd("files --nope 1")
        assert "Unknown flag" in capsys.readouterr().out
        assert shell._last_file_listing is None

    def test_bad_duration_names_the_units(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "a.log")

        shell.onecmd("files --newer 24")
        out = capsys.readouterr().out
        assert "90m, 24h, 7d, 2w" in out


# ---------------------------------------------------------------------------
# #N references
# ---------------------------------------------------------------------------


class TestFileReferences:
    """Tests for using '#N' in place of a path."""

    def test_resolves_to_listed_row(self, shell, storage_base):
        _seed(storage_base, PILLAR_BUCKET, "inc-1/a.log")

        shell.onecmd("files")
        entry = shell._resolve_file_ref("#1")
        assert entry is not None
        assert entry.file.object_path == "inc-1/a.log"
        assert entry.file.uri == f"gs://{PILLAR_BUCKET}/inc-1/a.log"

    def test_without_listing_is_refused(self, shell, capsys):
        assert shell._resolve_file_ref("#1") is None
        assert "Run 'files' first" in capsys.readouterr().out

    def test_out_of_range_is_refused(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "a.log")

        shell.onecmd("files")
        capsys.readouterr()
        assert shell._resolve_file_ref("#99") is None
        assert "out of range" in capsys.readouterr().out

    def test_stale_after_workspace_change(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "inc-1/a.log")

        shell.onecmd("files")
        capsys.readouterr()
        shell.session_manager.set_workspace("inc-1")

        assert shell._resolve_file_ref("#1") is None
        assert "Run 'files' again" in capsys.readouterr().out

    def test_index_follows_the_filtered_rows(self, shell, storage_base):
        _seed(storage_base, PILLAR_BUCKET, "a.json")
        _seed(storage_base, PILLAR_BUCKET, "b.log")

        shell.onecmd("files --ext .log")
        entry = shell._resolve_file_ref("#1")
        assert entry.file.filename == "b.log"

    def test_load_expands_to_uri(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "inc-1/a.log", content="hello")

        shell.onecmd("files")
        capsys.readouterr()
        shell.onecmd("load #1")
        out = capsys.readouterr().out
        assert f"gs://{PILLAR_BUCKET}/inc-1/a.log" in out
        assert "Loaded artifact" in out

    def test_run_before_load_errors_with_the_fix(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "a.log")

        shell.onecmd("files")
        capsys.readouterr()

        pairs, ok = shell._expand_file_refs([("path", "#1")])
        assert ok is False
        out = capsys.readouterr().out
        assert "not a local one" in out
        assert "load #1" in out

    def test_run_after_load_gets_the_local_path(self, shell, storage_base, capsys):
        _seed(storage_base, PILLAR_BUCKET, "a.log", content="hello")

        shell.onecmd("files")
        shell.onecmd("load #1")
        capsys.readouterr()

        pairs, ok = shell._expand_file_refs([("path", "#1")])
        assert ok is True
        assert Path(pairs[0][1]).exists()
        assert Path(pairs[0][1]).read_text() == "hello"

    def test_double_hash_is_a_literal(self, shell):
        pairs, ok = shell._expand_file_refs([("query", "##3")])
        assert ok is True
        assert pairs == [("query", "#3")]

    def test_hash_inside_a_value_is_untouched(self, shell):
        pairs, ok = shell._expand_file_refs([("query", "error #3 occurred")])
        assert ok is True
        assert pairs == [("query", "error #3 occurred")]
