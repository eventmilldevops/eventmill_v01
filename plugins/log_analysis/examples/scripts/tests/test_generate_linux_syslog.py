"""Contract tests for the synthetic YMMV Linux syslog generator."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parents[1]
GENERATOR = SCRIPT_DIR / "generate_linux_syslog.py"
CHECKED_LOG = SCRIPT_DIR.parent / "ymmv_legacy_invoicing_syslog.log"
CHECKED_TRUTH = SCRIPT_DIR.parent / (
    "ymmv_legacy_invoicing_syslog.ground_truth.json"
)


@pytest.fixture(scope="module")
def generator():
    name = "generate_linux_syslog"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def arguments(generator, output: Path, records: int = 3000):
    return generator.parse_args(
        [
            "--start-date",
            "2026-09-15",
            "--end-date",
            "2026-09-17",
            "--records",
            str(records),
            "--seed",
            "260921",
            "--output",
            str(output),
        ],
    )


def test_fixture_is_large_routine_and_noninteractive(generator, tmp_path):
    args = arguments(generator, tmp_path / "syslog")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert len(lines) == truth["record_count"] == 3000
    assert truth["interactive_user_events"] == 0
    assert truth["fixed_scenarios"] == {"OS_STARTUP": 28}
    assert truth["event_counts"]["CRON_COMMAND"] > 1000
    assert sum(truth["event_counts"].values()) == 3000


def test_startup_sequence_contains_host_services(generator, tmp_path):
    args = arguments(generator, tmp_path / "syslog")
    patterns = generator.load_patterns(args.patterns)
    lines, _ = generator.build_output(args, patterns)
    startup = [line for line in lines if "scenario=OS_STARTUP" in line]
    text = "\n".join(startup)

    assert len(startup) == 28
    assert "Started PostgreSQL RDBMS" in text
    assert "Started Apache Tomcat 9 Web Application Server" in text
    assert "Startup finished" in text


def test_checked_fixture_is_an_exact_generator_output(generator, tmp_path):
    args = arguments(generator, tmp_path / "syslog")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert CHECKED_LOG.read_text(encoding="utf-8") == "\n".join(lines) + "\n"
    assert json.loads(CHECKED_TRUTH.read_text(encoding="utf-8")) == truth


def test_generator_scales_beyond_checked_fixture(generator, tmp_path):
    args = arguments(generator, tmp_path / "syslog", records=5000)
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert len(lines) == truth["record_count"] == 5000
