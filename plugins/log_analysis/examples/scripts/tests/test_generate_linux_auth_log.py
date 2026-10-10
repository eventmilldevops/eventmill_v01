"""Contract tests for the synthetic YMMV Linux auth.log generator."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parents[1]
GENERATOR = SCRIPT_DIR / "generate_linux_auth_log.py"
CHECKED_LOG = SCRIPT_DIR.parent / "ymmv_legacy_invoicing_auth.log"
CHECKED_TRUTH = SCRIPT_DIR.parent / (
    "ymmv_legacy_invoicing_auth.ground_truth.json"
)


@pytest.fixture(scope="module")
def generator():
    name = "generate_linux_auth_log"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def arguments(generator, output: Path, records: int = 420):
    return generator.parse_args(
        [
            "--start-date",
            "2026-09-15",
            "--end-date",
            "2026-09-17",
            "--records",
            str(records),
            "--seed",
            "260922",
            "--output",
            str(output),
        ],
    )


def test_fixture_is_large_boring_and_low_interaction(generator, tmp_path):
    args = arguments(generator, tmp_path / "auth.log")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert truth["logical_record_count"] == 420
    assert truth["physical_line_count"] == len(lines) == 780
    assert truth["interactive_activity"] == {
        "successful_sessions": 5,
        "failed_attempts": 2,
        "total_attempts": 7,
    }
    assert truth["event_counts"]["CRON_SESSION"] == 249


def test_interactive_events_use_only_declared_synthetic_values(generator, tmp_path):
    args = arguments(generator, tmp_path / "auth.log")
    patterns = generator.load_patterns(args.patterns)
    lines, _ = generator.build_output(args, patterns)
    scenario_lines = [line for line in lines if "scenario=INTERACTIVE_" in line]
    text = "\n".join(scenario_lines)

    assert len(scenario_lines) == 7
    assert all(
        account in text for account in patterns["interactive_accounts"]
    )
    assert "198.51.100.22" in text
    assert "198.51.100.57" in text


def test_checked_fixture_is_an_exact_generator_output(generator, tmp_path):
    args = arguments(generator, tmp_path / "auth.log")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert CHECKED_LOG.read_text(encoding="utf-8") == "\n".join(lines) + "\n"
    assert json.loads(CHECKED_TRUTH.read_text(encoding="utf-8")) == truth


def test_generator_scales_to_thousands_of_logical_records(generator, tmp_path):
    args = arguments(generator, tmp_path / "auth.log", records=3000)
    patterns = generator.load_patterns(args.patterns)
    _, truth = generator.build_output(args, patterns)

    assert truth["logical_record_count"] == 3000
    assert truth["physical_line_count"] > 5000
    assert truth["interactive_activity"]["total_attempts"] == 7
