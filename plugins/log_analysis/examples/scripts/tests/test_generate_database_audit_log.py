"""Contract tests for the synthetic YMMV database audit generator."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parents[1]
GENERATOR = SCRIPT_DIR / "generate_database_audit_log.py"
CHECKED_LOG = SCRIPT_DIR.parent / "ymmv_legacy_invoicing_database_audit.log"
CHECKED_TRUTH = SCRIPT_DIR.parent / (
    "ymmv_legacy_invoicing_database_audit.ground_truth.json"
)


@pytest.fixture(scope="module")
def generator():
    name = "generate_database_audit_log"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def arguments(generator, output: Path):
    return generator.parse_args(
        [
            "--start-date", "2026-09-15",
            "--end-date", "2026-09-17",
            "--records", "200",
            "--seed", "260915",
            "--output", str(output),
        ],
    )


def test_fixture_contract(generator, tmp_path):
    args = arguments(generator, tmp_path / "database.log")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert len(lines) == truth["record_count"] == 200
    assert truth["date_range"] == {"start": "2026-09-15", "end": "2026-09-17"}
    assert truth["business_hours"]["count"] == 166
    assert truth["business_hours"]["ratio"] == pytest.approx(0.83)
    assert len(truth["tables"]) == 8
    assert len(truth["accounts"]["database_administrator"]) == 4
    assert truth["fixed_scenarios"] == {
        "MANUAL_CUSTOMER_EXPORT": 5,
        "NIGHTLY_BACKUP": 2,
    }
    assert sum(truth["event_counts"].values()) == 200
    assert all("event_time=" in line or line.startswith("2026-") for line in lines)


def test_customer_export_is_explicit_and_contains_no_customer_values(
    generator,
    tmp_path,
):
    args = arguments(generator, tmp_path / "database.log")
    patterns = generator.load_patterns(args.patterns)
    lines, _ = generator.build_output(args, patterns)
    scenario = [line for line in lines if "MANUAL_CUSTOMER_EXPORT" in line]

    assert len(scenario) == 5
    assert any("event=SPOOL_OPEN" in line for line in scenario)
    assert any(
        "object=YMMV.CUSTOMER" in line and "rows=4872" in line
        for line in scenario
    )
    assert any(
        "event=SPOOL_CLOSE" in line and "bytes=684291" in line
        for line in scenario
    )


def test_generation_is_deterministic(generator, tmp_path):
    args = arguments(generator, tmp_path / "database.log")
    patterns = generator.load_patterns(args.patterns)
    first = generator.build_output(args, patterns)
    second = generator.build_output(args, patterns)
    assert first == second


def test_checked_fixture_is_an_exact_generator_output(generator, tmp_path):
    args = arguments(generator, tmp_path / "database.log")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert CHECKED_LOG.read_text(encoding="utf-8") == "\n".join(lines) + "\n"
    assert json.loads(CHECKED_TRUTH.read_text(encoding="utf-8")) == truth


def test_date_range_is_inclusive(generator):
    assert generator.dates_in_range(date(2026, 9, 15), date(2026, 9, 17)) == [
        date(2026, 9, 15),
        date(2026, 9, 16),
        date(2026, 9, 17),
    ]
