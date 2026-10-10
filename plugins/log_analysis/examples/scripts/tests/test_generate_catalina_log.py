"""Contract tests for the synthetic YMMV Catalina generator."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parents[1]
GENERATOR = SCRIPT_DIR / "generate_catalina_log.py"
DATABASE_PATTERNS = SCRIPT_DIR / "database_audit_patterns.json"
CHECKED_LOG = SCRIPT_DIR.parent / "ymmv_legacy_invoicing_catalina.log"
CHECKED_TRUTH = SCRIPT_DIR.parent / (
    "ymmv_legacy_invoicing_catalina.ground_truth.json"
)


@pytest.fixture(scope="module")
def generator():
    name = "generate_catalina_log"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def arguments(generator, output: Path, records: int = 240):
    return generator.parse_args(
        [
            "--start-date",
            "2026-09-15",
            "--end-date",
            "2026-09-17",
            "--records",
            str(records),
            "--seed",
            "260918",
            "--output",
            str(output),
        ],
    )


def test_fixture_contract(generator, tmp_path):
    args = arguments(generator, tmp_path / "catalina.log")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert truth["logical_record_count"] == 240
    assert truth["physical_line_count"] == len(lines) == 249
    assert truth["continuation_line_count"] == 9
    assert truth["business_hours"]["count"] == 197
    assert truth["business_hours"]["ratio"] == pytest.approx(197 / 240)
    assert truth["fixed_scenarios"] == {
        "TOMCAT_STARTUP": 12,
        "DATABASE_POOL_EXHAUSTION": 3,
    }
    assert sum(truth["event_counts"].values()) == 240


def test_database_vocabulary_matches_database_fixture(generator):
    catalina = generator.load_patterns(generator.DEFAULT_PATTERNS)
    database = json.loads(DATABASE_PATTERNS.read_text(encoding="utf-8"))

    assert catalina["database"] == database["database"]
    assert catalina["tables"] == database["tables"]
    assert set(catalina["database_accounts"].values()) == {
        database["accounts"]["application_read_only"][0],
        database["accounts"]["application_read_write"][0],
        database["accounts"]["application_config_change"][0],
    }


def test_multiline_exceptions_are_present(generator, tmp_path):
    args = arguments(generator, tmp_path / "catalina.log")
    patterns = generator.load_patterns(args.patterns)
    lines, _ = generator.build_output(args, patterns)

    assert sum(line.startswith("java.sql.") for line in lines) == 3
    assert sum(line.startswith("\tat ") for line in lines) == 6
    assert sum("DATABASE_POOL_EXHAUSTION" in line for line in lines) == 3


def test_every_database_table_is_observed(generator, tmp_path):
    args = arguments(generator, tmp_path / "catalina.log")
    patterns = generator.load_patterns(args.patterns)
    lines, _ = generator.build_output(args, patterns)
    text = "\n".join(lines)

    assert all(table in text for table in patterns["tables"])
    assert all(account in text for account in patterns["database_accounts"].values())


def test_generation_is_deterministic(generator, tmp_path):
    args = arguments(generator, tmp_path / "catalina.log")
    patterns = generator.load_patterns(args.patterns)
    assert generator.build_output(args, patterns) == generator.build_output(
        args,
        patterns,
    )


def test_checked_fixture_is_an_exact_generator_output(generator, tmp_path):
    args = arguments(generator, tmp_path / "catalina.log")
    patterns = generator.load_patterns(args.patterns)
    lines, truth = generator.build_output(args, patterns)

    assert CHECKED_LOG.read_text(encoding="utf-8") == "\n".join(lines) + "\n"
    assert json.loads(CHECKED_TRUTH.read_text(encoding="utf-8")) == truth


def test_generator_scales_to_thousands_of_records(generator, tmp_path):
    args = arguments(generator, tmp_path / "catalina.log", records=3000)
    patterns = generator.load_patterns(args.patterns)
    _, truth = generator.build_output(args, patterns)

    assert truth["logical_record_count"] == 3000
    assert truth["physical_line_count"] == 3009
