#!/usr/bin/env python3
"""Generate deterministic synthetic audit logs for YMMV Legacy Invoicing.

The compact pattern catalogue is the creative input. Expanding it into hundreds
or millions of records is deterministic and makes no LLM calls. A low-cost
model may be used outside this script to propose another reviewed catalogue.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PATTERNS = SCRIPT_DIR / "database_audit_patterns.json"
DEFAULT_BUSINESS_RATIO = 0.83
MST = timezone(timedelta(hours=-7))


@dataclass(frozen=True)
class Event:
    occurred_at: datetime
    kind: str
    actor: str
    client: str
    table: str | None = None
    scenario: str | None = None
    step: int | None = None


class DeterministicRandom:
    """Small, stable PRNG so fixtures do not change with a Python upgrade."""

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF or 0x6D2B79F5

    def next_u32(self) -> int:
        value = self.state
        value ^= (value << 13) & 0xFFFFFFFF
        value ^= value >> 17
        value ^= (value << 5) & 0xFFFFFFFF
        self.state = value & 0xFFFFFFFF
        return self.state

    def randrange(self, start: int, stop: int | None = None) -> int:
        if stop is None:
            start, stop = 0, start
        if stop <= start:
            raise ValueError("empty range")
        return start + self.next_u32() % (stop - start)

    def choice(self, values: list[Any] | tuple[Any, ...]) -> Any:
        return values[self.randrange(len(values))]

    def weighted_choice(self, values: list[str], weights: list[int]) -> str:
        point = self.randrange(sum(weights))
        cumulative = 0
        for value, weight in zip(values, weights):
            cumulative += weight
            if point < cumulative:
                return value
        raise AssertionError("weighted choice did not select a value")

    def shuffle(self, values: list[Any]) -> None:
        for index in range(len(values) - 1, 0, -1):
            swap = self.randrange(index + 1)
            values[index], values[swap] = values[swap], values[index]

    def sample(self, values: list[str], count: int) -> list[str]:
        copied = list(values)
        self.shuffle(copied)
        return copied[:count]

    def getrandbits(self, bits: int) -> int:
        if bits != 32:
            raise ValueError("this fixture PRNG exposes only 32-bit values")
        return self.next_u32()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic YMMV database audit log.",
    )
    parser.add_argument("--start-date", required=True, type=date.fromisoformat)
    parser.add_argument("--end-date", required=True, type=date.fromisoformat)
    parser.add_argument("--records", required=True, type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ground-truth-output", type=Path)
    parser.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS)
    parser.add_argument("--seed", type=int, default=260915)
    parser.add_argument(
        "--business-hours-ratio",
        type=float,
        default=DEFAULT_BUSINESS_RATIO,
        help="Fraction from 07:00 through 17:59 (default: 0.83).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate inputs and print planned counts without writing files.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing output files.",
    )
    return parser.parse_args(argv)


def load_patterns(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "application",
        "database",
        "tables",
        "accounts",
        "clients",
        "event_weights",
    }
    missing = sorted(required - data.keys())
    if missing:
        raise ValueError(f"pattern catalogue is missing: {', '.join(missing)}")
    if len(data["tables"]) < 6 or len(data["tables"]) > 8:
        raise ValueError("database fixture must define 6 to 8 tables")
    if sum(data["event_weights"].values()) <= 0:
        raise ValueError("event weights must have a positive sum")
    return data


def validate_args(args: argparse.Namespace) -> None:
    if args.end_date < args.start_date:
        raise ValueError("--end-date must not precede --start-date")
    if args.records < 12:
        raise ValueError("--records must be at least 12 so fixed scenarios fit")
    if not 0.80 <= args.business_hours_ratio <= 0.85:
        raise ValueError("--business-hours-ratio must be between 0.80 and 0.85")
    if not args.check and args.output is None:
        raise ValueError("--output is required unless --check is used")


def dates_in_range(start: date, end: date) -> list[date]:
    return [start + timedelta(days=n) for n in range((end - start).days + 1)]


def random_timestamp(
    rng: DeterministicRandom,
    days: list[date],
    business: bool,
) -> datetime:
    selected = rng.choice(days)
    if business:
        seconds = rng.randrange(7 * 3600, 18 * 3600)
    else:
        ranges = ((0, 7 * 3600), (18 * 3600, 24 * 3600))
        start, stop = rng.choice(ranges)
        seconds = rng.randrange(start, stop)
    return datetime.combine(selected, time(), MST) + timedelta(seconds=seconds)


def scenario_events(days: list[date]) -> list[Event]:
    export_day = days[len(days) // 2]
    backup_day = days[0]
    export_base = datetime.combine(export_day, time(20, 37, 11), MST)
    backup_base = datetime.combine(backup_day, time(2, 5, 2), MST)
    return [
        Event(
            backup_base,
            "BACKUP_START",
            "svc_db_backup",
            "backup01.ymmv.example",
            scenario="NIGHTLY_BACKUP",
            step=1,
        ),
        Event(
            backup_base + timedelta(minutes=23, seconds=41),
            "BACKUP_COMPLETE",
            "svc_db_backup",
            "backup01.ymmv.example",
            scenario="NIGHTLY_BACKUP",
            step=2,
        ),
        Event(
            export_base,
            "CONNECT",
            "dba_morgan",
            "dba-jump02.ymmv.example",
            scenario="MANUAL_CUSTOMER_EXPORT",
            step=1,
        ),
        Event(
            export_base + timedelta(seconds=8),
            "SPOOL_OPEN",
            "dba_morgan",
            "dba-jump02.ymmv.example",
            scenario="MANUAL_CUSTOMER_EXPORT",
            step=2,
        ),
        Event(
            export_base + timedelta(seconds=13),
            "SELECT",
            "dba_morgan",
            "dba-jump02.ymmv.example",
            "YMMV.CUSTOMER",
            "MANUAL_CUSTOMER_EXPORT",
            3,
        ),
        Event(
            export_base + timedelta(seconds=26),
            "SPOOL_CLOSE",
            "dba_morgan",
            "dba-jump02.ymmv.example",
            scenario="MANUAL_CUSTOMER_EXPORT",
            step=4,
        ),
        Event(
            export_base + timedelta(seconds=31),
            "DISCONNECT",
            "dba_morgan",
            "dba-jump02.ymmv.example",
            scenario="MANUAL_CUSTOMER_EXPORT",
            step=5,
        ),
    ]


def choose_actor_client(
    kind: str,
    patterns: dict[str, Any],
    rng: DeterministicRandom,
) -> tuple[str, str]:
    accounts = patterns["accounts"]
    clients = patterns["clients"]
    if kind == "SELECT":
        role = rng.weighted_choice(
            [
                "application_read_only",
                "application_read_write",
                "database_administrator",
            ],
            [52, 42, 6],
        )
        client_group = "reporting" if role == "application_read_only" else "application"
        if role == "database_administrator":
            client_group = "administration"
    elif kind in {"INSERT", "UPDATE", "DELETE", "COMMIT", "ROLLBACK"}:
        role, client_group = "application_read_write", "application"
    elif kind == "CONFIG_CHANGE":
        role, client_group = "application_config_change", "application"
    elif kind in {"DDL", "MAINTENANCE"}:
        role, client_group = "database_administrator", "administration"
    elif kind == "BACKUP":
        role, client_group = "backup_agent", "backup"
    elif kind == "ACCESS_DENIED":
        role, client_group = "application_read_only", "application"
    else:
        role = rng.choice(["application_read_only", "application_read_write"])
        client_group = "reporting" if role == "application_read_only" else "application"
    return rng.choice(accounts[role]), rng.choice(clients[client_group])


def generate_events(args: argparse.Namespace, patterns: dict[str, Any]) -> list[Event]:
    rng = DeterministicRandom(args.seed)
    days = dates_in_range(args.start_date, args.end_date)
    fixed = scenario_events(days)
    business_target = round(args.records * args.business_hours_ratio)
    business_fixed = sum(7 <= event.occurred_at.hour < 18 for event in fixed)
    business_remaining = business_target - business_fixed
    remaining = args.records - len(fixed)
    if not 0 <= business_remaining <= remaining:
        raise ValueError(
            "record volume is too small for the requested time distribution",
        )

    schedule = [True] * business_remaining + [False] * (remaining - business_remaining)
    rng.shuffle(schedule)
    kinds = list(patterns["event_weights"])
    weights = list(patterns["event_weights"].values())
    tables = list(patterns["tables"])
    events = list(fixed)
    for business in schedule:
        kind = rng.weighted_choice(kinds, weights)
        actor, client = choose_actor_client(kind, patterns, rng)
        table = (
            rng.choice(tables)
            if kind in {"SELECT", "INSERT", "UPDATE", "DELETE", "ACCESS_DENIED"}
            else None
        )
        if kind == "CONFIG_CHANGE":
            table = "YMMV.APP_CONFIG"
        events.append(
            Event(random_timestamp(rng, days, business), kind, actor, client, table),
        )
    return sorted(events, key=lambda event: event.occurred_at)


def event_line(
    event: Event,
    sequence: int,
    patterns: dict[str, Any],
    rng: DeterministicRandom,
) -> str:
    timestamp = event.occurred_at.isoformat(timespec="milliseconds")
    session = f"S{rng.randrange(100000, 999999)}"
    transaction = f"TX{sequence:06d}"
    database = patterns["database"]
    if event.kind in {"BACKUP_START", "BACKUP_COMPLETE"}:
        outcome = "STARTED" if event.kind == "BACKUP_START" else "SUCCESS"
        detail = "type=FULL target=backup-set-{:04d}".format(
            event.occurred_at.timetuple().tm_yday,
        )
        scenario = (
            f" scenario={event.scenario} step={event.step}"
            if event.scenario
            else ""
        )
        return (
            f"YDBBACKUP account={event.actor} host={event.client} "
            f"database={database} action={event.kind} outcome={outcome} "
            f"{detail}{scenario} event_time={timestamp}"
        )
    if event.kind in {"SPOOL_OPEN", "SPOOL_CLOSE"}:
        outcome = "OPENED" if event.kind == "SPOOL_OPEN" else "SUCCESS"
        size = "" if event.kind == "SPOOL_OPEN" else " bytes=684291 rows=4872"
        export_date = event.occurred_at.strftime("%Y%m%d")
        return (
            f"DBAUDIT event={event.kind} actor={event.actor} client={event.client} "
            f"session={session} file=/var/tmp/customer_export_{export_date}.csv{size} "
            f"outcome={outcome} scenario={event.scenario} step={event.step} "
            f"event_time={timestamp}"
        )
    if event.kind in {"CONNECT", "DISCONNECT"}:
        program = (
            "dbadmin-cli"
            if event.actor.startswith("dba_")
            else "legacy-invoice-jdbc"
        )
        return (
            f"{timestamp} AUDIT AUTH database={database} session={session} "
            f"account={event.actor} client={event.client} program={program} "
            f"action={event.kind} outcome=SUCCESS "
            f"scenario={event.scenario or '-'} step={event.step or '-'}"
        )
    if event.kind == "SELECT" and event.scenario == "MANUAL_CUSTOMER_EXPORT":
        columns = ",".join(patterns["tables"][event.table])
        return (
            f"YDBTX tx={transaction} db={database} actor={event.actor} "
            f"src={event.client} app=dbadmin-cli action=SELECT object={event.table} "
            f"columns=[{columns}] rows=4872 outcome=SUCCESS sqlcode=0 "
            f"duration_ms=12891 scenario={event.scenario} step={event.step} "
            f"event_time={timestamp}"
        )
    if event.kind in {"SELECT", "INSERT", "UPDATE", "DELETE", "ACCESS_DENIED"}:
        action = "UPDATE" if event.kind == "ACCESS_DENIED" else event.kind
        outcome = "DENIED" if event.kind == "ACCESS_DENIED" else "SUCCESS"
        sqlcode = -551 if outcome == "DENIED" else 0
        rows = rng.randrange(1, 85) if action == "SELECT" else rng.randrange(1, 5)
        source_columns = patterns["tables"][event.table]
        columns = ",".join(rng.sample(source_columns, min(3, len(source_columns))))
        return (
            f"YDBTX tx={transaction} db={database} actor={event.actor} "
            f"src={event.client} app=legacy-invoice-jdbc action={action} "
            f"object={event.table} columns=[{columns}] rows={rows} "
            f"outcome={outcome} sqlcode={sqlcode} "
            f"duration_ms={rng.randrange(2, 1900)} event_time={timestamp}"
        )
    if event.kind in {"COMMIT", "ROLLBACK"}:
        return (
            f"YDBTX tx={transaction} db={database} actor={event.actor} "
            f"src={event.client} app=legacy-invoice-jdbc action={event.kind} "
            f"changes={rng.randrange(1, 12)} outcome=SUCCESS sqlcode=0 "
            f"duration_ms={rng.randrange(1, 90)} event_time={timestamp}"
        )
    if event.kind == "CONFIG_CHANGE":
        key = rng.choice(
            ["invoice.approval.limit", "tax.rounding.mode", "payment.retry.count"],
        )
        return (
            f"YDB-AUDIT|event_time={timestamp}|category=CONFIG|actor={event.actor}"
            f"|client={event.client}|action=UPDATE|object=YMMV.APP_CONFIG|key={key}"
            f"|old_hash={rng.getrandbits(32):08x}"
            f"|new_hash={rng.getrandbits(32):08x}|outcome=SUCCESS"
        )
    if event.kind == "DDL":
        table = rng.choice(list(patterns["tables"]))
        return (
            f"YDB-AUDIT|event_time={timestamp}|category=DDL|actor={event.actor}"
            f"|client={event.client}|action=ALTER_INDEX|object={table}"
            "|change=REBUILD|outcome=SUCCESS"
        )
    if event.kind == "MAINTENANCE":
        table = rng.choice(list(patterns["tables"]))
        return (
            f"YDB-AUDIT|event_time={timestamp}|category=MAINTENANCE"
            f"|actor={event.actor}|client={event.client}|action=ANALYZE"
            f"|object={table}|rows_examined={rng.randrange(500, 9000)}"
            "|outcome=SUCCESS"
        )
    if event.kind == "BACKUP":
        return (
            f"YDBBACKUP account={event.actor} host={event.client} "
            f"database={database} action=BACKUP_VERIFY outcome=SUCCESS "
            f"checksum=VALID event_time={timestamp}"
        )
    raise ValueError(f"unsupported event kind: {event.kind}")


def build_output(
    args: argparse.Namespace,
    patterns: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    events = generate_events(args, patterns)
    value_rng = DeterministicRandom(args.seed ^ 0x5A17)
    lines = [
        event_line(event, n, patterns, value_rng)
        for n, event in enumerate(events, 1)
    ]
    business_count = sum(7 <= event.occurred_at.hour < 18 for event in events)
    event_counts = Counter(event.kind for event in events)
    actor_counts = Counter(event.actor for event in events)
    truth = {
        "schema_version": 1,
        "synthetic": True,
        "application": patterns["application"],
        "database": patterns["database"],
        "seed": args.seed,
        "date_range": {
            "start": args.start_date.isoformat(),
            "end": args.end_date.isoformat(),
        },
        "record_count": len(lines),
        "business_hours": {
            "definition": "07:00:00 through 17:59:59 inclusive",
            "count": business_count,
            "ratio": business_count / len(lines),
        },
        "tables": list(patterns["tables"]),
        "accounts": patterns["accounts"],
        "event_counts": dict(sorted(event_counts.items())),
        "actor_counts": dict(sorted(actor_counts.items())),
        "fixed_scenarios": {
            "MANUAL_CUSTOMER_EXPORT": sum(
                event.scenario == "MANUAL_CUSTOMER_EXPORT" for event in events
            ),
            "NIGHTLY_BACKUP": sum(
                event.scenario == "NIGHTLY_BACKUP" for event in events
            ),
        },
        "line_sha256": hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest(),
    }
    return lines, truth


def write_new(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to replace {path}; pass --force")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        validate_args(args)
        patterns = load_patterns(args.patterns)
        lines, truth = build_output(args, patterns)
        if args.check:
            print(json.dumps(truth, indent=2))
            return 0
        truth_path = args.ground_truth_output or args.output.with_suffix(
            ".ground_truth.json",
        )
        write_new(args.output, "\n".join(lines) + "\n", args.force)
        try:
            write_new(truth_path, json.dumps(truth, indent=2) + "\n", args.force)
        except Exception:
            args.output.unlink(missing_ok=True)
            raise
        print(f"wrote {len(lines)} records to {args.output}")
        print(f"wrote ground truth to {truth_path}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
