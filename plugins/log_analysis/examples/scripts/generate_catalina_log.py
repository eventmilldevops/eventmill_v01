#!/usr/bin/env python3
"""Generate deterministic Catalina-style logs for YMMV Legacy Invoicing."""

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
DEFAULT_PATTERNS = SCRIPT_DIR / "catalina_log_patterns.json"
DEFAULT_BUSINESS_RATIO = 0.82
MST = timezone(timedelta(hours=-7))
MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


@dataclass(frozen=True)
class Event:
    occurred_at: datetime
    kind: str
    scenario: str | None = None
    step: int | None = None


class DeterministicRandom:
    """Stable xorshift32 generator shared conceptually with the database fixture."""

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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic YMMV Catalina log.",
    )
    parser.add_argument("--start-date", required=True, type=date.fromisoformat)
    parser.add_argument("--end-date", required=True, type=date.fromisoformat)
    parser.add_argument("--records", required=True, type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ground-truth-output", type=Path)
    parser.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS)
    parser.add_argument("--seed", type=int, default=260918)
    parser.add_argument(
        "--business-hours-ratio",
        type=float,
        default=DEFAULT_BUSINESS_RATIO,
        help="Logical-event fraction from 07:00 through 17:59 (default: 0.82).",
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def load_patterns(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "application",
        "service",
        "container",
        "database",
        "hosts",
        "database_accounts",
        "tables",
        "java_operations",
        "event_weights",
    }
    missing = sorted(required - data.keys())
    if missing:
        raise ValueError(f"pattern catalogue is missing: {', '.join(missing)}")
    if len(data["tables"]) != 8:
        raise ValueError("Catalina and database fixtures must share eight tables")
    if sum(data["event_weights"].values()) <= 0:
        raise ValueError("event weights must have a positive sum")
    return data


def validate_args(args: argparse.Namespace) -> None:
    if args.end_date < args.start_date:
        raise ValueError("--end-date must not precede --start-date")
    if args.records < 100:
        raise ValueError("--records must be at least 100 so fixed scenarios fit")
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
        span = rng.choice(((0, 7 * 3600), (18 * 3600, 24 * 3600)))
        seconds = rng.randrange(span[0], span[1])
    return datetime.combine(selected, time(), MST) + timedelta(seconds=seconds)


def scenario_events(days: list[date]) -> list[Event]:
    startup = datetime.combine(days[0], time(6, 42, 10), MST)
    events = [
        Event(
            startup + timedelta(milliseconds=n * 380),
            "STARTUP",
            "TOMCAT_STARTUP",
            n + 1,
        )
        for n in range(12)
    ]
    error_times = (
        datetime.combine(days[0], time(10, 14, 32), MST),
        datetime.combine(days[len(days) // 2], time(14, 48, 9), MST),
        datetime.combine(days[-1], time(19, 22, 51), MST),
    )
    events.extend(
        Event(stamp, "DATABASE_ERROR", "DATABASE_POOL_EXHAUSTION", n + 1)
        for n, stamp in enumerate(error_times)
    )
    return events


def generate_events(args: argparse.Namespace, patterns: dict[str, Any]) -> list[Event]:
    rng = DeterministicRandom(args.seed)
    days = dates_in_range(args.start_date, args.end_date)
    fixed = scenario_events(days)
    business_target = round(args.records * args.business_hours_ratio)
    business_fixed = sum(7 <= event.occurred_at.hour < 18 for event in fixed)
    remaining = args.records - len(fixed)
    business_remaining = business_target - business_fixed
    if not 0 <= business_remaining <= remaining:
        raise ValueError(
            "record volume is too small for the requested time distribution",
        )
    schedule = [True] * business_remaining + [False] * (
        remaining - business_remaining
    )
    rng.shuffle(schedule)
    kinds = list(patterns["event_weights"])
    weights = list(patterns["event_weights"].values())
    events = list(fixed)
    for business in schedule:
        events.append(
            Event(
                random_timestamp(rng, days, business),
                rng.weighted_choice(kinds, weights),
            ),
        )
    return sorted(events, key=lambda event: event.occurred_at)


def juli_timestamp(stamp: datetime) -> str:
    return (
        f"{stamp.day:02d}-{MONTHS[stamp.month - 1]}-{stamp.year} "
        f"{stamp:%H:%M:%S}.{stamp.microsecond // 1000:03d}"
    )


def request_id(rng: DeterministicRandom) -> str:
    return f"req-{rng.next_u32():08x}-{rng.next_u32():08x}"


def startup_line(event: Event, patterns: dict[str, Any]) -> str:
    messages = (
        (
            "INFO",
            "main",
            "org.apache.catalina.startup.VersionLoggerListener.log",
            f"Server version name: {patterns['container']}",
        ),
        (
            "INFO",
            "main",
            "org.apache.catalina.startup.VersionLoggerListener.log",
            "OS Name: Linux",
        ),
        (
            "INFO",
            "main",
            "org.apache.catalina.core.AprLifecycleListener.lifecycleEvent",
            "Loaded Apache Tomcat Native library [1.2.39] using APR version [1.7.0]",
        ),
        (
            "INFO",
            "main",
            "org.apache.coyote.AbstractProtocol.init",
            'Initializing ProtocolHandler ["http-nio-8080"]',
        ),
        (
            "INFO",
            "main",
            "org.apache.catalina.startup.Catalina.load",
            "Server initialization in [842] milliseconds",
        ),
        (
            "INFO",
            "main",
            "org.apache.catalina.core.StandardService.startInternal",
            "Starting service [Catalina]",
        ),
        (
            "INFO",
            "main",
            "org.apache.catalina.core.StandardEngine.startInternal",
            f"Starting Servlet engine: [{patterns['container']}]",
        ),
        (
            "INFO",
            "main",
            "org.apache.catalina.startup.HostConfig.deployWAR",
            "Deploying web application archive [/opt/tomcat/webapps/invoice.war]",
        ),
        (
            "INFO",
            "main",
            "com.zaxxer.hikari.HikariDataSource.getConnection",
            "HikariPool-1 - Starting... database=YMMV_INVOICE dbUser=ymmv_inv_rw",
        ),
        (
            "INFO",
            "main",
            "com.zaxxer.hikari.pool.HikariPool.checkFailFast",
            "HikariPool-1 - Added connection conn-0001 "
            "database=YMMV_INVOICE outcome=SUCCESS",
        ),
        (
            "INFO",
            "main",
            "com.zaxxer.hikari.HikariDataSource.getConnection",
            "HikariPool-1 - Start completed "
            "database=YMMV_INVOICE dbUser=ymmv_inv_rw",
        ),
        (
            "INFO",
            "main",
            "org.apache.catalina.startup.Catalina.start",
            "Server startup in [3918] milliseconds",
        ),
    )
    level, thread, logger, message = messages[event.step - 1]
    return (
        f"{juli_timestamp(event.occurred_at)} {level} [{thread}] "
        f"{logger} {message} scenario={event.scenario} step={event.step}"
    )


def database_error_lines(
    event: Event,
    patterns: dict[str, Any],
    rng: DeterministicRandom,
) -> list[str]:
    thread = f"http-nio-8080-exec-{rng.randrange(1, 21)}"
    req = request_id(rng)
    main = (
        f"{juli_timestamp(event.occurred_at)} SEVERE [{thread}] "
        "com.ymmv.invoice.web.InvoiceController.createInvoice Request failed "
        f"requestId={req} method=POST path=/invoice/api/v1/invoices status=500 "
        "database=YMMV_INVOICE dbUser=ymmv_inv_rw outcome=ERROR "
        f"scenario={event.scenario} step={event.step}"
    )
    return [
        main,
        "java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is "
        "not available, request timed out after 30000ms.",
        "\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException("
        "HikariPool.java:696)",
        "\tat com.ymmv.invoice.persistence.JdbcInvoiceRepository.insertHeader("
        "JdbcInvoiceRepository.java:214)",
    ]


def event_lines(
    event: Event,
    sequence: int,
    patterns: dict[str, Any],
    rng: DeterministicRandom,
) -> list[str]:
    if event.kind == "STARTUP":
        return [startup_line(event, patterns)]
    if event.kind == "DATABASE_ERROR":
        return database_error_lines(event, patterns, rng)

    stamp = juli_timestamp(event.occurred_at)
    thread = f"http-nio-8080-exec-{rng.randrange(1, 21)}"
    req = request_id(rng)
    user = f"user-{rng.randrange(1001, 1099)}"
    host = rng.choice(patterns["hosts"])
    tables = list(patterns["tables"])
    accounts = patterns["database_accounts"]

    if event.kind == "HTTP_REQUEST":
        operation = rng.choice(patterns["java_operations"][:3])
        method = rng.choice(operation["methods"])
        verb = (
            "POST"
            if method in {"createInvoice", "applyPayment", "updateContact"}
            else "GET"
        )
        status = rng.choice((200, 200, 200, 201, 204))
        message = (
            f"{operation['class']}.{method} Completed request requestId={req} "
            f"user={user} method={verb} path=/invoice/api/v1/{method} "
            f"status={status} durationMs={rng.randrange(4, 980)} host={host}"
        )
        level = "INFO"
    elif event.kind == "SERVICE_CALL":
        operation = rng.choice(patterns["java_operations"][3:])
        method = rng.choice(operation["methods"])
        message = (
            f"{operation['class']}.{method} Service operation completed "
            f"requestId={req} user={user} durationMs={rng.randrange(3, 700)} "
            "outcome=SUCCESS"
        )
        level = "INFO"
    elif event.kind in {"DAO_SELECT", "DAO_WRITE"}:
        table = rng.choice(tables)
        read = event.kind == "DAO_SELECT"
        db_user = accounts["read_only"] if read else accounts["read_write"]
        action = "SELECT" if read else rng.choice(("INSERT", "UPDATE", "DELETE"))
        method = "findRecords" if read else "saveRecord"
        rows = rng.randrange(1, 65) if read else rng.randrange(1, 5)
        message = (
            f"com.ymmv.invoice.persistence.JdbcInvoiceRepository.{method} "
            f"{action} completed requestId={req} database={patterns['database']} "
            f"dbUser={db_user} table={table} rows={rows} "
            f"durationMs={rng.randrange(2, 1500)} outcome=SUCCESS"
        )
        level = "DEBUG"
    elif event.kind == "DB_CONNECTION":
        db_user = rng.choice((accounts["read_only"], accounts["read_write"]))
        message = (
            "com.zaxxer.hikari.pool.HikariPool.getConnection HikariPool-1 - "
            f"Connection acquired database={patterns['database']} dbUser={db_user} "
            f"connection=conn-{rng.randrange(1, 33):04d} "
            f"active={rng.randrange(2, 15)} idle={rng.randrange(2, 9)} "
            "outcome=SUCCESS"
        )
        level = "DEBUG"
        thread = f"HikariPool-1 housekeeper"
    elif event.kind == "AUTHENTICATION":
        outcome = rng.choice(("SUCCESS", "SUCCESS", "SUCCESS", "FAILURE"))
        status = 200 if outcome == "SUCCESS" else 401
        message = (
            "com.ymmv.invoice.security.LoginService.authenticate "
            f"Authentication completed requestId={req} user={user} "
            f"remote=192.0.2.{rng.randrange(10, 220)} status={status} "
            f"outcome={outcome}"
        )
        level = "INFO" if outcome == "SUCCESS" else "WARNING"
    elif event.kind == "VALIDATION_WARNING":
        message = (
            "com.ymmv.invoice.web.InvoiceController.createInvoice "
            f"Request validation failed requestId={req} user={user} "
            "field=invoiceDate reason=outsideOpenPeriod status=400 outcome=REJECTED"
        )
        level = "WARNING"
    elif event.kind == "CONFIG_REFRESH":
        message = (
            "com.ymmv.invoice.config.ConfigRefreshJob.reload Configuration refreshed "
            f"database={patterns['database']} dbUser={accounts['config_change']} "
            "table=YMMV.APP_CONFIG keys=27 outcome=SUCCESS"
        )
        level = "INFO"
        thread = "Catalina-utility-1"
    elif event.kind == "BACKGROUND_JOB":
        message = (
            "com.ymmv.invoice.audit.AuditQueuePublisher.publishBatch Batch published "
            f"database={patterns['database']} dbUser={accounts['read_write']} "
            f"table=YMMV.AUDIT_QUEUE rows={rng.randrange(5, 75)} outcome=SUCCESS"
        )
        level = "INFO"
        thread = "invoice-audit-publisher-1"
    else:
        action = rng.choice(("created", "expired", "invalidated"))
        message = (
            "org.apache.catalina.session.ManagerBase.processExpires "
            f"HTTP session {action} session=SS{rng.next_u32():08x} user={user} "
            "outcome=SUCCESS"
        )
        level = "INFO"
        thread = "Catalina-utility-2"

    return [f"{stamp} {level} [{thread}] {message} eventSequence={sequence}"]


def build_output(
    args: argparse.Namespace,
    patterns: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    events = generate_events(args, patterns)
    value_rng = DeterministicRandom(args.seed ^ 0xC471A)
    lines: list[str] = []
    for sequence, event in enumerate(events, 1):
        lines.extend(event_lines(event, sequence, patterns, value_rng))
    business_count = sum(7 <= event.occurred_at.hour < 18 for event in events)
    counts = Counter(event.kind for event in events)
    truth = {
        "schema_version": 1,
        "synthetic": True,
        "application": patterns["application"],
        "service": patterns["service"],
        "container": patterns["container"],
        "seed": args.seed,
        "date_range": {
            "start": args.start_date.isoformat(),
            "end": args.end_date.isoformat(),
        },
        "logical_record_count": len(events),
        "physical_line_count": len(lines),
        "continuation_line_count": len(lines) - len(events),
        "business_hours": {
            "definition": "07:00:00 through 17:59:59 inclusive",
            "count": business_count,
            "ratio": business_count / len(events),
        },
        "database": patterns["database"],
        "database_accounts": patterns["database_accounts"],
        "tables": list(patterns["tables"]),
        "event_counts": dict(sorted(counts.items())),
        "fixed_scenarios": {
            "TOMCAT_STARTUP": sum(
                event.scenario == "TOMCAT_STARTUP" for event in events
            ),
            "DATABASE_POOL_EXHAUSTION": sum(
                event.scenario == "DATABASE_POOL_EXHAUSTION" for event in events
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
        print(f"wrote {len(lines)} lines from {truth['logical_record_count']} records")
        print(f"wrote ground truth to {truth_path}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
