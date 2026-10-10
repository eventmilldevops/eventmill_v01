#!/usr/bin/env python3
"""Generate a mostly non-interactive Linux auth.log for the YMMV host."""

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
DEFAULT_PATTERNS = SCRIPT_DIR / "linux_auth_patterns.json"
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
    account: str | None = None
    remote: str | None = None
    scenario: str | None = None
    step: int | None = None


class DeterministicRandom:
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a synthetic auth.log.")
    parser.add_argument("--start-date", required=True, type=date.fromisoformat)
    parser.add_argument("--end-date", required=True, type=date.fromisoformat)
    parser.add_argument("--records", required=True, type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ground-truth-output", type=Path)
    parser.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS)
    parser.add_argument("--seed", type=int, default=260922)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def load_patterns(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "system",
        "host",
        "interactive_accounts",
        "service_accounts",
        "reserved_remote_addresses",
        "sudo_commands",
        "event_weights",
    }
    missing = sorted(required - data.keys())
    if missing:
        raise ValueError(f"pattern catalogue is missing: {', '.join(missing)}")
    return data


def validate_args(args: argparse.Namespace) -> None:
    if args.end_date < args.start_date:
        raise ValueError("--end-date must not precede --start-date")
    if args.records < 50:
        raise ValueError("--records must be at least 50 so fixed scenarios fit")
    if not args.check and args.output is None:
        raise ValueError("--output is required unless --check is used")


def dates_in_range(start: date, end: date) -> list[date]:
    return [start + timedelta(days=n) for n in range((end - start).days + 1)]


def scenario_events(days: list[date]) -> list[Event]:
    middle = days[len(days) // 2]
    successes = (
        (days[0], time(8, 10, 14), "ops_lee", "192.0.2.18"),
        (days[0], time(16, 42, 3), "app_admin", "192.0.2.44"),
        (middle, time(9, 5, 39), "dba_singh", "192.0.2.73"),
        (middle, time(15, 32, 51), "ops_lee", "192.0.2.18"),
        (days[-1], time(11, 18, 7), "app_admin", "192.0.2.44"),
    )
    events = [
        Event(
            datetime.combine(day, at, MST),
            "INTERACTIVE_SUCCESS",
            account,
            remote,
            "INTERACTIVE_LOGIN_SUCCESS",
            step + 1,
        )
        for step, (day, at, account, remote) in enumerate(successes)
    ]
    failures = (
        (days[0], time(22, 16, 44), "deploy", "198.51.100.22"),
        (days[-1], time(5, 51, 18), "app_admin", "198.51.100.57"),
    )
    events.extend(
        Event(
            datetime.combine(day, at, MST),
            "INTERACTIVE_FAILURE",
            account,
            remote,
            "INTERACTIVE_LOGIN_FAILURE",
            step + 1,
        )
        for step, (day, at, account, remote) in enumerate(failures)
    )
    return events


def generate_events(args: argparse.Namespace, patterns: dict[str, Any]) -> list[Event]:
    rng = DeterministicRandom(args.seed)
    days = dates_in_range(args.start_date, args.end_date)
    events = scenario_events(days)
    kinds = list(patterns["event_weights"])
    weights = list(patterns["event_weights"].values())
    for _ in range(args.records - len(events)):
        selected = rng.choice(days)
        seconds = rng.randrange(0, 24 * 3600)
        stamp = datetime.combine(selected, time(), MST) + timedelta(seconds=seconds)
        events.append(Event(stamp, rng.weighted_choice(kinds, weights)))
    return sorted(events, key=lambda event: event.occurred_at)


def auth_timestamp(stamp: datetime) -> str:
    return f"{MONTHS[stamp.month - 1]} {stamp.day:2d} {stamp:%H:%M:%S}"


def event_lines(
    event: Event,
    patterns: dict[str, Any],
    rng: DeterministicRandom,
) -> list[str]:
    stamp = auth_timestamp(event.occurred_at)
    host = patterns["host"]
    pid = rng.randrange(700, 32000)
    prefix = f"{stamp} {host}"
    if event.kind == "INTERACTIVE_SUCCESS":
        port = rng.randrange(42000, 62000)
        session = rng.randrange(200, 9000)
        return [
            f"{prefix} sshd[{pid}]: Accepted publickey for {event.account} "
            f"from {event.remote} port {port} ssh2 scenario={event.scenario} "
            f"step={event.step}",
            f"{prefix} sshd[{pid}]: pam_unix(sshd:session): session opened "
            f"for user {event.account}(uid=1001) by (uid=0)",
            f"{prefix} systemd-logind[{rng.randrange(500, 900)}]: "
            f"New session {session} of user {event.account}.",
            f"{prefix} sshd[{pid}]: Disconnected from user {event.account} "
            f"{event.remote} port {port}",
        ]
    if event.kind == "INTERACTIVE_FAILURE":
        invalid = "invalid user " if event.account == "deploy" else ""
        return [
            f"{prefix} sshd[{pid}]: Failed publickey for "
            f"{invalid}{event.account} from {event.remote} "
            f"port {rng.randrange(42000, 62000)} ssh2 "
            f"scenario={event.scenario} step={event.step}",
        ]
    if event.kind == "CRON_SESSION":
        user = rng.choice(("root", "root", "root", "tomcat", "postgres"))
        return [
            f"{prefix} CRON[{pid}]: pam_unix(cron:session): session opened "
            f"for user {user}(uid=0) by (uid=0)",
            f"{prefix} CRON[{pid}]: pam_unix(cron:session): "
            f"session closed for user {user}",
        ]
    if event.kind == "SYSTEM_ACCOUNT_SESSION":
        user = rng.choice(patterns["service_accounts"])
        return [
            f"{prefix} systemd[{pid}]: pam_unix(systemd-user:session): "
            f"session opened for user {user}(uid={rng.randrange(0, 999)}) "
            "by (uid=0)",
            f"{prefix} systemd[{pid}]: pam_unix(systemd-user:session): "
            f"session closed for user {user}",
        ]
    if event.kind == "SUDO_COMMAND":
        user = rng.choice(patterns["interactive_accounts"])
        command = rng.choice(patterns["sudo_commands"])
        return [
            f"{prefix} sudo: {user} : TTY=pts/{rng.randrange(0, 4)} ; "
            f"PWD=/home/{user} ; USER=root ; COMMAND={command}",
            f"{prefix} sudo: pam_unix(sudo:session): session closed for user root",
        ]
    if event.kind == "SU_SESSION":
        user = rng.choice(patterns["interactive_accounts"])
        return [
            f"{prefix} su: pam_unix(su:session): session opened "
            f"for user root by {user}(uid=1001)",
            f"{prefix} su: pam_unix(su:session): session closed for user root",
        ]
    if event.kind == "POLKIT_CHECK":
        return [
            f"{prefix} polkitd(authority=local): Registered Authentication "
            f"Agent for unix-process:{pid}:{rng.randrange(1000, 9999)}",
        ]
    if event.kind == "SSHD_MONITOR":
        return [
            f"{prefix} sshd[{pid}]: Server listening on 0.0.0.0 port 22.",
        ]
    return [
        f"{prefix} sssd_nss[{pid}]: Enumeration requested for "
        "cached local service accounts",
    ]


def build_output(
    args: argparse.Namespace,
    patterns: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    events = generate_events(args, patterns)
    value_rng = DeterministicRandom(args.seed ^ 0xA01710)
    lines: list[str] = []
    for event in events:
        lines.extend(event_lines(event, patterns, value_rng))
    counts = Counter(event.kind for event in events)
    successes = counts["INTERACTIVE_SUCCESS"]
    failures = counts["INTERACTIVE_FAILURE"]
    truth = {
        "schema_version": 1,
        "synthetic": True,
        "system": patterns["system"],
        "host": patterns["host"],
        "seed": args.seed,
        "date_range": {
            "start": args.start_date.isoformat(),
            "end": args.end_date.isoformat(),
        },
        "logical_record_count": len(events),
        "physical_line_count": len(lines),
        "event_counts": dict(sorted(counts.items())),
        "interactive_activity": {
            "successful_sessions": successes,
            "failed_attempts": failures,
            "total_attempts": successes + failures,
        },
        "fixed_scenarios": {
            "INTERACTIVE_LOGIN_SUCCESS": successes,
            "INTERACTIVE_LOGIN_FAILURE": failures,
        },
        "investigative_scope_note": (
            "Authentication and privilege-use context only. Application actions "
            "and database transactions require the companion logs."
        ),
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
