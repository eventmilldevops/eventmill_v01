#!/usr/bin/env python3
"""Generate a long, routine Linux syslog for the YMMV application host."""

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
DEFAULT_PATTERNS = SCRIPT_DIR / "linux_syslog_patterns.json"
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
    parser = argparse.ArgumentParser(description="Generate a synthetic Linux syslog.")
    parser.add_argument("--start-date", required=True, type=date.fromisoformat)
    parser.add_argument("--end-date", required=True, type=date.fromisoformat)
    parser.add_argument("--records", required=True, type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ground-truth-output", type=Path)
    parser.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS)
    parser.add_argument("--seed", type=int, default=260921)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def load_patterns(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "system",
        "host",
        "platform",
        "kernel",
        "services",
        "cron_commands",
        "event_weights",
    }
    missing = sorted(required - data.keys())
    if missing:
        raise ValueError(f"pattern catalogue is missing: {', '.join(missing)}")
    return data


def validate_args(args: argparse.Namespace) -> None:
    if args.end_date < args.start_date:
        raise ValueError("--end-date must not precede --start-date")
    if args.records < 100:
        raise ValueError("--records must be at least 100 so the boot sequence fits")
    if not args.check and args.output is None:
        raise ValueError("--output is required unless --check is used")


def dates_in_range(start: date, end: date) -> list[date]:
    return [start + timedelta(days=n) for n in range((end - start).days + 1)]


def scenario_events(days: list[date]) -> list[Event]:
    boot = datetime.combine(days[0], time(6, 10, 2), MST)
    return [
        Event(
            boot + timedelta(milliseconds=step * 530),
            "OS_STARTUP",
            "OS_STARTUP",
            step + 1,
        )
        for step in range(28)
    ]


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


def syslog_timestamp(stamp: datetime) -> str:
    return f"{MONTHS[stamp.month - 1]} {stamp.day:2d} {stamp:%H:%M:%S}"


def startup_line(event: Event, patterns: dict[str, Any]) -> str:
    messages = (
        (
            "kernel",
            f"Linux version {patterns['kernel']} "
            "(buildd@lcy02-amd64-080) #118-Ubuntu SMP",
        ),
        (
            "kernel",
            "Command line: BOOT_IMAGE=/boot/vmlinuz "
            "root=/dev/mapper/vg0-root ro quiet",
        ),
        (
            "kernel",
            "x86/fpu: Supporting XSAVE feature 0x001: "
            "'x87 floating point registers'",
        ),
        ("kernel", "BIOS-provided physical RAM map:"),
        ("kernel", "Memory: 8012472K/8388608K available"),
        ("kernel", "NET: Registered PF_INET protocol family"),
        ("kernel", "EXT4-fs (dm-0): mounted filesystem with ordered data mode"),
        ("systemd[1]", "systemd 249.11-0ubuntu3.12 running in system mode"),
        ("systemd[1]", "Detected architecture x86-64."),
        ("systemd[1]", "Reached target Local File Systems."),
        ("systemd[1]", "Starting Journal Service..."),
        ("systemd-journald[318]", "Journal started"),
        ("systemd[1]", "Started Journal Service."),
        ("systemd[1]", "Starting Network Name Resolution..."),
        ("systemd[1]", "Started Network Name Resolution."),
        ("systemd-networkd[402]", "eth0: Link UP"),
        ("systemd-networkd[402]", "eth0: Gained carrier"),
        (
            "systemd-timesyncd[388]",
            "Initial synchronization to time server 192.0.2.123:123",
        ),
        ("systemd[1]", "Started Regular background program processing daemon."),
        ("cron[511]", "(CRON) INFO (Running @reboot jobs)"),
        ("systemd[1]", "Starting OpenBSD Secure Shell server..."),
        ("systemd[1]", "Started OpenBSD Secure Shell server."),
        ("systemd[1]", "Starting PostgreSQL RDBMS..."),
        ("systemd[1]", "Started PostgreSQL RDBMS."),
        ("systemd[1]", "Starting Apache Tomcat 9 Web Application Server..."),
        ("systemd[1]", "Started Apache Tomcat 9 Web Application Server."),
        (
            "rsyslogd",
            "imuxsock: Acquired UNIX socket "
            "'/run/systemd/journal/syslog' (fd 3)",
        ),
        (
            "systemd[1]",
            "Startup finished in 4.821s (kernel) + 8.992s (userspace) = 13.813s.",
        ),
    )
    process, message = messages[event.step - 1]
    return (
        f"{syslog_timestamp(event.occurred_at)} {patterns['host']} "
        f"{process}: {message} scenario={event.scenario} step={event.step}"
    )


def event_line(
    event: Event,
    sequence: int,
    patterns: dict[str, Any],
    rng: DeterministicRandom,
) -> str:
    if event.kind == "OS_STARTUP":
        return startup_line(event, patterns)
    stamp = syslog_timestamp(event.occurred_at)
    host = patterns["host"]
    pid = rng.randrange(600, 32000)
    if event.kind == "CRON_COMMAND":
        message = f"CRON[{pid}]: (root) CMD ({rng.choice(patterns['cron_commands'])})"
    elif event.kind == "SYSTEMD_SESSION":
        message = (
            f"systemd[1]: Started Session {rng.randrange(100, 9000)} "
            "of User root."
        )
    elif event.kind == "SYSTEMD_STATUS":
        service = rng.choice(patterns["services"])
        state = rng.choice(("Started", "Finished", "Reached target"))
        message = f"systemd[1]: {state} {service}."
    elif event.kind == "TIMESYNC":
        offset = rng.randrange(-18, 19)
        message = (
            "systemd-timesyncd[388]: Contacted time server 192.0.2.123:123 "
            f"(ntp.ymmv.example); offset {offset}ms"
        )
    elif event.kind == "RSYSLOG_STATUS":
        message = (
            "rsyslogd: action 'action-0-builtin:omfile' resumed "
            "(module 'builtin:omfile') [v8.2112.0]"
        )
    elif event.kind == "KERNEL_INFO":
        message = rng.choice(
            (
                f"kernel: [{rng.randrange(1000, 260000)}.124821] "
                "EXT4-fs (dm-0): re-mounted. Opts: errors=remount-ro",
                f"kernel: [{rng.randrange(1000, 260000)}.663008] "
                "e1000: eth0 NIC Link is Up 1000 Mbps Full Duplex",
                f"kernel: [{rng.randrange(1000, 260000)}.220117] "
                "audit: backlog limit 8192",
            ),
        )
    elif event.kind == "NETWORK_STATUS":
        message = rng.choice(
            (
                "systemd-networkd[402]: eth0: Gained IPv6LL",
                "systemd-networkd[402]: eth0: DHCPv4 address "
                "192.0.2.40/24 via 192.0.2.1",
                "networkd-dispatcher[704]: WARNING:Unknown index 3 seen, "
                "reloading interface list",
            ),
        )
    elif event.kind == "LOGROTATE":
        target = rng.choice(
            (
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/tomcat9/catalina.out",
            ),
        )
        message = f"logrotate[{pid}]: rotated {target}"
    elif event.kind == "TOMCAT_SERVICE":
        rng.randrange(300, 1800)
        message = "systemd[1]: tomcat9.service: Runtime health sample; state=active"
    elif event.kind == "DATABASE_SERVICE":
        message = rng.choice(
            (
                "systemd[1]: postgresql.service: Succeeded.",
                "postgresql@14-main[812]: "
                "database system is ready to accept connections",
                "postgresql@14-main[812]: checkpoint complete: wrote 37 buffers",
            ),
        )
    elif event.kind == "DISK_STATUS":
        used = rng.randrange(41, 58)
        message = f"ymmv-disk-check[{pid}]: filesystem=/ usage={used}% status=OK"
    else:
        message = (
            f"unattended-upgrade[{pid}]: Packages that will be upgraded: "
            f"{rng.choice(('libssl3', 'tzdata', 'ca-certificates', 'curl'))}"
        )
    return f"{stamp} {host} {message} eventSequence={sequence}"


def build_output(
    args: argparse.Namespace,
    patterns: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    events = generate_events(args, patterns)
    value_rng = DeterministicRandom(args.seed ^ 0x5A5106)
    lines = [
        event_line(event, sequence, patterns, value_rng)
        for sequence, event in enumerate(events, 1)
    ]
    counts = Counter(event.kind for event in events)
    truth = {
        "schema_version": 1,
        "synthetic": True,
        "system": patterns["system"],
        "host": patterns["host"],
        "platform": patterns["platform"],
        "kernel": patterns["kernel"],
        "seed": args.seed,
        "date_range": {
            "start": args.start_date.isoformat(),
            "end": args.end_date.isoformat(),
        },
        "record_count": len(lines),
        "event_counts": dict(sorted(counts.items())),
        "interactive_user_events": 0,
        "fixed_scenarios": {
            "OS_STARTUP": len(
                scenario_events(dates_in_range(args.start_date, args.end_date)),
            ),
        },
        "investigative_scope_note": (
            "Routine host operations only. Application requests and database "
            "transactions require the companion Catalina and database logs."
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
        print(f"wrote {len(lines)} records to {args.output}")
        print(f"wrote ground truth to {truth_path}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
