"""Does the value in a captured group look like what it was claimed to be?

A model says "group ``ts`` is the timestamp". These checks test that claim
against every value the group captured across the file. They describe values;
they do not judge whether the application logged the right thing.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

PLACEHOLDERS = {
    "",
    "-",
    "--",
    "null",
    "none",
    "nil",
    "n/a",
    "na",
    "(null)",
    "undefined",
    "?",
}
VALUE_TYPES = (
    "timestamp",
    "category",
    "identity",
    "address",
    "identifier",
    "integer",
    "text",
)
PRECISION_DIGITS = {"second": 0, "millisecond": 3, "microsecond": 6}

# Tried in order when the claimed format does not parse a value, so feedback
# can say "it is not what you claimed, it looks like this instead".
KNOWN_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S %z",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%b %d %Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%d-%b-%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d.%m.%Y %H:%M:%S",
    "%Y%m%d%H%M%S",
    "%Y%m%dT%H%M%SZ",
)
SPECIAL_FORMATS = ("iso8601", "epoch_s", "epoch_ms", "epoch_us")

_FRACTION = re.compile(r"[.,](\d+)")
_LONG_FRACTION = re.compile(r"([.,]\d{6})\d+")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_\-]{0,62})(\.[A-Za-z0-9_]([A-Za-z0-9_\-]{0,62}))*\.?$"
)
_EARLIEST = datetime(1990, 1, 1, tzinfo=timezone.utc)


def _fraction_digits(value: str) -> int:
    match = _FRACTION.search(value)
    return len(match.group(1)) if match else 0


def parse_timestamp(value: str, fmt: str | None) -> dict[str, Any] | None:
    """Parse one value with one format. None when it does not parse.

    Returns the moment, whether the value carried a zone, how many fractional
    digits it had, and whether the year had to be assumed.
    """
    value = value.strip().strip("[]")
    if not value or not fmt:
        return None
    try:
        if fmt in ("epoch_s", "epoch_ms", "epoch_us"):
            number = float(value)
            divisor = {"epoch_s": 1, "epoch_ms": 1_000, "epoch_us": 1_000_000}[fmt]
            moment = datetime.fromtimestamp(number / divisor, tz=timezone.utc)
            digits = {"epoch_s": 0, "epoch_ms": 3, "epoch_us": 6}[fmt]
            if fmt == "epoch_s" and "." in value:
                digits = len(value.split(".", 1)[1])
            return {
                "moment": moment,
                "has_tz": True,
                "digits": digits,
                "year_assumed": False,
            }
        trimmed = _LONG_FRACTION.sub(r"\1", value)
        if fmt == "iso8601":
            moment = datetime.fromisoformat(trimmed.replace(",", "."))
        else:
            moment = datetime.strptime(trimmed, fmt)
    except (ValueError, OverflowError, OSError):
        return None
    year_assumed = fmt not in SPECIAL_FORMATS and "%Y" not in fmt and "%y" not in fmt
    return {
        "moment": moment,
        "has_tz": moment.tzinfo is not None,
        "digits": _fraction_digits(value),
        "year_assumed": year_assumed,
    }


def guess_format(values: list[str]) -> str | None:
    """A format that parses every one of a handful of values, if any does."""
    values = [v for v in values if v.strip()]
    if not values:
        return None
    for fmt in ("iso8601", *KNOWN_FORMATS):
        if all(parse_timestamp(v, fmt) for v in values):
            return fmt
    if all(re.fullmatch(r"\d{10}(\.\d+)?", v.strip()) for v in values):
        return "epoch_s"
    if all(re.fullmatch(r"\d{13}", v.strip()) for v in values):
        return "epoch_ms"
    return None


def _plausible(moment: datetime, year_assumed: bool, now: datetime) -> bool:
    if year_assumed:
        return True
    aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return _EARLIEST <= aware <= now + timedelta(days=2)


def is_address(value: str) -> tuple[bool, bool]:
    """``(valid, is_ip)``. A hostname is a valid address; an ``ip:port`` is not."""
    candidate = value.strip().strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True, True
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", candidate):
        return False, False
    return bool(_HOSTNAME.match(candidate)), False


class FieldStats:
    """Accumulates what one captured group held across every matching record."""

    MAX_DISTINCT = 5000

    def __init__(self, value_type: str, fmt: str | None = None) -> None:
        self.value_type = value_type if value_type in VALUE_TYPES else "text"
        self.format = fmt
        self.records = 0
        self.filled = 0
        self.valid = 0
        self.chars = 0
        self.values: Counter[str] = Counter()
        self.distinct_capped = False
        self.failures: list[str] = []
        self.tz_count = 0
        self.year_assumed = 0
        self.implausible = 0
        self.digits: Counter[int] = Counter()
        self.ip_count = 0
        self.out_of_order = 0
        self._previous: datetime | None = None
        self._now = datetime.now(timezone.utc)

    def _fail(self, value: str) -> None:
        if len(self.failures) < 5 and value[:120] not in self.failures:
            self.failures.append(value[:120])

    def add(self, value: Any) -> tuple[bool, bool, int] | None:
        """Count one captured value and say what it was.

        Returns None for an empty or placeholder value, otherwise
        ``(valid, has_timezone, fraction_digits)``; the last two are only ever
        set for a valid timestamp.
        """
        self.records += 1
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        stripped = value.strip()
        if stripped.lower() in PLACEHOLDERS:
            return None
        self.filled += 1
        self.chars += len(stripped)
        key = stripped[:200]
        if len(self.values) < self.MAX_DISTINCT or key in self.values:
            self.values[key] += 1
        else:
            self.distinct_capped = True

        kind = self.value_type
        if kind == "timestamp":
            parsed = parse_timestamp(stripped, self.format)
            if parsed is None:
                self._fail(stripped)
                return (False, False, 0)
            if not _plausible(parsed["moment"], parsed["year_assumed"], self._now):
                self.implausible += 1
                self._fail(stripped)
                return (False, False, 0)
            self.valid += 1
            self.tz_count += 1 if parsed["has_tz"] else 0
            self.year_assumed += 1 if parsed["year_assumed"] else 0
            self.digits[min(parsed["digits"], 9)] += 1
            moment = parsed["moment"]
            comparable = (
                moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
            )
            if self._previous is not None and comparable < self._previous:
                self.out_of_order += 1
            self._previous = comparable
            return (True, bool(parsed["has_tz"]), min(parsed["digits"], 9))
        if kind == "address":
            ok, is_ip = is_address(stripped)
            self.ip_count += 1 if ok and is_ip else 0
        elif kind == "integer":
            ok = bool(re.fullmatch(r"[+-]?\d+", stripped))
        elif kind == "identifier":
            ok = not re.search(r"\s", stripped)
        elif kind == "category":
            ok = len(stripped) <= 64
        else:
            ok = True
        if ok:
            self.valid += 1
        else:
            self._fail(stripped)
        return (ok, False, 0)

    def flags(self) -> list[str]:
        """Observations about the value set. Questions for a reader, not failures."""
        flags: list[str] = []
        distinct = len(self.values)
        if self.value_type == "category" and self.filled >= 50:
            if self.distinct_capped or distinct > max(50, self.filled * 0.2):
                flags.append("high_cardinality_for_a_category")
        if (
            self.value_type in ("identity", "category")
            and self.filled >= 50
            and distinct == 1
        ):
            flags.append("constant_value")
        if self.value_type == "timestamp" and self.valid:
            if self.year_assumed:
                flags.append("year_absent")
            if self.tz_count == 0:
                flags.append("no_timezone")
            if self.out_of_order:
                flags.append("out_of_order")
        if self.filled and self.filled < self.records * 0.5:
            flags.append("mostly_empty")
        return flags

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "value_type": self.value_type,
            "records": self.records,
            "filled": self.filled,
            "valid": self.valid,
            "fill_rate": round(self.filled / self.records, 4) if self.records else 0.0,
            "pass_rate": round(self.valid / self.filled, 4) if self.filled else 0.0,
            "distinct": len(self.values),
            "chars": self.chars,
            "distinct_capped": self.distinct_capped,
            "top_values": [
                {"value": value, "count": count}
                for value, count in self.values.most_common(5)
            ],
            "failing_examples": list(self.failures),
            "flags": self.flags(),
        }
        if self.value_type in ("category", "identity") and not self.distinct_capped:
            out["value_counts"] = dict(self.values) if len(self.values) <= 200 else None
        if self.value_type == "timestamp":
            out["format"] = self.format
            out["with_timezone"] = self.tz_count
            out["year_assumed"] = self.year_assumed
            out["implausible"] = self.implausible
            out["out_of_order"] = self.out_of_order
            out["fraction_digits"] = {str(k): v for k, v in sorted(self.digits.items())}
            if self.filled and self.valid < self.filled and self.failures:
                out["format_suggestion"] = guess_format(self.failures)
        if self.value_type == "address":
            out["ip_addresses"] = self.ip_count
        return out


def meets_precision(fraction_digits: dict[str, int], minimum: str) -> int:
    """How many timestamp values carry at least the required resolution."""
    need = PRECISION_DIGITS.get(minimum, 0)
    return sum(
        count for digits, count in fraction_digits.items() if int(digits) >= need
    )
