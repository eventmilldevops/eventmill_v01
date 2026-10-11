"""The propose / test / feed-back loop that maps record elements.

A model proposes patterns from a small sample. Every proposal is then run over
the whole file here, in the container, and only what failed goes back: the
lines nothing matched and the captured values that are not what they were
claimed to be. The file itself never leaves.

Patterns are RE2. That is a safety property before it is a portability one:
RE2 runs in time linear in the input, so a pattern written by a model cannot
hang a run over a hundred thousand lines the way a backtracking engine can.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:  # google-re2; the plugins-log-analysis extra
    import re2

    _RE2_OPTIONS = re2.Options()
    _RE2_OPTIONS.log_errors = False
except ImportError:  # pragma: no cover - reported as DEPENDENCY_MISSING by the tool
    re2 = None
    _RE2_OPTIONS = None

STATE_VERSION = "1.0"
# Bump when a prompt's wording changes: two runs are only the same question
# when this matches.
PROMPT_VERSION = "2026-10-10.3"
# Distinct (elements, timestamp facts, constrained values) combinations kept
# per record type before exact counting gives way to an upper bound.
MAX_COMBINATIONS = 5000
MAX_ELEMENT_VALUES = 200
MAX_REGEX_CHARS = 4000
MAX_PATTERNS = 40
MAX_RESIDUE_KEPT = 2000
# Lines kept per pattern, spread over the file, to show a model what a pattern
# that did not break its records down is holding.
PATTERN_SAMPLES = 300
# A pattern is shallow when one free-text field holds at least this share of
# the characters of the records it takes.
SHALLOW_FIELD_SHARE = 0.5
SHALLOW_MIN_RECORDS = 20
SHALLOW_MIN_SHARE = 0.05
ENVELOPE_PATTERN_ID = "envelope"
FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,59}$")

DEFAULTS = {
    "max_rounds": 4,
    "target_coverage": 0.98,
    "target_pass_rate": 0.99,
    # Share of records that must be split beyond a free-text field before the
    # loop stops asking, unless a round of asking changes nothing.
    "target_depth": 0.85,
    "sample_lines": 160,
    "lines_per_cluster": 30,
    "sample_chars": 60_000,
    "residue_lines": 30,
    "thinking_level": "medium",
    "reply_content_tokens": 12_000,
    "call_allowance_seconds": 150,
}

SYSTEM_CONTEXT = (
    "You write RE2 regular expressions that split application log records into "
    "named fields. You reply with JSON only."
)

EXAMPLE_REPLY = {
    "patterns": [
        {
            "pattern_id": "p1",
            "kind": "regex",
            "describes": "service request record, timestamp at the end",
            "regex": (
                r"^(?P<program>[\w.-]+)\[(?P<pid>\d+)\] (?P<level>[A-Z]+) "
                r"code=(?P<code>[A-Z]{2}\d{3}) user=(?P<user>\S+) "
                r"(?P<message>.*) @(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)$"
            ),
            "fields": {
                "program": {"element": "source_component"},
                "pid": {"element": "process_id"},
                "level": {"element": "severity"},
                "code": {"element": "event_type"},
                "user": {"element": "actor_identity"},
                "message": {"element": "message"},
                "ts": {"element": "timestamp", "format": "iso8601"},
            },
        },
        {
            "pattern_id": "p2",
            "kind": "json",
            "describes": "JSON audit record",
            "fields": {
                "time": {"element": "timestamp", "format": "epoch_ms"},
                "actor.name": {"element": "actor_identity"},
                "result": {"element": "outcome"},
                "bytes": {"element": None},
            },
            "requires": ["time", "result"],
        },
    ]
}


def re2_available() -> bool:
    return re2 is not None


def compile_regex(regex: str) -> tuple[Any, str]:
    """``(compiled, problem)``. Accepts ``(?<name>`` and stores ``(?P<name>``."""
    if re2 is None:
        return None, "google-re2 is not installed"
    try:
        return re2.compile(regex, _RE2_OPTIONS), ""
    except (
        Exception
    ) as exc:  # noqa: BLE001 - re2.error, and anything the binding raises
        detail = exc.args[0] if exc.args else exc
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        return None, str(detail)


def normalise_pattern(
    raw: Any, catalogue: dict[str, Any], fallback_id: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """Turn one proposed pattern into a tested-shape record, or say why not.

    Returns ``(pattern, notes)``. ``pattern`` is None when the proposal cannot
    be used at all; the notes then carry the reason that goes back to the
    model. A usable pattern may still carry notes about what was dropped.
    """
    notes: list[str] = []
    if not isinstance(raw, dict):
        return None, [f"{fallback_id}: not an object"]
    pattern_id = raw.get("pattern_id")
    if not isinstance(pattern_id, str) or not FIELD_NAME.match(pattern_id):
        pattern_id = fallback_id
    kind = raw.get("kind")
    if kind not in ("regex", "json"):
        kind = "regex" if isinstance(raw.get("regex"), str) else "json"
    raw_fields = raw.get("fields")
    if not isinstance(raw_fields, dict):
        notes.append(f"{pattern_id}: 'fields' was not an object")
        raw_fields = {}
    elements = catalogue.get("elements", {})

    def field_spec(name: str) -> dict[str, Any]:
        spec = raw_fields.get(name)
        if isinstance(spec, str):
            spec = {"element": spec}
        if not isinstance(spec, dict):
            spec = {}
        element = spec.get("element")
        if element is not None and element not in elements:
            notes.append(
                f"{pattern_id}: field '{name}' claimed element {element!r}, which is "
                "not in the catalogue; kept as an unclassified field"
            )
            element = None
        fmt = spec.get("format") if isinstance(spec.get("format"), str) else None
        out: dict[str, Any] = {
            "element": element,
            "value_type": elements[element]["value_type"] if element else "text",
        }
        if out["value_type"] == "timestamp":
            out["format"] = fmt
            if not fmt:
                notes.append(f"{pattern_id}: timestamp field '{name}' has no format")
        return out

    pattern: dict[str, Any] = {
        "pattern_id": pattern_id,
        "kind": kind,
        "describes": str(raw.get("describes") or "")[:200],
    }
    if kind == "regex":
        regex = raw.get("regex")
        if not isinstance(regex, str) or not regex.strip():
            return None, [f"{pattern_id}: no regex string"]
        if len(regex) > MAX_REGEX_CHARS:
            return None, [
                f"{pattern_id}: regex is longer than {MAX_REGEX_CHARS} characters"
            ]
        regex = re.sub(r"\(\?<([A-Za-z_])", r"(?P<\1", regex)
        compiled, problem = compile_regex(regex)
        if compiled is None:
            return None, [
                f"{pattern_id}: does not compile as RE2 ({problem}). RE2 has no "
                "lookahead, lookbehind or backreferences."
            ]
        # groupindex is keyed alphabetically; fields read in record order.
        names = sorted(compiled.groupindex, key=compiled.groupindex.get)
        if not names:
            return None, [
                f"{pattern_id}: no named groups; use (?P<name>...) for every field"
            ]
        if compiled.groups > len(names):
            return None, [
                f"{pattern_id}: has {compiled.groups - len(names)} unnamed capturing "
                "group(s); write (?:...) for grouping and (?P<name>...) for fields"
            ]
        for name in raw_fields:
            if name not in names:
                notes.append(
                    f"{pattern_id}: 'fields' names '{name}', which is not a group"
                )
        pattern["regex"] = regex
        pattern["fields"] = {name: field_spec(name) for name in names}
    else:
        paths = [p for p in raw_fields if isinstance(p, str) and p.strip()]
        if not paths:
            return None, [f"{pattern_id}: a json pattern needs 'fields' keyed by path"]
        pattern["fields"] = {path: field_spec(path) for path in paths}
        requires = raw.get("requires")
        if isinstance(requires, list) and requires:
            kept = [p for p in requires if p in pattern["fields"]]
        else:
            kept = [p for p, spec in pattern["fields"].items() if spec["element"]]
        pattern["requires"] = kept or paths[:1]
    return pattern, notes


def order_patterns(patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most specific first: a record goes to the first pattern that takes it.

    The envelope pattern takes any record of its envelope, so it goes last.
    """
    return sorted(
        patterns,
        key=lambda p: (
            bool(p.get("envelope")),
            -len(p["fields"]),
            -len(p.get("regex", "")),
            p["pattern_id"],
        ),
    )


FLAG_KEYS = ("envelope", "program", "message_regex")


def restore_flags(pattern: dict[str, Any], raw: Any) -> dict[str, Any]:
    """Carry envelope facts across ``normalise_pattern``, which drops them."""
    if isinstance(raw, dict):
        for key in FLAG_KEYS:
            if raw.get(key):
                pattern[key] = raw[key]
    return pattern


def envelope_fallback(
    envelope: dict[str, Any], catalogue: dict[str, Any], survey_module: Any
) -> dict[str, Any]:
    """The pattern for the envelope alone: header fields and the whole message.

    Written by this tool, not a model. It takes every record of the envelope
    that no message pattern took, so such a record still has its timestamp,
    host and program.
    """
    pattern, _ = normalise_pattern(
        {
            "pattern_id": ENVELOPE_PATTERN_ID,
            "kind": "regex",
            "describes": envelope["describes"] + " (message not broken down)",
            "regex": survey_module.envelope_regex(envelope),
            "fields": envelope["fields"],
        },
        catalogue,
        ENVELOPE_PATTERN_ID,
    )
    assert pattern is not None
    pattern["envelope"] = envelope["kind"]
    return pattern


def compose_message_pattern(
    raw: dict[str, Any],
    envelope: dict[str, Any],
    catalogue: dict[str, Any],
    fallback_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """A whole-line pattern from one program's message pattern.

    The model writes a regex for the message of one program. The header in
    front of it is the envelope's, pinned to that program, so a message
    pattern can only ever take records of its own program.
    """
    pattern_id = raw.get("pattern_id")
    if not isinstance(pattern_id, str) or not FIELD_NAME.match(pattern_id):
        pattern_id = fallback_id
    if pattern_id == ENVELOPE_PATTERN_ID:
        pattern_id = fallback_id
    program = raw.get("program")
    if not isinstance(program, str) or not program.strip():
        return None, [
            f"{pattern_id}: no 'program'; a message pattern names one program"
        ]
    body = raw.get("message_regex")
    if not isinstance(body, str) or not body.strip():
        return None, [f"{pattern_id}: no 'message_regex' string"]
    body = body.strip()
    if body.startswith("^"):
        body = body[1:]
    if body.endswith("$") and not body.endswith("\\$"):
        body = body[:-1]
    body = re.sub(r"\(\?<([A-Za-z_])", r"(?P<\1", body)
    fields = raw.get("fields") if isinstance(raw.get("fields"), dict) else {}
    renamed: dict[str, Any] = {}
    for name, spec in fields.items():
        renamed[f"msg_{name}" if name in envelope["fields"] else name] = spec
    for name in envelope["fields"]:
        body = body.replace(f"(?P<{name}>", f"(?P<msg_{name}>")
    regex = (
        envelope["prefix"].format(program=re.escape(program.strip()))
        + "(?P<message>"
        + body
        + ")$"
    )
    pattern, notes = normalise_pattern(
        {
            "pattern_id": pattern_id,
            "kind": "regex",
            "describes": raw.get("describes"),
            "regex": regex,
            "fields": {**renamed, **envelope["fields"]},
        },
        catalogue,
        fallback_id,
    )
    if pattern is None:
        return None, notes
    pattern["program"] = program.strip()
    pattern["message_regex"] = body
    return pattern, notes


def shallow_patterns(
    test: dict[str, Any], patterns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Patterns that took records without breaking them down.

    The envelope pattern always is one. Any other pattern is one when it takes
    a real share of the file and a single free-text field holds most of the
    characters of its records, with values that vary: a header and ``.*``.
    """
    specs = {p["pattern_id"]: p for p in patterns}
    total = test["records"]
    found: list[dict[str, Any]] = []
    for result in test["patterns"]:
        pattern = specs.get(result["pattern_id"])
        if pattern is None or not result["records"]:
            continue
        if pattern.get("envelope"):
            found.append(
                {
                    "pattern_id": result["pattern_id"],
                    "field": "message",
                    "records": result["records"],
                    "envelope": True,
                }
            )
            continue
        if pattern.get("program") or pattern["kind"] != "regex":
            continue
        if result["records"] < max(SHALLOW_MIN_RECORDS, SHALLOW_MIN_SHARE * total):
            continue
        line_chars = result.get("line_chars") or 0
        for name, summary in result["fields"].items():
            spec = pattern["fields"][name]
            if spec.get("element") not in (None, "message"):
                continue
            if (
                not line_chars
                or summary.get("chars", 0) / line_chars < SHALLOW_FIELD_SHARE
            ):
                continue
            if summary["distinct"] < max(5, 0.2 * summary["filled"]):
                continue
            found.append(
                {
                    "pattern_id": result["pattern_id"],
                    "field": name,
                    "records": result["records"],
                    "share_of_line": round(summary["chars"] / line_chars, 2),
                    "envelope": False,
                }
            )
            break
    return found


def depth(test: dict[str, Any], patterns: list[dict[str, Any]]) -> dict[str, Any]:
    """How many records were split beyond a free-text field."""
    shallow = shallow_patterns(test, patterns)
    held = sum(item["records"] for item in shallow)
    total = test["records"]
    return {
        "records_broken_down": test["matched"] - held,
        "records_held_as_free_text": held,
        "share": round((test["matched"] - held) / total, 4) if total else 0.0,
        "shallow_patterns": shallow,
    }


def _digest(hasher: Any) -> str:
    return hasher.hexdigest()[:16]


def run_patterns(
    path: Path,
    patterns: list[dict[str, Any]],
    survey_module: Any,
    validators_module: Any,
    max_records: int | None = None,
    value_elements: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Run every pattern over the whole file and describe what each captured.

    Beside per-field statistics this keeps, for every record, which elements it
    carried with a valid value. That gives exact counts of records carrying a
    combination of elements, and signatures that identify a mapping by what it
    captured rather than by a model's names or regex text:

    - a record type's ``line_signature`` hashes the line numbers it took;
    - an element's ``signature`` hashes ``(line, value)`` for every record
      that carried it.

    ``value_elements`` names elements whose value is part of a record's
    combination, for requirements that restrict the allowed values.
    """
    ordered = order_patterns(patterns)
    compiled: list[Any] = []
    for pattern in ordered:
        if pattern["kind"] == "regex":
            matcher, problem = compile_regex(pattern["regex"])
            if matcher is None:
                raise ValueError(f"{pattern['pattern_id']}: {problem}")
            compiled.append(matcher)
        else:
            compiled.append(None)
    stats = [
        {
            name: validators_module.FieldStats(spec["value_type"], spec.get("format"))
            for name, spec in pattern["fields"].items()
        }
        for pattern in ordered
    ]
    # element -> fields carrying it, in field order; the first valid one wins.
    element_fields: list[dict[str, list[str]]] = []
    for pattern in ordered:
        mapping: dict[str, list[str]] = {}
        for name, spec in pattern["fields"].items():
            if spec.get("element"):
                mapping.setdefault(spec["element"], []).append(name)
        element_fields.append(mapping)
    combos: list[dict[tuple, int]] = [{} for _ in ordered]
    combos_capped = [False] * len(ordered)
    line_hash = [hashlib.sha256() for _ in ordered]
    element_hash: dict[str, Any] = {}
    element_records: dict[str, int] = {}
    element_values: dict[str, dict[str, int] | None] = {}
    element_sources: dict[str, set[str]] = {}
    counts = [0] * len(ordered)
    line_chars = [0] * len(ordered)
    kept: list[list[tuple[int, str]]] = [[] for _ in ordered]
    total = 0
    overlap = 0
    residue: list[tuple[int, str]] = []
    residue_total = 0

    for line_no, line, _extra in survey_module.iter_records(path, max_records):
        total += 1
        record = None
        record_checked = False
        hits = 0
        for index, pattern in enumerate(ordered):
            if pattern["kind"] == "regex":
                match = compiled[index].fullmatch(line)
                if match is None:
                    continue
                values = match.groupdict()
            else:
                if not record_checked:
                    record = survey_module.parse_json_record(line)
                    record_checked = True
                if record is None:
                    continue
                values = {
                    p: survey_module.json_path(record, p) for p in pattern["fields"]
                }
                if any(values.get(p) is None for p in pattern["requires"]):
                    continue
            hits += 1
            if hits == 1:
                counts[index] += 1
                line_chars[index] += len(line)
                # First lines, then at a stride that grows with the count, so
                # the kept lines span the file without randomness.
                stride = max(1, counts[index] // PATTERN_SAMPLES)
                if counts[index] % stride == 0:
                    if len(kept[index]) >= 2 * PATTERN_SAMPLES:
                        kept[index] = kept[index][::2]
                    kept[index].append((line_no, line))
                line_hash[index].update(f"{line_no}\n".encode())
                verdicts = {
                    name: field_stats.add(values.get(name))
                    for name, field_stats in stats[index].items()
                }
                carried: list[str] = []
                has_tz, digits = False, 0
                kept_values: list[tuple[str, str]] = []
                for element, names in element_fields[index].items():
                    for name in names:
                        verdict = verdicts[name]
                        if not verdict or not verdict[0]:
                            continue
                        value = str(values.get(name)).strip()
                        carried.append(element)
                        if element == "timestamp":
                            has_tz, digits = verdict[1], verdict[2]
                        if element in value_elements:
                            kept_values.append((element, value.lower()))
                        if element not in element_hash:
                            element_hash[element] = hashlib.sha256()
                            element_records[element] = 0
                            element_values[element] = {}
                            element_sources[element] = set()
                        element_hash[element].update(
                            f"{line_no}\x1f{value}\n".encode("utf-8", "replace")
                        )
                        element_records[element] += 1
                        element_sources[element].add(f"{pattern['pattern_id']}.{name}")
                        seen = element_values[element]
                        if seen is not None:
                            key = value[:200]
                            if key in seen or len(seen) < MAX_ELEMENT_VALUES:
                                seen[key] = seen.get(key, 0) + 1
                            else:
                                element_values[element] = None
                        break
                combo = (tuple(sorted(carried)), has_tz, digits, tuple(kept_values))
                bucket = combos[index]
                if combo in bucket or len(bucket) < MAX_COMBINATIONS:
                    bucket[combo] = bucket.get(combo, 0) + 1
                else:
                    combos_capped[index] = True
        if hits == 0:
            residue_total += 1
            if len(residue) < MAX_RESIDUE_KEPT:
                residue.append((line_no, line))
        elif hits > 1:
            overlap += 1

    results = []
    for index, pattern in enumerate(ordered):
        results.append(
            {
                "pattern_id": pattern["pattern_id"],
                "records": counts[index],
                "share": round(counts[index] / total, 4) if total else 0.0,
                "fields": {name: fs.summary() for name, fs in stats[index].items()},
                "line_signature": _digest(line_hash[index]),
                "line_chars": line_chars[index],
                "samples": kept[index][-PATTERN_SAMPLES:],
                "combinations": [
                    {
                        "elements": list(combo[0]),
                        "timezone": combo[1],
                        "fraction_digits": combo[2],
                        "values": dict(combo[3]),
                        "records": count,
                    }
                    for combo, count in sorted(combos[index].items())
                ],
                "combinations_capped": combos_capped[index],
            }
        )
    matched = total - residue_total
    split = hashlib.sha256()
    for signature in sorted(r["line_signature"] for r in results if r["records"]):
        split.update(signature.encode())
    return {
        "records": total,
        "matched": matched,
        "coverage": round(matched / total, 4) if total else 0.0,
        "unmatched": residue_total,
        "overlap_records": overlap,
        "patterns": results,
        "split_signature": _digest(split),
        "elements": {
            element: {
                "signature": _digest(element_hash[element]),
                "records": element_records[element],
                "fields": sorted(element_sources[element]),
                "value_counts": element_values[element],
            }
            for element in sorted(element_hash)
        },
        "residue": residue,
    }


def failing_fields(
    test: dict[str, Any], patterns: list[dict[str, Any]], target: float
) -> list[dict[str, Any]]:
    """Fields mapped to an element whose values do not hold up."""
    specs = {p["pattern_id"]: p for p in patterns}
    failing: list[dict[str, Any]] = []
    for result in test["patterns"]:
        if not result["records"]:
            continue
        pattern = specs[result["pattern_id"]]
        fields = pattern["fields"]
        for name, summary in result["fields"].items():
            element = fields[name]["element"]
            if not element:
                continue
            header_field = (
                pattern.get("envelope") or pattern.get("program")
            ) and f"(?P<{name}>" not in pattern.get("message_regex", "")
            if summary["filled"] == 0 and header_field:
                # An optional header field, such as a process id the program
                # does not write. Nothing a message pattern could change.
                continue
            if summary["filled"] == 0:
                reason = "captured nothing but empty or placeholder values"
            elif summary["pass_rate"] < target:
                reason = (
                    f"{summary['filled'] - summary['valid']} of {summary['filled']} values "
                    f"are not a valid {summary['value_type']}"
                )
            else:
                continue
            failing.append(
                {
                    "pattern_id": result["pattern_id"],
                    "field": name,
                    "element": element,
                    "reason": reason,
                    "failing_examples": summary["failing_examples"],
                    "format": summary.get("format"),
                    "format_suggestion": summary.get("format_suggestion"),
                }
            )
    return failing


def parse_reply(text: str | None) -> tuple[list[Any], list[str]]:
    """Proposed patterns from a reply, however it was wrapped. Never raises."""
    if not text or not text.strip():
        return [], ["the reply was empty"]
    body = text.strip()
    fenced = re.match(r"^```[a-zA-Z]*\s*\n(.*?)(?:\n```\s*)?$", body, re.DOTALL)
    if fenced:
        body = fenced.group(1).strip()
    parsed: Any = None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        first, last = body.find("{"), body.rfind("}")
        if first >= 0 and last > first:
            try:
                parsed = json.loads(body[first : last + 1])
            except json.JSONDecodeError:
                parsed = None
    if parsed is None:
        return [], [f"the reply was not JSON; it began: {body[:160]!r}"]
    if isinstance(parsed, dict):
        patterns = parsed.get("patterns")
        if isinstance(patterns, dict):
            patterns = [
                dict(value, pattern_id=key)
                for key, value in patterns.items()
                if isinstance(value, dict)
            ]
        if not isinstance(patterns, list):
            if "regex" in parsed or "fields" in parsed:
                return [parsed], []
            return [], ["the reply had no 'patterns' list"]
        return patterns, []
    if isinstance(parsed, list):
        return parsed, []
    return [], [f"the reply was JSON of type {type(parsed).__name__}"]


def _catalogue_text(catalogue: dict[str, Any], wanted: list[str]) -> str:
    lines = []
    for name, spec in catalogue["elements"].items():
        mark = "REQUIRED BY THE STANDARD" if name in wanted else "optional"
        lines.append(f"- {name} ({spec['value_type']}, {mark}): {spec['description']}")
    return "\n".join(lines)


RULES = """Rules:
- RE2 syntax only: no lookahead, no lookbehind, no backreferences.
- A regex must match the WHOLE line, from ^ to $. End with a named group such
  as (?P<message>.*) if the tail is free text.
- Every capturing group is named with (?P<name>...). Use (?:...) for grouping.
  Group names are field names for a database column: lowercase, digits and
  underscores.
- Elements can be anywhere in the line and in any order. Find them by what the
  values are, not by where they usually sit.
- Capture every part of the record as a field, not only the catalogue
  elements. A field with no catalogue element gets "element": null.
- A timestamp field needs "format": a Python strptime format such as
  "%d/%b/%Y:%H:%M:%S %z", or one of "iso8601", "epoch_s", "epoch_ms",
  "epoch_us". Capture the whole timestamp, zone included, in one group.
- An address field holds an IP address or hostname only, never a port.
- For lines that are JSON objects use "kind": "json" with fields keyed by
  dotted path, and no regex.
- One pattern per record shape. Do not write a catch-all that matches
  everything; a line no pattern matches is reported, which is the honest
  result.
- Only map an element that is really there. If the records do not carry a
  required element, leave it out. That absence is what this audit measures."""


def first_prompt(
    catalogue: dict[str, Any],
    wanted: list[str],
    samples: list[dict[str, Any]],
    records: int,
) -> str:
    groups = []
    for group in samples:
        share = f"{group['count']} of {records} records"
        groups.append(
            f"--- group {group['cluster_id']} ({share}) ---\n"
            + "\n".join(group["lines"])
        )
    return f"""These are sample lines from one application's log file. The file has
{records} records, but only a few record shapes that repeat. The lines are
grouped by a rough similarity pass; groups may be the same shape and one group
may hold more than one.

Write patterns that split each record shape into named fields, and say which
catalogue element each field is.

Catalogue:
{_catalogue_text(catalogue, wanted)}

{RULES}

Reply with one JSON object and nothing else, shaped like this example (the
example's log format is invented; only the shape of the reply matters):

{json.dumps(EXAMPLE_REPLY, indent=2)}

SAMPLE LINES:
{chr(10).join(groups)}
"""


def feedback_prompt(
    catalogue: dict[str, Any],
    wanted: list[str],
    patterns: list[dict[str, Any]],
    test: dict[str, Any],
    failing: list[dict[str, Any]],
    rejected: list[str],
    residue_samples: list[dict[str, Any]],
    shallow: list[dict[str, Any]] | None = None,
    shallow_samples: list[dict[str, Any]] | None = None,
) -> str:
    by_id = {r["pattern_id"]: r for r in test["patterns"]}
    current = []
    for pattern in patterns:
        entry: dict[str, Any] = {
            "pattern_id": pattern["pattern_id"],
            "kind": pattern["kind"],
            "records_matched": by_id.get(pattern["pattern_id"], {}).get("records", 0),
            "fields": {
                name: {k: v for k, v in spec.items() if k in ("element", "format")}
                for name, spec in pattern["fields"].items()
            },
        }
        if pattern["kind"] == "regex":
            entry["regex"] = pattern["regex"]
        else:
            entry["requires"] = pattern["requires"]
        current.append(entry)
    sections = [
        f"Your patterns were run over the whole file: {test['records']} records, "
        f"{test['matched']} matched, {test['unmatched']} matched nothing.",
        "CURRENT PATTERNS:\n" + json.dumps(current, indent=2),
    ]
    if failing:
        problems = []
        for item in failing:
            line = f"- {item['pattern_id']}.{item['field']} as {item['element']}: {item['reason']}"
            if item["failing_examples"]:
                line += "; e.g. " + " | ".join(
                    repr(v) for v in item["failing_examples"][:4]
                )
            if item.get("format_suggestion"):
                line += f"; these parse with format {item['format_suggestion']!r}"
            problems.append(line)
        sections.append(
            "FIELDS WHOSE VALUES FAILED THEIR CHECK:\n" + "\n".join(problems)
        )
    if rejected:
        sections.append(
            "PROPOSALS THAT COULD NOT BE USED:\n"
            + "\n".join(f"- {r}" for r in rejected)
        )
    if residue_samples:
        groups = [
            f"--- unmatched group ({g['count']} lines) ---\n" + "\n".join(g["lines"])
            for g in residue_samples
        ]
        sections.append("LINES NO PATTERN MATCHED:\n" + "\n".join(groups))
    if shallow and shallow_samples:
        named = "; ".join(
            f"{item['pattern_id']} ({item['records']} records, field "
            f"'{item['field']}' holds {int(item['share_of_line'] * 100)}% of each line)"
            for item in shallow
        )
        groups = [
            f"--- shape seen {g['count']} time(s) ---\n" + "\n".join(g["lines"])
            for g in shallow_samples
        ]
        sections.append(
            "PATTERNS THAT MATCH BUT DO NOT BREAK THE RECORD DOWN:\n"
            f"{named}. These take a header and leave the rest in one free-text field. "
            "The records they took are not all one shape. Write a more specific "
            "pattern for each shape below, with its own pattern_id; a more specific "
            "pattern is tried first. If the text really is free prose with nothing to "
            "extract, leave it.\n" + "\n".join(groups)
        )
    body = "\n\n".join(sections)
    return f"""{body}

Fix what failed. Return ONLY patterns that are new or changed: reuse a
pattern_id to replace that pattern, use a new pattern_id to add one. Patterns
you leave out are kept as they are. If an unmatched line is noise that belongs
to no record shape, leave it unmatched.

Catalogue:
{_catalogue_text(catalogue, wanted)}

{RULES}

Reply with one JSON object, {{"patterns": [...]}}, in the same shape as before.
"""


def _strip_test(test: dict[str, Any]) -> dict[str, Any]:
    """The test without the raw lines it kept for the next prompt."""
    out = {key: value for key, value in test.items() if key != "residue"}
    out["patterns"] = [
        {key: value for key, value in result.items() if key != "samples"}
        for result in test["patterns"]
    ]
    return out


MESSAGE_EXAMPLE = {
    "patterns": [
        {
            "pattern_id": "backupd_job_done",
            "program": "backupd",
            "describes": "backup job finished",
            "message_regex": (
                r"^job (?P<job>\S+) for (?P<owner>\S+) finished: "
                r"(?P<result>ok|failed) in (?P<seconds>\d+)s$"
            ),
            "fields": {
                "job": {"element": "target_object"},
                "owner": {"element": "actor_identity"},
                "result": {"element": "outcome"},
                "seconds": {"element": None},
            },
        }
    ]
}

MESSAGE_RULES = """Rules:
- RE2 syntax only: no lookahead, no lookbehind, no backreferences.
- "program" is the program name exactly as shown. A pattern applies to that
  program only. Never compare or merge messages of different programs.
- "message_regex" must match the WHOLE message, from ^ to $. Do not repeat the
  header.
- Keep the constant words of the message literal and capture what varies, each
  in a named group (?P<name>...). Use (?:...) for grouping. Names are
  lowercase with digits and underscores.
- One pattern per message shape. A program usually writes a handful of shapes.
- Do not write a pattern that captures the whole message in one group. A
  message you cannot break down is already kept whole; leave it out.
- A captured field that is a catalogue element gets that element; any other
  gets "element": null. Do not map timestamp, host, program or process id
  again: the header already carries them.
- A timestamp inside a message needs "format" as a strptime format or one of
  "iso8601", "epoch_s", "epoch_ms", "epoch_us".
- An address field holds an IP address or hostname only, never a port.
- Only map an element that is really there. Absence is what this audit
  measures."""


def envelope_prompt(
    catalogue: dict[str, Any],
    wanted: list[str],
    envelope: dict[str, Any],
    survey_envelope: dict[str, Any],
    patterns: list[dict[str, Any]],
    test: dict[str, Any] | None,
    failing: list[dict[str, Any]],
    rejected: list[str],
    samples: list[dict[str, Any]],
) -> str:
    """Ask for message patterns, program by program, for an envelope log."""
    header = ", ".join(
        f"{name}" + (f" ({spec['element']})" if spec.get("element") else "")
        for name, spec in envelope["fields"].items()
        if name != "message"
    )
    programs = "\n".join(
        f"- {p['program']}: {p['records']} records, about {p['message_shapes']} "
        "message shape(s)"
        for p in survey_envelope.get("programs", [])[:40]
    )
    sections = [
        f"This log is {envelope['describes']}.\n"
        f"The header is already parsed for every record: {header}. What is left is "
        "the message, which each program writes in its own way.",
        "PROGRAMS IN THE FILE:\n" + programs,
    ]
    held = [p for p in patterns if p.get("program")]
    if held and test is not None:
        by_id = {r["pattern_id"]: r for r in test["patterns"]}
        listing = [
            {
                "pattern_id": p["pattern_id"],
                "program": p["program"],
                "records_matched": by_id.get(p["pattern_id"], {}).get("records", 0),
                "message_regex": p.get("message_regex"),
                "fields": {
                    name: {k: v for k, v in spec.items() if k in ("element", "format")}
                    for name, spec in p["fields"].items()
                    if name not in envelope["fields"]
                },
            }
            for p in held
        ]
        sections.append(
            "MESSAGE PATTERNS ALREADY HELD:\n" + json.dumps(listing, indent=2)
        )
    if failing:
        problems = []
        for item in failing:
            line = f"- {item['pattern_id']}.{item['field']} as {item['element']}: {item['reason']}"
            if item["failing_examples"]:
                line += "; e.g. " + " | ".join(
                    repr(v) for v in item["failing_examples"][:4]
                )
            if item.get("format_suggestion"):
                line += f"; these parse with format {item['format_suggestion']!r}"
            problems.append(line)
        sections.append(
            "FIELDS WHOSE VALUES FAILED THEIR CHECK:\n" + "\n".join(problems)
        )
    if rejected:
        sections.append(
            "PROPOSALS THAT COULD NOT BE USED:\n"
            + "\n".join(f"- {r}" for r in rejected)
        )
    by_program: dict[str, list[str]] = {}
    for group in samples:
        title = (
            group.get("program") or "(records outside the envelope, whole line shown)"
        )
        by_program.setdefault(title, []).append(
            f"  -- shape seen {group['count']} time(s) --\n"
            + "\n".join(f"  {line}" for line in group["lines"])
        )
    listing_text = "\n".join(
        f"=== program {program} ===\n" + "\n".join(blocks)
        for program, blocks in by_program.items()
    )
    sections.append(
        "MESSAGES NOT YET BROKEN DOWN (message part only):\n" + listing_text
    )
    body = "\n\n".join(sections)
    return f"""{body}

Write patterns that break these messages into named fields, one program at a
time, and say which catalogue element each field is. Return only new or
changed patterns; reuse a pattern_id to replace that pattern. If none of the
remaining messages can be broken down, return an empty "patterns" list.

Catalogue:
{_catalogue_text(catalogue, wanted)}

{MESSAGE_RULES}

Reply with one JSON object and nothing else, shaped like this example (the
example's program and message are invented; only the shape matters):

{json.dumps(MESSAGE_EXAMPLE, indent=2)}
"""


def new_state(log: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    return {
        "state_version": STATE_VERSION,
        "log": log,
        "settings": settings,
        "status": "not_started",
        "stop_reason": None,
        "rounds_run": 0,
        "patterns": [],
        "test": None,
        "history": [],
        "sent": {"calls": 0, "lines": 0, "chars": 0, "truncated_lines": 0},
        "calls": [],
    }


def run_loop(
    path: Path,
    survey: dict[str, Any],
    catalogue: dict[str, Any],
    wanted: list[str],
    state: dict[str, Any],
    ask: Callable[[str], dict[str, Any]],
    survey_module: Any,
    validators_module: Any,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
    max_records: int | None = None,
    value_elements: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Propose, test, feed back, until mapped or out of rounds, progress or time.

    ``ask(prompt)`` makes one model call and returns
    ``{"ok", "text", "error", ...call facts}``. ``state`` is updated in place
    after every round, so whatever stops the loop, what it had learned by then
    is in the state the caller saves.

    When the survey found a syslog envelope, the header pattern is this tool's
    own and is held from the start; the model is asked only for message
    patterns, per program.

    Mapping every record is not enough: a header followed by ``.*`` does that.
    Progress is counted in records broken down beyond a free-text field, and
    a round is spent on any that are not before the loop calls itself done.
    """
    settings = state["settings"]
    patterns: list[dict[str, Any]] = list(state["patterns"])
    survey_envelope = survey.get("envelope") or {}
    envelope = survey_module.envelope_by_kind(survey_envelope.get("kind"))
    if envelope and not any(p.get("envelope") for p in patterns):
        patterns.append(envelope_fallback(envelope, catalogue, survey_module))

    def run(candidates: list[dict[str, Any]]) -> dict[str, Any]:
        return run_patterns(
            path,
            candidates,
            survey_module,
            validators_module,
            max_records,
            value_elements,
        )

    test: dict[str, Any] | None = run(patterns) if patterns else None
    stalled = 0
    rejected: list[str] = []
    rounds_this_run = 0
    target = settings["target_pass_rate"]

    def finish(status: str, reason: str) -> dict[str, Any]:
        state["status"] = status
        state["stop_reason"] = reason
        state["patterns"] = order_patterns(patterns)
        state["test"] = _strip_test(test) if test else None
        state["depth"] = depth(test, patterns) if test else None
        state["_residue"] = test["residue"] if test else []
        return state

    def done() -> str | None:
        """Why the mapping is finished, or None when it is not."""
        if test is None or test["coverage"] < settings["target_coverage"]:
            return None
        if failing_fields(test, patterns, target):
            return None
        reached = depth(test, patterns)
        if reached["share"] >= settings["target_depth"]:
            return "coverage and value checks met their targets"
        if stalled >= 1:
            return (
                "coverage and value checks met their targets; "
                f"{reached['records_held_as_free_text']} of {test['records']} records "
                "are still held as free text, and a further round did not break them down"
            )
        return None

    reason = done()
    if reason and not envelope:
        return finish("converged", "the saved patterns already meet the targets")

    while True:
        if rounds_this_run >= settings["max_rounds"]:
            return finish(
                "stopped_round_limit", f"{settings['max_rounds']} rounds used"
            )
        if deadline - clock() < settings["call_allowance_seconds"]:
            return finish(
                "stopped_time_budget",
                "not enough time left for another model call; run 'resume' to continue",
            )

        shallow = shallow_patterns(test, patterns) if test else []
        if envelope:
            if rounds_this_run == 0 and not any(p.get("program") for p in patterns):
                clusters = survey["clusters"]
            else:
                held = [
                    line
                    for result in test["patterns"]
                    if any(i["pattern_id"] == result["pattern_id"] for i in shallow)
                    for line in result.get("samples", [])
                ]
                clusters = survey_module.cluster_lines(
                    held + list(test["residue"]), envelope=envelope
                )
            per = max(3, settings["sample_lines"] // max(1, min(len(clusters), 40)))
            samples, account = survey_module.pick_samples(
                clusters, settings["sample_lines"], per, settings["sample_chars"]
            )
            failing = failing_fields(test, patterns, target)
            prompt = envelope_prompt(
                catalogue,
                wanted,
                envelope,
                survey_envelope,
                order_patterns(patterns),
                test,
                failing,
                rejected,
                samples,
            )
        elif test is None:
            samples, account = survey_module.pick_samples(
                survey["clusters"],
                settings["sample_lines"],
                settings["lines_per_cluster"],
                settings["sample_chars"],
            )
            prompt = first_prompt(catalogue, wanted, samples, survey["records"])
            if rejected:
                prompt += (
                    "\nYOUR PREVIOUS REPLY COULD NOT BE USED:\n"
                    + "\n".join(f"- {r}" for r in rejected)
                    + "\n"
                )
            failing = []
        else:
            failing = failing_fields(test, patterns, target)
            residue_clusters = survey_module.cluster_lines(test["residue"])
            per = max(
                3, settings["residue_lines"] // max(1, min(len(residue_clusters), 6))
            )
            samples, account = survey_module.pick_samples(
                residue_clusters,
                settings["residue_lines"],
                per,
                settings["sample_chars"],
            )
            shallow_samples: list[dict[str, Any]] = []
            if shallow:
                held = [
                    line
                    for result in test["patterns"]
                    if any(i["pattern_id"] == result["pattern_id"] for i in shallow)
                    for line in result.get("samples", [])
                ]
                held_clusters = survey_module.cluster_lines(held)
                per = max(3, 60 // max(1, min(len(held_clusters), 15)))
                shallow_samples, extra = survey_module.pick_samples(
                    held_clusters, 60, per, settings["sample_chars"]
                )
                for key in ("lines", "chars", "truncated_lines"):
                    account[key] += extra[key]
            prompt = feedback_prompt(
                catalogue,
                wanted,
                order_patterns(patterns),
                test,
                failing,
                rejected,
                samples,
                shallow,
                shallow_samples,
            )
        if test is not None:
            # Failing example values are log content too.
            examples = [v for item in failing for v in item["failing_examples"][:4]]
            account["chars"] += sum(len(v) for v in examples)
            account["value_examples"] = len(examples)

        state["rounds_run"] += 1
        rounds_this_run += 1
        round_no = state["rounds_run"]
        state["sent"]["calls"] += 1
        for key in ("lines", "chars", "truncated_lines"):
            state["sent"][key] += account.get(key, 0)
        started = clock()
        reply = ask(prompt)
        call = {k: v for k, v in reply.items() if k != "text"}
        call.update({"round": round_no, "seconds": round(clock() - started, 1)})
        state["calls"].append(call)
        entry: dict[str, Any] = {
            "round": round_no,
            "sent": account,
            "prompt_chars": len(prompt),
            "accepted": False,
            "notes": [],
        }
        state["history"].append(entry)

        if not reply.get("ok") or not reply.get("text"):
            entry["notes"].append(
                f"model call failed: {reply.get('error') or 'empty reply'}"
            )
            return finish(
                "stopped_llm_failure",
                f"round {round_no}: the model call failed "
                f"({reply.get('error') or 'empty reply'})",
            )

        raw_patterns, notes = parse_reply(reply["text"])
        if reply.get("truncated"):
            notes.append("the reply stopped at the output cap")
        entry["notes"].extend(notes)
        rejected = list(notes)
        candidate = {p["pattern_id"]: p for p in patterns}
        proposed = 0
        for index, raw in enumerate(raw_patterns[:MAX_PATTERNS], start=1):
            fallback_id = f"r{round_no}p{index}"
            if envelope and isinstance(raw, dict) and "regex" not in raw:
                pattern, pattern_notes = compose_message_pattern(
                    raw, envelope, catalogue, fallback_id
                )
            else:
                pattern, pattern_notes = normalise_pattern(raw, catalogue, fallback_id)
                if pattern is not None and pattern["pattern_id"] == ENVELOPE_PATTERN_ID:
                    pattern["pattern_id"] = fallback_id
            entry["notes"].extend(pattern_notes)
            if pattern is None:
                rejected.extend(pattern_notes)
                continue
            proposed += 1
            candidate[pattern["pattern_id"]] = pattern
        entry["proposed"] = proposed
        entry["rejected"] = len(raw_patterns) - proposed

        if not proposed:
            stalled += 1
            entry["notes"].append("no usable pattern in this reply")
            if not rejected:
                rejected = ["the reply contained no usable pattern"]
        else:
            candidates = list(candidate.values())
            candidate_test = run(candidates)
            new_failing = len(failing_fields(candidate_test, candidates, target))
            new_depth = depth(candidate_test, candidates)["share"]
            if test is None:
                accept, improved = True, True
            else:
                old_failing = len(failing_fields(test, patterns, target))
                gain = new_depth - depth(test, patterns)["share"]
                covered = candidate_test["coverage"] - test["coverage"]
                accept = (
                    covered >= -0.001 and gain >= -0.001 and new_failing <= old_failing
                ) or covered > 0.01
                improved = accept and (
                    gain > 0.0005 or covered > 0.0005 or new_failing < old_failing
                )
            entry.update(
                {
                    "accepted": accept,
                    "coverage": candidate_test["coverage"],
                    "depth": new_depth,
                    "failing_fields": new_failing,
                    "patterns": len(candidates),
                }
            )
            if accept:
                dead = [
                    r["pattern_id"]
                    for r in candidate_test["patterns"]
                    if r["records"] == 0 and r["pattern_id"] != ENVELOPE_PATTERN_ID
                ]
                if dead:
                    entry["notes"].append(
                        "matched no record and were dropped: " + ", ".join(dead)
                    )
                    rejected.extend(
                        f"{pid}: matched no record in the file" for pid in dead
                    )
                    candidates = [p for p in candidates if p["pattern_id"] not in dead]
                    candidate_test["patterns"] = [
                        r
                        for r in candidate_test["patterns"]
                        if r["pattern_id"] not in dead
                    ]
                patterns, test = candidates, candidate_test
            else:
                entry["notes"].append(
                    "this round's patterns did worse than the ones already held "
                    f"(coverage {candidate_test['coverage']}, {new_failing} failing "
                    "field(s)) and were not adopted"
                )
                rejected.append(
                    "your last revision matched fewer records, broke fewer down or "
                    "failed more value checks than the patterns already held, so it "
                    "was discarded"
                )
            stalled = 0 if improved else stalled + 1

        state["patterns"] = order_patterns(patterns)
        state["test"] = _strip_test(test) if test else None
        reason = done()
        if reason:
            return finish("converged", reason)
        if stalled >= 2:
            return finish("stopped_no_progress", "two rounds in a row improved nothing")
