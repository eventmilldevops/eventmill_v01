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
MAX_REGEX_CHARS = 4000
MAX_PATTERNS = 40
MAX_RESIDUE_KEPT = 2000
FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,59}$")

DEFAULTS = {
    "max_rounds": 4,
    "target_coverage": 0.98,
    "target_pass_rate": 0.99,
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
    """Most specific first: a record goes to the first pattern that takes it."""
    return sorted(
        patterns,
        key=lambda p: (-len(p["fields"]), -len(p.get("regex", "")), p["pattern_id"]),
    )


def run_patterns(
    path: Path,
    patterns: list[dict[str, Any]],
    survey_module: Any,
    validators_module: Any,
    max_records: int | None = None,
) -> dict[str, Any]:
    """Run every pattern over the whole file and describe what each captured."""
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
    counts = [0] * len(ordered)
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
                for name, field_stats in stats[index].items():
                    field_stats.add(values.get(name))
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
            }
        )
    matched = total - residue_total
    return {
        "records": total,
        "matched": matched,
        "coverage": round(matched / total, 4) if total else 0.0,
        "unmatched": residue_total,
        "overlap_records": overlap,
        "patterns": results,
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
        fields = specs[result["pattern_id"]]["fields"]
        for name, summary in result["fields"].items():
            element = fields[name]["element"]
            if not element:
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
    return {key: value for key, value in test.items() if key != "residue"}


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
) -> dict[str, Any]:
    """Propose, test, feed back, until mapped or out of rounds, progress or time.

    ``ask(prompt)`` makes one model call and returns
    ``{"ok", "text", "error", ...call facts}``. ``state`` is updated in place
    after every round, so whatever stops the loop, what it had learned by then
    is in the state the caller saves.
    """
    settings = state["settings"]
    patterns: list[dict[str, Any]] = list(state["patterns"])
    test: dict[str, Any] | None = None
    if patterns:
        test = run_patterns(
            path, patterns, survey_module, validators_module, max_records
        )
    stalled = 0
    rejected: list[str] = []
    rounds_this_run = 0

    def finish(status: str, reason: str) -> dict[str, Any]:
        state["status"] = status
        state["stop_reason"] = reason
        state["patterns"] = order_patterns(patterns)
        state["test"] = _strip_test(test) if test else None
        state["_residue"] = test["residue"] if test else []
        return state

    def converged() -> bool:
        return (
            test is not None
            and test["coverage"] >= settings["target_coverage"]
            and not failing_fields(test, patterns, settings["target_pass_rate"])
        )

    if converged():
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

        if test is None:
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
        else:
            failing = failing_fields(test, patterns, settings["target_pass_rate"])
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
            prompt = feedback_prompt(
                catalogue,
                wanted,
                order_patterns(patterns),
                test,
                failing,
                rejected,
                samples,
            )
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
            state["patterns"] = order_patterns(patterns)
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
            pattern, pattern_notes = normalise_pattern(
                raw, catalogue, f"r{round_no}p{index}"
            )
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
            candidate_test = run_patterns(
                path, candidates, survey_module, validators_module, max_records
            )
            target = settings["target_pass_rate"]
            new_failing = len(failing_fields(candidate_test, candidates, target))
            if test is None:
                accept, improved = True, True
            else:
                old_failing = len(failing_fields(test, patterns, target))
                gain = candidate_test["coverage"] - test["coverage"]
                accept = (gain >= -0.001 and new_failing <= old_failing) or gain > 0.01
                improved = accept and (gain > 0.0005 or new_failing < old_failing)
            entry.update(
                {
                    "accepted": accept,
                    "coverage": candidate_test["coverage"],
                    "failing_fields": new_failing,
                    "patterns": len(candidates),
                }
            )
            if accept:
                dead = [
                    r["pattern_id"]
                    for r in candidate_test["patterns"]
                    if r["records"] == 0
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
                    "your last revision matched fewer records or failed more value "
                    "checks than the patterns shown above, so it was discarded"
                )
            stalled = 0 if improved else stalled + 1

        state["patterns"] = order_patterns(patterns)
        state["test"] = _strip_test(test) if test else None
        if converged():
            return finish("converged", "coverage and value checks met their targets")
        if stalled >= 2:
            return finish("stopped_no_progress", "two rounds in a row improved nothing")
