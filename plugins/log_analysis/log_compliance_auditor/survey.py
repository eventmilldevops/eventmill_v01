"""Reading a log file as records, and grouping records that look alike.

Everything here is deterministic and streams the file. Clusters are sampling
strata, nothing more: they decide which lines a model is shown, so that a
100,000-line file with six record shapes is represented by a few dozen lines
of each. What a record *type* is gets decided later, by the patterns that
survive testing against the whole file.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

WILDCARD = "<*>"
# A template must agree with a line on at least this share of token positions.
SIMILARITY = 0.5
# Tokens beyond this are folded into one tail token, so a long free-text
# message does not make every line its own shape.
MAX_TOKENS = 24
MAX_CLUSTERS = 300
OVERFLOW_KEY = "overflow"
MAX_LINE_CHARS = 1000

# The last alternative is the unindented first line of a Java stack trace: a
# package-qualified class ending in Exception, Error or Throwable.
_CONTINUATION = re.compile(
    r"^(\s+\S|Caused by:|Traceback \(most recent call last\)"
    r"|(?:[A-Za-z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable)\b)"
)
_KV_TOKEN = re.compile(r"^([A-Za-z_][\w.\-]*)=(.*)$")

# Syslog envelopes this tool recognises itself. The header is fixed by a
# specification; the message is whatever the program chose to write, so only
# the header is parsed here and messages are compared within one program.
# ``prefix`` takes the program as ``{program}`` and ends where the message
# starts. ``fields`` maps each header group to a catalogue element.
_BSD_TAIL = r" (?P<host>\S+) (?P<program>{program})(?:\[(?P<pid>\d+)\])?: ?"
ENVELOPES: tuple[dict[str, Any], ...] = (
    {
        "kind": "syslog_rfc5424",
        "describes": "RFC 5424 syslog: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG",
        "prefix": (
            r"^<(?P<pri>\d{{1,3}})>(?P<version>\d{{1,2}}) (?P<timestamp>\S+) (?P<host>\S+) "
            r"(?P<program>{program}) (?P<pid>\S+) (?P<msgid>\S+) "
            r"(?P<structured_data>-|\[.*\]) ?"
        ),
        "program": r"\S+",
        "fields": {
            "pri": {"element": None},
            "version": {"element": None},
            "timestamp": {"element": "timestamp", "format": "iso8601"},
            "host": {"element": "host"},
            "program": {"element": "source_component"},
            "pid": {"element": None},
            "msgid": {"element": "event_type"},
            "structured_data": {"element": None},
            "message": {"element": "message"},
        },
    },
    {
        "kind": "syslog_bsd",
        "describes": "BSD syslog (RFC 3164): [<PRI>]Mmm dd hh:mm:ss HOST PROGRAM[PID]: MSG",
        "prefix": (
            r"^(?:<(?P<pri>\d{{1,3}})>)?"
            r"(?P<timestamp>[A-Z][a-z]{{2}} [ \d]\d \d{{2}}:\d{{2}}:\d{{2}})"
            + _BSD_TAIL
        ),
        "program": r"[^\s\[:]+",
        "fields": {
            "pri": {"element": None},
            "timestamp": {"element": "timestamp", "format": "%b %d %H:%M:%S"},
            "host": {"element": "host"},
            "program": {"element": "source_component"},
            "pid": {"element": "process_id"},
            "message": {"element": "message"},
        },
    },
    {
        "kind": "syslog_bsd_iso_time",
        "describes": "BSD-style syslog with an ISO 8601 timestamp: TIMESTAMP HOST PROGRAM[PID]: MSG",
        "prefix": (
            r"^(?:<(?P<pri>\d{{1,3}})>)?"
            r"(?P<timestamp>\d{{4}}-\d{{2}}-\d{{2}}T[\d:.,]+(?:Z|[+-]\d{{2}}:?\d{{2}})?)"
            + _BSD_TAIL
        ),
        "program": r"[^\s\[:]+",
        "fields": {
            "pri": {"element": None},
            "timestamp": {"element": "timestamp", "format": "iso8601"},
            "host": {"element": "host"},
            "program": {"element": "source_component"},
            "pid": {"element": "process_id"},
            "message": {"element": "message"},
        },
    },
)
# Share of probed records that must fit an envelope for it to be adopted.
ENVELOPE_SHARE = 0.9
ENVELOPE_PROBE_RECORDS = 2000
MAX_PROGRAMS_LISTED = 60


def envelope_regex(envelope: dict[str, Any], program: str | None = None) -> str:
    """The envelope's whole-line regex; ``program`` pins it to one program."""
    name = re.escape(program) if program is not None else envelope["program"]
    return envelope["prefix"].format(program=name) + r"(?P<message>.*)$"


def envelope_by_kind(kind: str | None) -> dict[str, Any] | None:
    return next((e for e in ENVELOPES if e["kind"] == kind), None)


def detect_envelope(
    path: Path, max_records: int | None = None
) -> dict[str, Any] | None:
    """The syslog envelope most records fit, or None.

    Decided on the first records only; ``survey_file`` then counts how many
    records of the whole file fit it.
    """
    compiled = [(e, re.compile(envelope_regex(e))) for e in ENVELOPES]
    hits = [0] * len(compiled)
    probed = 0
    limit = min(max_records or ENVELOPE_PROBE_RECORDS, ENVELOPE_PROBE_RECORDS)
    for _, line, _ in iter_records(path, limit):
        probed += 1
        for index, (_, matcher) in enumerate(compiled):
            if matcher.match(line):
                hits[index] += 1
                break
    if not probed:
        return None
    best = max(range(len(compiled)), key=lambda i: hits[i])
    if hits[best] / probed < ENVELOPE_SHARE:
        return None
    return compiled[best][0]


_HAS_DIGIT = re.compile(r"\d")


def iter_records(
    path: Path, max_records: int | None = None
) -> Iterator[tuple[int, str, int]]:
    """Yield ``(line_number, head_line, continuation_lines)``.

    A line that starts with whitespace, or opens a stack trace, belongs to the
    record above it. Only the head line is the record: it is where an
    application writes its timestamp, level and identifiers. Continuation
    lines are counted, not parsed.
    """
    head: str | None = None
    head_no = 0
    extra = 0
    produced = 0
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            if head is not None and _CONTINUATION.match(line):
                extra += 1
                continue
            if head is not None:
                yield head_no, head, extra
                produced += 1
                if max_records is not None and produced >= max_records:
                    return
            head, head_no, extra = line, line_no, 0
    if head is not None:
        yield head_no, head, extra


def parse_json_record(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        value = json.loads(stripped)
    except (json.JSONDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def flatten_keys(record: dict[str, Any], prefix: str = "", depth: int = 0) -> list[str]:
    """Dotted paths to the scalar values of a JSON record, two levels deep."""
    paths: list[str] = []
    for key, value in record.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and depth < 2:
            paths.extend(flatten_keys(value, f"{path}.", depth + 1))
        else:
            paths.append(path)
    return paths


def json_path(record: Any, path: str) -> Any:
    current = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def mask_tokens(line: str) -> list[str]:
    """Tokens of a line with the parts that vary replaced by a wildcard.

    Anything holding a digit varies. A ``key=value`` token keeps its key. This
    is deliberately crude: it only has to put like lines together.
    """
    tokens = line.split()
    if len(tokens) > MAX_TOKENS:
        tokens = tokens[:MAX_TOKENS] + ["<tail>"]
    masked: list[str] = []
    for token in tokens:
        kv = _KV_TOKEN.match(token)
        if kv:
            masked.append(f"{kv.group(1)}={WILDCARD}")
        elif _HAS_DIGIT.search(token):
            masked.append(WILDCARD)
        else:
            masked.append(token)
    return masked


class Clusterer:
    """Drain-style template clustering: same length, similar tokens."""

    def __init__(self, sample_size: int = 12, prefix: str = "c") -> None:
        self.sample_size = max(2, sample_size)
        self.prefix = prefix
        self.clusters: dict[str, dict[str, Any]] = {}
        self._by_length: dict[int, list[dict[str, Any]]] = {}
        self._json_keys: dict[tuple[str, ...], str] = {}

    def _new(self, key: str, kind: str, template: list[str]) -> dict[str, Any]:
        cluster = {
            "cluster_id": key,
            "kind": kind,
            "template": template,
            "count": 0,
            "first_line": None,
            "_seen": 0,
            "samples": [],
        }
        self.clusters[key] = cluster
        return cluster

    def _note(self, cluster: dict[str, Any], line_no: int, line: str) -> None:
        cluster["count"] += 1
        if cluster["first_line"] is None:
            cluster["first_line"] = line_no
        # Evenly spaced reservoir: keep the first lines, then replace at a
        # stride that doubles, so samples span the file without randomness.
        samples = cluster["samples"]
        if len(samples) < self.sample_size:
            samples.append((line_no, line))
        else:
            stride = max(1, cluster["count"] // self.sample_size)
            if cluster["count"] % stride == 0:
                slot = 1 + (cluster["_seen"] % (self.sample_size - 1))
                samples[slot] = (line_no, line)
                cluster["_seen"] += 1

    def add(self, line_no: int, line: str) -> str:
        record = parse_json_record(line)
        if record is not None:
            keys = tuple(sorted(flatten_keys(record)))
            key = self._json_keys.get(keys)
            if key is None:
                if len(self.clusters) >= MAX_CLUSTERS:
                    key = OVERFLOW_KEY
                    if key not in self.clusters:
                        self._new(key, "overflow", [])
                else:
                    key = f"{self.prefix}{len(self.clusters) + 1}"
                    self._new(key, "json", list(keys))
                self._json_keys[keys] = key
            self._note(self.clusters[key], line_no, line)
            return key

        tokens = mask_tokens(line)
        bucket = self._by_length.setdefault(len(tokens), [])
        best = None
        best_score = 0.0
        for cluster in bucket:
            template = cluster["template"]
            same = sum(1 for a, b in zip(template, tokens) if a == b or a == WILDCARD)
            score = same / len(tokens) if tokens else 1.0
            if score > best_score:
                best, best_score = cluster, score
        if best is not None and best_score >= SIMILARITY:
            template = best["template"]
            for index, token in enumerate(tokens):
                if template[index] != token:
                    template[index] = WILDCARD
            self._note(best, line_no, line)
            return best["cluster_id"]
        if len(self.clusters) >= MAX_CLUSTERS:
            if OVERFLOW_KEY not in self.clusters:
                self._new(OVERFLOW_KEY, "overflow", [])
            self._note(self.clusters[OVERFLOW_KEY], line_no, line)
            return OVERFLOW_KEY
        key = f"{self.prefix}{len(self.clusters) + 1}"
        cluster = self._new(key, "text", tokens)
        bucket.append(cluster)
        self._note(cluster, line_no, line)
        return key

    def ranked(self) -> list[dict[str, Any]]:
        return sorted(
            self.clusters.values(), key=lambda c: (-c["count"], c["cluster_id"])
        )


def detect_container(shares: dict[str, float]) -> str:
    if shares["json"] >= 0.9:
        return "json_lines"
    if shares["json"] >= 0.1:
        return "mixed_json_and_text"
    if shares["key_value"] >= 0.6:
        return "key_value"
    return "free_text"


class _ProgramClusters:
    """Clusters records by message within each program of a syslog envelope.

    A record that does not fit the envelope is clustered on its whole line.
    Each sample keeps the whole line and, for an envelope record, the message.
    """

    def __init__(self, envelope: dict[str, Any] | None, sample_size: int) -> None:
        self.envelope = envelope
        self.matcher = re.compile(envelope_regex(envelope)) if envelope else None
        self.sample_size = sample_size
        self.other = Clusterer(sample_size=sample_size)
        self.by_program: dict[str, Clusterer] = {}
        self.program_records: dict[str, int] = {}
        self.fitted = 0
        self.with_pri = 0
        self.with_pid = 0
        self._lines: dict[int, str] = {}

    def add(self, line_no: int, line: str) -> dict[str, Any]:
        match = self.matcher.match(line) if self.matcher else None
        if match is None:
            return self.other.clusters[self.other.add(line_no, line)]
        self.fitted += 1
        groups = match.groupdict()
        self.with_pri += 1 if groups.get("pri") else 0
        self.with_pid += 1 if groups.get("pid") not in (None, "-") else 0
        program = groups["program"]
        self.program_records[program] = self.program_records.get(program, 0) + 1
        clusterer = self.by_program.get(program)
        if clusterer is None:
            clusterer = Clusterer(
                sample_size=self.sample_size, prefix=f"p{len(self.by_program) + 1}m"
            )
            self.by_program[program] = clusterer
        cluster = clusterer.clusters[clusterer.add(line_no, groups["message"])]
        cluster["program"] = program
        self._lines[line_no] = line
        return cluster

    def ranked(self, records: int) -> list[dict[str, Any]]:
        raw = list(self.other.clusters.values())
        for clusterer in self.by_program.values():
            raw.extend(clusterer.clusters.values())
        raw.sort(key=lambda c: (-c["count"], c["cluster_id"]))
        out = []
        for cluster in raw:
            program = cluster.get("program")
            samples = []
            for number, text in cluster["samples"]:
                if program is None:
                    samples.append({"line": number, "text": text})
                else:
                    samples.append(
                        {"line": number, "text": self._lines[number], "message": text}
                    )
            out.append(
                {
                    "cluster_id": cluster["cluster_id"],
                    "kind": cluster["kind"],
                    "program": program,
                    "count": cluster["count"],
                    "share": round(cluster["count"] / records, 4) if records else 0.0,
                    "template": (
                        " ".join(cluster["template"])
                        if cluster["kind"] == "text"
                        else ", ".join(cluster["template"])
                    )[:400],
                    "first_line": cluster["first_line"],
                    "samples": samples,
                }
            )
        # Only sampled lines are needed again.
        keep = {s["line"] for c in out for s in c["samples"]}
        self._lines = {n: t for n, t in self._lines.items() if n in keep}
        return out

    def describe(self, records: int) -> dict[str, Any] | None:
        if not self.envelope:
            return None
        programs = sorted(self.program_records.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "kind": self.envelope["kind"],
            "describes": self.envelope["describes"],
            "records": self.fitted,
            "share": round(self.fitted / records, 4) if records else 0.0,
            "with_pri": self.with_pri,
            "with_pid": self.with_pid,
            "program_count": len(programs),
            "programs": [
                {
                    "program": name,
                    "records": count,
                    "message_shapes": len(self.by_program[name].clusters),
                }
                for name, count in programs[:MAX_PROGRAMS_LISTED]
            ],
        }


def survey_file(
    path: Path, max_records: int | None = None, sample_size: int = 12
) -> dict[str, Any]:
    """One pass over the file: counts, container, clusters and their samples.

    When most records fit a syslog envelope, clustering is done on the message
    and separately for each program, and ``envelope`` describes the fit.
    """
    envelope = detect_envelope(path, max_records)
    clusterer = _ProgramClusters(envelope, sample_size)
    records = 0
    continuation = 0
    json_records = 0
    kv_records = 0
    longest = 0
    for line_no, line, extra in iter_records(path, max_records):
        records += 1
        continuation += extra
        longest = max(longest, len(line))
        cluster = clusterer.add(line_no, line)
        if cluster["kind"] == "json":
            json_records += 1
        elif sum(1 for token in line.split() if _KV_TOKEN.match(token)) >= 3:
            kv_records += 1
    shares = {
        "json": json_records / records if records else 0.0,
        "key_value": kv_records / records if records else 0.0,
    }
    clusters = clusterer.ranked(records)
    return {
        "records": records,
        "continuation_lines": continuation,
        "longest_record_chars": longest,
        "scan": "full" if max_records is None else f"first {max_records} records",
        "container": detect_container(shares),
        "container_shares": {k: round(v, 4) for k, v in shares.items()},
        "envelope": clusterer.describe(records),
        "cluster_count": len(clusters),
        "clusters": clusters,
    }


def cluster_lines(
    lines: list[tuple[int, str]],
    sample_size: int = 8,
    envelope: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Cluster an in-memory list of lines; used on what was not broken down.

    With an envelope, lines are clustered by message within each program.
    """
    clusterer = _ProgramClusters(envelope, sample_size)
    for line_no, line in lines:
        clusterer.add(line_no, line)
    return [
        {k: c[k] for k in ("cluster_id", "kind", "program", "count", "samples")}
        for c in clusterer.ranked(len(lines))
    ]


def pick_samples(
    clusters: list[dict[str, Any]], max_lines: int, per_cluster: int, max_chars: int
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Choose which lines a model is shown, largest clusters first.

    Returns the chosen groups and an exact account of what was chosen, because
    these lines leave the container. For a cluster inside a syslog envelope
    only the message is shown: the header is already parsed.
    """
    chosen: list[dict[str, Any]] = []
    lines_used = 0
    chars_used = 0
    truncated = 0
    for cluster in clusters:
        if lines_used >= max_lines or chars_used >= max_chars:
            break
        take = min(per_cluster, max_lines - lines_used, len(cluster["samples"]))
        texts: list[str] = []
        for sample in cluster["samples"][:take]:
            text = sample.get("message", sample["text"])
            if len(text) > MAX_LINE_CHARS:
                text = text[:MAX_LINE_CHARS]
                truncated += 1
            if chars_used + len(text) > max_chars:
                break
            texts.append(text)
            chars_used += len(text)
        if not texts:
            break
        lines_used += len(texts)
        chosen.append(
            {
                "cluster_id": cluster["cluster_id"],
                "kind": cluster.get("kind", "text"),
                "program": cluster.get("program"),
                "count": cluster["count"],
                "lines": texts,
            }
        )
    return chosen, {
        "lines": lines_used,
        "chars": chars_used,
        "truncated_lines": truncated,
    }
