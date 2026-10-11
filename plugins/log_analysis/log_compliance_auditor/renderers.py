"""The run's outputs: the extraction pack and the alignment report.

One neutral spec is the tested artefact. The BigQuery, Splunk and Elastic
files are renderings of it. BigQuery uses RE2, the engine the patterns were
tested with, so its regexes are the tested ones. Splunk (PCRE) and Elastic
(Oniguruma) accept the RE2 subset, but nothing here runs either product, so
those two are labelled ``rendered_not_executed`` and say so in their headers.
"""

from __future__ import annotations

import json
import re
from typing import Any

EXECUTION = {
    "extraction_spec": "tested_against_sample",
    "bigquery": "regex_dialect_tested_sql_not_executed",
    "splunk": "rendered_not_executed",
    "elastic": "rendered_not_executed",
}

_NAMED_GROUP = re.compile(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>")
_STRPTIME_TO_JAVA = {
    "%Y": "yyyy",
    "%y": "yy",
    "%m": "MM",
    "%d": "dd",
    "%H": "HH",
    "%M": "mm",
    "%S": "ss",
    "%f": "SSSSSS",
    "%z": "Z",
    "%b": "MMM",
    "%B": "MMMM",
    "%a": "EEE",
    "%j": "DDD",
    "%I": "hh",
    "%p": "a",
}
_SPECIAL_ELASTIC = {"iso8601": "ISO8601", "epoch_s": "UNIX", "epoch_ms": "UNIX_MS"}


def column_name(field: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", field).strip("_").lower() or "field"
    return f"f_{name}" if name[0].isdigit() else name


def single_group_regex(regex: str, keep: str) -> str:
    """The same regex with only ``keep`` capturing.

    BigQuery's REGEXP_EXTRACT allows one capturing group, so each column gets
    the full pattern with every other named group made non-capturing.
    """
    return _NAMED_GROUP.sub(lambda m: "(" if m.group(1) == keep else "(?:", regex)


def java_time_format(fmt: str | None) -> str | None:
    if not fmt:
        return None
    if fmt in _SPECIAL_ELASTIC:
        return _SPECIAL_ELASTIC[fmt]
    out = []
    index = 0
    literal = ""
    while index < len(fmt):
        if fmt[index] == "%" and index + 1 < len(fmt):
            token = fmt[index : index + 2]
            if token not in _STRPTIME_TO_JAVA:
                return None
            if literal:
                out.append(
                    f"'{literal}'" if re.search(r"[A-Za-z]", literal) else literal
                )
                literal = ""
            out.append(_STRPTIME_TO_JAVA[token])
            index += 2
        else:
            literal += fmt[index]
            index += 1
    if literal:
        out.append(f"'{literal}'" if re.search(r"[A-Za-z]", literal) else literal)
    return "".join(out)


def extraction_spec(
    patterns: list[dict[str, Any]],
    test: dict[str, Any],
    log: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    """The neutral, tested description of how to split this log."""
    by_id = {r["pattern_id"]: r for r in test["patterns"]}
    record_types = []
    for order, pattern in enumerate(patterns, start=1):
        result = by_id.get(
            pattern["pattern_id"], {"records": 0, "share": 0.0, "fields": {}}
        )
        fields = []
        for name, spec in pattern["fields"].items():
            summary = result["fields"].get(name, {})
            field: dict[str, Any] = {
                "name": name,
                "column": column_name(name),
                "element": spec.get("element"),
                "value_type": spec.get("value_type", "text"),
                "fill_rate": summary.get("fill_rate"),
                "pass_rate": summary.get("pass_rate"),
            }
            if spec.get("value_type") == "timestamp":
                field["format"] = spec.get("format")
            fields.append(field)
        entry: dict[str, Any] = {
            "order": order,
            "pattern_id": pattern["pattern_id"],
            "kind": pattern["kind"],
            "describes": pattern.get("describes", ""),
            "records": result["records"],
            "share": result["share"],
            "fields": fields,
        }
        if pattern["kind"] == "regex":
            entry["regex"] = pattern["regex"]
        else:
            entry["requires"] = pattern.get("requires", [])
        # Envelope facts: which program a message pattern belongs to, and
        # which record type is the tool's own header-only pattern.
        for key in ("envelope", "program", "message_regex"):
            if pattern.get(key):
                entry[key] = pattern[key]
        record_types.append(entry)
    return {
        "spec_version": "1.0",
        "regex_dialect": "RE2",
        "match_semantics": (
            "try record types in order; a regex must match the whole line; "
            "the first that matches takes the record"
        ),
        "mapping_status": status,
        "tested_on": {
            "file": log.get("file"),
            "sha256": log.get("sha256"),
            "records": test["records"],
            "matched": test["matched"],
            "coverage": test["coverage"],
        },
        "execution": dict(EXECUTION),
        "record_types": record_types,
    }


def _sql_string(text: str) -> str:
    return "r'''" + text + "'''" if "'''" not in text else json.dumps(text)


def bigquery_sql(
    spec: dict[str, Any], table: str = "your_project.your_dataset.raw_logs"
) -> str:
    lines = [
        "-- Extraction query rendered by log_compliance_auditor.",
        "-- The regular expressions are RE2, the engine they were tested with against",
        f"-- {spec['tested_on']['file']} ({spec['tested_on']['matched']} of "
        f"{spec['tested_on']['records']} records matched). This SQL itself has not been",
        "-- executed. It expects a table with one STRING column `raw` per log line.",
        "-- Timestamps are left as strings; the format each one parsed with is noted.",
        "",
    ]
    selects = []
    for record_type in spec["record_types"]:
        columns = [f"  '{record_type['pattern_id']}' AS record_type"]
        notes = []
        if record_type["kind"] == "regex":
            for field in record_type["fields"]:
                rx = single_group_regex(record_type["regex"], field["name"])
                columns.append(
                    f"  REGEXP_EXTRACT(raw, {_sql_string(rx)}) AS {field['column']}"
                )
                if field.get("format"):
                    notes.append(
                        f"-- {field['column']}: timestamp, format {field['format']}"
                    )
            where = f"REGEXP_CONTAINS(raw, {_sql_string(record_type['regex'])})"
        else:
            for field in record_type["fields"]:
                columns.append(
                    f"  JSON_VALUE(raw, '$.{field['name']}') AS {field['column']}"
                )
                if field.get("format"):
                    notes.append(
                        f"-- {field['column']}: timestamp, format {field['format']}"
                    )
            where = (
                " AND ".join(
                    f"JSON_VALUE(raw, '$.{path}') IS NOT NULL"
                    for path in record_type["requires"]
                )
                or "TRUE"
            )
            where = f"STARTS_WITH(LTRIM(raw), '{{') AND {where}"
        header = (
            f"-- {record_type['pattern_id']}: {record_type['describes'] or record_type['kind']} "
            f"({record_type['records']} records in the sample)"
        )
        selects.append(
            "\n".join(
                [
                    header,
                    *notes,
                    "SELECT",
                    ",\n".join(columns),
                    f"FROM `{table}`",
                    f"WHERE {where};",
                ]
            )
        )
    lines.append("\n\n".join(selects))
    lines.append("")
    lines.append(
        "-- Record types overlap only where the sample showed they do; where they can,\n"
        "-- apply them in the order above and take the first that matches."
    )
    return "\n".join(lines) + "\n"


def splunk_conf(spec: dict[str, Any], sourcetype: str = "your_sourcetype") -> str:
    lines = [
        "# props.conf rendered by log_compliance_auditor.",
        "# rendered_not_executed: generated from patterns tested with RE2 against",
        f"# {spec['tested_on']['file']}; it has not been loaded into Splunk.",
        "# Set the stanza name to your sourcetype. TIME_PREFIX is not set: check where",
        "# the timestamp sits in each record type before relying on TIME_FORMAT.",
        "",
        f"[{sourcetype}]",
        "SHOULD_LINEMERGE = false",
    ]
    time_formats = []
    json_seen = False
    for record_type in spec["record_types"]:
        for field in record_type["fields"]:
            if field.get("format") and field["format"] not in time_formats:
                time_formats.append(field["format"])
        if record_type["kind"] == "regex":
            rx = _NAMED_GROUP.sub(lambda m: f"(?<{m.group(1)}>", record_type["regex"])
            lines.append(
                f"# {record_type['pattern_id']}: {record_type['records']} records in the sample"
            )
            lines.append(f"EXTRACT-{record_type['pattern_id']} = {rx}")
        else:
            json_seen = True
            for field in record_type["fields"]:
                if field["column"] != field["name"]:
                    lines.append(
                        f"FIELDALIAS-{record_type['pattern_id']}_{field['column']} = "
                        f"\"{field['name']}\" AS {field['column']}"
                    )
    if json_seen:
        lines.append("KV_MODE = json")
    strptime = [f for f in time_formats if f.startswith("%")]
    if strptime:
        lines.append(f"TIME_FORMAT = {strptime[0]}")
        for other in strptime[1:]:
            lines.append(f"# another record type uses TIME_FORMAT = {other}")
    for special in [f for f in time_formats if not f.startswith("%")]:
        lines.append(
            f"# a timestamp field is {special}; Splunk reads that without TIME_FORMAT"
        )
    return "\n".join(lines) + "\n"


def elastic_pipeline(spec: dict[str, Any]) -> dict[str, Any]:
    grok_patterns = []
    processors: list[dict[str, Any]] = []
    date_fields: dict[str, list[str]] = {}
    unconverted: list[str] = []
    json_types = [r for r in spec["record_types"] if r["kind"] == "json"]
    for record_type in spec["record_types"]:
        if record_type["kind"] == "regex":
            grok_patterns.append(
                _NAMED_GROUP.sub(lambda m: f"(?<{m.group(1)}>", record_type["regex"])
            )
        for field in record_type["fields"]:
            if not field.get("format"):
                continue
            target = field["name"]
            java = java_time_format(field["format"])
            if java is None:
                unconverted.append(
                    f"{record_type['pattern_id']}.{field['name']}: {field['format']}"
                )
            else:
                formats = date_fields.setdefault(target, [])
                if java not in formats:
                    formats.append(java)
    if json_types:
        processors.append(
            {"json": {"field": "message", "add_to_root": True, "ignore_failure": True}}
        )
    if grok_patterns:
        processors.append(
            {
                "grok": {
                    "field": "message",
                    "patterns": grok_patterns,
                    "ignore_failure": True,
                }
            }
        )
    for field, formats in date_fields.items():
        processors.append(
            {"date": {"field": field, "formats": formats, "ignore_failure": True}}
        )
    description = (
        "rendered_not_executed: generated by log_compliance_auditor from patterns "
        f"tested with RE2 against {spec['tested_on']['file']}; not run against "
        "Elasticsearch."
    )
    if unconverted:
        description += (
            " Timestamp formats with no direct Java equivalent were left out of the "
            "date processors: " + "; ".join(unconverted)
        )
    return {"description": description, "processors": processors}


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


STATE_WORDS = {
    "observed": "Observed",
    "partially_observed": "Partially observed",
    "not_observed": "Not observed",
    "not_assessable_from_sample": "Not assessable from a log sample",
    "not_evaluated": "Not evaluated",
}


SHORT_TYPES_SHOWN = 8
KIND_HEADINGS = {
    "prohibition": "Prohibitions: something must not be in a record",
    "quality": "Quality of values: correct, consistent, unambiguous",
    "event_selection": "Event selection: a kind of event must be logged at all",
    "permission": "Permissions: allowed, with nothing to fall short of",
    "presence": "No catalogue element to count",
}
_COUNT_PREFIX = re.compile(r"^\d+ of \d+ ")


def _element_rows(finding: dict[str, Any]) -> list[str]:
    """One table row per required element, summed over record types."""
    order: list[str] = []
    merged: dict[str, dict[str, Any]] = {}
    for record_type in finding["by_record_type"]:
        for element in record_type["elements"]:
            name = element["element"]
            if name not in merged:
                order.append(name)
                merged[name] = {"records": 0, "fields": [], "examples": [], "extra": []}
            entry = merged[name]
            entry["records"] += element["records"]
            if element["field"] and element["field"] not in entry["fields"]:
                entry["fields"].append(element["field"])
            for value in element.get("examples", []):
                if value not in entry["examples"] and len(entry["examples"]) < 3:
                    entry["examples"].append(value)
            for note in element.get("notes", []) + element.get("flags", []):
                note = _COUNT_PREFIX.sub("", note)
                if note not in entry["extra"]:
                    entry["extra"].append(note)
    rows = []
    for name in order:
        entry = merged[name]
        detail = ", ".join(f"`{v}`" for v in entry["examples"])
        extra = "; ".join(entry["extra"])
        if extra:
            detail = f"{detail} - {extra}" if detail else extra
        rows.append(
            f"| {name} | {entry['records']} of {finding['records']} | "
            f"{', '.join(entry['fields']) or '*no field*'} | {detail} |"
        )
    return rows


def _needs_lines(finding: dict[str, Any]) -> list[str]:
    """What the requirement needs of a record, and how many records met it."""
    needs = finding.get("needs") or []
    groups = [n for n in needs if n["any_of"]]
    met = (
        f"{finding['records_with_all_elements']} of {finding['records']} records "
        f"({_pct(finding['share'])})"
    )
    optional = finding["obligation"] == "may"
    if len(needs) == 1 and groups:
        lead = "Optional. At least one" if optional else "At least one"
        return [f"{lead} of the elements below is present in {met}."]
    if not groups:
        if optional:
            return [f"Optional. Present in {met}."]
        return [f"All required elements present in {met}."]
    parts = []
    for need in needs:
        if need["any_of"]:
            label = f"{need['label']}: " if need["label"] else ""
            parts.append(f"{label}one of " + " / ".join(need["elements"]))
        else:
            parts.append(need["elements"][0])
    lines = [
        ("Optional. Everything needed" if optional else "Everything needed")
        + f" is present in {met}.",
        "",
        "Needs: " + "; ".join(parts) + ".",
    ]
    for need in groups:
        lines.append(
            f"- One of {' / '.join(need['elements'])}: "
            f"{need['records']} of {finding['records']} records."
        )
    return lines


def _short_types(finding: dict[str, Any]) -> list[str]:
    """Record types where a required element is missing or not always valid."""
    short = []
    for record_type in finding["by_record_type"]:
        gaps = []
        by_name = {e["element"]: e for e in record_type["elements"]}
        needs = record_type.get("needs") or [
            {"elements": [e["element"]]} for e in record_type["elements"]
        ]
        for need in needs:
            if len(need["elements"]) > 1:
                if need["records"] < record_type["records"]:
                    names = " / ".join(need["elements"])
                    gaps.append(
                        f"none of {names}"
                        if not need["records"]
                        else f"one of {names} in {need['records']}"
                    )
                continue
            element = by_name[need["elements"][0]]
            if not element["field"]:
                gaps.append(f"no {element['element']}")
            elif element["records"] < record_type["records"]:
                gaps.append(f"{element['element']} valid in {element['records']}")
        if gaps:
            short.append(
                f"`{record_type['pattern_id']}` ({record_type['records']} of its records: "
                + ", ".join(gaps)
                + ")"
            )
    if len(short) > SHORT_TYPES_SHOWN:
        more = len(short) - SHORT_TYPES_SHOWN
        short = short[:SHORT_TYPES_SHOWN] + [f"and {more} more"]
    return short


def _depth_lines(survey: dict[str, Any], state: dict[str, Any]) -> list[str]:
    """What the envelope check and the under-split check found."""
    envelope = survey.get("envelope")
    depth = state.get("depth") or {}
    lines: list[str] = []
    if envelope:
        lines.append(
            f"- Envelope: {envelope['describes']}. {envelope['records']} of "
            f"{survey['records']} records fit it. PRI present in "
            f"{envelope['with_pri']}; process id present in {envelope['with_pid']}. "
            "The header was parsed by this tool, not proposed by a model."
        )
        lines.append(
            f"- Programs: {envelope['program_count']}. Messages were compared only "
            "within one program. Messages broken down into fields: "
            f"{depth.get('records_broken_down', 0)} records "
            f"({_pct(depth.get('share'))}); "
            f"{depth.get('records_held_as_free_text', 0)} keep the message whole."
        )
    elif depth.get("records_held_as_free_text"):
        named = ", ".join(
            f"`{item['pattern_id']}`" for item in depth.get("shallow_patterns", [])
        )
        lines.append(
            f"- {depth['records_held_as_free_text']} records are matched by a pattern "
            f"that leaves most of the line in one free-text field ({named}). Elements "
            "inside that text were not looked for."
        )
    return lines


def markdown_report(
    profile: dict[str, Any],
    assessment: dict[str, Any],
    spec: dict[str, Any],
    state: dict[str, Any],
    survey: dict[str, Any],
) -> str:
    standard = profile.get("standard") or {}
    counts = assessment["counts"]
    lines = [f"# Log alignment report: {standard.get('title', 'unnamed standard')}", ""]
    if profile.get("review_status") != "reviewed":
        lines += [
            "> **The requirement profile is `draft_unreviewed`.** It was extracted from the "
            "standard by a model and nobody has confirmed it. Every finding below rests on "
            "that reading.",
            "",
        ]
    if state["status"] != "converged":
        lines += [
            f"> **Mapping is incomplete (`{state['status']}`): {state['stop_reason']}.** "
            "Findings cover only the records the patterns below matched.",
            "",
        ]
    lines += [
        "## What was checked",
        "",
        f"- Standard: {standard.get('title', '')} {standard.get('version') or ''}".rstrip(),
        f"- Log sample: `{state['log'].get('file')}`, {assessment['records']} records"
        + (
            f" plus {survey['continuation_lines']} continuation lines"
            if survey.get("continuation_lines")
            else ""
        ),
        f"- Records mapped to a record type: {assessment['records_mapped']} "
        f"({_pct(assessment['coverage'])}); not mapped: {assessment['records_unmapped']}",
        f"- Requirements in the profile: {assessment['requirements']}; "
        f"assessed against records: {assessment['requirements_assessed']}",
    ]
    lines += _depth_lines(survey, state)
    lines += [
        "",
        "This report describes what this sample contains. `Observed` means the element was "
        "captured, with values that pass a format check, in at least 99% of records. It is "
        "not a certification, and it says nothing about events the application never logged.",
        "",
        "## Summary",
        "",
        "| Finding | Requirements |",
        "|---|---|",
    ]
    for key, word in STATE_WORDS.items():
        lines.append(f"| {word} | {counts.get(key, 0)} |")
    lines += ["", "## Requirements assessed against the records", ""]
    assessed = [
        f
        for f in assessment["findings"]
        if f["state"] in ("observed", "partially_observed", "not_observed")
    ]
    if not assessed:
        lines += [
            "None of the profile's requirements can be tested against log records.",
            "",
        ]
    order = {"not_observed": 0, "partially_observed": 1, "observed": 2}
    for finding in sorted(
        assessed, key=lambda f: (order[f["state"]], f["requirement_id"])
    ):
        lines += [
            f"### {finding['requirement_id']} - {STATE_WORDS[finding['state']]} "
            f"({finding['obligation']})",
            "",
            finding["summary"] or "",
            "",
        ]
        if finding["quote"]:
            flag = (
                " *(quote not found in the document text)*"
                if finding["quote_status"] == "quote_not_found"
                else ""
            )
            lines += [f"> {finding['quote']}{flag}", ""]
        lines += _needs_lines(finding)
        lines += [
            "",
            "| Element | Valid in | Fields | Examples / notes |",
            "|---|---|---|---|",
        ]
        lines += _element_rows(finding)
        short = _short_types(finding)
        if short:
            lines += ["", "Record types falling short: " + "; ".join(short) + "."]
        lines.append("")

    others = [f for f in assessment["findings"] if f["state"] == "not_evaluated"]
    if others:
        lines += [
            "## Requirements about records that were not counted",
            "",
            "Counting the records that carry an element answers a rule that the "
            "element must be there. The requirements below ask something else, or "
            "name nothing the catalogue has. They are neither met nor unmet by this "
            "report and need a person to look.",
            "",
        ]
        groups: dict[str, list[dict[str, Any]]] = {}
        for finding in others:
            kind = finding.get("kind") or "presence"
            groups.setdefault(kind if kind in KIND_HEADINGS else "presence", []).append(
                finding
            )
        for kind, heading in KIND_HEADINGS.items():
            if kind not in groups:
                continue
            lines += [f"### {heading}", ""]
            for finding in groups[kind]:
                line = (
                    f"- **{finding['requirement_id']}** ({finding['obligation']}): "
                    f"{finding['summary']}"
                )
                if kind == "presence":
                    line += f" - {finding['basis']}"
                reference = finding.get("reference_elements")
                if reference:
                    line += " For reference, in this sample: " + ", ".join(
                        f"{item['element']} in {item['records']} of {finding['records']}"
                        for item in reference
                    ) + "."
                lines.append(line)
            lines.append("")
    out_of_reach = [
        f for f in assessment["findings"] if f["state"] == "not_assessable_from_sample"
    ]
    if out_of_reach:
        lines += [
            "## Requirements a log sample cannot show",
            "",
            "These are neither met nor unmet by this report. They need other evidence.",
            "",
        ]
        for finding in out_of_reach:
            lines.append(
                f"- **{finding['requirement_id']}** ({finding['obligation']}): {finding['summary']}"
            )
        lines.append("")

    lines += [
        "## Record types found",
        "",
        "| Order | Type | Kind | Records | Share | Describes |",
        "|---|---|---|---|---|---|",
    ]
    for record_type in spec["record_types"]:
        lines.append(
            f"| {record_type['order']} | {record_type['pattern_id']} | {record_type['kind']} | "
            f"{record_type['records']} | {_pct(record_type['share'])} | {record_type['describes']} |"
        )
    lines.append("")
    for record_type in spec["record_types"]:
        lines += [f"### {record_type['pattern_id']}", ""]
        if record_type["kind"] == "regex":
            lines += ["```", record_type["regex"], "```", ""]
        lines += [
            "| Field | Element | Type | Filled | Valid |",
            "|---|---|---|---|---|",
        ]
        for field in record_type["fields"]:
            lines.append(
                f"| {field['name']} | {field['element'] or ''} | {field['value_type']} | "
                f"{_pct(field['fill_rate'])} | {_pct(field['pass_rate'])} |"
            )
        lines.append("")

    sent = state["sent"]
    lines += [
        "## How this was produced",
        "",
        f"- Mapping status: `{state['status']}` after {state['rounds_run']} round(s): "
        f"{state['stop_reason']}",
        f"- Sent to the model: {sent['lines']} log lines ({sent['chars']} characters) in "
        f"{sent['calls']} call(s). The rest of the file stayed in the container.",
    ]
    models = sorted(
        {
            f"{c.get('provider_id')}/{c.get('model_version') or c.get('model_used')}"
            for c in state["calls"]
            if c.get("provider_id") or c.get("model_used")
        }
    )
    if models:
        lines.append(f"- Model: {', '.join(models)}")
    lines += [
        f"- Patterns are RE2 and were tested against every record. Extraction files: "
        f"BigQuery ({EXECUTION['bigquery']}), Splunk and Elastic ({EXECUTION['splunk']}).",
        "",
    ]
    return "\n".join(lines)
