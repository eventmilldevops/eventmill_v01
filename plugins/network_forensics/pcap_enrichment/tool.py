"""
PCAP IP Enrichment — Enrich all IPs from a loaded PCAP via BigQuery lookup.

Usage:
    enrich --table project.dataset.table --fields hostname,zone,threat_score
    enrich --table project.dataset.table --fields hostname,zone --ip 10.1.5.20

Queries a user-specified BigQuery table with all unique IPs extracted from
the loaded PcapSession. Results are cached in the session for automatic
injection into pcap_ai_analyzer prompts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# BQ batch limit for UNNEST arrays
_BQ_BATCH_SIZE = 9000


@dataclass
class ToolResult:
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    output_artifacts: list[str] | None = None
    details: dict[str, Any] | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


# Module-level cache for enrichment results (session-scoped singleton)
_enrichment_cache: dict[str, dict[str, Any]] | None = None

# Field-role mappings — tells downstream tools which column serves which purpose.
# Keys are semantic roles, values are the actual column names from the BQ table.
# Supported roles: "name", "zone", "purdue", "os", "role"
_field_mappings: dict[str, str] = {}


def get_enrichment_cache() -> dict[str, dict[str, Any]] | None:
    """Return the current enrichment cache (ip -> row dict), or None if empty."""
    return _enrichment_cache


def get_field_mappings() -> dict[str, str]:
    """Return the current field-role mappings (role -> column name)."""
    return dict(_field_mappings)


def get_field(ip: str, role: str) -> str | None:
    """Look up a semantic field value for an IP.

    Args:
        ip: IP address to look up.
        role: Semantic role — one of 'name', 'zone', 'purdue', 'os', 'role'.

    Returns:
        The field value as a string, or None if not available.
    """
    if not _enrichment_cache or ip not in _enrichment_cache:
        return None
    col = _field_mappings.get(role)
    if not col:
        return None
    val = _enrichment_cache[ip].get(col)
    if val is None or str(val).strip() in ("", "—"):
        return None
    return str(val).strip()


def set_field_mappings(mappings: dict[str, str]) -> None:
    """Set field-role mappings (role -> column name)."""
    global _field_mappings
    _field_mappings = {k: v for k, v in mappings.items() if v}


def clear_enrichment_cache() -> None:
    """Clear the enrichment cache and field mappings."""
    global _enrichment_cache, _field_mappings
    _enrichment_cache = None
    _field_mappings = {}


def _validate_table_name(table: str) -> bool:
    """Validate fully qualified BQ table name (project.dataset.table)."""
    # Must be project.dataset.table with alphanumeric, hyphens, underscores
    pattern = r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$"
    return bool(re.match(pattern, table))


def _validate_field_names(fields: list[str]) -> list[str]:
    """Validate field names are safe identifiers. Returns list of invalid ones."""
    invalid = []
    for f in fields:
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", f.strip()):
            invalid.append(f)
    return invalid


class PcapEnrichment:
    """Enrich PCAP IPs with context from BigQuery tables."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_enrichment",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        mode = payload.get("mode", "run")
        if mode not in ("run", "run_single", "show", "clear"):
            errors.append(
                f"Invalid mode '{mode}'. Must be 'run', 'run_single', 'show', or 'clear'."
            )

        if mode in ("run", "run_single"):
            table = payload.get("table")
            if not table:
                errors.append("'--table' is required (format: project.dataset.table).")
            elif not _validate_table_name(table):
                errors.append(
                    f"Invalid table name '{table}'. "
                    "Must be fully qualified: project.dataset.table"
                )

            fields_str = payload.get("fields")
            if not fields_str:
                errors.append("'--fields' is required (comma-separated column names).")
            else:
                fields = [f.strip() for f in fields_str.split(",") if f.strip()]
                if not fields:
                    errors.append("'--fields' must contain at least one column name.")
                else:
                    invalid = _validate_field_names(fields)
                    if invalid:
                        errors.append(
                            f"Invalid field names: {', '.join(invalid)}. "
                            "Fields must be valid SQL identifiers."
                        )

        if mode == "run_single" and not payload.get("ip"):
            errors.append("'--ip' is required for run_single mode.")

        if mode in ("run", "run_single"):
            ip_col = payload.get("ip_column", "ip")
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", ip_col):
                errors.append(
                    f"Invalid --ip-column '{ip_col}'. Must be a valid SQL identifier."
                )

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute IP enrichment against BigQuery."""
        mode = payload.get("mode", "run")

        if mode == "show":
            return self._show_cached()
        elif mode == "clear":
            return self._clear_cached()
        elif mode == "run":
            return self._run_enrichment(payload)
        elif mode == "run_single":
            return self._run_single(payload)
        else:
            return ToolResult(
                ok=False, error_code="INPUT_VALIDATION_FAILED",
                message=f"Unknown mode: {mode}",
            )

    def _run_enrichment(self, payload: dict[str, Any]) -> ToolResult:
        """Enrich all IPs from the loaded PCAP session."""
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            get_pcap_session,
        )

        session = get_pcap_session()
        if not session:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message="No PCAP loaded. Use pcap_metadata_summary (mode=load) first.",
            )

        # Extract all unique IPs from conversations
        all_ips: set[str] = set()
        for src, dst, _dport, _proto in session.conversations:
            all_ips.add(src)
            all_ips.add(dst)

        if not all_ips:
            return ToolResult(
                ok=False,
                error_code="NO_DATA",
                message="No IPs found in loaded PCAP session.",
            )

        table = payload["table"]
        fields = [f.strip() for f in payload["fields"].split(",") if f.strip()]
        ip_column = payload.get("ip_column", "ip")

        return self._query_bq(list(all_ips), table, fields, ip_column)

    def _run_single(self, payload: dict[str, Any]) -> ToolResult:
        """Enrich a single IP."""
        ip = payload["ip"].strip()
        table = payload["table"]
        fields = [f.strip() for f in payload["fields"].split(",") if f.strip()]
        ip_column = payload.get("ip_column", "ip")

        return self._query_bq([ip], table, fields, ip_column)

    def _query_bq(
        self, ip_list: list[str], table: str, fields: list[str],
        ip_column: str = "ip",
    ) -> ToolResult:
        """Execute the BigQuery enrichment query."""
        global _enrichment_cache

        try:
            from google.cloud import bigquery
        except ImportError:
            return ToolResult(
                ok=False,
                error_code="DEPENDENCY_MISSING",
                message=(
                    "google-cloud-bigquery not installed. "
                    "Install with: pip install eventmill[gcp] or "
                    "pip install google-cloud-bigquery"
                ),
            )

        try:
            client = bigquery.Client()
        except Exception as e:
            return ToolResult(
                ok=False,
                error_code="AUTH_FAILED",
                message=f"Failed to initialize BigQuery client: {e}",
            )

        # Build safe query — fields are validated as identifiers, table is validated
        # ip_column is always included as the join key, aliased to "ip" in output
        select_fields = [ip_column] + [f for f in fields if f != ip_column]
        columns_sql = ", ".join(select_fields)
        query = f"SELECT {columns_sql} FROM `{table}` WHERE {ip_column} IN UNNEST(@ip_list)"

        # Batch if needed
        all_rows: list[dict[str, Any]] = []
        batches = [
            ip_list[i : i + _BQ_BATCH_SIZE]
            for i in range(0, len(ip_list), _BQ_BATCH_SIZE)
        ]

        try:
            for batch in batches:
                job_config = bigquery.QueryJobConfig(
                    query_parameters=[
                        bigquery.ArrayQueryParameter("ip_list", "STRING", batch),
                    ]
                )
                query_job = client.query(query, job_config=job_config)
                results = query_job.result()

                for row in results:
                    row_dict = dict(row.items())
                    # Normalize ip column name to "ip" in output
                    if ip_column != "ip" and ip_column in row_dict:
                        row_dict["ip"] = row_dict.pop(ip_column)
                    all_rows.append(row_dict)

        except Exception as e:
            return ToolResult(
                ok=False,
                error_code="QUERY_FAILED",
                message=f"BigQuery query failed: {e}",
            )

        # Build cache keyed by IP
        _enrichment_cache = {}
        for row in all_rows:
            ip_key = row.get("ip", "")
            if ip_key:
                _enrichment_cache[ip_key] = row

        # Identify unmatched IPs
        matched_ips = set(_enrichment_cache.keys())
        unmatched = sorted(set(ip_list) - matched_ips)

        # Build formatted output
        formatted = self._format_enrichment_table(all_rows, fields, unmatched)

        return ToolResult(
            ok=True,
            result={
                "mode": "run",
                "table": table,
                "fields": select_fields,
                "total_ips": len(ip_list),
                "matched_ips": len(matched_ips),
                "unmatched_ips": unmatched,
                "enrichment": all_rows,
                "formatted_output": formatted,
            },
        )

    def _show_cached(self) -> ToolResult:
        """Display the current enrichment cache."""
        if not _enrichment_cache:
            return ToolResult(
                ok=True,
                result={"mode": "show", "message": "No enrichment data cached."},
            )

        rows = list(_enrichment_cache.values())
        fields = [k for k in rows[0].keys() if k != "ip"] if rows else []
        formatted = self._format_enrichment_table(rows, fields, [])

        return ToolResult(
            ok=True,
            result={
                "mode": "show",
                "total_ips": len(rows),
                "enrichment": rows,
                "formatted_output": formatted,
            },
        )

    def _clear_cached(self) -> ToolResult:
        """Clear the enrichment cache."""
        clear_enrichment_cache()
        return ToolResult(
            ok=True,
            result={"mode": "clear", "message": "Enrichment cache cleared."},
        )

    @staticmethod
    def _format_enrichment_table(
        rows: list[dict[str, Any]], fields: list[str], unmatched: list[str]
    ) -> str:
        """Format enrichment data as a text table for display and LLM injection."""
        if not rows:
            return "No enrichment data returned from query."

        # Column widths
        all_fields = ["ip"] + [f for f in fields if f != "ip"]
        col_widths: dict[str, int] = {}
        for f in all_fields:
            col_widths[f] = max(
                len(f),
                max((len(str(row.get(f, "—"))) for row in rows), default=len(f)),
            )
            # Cap width to prevent extremely wide columns
            col_widths[f] = min(col_widths[f], 40)

        # Header
        header = " │ ".join(f.ljust(col_widths[f]) for f in all_fields)
        separator = "─┼─".join("─" * col_widths[f] for f in all_fields)

        lines = [
            "═══ IP ENRICHMENT (from asset/threat intelligence database) ═══",
            "USE THIS DATA: Cross-reference every IP in your analysis with this enrichment.",
            "When mentioning an IP, annotate it inline with key context from this table, e.g.:",
            "  '10.1.5.20 (HMI-PLANT3, OT-L2, criticality: high) communicated with...'",
            "DO NOT reproduce this table in your output. Use it as reference only.",
            "Identify each IP by its hostname/owner/zone when available. Flag IPs with high",
            "threat_score. IPs NOT FOUND below are unknown and should be treated as suspicious.",
            "Include in your report for each relevant IP: network/subnet, physical location,",
            "description/role, known vulnerabilities, and OS — when this data is present.",
            "If enrichment provides vulnerability or OS data, always surface it in findings.",
            "",
            f"({len(rows)} IPs matched)",
            header,
            separator,
        ]

        # Rows
        for row in sorted(rows, key=lambda r: r.get("ip", "")):
            line = " │ ".join(
                str(row.get(f, "—"))[:col_widths[f]].ljust(col_widths[f])
                for f in all_fields
            )
            lines.append(line)

        # Unmatched section
        if unmatched:
            lines.append(
                f"═══ {len(unmatched)} IPs NOT FOUND in enrichment table ═══"
            )
            # Show up to 50 unmatched IPs
            display_unmatched = unmatched[:50]
            lines.append("  " + ", ".join(display_unmatched))
            if len(unmatched) > 50:
                lines.append(f"  ... and {len(unmatched) - 50} more")

        return "\n".join(lines)

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Return enrichment data formatted for LLM context injection."""
        if not result.ok:
            return f"pcap_enrichment failed: {result.message}"

        data = result.result or {}
        formatted = data.get("formatted_output", "")
        if formatted:
            return formatted

        return "Enrichment completed but no formatted output available."

    @staticmethod
    def get_enrichment_for_prompt() -> str:
        """
        Static method for pcap_ai_analyzer to call — returns the cached
        enrichment data formatted for injection into the LLM prompt.
        Returns empty string if no enrichment is cached.
        """
        if not _enrichment_cache:
            return ""

        rows = list(_enrichment_cache.values())
        if not rows:
            return ""

        fields = [k for k in rows[0].keys() if k != "ip"]
        return PcapEnrichment._format_enrichment_table(rows, fields, [])
