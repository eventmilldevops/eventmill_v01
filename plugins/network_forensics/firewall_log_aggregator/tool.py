"""
Firewall Log Aggregator — Parses and aggregates firewall logs for analysis.

Supports multiple vendor formats:
- Palo Alto (CSV traffic logs)
- Fortinet (syslog)
- pfSense (filterlog CSV)
- iptables (syslog)
- Windows Firewall (CSV)
- Generic CSV (auto-column detection)

Provides:
- Traffic summary (total entries, action breakdown, time range)
- Top talkers by source/destination/port
- Deny hotspots (most blocked src→dst pairs)
- Port scan indicators (single source → many ports on one target)
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict

logger = logging.getLogger("eventmill.plugins.firewall_log_aggregator")


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


@dataclass
class FwEntry:
    """Normalized firewall log entry."""
    timestamp: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    action: str = ""  # allow, deny, drop, reset
    bytes_sent: int = 0
    bytes_recv: int = 0
    rule: str = ""
    interface: str = ""
    raw: str = ""


@dataclass
class FwSession:
    """Holds parsed firewall log data."""
    filename: str = ""
    entries: list[FwEntry] = field(default_factory=list)
    log_format: str = "unknown"


# Module-level session singleton
_fw_session: FwSession | None = None


def get_fw_session() -> FwSession | None:
    return _fw_session


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _detect_format(lines: list[str]) -> str:
    """Detect firewall log format from sample lines."""
    if not lines:
        return "generic_csv"

    sample = "\n".join(lines[:20])

    # Palo Alto CSV — has "TRAFFIC" or "THREAT" as log type in column 3
    if "TRAFFIC" in sample and lines[0].count(",") > 30:
        return "paloalto_csv"

    # Fortinet — contains "devname=" or "type=traffic"
    if "devname=" in sample or "type=traffic" in sample:
        return "fortinet_syslog"

    # pfSense — filterlog format with specific column count
    if "filterlog" in sample:
        return "pfsense"

    # iptables — kernel log with IN= OUT= SRC= DST=
    if re.search(r"SRC=\S+ DST=\S+", sample):
        return "iptables"

    # Windows Firewall — has header row with specific column names
    if "src-ip" in sample.lower() or "source address" in sample.lower():
        return "windows_fw"

    return "generic_csv"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_iptables(lines: list[str]) -> list[FwEntry]:
    """Parse iptables syslog format."""
    entries = []
    pattern = re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*?"
        r"(?P<action>DROP|ACCEPT|REJECT|LOG).*?"
        r"IN=(?P<in_if>\S*)\s+OUT=(?P<out_if>\S*)\s+"
        r".*?SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+"
        r".*?PROTO=(?P<proto>\S+)"
        r"(?:.*?SPT=(?P<spt>\d+))?"
        r"(?:.*?DPT=(?P<dpt>\d+))?",
        re.IGNORECASE,
    )
    for line in lines:
        m = pattern.search(line)
        if m:
            action_raw = m.group("action").lower()
            action = "deny" if action_raw in ("drop", "reject") else "allow"
            entries.append(FwEntry(
                timestamp=m.group("timestamp"),
                src_ip=m.group("src"),
                dst_ip=m.group("dst"),
                src_port=int(m.group("spt") or 0),
                dst_port=int(m.group("dpt") or 0),
                protocol=m.group("proto"),
                action=action,
                interface=m.group("in_if") or m.group("out_if"),
                raw=line.strip(),
            ))
    return entries


def _parse_fortinet(lines: list[str]) -> list[FwEntry]:
    """Parse Fortinet syslog key=value format."""
    entries = []
    for line in lines:
        kv: dict[str, str] = {}
        for m in re.finditer(r'(\w+)=(".*?"|\S+)', line):
            kv[m.group(1)] = m.group(2).strip('"')

        if "srcip" in kv or "src" in kv:
            action_raw = kv.get("action", kv.get("status", "")).lower()
            action = "deny" if action_raw in ("deny", "dropped", "blocked") else "allow"
            entries.append(FwEntry(
                timestamp=kv.get("date", "") + " " + kv.get("time", ""),
                src_ip=kv.get("srcip", kv.get("src", "")),
                dst_ip=kv.get("dstip", kv.get("dst", "")),
                src_port=int(kv.get("srcport", kv.get("sport", 0))),
                dst_port=int(kv.get("dstport", kv.get("dport", 0))),
                protocol=kv.get("proto", kv.get("service", "")),
                action=action,
                bytes_sent=int(kv.get("sentbyte", 0)),
                bytes_recv=int(kv.get("rcvdbyte", 0)),
                rule=kv.get("policyid", ""),
                interface=kv.get("srcintf", ""),
                raw=line.strip(),
            ))
    return entries


def _parse_paloalto_csv(lines: list[str]) -> list[FwEntry]:
    """Parse Palo Alto CSV traffic log format."""
    entries = []
    reader = csv.reader(io.StringIO("\n".join(lines)))
    for row in reader:
        if len(row) < 35:
            continue
        # Standard PAN-OS traffic log columns
        try:
            action_raw = row[30].strip().lower() if len(row) > 30 else ""
            action = "deny" if action_raw in ("deny", "drop", "reset-both") else "allow"
            entries.append(FwEntry(
                timestamp=row[1].strip() if len(row) > 1 else "",
                src_ip=row[7].strip() if len(row) > 7 else "",
                dst_ip=row[8].strip() if len(row) > 8 else "",
                src_port=int(row[24].strip() or 0) if len(row) > 24 else 0,
                dst_port=int(row[25].strip() or 0) if len(row) > 25 else 0,
                protocol=row[29].strip() if len(row) > 29 else "",
                action=action,
                bytes_sent=int(row[31].strip() or 0) if len(row) > 31 else 0,
                bytes_recv=int(row[32].strip() or 0) if len(row) > 32 else 0,
                rule=row[12].strip() if len(row) > 12 else "",
                raw=",".join(row[:10]),
            ))
        except (ValueError, IndexError):
            continue
    return entries


def _parse_generic_csv(lines: list[str]) -> list[FwEntry]:
    """Parse generic CSV with auto-column detection."""
    entries = []
    if not lines:
        return entries

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames:
        return entries

    # Map common column names
    col_map: dict[str, str] = {}
    for fn in reader.fieldnames:
        fn_lower = fn.lower().replace(" ", "_").replace("-", "_")
        if "src" in fn_lower and "ip" in fn_lower:
            col_map["src_ip"] = fn
        elif "dst" in fn_lower and "ip" in fn_lower or "dest" in fn_lower and "ip" in fn_lower:
            col_map["dst_ip"] = fn
        elif "src" in fn_lower and "port" in fn_lower:
            col_map["src_port"] = fn
        elif "dst" in fn_lower and "port" in fn_lower or "dest" in fn_lower and "port" in fn_lower:
            col_map["dst_port"] = fn
        elif fn_lower in ("action", "status"):
            col_map["action"] = fn
        elif fn_lower in ("protocol", "proto"):
            col_map["protocol"] = fn
        elif "time" in fn_lower or "date" in fn_lower:
            col_map["timestamp"] = fn

    for row in reader:
        try:
            action_raw = row.get(col_map.get("action", ""), "").lower()
            action = "deny" if any(d in action_raw for d in ("deny", "drop", "block", "reject")) else "allow"
            entries.append(FwEntry(
                timestamp=row.get(col_map.get("timestamp", ""), ""),
                src_ip=row.get(col_map.get("src_ip", ""), ""),
                dst_ip=row.get(col_map.get("dst_ip", ""), ""),
                src_port=int(row.get(col_map.get("src_port", ""), 0) or 0),
                dst_port=int(row.get(col_map.get("dst_port", ""), 0) or 0),
                protocol=row.get(col_map.get("protocol", ""), ""),
                action=action,
                raw=str(row),
            ))
        except (ValueError, KeyError):
            continue
    return entries


PARSERS = {
    "iptables": _parse_iptables,
    "fortinet_syslog": _parse_fortinet,
    "paloalto_csv": _parse_paloalto_csv,
    "pfsense": _parse_iptables,  # pfSense filterlog is similar to iptables
    "windows_fw": _parse_generic_csv,
    "generic_csv": _parse_generic_csv,
}


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


class FirewallLogAggregator:
    """Parses and aggregates firewall logs for statistical analysis."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "firewall_log_aggregator",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        if not payload.get("file_path"):
            errors.append("'file_path' is required.")
        mode = payload.get("mode", "summary")
        valid = ("load", "summary", "top_talkers", "deny_hotspots", "port_scan")
        if mode not in valid:
            errors.append(f"Invalid mode '{mode}'. Must be one of: {', '.join(valid)}")
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        global _fw_session

        mode = payload.get("mode", "summary")
        file_path = payload["file_path"]
        top_n = payload.get("top_n", 20)

        # Always load if not loaded or different file
        if _fw_session is None or _fw_session.filename != file_path or mode == "load":
            load_result = self._load(file_path, payload, context)
            if not load_result.ok:
                return load_result
            if mode == "load":
                return load_result

        session = _fw_session
        if not session or not session.entries:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message="No firewall log loaded.",
            )

        dispatch = {
            "summary": self._summary,
            "top_talkers": self._top_talkers,
            "deny_hotspots": self._deny_hotspots,
            "port_scan": self._port_scan,
        }

        try:
            return dispatch[mode](session, top_n)
        except Exception as e:
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"firewall_log_aggregator failed: {result.message}"
        data = result.result or {}
        summary = data.get("summary_text", "")
        return summary[:3000] if len(summary) > 3000 else summary

    # -------------------------------------------------------------------
    # Load
    # -------------------------------------------------------------------

    def _load(
        self, file_path: str, payload: dict, context: Any
    ) -> ToolResult:
        global _fw_session

        resolved = file_path

        # 1. Check workspace directory
        if context and hasattr(context, "config"):
            workspace = context.config.get("workspace_dir", "workspace")
            candidate = os.path.join(workspace, file_path)
            if os.path.isfile(candidate):
                resolved = candidate

        # 2. Check workspace artifacts directory
        if not os.path.isfile(resolved):
            workspace = os.environ.get("EVENTMILL_WORKSPACE", "/app/workspace")
            candidate = os.path.join(workspace, "artifacts", os.path.basename(file_path))
            if os.path.isfile(candidate):
                resolved = candidate

        # 3. Try GCS download
        if not os.path.isfile(resolved):
            from plugins.network_forensics.pcap_metadata_summary.tool import _download_from_gcs
            downloaded = _download_from_gcs(file_path, context)
            if downloaded:
                resolved = str(downloaded)

        if not os.path.isfile(resolved):
            return ToolResult(
                ok=False,
                error_code="FILE_NOT_FOUND",
                message=f"File not found: {file_path}",
            )

        # Limit to 100MB
        if os.path.getsize(resolved) > 100 * 1024 * 1024:
            return ToolResult(
                ok=False,
                error_code="FILE_TOO_LARGE",
                message="File exceeds 100MB limit.",
            )

        with open(resolved, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        log_format = payload.get("log_format", "auto")
        if log_format == "auto":
            log_format = _detect_format(lines[:30])

        parser = PARSERS.get(log_format, _parse_generic_csv)
        entries = parser(lines)

        _fw_session = FwSession(
            filename=file_path,
            entries=entries,
            log_format=log_format,
        )

        return ToolResult(
            ok=True,
            result={
                "total_entries": len(entries),
                "log_format": log_format,
                "summary_text": (
                    f"Loaded {len(entries):,} firewall entries from {file_path} "
                    f"(format: {log_format})"
                ),
            },
        )

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------

    def _summary(self, session: FwSession, top_n: int) -> ToolResult:
        actions = Counter(e.action for e in session.entries)
        protocols = Counter(e.protocol for e in session.entries if e.protocol)
        unique_src = len(set(e.src_ip for e in session.entries if e.src_ip))
        unique_dst = len(set(e.dst_ip for e in session.entries if e.dst_ip))

        timestamps = [e.timestamp for e in session.entries if e.timestamp]
        time_range = f"{timestamps[0]} — {timestamps[-1]}" if timestamps else "unknown"

        total_bytes = sum(e.bytes_sent + e.bytes_recv for e in session.entries)

        lines = [
            f"📋 FIREWALL LOG SUMMARY — {session.filename}",
            "=" * 60,
            f"Format: {session.log_format}",
            f"Entries: {len(session.entries):,}",
            f"Time range: {time_range}",
            f"Unique sources: {unique_src:,}",
            f"Unique destinations: {unique_dst:,}",
            f"Total bytes: {_format_bytes(total_bytes)}",
            "",
            "Actions:",
        ]
        for action, count in actions.most_common():
            pct = (count / len(session.entries) * 100) if session.entries else 0
            lines.append(f"  {action}: {count:,} ({pct:.1f}%)")

        lines.append("\nProtocols:")
        for proto, count in protocols.most_common(10):
            lines.append(f"  {proto}: {count:,}")

        return ToolResult(
            ok=True,
            result={
                "total_entries": len(session.entries),
                "time_range": time_range,
                "actions": dict(actions),
                "protocols": dict(protocols),
                "unique_sources": unique_src,
                "unique_destinations": unique_dst,
                "total_bytes": total_bytes,
                "summary_text": "\n".join(lines),
            },
        )

    # -------------------------------------------------------------------
    # Top talkers
    # -------------------------------------------------------------------

    def _top_talkers(self, session: FwSession, top_n: int) -> ToolResult:
        src_count: Counter = Counter()
        dst_count: Counter = Counter()
        port_count: Counter = Counter()

        for e in session.entries:
            if e.src_ip:
                src_count[e.src_ip] += 1
            if e.dst_ip:
                dst_count[e.dst_ip] += 1
            if e.dst_port > 0:
                port_count[e.dst_port] += 1

        lines = [f"🔝 TOP TALKERS (top {top_n})", "=" * 60]

        lines.append("\nTop Sources:")
        top_src = []
        for ip, count in src_count.most_common(top_n):
            lines.append(f"  {ip:<18} {count:,} entries")
            top_src.append({"ip": ip, "count": count})

        lines.append("\nTop Destinations:")
        top_dst = []
        for ip, count in dst_count.most_common(top_n):
            lines.append(f"  {ip:<18} {count:,} entries")
            top_dst.append({"ip": ip, "count": count})

        lines.append("\nTop Ports:")
        top_ports = []
        for port, count in port_count.most_common(top_n):
            lines.append(f"  {port:<8} {count:,} entries")
            top_ports.append({"port": port, "count": count})

        return ToolResult(
            ok=True,
            result={
                "top_sources": top_src,
                "top_destinations": top_dst,
                "top_ports": top_ports,
                "summary_text": "\n".join(lines),
            },
        )

    # -------------------------------------------------------------------
    # Deny hotspots
    # -------------------------------------------------------------------

    def _deny_hotspots(self, session: FwSession, top_n: int) -> ToolResult:
        deny_pairs: Counter = Counter()
        deny_ports: Counter = Counter()

        for e in session.entries:
            if e.action in ("deny", "drop", "reject", "reset"):
                if e.src_ip and e.dst_ip:
                    deny_pairs[(e.src_ip, e.dst_ip)] += 1
                if e.dst_port > 0:
                    deny_ports[e.dst_port] += 1

        lines = [f"🚫 DENY HOTSPOTS", "=" * 60]

        hotspots = []
        if deny_pairs:
            lines.append(f"\nTop blocked pairs ({sum(deny_pairs.values()):,} total denies):")
            for (src, dst), count in deny_pairs.most_common(top_n):
                lines.append(f"  {src:<18} → {dst:<18} {count:,} denies")
                hotspots.append({"src": src, "dst": dst, "count": count})
        else:
            lines.append("  No deny entries found.")

        lines.append("\nTop blocked ports:")
        blocked_ports = []
        for port, count in deny_ports.most_common(top_n):
            lines.append(f"  {port:<8} {count:,} denies")
            blocked_ports.append({"port": port, "count": count})

        return ToolResult(
            ok=True,
            result={
                "deny_hotspots": hotspots,
                "blocked_ports": blocked_ports,
                "summary_text": "\n".join(lines),
            },
        )

    # -------------------------------------------------------------------
    # Port scan detection
    # -------------------------------------------------------------------

    def _port_scan(self, session: FwSession, top_n: int) -> ToolResult:
        # src → dst → set of ports
        src_dst_ports: Dict[tuple, set] = defaultdict(set)

        for e in session.entries:
            if e.src_ip and e.dst_ip and e.dst_port > 0:
                src_dst_ports[(e.src_ip, e.dst_ip)].add(e.dst_port)

        scan_indicators = [
            {"src": src, "dst": dst, "port_count": len(ports), "sample_ports": sorted(ports)[:20]}
            for (src, dst), ports in src_dst_ports.items()
            if len(ports) >= 10
        ]
        scan_indicators.sort(key=lambda x: x["port_count"], reverse=True)

        lines = ["🔍 PORT SCAN INDICATORS", "=" * 60]

        if scan_indicators:
            lines.append(f"\n{len(scan_indicators)} potential scanner(s) detected (>=10 unique ports):")
            for s in scan_indicators[:top_n]:
                ports_str = ", ".join(str(p) for p in s["sample_ports"][:10])
                if s["port_count"] > 10:
                    ports_str += f" ... +{s['port_count'] - 10} more"
                lines.append(f"  {s['src']} → {s['dst']}: {s['port_count']} ports ({ports_str})")
        else:
            lines.append("  ✅ No port scan patterns detected")

        return ToolResult(
            ok=True,
            result={
                "scan_indicators": scan_indicators[:top_n],
                "summary_text": "\n".join(lines),
            },
        )
