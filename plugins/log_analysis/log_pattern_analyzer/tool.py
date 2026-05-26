"""
Log Pattern Analyzer — GROK/regex frequency analysis and auto-pattern discovery.

Ported from Event Mill v1.0 analysis.py with the following improvements:
- Conforms to EventMillToolProtocol
- Decoupled from GCS (works with local files via artifact registry)
- Structured JSON output instead of plain text
- Optional LLM integration via ExecutionContext
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Protocol-compatible result types
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# GROK Pattern Library
# ---------------------------------------------------------------------------

BUILTIN_GROK_PATTERNS: dict[str, str] = {
    "IP": r"((?:\d{1,3}\.){3}\d{1,3})",
    "IPV4": r"((?:\d{1,3}\.){3}\d{1,3})",
    "IPV6": r"((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})",
    "MAC": r"((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})",
    "EMAIL": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    "UUID": r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
    "HTTPSTATUS": r"\s(\d{3})\s",
    "HTTPMETHOD": r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND)",
    "LOGLEVEL": r"(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|TRACE|NOTICE|ALERT|EMERG(?:ENCY)?)",
    "USER": r"user[=:\s]+[\"']?(\w+)[\"']?",
    "USERNAME": r"user(?:name)?[=:\s]+[\"']?(\w+)[\"']?",
    "PORT": r":(\d{1,5})\b",
    "PATH": r"(\/[^\s?#]*)",
    "URI": r"(\/[^\s]*)",
    "URIPATH": r"(\/[^\s?#]*)",
    "URL": r"(https?:\/\/[^\s]+)",
    "TIMESTAMP": r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})",
    "DATE": r"(\d{4}-\d{2}-\d{2})",
    "TIME": r"(\d{2}:\d{2}:\d{2})",
    "INT": r"(\d+)",
    "NUMBER": r"([+-]?\d+(?:\.\d+)?)",
    "WORD": r"(\b\w+\b)",
    "HOSTNAME": r"(\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*\.?\b)",
    "SID": r"(S-\d-\d+-(?:\d+-)*\d+)",
}

# Patterns used by discover mode to abstract variable data into tokens
DISCOVER_ABSTRACTION_PATTERNS: list[tuple[str, str]] = [
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>"),
    (r"\d{4}-\d{2}-\d{2}", "<DATE>"),
    (r"\d{2}/\w{3}/\d{4}", "<DATE>"),
    (r"\d{2}:\d{2}:\d{2}", "<TIME>"),
    (r"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)", "<METHOD>"),
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>"),
    (r"0x[0-9a-fA-F]+", "<HEX>"),
    (r"\b\d+\b", "<NUM>"),
]


# ---------------------------------------------------------------------------
# Plugin Implementation
# ---------------------------------------------------------------------------

class LogPatternAnalyzer:
    """Analyze log files using GROK/regex patterns or auto-discover structures.
    
    Three modes:
    - grok: Named pattern frequency analysis (IP, HTTPSTATUS, LOGLEVEL, etc.)
    - regex: Custom regex with capture group frequency analysis
    - discover: Automatic structural signature generation
    """

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "log_pattern_analyzer",
            "version": "1.0.0",
            "pillar": "log_analysis",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        # Required fields
        if "mode" not in payload:
            errors.append("'mode' is required (grok, regex, or discover)")
        elif payload["mode"] not in ("grok", "regex", "discover"):
            errors.append(f"Invalid mode '{payload['mode']}'. Must be grok, regex, or discover.")

        if "file_path" not in payload:
            errors.append("'file_path' is required")

        mode = payload.get("mode")

        # Pattern required for grok/regex modes
        if mode == "grok":
            pattern = payload.get("pattern", "").upper()
            if not pattern:
                errors.append("'pattern' is required for grok mode (e.g. 'IP', 'HTTPSTATUS')")
            elif pattern not in BUILTIN_GROK_PATTERNS:
                available = ", ".join(sorted(BUILTIN_GROK_PATTERNS.keys()))
                errors.append(f"Unknown GROK pattern '{pattern}'. Available: {available}")

        elif mode == "regex":
            if not payload.get("pattern"):
                errors.append("'pattern' is required for regex mode (regex with capture group)")
            else:
                # Validate regex compiles
                try:
                    re.compile(payload["pattern"])
                except re.error as e:
                    errors.append(f"Invalid regex pattern: {e}")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute log pattern analysis."""
        mode = payload["mode"]
        file_path = payload["file_path"]
        
        # Resolve file path from artifact registry if available
        resolved_path = self._resolve_file(file_path, context)
        if resolved_path is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"File not found: {file_path}",
            )

        try:
            if mode == "grok":
                return self._analyze_grok(resolved_path, payload, context)
            elif mode == "regex":
                return self._analyze_regex(resolved_path, payload, context)
            elif mode == "discover":
                return self._discover_patterns(resolved_path, payload, context)
            else:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_VALIDATION_FAILED",
                    message=f"Unknown mode: {mode}",
                )
        except Exception as e:
            return ToolResult(
                ok=False,
                error_code="INTERNAL_ERROR",
                message=str(e),
            )

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context (max 2000 chars)."""
        if not result.ok:
            return f"log_pattern_analyzer failed: {result.message}"

        data = result.result or {}
        mode = data.get("mode", "unknown")
        lines = data.get("lines_processed", 0)
        matches = data.get("matches_found", 0)

        if mode in ("grok", "regex"):
            pattern = data.get("pattern_used", "")
            top = data.get("top_results", [])

            parts = [
                f"Pattern analysis ({mode}): {matches} matches in {lines} lines.",
                f"Pattern: {pattern}",
            ]

            # Show top 5 results in compact format
            for entry in top[:5]:
                parts.append(f"  {entry['value']}: {entry['count']}")

            if len(top) > 5:
                parts.append(f"  ... and {len(top) - 5} more")

            return "\n".join(parts)

        elif mode == "discover":
            patterns = data.get("patterns", [])
            parts = [f"Pattern discovery: {len(patterns)} structures in {lines} lines."]

            for p in patterns[:3]:
                parts.append(
                    f"  [{p['percentage']:.0f}%] {p['signature'][:160]}"
                )

            ai = data.get("ai_analysis")
            if ai:
                parts.append(f"\nAI Insight:\n{ai}")

            return "\n".join(parts)

        return f"log_pattern_analyzer completed: {lines} lines processed."

    # -------------------------------------------------------------------
    # Mode implementations
    # -------------------------------------------------------------------

    def _analyze_grok(
        self, file_path: Path, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        """GROK pattern frequency analysis."""
        pattern_name = payload["pattern"].upper()
        regex_pattern = BUILTIN_GROK_PATTERNS[pattern_name]

        result = self._run_frequency_analysis(
            file_path=file_path,
            regex_pattern=regex_pattern,
            limit=payload.get("limit", 10),
            sample_lines=payload.get("sample_lines", 50000),
            full_log=payload.get("full_log", False),
        )

        result["mode"] = "grok"
        result["pattern_used"] = f"{pattern_name} → {regex_pattern}"

        return ToolResult(ok=True, result=result)

    def _analyze_regex(
        self, file_path: Path, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        """Custom regex frequency analysis."""
        regex_pattern = payload["pattern"]

        result = self._run_frequency_analysis(
            file_path=file_path,
            regex_pattern=regex_pattern,
            limit=payload.get("limit", 10),
            sample_lines=payload.get("sample_lines", 50000),
            full_log=payload.get("full_log", False),
        )

        result["mode"] = "regex"
        result["pattern_used"] = regex_pattern

        return ToolResult(ok=True, result=result)

    def _discover_patterns(
        self, file_path: Path, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        """Auto-discover log structural patterns."""
        sample_lines = payload.get("sample_lines", 50000)
        full_log = payload.get("full_log", False)
        ai_analysis = payload.get("ai_analysis", False)

        signatures: Counter = Counter()
        examples: dict[str, str] = {}
        lines_read = 0
        max_lines = float("inf") if full_log else sample_lines

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if lines_read >= max_lines:
                    break

                line = line.strip()
                if not line:
                    continue

                lines_read += 1

                # Generate structural signature
                signature = line
                for pat, token in DISCOVER_ABSTRACTION_PATTERNS:
                    signature = re.sub(pat, token, signature)

                if len(signature) > 300:
                    signature = signature[:300] + "..."

                signatures[signature] += 1
                if signature not in examples:
                    examples[signature] = line

        if not signatures:
            return ToolResult(
                ok=False,
                error_code="INTERNAL_ERROR",
                message="File is empty or contains no readable text.",
            )

        # Build structured output
        top_patterns = []
        for sig, count in signatures.most_common(5):
            pct = (count / lines_read) * 100
            top_patterns.append({
                "signature": sig,
                "count": count,
                "percentage": round(pct, 1),
                "example": examples[sig],
            })

        result_data: dict[str, Any] = {
            "mode": "discover",
            "lines_processed": lines_read,
            "matches_found": lines_read,
            "scan_type": "full" if full_log else f"sample({sample_lines})",
            "unique_patterns": len(signatures),
            "patterns": top_patterns,
        }

        # Optional LLM analysis
        if ai_analysis and context and hasattr(context, "llm_query") and context.llm_query:
            ai_text = self._request_ai_analysis(
                file_path.name, top_patterns, context
            )
            if ai_text:
                result_data["ai_analysis"] = ai_text

        return ToolResult(ok=True, result=result_data)

    # -------------------------------------------------------------------
    # Shared helpers
    # -------------------------------------------------------------------

    def _run_frequency_analysis(
        self,
        file_path: Path,
        regex_pattern: str,
        limit: int,
        sample_lines: int,
        full_log: bool,
    ) -> dict[str, Any]:
        """Core frequency analysis shared by grok and regex modes."""
        compiled = re.compile(regex_pattern)
        counter: Counter = Counter()
        sample_records: dict[str, list[str]] = defaultdict(list)
        max_samples = 3

        lines_processed = 0
        matches_found = 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                lines_processed += 1

                if not full_log and lines_processed > sample_lines:
                    break

                match = compiled.search(line)
                if match:
                    val = match.group(1) if match.groups() else match.group(0)
                    counter[val] += 1
                    matches_found += 1

                    if len(sample_records[val]) < max_samples:
                        sample_records[val].append(line.strip()[:200])

        top_results = []
        for value, count in counter.most_common(limit):
            top_results.append({
                "value": value,
                "count": count,
                "samples": sample_records.get(value, []),
            })

        return {
            "lines_processed": lines_processed,
            "matches_found": matches_found,
            "scan_type": "full" if full_log else f"sample({sample_lines})",
            "top_results": top_results,
        }

    def _resolve_file(self, file_path: str, context: Any) -> Path | None:
        """Resolve file path, checking artifact registry if available."""
        # Direct path
        p = Path(file_path)
        if p.exists():
            return p

        # Try resolving through artifact registry
        if context and hasattr(context, "artifacts"):
            for art in (context.artifacts or []):
                if hasattr(art, "file_path"):
                    art_path = Path(art.file_path)
                    if art_path.name == p.name and art_path.exists():
                        return art_path

        return None

    def _request_ai_analysis(
        self,
        file_name: str,
        patterns: list[dict[str, Any]],
        context: Any,
    ) -> str | None:
        """Request LLM interpretation of discovered patterns."""
        try:
            pattern_summary = []
            for p in patterns:
                pattern_summary.append(
                    f"Pattern ({p['count']} occurrences, {p['percentage']}%):\n"
                    f"  Signature: {p['signature']}\n"
                    f"  Example:   {p['example']}"
                )

            prompt = (
                f"You are a Tier 3 SOC analyst. Analyze the following log patterns "
                f"discovered in file '{file_name}'.\n\n"
                + "\n\n".join(pattern_summary)
                + "\n\nProvide:\n"
                "1. What technology/application generated these logs\n"
                "2. Key security-relevant observations\n"
                "3. Threat assessment (severity, indicators of compromise)\n"
                "4. Recommended next analysis steps with specific regex patterns "
                "the analyst can use in Event Mill's log_pattern_analyzer (regex mode) "
                "and log_searcher tools\n"
                "Be thorough. This is a real investigation."
            )

            llm_response = context.llm_query.query_text(prompt=prompt, max_tokens=4096)
            if llm_response.ok:
                return llm_response.text
            import logging
            logging.getLogger("eventmill.plugin.log_pattern_analyzer").warning(
                "AI analysis request failed: %s", llm_response.error
            )
            return None
        except Exception as e:
            import logging
            logging.getLogger("eventmill.plugin.log_pattern_analyzer").warning(
                "AI analysis error: %s", e
            )
            return None
