"""
Log Investigator — AI-powered threat investigation and SOC analyst workflows.

Ported from Event Mill v1.0 investigation.py with improvements:
- Conforms to EventMillToolProtocol
- Decoupled from GCS (works with local files via artifact registry)
- Structured JSON output
- LLM integration via ExecutionContext.llm_query
- Predefined SOC workflows: top_talkers, investigate_ip, security_events, attack_patterns
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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


# Sampling budget for the LLM investigation prompt.
# Log lines tokenize densely (IPs, timestamps, paths) at roughly 3 chars/token,
# so 400k chars is ~130k tokens — about 13% of a 1,048,576-token context window.
# The char budget binds before the line count on wide lines, which is intended:
# the cap self-adjusts to line width instead of trusting a raw line count.
DEFAULT_CONTEXT_LINES = 500
MAX_SAMPLE_CHARS = 400_000
MAX_LINE_CHARS = 1_000

# Predefined security-relevant regex patterns for workflows
WORKFLOW_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "top_talkers": [
        ("IP Addresses", r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        ("HTTP Methods", r"\"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|PROPFIND|CONNECT|TRACE)\s"),
        ("Status Codes", r"\s(\d{3})\s"),
    ],
    "security_events": [
        ("HTTP Errors", r"\s(4\d{2}|5\d{2})\s"),
        ("Suspicious Methods", r"\"(PROPFIND|CONNECT|TRACE|TRACK|DEBUG)\s"),
        ("Error Messages", r"(?i)(error|failed|denied|forbidden|unauthorized)"),
        ("SQL Injection", r"(?i)(union.*select|drop.*table|insert.*into)"),
        ("XSS Attempts", r"(?i)(<script|javascript:|onload=|onerror=)"),
    ],
}

INVESTIGATION_PROMPT_TEMPLATE = """You are a Senior Security Analyst investigating a potential security incident.

INVESTIGATION TARGET: "{search_term}"
LOG FILE: {file_name}
TOTAL MATCHES: {total_matches} occurrences in {lines_scanned} lines

SAMPLE LOG ENTRIES{sampling_note}:
{sample_logs}

ANALYSIS REQUIRED:
1. **Identification**: What type of entity is "{search_term}"? (IP address, username, error code, malware signature, etc.)

2. **Threat Assessment**: Based on the log patterns:
   - Is this activity suspicious or malicious?
   - What is the severity level? (Critical/High/Medium/Low/Informational)
   - Are there indicators of compromise (IoCs)?

3. **Threat Intelligence**: Search your knowledge for:
   - Known malicious indicators matching this pattern
   - Associated threat actors or campaigns
   - Relevant CVEs or attack techniques (MITRE ATT&CK)

4. **Timeline Analysis**: What does the activity timeline suggest?

5. **Recommended Actions**:
   - Immediate containment steps
   - Further investigation queries
   - Evidence preservation
   - Escalation criteria

6. **Detection Rules**: Suggest detection logic or SIEM rules to catch similar activity.

Provide a structured, actionable security analysis. Keep response under 800 words."""


class LogInvestigator:
    """AI-powered threat investigation and SOC analyst workflows.

    Two modes:
    - investigate: Targeted search + LLM threat intelligence analysis
    - workflow: Predefined SOC patterns (top_talkers, investigate_ip, security_events, attack_patterns)
    """

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "log_investigator",
            "version": "1.0.0",
            "pillar": "log_analysis",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        if "mode" not in payload:
            errors.append("'mode' is required (investigate or workflow)")
        elif payload["mode"] not in ("investigate", "workflow"):
            errors.append(f"Invalid mode '{payload['mode']}'. Must be investigate or workflow.")

        if "file_path" not in payload:
            errors.append("'file_path' is required")

        mode = payload.get("mode")
        if mode == "investigate" and not payload.get("search_term"):
            errors.append("'search_term' is required for investigate mode")

        if mode == "workflow":
            wt = payload.get("workflow_type")
            valid_workflows = ("top_talkers", "investigate_ip", "security_events", "attack_patterns")
            if not wt:
                errors.append("'workflow_type' is required for workflow mode")
            elif wt not in valid_workflows:
                errors.append(f"Invalid workflow_type '{wt}'. Available: {', '.join(valid_workflows)}")
            if wt == "investigate_ip" and not payload.get("target"):
                errors.append("'target' IP is required for investigate_ip workflow")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute investigation or workflow."""
        mode = payload["mode"]
        file_path = payload["file_path"]

        resolved = self._resolve_file(file_path, context)
        if resolved is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"File not found: {file_path}",
            )

        try:
            if mode == "investigate":
                return self._investigate(resolved, payload, context)
            elif mode == "workflow":
                return self._run_workflow(resolved, payload, context)
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
        """Compress output for LLM context."""
        if not result.ok:
            return f"log_investigator failed: {result.message}"

        data = result.result or {}
        mode = data.get("mode", "unknown")

        if mode == "investigate":
            term = data.get("search_term", "?")
            total = data.get("total_matches", 0)
            scanned = data.get("lines_scanned", 0)
            parts = [f"Investigation of '{term}': {total} matches in {scanned} lines."]

            # Say when the analysis saw only a subset, so downstream context
            # does not read the findings as full coverage.
            sampling = data.get("sampling") or {}
            sampled = sampling.get("sampled", 0)
            if sampled and sampled < total:
                parts.append(
                    f"AI analysis reviewed {sampled} of {total} matches "
                    f"({sampling.get('strategy', 'sampled')})."
                )

            ai = data.get("ai_analysis")
            if ai:
                truncated = ai[:1500] + "..." if len(ai) > 1500 else ai
                parts.append(truncated)
            else:
                samples = data.get("sample_matches", [])
                for s in samples[:5]:
                    parts.append(f"  {s[:120]}")

            return "\n".join(parts)

        elif mode == "workflow":
            wtype = data.get("workflow_type", "?")
            sections = data.get("workflow_results", [])
            parts = [f"SOC Workflow '{wtype}': {len(sections)} analysis sections."]

            for sec in sections[:4]:
                parts.append(f"\n  {sec['section']}:")
                for entry in sec.get("entries", [])[:5]:
                    if "count" in entry:
                        parts.append(f"    {entry['value']}: {entry['count']}")
                    elif "line" in entry:
                        parts.append(f"    {entry['line'][:100]}")

            return "\n".join(parts)

        return f"log_investigator completed mode '{mode}'."

    # -------------------------------------------------------------------
    # Investigation mode
    # -------------------------------------------------------------------

    def _investigate(
        self, file_path: Path, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        """Targeted investigation with LLM threat analysis."""
        search_term = payload["search_term"]
        context_lines = payload.get("context_lines", DEFAULT_CONTEXT_LINES)

        matching_lines: list[str] = []
        lines_scanned = 0
        total_matches = 0
        needle = search_term.lower()

        # Always scan the whole file. Counting is decoupled from collection:
        # stopping early once the buffer filled made total_matches and
        # lines_scanned wrong, and the prompt reports both to the model as the
        # basis for severity and timeline analysis. Reading is cheap — the LLM
        # call is the expensive part, not the scan.
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                lines_scanned += 1
                if needle in line.lower():
                    total_matches += 1
                    if len(matching_lines) < context_lines:
                        matching_lines.append(line.strip()[:MAX_LINE_CHARS])

        result_data: dict[str, Any] = {
            "mode": "investigate",
            "search_term": search_term,
            "file_path": str(file_path),
            "lines_scanned": lines_scanned,
            "total_matches": total_matches,
            "sample_matches": matching_lines[:20],
        }

        if not matching_lines:
            result_data["ai_analysis"] = None
            result_data["sampling"] = {
                "total_matches": 0,
                "sampled": 0,
                "strategy": "none",
                "truncated_by": None,
            }
            return ToolResult(ok=True, result=result_data)

        sample, strategy, truncated_by = self._select_sample(
            matching_lines, total_matches,
        )
        result_data["sampling"] = {
            "total_matches": total_matches,
            "sampled": len(sample),
            "strategy": strategy,
            "truncated_by": truncated_by,
        }

        # LLM threat intelligence analysis
        ai_text = self._request_ai_investigation(
            file_name=file_path.name,
            search_term=search_term,
            sample_lines=sample,
            sampling_note=self._sampling_note(
                len(sample), total_matches, strategy,
            ),
            lines_scanned=lines_scanned,
            total_matches=total_matches,
            context=context,
        )
        result_data["ai_analysis"] = ai_text

        return ToolResult(ok=True, result=result_data)

    @staticmethod
    def _select_sample(
        matching_lines: list[str],
        total_matches: int,
        char_budget: int = MAX_SAMPLE_CHARS,
    ) -> tuple[list[str], str, str | None]:
        """Choose a representative subset of matches within a char budget.

        First-N is a poor choice for security logs: an attack starting late in
        the file would never be seen. When the retained matches exceed the
        budget, take the first quarter, the last quarter, and an evenly strided
        middle half — preserving onset, recency, and spread.

        Returns (lines, strategy, truncated_by) where truncated_by is
        "char_budget", "line_count", or None.
        """
        if not matching_lines:
            return [], "none", None

        def _fits(lines: list[str]) -> bool:
            return sum(len(line) + 1 for line in lines) <= char_budget

        truncated_by = "line_count" if len(matching_lines) < total_matches else None

        if _fits(matching_lines):
            strategy = (
                f"all {len(matching_lines)} retained matches"
                if truncated_by is None
                else f"first {len(matching_lines)} of {total_matches} matches"
            )
            return matching_lines, strategy, truncated_by

        # Binary-search the largest head+tail+stride selection that fits.
        lo, hi, best = 1, len(matching_lines), 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if _fits(LogInvestigator._stride_select(matching_lines, mid)):
                best, lo = mid, mid + 1
            else:
                hi = mid - 1

        selected = LogInvestigator._stride_select(matching_lines, best)
        head = tail = best // 4
        middle = best - head - tail
        step = max(1, (len(matching_lines) - head - tail) // max(1, middle))
        strategy = (
            f"first {head}, last {tail}, every {step}th match in between"
        )
        return selected, strategy, "char_budget"

    @staticmethod
    def _stride_select(lines: list[str], count: int) -> list[str]:
        """Take first 25%, last 25%, and an evenly strided middle 50%."""
        n = len(lines)
        if count >= n:
            return list(lines)
        if count <= 2:
            return lines[:count]

        head = tail = count // 4
        middle = count - head - tail
        head_part = lines[:head]
        tail_part = lines[n - tail:] if tail else []

        mid_lo, mid_hi = head, n - tail
        span = mid_hi - mid_lo
        if middle <= 0 or span <= 0:
            return head_part + tail_part
        step = span / middle
        mid_part = [
            lines[min(mid_hi - 1, int(mid_lo + i * step))]
            for i in range(middle)
        ]
        return head_part + mid_part + tail_part

    @staticmethod
    def _sampling_note(sampled: int, total_matches: int, strategy: str) -> str:
        """Phrase for the prompt so the model knows the sample is partial."""
        if sampled >= total_matches:
            return ""
        return f" (showing {sampled:,} of {total_matches:,} matches — {strategy})"

    def _request_ai_investigation(
        self,
        file_name: str,
        search_term: str,
        sample_lines: list[str],
        sampling_note: str,
        lines_scanned: int,
        total_matches: int,
        context: Any,
    ) -> str | None:
        """Request LLM-powered threat investigation."""
        if not context or not hasattr(context, "llm_query") or not context.llm_query:
            return None

        try:
            sample_logs = "\n".join(sample_lines)
            prompt = INVESTIGATION_PROMPT_TEMPLATE.format(
                search_term=search_term,
                file_name=file_name,
                total_matches=total_matches,
                lines_scanned=lines_scanned,
                sampling_note=sampling_note,
                sample_logs=sample_logs,
            )

            # The prompt asks for "under 800 words" (~1,100 tokens); 4096 is
            # ample. Stated explicitly so it is a decision, not an inherited
            # default. Tier comes from the manifest (model_tier: heavy).
            response = context.llm_query.query_text(prompt=prompt, max_tokens=4096)
            if response.ok:
                return response.text
            return None
        except Exception:
            return None

    # -------------------------------------------------------------------
    # Workflow mode
    # -------------------------------------------------------------------

    def _run_workflow(
        self, file_path: Path, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        """Execute predefined SOC analyst workflow."""
        workflow_type = payload["workflow_type"]

        if workflow_type == "top_talkers":
            return self._workflow_pattern_scan(file_path, "top_talkers")

        elif workflow_type == "investigate_ip":
            return self._workflow_investigate_ip(file_path, payload.get("target", ""))

        elif workflow_type == "security_events":
            return self._workflow_pattern_scan(file_path, "security_events")

        elif workflow_type == "attack_patterns":
            return self._workflow_attack_patterns(file_path)

        return ToolResult(
            ok=False,
            error_code="INPUT_VALIDATION_FAILED",
            message=f"Unknown workflow: {workflow_type}",
        )

    def _workflow_pattern_scan(
        self, file_path: Path, workflow_key: str
    ) -> ToolResult:
        """Scan log with predefined regex patterns and return frequency counts."""
        patterns = WORKFLOW_PATTERNS.get(workflow_key, [])
        sections: list[dict[str, Any]] = []

        for section_name, pattern in patterns:
            counter: Counter = Counter()
            compiled = re.compile(pattern)

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    match = compiled.search(line)
                    if match:
                        val = match.group(1) if match.groups() else match.group(0)
                        counter[val] += 1

            if counter:
                entries = [
                    {"value": val, "count": count}
                    for val, count in counter.most_common(10)
                ]
                sections.append({"section": section_name, "entries": entries})

        return ToolResult(
            ok=True,
            result={
                "mode": "workflow",
                "workflow_type": workflow_key,
                "file_path": str(file_path),
                "workflow_results": sections,
            },
        )

    def _workflow_investigate_ip(
        self, file_path: Path, target_ip: str
    ) -> ToolResult:
        """Find all log lines containing a specific IP address."""
        ip_pattern = re.compile(re.escape(target_ip))
        matches: list[dict[str, Any]] = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                if ip_pattern.search(line):
                    matches.append({"line": f"L{line_num}: {line.strip()[:200]}"})
                    if len(matches) >= 50:
                        break

        return ToolResult(
            ok=True,
            result={
                "mode": "workflow",
                "workflow_type": "investigate_ip",
                "file_path": str(file_path),
                "target": target_ip,
                "workflow_results": [
                    {"section": f"IP Activity: {target_ip}", "entries": matches}
                ],
            },
        )

    def _workflow_attack_patterns(self, file_path: Path) -> ToolResult:
        """Quick attack pattern scan using structural signature discovery."""
        # Reuse the discover logic inline (lightweight version)
        abstraction_patterns = [
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>"),
            (r"\d{4}-\d{2}-\d{2}", "<DATE>"),
            (r"\d{2}/\w{3}/\d{4}", "<DATE>"),
            (r"\d{2}:\d{2}:\d{2}", "<TIME>"),
            (r"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)", "<METHOD>"),
            (r"0x[0-9a-fA-F]+", "<HEX>"),
            (r"\b\d+\b", "<NUM>"),
        ]

        signatures: Counter = Counter()
        examples: dict[str, str] = {}
        lines_read = 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                lines_read += 1
                if lines_read > 500:
                    break

                sig = stripped
                for pat, token in abstraction_patterns:
                    sig = re.sub(pat, token, sig)
                if len(sig) > 200:
                    sig = sig[:200] + "..."

                signatures[sig] += 1
                if sig not in examples:
                    examples[sig] = stripped

        entries = []
        for sig, count in signatures.most_common(5):
            pct = (count / lines_read) * 100 if lines_read else 0
            entries.append({
                "value": f"[{pct:.0f}%] {sig[:120]}",
                "count": count,
                "line": examples[sig][:200],
            })

        return ToolResult(
            ok=True,
            result={
                "mode": "workflow",
                "workflow_type": "attack_patterns",
                "file_path": str(file_path),
                "lines_sampled": lines_read,
                "workflow_results": [
                    {"section": "Structural Patterns", "entries": entries}
                ],
            },
        )

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _resolve_file(self, file_path: str, context: Any) -> Path | None:
        """Resolve file path, checking artifact registry if available."""
        p = Path(file_path)
        if p.exists() and p.is_file():
            return p

        if context and hasattr(context, "artifacts"):
            for art in (context.artifacts or []):
                if hasattr(art, "file_path"):
                    art_path = Path(art.file_path)
                    if art_path.name == p.name and art_path.exists():
                        return art_path

        return None
