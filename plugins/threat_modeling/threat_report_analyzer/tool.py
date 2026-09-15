"""
Threat Report Analyzer — Summarize threat intelligence reports from common bucket.

Reads threat intelligence reports (MITRE ATT&CK, CAPEC, CISA advisories, vendor
bulletins) from the common bucket and generates 1500-2000 word markdown summaries
for use as context in other analysis tools.

Conforms to EventMillToolProtocol with three actions:
- list_reports: List available reports in common bucket
- summarize: Generate LLM-powered summary of a specific report
- search_reports: Search across report content
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.llm.providers import max_output_tokens_for_tier, thinking_reserve_tokens
from framework.logging.structured import log_llm_interaction
from framework.plugins.protocol import ArtifactRef, QueryHints


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
class Chunk:
    index: int
    content: str
    token_estimate: int
    source_type: str
    page_start: int | None = None
    page_end: int | None = None


# Reasoning depth for the native whole-PDF pass. Pinned rather than left to the
# provider default, because the defaults disagree — gcp_gemini declares medium
# and anthropic high — so a call naming no level gets a different depth per
# vendor for identical work, and a budget sized against one vendor's reserve is
# wrong for the other. The three levels below are what every provider's heavy
# tier accepts; "minimal" is declared only by gcp_gemini.
NATIVE_THINKING_LEVELS = ("low", "medium", "high")

# medium, because this pass runs against a whole document and thinking_level
# dominates latency — the 180 s client deadline is the real ceiling here, not
# the token cap.
DEFAULT_NATIVE_THINKING_LEVEL = "medium"

# Operator override for the above, mirroring EVENTMILL_PROJECTION_THINKING in
# adversary_path_projector: Cloud Run has latency headroom an interactive
# session does not, and that is a deployment decision rather than a code edit.
NATIVE_THINKING_ENV_OVERRIDE = "EVENTMILL_REPORT_NATIVE_THINKING"


def _native_thinking_level() -> str:
    """Reasoning depth for the whole-PDF pass: env override > the constant.

    Read at call time rather than import time so a .env loaded after this
    module is imported still takes effect, and so tests can set it without
    reloading. An unusable value warns and falls back rather than failing the
    run — an operator typo should not cost a summary.
    """
    value = (os.environ.get(NATIVE_THINKING_ENV_OVERRIDE) or "").strip().lower()
    if not value:
        return DEFAULT_NATIVE_THINKING_LEVEL
    if value in NATIVE_THINKING_LEVELS:
        return value
    logging.getLogger("eventmill.plugin.threat_report_analyzer").warning(
        "Ignoring %s=%r — must be one of: %s. Using %r.",
        NATIVE_THINKING_ENV_OVERRIDE, value,
        ", ".join(NATIVE_THINKING_LEVELS), DEFAULT_NATIVE_THINKING_LEVEL,
    )
    return DEFAULT_NATIVE_THINKING_LEVEL


def _budget(tier: str, thinking_level: str, content_tokens: int) -> int:
    """Output budget that leaves room for both thinking and content.

    Gemini spends thinking from the reply budget, so a bare content figure is
    silently a thinking cap. Ask for the content plus the reserve the provider
    declares for the level actually requested, bounded by the tier cap.
    """
    cap = max_output_tokens_for_tier(tier)
    return min(cap, content_tokens + thinking_reserve_tokens(thinking_level))


SUMMARIZATION_PROMPT_TEMPLATE = """You are a Senior Threat Intelligence Analyst creating a concise reference document.

SOURCE REPORT: {report_name}
SOURCE TYPE: {report_type}
WORD LIMIT: {max_words} words

INSTRUCTIONS:
1. Create a comprehensive 1500-2000 word summary suitable for security analysts
2. Focus on actionable intelligence: attack techniques, threat actors, mitigations
3. Include specific MITRE ATT&CK technique IDs where applicable
4. Highlight detection opportunities and SIEM-relevant indicators
5. Use clear section headers for scannability

FOCUS AREAS (if specified): {focus_areas}

REPORT CONTENT:
{content}

Generate a well-structured markdown summary with:
- Executive Summary (2-3 sentences)
- Key Threat Actors/Techniques
- Relevant ATT&CK Techniques (with IDs)
- Detection Opportunities
- Recommended Security Controls
- Sources and References

Output ONLY the markdown summary, no preamble."""


CHUNK_SUMMARIZATION_PROMPT_TEMPLATE = """You are a Senior Threat Intelligence Analyst summarizing one section of a larger threat report.

SOURCE REPORT: {report_name}
SOURCE TYPE: {report_type}
SECTION: {page_info}
WORD LIMIT: 800-1500 words

INSTRUCTIONS:
1. Summarize this section focusing on actionable threat intelligence
2. Include specific MITRE ATT&CK technique IDs (Txxxx format) where present
3. Note threat actors, malware families, and targeted industries
4. Highlight detection opportunities and indicators of compromise

FOCUS AREAS (if specified): {focus_areas}

SECTION CONTENT:
{content}

Generate a structured markdown summary with:
- Section Overview (1-2 sentences)
- Key Techniques & Tactics (with ATT&CK IDs)
- Threat Actors / Malware (if mentioned)
- Detection Opportunities
- Key Mitigations

Output ONLY the markdown summary, no preamble."""


SYNTHESIS_PROMPT_TEMPLATE = """You are a Senior Threat Intelligence Analyst synthesizing a complete threat report from section summaries.

SOURCE REPORT: {report_name}
TOTAL SECTIONS: {chunk_count}
TARGET LENGTH: {max_words} words

INSTRUCTIONS:
1. Synthesize the section summaries into a single cohesive intelligence report
2. Deduplicate and normalize all MITRE ATT&CK technique IDs
3. Identify overarching threat patterns that span multiple sections
4. Prioritize the most operationally relevant intelligence

FOCUS AREAS (if specified): {focus_areas}

SECTION SUMMARIES:
{chunk_summaries}

Generate a final markdown report with:
- Executive Summary (2-3 sentences)
- Key Threat Patterns
- Relevant ATT&CK Techniques (normalized, deduplicated list with IDs)
- Detection Opportunities
- Recommended Security Controls
- Sources and References

Output ONLY the markdown report, no preamble."""


class ThreatReportAnalyzer:
    """Analyze threat intelligence reports from common bucket.

    Actions:
    - list_reports: List available reports in common bucket
    - summarize: Generate LLM-powered summary of a report
    - search_reports: Search across report content
    """

    # Common bucket subdirectories for threat reports
    REPORT_DIRECTORIES = [
        "mitre",
        "capec",
        "cisa",
        "vendor_advisories",
        "threat_actors",
        "campaigns",
        "vulnerabilities",
    ]

    # File extensions to look for
    SUPPORTED_EXTENSIONS = {".json", ".pdf", ".xml", ".md", ".txt", ".csv", ".stix"}

    # Subdirectory within the common bucket where generated artifacts are written.
    # Convention: {common_bucket}/generated/{tool_name}/{source_relative_path}.summary.md
    # Other tools discover pre-built summaries by scanning common/generated/.
    GENERATED_BASE = "generated"

    # Guard refusals that mean "this provider will not take this document",
    # as opposed to a transport or model failure. The difference decides
    # whether falling back to extracted text is a reasonable degradation or a
    # way of hiding the operator's decision from them: a provider that cannot
    # read the PDF at all is a choice to make (run it on a provider with
    # larger limits, or split the document), not a condition to work around
    # by silently analysing worse input.
    PROVIDER_LIMIT_REFUSALS = frozenset({
        "pdf_exceeds_provider_page_limit",
        "pdf_exceeds_provider_size_limit",
        "pdf_exceeds_context_at_resolution",
        "pdf_exceeds_context_at_all_resolutions",
    })

    # (document_pages, pages_read) from the most recent _split_pdf_into_chunks
    # call, or None when the text path did not run (native ingestion read the
    # whole document, so coverage is total by construction).
    _last_pdf_pages: tuple[int, int] | None = None

    # Local intake and chunking limits. These are NOT provider limits and
    # must not be read as any: what a vendor accepts lives in
    # framework/llm/providers/<id>.json and is enforced by the dispatcher's
    # PDF guard against the provider actually routed to. These two bound what
    # this process will read off disk with pypdf — a resource ceiling, which
    # is the plugin's own business.
    #
    # They previously held 50 MB / 1000 pages, which are Gemini's figures, and
    # read as though the plugin were deciding provider policy. Anthropic and
    # OpenAI accept 100 pages / 32 MB, so the numbers were also wrong for two
    # of the three vendors.
    MAX_LOCAL_PDF_BYTES = 200 * 1024 * 1024
    MAX_LOCAL_PDF_PAGES = 2000
    MAX_PAGES_PER_CHUNK = 100
    MAX_TOKENS_PER_CHUNK = 100_000
    MAX_TEXT_TOKENS_SINGLE_PASS = 150_000
    CHARS_PER_TOKEN = 4

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "threat_report_analyzer",
            "version": "1.0.0",
            "pillar": "threat_modeling",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        action = payload.get("action")
        if not action:
            errors.append("'action' is required")
        elif action not in ("list_reports", "summarize", "search_reports"):
            errors.append(
                f"Invalid action '{action}'. Must be list_reports, summarize, or search_reports."
            )

        if action == "summarize" and not payload.get("report_path"):
            errors.append("'report_path' is required for summarize action")

        if action == "search_reports" and not payload.get("query"):
            errors.append("'query' is required for search_reports action")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute threat report analysis action."""
        action = payload["action"]

        try:
            if action == "list_reports":
                return self._list_reports(context)
            elif action == "summarize":
                return self._summarize_report(payload, context)
            elif action == "search_reports":
                return self._search_reports(payload, context)
            else:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_VALIDATION_FAILED",
                    message=f"Unknown action: {action}",
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
            return f"threat_report_analyzer failed: {result.message}"

        data = result.result or {}
        action = data.get("action", "unknown")

        if action == "list_reports":
            reports = data.get("reports", [])
            return f"Found {len(reports)} threat reports in common bucket: {', '.join(r.get('relative_path', r['name']) for r in reports[:10])}"

        elif action == "summarize":
            summaries = data.get("summaries", [])
            if summaries:
                s = summaries[0]
                wc = s.get("word_count", 0)
                chunks = s.get("chunk_count", 1)
                stored = s.get("summary_path")
                location = f" → {stored}" if stored else ""
                chunk_info = f", {chunks} chunk(s)" if chunks > 1 else ""
                dropped = s.get("pages_dropped") or 0
                coverage = ""
                if dropped:
                    # Stated first and in full: a reader told only what the
                    # summary contains cannot tell what was never read.
                    coverage = (
                        f" INCOMPLETE COVERAGE: only {s.get('pages_read')} of "
                        f"{s.get('pages_total')} pages were read; {dropped} "
                        f"pages were not examined, so a topic missing here may "
                        f"simply be in the part that was not read."
                    )
                return (
                    f"Summarized {s['report_path']} ({wc} words{chunk_info})"
                    f"{location}.{coverage}"
                )
            return "Report summarized"

        elif action == "search_reports":
            results = data.get("search_results", [])
            total_matches = sum(len(r.get("matches", [])) for r in results)
            return f"Search found {total_matches} matches across {len(results)} reports"

        return f"threat_report_analyzer completed action '{action}'."

    # -------------------------------------------------------------------
    # Action implementations
    # -------------------------------------------------------------------

    def _list_reports(self, context: Any) -> ToolResult:
        """List available threat reports in common bucket."""
        reports = []

        common_path = self._get_common_bucket_path(context)

        if common_path and common_path.exists():
            reports = self._scan_directory(common_path)

        if not reports:
            # Try GCS bucket directly (handles local dev pointing at real GCS)
            gcs_reports = self._scan_gcs_bucket(self._get_common_bucket_name(context))
            if gcs_reports:
                reports = gcs_reports
            else:
                # Final fallback: local reference data
                local_reports = self._scan_local_reference_data()
                reports.extend(local_reports)

        for report in reports:
            summary_path = self._summary_output_path(report["relative_path"], context)
            report["has_summary"] = summary_path is not None and summary_path.exists()
            if report["has_summary"]:
                common_path = self._get_common_bucket_path(context)
                if common_path:
                    try:
                        report["summary_relative_path"] = str(
                            summary_path.relative_to(common_path)
                        ).replace("\\", "/")
                    except ValueError:
                        pass

        return ToolResult(
            ok=True,
            result={
                "action": "list_reports",
                "reports": reports,
            },
            message=f"Found {len(reports)} threat reports",
        )

    def _summarize_report(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Generate LLM-powered summary of a threat report, with chunking for large files."""
        report_path = payload["report_path"]
        max_words = payload.get("max_word_count", 2000)
        focus_areas = payload.get("focus_areas", [])

        report_type = self._get_report_type(report_path)
        report_name = report_path.rsplit("/", 1)[-1] if "/" in report_path else report_path
        file_ext = Path(report_name).suffix.lower()
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")

        # Coverage is unknown until something reads the document; a value left
        # over from a previous run would describe the wrong report.
        self._last_pdf_pages = None
        # One stamp for every file this run writes, so a run's summary and its
        # chunk summaries sort together in the bucket.
        stamp = self._run_stamp()

        # --- Build chunks based on file type ---
        chunks: list[Chunk] = []

        # --- Native PDF path: send full document to LLM directly ---
        native_pdf_succeeded = False
        native_summary: str | None = None
        native_techniques: list[str] = []

        if file_ext == ".pdf":
            file_obj = self._resolve_report_path(report_path, context)
            if not file_obj:
                return ToolResult(
                    ok=False,
                    error_code="ARTIFACT_NOT_FOUND",
                    message=f"Report not found: {report_path}",
                )
            size_bytes = file_obj.stat().st_size
            if size_bytes > self.MAX_LOCAL_PDF_BYTES:
                # A local resource ceiling, deliberately generous. The
                # provider's own limit is smaller and is enforced downstream
                # against whichever provider is routed to, so this message
                # must not quote a vendor figure.
                return ToolResult(
                    ok=False,
                    error_code="ARTIFACT_TOO_LARGE",
                    message=(
                        f"PDF is {size_bytes // 1024 // 1024} MB, above this "
                        f"tool's local read ceiling of "
                        f"{self.MAX_LOCAL_PDF_BYTES // 1024 // 1024} MB: "
                        f"{report_path}. Split the document."
                    ),
                )

            # Attempt native PDF ingestion before text extraction
            if (context and hasattr(context, "llm_query") and context.llm_query
                    and hasattr(context.llm_query, "supports_native_document")
                    and context.llm_query.supports_native_document("application/pdf")):
                _log.info(
                    "Native PDF ingestion available — attempting "
                    "query_with_document() for %s", report_name,
                )
                native_prompt = SUMMARIZATION_PROMPT_TEMPLATE.format(
                    report_name=report_name,
                    report_type=report_type,
                    max_words=max_words,
                    focus_areas=(
                        ", ".join(focus_areas) if focus_areas
                        else "General threat overview"
                    ),
                    content=(
                        "[Full PDF document is attached — analyze the "
                        "complete document directly instead of this "
                        "placeholder text.]"
                    ),
                )
                # Build a lightweight ArtifactRef for the resolved file
                artifact_ref = ArtifactRef(
                    artifact_id=f"tra_native_{report_name}",
                    artifact_type="pdf_report",
                    file_path=str(file_obj),
                    metadata={"mime_type": "application/pdf"},
                )
                native_level = _native_thinking_level()
                try:
                    native_response = context.llm_query.query_with_document(
                        prompt=native_prompt,
                        artifact=artifact_ref,
                        system_context=(
                            "You are a Senior Threat Intelligence Analyst. "
                            "Produce a well-structured markdown summary."
                        ),
                        max_tokens=_budget("heavy", native_level, max_words * 8),
                        hints=QueryHints(
                            tier="heavy",
                            thinking_level=native_level,
                            prefers_native_file=True,
                        ),
                    )
                    log_llm_interaction(
                        prompt=f"[tra native_pdf] {native_prompt[:500]}",
                        response_text=native_response.text,
                        model_id=(
                            native_response.model_used
                            or "threat_report_analyzer"
                        ),
                        error=(
                            str(native_response.error)
                            if not native_response.ok else None
                        ),
                    )
                    if native_response.ok and native_response.text:
                        native_summary = native_response.text.strip()
                        native_techniques = self._extract_techniques(native_summary)
                        native_pdf_succeeded = True
                        _log.info(
                            "Native PDF summarization succeeded "
                            "(transport=%s, model=%s, words=%d, techniques=%d)",
                            native_response.transport_path,
                            native_response.model_used,
                            len(native_summary.split()),
                            len(native_techniques),
                        )
                    elif (native_response.fallback_reason
                            in self.PROVIDER_LIMIT_REFUSALS):
                        # The provider will not take this document. Falling
                        # back to pypdf text would return a summary that looks
                        # like every other summary while being built from
                        # markedly worse input, with the reason visible only
                        # in the logs. Surface the choice instead.
                        _log.warning(
                            "Native PDF refused by provider policy (%s) — "
                            "not falling back to text | %s",
                            native_response.fallback_reason,
                            native_response.error,
                        )
                        return ToolResult(
                            ok=False,
                            error_code="ARTIFACT_TOO_LARGE",
                            message=(
                                f"{native_response.error} "
                                f"This tool reads the PDF natively, so it "
                                f"cannot analyse a document the selected "
                                f"provider will not accept. Either point this "
                                f"tool at a provider with larger limits "
                                f"('use gcp_gemini for threat_report_analyzer') "
                                f"or split {report_path} and summarize the "
                                f"parts."
                            ),
                        )
                    else:
                        _log.warning(
                            "Native PDF query returned failure — "
                            "falling back to chunked text path "
                            "| ok=%s, error=%r, model=%s, "
                            "transport=%s, fallback_reason=%s",
                            native_response.ok,
                            native_response.error,
                            native_response.model_used,
                            native_response.transport_path,
                            native_response.fallback_reason,
                        )
                except Exception as e:
                    _log.error(
                        "Native PDF path exception — "
                        "falling back to chunked text path "
                        "| exception_type=%s, message=%s",
                        type(e).__name__, e,
                        exc_info=True,
                    )

            # Fall back to text extraction + chunking if native path didn't work
            if not native_pdf_succeeded:
                chunks = self._split_pdf_into_chunks(file_obj)
                if not chunks:
                    content = self._read_report_content(report_path, context)
                    if not content:
                        return ToolResult(
                            ok=False,
                            error_code="PARSE_FAILED",
                            message=f"PDF text extraction failed: {report_path}",
                        )
                    chunks = self._split_text_into_chunks(content)
        else:
            content = self._read_report_content(report_path, context)
            if not content:
                return ToolResult(
                    ok=False,
                    error_code="ARTIFACT_NOT_FOUND",
                    message=f"Report not found: {report_path}",
                )
            token_est = self.estimate_tokens(content)
            _log.info("Estimated %d tokens for %s", token_est, report_name)
            if token_est > self.MAX_TEXT_TOKENS_SINGLE_PASS:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_TOO_LARGE",
                    message=(
                        f"Text input (~{token_est:,} tokens) exceeds "
                        f"{self.MAX_TEXT_TOKENS_SINGLE_PASS:,} token limit. "
                        "Provide the report as a PDF for automatic chunking."
                    ),
                )
            chunks = self._split_text_into_chunks(content)

        # --- Use native summary or fall back to chunk-by-chunk ---
        chunk_artifacts: list[dict[str, Any]] = []

        if native_pdf_succeeded and native_summary:
            final_summary = native_summary
            relevant_techniques = native_techniques
            effective_chunk_count = 1
            _log.info(
                "Skipping chunked text path — native PDF "
                "summarization succeeded"
            )
        else:
            # Summarize each chunk
            chunk_summaries: list[dict[str, Any]] = []

            is_single_chunk = len(chunks) == 1
            for chunk in chunks:
                cs = self._summarize_chunk(
                    chunk, report_name, report_type, focus_areas, context,
                    max_words=max_words if is_single_chunk else None,
                )
                chunk_summaries.append(cs)
                if len(chunks) > 1:
                    artifact = self._write_chunk_artifact(
                        cs, report_path, context, stamp,
                    )
                    if artifact:
                        chunk_artifacts.append(artifact)

            # Synthesize
            if len(chunk_summaries) == 1:
                final_summary = chunk_summaries[0]["summary"]
                relevant_techniques = chunk_summaries[0].get("techniques", [])
            else:
                final_summary = self._synthesize_summaries(
                    chunk_summaries, report_name, focus_areas, max_words, context
                )
                relevant_techniques = list(
                    {t for cs in chunk_summaries for t in cs.get("techniques", [])}
                )
            effective_chunk_count = len(chunks)

        key_findings = self._extract_key_findings(final_summary)
        word_count = len(final_summary.split())

        # --- Persist final summary ---
        output_artifacts: list[dict[str, Any]] = list(chunk_artifacts)
        summary_relative = None
        summary_path = self._summary_export_path(report_path, context, stamp)
        if summary_path:
            try:
                summary_path.parent.mkdir(parents=True, exist_ok=True)
                summary_path.write_text(final_summary, encoding="utf-8")
                common_path = self._get_common_bucket_path(context)
                if common_path:
                    summary_relative = str(
                        summary_path.relative_to(common_path)
                    ).replace("\\", "/")
                output_artifacts.append(
                    {
                        "artifact_type": "text/markdown",
                        "file_path": str(summary_path),
                        "relative_path": summary_relative or str(summary_path),
                        "source_tool": "threat_report_analyzer",
                    }
                )
            except Exception as e:
                _log.warning("Failed to persist final summary: %s", e)
        else:
            # No local mirror — upload directly to GCS
            normalized = report_path.replace("\\", "/")
            gcs_object = (
                f"{self.GENERATED_BASE}/threat_report_analyzer/"
                f"{self._export_name(normalized, stamp, 'summary.md')}"
            )
            if self._upload_to_gcs(final_summary, gcs_object, context):
                bucket_name = self._get_common_bucket_name(context)
                summary_relative = f"gs://{bucket_name}/{gcs_object}"
                output_artifacts.append(
                    {
                        "artifact_type": "text/markdown",
                        "gcs_uri": summary_relative,
                        "relative_path": gcs_object,
                        "source_tool": "threat_report_analyzer",
                    }
                )

        return ToolResult(
            ok=True,
            result={
                "action": "summarize",
                "summaries": [
                    {
                        "report_path": report_path,
                        "summary_path": summary_relative,
                        "chunk_count": effective_chunk_count,
                        "word_count": word_count,
                        **self._coverage_fields(),
                        "summary": final_summary,
                        "key_findings": key_findings,
                        "relevant_techniques": relevant_techniques,
                    }
                ],
                "artifacts_created": [
                    a.get("relative_path", a.get("file_path", ""))
                    for a in chunk_artifacts
                ],
            },
            output_artifacts=output_artifacts or None,
            message=(
                f"Summarized {report_path} "
                f"({'native PDF' if native_pdf_succeeded else f'{effective_chunk_count} chunk(s)'}, "
                f"{word_count} words)"
            ),
        )

    def _search_reports(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Search across threat report content."""
        query = payload["query"].lower()
        search_results = []

        # Get all reports
        reports = []
        common_path = self._get_common_bucket_path(context)

        if common_path and common_path.exists():
            reports = self._scan_directory(common_path)

        # Search each report
        for report in reports:
            local_file = report.get("local_path")
            if not local_file:
                continue

            try:
                local_path_obj = Path(local_file)
                if not local_path_obj.exists():
                    continue
                if local_path_obj.suffix.lower() == ".pdf":
                    raw = self._extract_pdf_text(local_path_obj)
                    content = raw.lower() if raw else ""
                else:
                    with open(local_file, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read().lower()

                # Find matches
                matches = []
                for i, line in enumerate(content.split("\n"), 1):
                    if query in line:
                        matches.append(f"Line {i}: {line.strip()[:200]}")

                if matches:
                    search_results.append(
                        {
                            "report_path": report.get("relative_path", report.get("name", "")),
                            "name": report.get("name", ""),
                            "subdirectory": report.get("subdirectory", ""),
                            "matches": matches[:20],
                        }
                    )
            except Exception:
                continue

        return ToolResult(
            ok=True,
            result={
                "action": "search_reports",
                "query": payload["query"],
                "search_results": search_results,
            },
            message=f"Search found {len(search_results)} reports with matches",
        )

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _get_generated_path(self, context: Any) -> Path | None:
        """Return the generated artifacts directory for this tool within the common bucket."""
        common_path = self._get_common_bucket_path(context)
        if common_path is None:
            return None
        generated = common_path / self.GENERATED_BASE / "threat_report_analyzer"
        generated.mkdir(parents=True, exist_ok=True)
        return generated

    @staticmethod
    def _run_stamp() -> str:
        """UTC stamp identifying one run's exports.

        Basic ISO 8601, so it sorts lexicographically in the order it sorts
        chronologically — which is what a bucket listing gives you.
        """
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    @staticmethod
    def _export_name(normalized: str, stamp: str, suffix: str) -> str:
        """``<source path>.<stamp>.<suffix>`` for one exported file.

        The stamp goes before the suffix, not after, so anything globbing for
        ``*.summary.md`` keeps matching. Runs no longer overwrite each other:
        the same report summarised twice leaves both copies, which is the
        intent — storage is cheap and a replaced summary cannot be compared
        against the one it replaced.
        """
        return f"{normalized}.{stamp}.{suffix}"

    def _coverage_fields(self) -> dict[str, Any]:
        """Page coverage for the report just processed.

        Empty when nothing measured it, which means native ingestion read the
        whole document — coverage is total by construction there and claiming
        a page count the plugin never counted would be worse than saying
        nothing.
        """
        if not self._last_pdf_pages:
            return {}
        document_pages, pages_read = self._last_pdf_pages
        return {
            "pages_total": document_pages,
            "pages_read": pages_read,
            "pages_dropped": max(0, document_pages - pages_read),
        }

    def _summary_export_path(
        self, report_relative_path: str, context: Any, stamp: str,
    ) -> Path | None:
        """Where this run writes its summary, mirroring the source directory."""
        generated = self._get_generated_path(context)
        if generated is None:
            return None
        normalized = report_relative_path.replace("\\", "/")
        output = generated / self._export_name(normalized, stamp, "summary.md")
        output.parent.mkdir(parents=True, exist_ok=True)
        return output

    def _summary_output_path(self, report_relative_path: str, context: Any) -> Path | None:
        """The newest existing summary for a report, or None if there is none.

        Used to answer "has this been summarised?", which a stamped filename
        cannot answer by existence check alone. Unstamped summaries written
        before stamping are still found, so nothing already in the bucket
        becomes invisible.
        """
        generated = self._get_generated_path(context)
        if generated is None:
            return None
        normalized = report_relative_path.replace("\\", "/")
        legacy = generated / (normalized + ".summary.md")
        stamped = sorted(
            (generated / normalized).parent.glob(
                Path(normalized).name + ".*.summary.md"
            ),
            reverse=True,
        )
        # Exclude chunk summaries, which share the prefix.
        stamped = [p for p in stamped if ".chunk_" not in p.name]
        if stamped:
            return stamped[0]
        return legacy

    def _get_common_bucket_name(self, context: Any) -> str:
        """Return the common GCS bucket name from context config or environment.

        Reads EVENTMILL_BUCKET_PREFIX and EVENTMILL_BUCKET_COMMON from
        context.config first, then falls back to os.environ.  context.config
        is an empty dict by default, so the env-var fallback is always tried.
        """
        config = {}
        if context and hasattr(context, "config"):
            config = context.config or {}
        bucket_prefix = (
            config.get("EVENTMILL_BUCKET_PREFIX")
            or os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
        )
        override = (
            config.get("EVENTMILL_BUCKET_COMMON")
            or os.environ.get("EVENTMILL_BUCKET_COMMON")
        )
        return override or f"{bucket_prefix}-common"

    def _get_common_bucket_path(self, context: Any) -> Path | None:
        """Get the local filesystem path for the common bucket (local dev only).

        Returns None when running in Cloud Run (K_SERVICE set) or when the
        local mirror directory does not exist.  Callers that need GCS access
        should use _get_common_bucket_name() and the GCS helpers directly.
        """
        if os.environ.get("K_SERVICE"):
            return None
        common_bucket = self._get_common_bucket_name(context)
        workspace_path = Path.cwd() / "workspace" / "storage" / common_bucket
        return workspace_path if workspace_path.exists() else None

    def estimate_tokens(self, text: str) -> int:
        """Estimate LLM token count (~4 characters per token)."""
        return max(1, len(text) // self.CHARS_PER_TOKEN)

    def _resolve_report_path(self, report_path: str, context: Any) -> Path | None:
        """Resolve a report path to an absolute local Path, downloading from GCS if needed."""
        # 1. Direct filesystem path
        file_path = Path(report_path)
        if file_path.exists():
            return file_path
        # 2. Local common bucket mirror
        common_path = self._get_common_bucket_path(context)
        if common_path:
            normalized = report_path.replace("\\", "/")
            candidate = common_path / Path(normalized)
            if candidate.exists():
                return candidate
        # 3. Download from GCS on demand
        return self._download_from_gcs(self._get_common_bucket_name(context), report_path)

    def _extract_pdf_text(self, file_path: Path) -> str | None:
        """Extract all text from a PDF file page-by-page using pypdf."""
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")
        try:
            import pypdf
        except ImportError:
            _log.warning("pypdf not installed; cannot extract PDF text from %s", file_path)
            return None
        try:
            reader = pypdf.PdfReader(str(file_path))
            pages = []
            for page in reader.pages:
                try:
                    pages.append(page.extract_text() or "")
                except Exception:
                    pages.append("")
            raw = "\n\n".join(pages)
            return self._normalize_pdf_text(raw) if raw else None
        except Exception as e:
            _log.error("PDF text extraction failed for %s: %s", file_path, e)
            return None

    @staticmethod
    def _normalize_pdf_text(text: str) -> str:
        """Normalize fragmented PDF text where each word appears on its own line.

        pypdf's extract_text() can produce one token per line for PDFs that lay
        out text character-by-character or use certain composite fonts.  This
        method detects that pattern and joins the fragments into readable prose,
        preserving paragraph breaks, bullet points, and headings.
        """

        def join_fragments(frags: list[str]) -> str:
            joined = " ".join(frags)
            joined = re.sub(r"(\w)-\s(\w)", r"\1\2", joined)  # fix hyphenation
            return re.sub(r"  +", " ", joined).strip()

        result_blocks: list[str] = []
        for block in re.split(r"\n{2,}", text):
            lines = [l.strip() for l in block.split("\n") if l.strip()]
            if not lines:
                continue

            avg_len = sum(len(l) for l in lines) / len(lines)
            if avg_len >= 30:
                result_blocks.append("\n".join(lines))
                continue

            # Fragmented — join intelligently preserving structure
            buf: list[str] = []
            out: list[str] = []

            for line in lines:
                if re.match(r"^\d{1,3}$", line):  # standalone page numbers
                    continue
                if re.match(r"^[•\-–*]\s|^\d+\.\s", line):  # bullet / numbered list
                    if buf:
                        out.append(join_fragments(buf))
                        buf = []
                    out.append(line)
                else:
                    buf.append(line)

            if buf:
                out.append(join_fragments(buf))

            result_blocks.append("\n".join(out))

        return "\n\n".join(result_blocks)

    def _split_pdf_into_chunks(
        self, file_path: Path, max_pages_per_chunk: int | None = None
    ) -> list[Chunk]:
        """Split a PDF into page-range Chunks, each under MAX_PAGES_PER_CHUNK."""
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")
        try:
            import pypdf
        except ImportError:
            _log.warning("pypdf not installed; PDF chunking unavailable for %s", file_path.name)
            return []
        max_pages = max_pages_per_chunk or self.MAX_PAGES_PER_CHUNK
        chunks: list[Chunk] = []
        try:
            reader = pypdf.PdfReader(str(file_path))
            document_pages = len(reader.pages)
            total_pages = min(document_pages, self.MAX_LOCAL_PDF_PAGES)
            # Recorded so the caller can report coverage. A summary built from
            # part of a report must say so: "not mentioned" and "never read"
            # are different answers, and only one of them is about the report.
            self._last_pdf_pages = (document_pages, total_pages)
            if total_pages < document_pages:
                _log.warning(
                    "PDF %s: read %d of %d pages — pages %d-%d were NOT "
                    "examined and nothing in them reaches this summary. "
                    "Split the document to cover it fully.",
                    file_path.name, total_pages, document_pages,
                    total_pages + 1, document_pages,
                )
            else:
                _log.info(
                    "PDF %s: %d pages, all read", file_path.name, document_pages,
                )
            for start in range(0, total_pages, max_pages):
                end = min(start + max_pages, total_pages)
                texts = []
                for i in range(start, end):
                    try:
                        texts.append(reader.pages[i].extract_text() or "")
                    except Exception:
                        texts.append("")
                content = self._normalize_pdf_text("\n\n".join(texts))
                chunks.append(
                    Chunk(
                        index=len(chunks),
                        content=content,
                        token_estimate=self.estimate_tokens(content),
                        source_type="pdf_pages",
                        page_start=start + 1,
                        page_end=end,
                    )
                )
        except Exception as e:
            _log.error("PDF chunking failed for %s: %s", file_path.name, e)
        return chunks

    def _split_text_into_chunks(
        self, text: str, max_tokens: int | None = None
    ) -> list[Chunk]:
        """Split plain text into Chunks bounded by MAX_TOKENS_PER_CHUNK on paragraph breaks."""
        limit = max_tokens or self.MAX_TOKENS_PER_CHUNK
        max_chars = limit * self.CHARS_PER_TOKEN
        if len(text) <= max_chars:
            return [
                Chunk(
                    index=0,
                    content=text,
                    token_estimate=self.estimate_tokens(text),
                    source_type="text",
                )
            ]
        chunks: list[Chunk] = []
        paragraphs = text.split("\n\n")
        current: list[str] = []
        current_len = 0
        for para in paragraphs:
            para_len = len(para) + 2
            if current_len + para_len > max_chars and current:
                content = "\n\n".join(current)
                chunks.append(
                    Chunk(
                        index=len(chunks),
                        content=content,
                        token_estimate=self.estimate_tokens(content),
                        source_type="text",
                    )
                )
                current = [para]
                current_len = para_len
            else:
                current.append(para)
                current_len += para_len
        if current:
            content = "\n\n".join(current)
            chunks.append(
                Chunk(
                    index=len(chunks),
                    content=content,
                    token_estimate=self.estimate_tokens(content),
                    source_type="text",
                )
            )
        return chunks

    def _summarize_chunk(
        self,
        chunk: Chunk,
        report_name: str,
        report_type: str,
        focus_areas: list[str],
        context: Any,
        max_words: int | None = None,
    ) -> dict[str, Any]:
        """Summarize one chunk.  When max_words is supplied this is a single-chunk
        report and the full SUMMARIZATION_PROMPT_TEMPLATE is used so the user's
        word-count target is respected.  Multi-chunk reports use the section prompt.
        """
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")
        page_info = (
            f"pages {chunk.page_start}\u2013{chunk.page_end}"
            if chunk.page_start is not None
            else f"chunk {chunk.index + 1}"
        )
        if max_words is not None:
            # Single-pass — use the full report prompt so word limit is respected
            prompt = SUMMARIZATION_PROMPT_TEMPLATE.format(
                report_name=report_name,
                report_type=report_type,
                max_words=max_words,
                focus_areas=", ".join(focus_areas) if focus_areas else "General threat overview",
                content=chunk.content,
            )
            out_tokens = _budget("light", "low", max_words * 8)  # ~8 chars/token
        else:
            prompt = CHUNK_SUMMARIZATION_PROMPT_TEMPLATE.format(
                report_name=report_name,
                report_type=report_type,
                page_info=page_info,
                focus_areas=", ".join(focus_areas) if focus_areas else "General threat overview",
                content=chunk.content,
            )
            out_tokens = _budget("light", "low", 3072)
        summary_text = chunk.content[:3000]
        techniques: list[str] = []
        if context and hasattr(context, "llm_query") and context.llm_query:
            try:
                # Per-chunk summarization is bulk, repetitive work — pin it to
                # the light tier instead of letting out_tokens decide the model.
                # The heavy tier is reserved for the synthesis pass below.
                response = context.llm_query.query_text(
                    prompt=prompt,
                    max_tokens=out_tokens,
                    # Bulk, repetitive work: light tier and shallow thinking.
                    # The heavy tier and default thinking are reserved for the
                    # synthesis pass, which reasons across every chunk.
                    hints=QueryHints(tier="light", thinking_level="low"),
                )
                log_llm_interaction(
                    prompt=f"[tra chunk {chunk.index}] {prompt[:500]}",
                    response_text=response.text,
                    model_id=response.model_used or "threat_report_analyzer",
                    error=str(response.error) if not response.ok else None,
                )
                if response.ok:
                    summary_text = response.text.strip()
                    techniques = self._extract_techniques(summary_text)
            except Exception as e:
                _log.warning("Chunk summarization failed (chunk %d): %s", chunk.index, e)
        return {
            "chunk_index": chunk.index,
            "page_start": chunk.page_start,
            "page_end": chunk.page_end,
            "source_type": chunk.source_type,
            "token_estimate": chunk.token_estimate,
            "summary": summary_text,
            "techniques": techniques,
        }

    def _synthesize_summaries(
        self,
        chunk_summaries: list[dict[str, Any]],
        report_name: str,
        focus_areas: list[str],
        max_words: int,
        context: Any,
    ) -> str:
        """Second-pass synthesis: combine chunk summaries into a final cohesive report."""
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")

        def _label(cs: dict[str, Any]) -> str:
            if cs.get("page_start") is not None:
                return f"Pages {cs['page_start']}\u2013{cs['page_end']}"
            return f"Chunk {cs['chunk_index'] + 1}"

        combined = "\n\n---\n\n".join(
            f"[{_label(cs)}]\n{cs['summary']}" for cs in chunk_summaries
        )
        prompt = SYNTHESIS_PROMPT_TEMPLATE.format(
            report_name=report_name,
            chunk_count=len(chunk_summaries),
            max_words=max_words,
            focus_areas=", ".join(focus_areas) if focus_areas else "General threat overview",
            chunk_summaries=combined,
        )
        if context and hasattr(context, "llm_query") and context.llm_query:
            try:
                # Synthesis reasons across every chunk summary at once — this is
                # the pass that earns the heavy tier (the manifest default).
                response = context.llm_query.query_text(
                    prompt=prompt,
                    max_tokens=_budget("heavy", "high", max_words * 8),
                    hints=QueryHints(tier="heavy", thinking_level="high"),
                )
                log_llm_interaction(
                    prompt=f"[tra synthesis] {prompt[:500]}",
                    response_text=response.text,
                    model_id=response.model_used or "threat_report_analyzer",
                    error=str(response.error) if not response.ok else None,
                )
                if response.ok:
                    return response.text.strip()
            except Exception as e:
                _log.warning("Synthesis pass failed: %s", e)
        return combined

    def _write_chunk_artifact(
        self,
        chunk_summary: dict[str, Any],
        report_path: str,
        context: Any,
        stamp: str,
    ) -> dict[str, Any] | None:
        """Persist a chunk summary to disk (or GCS) and return its artifact descriptor.

        Takes the run's *stamp* rather than making its own, so every file one
        run writes carries the same one and they group together in the bucket.
        """
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")
        idx = chunk_summary["chunk_index"]
        normalized = report_path.replace("\\", "/")
        suffix = f"chunk_{idx:03d}.summary.md"
        generated = self._get_generated_path(context)

        if generated is not None:
            # Local mirror path
            chunk_file = generated / self._export_name(normalized, stamp, suffix)
            chunk_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                chunk_file.write_text(chunk_summary["summary"], encoding="utf-8")
                common_path = self._get_common_bucket_path(context)
                relative = None
                if common_path:
                    try:
                        relative = str(chunk_file.relative_to(common_path)).replace("\\", "/")
                    except ValueError:
                        pass
                return {
                    "artifact_type": "text/markdown",
                    "tag": "threat_summary_chunk",
                    "file_path": str(chunk_file),
                    "relative_path": relative or str(chunk_file),
                    "source_tool": "threat_report_analyzer",
                    "metadata": {
                        "source_report": report_path,
                        "chunk_index": idx,
                        "page_start": chunk_summary.get("page_start"),
                        "page_end": chunk_summary.get("page_end"),
                        "extracted_techniques": chunk_summary.get("techniques", []),
                    },
                }
            except Exception as e:
                _log.warning("Failed to write chunk artifact: %s", e)
                return None
        else:
            # No local mirror — upload chunk to GCS
            gcs_object = (
                f"{self.GENERATED_BASE}/threat_report_analyzer/"
                f"{self._export_name(normalized, stamp, suffix)}"
            )
            if self._upload_to_gcs(chunk_summary["summary"], gcs_object, context):
                bucket_name = self._get_common_bucket_name(context)
                return {
                    "artifact_type": "text/markdown",
                    "tag": "threat_summary_chunk",
                    "gcs_uri": f"gs://{bucket_name}/{gcs_object}",
                    "relative_path": gcs_object,
                    "source_tool": "threat_report_analyzer",
                    "metadata": {
                        "source_report": report_path,
                        "chunk_index": idx,
                        "page_start": chunk_summary.get("page_start"),
                        "page_end": chunk_summary.get("page_end"),
                        "extracted_techniques": chunk_summary.get("techniques", []),
                    },
                }
            return None

    def _scan_directory(self, base_path: Path) -> list[dict[str, Any]]:
        """Scan a directory for threat report files, preserving nested relative paths."""
        reports = []

        for ext in self.SUPPORTED_EXTENSIONS:
            for file_path in base_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    try:
                        size = file_path.stat().st_size
                        relative = file_path.relative_to(base_path)
                        parts = relative.parts
                        if parts[0] == self.GENERATED_BASE:
                            continue
                        reports.append(
                            {
                                "name": file_path.name,
                                "relative_path": str(relative).replace("\\", "/"),
                                "subdirectory": parts[0] if len(parts) > 1 else "",
                                "depth": len(parts) - 1,
                                "size_bytes": size,
                                "local_path": str(file_path),
                            }
                        )
                    except Exception:
                        continue

        return sorted(reports, key=lambda r: r["relative_path"])

    def _scan_local_reference_data(self) -> list[dict[str, Any]]:
        """Scan local reference data directory as fallback."""
        reports = []
        ref_data_path = Path(__file__).parent.parent.parent / "framework" / "reference_data"

        if ref_data_path.exists():
            for file_path in ref_data_path.rglob("*"):
                if file_path.is_file() and file_path.suffix in self.SUPPORTED_EXTENSIONS:
                    try:
                        size = file_path.stat().st_size
                        relative = file_path.relative_to(ref_data_path)
                        parts = relative.parts
                        reports.append(
                            {
                                "name": file_path.name,
                                "relative_path": str(relative).replace("\\", "/"),
                                "subdirectory": parts[0] if len(parts) > 1 else "",
                                "depth": len(parts) - 1,
                                "size_bytes": size,
                                "local_path": str(file_path),
                            }
                        )
                    except Exception:
                        continue

        return sorted(reports, key=lambda r: r["relative_path"])

    def _scan_gcs_bucket(self, bucket_name: str) -> list[dict[str, Any]]:
        """List threat reports directly from a GCS bucket.

        Used when the local common-bucket mirror does not exist, i.e. local
        development pointing at a real GCS bucket.  Returns an empty list if
        google-cloud-storage is not installed or credentials are unavailable.
        """
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")
        try:
            from google.cloud import storage as gcs_storage
        except ImportError:
            _log.warning(
                "google-cloud-storage not installed; GCS listing unavailable for %s", bucket_name
            )
            return []
        try:
            project = os.environ.get("GCP_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
            client = gcs_storage.Client(project=project)
            reports = []
            for blob in client.list_blobs(bucket_name):
                suffix = Path(blob.name).suffix.lower()
                if suffix not in self.SUPPORTED_EXTENSIONS:
                    continue
                parts = Path(blob.name).parts
                if parts and parts[0] == self.GENERATED_BASE:
                    continue
                reports.append(
                    {
                        "name": Path(blob.name).name,
                        "relative_path": blob.name.replace("\\", "/"),
                        "subdirectory": parts[0] if len(parts) > 1 else "",
                        "depth": len(parts) - 1,
                        "size_bytes": blob.size or 0,
                        "local_path": None,
                        "gcs_uri": f"gs://{bucket_name}/{blob.name}",
                    }
                )
            return sorted(reports, key=lambda r: r["relative_path"])
        except Exception as e:
            _log.warning("GCS bucket scan failed (%s): %s", bucket_name, e)
            return []

    def _download_from_gcs(self, bucket_name: str, object_path: str) -> Path | None:
        """Download a GCS object to a local temp file and return the path.

        Used by _resolve_report_path when the file is not present in the local
        common-bucket mirror.  The caller is responsible for the temp file; it
        will be cleaned up by the OS on process exit.
        """
        import tempfile

        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")
        try:
            from google.cloud import storage as gcs_storage
        except ImportError:
            _log.warning("google-cloud-storage not installed; cannot download from GCS")
            return None
        try:
            normalized = object_path.replace("\\", "/")
            project = os.environ.get("GCP_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
            client = gcs_storage.Client(project=project)
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(normalized)
            if not blob.exists():
                _log.warning("GCS object not found: gs://%s/%s", bucket_name, normalized)
                return None
            suffix = Path(normalized).suffix or ".bin"
            fd, tmp_path = tempfile.mkstemp(suffix=suffix)
            os.close(fd)
            blob.download_to_filename(tmp_path)
            _log.info("Downloaded gs://%s/%s → %s", bucket_name, normalized, tmp_path)
            return Path(tmp_path)
        except Exception as e:
            _log.warning("GCS download failed (%s/%s): %s", bucket_name, object_path, e)
            return None

    def _upload_to_gcs(self, content: str, object_path: str, context: Any) -> bool:
        """Upload text content to a GCS object in the common bucket.

        Used to persist generated summaries when no local common-bucket mirror
        exists (local dev pointing at real GCS, or Cloud Run).
        Returns True on success, False on any failure.
        """
        _log = logging.getLogger("eventmill.plugin.threat_report_analyzer")
        bucket_name = self._get_common_bucket_name(context)
        try:
            from google.cloud import storage as gcs_storage
        except ImportError:
            _log.warning("google-cloud-storage not installed; cannot upload to GCS")
            return False
        try:
            project = os.environ.get("GCP_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
            client = gcs_storage.Client(project=project)
            blob = client.bucket(bucket_name).blob(object_path)
            blob.upload_from_string(
                content.encode("utf-8"),
                content_type="text/markdown; charset=utf-8",
            )
            _log.info("Uploaded summary → gs://%s/%s", bucket_name, object_path)
            return True
        except Exception as e:
            _log.warning("GCS upload failed (%s/%s): %s", bucket_name, object_path, e)
            return False

    def _read_report_content(self, report_path: str, context: Any) -> str | None:
        """Read content from a report file, resolving paths at any nesting depth."""
        file_path = self._resolve_report_path(report_path, context)
        if file_path is None:
            return None
        if file_path.suffix.lower() == ".pdf":
            return self._extract_pdf_text(file_path)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return None

    def _get_report_type(self, report_path: str) -> str:
        """Determine report type from path."""
        path_lower = report_path.lower()

        if "mitre" in path_lower or "attack" in path_lower:
            return "MITRE ATT&CK Framework"
        elif "capec" in path_lower:
            return "CAPEC (Common Attack Pattern Enumeration)"
        elif "cisa" in path_lower or "kev" in path_lower:
            return "CISA Advisory"
        elif "vendor" in path_lower or "msrc" in path_lower:
            return "Vendor Security Advisory"
        elif "threat_actor" in path_lower:
            return "Threat Actor Profile"
        elif "campaign" in path_lower:
            return "Threat Campaign Report"
        elif "vulnerability" in path_lower or "cve" in path_lower:
            return "Vulnerability Report"
        else:
            return "Threat Intelligence Report"

    def _extract_key_findings(self, summary: str) -> list[str]:
        """Extract key findings from summary."""
        findings = []

        # Look for bullet points or numbered items
        lines = summary.split("\n")
        for line in lines:
            line = line.strip()
            if line and (line.startswith("- ") or line.startswith("* ")):
                finding = line[2:].strip()
                if finding and len(finding) > 10:
                    findings.append(finding)
            elif line and re.match(r"^\d+[\.\)]\s", line):
                match = re.match(r"^\d+[\.\)]\s(.+)", line)
                if match:
                    findings.append(match.group(1).strip())

        return findings[:10]  # Limit to 10 findings

    def _extract_techniques(self, summary: str) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from summary."""
        # Match patterns like T1234, T1566, etc.
        techniques = re.findall(r"T\d{4}(?:\.\d{3})?", summary)
        return list(set(techniques))[:20]  # Dedupe and limit
