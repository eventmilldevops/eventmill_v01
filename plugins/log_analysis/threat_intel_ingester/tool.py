"""
Threat Intel Ingester — Event Mill Plugin

Ingests threat intelligence reports (PDF, HTML, STIX, CSV/JSON IOC lists)
and extracts structured IOC data with MITRE ATT&CK mapping.

This plugin depends on LLM capabilities for contextual IOC extraction
and MITRE technique inference. Regex-based extraction provides a baseline;
LLM analysis provides confidence scoring and priority assessment.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from framework.logging.structured import log_llm_interaction
from framework.documents import (
    LatencyModel,
    PageRange,
    PdfSplitError,
    bisect_range,
    plan_ingestion,
    profile_document,
    split_pdf,
)
from framework.llm.providers import OutputLimits, output_limits
from framework.plugins.protocol import ArtifactRef, QueryHints, ToolResult, ValidationResult
from framework.reference_data.mitre_attack import LEGACY_TACTIC_ALIASES
from framework.reference_data.mitre_attack import TACTIC_ORDER as _TACTIC_SEQUENCE
from framework.reference_data.mitre_attack import canonical_tactic as _canonical_tactic
from framework.reference_data.mitre_attack import get_mitre_db as _get_mitre_db
from framework.reference_data.mitre_attack import is_legacy_tactic as _is_legacy_tactic
from framework.reference_data.mitre_attack import (
    resolve_legacy_tactic as _resolve_legacy_tactic,
)
from framework.reference_data.mitre_attack import (
    resolve_retired_technique as _resolve_retired_technique,
)
from framework.reference_data.mitre_attack import (
    retirement_note as _retirement_note,
)

logger = logging.getLogger("eventmill.plugin.threat_intel_ingester")

# ---------------------------------------------------------------------------
# IOC Regex Patterns
# ---------------------------------------------------------------------------

IOC_PATTERNS = {
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)(?:\.|\[\.\]))"
        r"{3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.|\[\.\]))+(?:com|net|org|io|info|biz|xyz|top|"
        r"ru|cn|de|uk|fr|jp|br|au|ca|nl|it|es|ch|se|no|fi|"
        r"dk|be|at|pl|cz|sk|hu|ro|bg|hr|si|lt|lv|ee|ie|pt|"
        r"gr|cy|lu|mt|li|is)\b",
        re.IGNORECASE,
    ),
    "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "hash_sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(
        r"(?:https?|hxxps?|ftp)(?:://|(?:\[:\]//))[\w\-._~:/?#\[\]@!$&'()*+,;=%]+",
        re.IGNORECASE,
    ),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "mitre_technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}

# Defanging reversal patterns
DEFANG_REPLACEMENTS = [
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
]


def refang(value: str) -> str:
    """Reverse common defanging patterns."""
    result = value
    for pattern, replacement in DEFANG_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    return result


def was_defanged(original: str, refanged: str) -> bool:
    """Check if the value was defanged in the original text."""
    return original != refanged


# ---------------------------------------------------------------------------
# MITRE ATT&CK Kill-Chain Ordering
# ---------------------------------------------------------------------------

# Tactic name -> 1-based kill-chain ordinal.  The sequence itself lives in
# framework.reference_data.mitre_attack so it stays in step with the ATT&CK
# release the technique database was built from.
TACTIC_ORDER: dict[str, int] = {
    tactic: ordinal for ordinal, tactic in enumerate(_TACTIC_SEQUENCE, start=1)
}

# Tactics introduced together as replacements for one retired tactic (v19:
# Stealth / Defense Impairment for Defense Evasion).  The LLM routinely picks
# the wrong one of the pair; when a technique allows exactly one of them the
# swap is unambiguous and is applied automatically.
_SIBLING_TACTIC_SETS: list[set[str]] = [
    set(successors) for successors in LEGACY_TACTIC_ALIASES.values()
]

# Tactics that should only appear at the entry point (first step) of a path.
# If a later step is assigned one of these and the technique has alternatives,
# the reconciler will reassign using the kill-chain ordering.
ENTRY_ONLY_TACTICS: set[str] = {"Reconnaissance", "Resource Development", "Initial Access"}


# ---------------------------------------------------------------------------
# Text Extraction Helpers
# ---------------------------------------------------------------------------


def extract_pdf_page_texts(
    file_path: str, max_pages: int | None = None
) -> list[str]:
    """Extract text per page from a PDF using pdfplumber.

    One entry per page in document order (empty string for pages with no
    extractable text), so list index + 1 is the 1-based page number used by
    page-range batching.

    ``max_pages`` of None reads the whole document, and is the default. The
    page limit belongs to the provider manifest; a second limit here would
    silently cap a document the selected provider could have taken whole.
    """
    try:
        import pdfplumber
    except ImportError:
        raise RuntimeError("pdfplumber is required for PDF processing")

    pages: list[str] = []
    with pdfplumber.open(file_path) as pdf:
        for i, page in enumerate(pdf.pages):
            if max_pages is not None and i >= max_pages:
                break
            pages.append(page.extract_text() or "")
    return pages


def pdf_page_total(file_path: str) -> int | None:
    """How many pages the PDF has, or None when that cannot be read.

    Needed only when extraction was capped: a capped read cannot report what
    it left behind, and counting the pages read as though they were the whole
    document is what made truncation invisible.
    """
    try:
        import pdfplumber
    except ImportError:
        return None
    try:
        with pdfplumber.open(file_path) as pdf:
            return len(pdf.pages)
    except Exception:
        return None


def extract_text_from_pdf(file_path: str, max_pages: int | None = None) -> str:
    """Extract text from a PDF file using pdfplumber."""
    return "\n\n".join(t for t in extract_pdf_page_texts(file_path, max_pages) if t)


def extract_text_from_html(file_path: str) -> str:
    """Extract text from an HTML file using BeautifulSoup."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        raise RuntimeError("beautifulsoup4 is required for HTML processing")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    # Remove script and style elements
    for element in soup(["script", "style", "nav", "footer", "header"]):
        element.decompose()

    return soup.get_text(separator="\n", strip=True)


def extract_text_from_text(file_path: str) -> str:
    """Read a plain text file (including Markdown)."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def extract_text_from_docx(file_path: str) -> str:
    """Extract text from a Word document using python-docx."""
    try:
        from docx import Document
    except ImportError:
        raise RuntimeError(
            "python-docx is required for Word document processing. "
            "Install with: pip install python-docx"
        )
    doc = Document(file_path)
    parts = []
    for para in doc.paragraphs:
        if para.text.strip():
            parts.append(para.text)
    # Also extract text from tables
    for table in doc.tables:
        for row in table.rows:
            row_text = "  ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
            if row_text:
                parts.append(row_text)
    return "\n".join(parts)


TEXT_EXTRACTORS = {
    "pdf_report": extract_text_from_pdf,
    "html_report": extract_text_from_html,
    "text": extract_text_from_text,
    "docx_report": extract_text_from_docx,
}


# ---------------------------------------------------------------------------
# Regex-Based IOC Extraction
# ---------------------------------------------------------------------------


@dataclass
class RawIOC:
    """An IOC extracted by regex before LLM refinement."""
    ioc_type: str
    value: str
    raw_value: str
    defanged: bool
    context: str = ""
    confidence: str = "low"
    priority: str = "medium"
    related_mitre: list[str] = field(default_factory=list)


def extract_iocs_regex(
    text: str,
    ioc_types: list[str],
) -> list[RawIOC]:
    """Extract IOCs from text using regex patterns.

    Returns deduplicated IOCs with surrounding context.
    """
    seen: set[tuple[str, str]] = set()
    results: list[RawIOC] = []

    for ioc_type in ioc_types:
        pattern = IOC_PATTERNS.get(ioc_type)
        if not pattern:
            continue

        for match in pattern.finditer(text):
            raw_value = match.group(0)
            value = refang(raw_value)
            defanged = was_defanged(raw_value, value)

            key = (ioc_type, value.lower())
            if key in seen:
                continue
            seen.add(key)

            # Extract surrounding context (up to 150 chars each side)
            start = max(0, match.start() - 150)
            end = min(len(text), match.end() + 150)
            context = text[start:end].replace("\n", " ").strip()

            results.append(
                RawIOC(
                    ioc_type=ioc_type,
                    value=value,
                    raw_value=raw_value,
                    defanged=defanged,
                    context=context[:300],
                    confidence="low",
                )
            )

    return results


# ---------------------------------------------------------------------------
# Chunked LLM processing helpers
# ---------------------------------------------------------------------------

# One taxonomy across both report tools; see threat_report_analyzer.
from framework.reference_data.mitre_attack import (  # noqa: E402
    attack_grounding,
)

_MAX_IOC_PER_CHUNK: int = 50        # IOC candidates per LLM call
_MAX_TEXT_CHARS_PER_CHUNK: int = 6_000  # Report text chars per LLM call

# Output-token cost model and density threshold live in framework.documents;
# these aliases keep the plugin's log messages and tests on the same numbers.
from framework.documents.profile import (  # noqa: E402
    IOC_DENSE_PER_PAGE as _IOC_DENSE_PER_PAGE,
    OUTPUT_TOKENS_BASE as _OUTPUT_TOKENS_BASE,
    OUTPUT_TOKENS_PER_CANDIDATE as _OUTPUT_TOKENS_PER_IOC,
)

# Thinking depth for the native PDF calls. Raised from "low" on 2026-09-12:
# reading a report is not pure pattern work, and the light tier's model reads
# PDFs better than the heavy tier's. Thinking tokens come out of the same
# budget as the reply, so _native_content_budget() holds more back and batches
# are smaller — that is the trade being made, not an oversight.
_NATIVE_THINKING_LEVEL: str = "medium"


@lru_cache(maxsize=1)
def _native_tier() -> str:
    """Tier the native PDF calls run on, read from this plugin's manifest.

    The calls pin no tier in QueryHints, so TierScopedLLMClient applies the
    manifest's model_tier and the manifest stays the one place the model is
    chosen. This reads the same value only to size the output budget against
    the cap of the model that will actually run.
    """
    try:
        with open(Path(__file__).parent / "manifest.json", encoding="utf-8") as f:
            return json.load(f).get("model_tier") or "light"
    except (OSError, json.JSONDecodeError, KeyError):
        return "light"

# Request deadline the LLM client enforces. All three clients agree on 180 s
# (clients/gemini.py http_options timeout, clients/anthropic.py and
# clients/openai.py `timeout`), and Gemini also sends it as a server deadline.
# This said 120 s and cited framework/llm/client.py, a module that no longer
# exists — understating the deadline splits a document into more batches than
# it needs, which costs per-call overhead and separates pages that should be
# read together.
_NATIVE_CALL_DEADLINE_S: float = 180.0

# A truncated batch is halved and retried; this bounds the extra calls that
# can generate, so a persistently bad estimate cannot loop.
_NATIVE_MAX_EXTRA_CALLS: int = 8


def _native_limits(llm_query: Any = None) -> OutputLimits:
    """Cap and thinking reserve of the provider serving this execution.

    Asked of the LLM handle, because only the framework knows which vendor the
    operator chose. Both figures used to be read from the default provider's
    manifest whatever was selected, so a run on OpenAI was sized with
    Gemini's numbers. A handle that cannot answer (a test fake, or no LLM)
    gets the default provider's figures, which is what every run used before.
    """
    ask = getattr(llm_query, "output_limits", None)
    if ask is not None:
        try:
            limits = ask(_native_tier(), _NATIVE_THINKING_LEVEL)
        except Exception:  # noqa: BLE001 - sizing must never fail the run
            limits = None
        if isinstance(limits, OutputLimits):
            return limits
    return output_limits(_native_tier(), _NATIVE_THINKING_LEVEL)


def _native_max_output_tokens(llm_query: Any = None) -> int:
    """What one native call may emit — the tier's real cap, not a guess."""
    return _native_limits(llm_query).max_output_tokens


def _native_content_budget(llm_query: Any = None) -> int:
    """Of that cap, how much can go to JSON once thinking has taken its share.

    Sizing batches against the full cap is what truncated replies mid-record:
    the model spends thinking tokens first and the answer is cut off with no
    error from the provider.
    """
    return _native_limits(llm_query).content_budget


def _latency_model() -> LatencyModel:
    """Native-call latency model, overridable per deployment via env vars."""
    def _env(name: str, default: float) -> float:
        raw = os.environ.get(name)
        try:
            return float(raw) if raw else default
        except ValueError:
            return default
    base = LatencyModel()
    return LatencyModel(
        base_seconds=_env("EVENTMILL_NATIVE_BASE_S", base.base_seconds),
        seconds_per_page=_env("EVENTMILL_NATIVE_S_PER_PAGE", base.seconds_per_page),
        seconds_per_candidate=_env(
            "EVENTMILL_NATIVE_S_PER_CANDIDATE", base.seconds_per_candidate
        ),
    )


def _page_iocs(page_texts: list[str], ioc_types: list[str]) -> list[list[RawIOC]]:
    """Regex candidates per page (deduplicated within a page)."""
    return [extract_iocs_regex(t, ioc_types) for t in page_texts]


@dataclass
class ChunkUnit:
    """One chunked LLM call's input: some text, and the candidates in it.

    The two used to be split independently - ``fallback_iocs`` sliced by index
    and ``fallback_text`` split by paragraph - and chunk *i* paired slice *i*
    with paragraph-chunk *i*, which have no relationship at all. On the
    whole-document path that put the first fifty candidates, in practice all
    of one type and drawn from anywhere in the report, beside the report's
    first 6,000 characters. A unit is the fix: the text is chosen first and
    the candidates are the ones that text contains.
    """
    text: str
    iocs: list[RawIOC]
    page_start: int | None = None
    page_end: int | None = None
    gap_before: bool = False
    gap_pages: tuple[int, int] | None = None

    @property
    def page_label(self) -> str | None:
        if self.page_start is None:
            return None
        if self.page_start == self.page_end:
            return f"page {self.page_start}"
        return f"pages {self.page_start}-{self.page_end}"


def _pack_pages(
    pages: list[int],
    page_texts: list[str],
    max_chars: int,
) -> list[tuple[list[int], str]]:
    """Group pages into runs of text under ``max_chars``, in page order.

    A page whose own text exceeds the budget is returned alone and is split
    further by the caller; nothing is dropped to make a page fit.
    """
    runs: list[tuple[list[int], str]] = []
    current: list[int] = []
    parts: list[str] = []
    size = 0
    for pg in pages:
        text = page_texts[pg - 1]
        if not text:
            continue
        cost = len(text) + 2
        if current and size + cost > max_chars:
            runs.append((current, "\n\n".join(parts)))
            current, parts, size = [], [], 0
        current.append(pg)
        parts.append(text)
        size += cost
    if current:
        runs.append((current, "\n\n".join(parts)))
    return runs


def _build_chunk_units(
    page_texts: list[str],
    page_iocs: list[list[RawIOC]],
    ioc_types: list[str],
    pages: list[int] | None = None,
    paged: bool = True,
    max_chars: int | None = None,
    max_iocs: int | None = None,
) -> list[ChunkUnit]:
    """Build the chunked path's calls, text first and candidates from that text.

    ``pages`` is the 1-based pages the chunked path has to cover: every page
    on a pure chunked run, only the pages the native path could not finish
    otherwise. Gaps between non-adjacent runs are marked so the prompt can say
    that the missing pages were read elsewhere rather than leaving the model
    to infer a jump in the narrative.

    Candidates are deduplicated across units as they always were, so a value
    seen on pages 3 and 40 is still asked about once - in the unit whose text
    contains it, which is the part that was wrong. Submitting it in both would
    pair it with each context at the cost of a longer prompt per repeat; that
    is a cost decision, not a correctness one, and it is not made here.

    A unit holding more than ``max_iocs`` candidates is split **within the
    unit**, every piece keeping the same text, so a candidate is never paired
    with text it did not come from just because its unit was crowded.
    """
    # Read at call time, not bound as a default: these are module-level
    # knobs, and a default argument would freeze whatever they were at import.
    if max_chars is None:
        max_chars = _MAX_TEXT_CHARS_PER_CHUNK
    if max_iocs is None:
        max_iocs = _MAX_IOC_PER_CHUNK
    if pages is None:
        pages = list(range(1, len(page_texts) + 1))

    units: list[ChunkUnit] = []
    requested = set(pages)
    prev_page: int | None = None
    for run_pages, run_text in _pack_pages(pages, page_texts, max_chars):
        start, end = run_pages[0], run_pages[-1]
        pieces: list[tuple[str, list[RawIOC]]]
        if len(run_text) > max_chars:
            # One page bigger than the whole budget. Split its text and
            # re-extract per piece: on a single-page artifact this is the only
            # thing standing between a candidate and text it never appeared in.
            pieces = [
                (part, extract_iocs_regex(part, ioc_types))
                for part in _chunk_text(run_text, max_chars)
            ]
        else:
            pieces = [(run_text, _dedupe_iocs(
                [ioc for pg in run_pages for ioc in page_iocs[pg - 1]]
            ))]
        for text, iocs in pieces:
            unit = ChunkUnit(
                text=text,
                iocs=iocs,
                page_start=start if paged else None,
                page_end=end if paged else None,
            )
            # A gap is pages this run was never asked to cover, not pages
            # that were skipped here for being blank - saying a blank page was
            # "analysed separately" would be a claim nobody can check.
            missing = sorted(set(range(prev_page + 1, start)) - requested) \
                if (paged and prev_page is not None) else []
            if missing:
                unit.gap_before = True
                unit.gap_pages = (missing[0], missing[-1])
            units.append(unit)
        prev_page = end

    # Deduplicate across units, keeping the first unit that holds each value.
    seen: set[tuple[str, str]] = set()
    for unit in units:
        kept = []
        for ioc in unit.iocs:
            key = (ioc.ioc_type, ioc.value.lower())
            if key in seen:
                continue
            seen.add(key)
            kept.append(ioc)
        unit.iocs = kept

    # Then cap, within the unit, so every piece keeps the text its candidates
    # were found in.
    capped: list[ChunkUnit] = []
    for unit in units:
        if len(unit.iocs) <= max_iocs:
            capped.append(unit)
            continue
        for i in range(0, len(unit.iocs), max_iocs):
            capped.append(ChunkUnit(
                text=unit.text,
                iocs=unit.iocs[i:i + max_iocs],
                page_start=unit.page_start,
                page_end=unit.page_end,
                gap_before=unit.gap_before if i == 0 else False,
                gap_pages=unit.gap_pages if i == 0 else None,
            ))
    return capped


def _unit_report_text(unit: ChunkUnit) -> str:
    """The text as the prompt carries it, with its page label and any gap.

    Without the label the model cannot cite a page, and without the gap note a
    section starting at page 30 reads as continuous with one ending at 19.
    """
    header = []
    label = unit.page_label
    if label:
        header.append(f"[Report {label}]")
    if unit.gap_before and unit.gap_pages:
        a, b = unit.gap_pages
        span = f"page {a}" if a == b else f"pages {a}-{b}"
        header.append(
            f"[{span} are not shown here - they were analysed separately, so "
            f"this section does not continue directly from the one before it]"
        )
    if not header:
        return unit.text
    return "\n".join(header) + "\n\n" + unit.text


def _dedupe_iocs(iocs: list[RawIOC]) -> list[RawIOC]:
    seen: set[tuple[str, str]] = set()
    out: list[RawIOC] = []
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value)
        if key not in seen:
            seen.add(key)
            out.append(ioc)
    return out


def _build_profile(
    artifact_type: str,
    page_texts: list[str],
    page_iocs: list[list[RawIOC]],
    raw_iocs: list[RawIOC],
    content_budget: int | None = None,
):
    """Framework DocumentProfile plus the plugin's by-type breakdown dict."""
    doc_profile = profile_document(
        artifact_type=artifact_type,
        page_chars=[len(t) for t in page_texts] or [0],
        page_candidates=[len(p) for p in page_iocs] or [0],
        max_output_tokens=(
            content_budget if content_budget is not None else _native_content_budget()
        ),
    )
    by_type: dict[str, int] = {}
    for ioc in raw_iocs:
        by_type[ioc.ioc_type] = by_type.get(ioc.ioc_type, 0) + 1
    profile = doc_profile.to_dict()
    profile["candidates"] = len(raw_iocs)
    profile["candidates_by_type"] = by_type
    return doc_profile, profile


def _profile_document(
    raw_text: str,
    raw_iocs: list,
    artifact_type: str,
    page_count: int,
) -> dict:
    """Describe the document before any LLM call (see framework.documents).

    Convenience wrapper over ``_build_profile`` for callers that only have
    the joined text: PDF pages are recovered from the blank-line join used
    by ``extract_text_from_pdf``; anything else is a single page.
    """
    if artifact_type == "pdf_report":
        page_texts = raw_text.split("\n\n")
    else:
        page_texts = [raw_text]
    ioc_types = sorted({i.ioc_type for i in raw_iocs}) or ["ip"]
    _, profile = _build_profile(
        artifact_type, page_texts, _page_iocs(page_texts, ioc_types), raw_iocs
    )
    return profile


def _elapsed(start: float) -> float:
    return round(time.monotonic() - start, 1)


def _chunk_text(text: str, max_chars: int = _MAX_TEXT_CHARS_PER_CHUNK) -> list[str]:
    """Split text into paragraph-bounded chunks, each under max_chars."""
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    paragraphs = text.split("\n\n")
    current: list[str] = []
    current_len = 0
    for para in paragraphs:
        para_len = len(para) + 2  # account for the "\n\n" separator
        if current_len + para_len > max_chars and current:
            chunks.append("\n\n".join(current))
            current = [para]
            current_len = para_len
        else:
            current.append(para)
            current_len += para_len
    if current:
        chunks.append("\n\n".join(current))
    return chunks or [text[:max_chars]]


# Scalar fields a second report of the same entity can contradict. The key
# fields are excluded by construction: (ioc_type, value) and (technique_id,
# tactic) are the identities, so a disagreement there is a different entity.
_IOC_CONFLICT_FIELDS = ("confidence", "priority", "is_false_positive")
# Not technique_name: two batches naming T1566.001 "Spearphishing Attachment"
# and "Phishing: Spearphishing Attachment" agree about the technique, and
# _reconcile_mitre_mappings overwrites the name from the local ATT&CK lookup
# regardless. Treating that as a conflict set whole runs partial on a spelling.
_MITRE_CONFLICT_FIELDS = ("confidence",)


def _mark_superseded(provenance: list[dict], chunked_pages: set[int]) -> int:
    """Flag every truncated native partial that a later attempt replaced.

    Containment, not label match: PageRange.label is derived from the page
    numbers, so bisecting p1-10 yields p1-5 and p6-10 and no child ever shares
    its parent's label. A partial is replaced once the attempts after it cover
    every page it covered.

    Two paths lead there and both are handled the same way. A bisected retry
    covers the parent's pages between its halves. A truncated batch that could
    not be split hands its pages to the chunked text path instead, which
    re-submits every candidate on them - so `chunked_pages` counts as coverage
    too, and without it the partial would keep beating the re-read that
    replaced it.

    Walked in reverse so a child that was itself replaced counts as covered
    through its own successors.
    """
    marked = 0
    for i in range(len(provenance) - 1, -1, -1):
        rec = provenance[i]
        if not rec.get("truncated") or rec.get("superseded_by"):
            continue
        if rec.get("source") == "chunked":
            # Supersession answers "did a later attempt re-read these pages".
            # Nothing re-reads a chunk: the chunked path is the last one, and
            # 2.5 gave its results a page range that would otherwise make a
            # truncated chunk look covered - by `chunked_pages`, which
            # contains its own pages, or by a sibling unit that shares its
            # page range because the candidate cap split it and that assessed
            # a different set of candidates entirely.
            continue
        start, end = rec.get("page_start"), rec.get("page_end")
        if start is None or end is None:
            # A chunked result has no page range, so nothing can be shown to
            # cover it. Left standing rather than guessed at.
            continue
        pages = set(range(start, end + 1))
        covered: set[int] = set()
        by: list[str] = []
        for later in provenance[i + 1:]:
            if later.get("truncated") and not later.get("superseded_by"):
                # A partial nobody replaced covers nothing reliably.
                continue
            lp_start, lp_end = later.get("page_start"), later.get("page_end")
            if lp_start is None or lp_end is None:
                continue
            lp = set(range(lp_start, lp_end + 1))
            if lp & pages:
                covered |= lp
                by.append(str(later.get("label") or "?"))
        overlap = chunked_pages & pages
        if overlap:
            covered |= overlap
            by.append("chunked text path")
        if pages <= covered and by:
            rec["superseded_by"] = ", ".join(dict.fromkeys(by))
            marked += 1
    return marked


def _occurrence(entry: dict, prov: dict, fields: tuple[str, ...]) -> dict:
    """One sighting of an entity: where it was reported, and what was said."""
    occ = {
        "batch_label": prov.get("label"),
        "attempt_id": prov.get("attempt_id"),
        "page_start": prov.get("page_start"),
        "page_end": prov.get("page_end"),
    }
    if prov.get("superseded_by"):
        occ["superseded"] = True
    context = entry.get("report_context", entry.get("context"))
    if context:
        occ["context"] = str(context)[:300]
    for f in fields:
        if f in entry:
            occ[f] = entry[f]
    return occ


def _merge_entity(
    entry: dict,
    key,
    canonical: dict,
    order: list,
    prov: dict,
    fields: tuple[str, ...],
    stats: dict,
) -> None:
    """Fold one reported entity into the canonical record for its identity.

    First-wins still decides every canonical scalar, so no consumer sees a
    different shape than before - but the report that lost is kept as an
    occurrence rather than dropped, and a scalar it disagrees on is recorded
    as a conflict instead of being silently overruled.

    A superseded report contributes its occurrence for the audit trail and
    nothing else: it neither sets canonical values nor raises a conflict,
    because the attempt that replaced it is the answer.
    """
    superseded = bool(prov.get("superseded_by"))
    occ = _occurrence(entry, prov, fields)
    if key not in canonical:
        record = dict(entry)
        record["occurrences"] = [occ]
        if superseded:
            # Survives only because nothing else reported it. Named so a
            # reader knows it comes from a reply that was cut off.
            record["recovered_from_partial"] = True
            stats["recovered_from_partial"] += 1
        canonical[key] = record
        order.append(key)
        return

    record = canonical[key]
    record.setdefault("occurrences", []).append(occ)
    if superseded:
        return
    for f in fields:
        if f not in entry or f not in record:
            continue
        if entry[f] == record[f]:
            continue
        record.setdefault("conflicts", []).append({
            "field": f,
            "reported": entry[f],
            "canonical": record[f],
            "batch_label": prov.get("label"),
            "attempt_id": prov.get("attempt_id"),
        })
        stats["conflicts"] += 1


def _path_shape(path: dict) -> tuple:
    """Structural identity of an attack path: its steps, not its slug.

    Separate model calls coin slugs independently, so a shared slug says
    nothing about whether two batches described the same path - and two
    different slugs say nothing about whether they described different ones.
    The step sequence is the only thing that does.
    """
    shape = []
    for step in path.get("steps", []) or []:
        leads = step.get("leads_to") or []
        shape.append((
            str(step.get("technique_id", "")),
            str(step.get("tactic", "")),
            tuple(sorted(str(t) for t in leads)),
        ))
    return tuple(shape)


def _merge_path(
    path: dict,
    prov: dict,
    by_shape: dict,
    used_ids: set,
    out: list,
    stats: dict,
) -> None:
    """Fold one reported attack path into the unioned graph.

    The union used to keep the first path to claim a slug and drop every later
    one that reused it, however different its steps - so two batches that both
    coined "initial-access-to-exfil" for unrelated paths yielded one path and
    no record that a second existed.

    Reconciliation is on the step sequence. An id is namespaced with its batch
    label only when it collides with a structurally different path, so a run
    whose slugs do not collide - which is every single-batch run - emits
    exactly the ids it emitted before.

    A superseded partial contributes on the same terms as any other record it
    supplies: only a path nothing else reported. Its version of a path its own
    retry restated is not a second path, it is the cut-off draft of one.
    """
    label = str(prov.get("label") or "")
    superseded = bool(prov.get("superseded_by"))
    shape = _path_shape(path)
    # An empty shape is not an identity - every path with no steps would share
    # it - so those fall through to the id rules below.
    existing = by_shape.get(shape) if shape else None
    if existing is not None:
        labels = existing.setdefault("batch_labels", [])
        if label and label not in labels:
            labels.append(label)
        return

    pid = str(path.get("path_id") or "")
    if superseded and pid in used_ids:
        return

    record = dict(path)
    if not pid or pid in used_ids:
        base = f"{label}:{pid}" if (label and pid) else (
            pid or f"path-{len(out) + 1}"
        )
        candidate = base
        n = 2
        while candidate in used_ids:
            candidate = f"{base}-{n}"
            n += 1
        if candidate != pid:
            record["path_id"] = candidate
            if pid:
                record["original_path_id"] = pid
            stats["paths_namespaced"] += 1
    record["batch_labels"] = [label] if label else []
    if superseded:
        record["recovered_from_partial"] = True
        stats["recovered_from_partial"] += 1
    used_ids.add(str(record["path_id"]))
    if shape:
        by_shape[shape] = record
    out.append(record)


def _merge_metadata(
    meta: dict,
    prov: dict,
    canonical: dict,
    actors: list[dict],
    campaigns: list[dict],
) -> None:
    """Fold one batch's report metadata into the canonical record, per field.

    First-wins object-at-a-time discarded every field a later batch filled in
    as soon as an earlier one had answered any field at all: a batch that
    recognised only the title took the whole record, and the batch that
    identified the actor was dropped with it.

    Attribution is also not a scalar property of a report. One report can name
    two groups, and a later section can qualify what an earlier one asserted.
    The scalars keep their first value because consumers read them; every
    actor and campaign named anywhere is collected beside them.
    """
    label = prov.get("label")
    for key, value in meta.items():
        # An empty value is the model emitting a key it did not answer, so it
        # neither claims the field nor stops a later batch filling it.
        if value and not canonical.get(key):
            canonical[key] = value

    actor = str(meta.get("attributed_actor") or "").strip()
    if actor and not any(a["name"].lower() == actor.lower() for a in actors):
        actors.append({
            "name": actor,
            "confidence": str(meta.get("attribution_confidence") or ""),
            "batch_label": label,
        })
    campaign = str(meta.get("campaign_name") or "").strip()
    if campaign and not any(
        c["name"].lower() == campaign.lower() for c in campaigns
    ):
        campaigns.append({"name": campaign, "batch_label": label})


def _merge_llm_chunk_results(
    chunk_results: list[dict],
    provenance: list[dict] | None = None,
) -> dict:
    """Merge LLM JSON results from multiple document chunks.

    IOCs are deduplicated by (type, value); MITRE techniques by (technique_id, tactic).
    report_metadata comes from the first successful chunk.
    attack_graph paths are unioned and deduplicated by path_id.

    ``provenance`` runs parallel to ``chunk_results`` and carries each
    result's batch label, attempt id, page range and ``superseded_by`` flag.
    Metadata is kept beside the payload rather than inside it so a key the
    model happens to emit can never be read as bookkeeping. Omitted, every
    result is treated as a first attempt with no page range, which is what
    the merge did before Stage 2.2.

    (ioc_type, value) and (technique_id, tactic) are entity identities, not
    evidence identities: several procedures share one technique and one
    indicator carries several roles. So the canonical scalars stay first-wins
    for the consumers that depend on them, and every report is kept as an
    occurrence underneath.
    """
    ioc_canonical: dict[str, dict] = {}
    ioc_order: list[str] = []
    mitre_canonical: dict[tuple[str, str], dict] = {}
    mitre_order: list[tuple[str, str]] = []
    report_meta: dict = {}
    actors: list[dict] = []
    campaigns: list[dict] = []
    ag_paths: list[dict] = []
    ag_shapes: dict[tuple, dict] = {}
    ag_used_ids: set[str] = set()
    ag_convergence: set[str] = set()
    ag_branches: set[str] = set()
    stats = {"conflicts": 0, "recovered_from_partial": 0, "paths_namespaced": 0}

    provenance = provenance or []
    pairs = [
        (result, provenance[idx] if idx < len(provenance) else {})
        for idx, result in enumerate(chunk_results)
    ]
    # Two passes, and the order is the whole point of 2.1. Results that still
    # stand establish the canonical record; superseded partials are folded in
    # afterwards, so a reply that was cut off can no longer set a value its
    # own retry corrected. A single pass in arrival order puts the partial
    # first - which is the defect.
    live = [(r, p) for r, p in pairs if not p.get("superseded_by")]
    replaced = [(r, p) for r, p in pairs if p.get("superseded_by")]

    for result, prov in live + replaced:
        for ioc in result.get("refined_iocs", []):
            key = f"{ioc.get('ioc_type')}:{ioc.get('value', '').lower()}"
            _merge_entity(
                ioc, key, ioc_canonical, ioc_order, prov,
                _IOC_CONFLICT_FIELDS, stats,
            )

        for m in result.get("additional_mitre_techniques", []):
            tid = m.get("technique_id", "")
            if not tid:
                continue
            _merge_entity(
                m, (tid, m.get("tactic", "")), mitre_canonical, mitre_order,
                prov, _MITRE_CONFLICT_FIELDS, stats,
            )

        # Field by field, not object at a time: a superseded partial still
        # supplies only what nothing else did, but a later batch that names
        # the actor is no longer discarded because an earlier one named the
        # title. Actors and campaigns are collected rather than chosen.
        _merge_metadata(
            result.get("report_metadata") or {}, prov,
            report_meta, actors, campaigns,
        )

        # The graph is unioned rather than chosen, so a superseded partial's
        # paths are kept. Reconciliation is on the steps, not the slug.
        ag = result.get("attack_graph") or {}
        for path in ag.get("paths", []):
            _merge_path(path, prov, ag_shapes, ag_used_ids, ag_paths, stats)
        ag_convergence.update(ag.get("convergence_points", []))
        ag_branches.update(ag.get("branch_points", []))

    merged_iocs = [ioc_canonical[k] for k in ioc_order]
    merged_mitre = [mitre_canonical[k] for k in mitre_order]
    # Only when something was reported: an empty metadata block stays empty
    # rather than growing two empty lists nobody wrote.
    if report_meta or actors or campaigns:
        report_meta = dict(report_meta)
        report_meta["actors"] = actors
        report_meta["campaigns"] = campaigns
    return {
        "refined_iocs": merged_iocs,
        "additional_mitre_techniques": merged_mitre,
        "report_metadata": report_meta,
        "attack_graph": {
            "paths": ag_paths,
            "convergence_points": list(ag_convergence),
            "branch_points": list(ag_branches),
        } if ag_paths else {},
        "merge_stats": {
            "conflicts": stats["conflicts"],
            "recovered_from_partial": stats["recovered_from_partial"],
            "superseded_results": sum(
                1 for p in provenance if p.get("superseded_by")
            ),
            "paths_namespaced": stats["paths_namespaced"],
            "occurrences": sum(
                len(e.get("occurrences", ())) for e in merged_iocs + merged_mitre
            ),
        },
    }


# PluginExecutor truncates summarize_for_llm at this plugin's manifest
# summary_budget, from the end. That is the whole reason Stage 1.4 put the
# status first, and it means any unbounded list in the summary does not merely
# get long - it deletes everything after itself. On the 154-page Anthropic
# report the attribution narration alone reached 2,033 characters and took the
# IOC counts, the analyst-action line and the output artifact id with it.
#
# So the plugin decides what to drop rather than letting the truncator decide.


@lru_cache(maxsize=1)
def _summary_cap() -> int:
    """Characters this plugin's summary may use, from its own manifest.

    Read here as well as by the executor so the plugin can budget itself
    rather than be cut. Same reason _native_tier() reads model_tier: the
    manifest stays the single place the number is set.
    """
    try:
        with open(Path(__file__).parent / "manifest.json", encoding="utf-8") as f:
            return int(json.load(f).get("summary_budget") or 4000)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 4000
# Headroom, because the cap is enforced elsewhere and an off-by-a-few there
# should not cost a whole sentence here.
_SUMMARY_SAFETY: int = 60
# Never narrate an unbounded list even when there is room: a summary that is
# 90% threat-actor names is not a summary.
_SUMMARY_LIST_BUDGET: int = 180


def _bounded_list(
    names: list[str], budget: int = _SUMMARY_LIST_BUDGET,
) -> str:
    """Join names until `budget` characters, then say how many are left.

    The first name always goes in, however long it is - an entry over budget
    is narrated and counted, never silently reduced to nothing.

    The full lists stay in report_metadata. This bounds only what is narrated.
    """
    shown: list[str] = []
    used = 0
    for name in names:
        cost = len(name) + 2
        if shown and used + cost > budget:
            break
        shown.append(name)
        used += cost
    remaining = len(names) - len(shown)
    text = ", ".join(shown)
    if remaining > 0:
        text += f" (and {remaining} more)"
    return text


def _attribution_narration(
    actors: list[str], campaigns: list[str], room: int,
) -> str:
    """The attribution lines, sized to whatever room the rest of the summary
    left.

    Attribution is the part of this summary a reader can most afford to read
    in the artifact instead, and the part most able to run away - a model asked
    for "threat actor if attributed" answers with whatever the section named,
    and on a real report that was thirty-odd entries, several of them
    themselves comma-separated lists.

    Three tiers, by how much room is left: narrate what fits; or state the
    counts and where to look; or, when not even that fits, say nothing.

    The last tier looks like the silent dropping this project spends its time
    removing, and is not. Every actor is in report_metadata and in the
    artifact either way - what is being rationed is one sentence of narration
    in a summary that is lossy by construction. Attribution sits *before* the
    IOC counts in reading order, so a counts-line squeezed in against a cap
    that is already full does not get added at the end, it pushes the findings
    off it. Nothing is worth that.
    """
    if not actors and not campaigns:
        return ""
    counts = []
    if actors:
        counts.append(f"{len(actors)} further actor(s)")
    if campaigns:
        counts.append(f"{len(campaigns)} further campaign(s)")
    minimal = (
        f"{' and '.join(counts)} are named elsewhere in the report; see "
        f"report_metadata."
    )
    if room < len(minimal):
        return ""

    budget = min(_SUMMARY_LIST_BUDGET, max(0, room - len(minimal)) // 2
                 + _SUMMARY_LIST_BUDGET // 2)
    out = []
    if actors:
        out.append(
            "Also attributed, elsewhere in the report: "
            f"{_bounded_list(actors, budget)}."
        )
    if campaigns:
        out.append(f"Other campaigns named: {_bounded_list(campaigns, budget)}.")
    text = " ".join(out)
    return text if len(text) <= room else minimal


def _analysis_fields(
    *,
    ingestion_mode: str,
    pages_total: int,
    pages_read: int,
    truncated_chunks: list[int],
    chunks_attempted: int = 0,
    chunks_failed: int = 0,
    candidates_rejected: int = 0,
    candidates_unassessed: int = 0,
    candidates_not_submitted: int = 0,
    merge_conflicts: int = 0,
    recovered_from_partial: int = 0,
    rejected_with_dissent: int = 0,
    accepted_none: bool = False,
    unit: str = "pages",
) -> dict:
    """One status for the whole ingestion, with the reasons behind it.

    Precedence is degraded > partial > complete. "regex_only" is degraded and
    not merely partial: the indicators are unrefined and unclassified, which is
    a different kind of answer rather than less of the same one.

    The notes carry the markers that used to be separate sentences in
    summarize_for_llm, so that the status can lead there. That matters because
    PluginExecutor truncates the summary at the manifest's summary_budget,
    and a warning placed after the content is the part that gets cut.
    """
    notes: list[str] = []
    dropped = max(0, (pages_total or 0) - (pages_read or 0))
    if dropped:
        # `unit` because a text artifact is measured in lines, not pages, and
        # a coverage figure that names the wrong unit invites a reader to think
        # a 114-line summary was a 114-page report.
        notes.append(
            f"INCOMPLETE COVERAGE: only {pages_read} of {pages_total} {unit} "
            f"were read, so absence of an indicator here is not evidence it is "
            f"absent from the report"
        )
    if truncated_chunks:
        listed = ", ".join(str(c) for c in truncated_chunks)
        plural = "s" if len(truncated_chunks) != 1 else ""
        notes.append(
            f"TRUNCATED OUTPUT: chunk{plural} {listed} stopped at the output "
            f"cap; their candidates were only partly assessed"
        )
    # A chunk that failed took its candidates with it. Counting these only in
    # the logs is what let a run where four of ten chunks failed report exactly
    # like a clean one.
    if chunks_failed:
        notes.append(
            f"INCOMPLETE ANALYSIS: {chunks_failed} of {chunks_attempted} "
            f"chunk(s) produced no usable result, so their candidates were "
            f"never assessed"
        )
    # A candidate the regex pass found and no prompt ever carried. Kept apart
    # from the unassessed count because the two have different causes and
    # different fixes: this one means no model was ever asked, and charging it
    # to the model's silence points the reader at the wrong thing.
    if candidates_not_submitted:
        notes.append(
            f"CANDIDATES NOT SUBMITTED: {candidates_not_submitted} indicator "
            f"candidate(s) found by the regex pre-scan were never placed in a "
            f"prompt, so no model was asked about them"
        )
    # Not a defect and not a degradation: the model looked at every candidate
    # and rejected all of them. Said plainly so an empty IOC list is not read
    # as a failure to produce one.
    # Candidates the model was given but never answered about. Reported before
    # the rejection note, because it changes what that note means: rejecting
    # three of three is an assessment, rejecting three of forty is not.
    if candidates_unassessed:
        notes.append(
            f"UNASSESSED CANDIDATES: {candidates_unassessed} indicator "
            f"candidate(s) received no verdict from the model, so they are "
            f"neither accepted nor ruled out"
        )
    if accepted_none:
        # Deliberately says "the model assessed N" rather than "all N": this
        # counts verdicts returned, and the line above carries what was missed.
        notes.append(
            f"NO INDICATORS ACCEPTED: the model assessed {candidates_rejected} "
            f"candidate(s) and judged every one a false positive; that empty "
            f"result is the assessment, not a failure to produce one"
        )

    # Two batches reported the same entity and disagreed on a scalar. Not
    # auto-resolved: a later correction and a lower-confidence restatement are
    # not distinguishable by value, so the first value is reported and the
    # disagreement is handed to the reader.
    if merge_conflicts:
        notes.append(
            f"UNRESOLVED CONFLICTS: {merge_conflicts} reported value(s) "
            f"disagree between batches; the first is reported and every "
            f"reading is kept under the record's conflicts"
        )
    # A rejection another batch argued against. Reported separately from the
    # conflicts note because these records are *not* in the output: the
    # rejection stands, so the only place the disagreement can be seen is
    # here.
    if rejected_with_dissent:
        notes.append(
            f"REJECTED OVER DISSENT: {rejected_with_dissent} indicator(s) were "
            f"dropped as false positives although another batch assessed them "
            f"as real; they are not in the indicator list, so this note is the "
            f"only record of the disagreement"
        )
    # A record that exists only because a cut-off reply mentioned it, and that
    # the retry replacing that reply did not confirm.
    if recovered_from_partial:
        notes.append(
            f"RECOVERED FROM A PARTIAL REPLY: {recovered_from_partial} "
            f"record(s) survive only from a batch whose reply was cut off and "
            f"were not restated by the attempt that replaced it"
        )
    if ingestion_mode == "regex_only":
        notes.append(
            "DEGRADED INPUT: LLM refinement did not run, so these indicators "
            "are a regex baseline — low confidence, no false-positive "
            "assessment, no MITRE mapping, no attack graph"
        )

    # "No indicators accepted" is a complete answer and does not by itself make
    # the run partial — the work was done and this is its result. Every other
    # note means something was not looked at.
    incomplete = [n for n in notes if not n.startswith("NO INDICATORS ACCEPTED")]
    if ingestion_mode == "regex_only":
        status = "degraded"
    elif incomplete:
        status = "partial"
    else:
        status = "complete"
    return {"analysis_status": status, "analysis_notes": notes}


def _parse_llm_json(response_text: str) -> dict | None:
    """Strip markdown code fences and parse JSON from LLM response."""
    parsed, _ = _parse_llm_json_result(response_text)
    return parsed


def _parse_llm_json_result(response_text: str) -> tuple[dict | None, bool]:
    """Parse an LLM JSON reply, reporting whether it had to be repaired.

    Returns ``(parsed, truncated)``. A truncated reply parses only after
    unmatched brackets are closed, and whatever the model had not written
    yet is gone — the caller must treat it as a partial answer, not a
    successful one, or those indicators are silently dropped.

    Logs the exact parse error on failure.  If the JSON appears truncated
    (common when the model hits its output-token limit), attempts
    best-effort repair by closing unmatched brackets.
    """
    _log = logging.getLogger("eventmill.plugin.threat_intel_ingester")
    raw_resp = response_text.strip()

    had_fences = raw_resp.startswith("```")
    if had_fences:
        raw_resp = re.sub(r"^```(?:json)?\s*\n?", "", raw_resp)
        raw_resp = re.sub(r"\n?```\s*$", "", raw_resp)

    text = raw_resp.strip()
    resp_len = len(text)

    # --- Fast path: direct parse ---
    try:
        return json.loads(text), False
    except json.JSONDecodeError as exc:
        _log.warning(
            "JSON parse error at char %d (line %d col %d): %s "
            "| response_length=%d, had_fences=%s, "
            "last_100_chars=%r",
            exc.pos, exc.lineno, exc.colno, exc.msg,
            resp_len, had_fences,
            text[-100:] if resp_len > 100 else text,
        )
    except ValueError as exc:
        _log.warning(
            "JSON ValueError: %s | response_length=%d",
            exc, resp_len,
        )

    # --- Slow path: repair truncated JSON ---
    repaired = _repair_truncated_json(text)
    if repaired is not None:
        _log.warning(
            "[TRUNCATED] Recovered a truncated JSON reply by closing brackets "
            "— %d refined_iocs and %d techniques kept; anything the model had "
            "not yet written is lost (original_length=%d, keys=%s). "
            "The reply hit the output-token limit — the caller must re-run "
            "the remainder in smaller pieces rather than accept this.",
            len(repaired.get("refined_iocs", []) or []),
            len(repaired.get("additional_mitre_techniques", []) or []),
            resp_len, list(repaired.keys()),
        )
        return repaired, True

    _log.warning(
        "JSON repair also failed "
        "| response_length=%d, starts_with_brace=%s",
        resp_len, text[:1] == '{',
    )
    return None, True


def _repair_truncated_json(text: str) -> dict | None:
    """Best-effort repair of JSON truncated by LLM output-token limits.

    Scans backward from the end of *text* looking for the last ``}`` or
    ``]`` that, when followed by the right number of closing brackets,
    produces a valid JSON object.  Tries up to 30 candidate positions.
    """
    if not text.startswith('{'):
        return None

    attempts = 0
    for i in range(len(text) - 1, max(0, len(text) - 4000), -1):
        if text[i] not in ('}', ']'):
            continue
        if attempts >= 30:
            break
        attempts += 1

        candidate = text[:i + 1]
        need_brackets = candidate.count('[') - candidate.count(']')
        need_braces = candidate.count('{') - candidate.count('}')
        if need_brackets < 0 or need_braces < 0:
            continue

        closer = ']' * need_brackets + '}' * need_braces
        try:
            obj = json.loads(candidate + closer)
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, ValueError):
            continue

    return None


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique lookup — delegated to framework.reference_data
# ---------------------------------------------------------------------------
# _get_mitre_db is imported above from framework.reference_data.mitre_attack


def _resolve_tactic(
    tid: str, tactic: str, mitre_db: dict[str, dict]
) -> tuple[str, str] | None:
    """Return ``(corrected_tactic, reason)`` when *tactic* can be fixed
    deterministically for *tid*, else None.

    Reasons, in order of precedence:

    * ``legacy``  — a tactic retired by a later ATT&CK release, resolved to
      the single successor the technique lists (see LEGACY_TACTIC_ALIASES).
    * ``sibling`` — the LLM chose one of a pair of replacement tactics but
      the technique only allows the other one.
    * ``single``  — the technique has exactly one valid tactic in ATT&CK, so
      any other label is simply wrong.

    Anything else (a technique with several valid tactics, none of which
    was chosen) is left for validation to flag with the allowed options.
    """
    if not tid or not tactic:
        return None
    allowed = mitre_db.get(tid, {}).get("tactics", [])
    if _is_legacy_tactic(tactic):
        successor = _resolve_legacy_tactic(tactic, allowed)
        return (successor, "legacy") if successor else None
    if not allowed:
        return None
    allowed_lower = {t.lower() for t in allowed}
    if tactic.lower() in allowed_lower:
        return None
    canonical = _canonical_tactic(tactic)
    if canonical:
        for siblings in _SIBLING_TACTIC_SETS:
            if canonical in siblings:
                options = [t for t in allowed if t in siblings and t != canonical]
                if len(options) == 1:
                    return options[0], "sibling"
    if len(allowed) == 1:
        return allowed[0], "single"
    return None


def _normalize_tactics(
    all_mitre: list[dict],
    attack_graph: dict,
    mitre_db: dict[str, dict],
) -> tuple[list[dict], int, int]:
    """Apply deterministic tactic corrections to graph steps and mappings.

    Runs before backfill so that attack_graph steps and mitre_mappings
    agree.  Each corrected mapping entry records the original label in
    ``tactic_corrected_from`` so analysts can see what changed.  Occurrences
    that cannot be resolved are left untouched for validation to flag as
    ``tactic_mismatch`` alongside the technique's ``allowed_tactics``.

    Mutates ``attack_graph`` in place.  Returns the mapping list (with any
    entries that now collide on ``(technique_id, tactic)`` merged), the
    number of retired-tactic migrations and the number of other corrections.
    """
    if not mitre_db:
        return all_mitre, 0, 0

    migrated = 0
    corrected = 0

    for path in attack_graph.get("paths", []):
        path_id = path.get("path_id", "unknown")
        for step in path.get("steps", []):
            tid = step.get("technique_id", "")
            tactic = step.get("tactic", "")
            resolved = _resolve_tactic(tid, tactic, mitre_db)
            if resolved is None:
                continue
            new_tactic, reason = resolved
            logger.info(
                "[TACTIC-FIX] Path %r: %s %r -> %r (%s)",
                path_id, tid, tactic, new_tactic, reason,
            )
            step["tactic"] = new_tactic
            if reason == "legacy":
                migrated += 1
            else:
                corrected += 1

    changed_keys: set[tuple[str, str]] = set()
    for entry in all_mitre:
        tid = entry.get("technique_id", "")
        tactic = entry.get("tactic", "")
        resolved = _resolve_tactic(tid, tactic, mitre_db)
        if resolved is None:
            continue
        new_tactic, reason = resolved
        logger.info(
            "[TACTIC-FIX] Mapping %s %r -> %r (%s)",
            tid, tactic, new_tactic, reason,
        )
        entry["tactic"] = new_tactic
        entry["tactic_corrected_from"] = tactic
        changed_keys.add((tid, new_tactic))
        if reason == "legacy":
            migrated += 1
        else:
            corrected += 1

    if not changed_keys:
        return all_mitre, migrated, corrected

    # A corrected entry may now share its key with an entry the LLM already
    # emitted under the right tactic — fold them together.
    kept: list[dict] = []
    seen: dict[tuple[str, str], dict] = {}
    for entry in all_mitre:
        key = (entry.get("technique_id", ""), entry.get("tactic", ""))
        if key in changed_keys and key in seen:
            target = seen[key]
            paths_list = target.setdefault("context_paths", [])
            for pid in entry.get("context_paths", []):
                if pid not in paths_list:
                    paths_list.append(pid)
            continue
        seen.setdefault(key, entry)
        kept.append(entry)
    return kept, migrated, corrected


def _fix_tactic_progression(
    attack_graph: dict,
    mitre_db: dict[str, dict],
) -> tuple[dict, int]:
    """Enforce kill-chain tactic progression within each attack path.

    **Entry-point-only rule**: ``Initial Access``, ``Reconnaissance``, and
    ``Resource Development`` should only appear at the first step of a path.
    If a later step uses one of these and the technique has alternative valid
    tactics in the MITRE database, reassign to the valid tactic with the
    highest kill-chain ordinal (preferring forward progression).

    Mutates the ``attack_graph`` in place and returns it along with the
    count of reassignments made.
    """
    reassign_count = 0

    for path in attack_graph.get("paths", []):
        path_id = path.get("path_id", "unknown")
        steps = path.get("steps", [])
        if len(steps) < 2:
            continue

        for step_idx, step in enumerate(steps):
            if step_idx == 0:
                continue  # first step is allowed to use entry-only tactics

            tid = step.get("technique_id", "")
            tactic = step.get("tactic", "")
            if not tid or not tactic:
                continue

            if tactic not in ENTRY_ONLY_TACTICS:
                continue  # tactic is fine, no fix needed

            # Technique is using an entry-only tactic at a non-first step.
            # Look up its valid tactics from the MITRE database.
            local = mitre_db.get(tid, {})
            valid_tactics: list[str] = local.get("tactics", [])
            if not valid_tactics:
                continue  # no DB data to pick from

            # Filter out entry-only tactics, keep alternatives
            alternatives = [
                t for t in valid_tactics
                if t not in ENTRY_ONLY_TACTICS and t in TACTIC_ORDER
            ]
            if not alternatives:
                continue  # all valid tactics are entry-only; keep as-is

            # Pick the alternative with the highest kill-chain ordinal
            best = max(alternatives, key=lambda t: TACTIC_ORDER[t])

            logger.info(
                "[TACTIC-FIX] Path %r step %d: %s reassigned "
                "%r -> %r (entry-only tactic at non-first step; "
                "valid alternatives: %s)",
                path_id, step_idx, tid, tactic, best, alternatives,
            )
            step["tactic"] = best
            reassign_count += 1

    return attack_graph, reassign_count


def _canonicalize_retired_techniques(
    all_mitre: list[dict],
    attack_graph: dict,
    mitre_db: dict,
) -> int:
    """Rewrite retired technique ids to their current equivalent, in place.

    Runs before everything else so the rest of reconciliation, the tactic
    lookups and the attack graph all see one vocabulary. Rewriting only
    ``mitre_mappings`` would leave the graph pointing at ids that no longer
    exist, and the two views of the same report would disagree.

    Version skew, not model error: a model emits the numbering in its
    training data and in most published reporting, so a correct technique can
    arrive under an id ATT&CK has retired. Left alone it is demoted to
    "non-ATT&CK" — dropped from every ATT&CK-keyed view and shown to an
    analyst as though it were not a real technique.

    Returns how many ids were rewritten. Each rewrite keeps the id it came
    from on the entry, because a silent renumber is its own kind of wrong.

    Mutates *all_mitre* in place, which can shorten it: if a report names
    both the retired id and its successor for the same tactic, remapping
    makes them the same entry, and the identity index downstream is keyed on
    ``(technique_id, tactic)`` — it would keep one and the output would carry
    the technique twice.
    """
    if not mitre_db:
        return 0

    # One decision per distinct id, so the graph and the mappings cannot
    # diverge and the log has one line per retirement rather than per use.
    decided: dict[str, str | None] = {}

    def _current(tid: str, name: str = "") -> str | None:
        if tid in decided:
            return decided[tid]
        resolved = _resolve_retired_technique(tid, name)
        if resolved:
            new_id, basis = resolved
            decided[tid] = new_id
            logger.info(
                "[RECONCILE] Retired technique %s -> %s (%s, matched by %s). "
                "ATT&CK renumbered it; the finding stands.",
                tid, new_id, mitre_db.get(new_id, {}).get("name", ""), basis,
            )
        else:
            decided[tid] = None
            if tid not in mitre_db:
                note = _retirement_note(tid)
                if note:
                    logger.warning("[RECONCILE] %s.", note)
        return decided[tid]

    remapped = 0
    kept: list[dict] = []
    by_key: dict[tuple[str, str], dict] = {}

    def _fold(into: dict, dropped: dict) -> None:
        """Merge a remapped duplicate into the entry that already held the id."""
        paths = into.setdefault("context_paths", [])
        for pid in dropped.get("context_paths") or []:
            if pid not in paths:
                paths.append(pid)
        into.setdefault(
            "technique_id_retired_from", dropped.get("technique_id_retired_from", "")
        )

    for entry in all_mitre:
        tid = entry.get("technique_id", "")
        if tid and tid not in mitre_db:
            new_id = _current(tid, entry.get("technique_name", ""))
            if new_id:
                entry["technique_id"] = new_id
                entry["technique_id_retired_from"] = tid
                # The old name described the old numbering; take the current one.
                entry["technique_name"] = mitre_db.get(new_id, {}).get("name", "")
                remapped += 1

        key = (entry.get("technique_id", ""), entry.get("tactic", ""))
        if key[0] and key in by_key:
            _fold(by_key[key], entry)
            logger.info(
                "[RECONCILE] Merged duplicate %s (%s) — the report named both "
                "the retired id and its successor for this tactic.",
                key[0], key[1] or "no tactic",
            )
            continue
        if key[0]:
            by_key[key] = entry
        kept.append(entry)

    all_mitre[:] = kept

    # The graph carries the same ids in steps and in leads_to.
    for path in attack_graph.get("paths", []):
        for step in path.get("steps", []):
            tid = step.get("technique_id", "")
            if tid and tid not in mitre_db:
                new_id = _current(tid, step.get("technique_name", ""))
                if new_id:
                    step["technique_id"] = new_id
                    step["technique_id_retired_from"] = tid
            leads = step.get("leads_to")
            if leads:
                step["leads_to"] = [
                    (_current(t) or t) if t and t not in mitre_db else t
                    for t in leads
                ]
    return remapped


def _reconcile_mitre_mappings(
    all_mitre: list[dict],
    attack_graph: dict,
) -> list[dict]:
    """Reconcile and enrich mitre_mappings against local ATT&CK data.

    Identity key is ``(technique_id, tactic)`` — one technique can appear
    multiple times with different tactics when it serves different roles
    across attack paths.

    0a. Rewrites retired technique ids to their current equivalent across
       both *all_mitre* and *attack_graph*, so a technique ATT&CK has
       renumbered is not demoted to "non-ATT&CK" in step 3.
    0. Runs ``_normalize_tactics`` to apply deterministic tactic fixes
       (retired tactics such as "Defense Evasion", Stealth / Defense
       Impairment sibling swaps, single-tactic techniques), then
       ``_fix_tactic_progression`` on the attack_graph to reassign
       entry-only tactics (Initial Access, etc.) on non-first steps.
    1. Backfills ``(technique_id, tactic)`` pairs from *attack_graph* steps,
       populating ``context_paths`` with the path IDs where each pair appears.
    2. Enriches entries that have empty ``technique_name`` or ``tactic``
       using the local MITRE lookup.
    3. Validates technique IDs, marks non-ATT&CK entries, and flags tactic
       mismatches.

    Returns the (mutated) *all_mitre* list.
    """
    mitre_db = _get_mitre_db()

    # --- Step 0a: retired ids first, so every later step sees one vocabulary ---
    retired_count = _canonicalize_retired_techniques(
        all_mitre, attack_graph, mitre_db
    )

    # --- Step 0: deterministic tactic fixes, then progression in attack_graph ---
    all_mitre, migrated_count, corrected_count = _normalize_tactics(
        all_mitre, attack_graph, mitre_db
    )
    _fix_tactic_progression(attack_graph, mitre_db)

    # --- Index existing entries by (technique_id, tactic) ---
    existing: dict[tuple[str, str], dict] = {}
    for m in all_mitre:
        tid = m.get("technique_id", "")
        tactic = m.get("tactic", "")
        if tid:
            existing[(tid, tactic)] = m

    backfill_count = 0
    enrich_count = 0

    # --- Step 1: backfill from attack_graph with per-step tactic ---
    # Collect all (tid, tactic) -> [path_ids] from graph steps
    graph_keys: dict[tuple[str, str], list[str]] = {}
    all_leads_to: set[str] = set()
    step_tids: set[str] = set()

    for path in attack_graph.get("paths", []):
        path_id = path.get("path_id", "unknown")
        for step in path.get("steps", []):
            tid = step.get("technique_id", "")
            tactic = step.get("tactic", "")
            if not tid:
                continue
            step_tids.add(tid)
            key = (tid, tactic)
            graph_keys.setdefault(key, [])
            if path_id not in graph_keys[key]:
                graph_keys[key].append(path_id)
            all_leads_to.update(t for t in step.get("leads_to", []) if t)

    for key, path_ids in graph_keys.items():
        tid, tactic = key
        if key in existing:
            # Exact (tid, tactic) match — just add context_paths
            entry = existing[key]
            paths_list = entry.setdefault("context_paths", [])
            for pid in path_ids:
                if pid not in paths_list:
                    paths_list.append(pid)
            continue

        # Check for existing entry with same tid but empty tactic
        # (from IOC-derived or LLM additional_mitre with empty tactic)
        empty_key = (tid, "")
        if empty_key in existing:
            entry = existing.pop(empty_key)
            entry["tactic"] = tactic
            paths_list = entry.setdefault("context_paths", [])
            for pid in path_ids:
                if pid not in paths_list:
                    paths_list.append(pid)
            existing[key] = entry
            enrich_count += 1
            logger.info(
                "[RECONCILE] Promoted %s: set tactic=%r from "
                "attack_graph path(s) %s",
                tid, tactic, ", ".join(path_ids),
            )
            continue

        # New (tid, tactic) pair — create entry
        local = mitre_db.get(tid, {})
        new_entry = {
            "technique_id": tid,
            "technique_name": local.get("name", ""),
            "tactic": tactic,
            "context_paths": list(path_ids),
            "confidence": "inferred",
            "report_context": (
                f"Backfilled from attack_graph path(s) "
                f"'{', '.join(path_ids)}'"
            ),
        }
        all_mitre.append(new_entry)
        existing[key] = new_entry
        backfill_count += 1
        logger.info(
            "[RECONCILE] Backfilled technique %s (tactic=%s) "
            "from attack_graph path(s) %s | local_lookup=%s",
            tid, tactic, ", ".join(path_ids),
            "hit" if local else "miss",
        )

    # Handle leads_to targets that never appear as steps in any path
    orphan_tids = all_leads_to - step_tids
    for oid in sorted(orphan_tids):
        # Skip if any entry already exists for this technique_id
        if any(etid == oid for (etid, _) in existing):
            continue
        local = mitre_db.get(oid, {})
        fallback_tactic = local["tactics"][0] if local.get("tactics") else ""
        new_entry = {
            "technique_id": oid,
            "technique_name": local.get("name", ""),
            "tactic": fallback_tactic,
            "context_paths": [],
            "confidence": "inferred",
            "report_context": (
                "Backfilled — referenced as leads_to target "
                "in attack_graph"
            ),
        }
        all_mitre.append(new_entry)
        existing[(oid, fallback_tactic)] = new_entry
        backfill_count += 1
        logger.info(
            "[RECONCILE] Backfilled leads_to orphan %s (tactic=%s) "
            "| local_lookup=%s",
            oid, fallback_tactic or "(unknown)",
            "hit" if local else "miss",
        )

    # --- Step 2: enrich stubs with empty name/tactic ---
    for entry in all_mitre:
        tid = entry.get("technique_id", "")
        if not tid:
            continue

        needs_name = not entry.get("technique_name")
        needs_tactic = not entry.get("tactic")
        if not needs_name and not needs_tactic:
            continue

        local = mitre_db.get(tid, {})
        if not local:
            continue

        changes: list[str] = []
        if needs_name and local.get("name"):
            entry["technique_name"] = local["name"]
            changes.append(f"name={local['name']!r}")
        if needs_tactic and local.get("tactics"):
            if len(local["tactics"]) > 1:
                logger.warning(
                    "[RECONCILE] %s has %d valid tactics %s but no "
                    "graph context to disambiguate — defaulting to %r",
                    tid, len(local["tactics"]), local["tactics"],
                    local["tactics"][0],
                )
            entry["tactic"] = local["tactics"][0]
            changes.append(f"tactic={local['tactics'][0]!r}")

        if changes:
            enrich_count += 1
            logger.info(
                "[RECONCILE] Enriched %s: %s | from local MITRE lookup",
                tid, ", ".join(changes),
            )

    # --- Step 3: validate IDs and mark non-ATT&CK entries ---
    # Only run when we actually have a loaded DB; skip if the lookup
    # file hasn't been built yet (all entries stay unmarked).
    unvalidated_count = 0
    tactic_mismatch_count = 0
    if mitre_db:
        for entry in all_mitre:
            tid = entry.get("technique_id", "")
            if not tid:
                continue
            if tid in mitre_db:
                entry["mitre_validated"] = True
                # Validate tactic against allowed tactics for this technique
                entry_tactic = entry.get("tactic", "")
                allowed = mitre_db[tid].get("tactics", [])
                if entry_tactic and allowed:
                    # Case-insensitive lookup: LLM may write
                    # "Command and Control" vs DB's "Command And Control"
                    allowed_lower = {t.lower(): t for t in allowed}
                    if entry_tactic in allowed:
                        # Exact match — nothing to do
                        pass
                    elif entry_tactic.lower() in allowed_lower:
                        # Case-only mismatch — auto-correct to DB casing
                        canonical = allowed_lower[entry_tactic.lower()]
                        logger.info(
                            "[RECONCILE] Auto-corrected tactic casing for "
                            "%s: %r -> %r",
                            tid, entry_tactic, canonical,
                        )
                        entry["tactic"] = canonical
                    else:
                        # Genuine mismatch: the technique has several valid
                        # tactics and the LLM chose none of them.  Keep the
                        # LLM's label (it may describe the role in the
                        # report) and record the options for the analyst.
                        tactic_mismatch_count += 1
                        entry["tactic_mismatch"] = True
                        entry["allowed_tactics"] = list(allowed)
                        logger.warning(
                            "[RECONCILE] Tactic needs analyst review: %s "
                            "(%s) labelled %r by the LLM; ATT&CK allows %s. "
                            "Kept as-is with tactic_mismatch=true and "
                            "allowed_tactics listed in the output — confirm "
                            "the role from the report or pick one of the "
                            "allowed tactics.",
                            tid, entry.get("technique_name", ""),
                            entry_tactic, allowed,
                        )
            else:
                entry["mitre_validated"] = False
                unvalidated_count += 1
                # Annotate the name so frontline analysts see it
                # without needing access to tool logs.
                name = entry.get("technique_name", "")
                if name and "(non-ATT&CK ID)" not in name:
                    entry["technique_name"] = f"{name} (non-ATT&CK ID)"
                elif not name:
                    entry["technique_name"] = "(non-ATT&CK ID)"
                logger.warning(
                    "[RECONCILE] Unvalidated technique %s (%s) — "
                    "not found in the local ATT&CK database (%d techniques). "
                    "Keeping entry but marking as non-ATT&CK.",
                    tid, entry["technique_name"], len(mitre_db),
                )

    if (
        migrated_count or corrected_count or backfill_count or enrich_count
        or unvalidated_count or tactic_mismatch_count or retired_count
    ):
        logger.info(
            "[RECONCILE] Summary: %d retired ids remapped, %d legacy tactics "
            "migrated, %d tactics "
            "auto-corrected, %d backfilled, %d enriched, %d unvalidated, "
            "%d tactics needing analyst review, "
            "%d total mitre_mappings (local DB has %d techniques)",
            retired_count, migrated_count, corrected_count, backfill_count,
            enrich_count,
            unvalidated_count, tactic_mismatch_count,
            len(all_mitre), len(mitre_db),
        )

    return all_mitre


# ---------------------------------------------------------------------------
# LLM Refinement Prompt
# ---------------------------------------------------------------------------

LLM_REFINEMENT_PROMPT = """You are an experienced threat intelligence analyst reviewing extracted IOCs from a security report.

TASK: Complete ALL five sections below.

SECTION 1 — IOC VALIDATION: Review each IOC candidate and its surrounding context.
For each IOC:
1. Assess whether it is a true indicator of compromise (not a benign version number, documentation example, or false positive)
2. Assign a confidence level: "low" (uncertain), "medium" (likely real IOC), "high" (confirmed IOC based on context)
3. Assign an operational priority: "low", "medium", "high" based on the IOC's role in the described attack
4. Identify related MITRE ATT&CK technique IDs if the context suggests a specific technique

SECTION 2 — ADDITIONAL MITRE TECHNIQUES: Identify any MITRE ATT&CK techniques described in the report text that are not already captured as IOC-type extractions. For each technique, note whether it was explicitly mentioned (technique ID appears in text) or inferred from described behavior.

SECTION 3 — REPORT METADATA: Extract the report title, campaign name, attributed threat actor, and attribution confidence.

SECTION 4 — TECHNIQUE TACTIC ASSIGNMENT: For EVERY technique in both refined_iocs.related_mitre AND additional_mitre_techniques, you MUST populate the "tactic" field with the correct MITRE ATT&CK tactic name. Use the official ATT&CK v19 tactic names exactly as written:
Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Stealth, Defense Impairment, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.
ATT&CK v19 retired "Defense Evasion". Use "Stealth" for hiding, blending in, obfuscation, masquerading, or indicator removal, and "Defense Impairment" for disabling, degrading, or tampering with security controls. Never output "Defense Evasion".
If a technique maps to multiple tactics, use the tactic most relevant to how the report describes its use. When the same technique ID appears in multiple attack paths serving different attacker objectives, include it multiple times in `additional_mitre_techniques` — once per distinct role — with the tactic that matches each role. This is expected, not a duplication error. NEVER leave the tactic field empty.

SECTION 5 — ATTACK GRAPH: Analyze how the techniques described in the report relate to each other operationally. Real attacks have multiple paths, branches, and convergence points.

For the attack_graph:
- Identify distinct attack PATHS (e.g., "phishing path" and "supply chain path" may both lead to execution)
- For each path, list the techniques in causal order: which technique ENABLES or LEADS TO the next
- Identify CONVERGENCE POINTS — techniques that multiple paths flow into (e.g., both initial access vectors lead to the same execution technique)
- Identify BRANCH POINTS — techniques that lead to multiple downstream techniques
- If the report describes only one path, return a single path. Do not invent paths not supported by the report.
- Use only technique IDs that appear in refined_iocs or additional_mitre_techniques

CRITICAL — TACTIC ASSIGNMENT IN ATTACK PATHS:
Each step's tactic MUST reflect the technique's ROLE AT THAT POSITION in the path, not its most common tactic. "Initial Access" should only appear at the FIRST step of a path — it means the entry point. If the same technique appears later (after access was already gained), assign the tactic that matches its role at that later stage.

Many techniques have multiple valid MITRE tactics. Common multi-tactic techniques:
- T1078 (Valid Accounts): Initial Access, Persistence, Privilege Escalation, Stealth
- T1053 (Scheduled Task/Job): Execution, Persistence, Privilege Escalation
- T1098 (Account Manipulation): Persistence, Privilege Escalation

Example — T1078 reused across two paths with DIFFERENT tactics:
  Path "cred-spray": T1110 (Credential Access) → T1078 (tactic: "Initial Access") → T1087 (Discovery)
    ↑ T1078 IS the initial foothold here — correct tactic is Initial Access.

  Path "aitm-phishing": T1566 (Initial Access) → T1557 (Credential Access) → T1078 (tactic: "Persistence")
    ↑ Initial access already happened at T1566. T1078 is using stolen creds to MAINTAIN access — correct tactic is Persistence.

  Path "insider-escalation": T1078 (tactic: "Initial Access") → T1068 (Privilege Escalation) → T1078 (tactic: "Privilege Escalation")
    ↑ Same technique at two different stages — different roles, different tactics.

SOURCE CONTEXT: {source_context}

IOC CANDIDATES:
{ioc_candidates}

FULL REPORT TEXT (truncated):
{report_text}

Respond ONLY with a JSON object in this exact format:
{{
  "refined_iocs": [
    {{
      "value": "the IOC value",
      "ioc_type": "ip|domain|hash_sha256|etc",
      "confidence": "low|medium|high",
      "priority": "low|medium|high",
      "context": "brief description of the IOC's role",
      "related_mitre": ["T1234", "T1234.001"],
      "is_false_positive": false
    }}
  ],
  "additional_mitre_techniques": [
    {{
      "technique_id": "T1234.001",
      "technique_name": "Technique Name",
      "tactic": "Tactic Name",
      "confidence": "explicit|inferred",
      "report_context": "brief description of the behavior"
    }},
    {{
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "tactic": "Initial Access",
      "confidence": "inferred",
      "report_context": "Attacker used harvested credentials for initial foothold"
    }},
    {{
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "tactic": "Persistence",
      "confidence": "inferred",
      "report_context": "Same credentials reused to maintain long-term access"
    }}
  ],
  "report_metadata": {{
    "title": "report title if identifiable",
    "campaign_name": "named campaign if mentioned",
    "attributed_actor": "threat actor if attributed",
    "attribution_confidence": "low|medium|high"
  }},
  "attack_graph": {{
    "paths": [
      {{
        "path_id": "short-slug-name",
        "description": "One sentence describing this attack path",
        "steps": [
          {{
            "technique_id": "T1566.001",
            "tactic": "Initial Access",
            "leads_to": ["T1059.001"]
          }},
          {{
            "technique_id": "T1059.001",
            "tactic": "Execution",
            "leads_to": ["T1053.005", "T1210"]
          }}
        ]
      }}
    ],
    "convergence_points": ["T1059.001"],
    "branch_points": ["T1059.001"]
  }}
}}
"""


# ToolResult, ValidationResult, QueryHints imported from framework.plugins.protocol


# ---------------------------------------------------------------------------
# Tool Implementation
# ---------------------------------------------------------------------------


class ThreatIntelIngester:
    """Event Mill plugin: Threat Intelligence Report Ingester.

    Extracts IOCs from threat intelligence reports (PDF, HTML, text)
    using a two-pass approach:
    1. Regex-based extraction for baseline IOC identification
    2. LLM-based refinement for confidence scoring, false positive
       filtering, MITRE ATT&CK mapping, and priority assessment
    """

    def __init__(self) -> None:
        self._manifest: dict | None = None

    def _load_manifest(self) -> dict:
        if self._manifest is None:
            manifest_path = Path(__file__).parent / "manifest.json"
            with open(manifest_path) as f:
                self._manifest = json.load(f)
        return self._manifest

    def metadata(self) -> dict:
        """Return runtime metadata reflecting the manifest."""
        manifest = self._load_manifest()
        return {
            "tool_name": manifest["tool_name"],
            "version": manifest["version"],
            "pillar": manifest["pillar"],
            "display_name": manifest["display_name"],
            "description_short": manifest["description_short"],
            "stability": manifest["stability"],
            "requires_llm": manifest["requires_llm"],
            "artifacts_consumed": manifest["artifacts_consumed"],
            "artifacts_produced": manifest["artifacts_produced"],
        }

    def validate_inputs(self, payload: dict) -> ValidationResult:
        """Validate the input payload against the input schema."""
        errors = []

        if "artifact_id" not in payload:
            errors.append("artifact_id is required")

        if "ioc_types" in payload:
            valid_types = {
                "ip", "domain", "hash_md5", "hash_sha1", "hash_sha256",
                "url", "email", "cve", "mitre_technique",
            }
            for t in payload["ioc_types"]:
                if t not in valid_types:
                    errors.append(f"Unknown ioc_type: {t}")

        if "confidence_threshold" in payload:
            if payload["confidence_threshold"] not in ("low", "medium", "high"):
                errors.append("confidence_threshold must be low, medium, or high")

        if "max_pages" in payload:
            mp = payload["max_pages"]
            if not isinstance(mp, int) or mp < 1 or mp > 1000:
                errors.append("max_pages must be an integer between 1 and 1000")

        return ValidationResult(ok=len(errors) == 0, errors=errors if errors else None)

    def execute(self, payload: dict, context: Any) -> ToolResult:
        """Ingest a threat intelligence report and extract structured IOC data.

        Two-pass extraction:
        1. Regex pass: identify IOC candidates from raw text
        2. LLM pass: refine confidence, filter false positives, map MITRE techniques
        """
        artifact_id = payload.get("artifact_id")
        if not artifact_id:
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=(
                    "artifact_id is required. "
                    "Usage: run threat_intel_ingester {\"artifact_id\": \"<id>\"}"
                ),
            )
        source_context = payload.get("source_context", "")
        ioc_types = payload.get(
            "ioc_types",
            ["ip", "domain", "hash_sha256", "url", "cve", "mitre_technique"],
        )
        confidence_threshold = payload.get("confidence_threshold", "low")
        # None means "no limit here" — the provider manifest's max_pages is
        # the one that matters, and it is enforced by the dispatcher's guard
        # against the provider actually routed to. An explicit max_pages is a
        # deliberate cost ceiling and is honoured, but it is then reported as
        # a truncation rather than as the document's size.
        max_pages = payload.get("max_pages")

        # --- Resolve artifact ---
        artifact = None
        for art in context.artifacts:
            if art.artifact_id == artifact_id:
                artifact = art
                break

        if artifact is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=(
                    f"Artifact {artifact_id!r} not found in session. "
                    f"Use 'artifacts' to list loaded artifacts."
                ),
            )

        if artifact.artifact_type not in ("pdf_report", "html_report", "text", "docx_report"):
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=(
                    f"Artifact type '{artifact.artifact_type}' is not supported. "
                    f"Expected pdf_report, html_report, text (including .md), or docx_report."
                ),
            )

        # --- Extract text ---
        t_start = time.monotonic()
        timings: dict[str, float] = {}
        logger.info(
            "Extracting text from %s artifact %s",
            artifact.artifact_type,
            artifact_id,
        )
        extractor = TEXT_EXTRACTORS[artifact.artifact_type]
        page_texts: list[str] = []
        try:
            if artifact.artifact_type == "pdf_report":
                page_texts = extract_pdf_page_texts(artifact.file_path, max_pages)
                raw_text = "\n\n".join(t for t in page_texts if t)
            else:
                raw_text = extractor(str(artifact.file_path))
                page_texts = [raw_text]
        except Exception as e:
            logger.error("Text extraction failed: %s", e)
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_UNREADABLE",
                message=f"Failed to extract text: {e}",
            )

        pages_total: int | None = None
        pages_dropped = 0
        if artifact.artifact_type == "pdf_report":
            page_count = len(page_texts)
            # A capped read cannot see past its own cap, so ask the file.
            pages_total = (
                pdf_page_total(str(artifact.file_path))
                if max_pages is not None
                else page_count
            )
            if pages_total and pages_total > page_count:
                pages_dropped = pages_total - page_count
                logger.warning(
                    "[TRUNCATED] Read %d of %d pages from %s — pages %d-%d were "
                    "NOT examined and any indicator on them is missing from this "
                    "result. Raise max_pages (up to 1000) or split the document.",
                    page_count, pages_total, artifact_id,
                    page_count + 1, pages_total,
                )
        else:
            page_count = len(raw_text.splitlines())

        timings["extract_s"] = _elapsed(t_start)

        # --- Regex extraction pass ---
        logger.info("Running regex IOC extraction for types: %s", ioc_types)
        raw_iocs = extract_iocs_regex(raw_text, ioc_types)
        logger.info("Regex pass found %d IOC candidates", len(raw_iocs))

        # --- Document profile: what are we about to send to the model? ---
        # Sized against the provider this execution will actually use, once.
        limits = _native_limits(
            context.llm_query if context.llm_enabled else None
        )
        page_iocs = _page_iocs(page_texts, ioc_types)
        doc_profile, profile = _build_profile(
            artifact.artifact_type, page_texts, page_iocs, raw_iocs,
            content_budget=limits.content_budget,
        )
        logger.info(
            "[PROFILE] %s: %d page(s), %d chars, %d candidates (%s), "
            "%.1f/page (max %d on one page), est. output ~%d tokens -> %s",
            artifact.artifact_type, profile["pages"], profile["text_chars"],
            profile["candidates"],
            ", ".join(f"{k}={v}" for k, v in sorted(profile["candidates_by_type"].items()))
            or "none",
            profile["candidates_per_page"], profile["max_candidates_on_a_page"],
            profile["estimated_output_tokens"], profile["profile"],
        )
        if profile["profile"] == "ioc_dense":
            logger.info(
                "[PROFILE] IOC-dense document: the model's reply grows with the "
                "%d candidates, not the page count (est. ~%d output tokens vs "
                "~%d usable per call, of a %d-token cap less the %s-thinking "
                "reserve)%s",
                profile["candidates"], profile["estimated_output_tokens"],
                limits.content_budget, limits.max_output_tokens,
                _NATIVE_THINKING_LEVEL,
                " — too much for one call, so it is split below."
                if profile["exceeds_single_call_output"] else ".",
            )

        # --- Ingestion plan: whole document, page-range batches, or text ---
        native_capable = bool(
            artifact.artifact_type == "pdf_report"
            and context.llm_enabled and context.llm_query is not None
            and hasattr(context.llm_query, "supports_native_document")
            and context.llm_query.supports_native_document("application/pdf")
        )
        plan = plan_ingestion(
            doc_profile,
            native_available=native_capable,
            max_output_tokens=limits.max_output_tokens,
            output_reserve_tokens=limits.thinking_reserve_tokens,
            call_deadline_s=_NATIVE_CALL_DEADLINE_S,
            latency=_latency_model(),
        )
        # The console shows WARNING and above: a document that had to be split
        # says so there, so a multi-minute run is never silent about why.
        logger.log(
            logging.WARNING if plan.strategy != "native" else logging.INFO,
            "[PLAN] %s", plan.describe(),
        )

        # --- LLM refinement pass ---
        refined_iocs = []
        mitre_mappings = []
        report_meta = {}
        attack_graph = {}  # multi-path attack graph from LLM
        native_batch_results: list[dict] = []
        # Parallel to native_batch_results: what each one was, so a partial
        # can be told apart from the retry that replaced it. Kept beside the
        # payload rather than inside it - a key the model emits must never be
        # readable as bookkeeping.
        native_provenance: list[dict] = []
        # Pages the native path could not finish, so the chunked path took
        # them. Method-level because supersession is resolved after both.
        failed_pages: list[int] = []
        native_calls = 0
        # 1-based indices of chunks whose reply stopped at the output cap.
        # Their candidates were only partly assessed, which is invisible in the
        # merged result unless it is recorded here. Method-level, because the
        # result is built outside the LLM block.
        chunk_truncations: list[int] = []
        # Per-chunk outcomes. These were counted for the logs only, so a run
        # where four of ten chunks failed and six succeeded produced a merged
        # result indistinguishable from a clean one — the partial-coverage
        # question the whole of Stage 1 exists to answer.
        chunks_attempted = 0
        chunk_json_failures = 0
        chunk_llm_failures = 0
        chunk_exceptions = 0
        # True once at least one chunk or native batch produced parseable JSON.
        # Distinct from "any IOC survived": a refinement that ran and rejected
        # every candidate is a real answer, not a failure to answer.
        refinement_ran = False
        # Populated by the merge. Defaulted here because the regex-only and
        # total-failure paths never reach it and still build a summary.
        merge_stats: dict = {}
        candidates_rejected = 0
        # Candidates the model never returned a verdict on. The count of
        # rejections says nothing about these: a model that answers about three
        # of forty candidates and rejects all three is not the same as one that
        # assessed forty and accepted none, and the two used to be reported
        # identically. mitre_technique matches are excluded — they are asked
        # for as techniques, not as indicators, so their absence from
        # refined_iocs is correct rather than a gap.
        candidates_unassessed: list[str] = []
        # Every candidate that actually reached a prompt, lowercased value ->
        # the value as extracted. The reconciliation compares verdicts against
        # this rather than against raw_iocs, so that "no verdict" can only ever
        # mean the model was asked and stayed silent. The two agree on every
        # run today - no path drops a candidate between the regex pass and a
        # prompt - so this is an invariant to hold rather than a bug fixed, and
        # the batching change in Stage 2.5 is what it guards.
        candidates_submitted: dict[str, str] = {}
        # Candidates raw_iocs holds that no prompt carried. Our coverage gap,
        # reported apart from the model's silence, because the two have
        # different causes and one counter cannot say which happened.
        candidates_not_submitted: list[str] = []
        # Indicators the canonical verdict rejected while another batch called
        # them real. The rejection stands, but it is not silent.
        rejected_with_dissent: list[str] = []
        # Pages the chunked path must cover: the whole document unless native
        # batches covered some, in which case only the ones that failed. Pages
        # rather than a prebuilt text blob, because the text and the candidates
        # have to be chosen together - see _build_chunk_units.
        fallback_pages = list(range(1, len(page_texts) + 1))

        def _record_submitted(iocs: list[RawIOC]) -> None:
            """Remember the candidates going into a prompt, once each.

            mitre_technique matches are skipped for the same reason the
            reconciliation excludes them: they are asked for as techniques
            rather than indicators, so their absence from refined_iocs is
            correct rather than a gap.
            """
            for ioc in iocs:
                if ioc.ioc_type == "mitre_technique":
                    continue
                key = ioc.value.strip().lower()
                if key and key not in candidates_submitted:
                    candidates_submitted[key] = ioc.value

        if context.llm_enabled and context.llm_query is not None:
            logger.info("[DIAG] LLM enabled, llm_query type=%s", type(context.llm_query).__name__)
            logger.info("Running LLM refinement on %d IOC candidates", len(raw_iocs))

            # Use framework reference data for MITRE grounding
            # Grounded from the local lookup, not from a reference_data key.
            # This read `context.reference_data.get("mitre_attack_enterprise")`
            # until 2026-09-16, and nothing has ever written that key - the
            # shell supplies "mitre_techniques" and "mitre_relationships" - so
            # `grounding` was always empty and every prompt went out with no
            # ATT&CK anchor at all. The reconciler downstream was doing the
            # whole job, which is why a live run needed four tactic
            # corrections and two analyst flags: the model was never told
            # which release it was answering against.
            #
            # Shared with threat_report_analyzer so both tools state one
            # taxonomy in the same words.
            grounding: list[str] = []
            anchor = attack_grounding()
            if anchor:
                grounding.append(anchor)

            # --- Native PDF path: whole document, or page-range batches ---
            native_pdf_succeeded = False
            if native_capable and plan.strategy in ("native", "native_batched"):
                native_cap = limits.max_output_tokens
                latency = _latency_model()
                page_candidate_counts = [len(pg) for pg in page_iocs]
                sub_paths: dict[str, str] = {}
                tmp_dir: str | None = None

                def _batch_document(rng: PageRange) -> ArtifactRef | None:
                    """The document to attach for one range, cut on first use.

                    A range covering every page is the artifact itself; any
                    narrower range becomes a sub-PDF, so the model still sees
                    page images and layout rather than extracted text.

                    "Every page" is measured against the file, not against
                    doc_profile.pages. Those differ exactly when extraction
                    was capped, and attaching the whole artifact there would
                    send the model pages the plan never counted — so the
                    profile would describe a 50-page document while the model
                    read 150.
                    """
                    nonlocal tmp_dir
                    covers_whole_file = (
                        rng.start == 1
                        and rng.end == doc_profile.pages
                        and not pages_dropped
                    )
                    if covers_whole_file:
                        return artifact
                    if rng.label not in sub_paths:
                        try:
                            if tmp_dir is None:
                                workspace = os.environ.get(
                                    "EVENTMILL_WORKSPACE", "./workspace",
                                )
                                batch_root = os.path.join(workspace, "artifacts")
                                os.makedirs(batch_root, exist_ok=True)
                                tmp_dir = tempfile.mkdtemp(
                                    prefix=f"{artifact_id}_batches_", dir=batch_root,
                                )
                            written = split_pdf(
                                artifact.file_path,
                                [(rng.start, rng.end)],
                                tmp_dir,
                                stem=artifact_id,
                            )
                        except (PdfSplitError, OSError) as exc:
                            logger.warning(
                                "[BATCH] Could not cut pages %d-%d out of %s (%s) — "
                                "those pages go to the chunked text path",
                                rng.start, rng.end, artifact_id, exc,
                            )
                            return None
                        sub_paths[rng.label] = str(written[0])
                        logger.info(
                            "[BATCH] Cut %s from %s (%d page(s), %d candidates)",
                            rng.label, artifact_id, rng.pages, rng.candidates,
                        )
                    return ArtifactRef(
                        artifact_id=f"{artifact_id}_{rng.label}",
                        artifact_type="pdf_report",
                        file_path=sub_paths[rng.label],
                        metadata={
                            "mime_type": "application/pdf",
                            "page_range": [rng.start, rng.end],
                            "parent_artifact_id": artifact_id,
                        },
                    )

                # The batches are a queue, not a fixed list: a reply that comes
                # back truncated proves the estimate was wrong for this
                # document, so that range is halved and re-run instead of being
                # accepted with indicators missing.
                pending: list[PageRange] = list(plan.batches)
                calls_left = len(pending) + _NATIVE_MAX_EXTRA_CALLS
                batch_no = 0
                t_native = time.monotonic()
                try:
                    while pending and calls_left > 0:
                        batch = pending.pop(0)
                        calls_left -= 1
                        batch_no += 1
                        doc_ref = _batch_document(batch)
                        if doc_ref is None:
                            failed_pages.extend(range(batch.start, batch.end + 1))
                            continue

                        whole = batch.pages == doc_profile.pages
                        if whole:
                            batch_iocs = raw_iocs
                            page_note = ""
                        else:
                            batch_iocs = _dedupe_iocs([
                                ioc for pg in range(batch.start, batch.end + 1)
                                for ioc in page_iocs[pg - 1]
                            ])
                            page_note = (
                                f" [pages {batch.start}-{batch.end} of "
                                f"{doc_profile.pages}; other pages are "
                                f"processed separately]"
                            )

                        candidates_text = (
                            "\n".join(
                                f"- [{ioc.ioc_type}] {ioc.value} "
                                f"| Context: {ioc.context[:200]}"
                                for ioc in batch_iocs
                            )
                            or "(none found by regex pre-scan)"
                        )
                        _record_submitted(batch_iocs)
                        native_prompt = LLM_REFINEMENT_PROMPT.format(
                            source_context=(source_context or "Not provided") + page_note,
                            ioc_candidates=candidates_text,
                            report_text=(
                                "[Full PDF document is attached — analyze the "
                                "complete document directly instead of this "
                                "placeholder text.]"
                            ),
                        )
                        t_call = time.monotonic()
                        logger.info(
                            "[NATIVE] %s start (call %d): %d candidates in prompt "
                            "(%d chars), max_tokens=%d, tier=%s, thinking=%s, "
                            "pages=%d-%d, est. ~%d output tokens / ~%.0fs",
                            batch.label, batch_no, len(batch_iocs),
                            len(native_prompt), native_cap, _native_tier(),
                            _NATIVE_THINKING_LEVEL, batch.start, batch.end,
                            batch.estimated_output_tokens, batch.estimated_seconds,
                        )
                        try:
                            native_response = context.llm_query.query_with_document(
                                prompt=native_prompt,
                                artifact=doc_ref,
                                system_context=(
                                    "You are a threat intelligence analyst. "
                                    "Respond only with valid JSON."
                                ),
                                max_tokens=native_cap,
                                grounding_data=grounding,
                                hints=QueryHints(
                                    # No tier: the manifest's model_tier
                                    # governs, applied by
                                    # TierScopedLLMClient.
                                    prefers_native_file=True,
                                    needs_structured_output=True,
                                    # Refining regex hits into records is
                                    # extraction, not reasoning, and thinking
                                    # tokens come out of the reply's budget.
                                    thinking_level=_NATIVE_THINKING_LEVEL,
                                ),
                            )
                        except Exception as e:
                            logger.error(
                                "[NATIVE] %s exception after %.1fs — pages %d-%d go "
                                "to the chunked text path | exception_type=%s, message=%s",
                                batch.label, _elapsed(t_call), batch.start, batch.end,
                                type(e).__name__, e, exc_info=True,
                            )
                            failed_pages.extend(range(batch.start, batch.end + 1))
                            continue

                        call_s = _elapsed(t_call)
                        log_llm_interaction(
                            prompt=f"[ti_ingester native_pdf {batch.label}] {native_prompt[:500]}",
                            response_text=native_response.text,
                            model_id=native_response.model_used or "threat_intel_ingester",
                            error=str(native_response.error) if not native_response.ok else None,
                        )
                        logger.info(
                            "[NATIVE] %s done in %.1fs: ok=%s, model=%s, transport=%s, "
                            "finish=%s, response=%d chars, token_usage=%s",
                            batch.label, call_s, native_response.ok,
                            native_response.model_used, native_response.transport_path,
                            native_response.finish_reason,
                            len(native_response.text or ""), native_response.token_usage,
                        )
                        if not native_response.ok and (
                            "DEADLINE" in (native_response.error or "").upper()
                            or "504" in (native_response.error or "")
                        ):
                            logger.warning(
                                "[NATIVE] %s hit the request deadline (%.0fs) with "
                                "%d candidates on %d page(s) (~%.0fs/page observed). "
                                "Lower EVENTMILL_NATIVE_S_PER_PAGE is too optimistic "
                                "for this deployment; these pages go to the chunked path.",
                                batch.label, call_s, len(batch_iocs), batch.pages,
                                call_s / max(1, batch.pages),
                            )

                        parsed = None
                        truncated = bool(native_response.truncated)
                        if native_response.ok and native_response.text:
                            parsed, repaired = _parse_llm_json_result(native_response.text)
                            truncated = truncated or repaired
                            if parsed is None:
                                logger.warning(
                                    "[NATIVE] %s JSON parse failed — pages %d-%d go "
                                    "to the chunked text path | response_length=%d, "
                                    "first_200=%r, last_200=%r",
                                    batch.label, batch.start, batch.end,
                                    len(native_response.text),
                                    native_response.text[:200],
                                    native_response.text[-200:],
                                )
                                log_llm_interaction(
                                    prompt=f"[ti_ingester native_pdf {batch.label}] JSON_PARSE_FAILED",
                                    response_text=native_response.text,
                                    model_id=native_response.model_used or "threat_intel_ingester",
                                    error=(
                                        f"JSON parse failed on {len(native_response.text)}-char "
                                        f"response. first_100={native_response.text[:100]!r}"
                                    ),
                                )
                        elif not native_response.ok:
                            logger.warning(
                                "[NATIVE] %s returned failure — pages %d-%d go to the "
                                "chunked text path | error=%r, fallback_reason=%s",
                                batch.label, batch.start, batch.end,
                                native_response.error, native_response.fallback_reason,
                            )

                        if parsed:
                            native_batch_results.append(parsed)
                            native_provenance.append({
                                "label": batch.label,
                                "attempt_id": batch_no,
                                "page_start": batch.start,
                                "page_end": batch.end,
                                "truncated": truncated,
                                "superseded_by": None,
                            })
                            logger.info(
                                "[NATIVE] %s parsed %s — %d refined_iocs, %d techniques, "
                                "%d attack paths",
                                batch.label, "PARTIAL" if truncated else "OK",
                                len(parsed.get("refined_iocs", [])),
                                len(parsed.get("additional_mitre_techniques", [])),
                                len(parsed.get("attack_graph", {}).get("paths", [])),
                            )
                            if not truncated:
                                continue

                        if truncated:
                            halves = bisect_range(
                                batch, page_candidate_counts, latency=latency,
                            )
                            returned = len(parsed.get("refined_iocs", [])) if parsed else 0
                            if len(halves) > 1 and calls_left >= len(halves):
                                logger.warning(
                                    "[NATIVE] %s was cut off at the output cap after "
                                    "%d of %d candidate(s) — re-running those pages as "
                                    "%s and %s instead of dropping the remainder",
                                    batch.label, returned, len(batch_iocs),
                                    halves[0].label, halves[1].label,
                                )
                                pending[:0] = halves
                                continue
                            logger.warning(
                                "[NATIVE] %s was cut off at the output cap after %d of "
                                "%d candidate(s) and cannot be split further (%d page(s), "
                                "%d call(s) left) — pages %d-%d go to the chunked path "
                                "at %d candidates per call",
                                batch.label, returned, len(batch_iocs), batch.pages,
                                calls_left, batch.start, batch.end, _MAX_IOC_PER_CHUNK,
                            )
                        failed_pages.extend(range(batch.start, batch.end + 1))

                    if pending:
                        leftover = [
                            pg for rng in pending
                            for pg in range(rng.start, rng.end + 1)
                        ]
                        logger.warning(
                            "[NATIVE] Call budget spent with %d page(s) still "
                            "unprocessed (%s) — they go to the chunked text path",
                            len(leftover), ", ".join(rng.label for rng in pending),
                        )
                        failed_pages.extend(leftover)
                finally:
                    timings["native_s"] = _elapsed(t_native)
                    if tmp_dir:
                        shutil.rmtree(tmp_dir, ignore_errors=True)

                native_calls = batch_no
                failed_pages = sorted(set(failed_pages))
                if native_batch_results and not failed_pages:
                    native_pdf_succeeded = True
                    logger.info(
                        "Native PDF ingestion succeeded in %.1fs (%d call(s))",
                        timings["native_s"], len(native_batch_results),
                    )
                elif failed_pages:
                    fallback_pages = list(failed_pages)
                    logger.warning(
                        "[NATIVE] %d call(s) returned usable JSON; %d page(s) (%s) with "
                        "%d candidates fall back to the chunked text path",
                        len(native_batch_results), len(failed_pages),
                        ", ".join(str(pg) for pg in failed_pages[:12])
                        + (" ..." if len(failed_pages) > 12 else ""),
                        sum(len(page_iocs[pg - 1]) for pg in failed_pages),
                    )

            # Split large inputs into chunks to stay within LLM context limits.
            # Large PDFs previously caused repeated 503s even with backoff because
            # the monolithic prompt (100 IOCs + 8 kB text) exceeded the model's
            # comfortable input window.  Each chunk call is ~7-10 kB total.
            # One split, not two. Candidates used to be sliced by index and
            # the text split by paragraph, and chunk i paired slice i with
            # paragraph-chunk i - two orderings with no relationship to each
            # other, so an appendix indicator was routinely asked about beside
            # an unrelated narrative section.
            chunk_units = _build_chunk_units(
                page_texts, page_iocs, ioc_types,
                pages=fallback_pages,
                paged=(artifact.artifact_type == "pdf_report"),
            )
            n_chunks = len(chunk_units)

            if native_pdf_succeeded:
                chunk_units = []
                n_chunks = 0
                logger.info(
                    "Skipping chunked LLM path — native PDF "
                    "ingestion succeeded"
                )

            logger.info(
                "Splitting into %d LLM chunk(s) over %d page(s), %d candidate(s)",
                n_chunks, len(fallback_pages),
                sum(len(u.iocs) for u in chunk_units),
            )

            # Native batch results are merged together with any chunk results
            chunk_results: list[dict] = list(native_batch_results)
            chunk_provenance: list[dict] = [dict(p) for p in native_provenance]
            chunks_attempted = n_chunks
            t_chunks = time.monotonic()
            for i, unit in enumerate(chunk_units):
                t_chunk = time.monotonic()
                ioc_batch = unit.iocs
                # The page label and any gap travel with the text, so the model
                # can cite a page and is told when a section does not continue
                # from the one before it.
                text_chunk = _unit_report_text(unit)

                if not ioc_batch and not unit.text:
                    continue

                candidates_text = (
                    "\n".join(
                        f"- [{ioc.ioc_type}] {ioc.value} | Context: {ioc.context[:200]}"
                        for ioc in ioc_batch
                    )
                    or "(none in this section)"
                )
                _record_submitted(ioc_batch)

                prompt = LLM_REFINEMENT_PROMPT.format(
                    source_context=source_context or "Not provided",
                    ioc_candidates=candidates_text,
                    report_text=text_chunk,
                )

                logger.info(
                    "LLM chunk %d/%d — %d IOCs, %d chars text",
                    i + 1, n_chunks, len(ioc_batch), len(text_chunk),
                )
                logger.info(
                    "[DIAG] Chunk %d/%d PROMPT SENT (%d chars). "
                    "First 500: %.500s",
                    i + 1, n_chunks, len(prompt), prompt[:500],
                )

                try:
                    llm_response = context.llm_query.query_text(
                        prompt=prompt,
                        system_context=(
                            "You are a threat intelligence analyst. "
                            "Respond only with valid JSON."
                        ),
                        max_tokens=4096,
                        grounding_data=grounding,
                        hints=QueryHints(
                            tier="light",
                            needs_structured_output=True,
                            # Bulk IOC extraction is pattern-matching, not
                            # reasoning — the provider default (medium) just
                            # adds latency and cost across N chunks.
                            thinking_level="low",
                        ),
                    )

                    # --- Cloud Logging audit: input + output ---
                    log_llm_interaction(
                        prompt=f"[ti_ingester chunk {i+1}/{n_chunks}] {prompt[:500]}",
                        response_text=llm_response.text,
                        model_id=llm_response.model_used or "threat_intel_ingester",
                        error=(
                            str(llm_response.error)
                            if not llm_response.ok else None
                        ),
                    )

                    logger.info(
                        "[CHUNK] %d/%d done in %.1fs: ok=%s, model=%s, "
                        "%d candidates in, response=%d chars, token_usage=%s",
                        i + 1, n_chunks, _elapsed(t_chunk), llm_response.ok,
                        llm_response.model_used, len(ioc_batch),
                        len(llm_response.text or ""), llm_response.token_usage,
                    )
                    if llm_response.ok and llm_response.text:
                        logger.info(
                            "[DIAG] Chunk %d/%d LLM RESPONSE (%d chars). "
                            "First 500: %.500s",
                            i + 1, n_chunks, len(llm_response.text),
                            llm_response.text[:500],
                        )
                        # Both signals are needed and neither subsumes the
                        # other: truncated is the transport's finish reason,
                        # repaired catches a reply that parsed only after
                        # unmatched brackets were closed. Same pattern the
                        # native path uses.
                        parsed, repaired = _parse_llm_json_result(llm_response.text)
                        if bool(llm_response.truncated) or repaired:
                            chunk_truncations.append(i + 1)
                            logger.warning(
                                "[CHUNK] %d/%d was cut off at the output cap "
                                "(finish_reason_truncated=%s, bracket_repair=%s) "
                                "— its candidates are only partly assessed",
                                i + 1, n_chunks,
                                bool(llm_response.truncated), repaired,
                            )
                        if parsed:
                            n_refined = len(parsed.get("refined_iocs", []))
                            n_fp = sum(
                                1 for r in parsed.get("refined_iocs", [])
                                if r.get("is_false_positive")
                            )
                            n_mitre = len(parsed.get("additional_mitre_techniques", []))
                            n_paths = len(parsed.get("attack_graph", {}).get("paths", []))
                            logger.info(
                                "[DIAG] Chunk %d/%d parsed OK — "
                                "%d refined_iocs (%d false_pos), "
                                "%d additional_mitre, %d attack_paths",
                                i + 1, n_chunks,
                                n_refined, n_fp, n_mitre, n_paths,
                            )
                            chunk_results.append(parsed)
                            chunk_provenance.append({
                                # The page label as well as the ordinal: a
                                # chunk now covers a known page range, so an
                                # occurrence recorded against it can say where
                                # in the report it was seen.
                                "label": (
                                    f"chunk {i + 1}/{n_chunks}"
                                    + (f" ({unit.page_label})"
                                       if unit.page_label else "")
                                ),
                                "attempt_id": i + 1,
                                "source": "chunked",
                                "page_start": unit.page_start,
                                "page_end": unit.page_end,
                                "truncated": (
                                    bool(llm_response.truncated) or repaired
                                ),
                                "superseded_by": None,
                            })
                        else:
                            chunk_json_failures += 1
                            logger.warning(
                                "[DIAG] Chunk %d/%d: JSON parse FAILED "
                                "| response_length=%d, model=%s, "
                                "first_200=%r, last_200=%r",
                                i + 1, n_chunks,
                                len(llm_response.text),
                                llm_response.model_used,
                                llm_response.text[:200],
                                llm_response.text[-200:],
                            )
                    else:
                        logger.warning(
                            "[DIAG] Chunk %d/%d LLM call failed: ok=%s, "
                            "has_text=%s, error=%s",
                            i + 1, n_chunks, llm_response.ok,
                            bool(llm_response.text), llm_response.error,
                        )
                        chunk_llm_failures += 1
                        logger.warning(
                            "[DIAG] Chunk %d/%d FAILED RESPONSE "
                            "| model=%s, error=%r, "
                            "has_text=%s, text_length=%d, "
                            "first_200=%r",
                            i + 1, n_chunks,
                            llm_response.model_used,
                            llm_response.error,
                            llm_response.text is not None,
                            len(llm_response.text or ""),
                            (llm_response.text or "")[:200],
                        )

                except Exception as e:
                    chunk_exceptions += 1
                    logger.error(
                        "[DIAG] Chunk %d/%d EXCEPTION "
                        "| type=%s, message=%s",
                        i + 1, n_chunks, type(e).__name__, e,
                        exc_info=True,
                    )

            if n_chunks:
                timings["chunks_s"] = _elapsed(t_chunks)
            logger.info(
                "[DIAG] LLM loop done in %.1fs — %d/%d chunks produced parseable JSON "
                "(%d JSON failures, %d LLM failures, %d exceptions); "
                "%d native batch result(s) carried in",
                timings.get("chunks_s", 0.0),
                len(chunk_results) - len(native_batch_results), n_chunks,
                chunk_json_failures, chunk_llm_failures, chunk_exceptions,
                len(native_batch_results),
            )

            if chunk_results:
                refinement_ran = True
                # Which pages the chunked path re-read. A native partial that
                # could not be bisected sent its pages here, and the re-read
                # replaces it exactly as a bisected retry would - so this is
                # resolved before the merge, not inside it, because the page
                # bookkeeping lives out here.
                chunked_pages = (
                    set(failed_pages)
                    if len(chunk_results) > len(native_batch_results)
                    else set()
                )
                superseded = _mark_superseded(chunk_provenance, chunked_pages)
                if superseded:
                    logger.info(
                        "[MERGE] %d truncated native partial(s) were replaced "
                        "by a later attempt and no longer win the merge: %s",
                        superseded,
                        ", ".join(
                            f"{p['label']} <- {p['superseded_by']}"
                            for p in chunk_provenance if p.get("superseded_by")
                        ),
                    )
                merged = _merge_llm_chunk_results(chunk_results, chunk_provenance)
                merge_stats = merged.get("merge_stats", {})
                if merge_stats.get("conflicts"):
                    logger.warning(
                        "[MERGE] %d reported value(s) disagree between "
                        "batches; the first is canonical and every reading is "
                        "kept under the record's conflicts",
                        merge_stats["conflicts"],
                    )
                all_refined = merged.get("refined_iocs", [])
                non_fp = [r for r in all_refined if not r.get("is_false_positive", False)]
                candidates_rejected = len(all_refined) - len(non_fp)
                # Reconcile what was asked about against what came back.
                # Compared on value alone: the model relabels ioc_type freely
                # and a type disagreement is not a missing verdict.
                assessed_values = {
                    str(r.get("value", "")).strip().lower() for r in all_refined
                }
                # Against what was submitted, not against raw_iocs. A
                # candidate in neither set was never asked about, which is a
                # coverage gap of ours and not a silence of the model's, so it
                # is counted and reported separately.
                candidates_unassessed = sorted(
                    display
                    for key, display in candidates_submitted.items()
                    if key not in assessed_values
                )
                candidates_not_submitted = sorted({
                    ioc.value for ioc in raw_iocs
                    if ioc.ioc_type != "mitre_technique"
                    and ioc.value.strip().lower() not in candidates_submitted
                })
                if candidates_unassessed:
                    logger.warning(
                        "[DIAG] %d of %d submitted indicator candidate(s) "
                        "received no verdict from the model — first few: %s",
                        len(candidates_unassessed), len(candidates_submitted),
                        candidates_unassessed[:5],
                    )
                if candidates_not_submitted:
                    logger.warning(
                        "[DIAG] %d indicator candidate(s) from the regex pass "
                        "reached no prompt at all — first few: %s",
                        len(candidates_not_submitted),
                        candidates_not_submitted[:5],
                    )
                logger.info(
                    "[DIAG] Merged result — %d refined_iocs total, "
                    "%d after false-positive filter, "
                    "%d additional_mitre, attack_graph paths=%d",
                    len(all_refined), len(non_fp),
                    len(merged.get("additional_mitre_techniques", [])),
                    len(merged.get("attack_graph", {}).get("paths", [])),
                )
                # An entity whose canonical verdict is "false positive" is
                # dropped here, per Stage 1.5 - a rejection is an answer and
                # must not be reinstated. But dropping it silently took its
                # conflict records out of the output too, so a run could
                # report 25 disagreements and show the reader 17. The
                # rejection stands; the dissent is named.
                for refined in all_refined:
                    if not refined.get("is_false_positive", False):
                        refined_iocs.append(refined)
                    elif refined.get("conflicts"):
                        rejected_with_dissent.append(str(refined.get("value", "")))
                if rejected_with_dissent:
                    logger.warning(
                        "[MERGE] %d indicator(s) were dropped as false "
                        "positives while another batch disagreed: %s",
                        len(rejected_with_dissent),
                        ", ".join(rejected_with_dissent[:8]),
                    )
                mitre_mappings = merged.get("additional_mitre_techniques", [])
                report_meta = merged.get("report_metadata", {})
                attack_graph = merged.get("attack_graph", {})
            elif not native_pdf_succeeded:
                logger.warning(
                    "[DIAG] All %d LLM chunks failed — "
                    "json_parse_failures=%d, llm_call_failures=%d, "
                    "exceptions=%d — falling back to regex-only.",
                    n_chunks, chunk_json_failures,
                    chunk_llm_failures, chunk_exceptions,
                )

        # Fall back to the regex baseline only when refinement was unavailable
        # or wholly failed — never when it ran and rejected what it found.
        #
        # "refined_iocs is empty" answers two different questions at once. If
        # the model assessed every candidate as a false positive, reinstating
        # them here returns the exact indicators it rejected, at
        # confidence "low", and labels the run regex_only — turning a correct
        # filtering result into a wrong one. An empty set is the honest answer
        # to "what survived assessment", and it is reported as complete.
        ingestion_mode = "llm"  # track which path produced results
        if not refined_iocs and refinement_ran:
            logger.info(
                "[DIAG] Refinement ran and accepted no candidates — %d assessed "
                "as false positives. Returning zero IOCs rather than "
                "reinstating the regex baseline the model just rejected.",
                candidates_rejected,
            )
        elif not refined_iocs:
            ingestion_mode = "regex_only"
            llm_was_enabled = context.llm_enabled and context.llm_query is not None
            logger.warning(
                "[DIAG] FALLBACK to regex-only — refinement did not run. "
                "LLM enabled=%s, mitre_mappings=%d, attack_graph_paths=%d",
                llm_was_enabled, len(mitre_mappings),
                len(attack_graph.get("paths", [])) if isinstance(attack_graph, dict) else 0,
            )
            logger.info("Using regex-only IOC results (no LLM refinement)")
            refined_iocs = [
                {
                    "ioc_type": ioc.ioc_type,
                    "value": ioc.value,
                    "confidence": "low",
                    "priority": "medium",
                    "context": ioc.context[:300],
                    "related_mitre": [],
                    "defanged": ioc.defanged,
                }
                for ioc in raw_iocs
            ]

        # --- Apply confidence threshold filter ---
        confidence_order = {"low": 0, "medium": 1, "high": 2}
        threshold_value = confidence_order.get(confidence_threshold, 0)
        filtered_iocs = [
            ioc
            for ioc in refined_iocs
            if confidence_order.get(ioc.get("confidence", "low"), 0) >= threshold_value
        ]

        # Computed once, here, because it goes two places: the returned
        # ToolResult and the persisted artifact. An export outlives the session
        # that produced it, and a file read back from the bucket months later
        # has only what was written into it.
        # A PDF is counted in pages; every other artifact type is counted in
        # lines. The keys stay "pages_*" so existing consumers keep working,
        # and "unit" says what they actually mean.
        coverage_unit = "pages" if artifact.artifact_type == "pdf_report" else "lines"
        coverage_fields = {
            "pages_total": pages_total if pages_total else page_count,
            "pages_read": page_count,
            "pages_dropped": pages_dropped,
            "unit": coverage_unit,
        }
        analysis = _analysis_fields(
            ingestion_mode=ingestion_mode,
            pages_total=coverage_fields["pages_total"],
            pages_read=page_count,
            truncated_chunks=chunk_truncations,
            chunks_attempted=chunks_attempted,
            chunks_failed=(
                chunk_json_failures + chunk_llm_failures + chunk_exceptions
            ),
            candidates_rejected=candidates_rejected,
            candidates_unassessed=len(candidates_unassessed),
            candidates_not_submitted=len(candidates_not_submitted),
            merge_conflicts=merge_stats.get("conflicts", 0),
            recovered_from_partial=merge_stats.get("recovered_from_partial", 0),
            rejected_with_dissent=len(rejected_with_dissent),
            # refined_iocs, not filtered_iocs: an empty result after the
            # confidence threshold is the threshold's doing, not a
            # false-positive assessment.
            accepted_none=(refinement_ran and not refined_iocs),
            unit=coverage_unit,
        )

        # --- Build MITRE mappings from IOCs + additional techniques ---
        all_mitre = list(mitre_mappings)  # Start with additional techniques
        seen_techniques = {m["technique_id"] for m in all_mitre}

        for ioc in filtered_iocs:
            for tech_id in ioc.get("related_mitre", []):
                if tech_id not in seen_techniques:
                    seen_techniques.add(tech_id)
                    all_mitre.append(
                        {
                            "technique_id": tech_id,
                            "technique_name": "",  # enriched by _reconcile below
                            "tactic": "",
                            "confidence": "inferred",
                            "report_context": f"Associated with IOC {ioc['value']}",
                        }
                    )

        # --- Reconcile: backfill + enrich from local ATT&CK data ---
        t_reconcile = time.monotonic()
        all_mitre = _reconcile_mitre_mappings(all_mitre, attack_graph)
        timings["reconcile_s"] = _elapsed(t_reconcile)
        timings["total_s"] = _elapsed(t_start)

        # --- Build summary ---
        ioc_breakdown: dict[str, int] = {}
        high_priority_count = 0
        confidence_dist = {"low": 0, "medium": 0, "high": 0}

        for ioc in filtered_iocs:
            ioc_type = ioc["ioc_type"]
            ioc_breakdown[ioc_type] = ioc_breakdown.get(ioc_type, 0) + 1
            if ioc.get("priority") == "high":
                high_priority_count += 1
            conf = ioc.get("confidence", "low")
            confidence_dist[conf] = confidence_dist.get(conf, 0) + 1

        # --- Register output artifact ---
        output_artifact_path = None
        output_artifact_id = None

        if hasattr(context, "register_artifact") and context.register_artifact:
            output_data = {
                "report_metadata": report_meta,
                "iocs": filtered_iocs,
                "mitre_mappings": all_mitre,
                "attack_graph": attack_graph,
                # Coverage and status travel with the data. Without these the
                # artifact says what was found and nothing about what was
                # looked at, and a reader months later cannot tell a full
                # ingestion from one that read a third of the document.
                "coverage": dict(coverage_fields),
                "ingestion_mode": ingestion_mode,
                **analysis,
            }

            # Write artifact file

            workspace = os.environ.get("EVENTMILL_WORKSPACE", "/tmp")
            artifact_dir = os.path.join(workspace, "artifacts")
            os.makedirs(artifact_dir, exist_ok=True)

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix="_ti_iocs.json",
                dir=artifact_dir,
                delete=False,
                prefix="art_",
            ) as f:
                json.dump(output_data, f, indent=2)
                output_artifact_path = f.name

            art_ref = context.register_artifact(
                artifact_type="json_events",
                file_path=output_artifact_path,
                source_tool="threat_intel_ingester",
                metadata={
                    "ioc_count": len(filtered_iocs),
                    "source_artifact": artifact_id,
                },
            )
            output_artifact_id = art_ref.artifact_id

        # --- Build result ---
        output_artifacts_list = None
        if output_artifact_id:
            output_artifacts_list = [
                {
                    "artifact_id": output_artifact_id,
                    "artifact_type": "json_events",
                    "file_path": output_artifact_path,
                    "description": "Structured IOC records extracted from threat intel report.",
                }
            ]

        logger.info(
            "[TIMING] %s | mode=%s | %s",
            artifact_id, ingestion_mode,
            ", ".join(f"{k}={v}" for k, v in timings.items()),
        )
        logger.info(
            "Ingestion complete: %d IOCs, %d MITRE techniques, %d high-priority",
            len(filtered_iocs),
            len(all_mitre),
            high_priority_count,
        )

        return ToolResult(
            ok=True,
            result={
                "report_metadata": {
                    "title": report_meta.get("title", ""),
                    "source_organization": report_meta.get("source_organization", ""),
                    "publication_date": report_meta.get("publication_date", ""),
                    "page_count": page_count,
                    "pages_total": pages_total if pages_total else page_count,
                    "pages_dropped": pages_dropped,
                    "artifact_type": artifact.artifact_type,
                    "campaign_name": report_meta.get("campaign_name", ""),
                    "attributed_actor": report_meta.get("attributed_actor", ""),
                    "attribution_confidence": report_meta.get(
                        "attribution_confidence", ""
                    ),
                    # Every actor and campaign named anywhere in the report,
                    # in order of first mention. The scalars above are the
                    # first of each and are kept for consumers that read
                    # them; a report describing two groups is not a report
                    # about whichever one a batch happened to name first.
                    "actors": list(report_meta.get("actors", [])),
                    "campaigns": list(report_meta.get("campaigns", [])),
                },
                "iocs": filtered_iocs,
                "mitre_mappings": all_mitre,
                "attack_graph": attack_graph,
                "summary": {
                    "total_iocs": len(filtered_iocs),
                    "ioc_breakdown": ioc_breakdown,
                    "high_priority_count": high_priority_count,
                    "mitre_technique_count": len(all_mitre),
                    "unique_technique_count": len(
                        {m.get("technique_id") for m in all_mitre
                         if m.get("technique_id")}
                    ),
                    "confidence_distribution": confidence_dist,
                    "truncated": bool(chunk_truncations),
                    "truncated_chunks": list(chunk_truncations),
                    "chunks_attempted": chunks_attempted,
                    "chunks_failed": (
                        chunk_json_failures + chunk_llm_failures + chunk_exceptions
                    ),
                    "chunk_failure_breakdown": {
                        "json_parse": chunk_json_failures,
                        "llm_call": chunk_llm_failures,
                        "exception": chunk_exceptions,
                    },
                    "candidates_rejected": candidates_rejected,
                    "candidates_unassessed": len(candidates_unassessed),
                    "candidates_not_submitted": len(candidates_not_submitted),
                    "merge_stats": dict(merge_stats),
                    # Bounded: the note carries the count, this carries enough
                    # values to go and look.
                    "rejected_with_dissent": rejected_with_dissent[:25],
                    "native_attempts": len(native_provenance),
                    # What pages_total/pages_read in report_metadata count.
                    "coverage_unit": coverage_unit,
                    **analysis,
                    "ingestion_mode": ingestion_mode,
                    "document_profile": profile,
                    "ingestion_plan": plan.to_dict(),
                    "native_calls": native_calls,
                    "timings": timings,
                    "tactic_corrected_count": sum(
                        1 for m in all_mitre if m.get("tactic_corrected_from")
                    ),
                    "tactic_mismatch_count": sum(
                        1 for m in all_mitre if m.get("tactic_mismatch")
                    ),
                },
            },
            output_artifacts=output_artifacts_list,
        )

    def summarize_for_llm(self, result: Any) -> str:
        """Produce a compressed summary for LLM context window."""
        if not result.ok:
            error = result.message or "Unknown error"
            return f"Threat intel ingestion failed: {error}"

        r = result.result or {}
        meta = r.get("report_metadata", {})
        summary = r.get("summary", {})
        mitre = r.get("mitre_mappings", [])

        parts = []

        # Report identity
        title = meta.get("title", "Unknown report")
        artifact_type = meta.get("artifact_type", "unknown")
        pages = meta.get("page_count", "?")
        size_label = "pages" if artifact_type == "pdf_report" else "lines"
        # Status before anything else, including the report identity. The
        # summary is capped at the manifest's summary_budget by
        # PluginExecutor, so a warning placed after the content is the part
        # that gets cut.
        status = summary.get("analysis_status", "complete")
        notes = "; ".join(summary.get("analysis_notes") or [])
        if status != "complete":
            parts.append(f"{status.upper()} — {notes}.")
        elif notes:
            # A complete run can still carry a note: "every candidate was
            # assessed as a false positive" is a finished answer, but an empty
            # IOC list reads as a failure unless the reason is stated.
            parts.append(f"{notes}.")

        parts.append(f"Ingested {artifact_type} ({pages} {size_label}): {title}.")


        # Attribution
        actor = meta.get("attributed_actor")
        campaign = meta.get("campaign_name")
        if actor:
            conf = meta.get("attribution_confidence", "")
            parts.append(
                f"Attributed to {actor}"
                + (f" ({conf} confidence)" if conf else "")
                + (f", campaign: {campaign}" if campaign else "")
                + "."
            )
        # The scalars above carry one of each. Saying so is what stops a
        # reader taking a single-actor line as the report's whole attribution.
        #
        # A slot, filled once everything else is measured: this is the part
        # that gets whatever room is left, rather than the part that takes the
        # room and leaves the findings to be truncated away.
        others = [
            a.get("name") for a in meta.get("actors", [])[1:] if a.get("name")
        ]
        other_campaigns = [
            c.get("name") for c in meta.get("campaigns", [])[1:] if c.get("name")
        ]
        attribution_slot = None
        if others or other_campaigns:
            attribution_slot = len(parts)
            parts.append("")

        # IOC counts
        total = summary.get("total_iocs", 0)
        breakdown = summary.get("ioc_breakdown", {})
        breakdown_str = ", ".join(
            f"{count} {ioc_type}{'s' if count != 1 else ''}"
            for ioc_type, count in sorted(breakdown.items())
        )
        parts.append(f"Extracted {total} IOCs: {breakdown_str}.")

        # High priority
        hp = summary.get("high_priority_count", 0)
        if hp > 0:
            parts.append(f"{hp} IOCs flagged as high-priority.")

        # MITRE techniques — group by technique_id for multi-role display
        tech_count = summary.get("mitre_technique_count", 0)
        unique_count = summary.get("unique_technique_count", tech_count)
        if tech_count > 0 and mitre:
            by_tid: dict[str, list[str]] = {}
            names: dict[str, str] = {}
            for m in mitre:
                tid = m.get("technique_id", "")
                if not tid:
                    continue
                by_tid.setdefault(tid, [])
                tac = m.get("tactic", "")
                if tac and tac not in by_tid[tid]:
                    by_tid[tid].append(tac)
                if not names.get(tid):
                    names[tid] = m.get("technique_name", "")

            tech_parts = []
            for tid in list(by_tid.keys())[:6]:
                tactics = by_tid[tid]
                if len(tactics) > 1:
                    tech_parts.append(f"{tid} ({', '.join(tactics)})")
                else:
                    tech_parts.append(f"{tid} ({names.get(tid, '')})")

            if unique_count != tech_count:
                parts.append(
                    f"Mapped to {unique_count} unique techniques across "
                    f"{tech_count} tactical roles: {', '.join(tech_parts)}."
                )
            else:
                parts.append(
                    f"Mapped to {tech_count} MITRE techniques: "
                    f"{', '.join(tech_parts)}."
                )
            if len(by_tid) > 6:
                parts.append(f"(and {len(by_tid) - 6} more)")

        # Attack graph paths
        if r.get("attack_graph", {}).get("paths"):
            path_count = len(r["attack_graph"]["paths"])
            convergence = r["attack_graph"].get("convergence_points", [])
            parts.append(
                f"Attack graph: {path_count} path(s) identified"
                + (f", converging at {', '.join(convergence)}" if convergence else "")
                + "."
            )

        # Tactic review guidance
        corrected = summary.get("tactic_corrected_count", 0)
        unresolved = [
            m for m in r.get("mitre_mappings", []) if m.get("tactic_mismatch")
        ]
        if corrected:
            parts.append(
                f"Tactic review: {corrected} tactic label(s) corrected "
                "automatically against ATT&CK (see tactic_corrected_from)."
            )
        if unresolved:
            examples = "; ".join(
                f"{m.get('technique_id')} labelled {m.get('tactic')!r}, "
                f"ATT&CK allows {' / '.join(m.get('allowed_tactics', []))}"
                for m in unresolved[:3]
            )
            more = f" (and {len(unresolved) - 3} more)" if len(unresolved) > 3 else ""
            parts.append(
                f"ACTION: {len(unresolved)} tactic label(s) need analyst "
                f"confirmation — {examples}{more}. Entries carry "
                "tactic_mismatch=true and allowed_tactics in the artifact; "
                "the visualizer marks them 'tactic unconfirmed'."
            )

        # The regex-only warning used to live here, at the end. It is now the
        # DEGRADED INPUT note that leads the summary — saying it twice wastes a
        # budget PluginExecutor caps at summary_budget, and the copy that got
        # cut was this one.

        # Output artifact + quick chart command
        artifacts = result.output_artifacts or []
        if artifacts:
            art = artifacts[0]
            aid = art['artifact_id']
            parts.append(
                f"Output artifact: {aid} "
                f"({art['artifact_type']})."
            )
            parts.append(
                f"Quick chart: run attack_path_visualizer "
                f"--artifact_id {aid} --format mermaid"
            )

        if attribution_slot is not None:
            fixed = len(" ".join(
                p for i, p in enumerate(parts) if i != attribution_slot
            ))
            room = _summary_cap() - _SUMMARY_SAFETY - fixed
            parts[attribution_slot] = _attribution_narration(
                others, other_campaigns, room,
            )
            parts = [p for p in parts if p]

        return " ".join(parts)
