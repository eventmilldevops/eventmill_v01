"""Document profile and ingestion plan.

The model's reply to an IOC-extraction prompt is one JSON record per
indicator, so its size — and the time it takes to generate — grows with the
number of indicator candidates, not with the number of pages. A 20-page
IOC appendix costs more than a 100-page narrative report. This module turns
per-page measurements taken before any LLM call into a plan:

* ``native`` — one call with the whole document attached.
* ``native_batched`` — several calls, each with a page-range sub-document
  attached, sized so no call exceeds the output-token cap or the request
  deadline. Batches always split on page boundaries.
* ``chunked_text`` — extracted text and candidate lists in small calls;
  the path for callers that cannot send documents natively.

Everything here is arithmetic on counts the caller supplies; the module
knows nothing about IOC regexes or the LLM client.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# ---------------------------------------------------------------------------
# Cost model defaults
# ---------------------------------------------------------------------------

# Output tokens per refined indicator record (value, type, confidence,
# priority, context, related techniques) and a fixed allowance for report
# metadata, additional techniques and the attack graph.
OUTPUT_TOKENS_PER_CANDIDATE = 70
OUTPUT_TOKENS_BASE = 1_500

# Candidates per page at or above which a document is "ioc_dense".
IOC_DENSE_PER_PAGE = 8.0

# Fraction of a cap a batch may use, leaving headroom for estimate error.
OUTPUT_HEADROOM = 0.75
DEADLINE_HEADROOM = 0.80


@dataclass(frozen=True)
class LatencyModel:
    """Seconds a native document call takes, as a function of its inputs.

    Calibrated from observed runs on the heavy tier: a 5-page, 14-candidate
    PDF took ~80 s, and a 133-candidate batch was still generating past the
    120 s deadline. Writing the records dominates — the per-candidate term is
    what keeps a batch inside the deadline, and at these values a batch lands
    near the ~50 candidates per call the chunked path already sustains.
    Override per deployment if the model or tier changes.
    """

    base_seconds: float = 10.0
    seconds_per_page: float = 12.0
    seconds_per_candidate: float = 0.7

    def estimate(self, pages: int, candidates: int) -> float:
        return (
            self.base_seconds
            + self.seconds_per_page * pages
            + self.seconds_per_candidate * candidates
        )


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


@dataclass
class DocumentProfile:
    """What was measured before any model call."""

    artifact_type: str
    pages: int
    text_chars: int
    candidates: int
    candidates_per_page_list: list[int] = field(default_factory=list)
    chars_per_page_list: list[int] = field(default_factory=list)
    estimated_output_tokens: int = 0
    max_output_tokens: int = 0

    @property
    def candidates_per_page(self) -> float:
        return round(self.candidates / max(1, self.pages), 1)

    @property
    def max_candidates_on_a_page(self) -> int:
        return max(self.candidates_per_page_list) if self.candidates_per_page_list else 0

    @property
    def profile(self) -> str:
        return "ioc_dense" if self.candidates_per_page >= IOC_DENSE_PER_PAGE else "narrative"

    @property
    def exceeds_single_call_output(self) -> bool:
        return bool(self.max_output_tokens) and (
            self.estimated_output_tokens > self.max_output_tokens
        )

    def to_dict(self) -> dict:
        return {
            "artifact_type": self.artifact_type,
            "pages": self.pages,
            "text_chars": self.text_chars,
            "candidates": self.candidates,
            "candidates_per_page": self.candidates_per_page,
            "max_candidates_on_a_page": self.max_candidates_on_a_page,
            "estimated_output_tokens": self.estimated_output_tokens,
            "exceeds_single_call_output": self.exceeds_single_call_output,
            "profile": self.profile,
        }


def estimate_output_tokens(candidates: int) -> int:
    return OUTPUT_TOKENS_BASE + candidates * OUTPUT_TOKENS_PER_CANDIDATE


def profile_document(
    artifact_type: str,
    page_chars: list[int],
    page_candidates: list[int],
    max_output_tokens: int = 0,
) -> DocumentProfile:
    """Build a profile from per-page measurements.

    ``page_chars`` and ``page_candidates`` are parallel lists, one entry per
    page (a non-paged document is a single page). ``page_candidates`` should
    be counted per page *after* whatever de-duplication the caller applies,
    so the total matches what will actually be sent to the model.
    """
    if len(page_chars) != len(page_candidates):
        raise ValueError("page_chars and page_candidates must have the same length")
    pages = max(1, len(page_chars))
    candidates = sum(page_candidates)
    return DocumentProfile(
        artifact_type=artifact_type,
        pages=pages,
        text_chars=sum(page_chars),
        candidates=candidates,
        candidates_per_page_list=list(page_candidates),
        chars_per_page_list=list(page_chars),
        estimated_output_tokens=estimate_output_tokens(candidates),
        max_output_tokens=max_output_tokens,
    )


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


@dataclass
class PageRange:
    """A contiguous 1-based, inclusive page range to send in one call."""

    start: int
    end: int
    candidates: int
    estimated_output_tokens: int
    estimated_seconds: float
    oversized: bool = False  # a single page that alone exceeds a cap

    @property
    def pages(self) -> int:
        return self.end - self.start + 1

    @property
    def label(self) -> str:
        return f"p{self.start}-{self.end}" if self.pages > 1 else f"p{self.start}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["pages"] = self.pages
        return d


@dataclass
class IngestionPlan:
    strategy: str  # native | native_batched | chunked_text
    reason: str
    batches: list[PageRange] = field(default_factory=list)
    estimated_seconds: float = 0.0
    output_cap_per_call: int = 0
    deadline_per_call_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "reason": self.reason,
            "batch_count": len(self.batches),
            "batches": [b.to_dict() for b in self.batches],
            "estimated_seconds": round(self.estimated_seconds, 1),
            "output_cap_per_call": self.output_cap_per_call,
            "deadline_per_call_s": self.deadline_per_call_s,
        }

    def describe(self) -> str:
        """One line for logs and run summaries."""
        if self.strategy == "native_batched":
            ranges = ", ".join(
                f"{b.label} ({b.candidates} cand.)" for b in self.batches
            )
            return (
                f"{self.strategy}: {len(self.batches)} batch(es) [{ranges}], "
                f"est. {self.estimated_seconds:.0f}s — {self.reason}"
            )
        return f"{self.strategy}: est. {self.estimated_seconds:.0f}s — {self.reason}"


def _fits(tokens: int, seconds: float, plan_cap: int, plan_deadline: float) -> bool:
    return tokens <= plan_cap and seconds <= plan_deadline


def plan_ingestion(
    profile: DocumentProfile,
    *,
    native_available: bool,
    max_output_tokens: int,
    call_deadline_s: float,
    output_reserve_tokens: int = 0,
    latency: LatencyModel | None = None,
) -> IngestionPlan:
    """Decide how to send the document to the model.

    ``max_output_tokens`` is the cap on one call's reply; ``call_deadline_s``
    is the request deadline the client enforces. Both are reduced by a
    headroom factor before comparison so estimate error does not turn into a
    truncated reply or a 504.

    ``output_reserve_tokens`` is subtracted from the cap first: on a thinking
    model the reasoning tokens are drawn from the same budget as the reply,
    so only the remainder is available for JSON. Sizing batches against the
    full cap is what truncates a reply mid-record.
    """
    latency = latency or LatencyModel()
    content_budget = max(1, max_output_tokens - max(0, output_reserve_tokens))
    cap = int(content_budget * OUTPUT_HEADROOM)
    deadline = call_deadline_s * DEADLINE_HEADROOM

    whole_tokens = profile.estimated_output_tokens
    whole_seconds = latency.estimate(profile.pages, profile.candidates)

    if not native_available:
        return IngestionPlan(
            strategy="chunked_text",
            reason="native document ingestion not available for this artifact",
            estimated_seconds=whole_seconds,
            output_cap_per_call=cap,
            deadline_per_call_s=round(deadline, 1),
        )

    if _fits(whole_tokens, whole_seconds, cap, deadline):
        return IngestionPlan(
            strategy="native",
            reason=(
                f"whole document fits one call "
                f"(~{whole_tokens} of {cap} output tokens, "
                f"~{whole_seconds:.0f}s of {deadline:.0f}s)"
            ),
            batches=[
                PageRange(1, profile.pages, profile.candidates, whole_tokens, whole_seconds)
            ],
            estimated_seconds=whole_seconds,
            output_cap_per_call=cap,
            deadline_per_call_s=round(deadline, 1),
        )

    # Greedy page-boundary batching: close a batch when the next page would
    # push it over either cap. A page that alone exceeds a cap becomes its
    # own batch and is marked oversized so the caller can treat it specially.
    batches: list[PageRange] = []
    start = 1
    run_candidates = 0
    for idx, page_cand in enumerate(profile.candidates_per_page_list, start=1):
        trial_cand = run_candidates + page_cand
        trial_pages = idx - start + 1
        trial_tokens = estimate_output_tokens(trial_cand)
        trial_seconds = latency.estimate(trial_pages, trial_cand)
        if start != idx and not _fits(trial_tokens, trial_seconds, cap, deadline):
            batches.append(_make_range(start, idx - 1, run_candidates, latency, cap, deadline))
            start = idx
            run_candidates = page_cand
        else:
            run_candidates = trial_cand
    batches.append(_make_range(start, profile.pages, run_candidates, latency, cap, deadline))

    total_seconds = sum(b.estimated_seconds for b in batches)
    oversized = [b.label for b in batches if b.oversized]
    reason = (
        f"whole document would need ~{whole_tokens} output tokens "
        f"(cap {cap}) and ~{whole_seconds:.0f}s (deadline {deadline:.0f}s); "
        f"split on page boundaries"
    )
    if oversized:
        reason += f"; page(s) {', '.join(oversized)} exceed a cap on their own"
    return IngestionPlan(
        strategy="native_batched",
        reason=reason,
        batches=batches,
        estimated_seconds=total_seconds,
        output_cap_per_call=cap,
        deadline_per_call_s=round(deadline, 1),
    )


def bisect_range(
    rng: PageRange,
    page_candidates: list[int],
    *,
    latency: LatencyModel | None = None,
) -> list[PageRange]:
    """Split one batch in two at the page boundary nearest half its candidates.

    The retry path for a batch whose reply came back truncated: the estimate
    that sized it was wrong, so the only sound response is to send less of the
    document per call. A single page cannot be split — it is returned
    unchanged, and the caller falls back to the text path for that page.
    """
    if rng.pages < 2:
        return [rng]
    latency = latency or LatencyModel()
    page_slice = page_candidates[rng.start - 1: rng.end]
    half = sum(page_slice) / 2
    cut = rng.start
    run = 0
    for offset, count in enumerate(page_slice[:-1]):
        run += count
        cut = rng.start + offset
        if run >= half:
            break
    cut = min(max(cut, rng.start), rng.end - 1)
    return [
        range_from_pages(rng.start, cut, page_candidates, latency),
        range_from_pages(cut + 1, rng.end, page_candidates, latency),
    ]


def range_from_pages(
    start: int, end: int, page_candidates: list[int],
    latency: LatencyModel | None = None,
) -> PageRange:
    """A PageRange over ``start..end`` costed from per-page candidate counts."""
    latency = latency or LatencyModel()
    candidates = sum(page_candidates[start - 1: end])
    pages = end - start + 1
    return PageRange(
        start=start,
        end=end,
        candidates=candidates,
        estimated_output_tokens=estimate_output_tokens(candidates),
        estimated_seconds=round(latency.estimate(pages, candidates), 1),
    )


def _make_range(
    start: int, end: int, candidates: int,
    latency: LatencyModel, cap: int, deadline: float,
) -> PageRange:
    pages = end - start + 1
    tokens = estimate_output_tokens(candidates)
    seconds = latency.estimate(pages, candidates)
    return PageRange(
        start=start,
        end=end,
        candidates=candidates,
        estimated_output_tokens=tokens,
        estimated_seconds=round(seconds, 1),
        oversized=not _fits(tokens, seconds, cap, deadline),
    )
