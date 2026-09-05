"""Tests for framework.documents: profile, ingestion plan, PDF page-range split."""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.documents import (
    LatencyModel,
    PdfSplitError,
    plan_ingestion,
    profile_document,
    split_pdf,
)
from framework.documents.profile import (
    DEADLINE_HEADROOM,
    OUTPUT_HEADROOM,
    OUTPUT_TOKENS_BASE,
    OUTPUT_TOKENS_PER_CANDIDATE,
)

CAP = 16_384
DEADLINE = 120.0


class TestProfile:
    def test_basic_measurements(self):
        prof = profile_document("pdf_report", [1000, 2000, 500], [2, 40, 0], CAP)
        assert prof.pages == 3
        assert prof.text_chars == 3500
        assert prof.candidates == 42
        assert prof.candidates_per_page == 14.0
        assert prof.max_candidates_on_a_page == 40
        assert prof.profile == "ioc_dense"
        assert prof.estimated_output_tokens == OUTPUT_TOKENS_BASE + 42 * OUTPUT_TOKENS_PER_CANDIDATE
        assert prof.exceeds_single_call_output is False

    def test_narrative_and_dict(self):
        prof = profile_document("pdf_report", [3000] * 10, [1] * 10, CAP)
        assert prof.profile == "narrative"
        d = prof.to_dict()
        assert d["pages"] == 10 and d["candidates"] == 10
        assert set(d) >= {"profile", "estimated_output_tokens", "exceeds_single_call_output"}

    def test_exceeds_cap(self):
        prof = profile_document("text", [5000], [400], CAP)
        assert prof.exceeds_single_call_output is True

    def test_mismatched_lists_rejected(self):
        with pytest.raises(ValueError):
            profile_document("text", [1, 2], [1])

    def test_empty_document(self):
        prof = profile_document("text", [], [], CAP)
        assert prof.pages == 1 and prof.candidates == 0


class TestPlan:
    def test_small_document_goes_native_whole(self):
        prof = profile_document("pdf_report", [2000] * 4, [3, 2, 0, 1], CAP)
        plan = plan_ingestion(prof, native_available=True, max_output_tokens=CAP, call_deadline_s=DEADLINE)
        assert plan.strategy == "native"
        assert len(plan.batches) == 1
        assert (plan.batches[0].start, plan.batches[0].end) == (1, 4)
        assert plan.estimated_seconds < DEADLINE * DEADLINE_HEADROOM

    def test_not_native_capable(self):
        prof = profile_document("html_report", [2000], [3], CAP)
        plan = plan_ingestion(prof, native_available=False, max_output_tokens=CAP, call_deadline_s=DEADLINE)
        assert plan.strategy == "chunked_text"
        assert plan.batches == []

    def test_dense_document_is_batched_on_page_boundaries(self):
        # 20 pages, 30 candidates each: whole doc ~43k output tokens, ~370 s
        prof = profile_document("pdf_report", [3000] * 20, [30] * 20, CAP)
        plan = plan_ingestion(prof, native_available=True, max_output_tokens=CAP, call_deadline_s=DEADLINE)
        assert plan.strategy == "native_batched"
        assert len(plan.batches) > 1
        # contiguous, ordered, covering every page exactly once
        assert plan.batches[0].start == 1
        assert plan.batches[-1].end == 20
        for a, b in zip(plan.batches, plan.batches[1:]):
            assert b.start == a.end + 1
        cap = int(CAP * OUTPUT_HEADROOM)
        deadline = DEADLINE * DEADLINE_HEADROOM
        for b in plan.batches:
            assert b.estimated_output_tokens <= cap
            assert b.estimated_seconds <= deadline
            assert not b.oversized
        assert sum(b.candidates for b in plan.batches) == 600
        assert plan.estimated_seconds == pytest.approx(sum(b.estimated_seconds for b in plan.batches))
        assert "split on page boundaries" in plan.reason

    def test_latency_dominates_for_narrative_long_document(self):
        # Few candidates but many pages: pages, not tokens, force the split
        prof = profile_document("pdf_report", [3000] * 30, [1] * 30, CAP)
        plan = plan_ingestion(prof, native_available=True, max_output_tokens=CAP, call_deadline_s=DEADLINE)
        assert plan.strategy == "native_batched"
        assert all(b.pages <= 7 for b in plan.batches)  # 10 + 12*7 = 94 s < 96 s

    def test_oversized_page_is_its_own_batch_and_flagged(self):
        prof = profile_document("pdf_report", [3000, 30000, 3000], [2, 400, 2], CAP)
        plan = plan_ingestion(prof, native_available=True, max_output_tokens=CAP, call_deadline_s=DEADLINE)
        assert plan.strategy == "native_batched"
        big = next(b for b in plan.batches if b.oversized)
        assert (big.start, big.end) == (2, 2)
        assert "exceed a cap on their own" in plan.reason

    def test_custom_latency_model_changes_batching(self):
        prof = profile_document("pdf_report", [3000] * 10, [5] * 10, CAP)
        fast = LatencyModel(base_seconds=1, seconds_per_page=1, seconds_per_candidate=0.01)
        slow = LatencyModel(base_seconds=10, seconds_per_page=40, seconds_per_candidate=0.5)
        assert plan_ingestion(prof, native_available=True, max_output_tokens=CAP,
                              call_deadline_s=DEADLINE, latency=fast).strategy == "native"
        assert plan_ingestion(prof, native_available=True, max_output_tokens=CAP,
                              call_deadline_s=DEADLINE, latency=slow).strategy == "native_batched"

    def test_describe_and_to_dict(self):
        prof = profile_document("pdf_report", [3000] * 20, [30] * 20, CAP)
        plan = plan_ingestion(prof, native_available=True, max_output_tokens=CAP, call_deadline_s=DEADLINE)
        text = plan.describe()
        assert text.startswith("native_batched:")
        assert "p1-" in text
        d = plan.to_dict()
        assert d["batch_count"] == len(plan.batches)
        assert d["batches"][0]["pages"] == plan.batches[0].pages


@pytest.fixture
def blank_pdf(tmp_path: Path) -> Path:
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    for _ in range(7):
        writer.add_blank_page(width=200, height=200)
    path = tmp_path / "seven.pdf"
    with open(path, "wb") as fh:
        writer.write(fh)
    return path


class TestSplitPdf:
    def test_writes_ranges_with_correct_page_counts(self, blank_pdf, tmp_path):
        pypdf = pytest.importorskip("pypdf")
        out = split_pdf(blank_pdf, [(1, 3), (4, 5), (6, 7)], tmp_path / "parts", stem="doc")
        assert [p.name for p in out] == ["doc_p1-3.pdf", "doc_p4-5.pdf", "doc_p6-7.pdf"]
        assert [len(pypdf.PdfReader(str(p)).pages) for p in out] == [3, 2, 2]

    def test_range_past_end_is_clipped(self, blank_pdf, tmp_path):
        pypdf = pytest.importorskip("pypdf")
        out = split_pdf(blank_pdf, [(6, 40)], tmp_path / "parts")
        assert out[0].name.endswith("_p6-7.pdf")
        assert len(pypdf.PdfReader(str(out[0])).pages) == 2

    def test_invalid_range_raises(self, blank_pdf, tmp_path):
        pytest.importorskip("pypdf")
        with pytest.raises(PdfSplitError):
            split_pdf(blank_pdf, [(5, 2)], tmp_path / "parts")

    def test_missing_file_raises(self, tmp_path):
        pytest.importorskip("pypdf")
        with pytest.raises(PdfSplitError):
            split_pdf(tmp_path / "nope.pdf", [(1, 1)], tmp_path / "parts")
