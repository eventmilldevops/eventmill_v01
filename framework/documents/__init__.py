"""Document profiling and ingestion planning.

Deterministic, LLM-free analysis of a document before any model call:
how many pages, how many indicator candidates per page, how much output
the model will have to produce, and therefore how the document should be
sent — whole, in page-range batches, or as chunked text.

See ``profile.py`` for the profile / plan model and ``pdf_split.py`` for
cutting a PDF into page-range sub-documents that keep the native
(page-image) ingestion path.
"""

from .pdf_split import PdfSplitError, split_pdf
from .profile import (
    DocumentProfile,
    IngestionPlan,
    LatencyModel,
    PageRange,
    bisect_range,
    plan_ingestion,
    profile_document,
    range_from_pages,
)

__all__ = [
    "DocumentProfile",
    "IngestionPlan",
    "LatencyModel",
    "PageRange",
    "PdfSplitError",
    "bisect_range",
    "plan_ingestion",
    "profile_document",
    "range_from_pages",
    "split_pdf",
]
