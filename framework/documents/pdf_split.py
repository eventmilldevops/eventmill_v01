"""Cut a PDF into page-range sub-documents.

Used by batched native ingestion: each sub-PDF is sent to the model as a
document, so the page images, tables and layout survive — unlike text
chunking. Splitting is done with pypdf; the extracted text is never used
here.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("eventmill.documents.pdf_split")


class PdfSplitError(RuntimeError):
    """Raised when a PDF cannot be split (missing library, bad range, I/O)."""


def pdf_page_count(path: str | Path) -> int:
    """Number of pages in the PDF, or 0 if it cannot be read."""
    try:
        import pypdf
    except ImportError:
        return 0
    try:
        return len(pypdf.PdfReader(str(path)).pages)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Could not count pages in %s: %s", path, exc)
        return 0


def split_pdf(
    path: str | Path,
    ranges: list[tuple[int, int]],
    out_dir: str | Path,
    stem: str | None = None,
) -> list[Path]:
    """Write one sub-PDF per ``(start, end)`` range (1-based, inclusive).

    Returns the written paths in range order. Ranges beyond the document's
    last page are clipped; an empty range raises ``PdfSplitError``.
    """
    try:
        import pypdf
    except ImportError as exc:
        raise PdfSplitError(
            "pypdf is required to split PDFs into page ranges "
            "(pip install pypdf)"
        ) from exc

    src = Path(path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = stem or src.stem

    try:
        reader = pypdf.PdfReader(str(src))
    except Exception as exc:
        raise PdfSplitError(f"Cannot open {src}: {exc}") from exc
    total = len(reader.pages)

    written: list[Path] = []
    for start, end in ranges:
        end = min(end, total)
        if start < 1 or start > end:
            raise PdfSplitError(
                f"Invalid page range {start}-{end} for a {total}-page document"
            )
        writer = pypdf.PdfWriter()
        for page_idx in range(start - 1, end):
            writer.add_page(reader.pages[page_idx])
        target = out / f"{stem}_p{start}-{end}.pdf"
        try:
            with open(target, "wb") as fh:
                writer.write(fh)
        except OSError as exc:
            raise PdfSplitError(f"Cannot write {target}: {exc}") from exc
        written.append(target)
        logger.info("Wrote %s (pages %d-%d of %d)", target.name, start, end, total)
    return written
