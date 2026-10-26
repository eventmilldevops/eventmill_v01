"""Turn a fetched web page into Markdown an extraction prompt can read.

The conversion is shaped by what the ingester does with the result:

* **Nothing is escaped.** A Markdown converter normally writes ``[.]`` as
  ``\\[.\\]`` and ``evil_domain`` as ``evil\\_domain``. Both stop the IOC
  regexes from matching, so a defanged indicator in a table would be invisible
  to the regex baseline. Escaping is off and the text is kept verbatim.
* **Link targets are dropped and their text kept.** A vendor page links its
  own products, documentation and share buttons dozens of times; every one is a
  URL and domain candidate that costs output tokens and can force a split.
  Indicators in reports are written as text, usually defanged, so they survive.
* **The article is kept and the page around it is not.** Whichever of the
  ``<article>`` and ``<main>`` elements holds the most text, else the body,
  with scripts, styles, form controls, navigation, footers and related-post
  cards removed.
* **Tables and code blocks keep their structure.** IOC tables stay rows, and
  hunting queries stay fenced, so a value stays beside its description.

``split_markdown_sections`` cuts the result at headings, so a document that is
too large for one call is split between sections rather than inside a table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Well beyond any single web report (~250k tokens), and inside the input window
# of every configured provider, so one section batch always fits one call.
MAX_MARKDOWN_CHARS = 1_000_000

# Granularity for splitting when a document does not fit one call. Sections
# are merged back into batches up to the output budget, so this bounds only how
# finely a retry can halve a batch.
MAX_SECTION_CHARS = 20_000

# Form controls, not <form>: ASP.NET pages wrap the whole page in one form.
_DROP_EVERYWHERE = [
    "script", "style", "noscript", "template", "svg", "canvas", "iframe",
    "object", "embed", "button", "input", "select", "textarea",
    "link", "meta",
]
_DROP_IN_CONTENT = ["nav", "footer"]

_HEADING = re.compile(r"^#{1,6}\s")
_FENCE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True)
class MarkdownPage:
    title: str
    markdown: str


def _page_title(soup) -> str:
    og = soup.find("meta", attrs={"property": "og:title"})
    if og and og.get("content"):
        return " ".join(str(og["content"]).split())
    if soup.title and soup.title.string:
        return " ".join(soup.title.string.split())
    h1 = soup.find("h1")
    if h1:
        return " ".join(h1.get_text(" ").split())
    return ""


def _text_len(el) -> int:
    return len(el.get_text(" ", strip=True))


def _content_root(soup):
    """The element holding the report, chosen by how much text it holds.

    ``<article>`` alone is not trusted: blogs use it for related-post cards
    while the post itself sits in ``<main>``. Small ``<article>`` elements
    inside the chosen root are such cards - teasers for other campaigns, whose
    actor names would otherwise be read as part of this report - and are
    removed.
    """
    body = soup.body or soup
    candidates = list(soup.find_all("article"))
    candidates += soup.find_all("main")
    candidates += soup.find_all(attrs={"role": "main"})
    if not candidates:
        return body
    root = max(candidates, key=_text_len)
    root_len = _text_len(root)
    if root_len < 0.2 * _text_len(body):
        return body
    for card in root.find_all("article"):
        if _text_len(card) < 0.1 * root_len:
            card.decompose()
    return root


def _converter_class():
    from markdownify import MarkdownConverter

    class _ReportConverter(MarkdownConverter):
        def convert_a(self, el, text, *args, **kwargs):
            return text or ""

        def convert_img(self, el, text, *args, **kwargs):
            alt = " ".join((el.get("alt") or "").split())
            return f"[Image: {alt}]" if alt else ""

    return _ReportConverter


def html_to_markdown(
    html: bytes | str,
    *,
    encoding: str | None = None,
) -> MarkdownPage:
    """Convert one HTML page to report Markdown.

    Requires ``beautifulsoup4`` and ``markdownify`` (the plugins-log-analysis
    extra); ImportError propagates so the caller can name the missing package.
    """
    from bs4 import BeautifulSoup

    if isinstance(html, bytes):
        soup = BeautifulSoup(html, "html.parser", from_encoding=encoding)
    else:
        soup = BeautifulSoup(html, "html.parser")

    title = _page_title(soup)
    for tag in soup.find_all(_DROP_EVERYWHERE):
        tag.decompose()
    root = _content_root(soup)
    for tag in root.find_all(_DROP_IN_CONTENT):
        tag.decompose()
    for tag in root.find_all(attrs={"role": "navigation"}):
        tag.decompose()

    converter = _converter_class()(
        heading_style="ATX",
        bullets="*",
        escape_asterisks=False,
        escape_underscores=False,
        escape_misc=False,
        code_language="",
    )
    markdown = converter.convert_soup(root)
    markdown = "\n".join(line.rstrip() for line in markdown.splitlines())
    markdown = re.sub(r"\n{3,}", "\n\n", markdown).strip()

    if title:
        head = markdown[:500].lower()
        if title.lower() not in head:
            markdown = f"# {title}\n\n{markdown}" if markdown else f"# {title}"
    return MarkdownPage(title=title, markdown=markdown)


def text_to_markdown(body: bytes, encoding: str | None = None) -> str:
    """Decode a plain-text or Markdown body; it is already readable as-is."""
    try:
        text = body.decode(encoding or "utf-8")
    except (LookupError, UnicodeDecodeError):
        text = body.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _split_long(lines: list[str], max_chars: int) -> list[str]:
    """Cut one oversized section at line boundaries, keeping fences balanced."""
    pieces: list[str] = []
    current: list[str] = []
    size = 0
    fence: str | None = None
    for line in lines:
        cost = len(line) + 1
        if current and size + cost > max_chars:
            if fence:
                current.append(fence)
            pieces.append("\n".join(current).strip())
            current = [fence] if fence else []
            size = sum(len(x) + 1 for x in current)
        current.append(line)
        size += cost
        match = _FENCE.match(line)
        if match:
            fence = None if fence else match.group(1)
    if current:
        pieces.append("\n".join(current).strip())
    return [p for p in pieces if p]


def split_markdown_sections(
    markdown: str,
    max_section_chars: int = MAX_SECTION_CHARS,
) -> list[str]:
    """Split Markdown into sections, each starting at a heading.

    Headings inside fenced code are not boundaries. Text before the first
    heading is its own section. A section longer than ``max_section_chars`` is
    cut further at line boundaries. Nothing is dropped except blank sections.
    """
    sections: list[list[str]] = []
    current: list[str] = []
    in_fence = False
    for line in markdown.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and _HEADING.match(line) and any(x.strip() for x in current):
            sections.append(current)
            current = []
        current.append(line)
    if current:
        sections.append(current)

    out: list[str] = []
    for lines in sections:
        text = "\n".join(lines).strip()
        if not text:
            continue
        if len(text) > max_section_chars:
            out.extend(_split_long(lines, max_section_chars))
        else:
            out.append(text)
    return out
