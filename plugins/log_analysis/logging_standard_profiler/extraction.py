"""Reading a logging standard into requirement records.

The model does the reading; everything around it is deterministic. Document
text is extracted locally so that every quote the model returns can be looked
for in the source, and a reply is parsed as untrusted shape: fenced, wrapped,
truncated or oddly nested JSON yields what can be salvaged plus a note.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Characters of standard text per call on the text path. Standards are prose,
# roughly 4 characters a token, so this is about 30k tokens a part.
TEXT_PART_CHARS = 120_000

EXAMPLE_REPLY = {
    "standard": {
        "title": "Example Corp Application Logging Standard",
        "version": "v2.1 (March 2024)",
    },
    "requirements": [
        {
            "requirement_id": "4.2.1",
            "section": "4.2 Record content",
            "page": 7,
            "obligation": "must",
            "assessable_from": "record_content",
            "summary": "Every record carries a UTC timestamp with millisecond precision.",
            "quote": "Each log entry shall include a timestamp in UTC with at least millisecond resolution.",
            "elements": [
                {
                    "element": "timestamp",
                    "constraints": {
                        "timezone_required": True,
                        "min_precision": "millisecond",
                    },
                }
            ],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "4.2.3",
            "section": "4.2 Record content",
            "page": 7,
            "obligation": "must",
            "assessable_from": "record_content",
            "summary": "Authentication events identify the user and whether the attempt succeeded.",
            "quote": "Authentication events shall record the user identity and the outcome of the attempt.",
            "elements": [{"element": "actor_identity"}, {"element": "outcome"}],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "6.1",
            "section": "6 Retention",
            "page": 12,
            "obligation": "must",
            "assessable_from": "not_assessable_from_sample",
            "summary": "Logs are retained for at least twelve months.",
            "quote": "Log data shall be retained for a minimum of twelve months.",
            "elements": [],
            "unmapped_reason": None,
        },
    ],
}

SYSTEM_CONTEXT = (
    "You are an audit analyst reading a logging standard. You extract only "
    "what the document states, quote it exactly, and return JSON."
)


def document_pages(path: Path) -> tuple[list[str], str | None]:
    """Text of the document, one string per page. ``(pages, problem)``.

    A PDF with no text layer returns empty pages and a problem string; the
    caller can still read it natively, it just cannot check quotes.
    """
    if path.suffix.lower() == ".pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(str(path))
            pages = [(page.extract_text() or "") for page in reader.pages]
        except Exception as exc:  # noqa: BLE001 - any pypdf failure is the same answer
            return [], f"could not extract PDF text: {exc}"
        if not any(page.strip() for page in pages):
            return pages, "the PDF has no extractable text layer"
        return pages, None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"could not read file: {exc}"
    return [text], None


def text_parts(
    pages: list[str], max_chars: int = TEXT_PART_CHARS
) -> list[dict[str, Any]]:
    """Group consecutive pages into parts that fit one call."""
    parts: list[dict[str, Any]] = []
    current: list[str] = []
    size = 0
    first = 1
    for number, page in enumerate(pages, start=1):
        piece = f"\n[page {number}]\n{page}"
        if len(piece) > max_chars:
            piece = piece[:max_chars]
        if current and size + len(piece) > max_chars:
            parts.append(
                {"first_page": first, "last_page": number - 1, "text": "".join(current)}
            )
            current, size, first = [], 0, number
        current.append(piece)
        size += len(piece)
    if current:
        parts.append(
            {"first_page": first, "last_page": len(pages), "text": "".join(current)}
        )
    return parts


def build_prompt(
    catalogue: dict[str, Any], content: str | None, part_note: str = ""
) -> str:
    elements = "\n".join(
        f"- {name} ({spec['value_type']}): {spec['description']}"
        for name, spec in catalogue["elements"].items()
    )
    constraints = "\n".join(
        f"- {name}: {text}" for name, text in catalogue.get("constraints", {}).items()
    )
    source = (
        "The standard is attached as a document. Read all of it."
        if content is None
        else f"STANDARD TEXT{part_note}:\n{content}"
    )
    return f"""Extract the logging requirements from this standard.

Most of a standard is scope, definitions, roles and rationale. Skip that. Keep
only statements that say what must, should or may be logged, what a log record
has to contain, how its values must be formatted, and how logs are to be
handled. One requirement per statement; do not merge statements and do not
invent requirements the document does not make.

For each requirement return:
- requirement_id: the document's own clause or control number if it has one.
- section: the heading it sits under.
- page: the page number it appears on.
- obligation: "must" (shall, must, required), "should" (should, recommended)
  or "may" (may, optional), as the document words it.
- summary: one sentence in plain words.
- quote: the sentence from the document, copied exactly, character for
  character. It will be searched for in the document, so do not paraphrase,
  join or tidy it. Keep it under 60 words.
- assessable_from:
    "record_content" - can be checked by looking inside individual log
      records (a field is present, a value has a format).
    "record_set" - needs many records together (ordering, gaps, that a
      kind of event appears at all).
    "not_assessable_from_sample" - cannot be seen in a log file at all:
      retention, access control, protection, review, roles, storage.
- elements: for the first two kinds, which record elements the requirement
  needs, chosen ONLY from this catalogue:
{elements}
  Each entry is {{"element": name}} with optional "constraints":
{constraints}
  Use an empty list for "not_assessable_from_sample".
- unmapped_reason: if the requirement is about record content but no catalogue
  element expresses it, leave elements empty and say here what it needs.
  Otherwise null. Never force a requirement onto an element that does not fit.

Reply with one JSON object and nothing else, shaped exactly like this example
(the example's content is invented; only its shape matters):

{json.dumps(EXAMPLE_REPLY, indent=2)}

{source}
"""


def _strip_fences(text: str) -> str:
    text = text.strip()
    match = re.match(r"^```[a-zA-Z]*\s*\n(.*?)(?:\n```\s*)?$", text, re.DOTALL)
    return match.group(1).strip() if match else text


def _balanced_objects(text: str, start: int) -> list[str]:
    """Complete top-level ``{...}`` objects in ``text`` from ``start`` on.

    String-aware, so a brace inside a quote does not count. Used to salvage
    whole requirements from a reply that was cut off mid-array.
    """
    objects: list[str] = []
    depth = 0
    begin = -1
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                begin = index
            depth += 1
        elif char == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and begin >= 0:
                    objects.append(text[begin : index + 1])
        elif char == "]" and depth == 0:
            break
    return objects


def parse_reply(text: str | None) -> tuple[dict[str, Any], list[Any], list[str]]:
    """``(standard, raw_requirements, notes)`` from a model reply.

    Never raises. A reply that is not JSON at all returns no requirements and
    a note carrying the first characters of what came back.
    """
    notes: list[str] = []
    if not text or not text.strip():
        return {}, [], ["the reply was empty"]
    body = _strip_fences(text)
    parsed: Any = None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        first, last = body.find("{"), body.rfind("}")
        if first >= 0 and last > first:
            try:
                parsed = json.loads(body[first : last + 1])
            except json.JSONDecodeError:
                parsed = None
    if parsed is None:
        key = body.find('"requirements"')
        bracket = body.find("[", key) if key >= 0 else body.find("[")
        salvaged: list[Any] = []
        if bracket >= 0:
            for chunk in _balanced_objects(body, bracket + 1):
                try:
                    salvaged.append(json.loads(chunk))
                except json.JSONDecodeError:
                    continue
        if salvaged:
            notes.append(
                f"the reply was not complete JSON; salvaged {len(salvaged)} "
                "whole requirement(s) from it"
            )
            return {}, salvaged, notes
        return {}, [], [f"the reply was not JSON; it began: {body[:160]!r}"]

    if isinstance(parsed, list):
        return {}, parsed, notes
    if not isinstance(parsed, dict):
        return (
            {},
            [],
            [f"the reply was JSON of type {type(parsed).__name__}, not an object"],
        )
    standard = parsed.get("standard")
    if not isinstance(standard, dict):
        standard = {}
    requirements = parsed.get("requirements")
    if not isinstance(requirements, list):
        notes.append("the reply had no 'requirements' list")
        requirements = []
    return standard, requirements, notes


def _squash(text: str) -> str:
    text = text.replace("­", "").replace("-\n", "")
    for odd, plain in (
        ("‘", "'"),
        ("’", "'"),
        ("“", '"'),
        ("”", '"'),
        ("–", "-"),
        ("—", "-"),
        (" ", " "),
    ):
        text = text.replace(odd, plain)
    return re.sub(r"\s+", " ", text).strip().lower()


def check_quotes(
    requirements: list[dict[str, Any]], pages: list[str]
) -> dict[str, int]:
    """Mark each requirement's quote as found or not in the document text.

    Comparison ignores case, whitespace, line-break hyphenation and typographic
    quotes, which is what PDF extraction disturbs. When a quote is located the
    page is taken from where it was found, since that the record can state for
    itself. Nothing is dropped: a quote that is not found is flagged for a
    person to look at.
    """
    counts = {"found": 0, "quote_not_found": 0, "not_checked": 0}
    squashed = [_squash(page) for page in pages]
    whole = " ".join(squashed)
    has_text = bool(whole.strip())
    for requirement in requirements:
        quote = _squash(requirement.get("quote") or "")
        if not has_text or not quote:
            requirement["quote_status"] = "not_checked"
        elif quote in whole:
            requirement["quote_status"] = "found"
            if len(pages) > 1:
                for number, page in enumerate(squashed, start=1):
                    if quote in page:
                        requirement["page"] = number
                        break
        else:
            requirement["quote_status"] = "quote_not_found"
        counts[requirement["quote_status"]] += 1
    return counts
