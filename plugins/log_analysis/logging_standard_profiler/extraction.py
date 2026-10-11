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
            "kind": "presence",
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
            "kind": "presence",
            "summary": "Authentication events identify the user and whether the attempt succeeded.",
            "quote": "Authentication events shall record the user identity and the outcome of the attempt.",
            "elements": [{"element": "actor_identity"}, {"element": "outcome"}],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "4.2.4",
            "section": "4.2 Record content",
            "page": 7,
            "obligation": "must",
            "assessable_from": "record_content",
            "kind": "presence",
            "summary": "Every record says when and where the event happened.",
            "quote": "Each log entry shall carry its time and the originating host, service or component.",
            "elements": [
                {"element": "timestamp"},
                {
                    "any_of": [{"element": "host"}, {"element": "source_component"}],
                    "label": "origin",
                },
            ],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "4.3.1",
            "section": "4.3 Sensitive content",
            "page": 8,
            "obligation": "must",
            "assessable_from": "record_content",
            "kind": "prohibition",
            "summary": "Free-text messages never carry passwords or tokens.",
            "quote": "Message text shall not contain passwords or session tokens.",
            "elements": [{"element": "message"}],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "4.4.2",
            "section": "4.4 Event selection",
            "page": 9,
            "obligation": "must",
            "assessable_from": "record_set",
            "kind": "event_selection",
            "summary": "Changes to user privileges are logged.",
            "quote": "Changes to user privileges shall be logged.",
            "elements": [{"element": "event_type"}, {"element": "actor_identity"}],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "6.1",
            "section": "6 Retention",
            "page": 12,
            "obligation": "must",
            "assessable_from": "not_assessable_from_sample",
            "kind": None,
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
    return f"""Extract every logging requirement this standard makes.

A standard also holds scope, definitions, roles and rationale; those are not
requirements. A requirement is any sentence that obliges or recommends
something about event records or logs: what is recorded, what a record
contains, how values are formatted, and equally how logs are collected,
transported, protected, retained, reviewed and disposed of.

Be exhaustive. Go through the document section by section and return every
such sentence, one requirement per sentence, including the many that a log
file cannot show; those are kept and labelled, not skipped. A standard of a
dozen pages usually makes dozens of requirements, often more than a hundred.
Every sentence containing shall, must, should or required will be counted in
the document afterwards and compared with what you return. Do not merge
sentences and do not invent requirements the document does not make.

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
- kind: what sort of rule it is. Only the first is answered by counting
  records, so choose with care. null for "not_assessable_from_sample".
    "presence" - a record must or should carry something, possibly in a
      stated format ("every record shall include the date and time",
      "timestamps should conform to ISO 8601", "shall identify the user").
      A sentence that requires an element and also qualifies it ("with
      enough specificity for investigation") is still presence.
    "prohibition" - something must not appear or must not be done ("shall
      not expose credentials", "shall not be the sole representation").
    "quality" - values must be correct, valid, stable, consistent or
      unambiguous in a way no single value shows ("field meanings shall be
      consistent", "values shall be reasonable for their role").
    "event_selection" - a kind of event or activity must be logged at all
      ("export activity shall be logged", "the system shall produce audit
      records for selected events").
    "permission" - something is allowed, with nothing to fall short of
      ("date and time may be split across fields").
- elements: for the first two values of assessable_from, which record
  elements the requirement is about, chosen ONLY from this catalogue:
{elements}
  Each entry is {{"element": name}} with optional "constraints":
{constraints}
  When the standard lists interchangeable ways to satisfy one thing ("a host,
  service, component or other stable identifier"; "a user, service account or
  process"), put the catalogue elements that fit in one group:
  {{"any_of": [{{"element": "host"}}, {{"element": "source_component"}}], "label": "origin"}}
  A record needs only one member of a group. List elements side by side only
  when the standard requires every one of them in the same record.
  Use an empty list for "not_assessable_from_sample".
  A requirement worded as conditional ("where applicable", "when an outcome
  exists") still names its elements.
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


NORMATIVE = re.compile(r"\b(shall|must|should|required)\b", re.IGNORECASE)
HEADING = re.compile(r"^(\d{1,2}(?:\.\d{1,2}){0,3})\.?\s+([A-Z][^\n]{2,90})$")
# Sentences sent for classification in one sweep call, and characters of each.
SWEEP_SENTENCES = 250
SWEEP_SENTENCE_CHARS = 500
NOT_REQUIREMENT_KEPT = 200

SWEEP_EXAMPLE = {
    "sentences": [
        {
            "n": 1,
            "requirement": True,
            "obligation": "must",
            "assessable_from": "not_assessable_from_sample",
            "summary": "Logs are kept for at least twelve months.",
            "elements": [],
            "unmapped_reason": None,
        },
        {
            "n": 2,
            "requirement": True,
            "obligation": "should",
            "assessable_from": "record_content",
            "kind": "presence",
            "summary": "Records name the host that produced them.",
            "elements": [{"element": "host"}],
            "unmapped_reason": None,
        },
        {"n": 3, "requirement": False, "why": "defines the word 'shall'"},
    ]
}


def _tidy(text: str) -> str:
    text = text.replace(chr(173), "").replace("-" + chr(10), "")
    return re.sub(r"\s+", " ", text).strip()


def _running_lines(pages: list[str]) -> set[str]:
    """Lines repeated on most pages: running headers and footers."""
    if len(pages) < 4:
        return set()
    seen: dict[str, int] = {}
    for page in pages:
        for line in {ln.strip() for ln in page.splitlines() if ln.strip()}:
            seen[line] = seen.get(line, 0) + 1
    return {line for line, count in seen.items() if count * 2 > len(pages)}


def obligation_sentences(pages: list[str]) -> list[dict[str, Any]]:
    """Every sentence in the document worded shall, must, should or required.

    Each carries its page and the numbered heading it sits under, when the
    document numbers its headings. This is a wording match, not a judgment:
    it over-collects (a sentence defining "shall" matches) and the caller
    decides what each one is.
    """
    running = _running_lines(pages)
    many = len(pages) > 1
    found: list[dict[str, Any]] = []
    number_of, heading = "", ""

    def flush(lines: list[str], page: int) -> None:
        for sentence in re.split(r"(?<=[.;!?])\s+", _tidy("\n".join(lines))):
            if len(sentence) >= 20 and NORMATIVE.search(sentence):
                found.append(
                    {
                        "n": len(found) + 1,
                        "page": page if many else None,
                        "section_number": number_of,
                        "section": heading,
                        "text": sentence,
                    }
                )

    for page_number, page in enumerate(pages, start=1):
        block: list[str] = []
        for line in page.splitlines():
            stripped = line.strip()
            if not stripped or stripped in running:
                continue
            match = HEADING.match(stripped)
            if match and stripped[-1] not in ".;:,":
                flush(block, page_number)
                block = []
                number_of = match.group(1)
                heading = f"{match.group(1)} {match.group(2).strip()}"
                continue
            block.append(line)
        flush(block, page_number)
    return found


def not_quoted(
    sentences: list[dict[str, Any]], requirements: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The sentences no requirement's quote contains or is contained in."""
    quotes = [q for q in (_squash(r.get("quote") or "") for r in requirements) if q]
    out = []
    for sentence in sentences:
        squashed = _squash(sentence["text"])
        if not any(q in squashed or squashed in q for q in quotes):
            out.append(sentence)
    return out


def build_sweep_prompt(
    catalogue: dict[str, Any], sentences: list[dict[str, Any]]
) -> str:
    elements = "\n".join(
        f"- {name} ({spec['value_type']}): {spec['description']}"
        for name, spec in catalogue["elements"].items()
    )
    constraints = "\n".join(
        f"- {name}: {text}" for name, text in catalogue.get("constraints", {}).items()
    )
    listing = "\n".join(
        f"{s['n']}. [{s['section'] or 'no heading'}] {s['text'][:SWEEP_SENTENCE_CHARS]}"
        for s in sentences
    )
    return f"""These numbered sentences come from a logging standard. Each contains
shall, must, should or required. Classify every one of them.

A sentence is a requirement when it obliges or recommends something about
event records or logs: what is recorded, what a record contains, how values
are formatted, or how logs are collected, transported, protected, retained,
reviewed or disposed of. It is not a requirement when it defines a term,
states scope, disclaims, describes the document itself, or is a fragment of a
table or heading.

For each sentence return an object with:
- n: its number.
- requirement: true or false. When false add "why" in a few words and nothing
  else.
- obligation: "must" (shall, must, required), "should" or "may".
- assessable_from:
    "record_content" - can be checked by looking inside individual log
      records (a field is present, a value has a format).
    "record_set" - needs many records together (ordering, gaps, consistency).
    "not_assessable_from_sample" - cannot be seen in a log file at all:
      retention, access control, protection, review, roles, storage,
      configuration, documentation.
- summary: one plain sentence of at most 20 words.
- kind: what sort of rule it is. Only the first is answered by counting
  records, so choose with care. null for "not_assessable_from_sample".
    "presence" - a record must or should carry something, possibly in a
      stated format ("every record shall include the date and time",
      "timestamps should conform to ISO 8601", "shall identify the user").
      A sentence that requires an element and also qualifies it ("with
      enough specificity for investigation") is still presence.
    "prohibition" - something must not appear or must not be done ("shall
      not expose credentials", "shall not be the sole representation").
    "quality" - values must be correct, valid, stable, consistent or
      unambiguous in a way no single value shows ("field meanings shall be
      consistent", "values shall be reasonable for their role").
    "event_selection" - a kind of event or activity must be logged at all
      ("export activity shall be logged", "the system shall produce audit
      records for selected events").
    "permission" - something is allowed, with nothing to fall short of
      ("date and time may be split across fields").
- elements: for the first two values of assessable_from, which record
  elements it is about, chosen ONLY from this catalogue:
{elements}
  Each entry is {{"element": name}} with optional "constraints":
{constraints}
  When the standard lists interchangeable ways to satisfy one thing ("a host,
  service, component or other stable identifier"; "a user, service account or
  process"), put the catalogue elements that fit in one group:
  {{"any_of": [{{"element": "host"}}, {{"element": "source_component"}}], "label": "origin"}}
  A record needs only one member of a group. List elements side by side only
  when the standard requires every one of them in the same record.
  Empty for "not_assessable_from_sample".
- unmapped_reason: if it is about record content but no catalogue element
  expresses it, leave elements empty and say here what it needs. Otherwise
  null.

Return one object for each of the {len(sentences)} sentences, keeping its number. Reply
with one JSON object and nothing else, shaped like this example (its content is invented):

{json.dumps(SWEEP_EXAMPLE, indent=2)}

SENTENCES:
{listing}
"""


def parse_sweep(text: str | None) -> tuple[dict[int, dict[str, Any]], list[str]]:
    """``({n: item}, notes)`` from a sweep reply. Never raises."""
    _, items, notes = parse_reply(
        (text or "").replace('"sentences"', '"requirements"', 1)
    )
    out: dict[int, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            number = int(item.get("n"))
        except (TypeError, ValueError):
            continue
        out.setdefault(number, item)
    return out, notes


def sweep_requirements(
    sentences: list[dict[str, Any]], verdicts: dict[int, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """``(raw_requirements, not_requirements, unclassified)`` from sweep verdicts.

    A requirement's quote is the sentence as extracted here, never text the
    model returned, so it is in the document by construction.
    """
    raw: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    for sentence in sentences:
        verdict = verdicts.get(sentence["n"])
        where = {"page": sentence["page"], "text": sentence["text"][:400]}
        if verdict is None:
            unclassified.append(where)
            continue
        if verdict.get("requirement") in (False, "false", "no", 0):
            rejected.append({**where, "why": str(verdict.get("why") or "")[:160]})
            continue
        raw.append(
            {
                "requirement_id": sentence["section_number"] or "",
                "section": sentence["section"],
                "page": sentence["page"],
                "obligation": verdict.get("obligation"),
                "assessable_from": verdict.get("assessable_from"),
                "kind": verdict.get("kind"),
                "summary": verdict.get("summary"),
                "quote": sentence["text"],
                "elements": verdict.get("elements"),
                "unmapped_reason": verdict.get("unmapped_reason"),
            }
        )
    return raw, rejected, unclassified


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


def in_document_order(
    requirements: list[dict[str, Any]], pages: list[str]
) -> list[dict[str, Any]]:
    """Requirements sorted by where their quote sits in the document.

    A requirement whose quote was not located keeps its place after the last
    located one before it.
    """
    whole = " ".join(_squash(page) for page in pages)
    keyed = []
    last = -1.0
    for index, requirement in enumerate(requirements):
        quote = _squash(requirement.get("quote") or "")
        at = whole.find(quote) if quote and whole.strip() else -1
        if at >= 0:
            last = float(at)
            keyed.append((float(at), index, requirement))
        else:
            keyed.append((last + 0.5, index, requirement))
    return [requirement for _, _, requirement in sorted(keyed, key=lambda k: k[:2])]
