"""Fetch one document from a URL for ingestion.

Threat reports name attacker infrastructure on purpose, and the service runs
with cloud credentials one hop away from the metadata server, so the fetch is
deliberately narrow:

* ``http`` and ``https`` on their default ports only, no credentials in the URL.
* Every address the host resolves to must be public. Loopback, private,
  link-local (where the metadata server lives), shared/CGNAT, multicast and
  reserved ranges are refused, including IPv4 hidden inside IPv6.
* The connection goes to the address that was checked, not to whatever a
  second DNS lookup returns, so a rebinding answer cannot redirect it. TLS is
  still verified against the hostname.
* Each redirect is a new URL and is checked the same way, up to a limit.
* Size and wall-clock time are capped while streaming, after decompression.
* Exactly one document is fetched. Nothing on the page is followed.

Proxy environment variables are ignored: a proxy would make the address that
was checked irrelevant to where the request actually goes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 5
MAX_BYTES_TEXT = 10 * 1024 * 1024
# The largest PDF any configured provider accepts (Gemini, OpenAI: 50 MB).
MAX_BYTES_PDF = 50 * 1024 * 1024
CONNECT_TIMEOUT_S = 10.0
READ_TIMEOUT_S = 30.0
TOTAL_DEADLINE_S = 90.0

_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

USER_AGENT = (
    "EventMill-ThreatIntelIngester/1.0 "
    "(+https://github.com/eventmilldevops/eventmill_v01)"
)
_ACCEPT = (
    "text/html,application/xhtml+xml,application/pdf;q=0.9,"
    "text/plain;q=0.8,text/markdown;q=0.8"
)

_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_TEXT_TYPES = {"text/plain", "text/markdown", "text/x-markdown"}
_PDF_TYPES = {"application/pdf", "application/x-pdf"}


class UrlFetchError(Exception):
    """A fetch that did not produce a document.

    ``reason`` is one of ``invalid``, ``blocked``, ``failed``, ``too_large``
    or ``unsupported``; the message names the actual cause.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class FetchedDocument:
    """One fetched document and what is known about where it came from."""

    requested_url: str
    final_url: str
    kind: str  # "html" | "pdf" | "text"
    content_type: str
    charset: str | None
    body: bytes
    sha256: str
    fetched_at: str
    peer_address: str
    redirects: list[str] = field(default_factory=list)


Resolver = Callable[..., list[tuple[Any, ...]]]


def _blocked_reason(addr: str) -> str | None:
    """Why ``addr`` must not be contacted, or None if it is public."""
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return "not an IP address"
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is None and ip.teredo:
            embedded = ip.teredo[1]
        if embedded is not None:
            inner = _blocked_reason(str(embedded))
            if inner:
                return f"embeds {embedded}, which is {inner}"
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address (the cloud metadata range)"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_unspecified:
        return "the unspecified address"
    if not ip.is_global:
        return "a private or reserved address"
    return None


def _check_url(url: str) -> tuple[str, str, int]:
    """Validate a URL's shape and return (scheme, ASCII hostname, port)."""
    if not isinstance(url, str) or not url.strip():
        raise UrlFetchError("invalid", "URL is empty")
    if len(url) > MAX_URL_LENGTH:
        raise UrlFetchError(
            "invalid", f"URL is longer than {MAX_URL_LENGTH} characters"
        )
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise UrlFetchError("invalid", "URL contains whitespace or control characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UrlFetchError("invalid", f"URL could not be parsed: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise UrlFetchError(
            "invalid", f"only http and https URLs can be fetched, not {scheme or 'none'!r}"
        )
    if parts.username is not None or parts.password is not None:
        raise UrlFetchError("invalid", "URLs carrying credentials are refused")
    host = parts.hostname
    if not host:
        raise UrlFetchError("invalid", "URL has no host")
    default_port = _DEFAULT_PORTS[scheme]
    if port is not None and port != default_port:
        raise UrlFetchError(
            "blocked",
            f"port {port} is refused; only the default {scheme} port "
            f"({default_port}) is fetched",
        )
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UrlFetchError("invalid", f"host {host!r} is not a valid name") from exc
    return scheme, ascii_host.rstrip("."), default_port


def _resolve_public(host: str, port: int, resolver: Resolver) -> str:
    """The address to connect to, after checking every address of ``host``."""
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise UrlFetchError("failed", f"could not resolve {host}: {exc}") from exc
    addrs: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in addrs:
            addrs.append(addr)
    if not addrs:
        raise UrlFetchError("failed", f"{host} resolved to no addresses")
    # Every answer is checked, not only the one used: a name that resolves to
    # anything internal is refused outright.
    for addr in addrs:
        why = _blocked_reason(addr)
        if why:
            raise UrlFetchError(
                "blocked", f"{host} resolves to {addr}, which is {why}"
            )
    ipv4 = [a for a in addrs if ":" not in a]
    return (ipv4 or addrs)[0]


def _media_type(content_type: str) -> tuple[str, str | None]:
    """Split a Content-Type header into (media type, charset)."""
    media, _, params = (content_type or "").partition(";")
    charset = None
    for param in params.split(";"):
        key, _, value = param.strip().partition("=")
        if key.lower() == "charset" and value:
            charset = value.strip().strip('"') or None
    return media.strip().lower(), charset


def _classify(media: str, body: bytes) -> str | None:
    """Decide what a response body is from its bytes, then its header."""
    head = body[:1024].lstrip()
    if head.startswith(b"%PDF-"):
        return "pdf"
    if media in _PDF_TYPES:
        # Declared as a PDF but not one: refuse rather than mislabel it.
        return None
    if media in _HTML_TYPES:
        return "html"
    if media in _TEXT_TYPES:
        return "text"
    if media in ("", "application/octet-stream"):
        lowered = head.lower()
        if lowered.startswith(b"<!doctype html") or b"<html" in lowered:
            return "html"
    return None


def _byte_limit(media: str) -> int:
    if media in _PDF_TYPES or media in ("", "application/octet-stream"):
        return MAX_BYTES_PDF
    return MAX_BYTES_TEXT


def fetch_url(
    url: str,
    *,
    resolver: Resolver = socket.getaddrinfo,
    transport: Any = None,
    max_redirects: int = MAX_REDIRECTS,
    deadline_s: float = TOTAL_DEADLINE_S,
) -> FetchedDocument:
    """Fetch one HTML, plain-text or PDF document from ``url``.

    ``resolver`` and ``transport`` exist for tests: the first replaces
    ``socket.getaddrinfo``, the second is an ``httpx`` transport.

    Raises UrlFetchError, never a transport exception.
    """
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - httpx ships with the LLM SDKs
        raise UrlFetchError("failed", "httpx is required to fetch URLs") from exc

    started = time.monotonic()
    current = url.strip() if isinstance(url, str) else url
    redirects: list[str] = []
    timeout = httpx.Timeout(
        connect=CONNECT_TIMEOUT_S, read=READ_TIMEOUT_S,
        write=READ_TIMEOUT_S, pool=CONNECT_TIMEOUT_S,
    )
    client_kwargs: dict[str, Any] = {
        "timeout": timeout,
        "follow_redirects": False,
        "trust_env": False,
    }
    if transport is not None:
        client_kwargs["transport"] = transport

    with httpx.Client(**client_kwargs) as client:
        for _hop in range(max_redirects + 1):
            scheme, host, port = _check_url(current)
            addr = _resolve_public(host, port, resolver)
            parts = urlsplit(current)
            netloc = f"[{addr}]" if ":" in addr else addr
            pinned = urlunsplit(
                (scheme, f"{netloc}:{port}", parts.path or "/", parts.query, "")
            )
            extensions = {"sni_hostname": host} if scheme == "https" else {}
            headers = {
                "Host": host,
                "User-Agent": USER_AGENT,
                "Accept": _ACCEPT,
            }
            try:
                with client.stream(
                    "GET", pinned, headers=headers, extensions=extensions
                ) as response:
                    status = response.status_code
                    if status in _REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location:
                            raise UrlFetchError(
                                "failed",
                                f"{current} answered HTTP {status} with no Location",
                            )
                        redirects.append(current)
                        current = urljoin(current, location)
                        continue
                    if not (200 <= status < 300) or status == 204:
                        raise UrlFetchError(
                            "failed",
                            f"{current} answered HTTP {status} "
                            f"{response.reason_phrase}".rstrip(),
                        )
                    content_type = response.headers.get("content-type", "")
                    media, charset = _media_type(content_type)
                    limit = _byte_limit(media)
                    declared = response.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > limit:
                        raise UrlFetchError(
                            "too_large",
                            f"{current} declares {int(declared):,} bytes; the limit "
                            f"for {media or 'this content'} is {limit:,}",
                        )
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > limit:
                            raise UrlFetchError(
                                "too_large",
                                f"{current} is larger than the {limit:,}-byte limit "
                                f"for {media or 'this content'}",
                            )
                        if time.monotonic() - started > deadline_s:
                            raise UrlFetchError(
                                "failed",
                                f"{current} took longer than {deadline_s:.0f}s",
                            )
            except UrlFetchError:
                raise
            except httpx.HTTPError as exc:
                raise UrlFetchError(
                    "failed", f"fetching {current} failed: {type(exc).__name__}: {exc}"
                ) from exc

            data = bytes(body)
            kind = _classify(media, data)
            if kind is None:
                raise UrlFetchError(
                    "unsupported",
                    f"{current} returned {media or 'no content type'}; only HTML, "
                    f"plain text, Markdown and PDF can be ingested",
                )
            return FetchedDocument(
                requested_url=url,
                final_url=current,
                kind=kind,
                content_type=content_type,
                charset=charset,
                body=data,
                sha256=hashlib.sha256(data).hexdigest(),
                fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                peer_address=addr,
                redirects=redirects,
            )

    raise UrlFetchError(
        "failed", f"more than {max_redirects} redirects starting from {url}"
    )
