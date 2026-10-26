"""Tests for framework.documents.url_fetch: what may be fetched, and how."""

from __future__ import annotations

import socket

import httpx
import pytest

from framework.documents import url_fetch
from framework.documents.url_fetch import UrlFetchError, _blocked_reason, fetch_url

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def _resolver(table: dict[str, list[str]]):
    """A getaddrinfo stand-in answering from ``table``."""
    calls: list[str] = []

    def resolve(host, port, type=None, **_kw):
        calls.append(host)
        if host not in table:
            raise socket.gaierror(f"no such host {host}")
        out = []
        for addr in table[host]:
            family = socket.AF_INET6 if ":" in addr else socket.AF_INET
            sockaddr = (addr, port, 0, 0) if family == socket.AF_INET6 else (addr, port)
            out.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return out

    resolve.calls = calls
    return resolve


def _transport(handler):
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    t = httpx.MockTransport(wrapped)
    t.seen = seen
    return t


def _html(body: str = "<html><body><p>report</p></body></html>", status: int = 200,
          headers: dict | None = None):
    def handler(request):
        h = {"content-type": "text/html; charset=utf-8"}
        h.update(headers or {})
        return httpx.Response(status, headers=h, content=body.encode("utf-8"))
    return handler


class TestAddressPolicy:
    @pytest.mark.parametrize("addr", [
        "127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "100.64.0.1",
        "169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255",
        "::1", "fe80::1", "fc00::1", "::ffff:169.254.169.254", "::ffff:10.0.0.1",
        "2002:a9fe:a9fe::1",
    ])
    def test_internal_addresses_are_refused(self, addr):
        assert _blocked_reason(addr) is not None

    @pytest.mark.parametrize("addr", [PUBLIC_V4, "8.8.8.8", PUBLIC_V6])
    def test_public_addresses_are_allowed(self, addr):
        assert _blocked_reason(addr) is None

    def test_metadata_server_is_named_as_such(self):
        assert "metadata" in _blocked_reason("169.254.169.254")


class TestUrlShape:
    @pytest.mark.parametrize("url, reason", [
        ("", "invalid"),
        ("ftp://example.com/r.pdf", "invalid"),
        ("file:///etc/passwd", "invalid"),
        ("https://user:pw@example.com/", "invalid"),
        ("https://example.com/a b", "invalid"),
        ("https://example.com:8443/", "blocked"),
        ("http://example.com:22/", "blocked"),
        ("https:///nohost", "invalid"),
    ])
    def test_refused_before_any_lookup(self, url, reason):
        resolver = _resolver({"example.com": [PUBLIC_V4]})
        with pytest.raises(UrlFetchError) as exc:
            fetch_url(url, resolver=resolver, transport=_transport(_html()))
        assert exc.value.reason == reason
        assert resolver.calls == []

    def test_explicit_default_port_is_fine(self):
        doc = fetch_url(
            "https://example.com:443/r",
            resolver=_resolver({"example.com": [PUBLIC_V4]}),
            transport=_transport(_html()),
        )
        assert doc.kind == "html"


class TestResolution:
    def test_a_private_answer_is_refused(self):
        with pytest.raises(UrlFetchError) as exc:
            fetch_url(
                "https://intranet.example.com/",
                resolver=_resolver({"intranet.example.com": ["10.0.0.7"]}),
                transport=_transport(_html()),
            )
        assert exc.value.reason == "blocked"
        assert "10.0.0.7" in str(exc.value)

    def test_every_answer_is_checked_not_just_the_first(self):
        transport = _transport(_html())
        with pytest.raises(UrlFetchError) as exc:
            fetch_url(
                "https://mixed.example.com/",
                resolver=_resolver({"mixed.example.com": [PUBLIC_V4, "127.0.0.1"]}),
                transport=transport,
            )
        assert exc.value.reason == "blocked"
        assert transport.seen == []

    def test_unresolvable_host_fails_with_the_cause(self):
        with pytest.raises(UrlFetchError) as exc:
            fetch_url("https://nope.invalid/", resolver=_resolver({}),
                      transport=_transport(_html()))
        assert exc.value.reason == "failed"
        assert "nope.invalid" in str(exc.value)


class TestPinnedConnection:
    def test_request_goes_to_the_checked_address_with_the_real_host(self):
        transport = _transport(_html())
        doc = fetch_url(
            "https://example.com/blog/post?x=1#frag",
            resolver=_resolver({"example.com": [PUBLIC_V4]}),
            transport=transport,
        )
        req = transport.seen[0]
        assert req.url.host == PUBLIC_V4
        assert req.url.path == "/blog/post" and req.url.query == b"x=1"
        assert req.headers["host"] == "example.com"
        assert req.extensions.get("sni_hostname") == "example.com"
        assert doc.peer_address == PUBLIC_V4
        assert doc.final_url == "https://example.com/blog/post?x=1#frag"

    def test_ipv4_is_preferred_when_both_families_answer(self):
        transport = _transport(_html())
        fetch_url(
            "https://dual.example.com/",
            resolver=_resolver({"dual.example.com": [PUBLIC_V6, PUBLIC_V4]}),
            transport=transport,
        )
        assert transport.seen[0].url.host == PUBLIC_V4

    def test_plain_http_sends_no_sni(self):
        transport = _transport(_html())
        fetch_url("http://example.com/", resolver=_resolver({"example.com": [PUBLIC_V4]}),
                  transport=transport)
        assert "sni_hostname" not in transport.seen[0].extensions


class TestRedirects:
    def test_each_hop_is_checked(self):
        def handler(request):
            if request.headers["host"] == "public.example.com":
                return httpx.Response(302, headers={"location": "http://internal.example.com/x"})
            return _html()(request)

        resolver = _resolver({
            "public.example.com": [PUBLIC_V4],
            "internal.example.com": ["192.168.0.10"],
        })
        transport = _transport(handler)
        with pytest.raises(UrlFetchError) as exc:
            fetch_url("https://public.example.com/", resolver=resolver, transport=transport)
        assert exc.value.reason == "blocked"
        assert len(transport.seen) == 1

    def test_chain_is_recorded(self):
        def handler(request):
            if request.url.path == "/old":
                return httpx.Response(301, headers={"location": "/new"})
            return _html()(request)

        doc = fetch_url(
            "https://example.com/old",
            resolver=_resolver({"example.com": [PUBLIC_V4]}),
            transport=_transport(handler),
        )
        assert doc.redirects == ["https://example.com/old"]
        assert doc.final_url == "https://example.com/new"

    def test_too_many_redirects(self):
        def handler(request):
            return httpx.Response(302, headers={"location": "/again"})

        with pytest.raises(UrlFetchError) as exc:
            fetch_url("https://example.com/", resolver=_resolver({"example.com": [PUBLIC_V4]}),
                      transport=_transport(handler), max_redirects=3)
        assert exc.value.reason == "failed"
        assert "redirects" in str(exc.value)


class TestBody:
    def _fetch(self, handler):
        return fetch_url("https://example.com/r",
                         resolver=_resolver({"example.com": [PUBLIC_V4]}),
                         transport=_transport(handler))

    def test_html_with_charset(self):
        doc = self._fetch(_html(headers={"content-type": "text/html; charset=ISO-8859-1"}))
        assert doc.kind == "html" and doc.charset == "ISO-8859-1"
        assert len(doc.sha256) == 64

    def test_pdf_recognised_by_its_bytes(self):
        def handler(request):
            return httpx.Response(200, headers={"content-type": "application/octet-stream"},
                                  content=b"%PDF-1.7\n...")
        assert self._fetch(handler).kind == "pdf"

    def test_declared_pdf_that_is_not_one_is_refused(self):
        def handler(request):
            return httpx.Response(200, headers={"content-type": "application/pdf"},
                                  content=b"<html>login</html>")
        with pytest.raises(UrlFetchError) as exc:
            self._fetch(handler)
        assert exc.value.reason == "unsupported"

    def test_plain_text(self):
        def handler(request):
            return httpx.Response(200, headers={"content-type": "text/plain"},
                                  content=b"1.2.3[.]4")
        assert self._fetch(handler).kind == "text"

    def test_images_are_refused(self):
        def handler(request):
            return httpx.Response(200, headers={"content-type": "image/png"},
                                  content=b"\x89PNG....")
        with pytest.raises(UrlFetchError) as exc:
            self._fetch(handler)
        assert exc.value.reason == "unsupported"

    def test_http_error_names_the_status(self):
        with pytest.raises(UrlFetchError) as exc:
            self._fetch(_html(status=404))
        assert exc.value.reason == "failed" and "404" in str(exc.value)

    def test_declared_size_over_the_limit(self, monkeypatch):
        monkeypatch.setattr(url_fetch, "MAX_BYTES_TEXT", 100)
        with pytest.raises(UrlFetchError) as exc:
            self._fetch(_html(body="x" * 50, headers={"content-length": "5000"}))
        assert exc.value.reason == "too_large"

    def test_streamed_size_over_the_limit(self, monkeypatch):
        # No Content-Length: the cap has to hold while the body streams in.
        monkeypatch.setattr(url_fetch, "MAX_BYTES_TEXT", 100)

        def handler(request):
            chunks = iter([b"<html>", b"x" * 80, b"x" * 80, b"</html>"])
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  content=chunks)
        with pytest.raises(UrlFetchError) as exc:
            self._fetch(handler)
        assert exc.value.reason == "too_large"

    def test_transport_errors_are_reported_not_raised_raw(self):
        def handler(request):
            raise httpx.ConnectError("connection refused", request=request)
        with pytest.raises(UrlFetchError) as exc:
            self._fetch(handler)
        assert exc.value.reason == "failed"
        assert "ConnectError" in str(exc.value)
