"""
Native documents for providers that cannot read a GCS URI.

Plan: ``docs/specs/openai_document_path_plan.md``. OpenAI and Anthropic get the
PDF as inline base64, never as a Files API upload: an upload is retained
provider-side until deleted, and OpenAI's client sends ``store=False`` as a
declared no-retention property. The dispatcher reads the bytes before the
client is called, unless the routed tier declares ``remote_uri_gs`` (Gemini).
"""

import base64
from types import SimpleNamespace

import pytest

from framework.llm.backends.base import DocumentPart, DocumentUnavailable
from framework.llm.clients.anthropic import AnthropicClient
from framework.llm.clients.openai import OpenAIClient
from framework.llm.dispatcher import LLMDispatcher
from framework.llm.factory import PROVIDER_CLIENTS, client_class
from framework.llm.providers import TierSpec, load_tier_specs
from framework.plugins.protocol import ArtifactRef, QueryHints

from tests.framework.test_provider_seam import PublicOnlyClient

PDF_BYTES = b"%PDF-1.4 fake body"


@pytest.fixture
def pdf_file(tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(PDF_BYTES)
    return f


# ---------------------------------------------------------------------------
# DocumentPart.read_bytes
# ---------------------------------------------------------------------------


class TestReadBytes:
    def test_inline_bytes_win(self, pdf_file):
        part = DocumentPart("application/pdf", file_path=str(pdf_file),
                            inline_bytes=b"inline")
        assert part.read_bytes() == b"inline"

    def test_a_local_file_is_read(self, pdf_file):
        assert DocumentPart("application/pdf", file_path=str(pdf_file)).read_bytes() \
            == PDF_BYTES

    def test_an_empty_file_is_refused_not_sent(self, tmp_path):
        empty = tmp_path / "empty.pdf"
        empty.write_bytes(b"")
        with pytest.raises(DocumentUnavailable, match="empty"):
            DocumentPart("application/pdf", file_path=str(empty)).read_bytes()

    def test_nothing_readable_names_what_was_tried(self, tmp_path):
        missing = str(tmp_path / "gone.pdf")
        with pytest.raises(DocumentUnavailable, match="gone.pdf"):
            DocumentPart("application/pdf", file_path=missing).read_bytes()

    def test_a_client_never_fetches_from_storage(self, monkeypatch):
        # allow_remote=False is what clients pass: fetching is the framework's.
        import framework.llm.backends.base as base

        monkeypatch.setattr(base, "_read_gcs", lambda uri: pytest.fail("fetched"))
        part = DocumentPart("application/pdf", storage_uri="gs://b/o.pdf")
        with pytest.raises(DocumentUnavailable):
            part.read_bytes(allow_remote=False)

    def test_the_framework_fetches_gs_uris(self, monkeypatch):
        import framework.llm.backends.base as base

        monkeypatch.setattr(base, "_read_gcs", lambda uri: b"from " + uri.encode())
        part = DocumentPart("application/pdf", storage_uri="gs://b/o.pdf")
        assert part.read_bytes() == b"from gs://b/o.pdf"


# ---------------------------------------------------------------------------
# Dispatcher materialisation
# ---------------------------------------------------------------------------


def _dispatcher(capabilities: tuple[str, ...]):
    client = PublicOnlyClient("m-light", "light", "vendor_x")
    spec = TierSpec("light", "m-light", "K", 65536, 1_000_000, "low",
                    capabilities, provider_id="vendor_x")
    return LLMDispatcher(clients={("vendor_x", "light"): client},
                         tier_specs={("vendor_x", "light"): spec}), client


def _artifact(path: str, storage_uri: str | None = None) -> ArtifactRef:
    return ArtifactRef("a1", "pdf_report", path, storage_uri=storage_uri,
                       metadata={"mime_type": "application/pdf"})


class TestDispatcherMaterialisesBytes:
    def test_a_tier_without_remote_uri_gs_is_handed_bytes(self, pdf_file):
        dispatcher, client = _dispatcher(("text", "native_pdf"))
        result = dispatcher.query_with_document(
            "p", _artifact(str(pdf_file)), hints=QueryHints(tier="light"),
        )
        assert result.ok
        assert client.calls[0]["doc"].inline_bytes == PDF_BYTES

    def test_a_gs_reading_tier_is_left_the_uri(self, pdf_file):
        dispatcher, client = _dispatcher(("text", "native_pdf", "remote_uri_gs"))
        dispatcher.query_with_document(
            "p", _artifact(str(pdf_file), "gs://b/report.pdf"),
            hints=QueryHints(tier="light"),
        )
        doc = client.calls[0]["doc"]
        assert doc.inline_bytes is None
        assert doc.storage_uri == "gs://b/report.pdf"

    def test_an_unreadable_document_is_refused_before_any_call(self, tmp_path):
        dispatcher, client = _dispatcher(("text", "native_pdf"))
        result = dispatcher.query_with_document(
            "p", _artifact(str(tmp_path / "gone.pdf")),
            hints=QueryHints(tier="light"),
        )
        assert not result.ok
        assert result.fallback_reason == "document bytes could not be read"
        assert not client.calls


# ---------------------------------------------------------------------------
# Provider clients
# ---------------------------------------------------------------------------


class _RecordingOpenAI:
    """The two SDK surfaces the client may touch. files is a tripwire."""

    def __init__(self, response):
        self.requests: list[dict] = []
        outer = self

        class _Responses:
            def create(self, **kw):
                outer.requests.append(kw)
                return response

        class _Files:
            def create(self, **kw):
                pytest.fail("a document was uploaded to the Files API")

        self.responses = _Responses()
        self.files = _Files()


def _openai_response(text="ok", reason=None, status="completed"):
    return SimpleNamespace(
        output_text=text, status=status, model="gpt-x",
        incomplete_details=SimpleNamespace(reason=reason) if reason else None,
        usage=SimpleNamespace(input_tokens=10, output_tokens=5, total_tokens=15,
                              output_tokens_details=None),
    )


def _openai(response=None, tier="light"):
    client = OpenAIClient(model_id="gpt-x", tier=tier)
    client._connected = True
    client._sdk_client = _RecordingOpenAI(response or _openai_response())
    return client


class TestOpenAIDocument:
    def test_the_pdf_goes_inline_with_the_prompt(self):
        client = _openai()
        result = client.query_with_document(
            "extract", DocumentPart("application/pdf", inline_bytes=PDF_BYTES),
            system_context="sys", max_tokens=1000,
        )
        assert result.ok
        assert result.transport_path == "inline_bytes"
        req = client._sdk_client.requests[0]
        assert req["store"] is False
        assert req["instructions"] == "sys"
        assert req["max_output_tokens"] == 1000
        file_part, text_part = req["input"][0]["content"]
        assert file_part["type"] == "input_file"
        assert file_part["file_data"] == (
            "data:application/pdf;base64," + base64.b64encode(PDF_BYTES).decode()
        )
        assert file_part["filename"]
        assert text_part == {"type": "input_text", "text": "extract"}

    @pytest.mark.parametrize("resolution, detail", [
        ("low", "low"), ("medium", "auto"), ("high", "high"), (None, None),
    ])
    def test_media_resolution_maps_onto_detail(self, resolution, detail):
        client = _openai()
        client.query_with_document(
            "p", DocumentPart("application/pdf", inline_bytes=PDF_BYTES),
            hints=QueryHints(media_resolution=resolution),
        )
        file_part = client._sdk_client.requests[0]["input"][0]["content"][0]
        assert file_part.get("detail") == detail

    def test_the_filename_is_the_files_own(self, pdf_file):
        client = _openai()
        client.query_with_document(
            "p", DocumentPart("application/pdf", file_path=str(pdf_file)),
        )
        file_part = client._sdk_client.requests[0]["input"][0]["content"][0]
        assert file_part["filename"] == "report.pdf"

    def test_a_truncated_reply_is_flagged_like_text(self):
        client = _openai(_openai_response(reason="max_output_tokens",
                                          status="incomplete"))
        result = client.query_with_document(
            "p", DocumentPart("application/pdf", inline_bytes=PDF_BYTES),
        )
        assert result.truncated

    def test_no_bytes_is_a_named_failure_and_no_call(self, tmp_path):
        client = _openai()
        result = client.query_with_document(
            "p", DocumentPart("application/pdf", file_path=str(tmp_path / "x.pdf")),
        )
        assert not result.ok
        assert not client._sdk_client.requests


class _RecordingAnthropic:
    def __init__(self, message):
        self.requests: list[dict] = []
        outer = self

        class _Messages:
            def create(self, **kw):
                outer.requests.append(kw)
                return message

            def stream(self, **kw):  # pragma: no cover - small budgets only
                pytest.fail("unexpected stream")

        class _Files:
            def upload(self, **kw):
                pytest.fail("a document was uploaded to the Files API")

        self.messages = _Messages()
        self.beta = SimpleNamespace(files=_Files())


def _anthropic_message(text="ok", stop="end_turn"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason=stop, model="claude-x",
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
    )


def _anthropic(message=None):
    client = AnthropicClient(model_id="claude-x", tier="light")
    client._connected = True
    client._sdk_client = _RecordingAnthropic(message or _anthropic_message())
    return client


class TestAnthropicDocument:
    def test_the_pdf_goes_inline_as_a_base64_document_block(self):
        client = _anthropic()
        result = client.query_with_document(
            "extract", DocumentPart("application/pdf", inline_bytes=PDF_BYTES),
            system_context="sys", max_tokens=1000,
        )
        assert result.ok, result.error
        assert result.transport_path == "inline_bytes"
        req = client._sdk_client.requests[0]
        assert req["system"] == "sys"
        doc_block, text_block = req["messages"][0]["content"]
        assert doc_block == {
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf",
                       "data": base64.b64encode(PDF_BYTES).decode()},
        }
        assert text_block == {"type": "text", "text": "extract"}

    def test_a_truncated_reply_is_flagged_like_text(self):
        client = _anthropic(_anthropic_message(stop="max_tokens"))
        result = client.query_with_document(
            "p", DocumentPart("application/pdf", inline_bytes=PDF_BYTES),
        )
        assert result.truncated

    def test_no_bytes_is_a_named_failure_and_no_call(self, tmp_path):
        client = _anthropic()
        result = client.query_with_document(
            "p", DocumentPart("application/pdf", file_path=str(tmp_path / "x.pdf")),
        )
        assert not result.ok
        assert not client._sdk_client.requests


# ---------------------------------------------------------------------------
# A capability flag never ships ahead of its client
# ---------------------------------------------------------------------------


def _native_pdf_providers() -> list[str]:
    return [
        p for p in PROVIDER_CLIENTS
        if any("native_pdf" in s.capabilities for s in load_tier_specs(p).values())
    ]


@pytest.mark.parametrize("provider_id", _native_pdf_providers())
def test_a_provider_declaring_native_pdf_has_a_working_document_path(provider_id):
    """anthropic.json declared native_pdf for weeks while its client refused
    every document. The plugins trust the flag, so a stub behind it looks like
    native support that fails on every call."""
    cls = client_class(provider_id)
    if cls is OpenAIClient:
        client = _openai()
    elif cls is AnthropicClient:
        client = _anthropic()
    else:
        pytest.skip(f"{cls.__name__} has its own document tests")
    result = client.query_with_document(
        "p", DocumentPart("application/pdf", inline_bytes=PDF_BYTES),
    )
    assert "not implemented" not in (result.error or "")
    assert result.ok
