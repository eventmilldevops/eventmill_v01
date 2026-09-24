"""The provider seam — pinned in Stage 0, held ever since.

Plan: ``docs/specs/multi_provider_llm_clients.md``.

Two groups of tests here, and the split is still the point.

**Group A** — routing, clamping, tier fallback and capability checks against a
client that exposes nothing but the public model-client interface. This is the
genuinely provider-neutral part of ``LLMDispatcher``, and these exist so a
refactor cannot quietly break it.

**Group B** — the paths where the dispatcher used to reach through the
interface into a Gemini client's privates (``_build_prompt``, ``_genai_client``,
``transport``) or construct ``MCPLLMClient`` by name. All seven were
``xfail(strict=True)`` through Stage 0; Stage 1 moved that code into
``GeminiClient`` and the markers came off. They now guard the split rather than
describe the leak.

``PublicOnlyClient`` is the instrument. It implements only what the
``LLMModelClient`` protocol declares, so any private attribute the dispatcher
reaches for raises ``AttributeError`` — which is what makes these tests worth
keeping now that they pass. A dispatcher that works against this fake works
against a provider client that shares no code with Gemini.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from framework.llm.backends.base import DocumentPart
from framework.llm.dispatcher import LLMDispatcher
from framework.llm.providers import TierSpec
from framework.plugins.protocol import ArtifactRef, LLMResponse, QueryHints

REPO_ROOT = Path(__file__).resolve().parents[2]

# Vendor SDK roots that must never be imported by the dispatcher. Checked
# against import statements rather than raw text, so a comment mentioning
# Google Cloud Storage — which the dispatcher legitimately handles — does not
# trip it.
VENDOR_SDK_ROOTS = {"google", "openai", "anthropic"}


class PublicOnlyClient:
    """A model client exposing only the public interface, and nothing else.

    Deliberately has no ``_genai_client``, no ``_build_prompt``, no
    ``transport`` and no ``endpoint``. A dispatcher that needs any of those is
    a dispatcher that only works with one provider.
    """

    def __init__(
        self,
        model_id: str,
        tier: str,
        provider_id: str = "fake_provider",
        connected: bool = True,
        fail_with: str | None = None,
    ):
        self.provider_id = provider_id
        self.model_id = model_id
        self.tier = tier
        self.connected = connected
        self.total_tokens_used = 0
        self.max_retries = 3
        self.calls: list[dict] = []
        self._fail_with = fail_with

    # --- lifecycle ---------------------------------------------------------

    def connect(self, api_key: str | None = None) -> bool:
        self.connected = True
        return True

    def with_model(self, model_id: str) -> "PublicOnlyClient":
        """Rebind to another model id, carrying the live session forward.

        ``_retry_on_retired_model`` used to open-code this by cloning four
        private attributes of an ``MCPLLMClient``.
        """
        rebound = PublicOnlyClient(
            model_id=model_id,
            tier=self.tier,
            provider_id=self.provider_id,
            connected=self.connected,
        )
        rebound.total_tokens_used = self.total_tokens_used
        return rebound

    def supports(self, capability: str) -> bool:
        return capability in ("text", "multimodal_image", "native_pdf")

    # --- queries -----------------------------------------------------------

    def _record(self, kind: str, **kw) -> LLMResponse | None:
        self.calls.append({"kind": kind, **kw})
        if self._fail_with:
            return LLMResponse(ok=False, error=self._fail_with)
        return None

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None) -> LLMResponse:
        failed = self._record(
            "text", max_tokens=max_tokens, hints=hints,
            grounding_data=grounding_data, prompt=prompt,
        )
        return failed or LLMResponse(
            ok=True, text=f"text from {self.model_id}", model_used=self.model_id,
        )

    def query_multimodal(self, prompt, image_data, image_format,
                         system_context=None, max_tokens=4096,
                         hints=None) -> LLMResponse:
        failed = self._record("multimodal", max_tokens=max_tokens, hints=hints)
        return failed or LLMResponse(
            ok=True, text=f"image from {self.model_id}", model_used=self.model_id,
        )

    def query_with_document(self, prompt, doc: DocumentPart,
                            system_context=None, max_tokens=8192,
                            hints=None) -> LLMResponse:
        """Take a resolved DocumentPart and decide the ingestion path itself.

        The dispatcher used to do this on the client's behalf, building Gemini
        ``Part`` objects from another object's private SDK handle.
        """
        failed = self._record(
            "document", max_tokens=max_tokens, hints=hints, doc=doc, prompt=prompt,
        )
        if failed:
            return failed
        remote = (doc.storage_uri or "").startswith("gs://")
        path = "gs_uri" if remote else "inline_bytes"
        return LLMResponse(
            ok=True, text=f"document from {self.model_id}",
            model_used=self.model_id, transport_path=path,
        )


def _specs() -> dict[str, TierSpec]:
    """Two capacity-identical tiers, both native-PDF capable and gs://-reading.

    The light tier declares a fallback so the retired-model path is reachable
    without depending on which tier the real Gemini manifest happens to give
    one to.
    """
    return {
        "light": TierSpec("light", "fake-light", "K_LIGHT", 65536, 1_048_576,
                          "low", ("text", "multimodal_image", "native_pdf",
                           "remote_uri_gs"),
                          fallback_model_id="fake-light-ga"),
        "heavy": TierSpec("heavy", "fake-heavy", "K_HEAVY", 65536, 1_048_576,
                          "high", ("text", "multimodal_image", "native_pdf",
                                   "remote_uri_gs", "deep_reasoning")),
    }


@pytest.fixture
def clients() -> dict[str, PublicOnlyClient]:
    return {
        "light": PublicOnlyClient("fake-light", "light"),
        "heavy": PublicOnlyClient("fake-heavy", "heavy"),
    }


@pytest.fixture
def dispatcher(clients) -> LLMDispatcher:
    return LLMDispatcher(clients=clients, tier_specs=_specs())


@pytest.fixture
def pdf_artifact() -> ArtifactRef:
    """A PDF that lives only in object storage, as it does on Cloud Run.

    Page count and size come from metadata because there is no local file to
    read them from — which is also why a non-Gemini provider cannot be handed
    this artifact without the framework fetching the bytes first.
    """
    return ArtifactRef(
        artifact_id="art-probe-001",
        artifact_type="pdf_report",
        file_path="",
        storage_uri="gs://eventmill-common/probe.pdf",
        metadata={"mime_type": "application/pdf", "pages": 3,
                  "size_bytes": 8_021},
    )


# ---------------------------------------------------------------------------
# Group A — already provider-neutral, must stay that way
# ---------------------------------------------------------------------------


class TestPublicInterfaceIsEnoughToday:
    """Paths a provider-agnostic client can already serve unchanged."""

    def test_text_query_needs_nothing_private(self, dispatcher, clients):
        result = dispatcher.query_text("hello", hints=QueryHints(tier="light"))
        assert result.ok
        assert result.text == "text from fake-light"
        assert clients["light"].calls[0]["kind"] == "text"

    def test_grounding_data_reaches_the_client_on_the_text_path(
        self, dispatcher, clients,
    ):
        dispatcher.query_text(
            "hello", grounding_data=["ctx one"], hints=QueryHints(tier="light"),
        )
        assert clients["light"].calls[0]["grounding_data"] == ["ctx one"]

    def test_multimodal_query_needs_nothing_private(self, dispatcher, clients):
        result = dispatcher.query_multimodal(
            "describe", b"\x89PNG", "png", hints=QueryHints(tier="heavy"),
        )
        assert result.ok
        assert clients["heavy"].calls[0]["kind"] == "multimodal"

    def test_tier_precedence_survives_a_foreign_client(self, dispatcher, clients):
        dispatcher.query_text("x", hints=QueryHints(needs_reasoning=True))
        assert clients["heavy"].calls and not clients["light"].calls

    def test_output_clamping_reads_only_model_id(self):
        specs = _specs()
        specs["light"] = TierSpec("light", "fake-light", "K_LIGHT", 8192,
                                  1_048_576, "low", ("text",))
        clients = {"light": PublicOnlyClient("fake-light", "light")}
        LLMDispatcher(clients=clients, tier_specs=specs).query_text(
            "x", max_tokens=60000, hints=QueryHints(tier="light"),
        )
        assert clients["light"].calls[0]["max_tokens"] == 8192

    def test_tier_fallback_on_quota_needs_nothing_private(self):
        clients = {
            "light": PublicOnlyClient(
                "fake-light", "light",
                fail_with="429 RESOURCE_EXHAUSTED: quota exceeded",
            ),
            "heavy": PublicOnlyClient("fake-heavy", "heavy"),
        }
        result = LLMDispatcher(clients=clients, tier_specs=_specs()).query_text(
            "x", hints=QueryHints(tier="light"),
        )
        assert result.ok
        assert result.text == "text from fake-heavy"

    def test_native_capability_comes_from_the_manifest_not_the_sdk(
        self, dispatcher,
    ):
        assert dispatcher.supports_native_document("application/pdf") is True
        assert dispatcher.supports_native_document("application/x-pcap") is False

    def test_connected_models_reads_only_public_attributes(self, dispatcher):
        # provider_id rides along since the (provider_id, tier) rekey: with two
        # vendors bound, "heavy" alone no longer identifies a model, and a run
        # record that cannot name its provider is uninterpretable afterwards.
        assert dispatcher.connected_models() == [
            {"provider_id": "fake_provider", "tier": "light",
             "model_id": "fake-light"},
            {"provider_id": "fake_provider", "tier": "heavy",
             "model_id": "fake-heavy"},
        ]


# ---------------------------------------------------------------------------
# Group B — the seam, as Stage 1 made it
# ---------------------------------------------------------------------------


class TestDocumentPathBelongsToTheClient:
    """The document path belongs to the provider client.

    It used to be ``LLMDispatcher._execute_document_query``, a staticmethod
    that built ``genai_types.Part`` objects out of ``client._genai_client``.
    The dispatcher's job is to resolve the artifact into a ``DocumentPart``,
    run the PDF guard and clamp the budget — not to know that one vendor reads
    ``gs://`` and another needs bytes.
    """

    def test_document_query_reaches_the_client_through_its_interface(
        self, dispatcher, clients, pdf_artifact,
    ):
        result = dispatcher.query_with_document(
            "extract indicators", pdf_artifact, hints=QueryHints(tier="light"),
        )
        assert result.ok
        assert result.text == "document from fake-light"
        assert clients["light"].calls[0]["kind"] == "document"

    def test_grounding_data_reaches_the_client_on_the_document_path(
        self, dispatcher, clients, pdf_artifact,
    ):
        dispatcher.query_with_document(
            "extract indicators", pdf_artifact,
            grounding_data=["prior findings"], hints=QueryHints(tier="light"),
        )
        assert clients["light"].calls[0]["kind"] == "document"

    def test_the_client_decides_the_ingestion_path(
        self, dispatcher, clients, pdf_artifact,
    ):
        result = dispatcher.query_with_document(
            "extract indicators", pdf_artifact, hints=QueryHints(tier="light"),
        )
        doc = clients["light"].calls[0]["doc"]
        assert isinstance(doc, DocumentPart)
        assert doc.storage_uri == "gs://eventmill-common/probe.pdf"
        assert result.transport_path == "gs_uri"

    def test_the_pdf_guard_stays_on_the_dispatcher(self, dispatcher, clients):
        """The one document-path decision that is *not* the client's.

        Refusing an oversized PDF is a policy call made from the manifest, and
        it has to happen before any provider is asked to do work.
        """
        huge = ArtifactRef(
            artifact_id="art-huge", artifact_type="pdf_report", file_path="",
            storage_uri="gs://eventmill-common/huge.pdf",
            metadata={"mime_type": "application/pdf", "pages": 4000,
                      "size_bytes": 20_000_000},
        )
        result = dispatcher.query_with_document(
            "extract", huge, hints=QueryHints(tier="light"),
        )
        assert not result.ok
        assert not clients["light"].calls


class TestRetiredModelRetryStaysWithinTheProvider:
    """``_retry_on_retired_model`` must not name a provider class.

    It used to construct ``MCPLLMClient`` directly and copy ``_genai_client``,
    ``_api_key_env_var``, ``_connected`` and ``_total_tokens_used`` across to
    reuse the live session. A factory returning a fresh client loses all four,
    which is why the replacement is a ``with_model()`` operation on the client
    rather than a lookup.
    """

    def test_the_substitute_is_the_same_provider_client(self):
        client = PublicOnlyClient(
            "fake-light", "light",
            fail_with="404 NOT_FOUND: model fake-light was not found",
        )
        dispatcher = LLMDispatcher(
            clients={"light": client}, tier_specs=_specs(),
        )
        result = dispatcher.query_text("x", hints=QueryHints(tier="light"))

        substitute = dispatcher.client_at("light")
        assert type(substitute) is type(client)
        assert substitute.model_id == "fake-light-ga"
        assert result.ok

    def test_the_substitute_carries_the_session_spend_forward(self):
        client = PublicOnlyClient(
            "fake-light", "light",
            fail_with="404 NOT_FOUND: model fake-light was not found",
        )
        client.total_tokens_used = 4242
        dispatcher = LLMDispatcher(
            clients={"light": client}, tier_specs=_specs(),
        )
        dispatcher.query_text("x", hints=QueryHints(tier="light"))

        assert dispatcher.client_at("light").total_tokens_used == 4242


class TestDispatcherCarriesNoVendorSdk:
    """The mechanical guarantee that the split stayed split.

    Cheap to keep forever, and the only thing that stops a vendor import
    drifting back in during Stage 3 or Stage 5.
    """

    def test_the_dispatcher_module_exists_under_its_real_name(self):
        importlib.import_module("framework.llm.dispatcher")

    def test_the_dispatcher_imports_no_vendor_sdk(self):
        source = (REPO_ROOT / "framework" / "llm" / "dispatcher.py").read_text(
            encoding="utf-8",
        )
        imported = _imported_roots(source)
        assert not (imported & VENDOR_SDK_ROOTS), (
            f"dispatcher.py imports vendor SDKs: "
            f"{sorted(imported & VENDOR_SDK_ROOTS)}"
        )


def _imported_roots(source: str) -> set[str]:
    """Top-level package name of every import in a module's source.

    Checks the parse tree rather than the text so that a comment or a string
    mentioning a vendor — ``gs://`` handling keeps a few — is not a false
    positive.
    """
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots
