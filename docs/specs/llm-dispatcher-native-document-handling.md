# LLM Dispatcher & Native Document Handling — Design Specification

**Status:** Approved for MVP  
**Date:** 2026-04-17  
**Scope:** `framework/llm/`, `framework/plugins/protocol.py`, artifact model  
**Inputs:** Windsurf analysis of Google Gemini 2026 docs, Claude 4.7 routing design review

---

## 1. Problem Statement

The current `LLMQueryInterface` only supports `query_text()` and `query_multimodal(image)`.
Plugins that process documents (PDFs, STIX bundles, HTML reports) must extract text, chunk it,
and submit chunks individually. This causes three failures:

1. **Quality** — Text extraction destroys layout, charts, tables, and cross-page context.
   The `threat_intel_ingester` sends 43 disconnected text fragments instead of one coherent
   50-page CrowdStrike report. The LLM cannot build accurate MITRE mappings or attack graphs
   from context-stripped chunks.

2. **Reliability** — Each chunk is a separate API call that can fail, timeout, or return
   malformed JSON. With 43 chunks, even a 5% per-call failure rate yields ~89% chance of
   at least one failure. Currently all 43 chunks fail to parse → empty MITRE mappings →
   `attack_path_visualizer` cannot render.

3. **Wasted cost** — 43 API calls to process what Gemini handles in 1 call natively.
   A 50-page PDF is ~12,900 tokens (258 tokens/page) — trivial for any current model.

### What Google says (2026 docs)

> Gemini models can process documents in PDF format, using **native vision** to understand
> entire document contexts — up to **1,000 pages / 50 MB**.

Gemini accepts PDFs via:
- `Part.from_uri("gs://...")` — zero-copy from GCS (preferred on Cloud Run)
- `Part.from_bytes(data, mime_type)` — inline bytes (works everywhere)
- Files API upload — for reuse across multiple requests

**The fix is not better chunking. It is bypassing text extraction entirely for PDF artifacts.**

---

## 2. Design Principles

1. **MVP discipline** — Ship the minimum that unblocks native PDF on GCP. Defer multi-provider,
   streaming, multi-document, and cost optimization to post-MVP.
2. **Additive, not breaking** — New fields and methods are added alongside existing ones.
   `query_text()` and `query_multimodal()` continue to work unchanged. No plugin rewrites
   except the ingester.
3. **Extend `TieredLLMClient`, don't replace it** — The existing light/heavy routing works.
   We extend it with richer intent signals and native document dispatch.
4. **Declarative capabilities** — Provider manifests declare what each model can do. The
   dispatcher matches plugin needs to model capabilities at runtime.
5. **Plugins don't know provider specifics** — No plugin imports `google.genai`. Plugins
   pass an `ArtifactRef` and `QueryHints`; the dispatcher handles the rest.
6. **Transparent fallback** — If native PDF isn't available, fall back to text extraction
   silently. The `LLMResponse` reports what path was used via `transport_path` and
   `fallback_reason` for diagnostics.

---

## 3. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                          Plugin Layer                            │
│  context.llm_query.query_text(prompt, hints=...)                │
│  context.llm_query.query_with_document(prompt, artifact, hints) │
│  context.llm_query.supports_native_document("application/pdf")  │
└────────────────────────┬─────────────────────────────────────────┘
                         │  LLMQueryInterface (protocol.py)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                      LLMDispatcher                               │
│  (extends TieredLLMClient)                                       │
│  Routes by QueryHints: tier + needs_reasoning + document type    │
│  Loads provider manifest for capability matching                 │
│  Resolves ingestion path: gs_uri > inline_bytes > text_fallback  │
└──────────┬──────────────────────────────────┬────────────────────┘
           │ light                            │ heavy
           ▼                                  ▼
┌─────────────────────┐          ┌─────────────────────────┐
│  LLMBackend (ABC)   │          │  LLMBackend (ABC)       │
│  GeminiBackend      │          │  GeminiBackend           │
│  model: 2.5-flash   │          │  model: 2.5-pro         │
│  caps: native_pdf,  │          │  caps: native_pdf,      │
│    structured_output │          │    deep_reasoning, ...  │
└─────────────────────┘          └─────────────────────────┘
           │                                  │
           ▼                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Provider SDK (google.genai)                    │
│  generate_content(contents=[Part.from_uri("gs://..."), prompt])  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Data Model Changes

### 4.1 `ArtifactRef` — add `storage_uri` (additive, not breaking)

```python
# framework/plugins/protocol.py
@dataclass
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    file_path: str
    storage_uri: str | None = None    # NEW — gs://, s3://, or None
    source_tool: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
```

`file_path` remains the primary field. `storage_uri` is populated when the artifact
lives in cloud storage. Both can coexist — `file_path` is the local cache,
`storage_uri` is the canonical cloud location.

### 4.2 `Artifact` — same addition

```python
# framework/session/models.py
@dataclass
class Artifact:
    artifact_id: str
    session_id: str
    artifact_type: str
    file_path: str
    storage_uri: str | None = None    # NEW
    source_tool: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)
```

SQLite migration: one `ALTER TABLE artifacts ADD COLUMN storage_uri TEXT;` — nullable,
backward compatible. Existing rows get `NULL`.

### 4.3 `LLMResponse` — add diagnostic fields

```python
@dataclass
class LLMResponse:
    ok: bool
    text: str | None = None
    error: str | None = None
    token_usage: dict[str, int] | None = None
    model_used: str | None = None          # NEW — which model actually ran
    transport_path: str | None = None      # NEW — "gs_uri", "inline_bytes", "text_fallback"
    fallback_reason: str | None = None     # NEW — why preferred path wasn't used
```

### 4.4 `QueryHints` — new dataclass

```python
@dataclass
class QueryHints:
    """Plugin hints to the LLMDispatcher about what kind of query this is."""
    tier: str = "light"                    # "light" | "heavy"
    needs_reasoning: bool = False          # biases toward deep-reasoning models
    needs_structured_output: bool = False  # ensures JSON-mode capable model
    prefers_native_file: bool = False      # prefer native file > text extraction
    max_budget_cents: float | None = None  # cost ceiling per call (safety net)
```

---

## 5. Updated LLMQueryInterface

Backward-compatible additions. All existing `query_text()` calls continue to work.

```python
class LLMQueryInterface(Protocol):

    # --- Existing (signature extended with optional hints) ---

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,              # NEW optional param
    ) -> LLMResponse: ...

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    # --- New methods ---

    def query_with_document(
        self,
        prompt: str,
        artifact: ArtifactRef,
        system_context: str | None = None,
        max_tokens: int = 8192,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Query with a document artifact.

        The dispatcher resolves the best ingestion path automatically:
          1. Native document + remote URI (gs:// for Gemini)
          2. Native document + inline bytes
          3. Text extraction fallback (existing chunk approach)

        The response's transport_path field records which path was used.
        """
        ...

    def supports_native_document(self, mime_type: str) -> bool:
        """Check if any connected model handles this MIME type natively."""
        ...
```

---

## 6. Provider Manifest

Each provider has a JSON manifest at `framework/llm/providers/<provider>.json`.
The dispatcher loads the active manifest at startup.

### `framework/llm/providers/gcp_gemini.json`

```json
{
  "provider_id": "gcp_gemini",
  "display_name": "Google Gemini (GCP)",

  "tiers": {
    "light": {
      "model_id": "gemini-2.5-flash",
      "api_key_env": "GEMINI_FLASH_API_KEY",
      "max_output_tokens": 8192,
      "max_context_tokens": 1048576,
      "cost_tier": "low",
      "capabilities": [
        "text", "multimodal_image", "native_pdf",
        "structured_output", "function_calling"
      ]
    },
    "heavy": {
      "model_id": "gemini-2.5-pro",
      "api_key_env": "GEMINI_PRO_API_KEY",
      "max_output_tokens": 65536,
      "max_context_tokens": 2097152,
      "cost_tier": "high",
      "capabilities": [
        "text", "multimodal_image", "native_pdf",
        "structured_output", "function_calling", "deep_reasoning"
      ]
    }
  },

  "file_handling": {
    "application/pdf": {
      "max_pages": 1000,
      "max_size_mb": 50,
      "tokens_per_page": 258,
      "ingestion_paths": ["gs_uri", "inline_bytes", "files_api"],
      "preferred_ingestion": "gs_uri"
    }
  },

  "document_strategies": {
    "application/pdf": "native",
    "application/json": "extract_text",
    "text/csv": "extract_text",
    "text/plain": "extract_text",
    "text/html": "extract_text",
    "default": "extract_and_chunk"
  }
}
```

**Design decisions on the manifest:**
- **No absolute cost values** (e.g., `$0.00030/1k tokens`). These go stale within months.
  Use relative `cost_tier` only ("low", "high") for routing decisions.
- **No `transport_class` string** for dynamic import. Use an explicit backend registry dict
  in code — explicit beats implicit, and IDE refactoring tools work correctly.
- **Ingestion paths are ordered** — the dispatcher tries them in manifest order until one
  succeeds. `gs_uri` first (zero-copy), then `inline_bytes`, then `files_api` (upload).

---

## 7. LLMBackend ABC

```python
# framework/llm/backends/base.py

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModelCapabilities:
    """Declared capabilities of a connected model."""
    model_id: str = ""
    tier: str = "light"
    native_document_types: list[str] = field(default_factory=list)
    native_image_types: list[str] = field(default_factory=list)
    max_context_tokens: int = 128_000
    max_output_tokens: int = 8192
    supports_structured_output: bool = False
    supports_reasoning: bool = False


@dataclass
class DocumentPart:
    """A document to include in an LLM request."""
    mime_type: str
    storage_uri: str | None = None     # gs://, s3:// — preferred
    file_path: str | None = None       # local filesystem path — fallback
    inline_bytes: bytes | None = None  # raw bytes — last resort


class LLMBackend(ABC):
    """Abstract backend for a specific LLM provider + model.

    One instance per model. The LLMDispatcher holds one per tier.
    """

    @abstractmethod
    def connect(self, api_key: str | None = None) -> bool: ...

    @property
    @abstractmethod
    def connected(self) -> bool: ...

    @property
    @abstractmethod
    def model_id(self) -> str: ...

    @abstractmethod
    def capabilities(self) -> ModelCapabilities: ...

    @abstractmethod
    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    @abstractmethod
    def query_with_documents(
        self,
        prompt: str,
        documents: list[DocumentPart],
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Query with document parts. Backend resolves transport internally."""
        ...

    @abstractmethod
    def query_with_images(
        self,
        prompt: str,
        images: list[tuple[bytes, str]],
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    @property
    @abstractmethod
    def total_tokens_used(self) -> int: ...
```

---

## 8. GeminiBackend (MVP Implementation)

```python
# framework/llm/backends/gemini.py

class GeminiBackend(LLMBackend):
    """Gemini-specific backend using google.genai SDK."""

    def query_with_documents(self, prompt, documents, system_context, max_tokens):
        parts = []
        transport_path = None

        for doc in documents:
            # Try ingestion paths in priority order: gs_uri > inline_bytes
            if doc.storage_uri and doc.storage_uri.startswith("gs://"):
                parts.append(genai_types.Part.from_uri(
                    file_uri=doc.storage_uri,
                    mime_type=doc.mime_type,
                ))
                transport_path = "gs_uri"

            elif doc.inline_bytes:
                parts.append(genai_types.Part.from_bytes(
                    data=doc.inline_bytes,
                    mime_type=doc.mime_type,
                ))
                transport_path = "inline_bytes"

            elif doc.file_path:
                with open(doc.file_path, "rb") as f:
                    parts.append(genai_types.Part.from_bytes(
                        data=f.read(),
                        mime_type=doc.mime_type,
                    ))
                transport_path = "inline_bytes"

        parts.append(prompt)

        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
        )
        if system_context:
            config.system_instruction = system_context

        response = self._client.models.generate_content(
            model=self._model_id,
            contents=parts,
            config=config,
        )

        return LLMResponse(
            ok=True,
            text=response.text or "",
            model_used=self._model_id,
            transport_path=transport_path,
        )
```

**Note:** No separate `ArtifactResolver` service. The backend resolves transport
inline — it's 15 lines of code. Extract to a service in Phase 2 if/when a second
provider needs different resolution logic.

---

## 9. LLMDispatcher (extends TieredLLMClient)

The existing `TieredLLMClient` is renamed to `LLMDispatcher` and extended with
intent-based routing and document dispatch.

### 9.1 Routing logic

```python
class LLMDispatcher:
    """Routes LLM queries to the appropriate backend based on QueryHints.

    Extends the light/heavy tier concept with capability-aware routing.
    Backward-compatible: all existing query_text() calls work unchanged.
    """

    def _route(self, hints: QueryHints | None, document_mime: str | None = None) -> LLMBackend:
        """Select backend based on hints + capabilities."""
        hints = hints or QueryHints()

        # 1. Determine tier preference
        if hints.needs_reasoning:
            order = ("heavy", "light")
        elif hints.tier == "heavy":
            order = ("heavy", "light")
        else:
            order = ("light", "heavy")

        # 2. If native document needed, filter by capability
        if document_mime and hints.prefers_native_file:
            for tier in order:
                backend = self._backends.get(tier)
                if backend and backend.connected:
                    caps = backend.capabilities()
                    if document_mime in caps.native_document_types:
                        return backend
            # No native support — fall through to any connected backend

        # 3. Standard fallback: first connected in preferred order
        for tier in order:
            backend = self._backends.get(tier)
            if backend and backend.connected:
                return backend

        raise RuntimeError("No LLM backend connected — run 'connect' first")
```

### 9.2 query_with_document implementation

```python
    def query_with_document(
        self,
        prompt: str,
        artifact: ArtifactRef,
        system_context: str | None = None,
        max_tokens: int = 8192,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        hints = hints or QueryHints(tier="heavy", prefers_native_file=True)
        mime_type = artifact.metadata.get("mime_type", "application/pdf")

        try:
            backend = self._route(hints, document_mime=mime_type)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))

        caps = backend.capabilities()

        # Check if backend supports native document for this MIME type
        if mime_type in caps.native_document_types:
            doc = DocumentPart(
                mime_type=mime_type,
                storage_uri=artifact.storage_uri,
                file_path=artifact.file_path,
            )
            full_prompt = self._build_prompt(prompt, grounding_data)
            return backend.query_with_documents(
                prompt=full_prompt,
                documents=[doc],
                system_context=system_context,
                max_tokens=max_tokens,
            )
        else:
            # Fallback: text extraction (existing chunk approach)
            # Plugin handles this in its own code when supports_native_document
            # returns False. Alternatively, dispatcher could extract here.
            return LLMResponse(
                ok=False,
                error="Native document processing not available for this MIME type",
                fallback_reason=f"model {backend.model_id} lacks native_{mime_type}",
            )

    def supports_native_document(self, mime_type: str) -> bool:
        """Check if any connected backend supports this MIME type natively."""
        for backend in self._backends.values():
            if backend.connected:
                caps = backend.capabilities()
                if mime_type in caps.native_document_types:
                    return True
        return False
```

---

## 10. Plugin Impact — threat_intel_ingester

### Before (current — 43 chunks, all failing)

```python
raw_text = _extract_text(artifact.file_path)
text_chunks = _chunk_text(raw_text, 6000)
for i, (text_chunk, ioc_batch) in enumerate(zip(text_chunks, ioc_chunks)):
    prompt = LLM_REFINEMENT_PROMPT.format(...)
    response = context.llm_query.query_text(prompt=prompt, max_tokens=3000)
    # parse JSON, merge, repeat 43 times
```

### After (single call, native PDF)

```python
if context.llm_query.supports_native_document("application/pdf"):
    response = context.llm_query.query_with_document(
        prompt=LLM_REFINEMENT_PROMPT.format(
            source_context=source_context,
            ioc_candidates=candidates_text,
        ),
        artifact=pdf_artifact,
        system_context="You are a threat intelligence analyst. Respond only with valid JSON.",
        max_tokens=8192,
        hints=QueryHints(
            tier="heavy",
            needs_reasoning=True,
            needs_structured_output=True,
            prefers_native_file=True,
        ),
    )
    if response.ok:
        parsed = _parse_llm_json(response.text)
        # ... single parse, done
    else:
        logger.warning("Native doc failed (%s), falling back to chunk approach",
                       response.fallback_reason)
        # existing chunk code as fallback
else:
    # Existing chunk-based approach for non-Gemini providers
    ...
```

The chunk code stays as a fallback path. It is not deleted — it serves providers
that lack native PDF support.

---

## 11. File Layout

### New files

```
framework/llm/
    backends/
        __init__.py
        base.py                 # LLMBackend ABC, ModelCapabilities, DocumentPart
        gemini.py               # GeminiBackend implementation
    providers/
        __init__.py
        gcp_gemini.json         # Capability manifest
```

### Modified files

```
framework/llm/
    __init__.py                 # Export LLMDispatcher, GeminiBackend
    client.py                   # TieredLLMClient → LLMDispatcher, add query_with_document

framework/plugins/
    protocol.py                 # Add QueryHints, query_with_document, storage_uri,
                                # LLMResponse diagnostic fields

framework/session/
    models.py                   # Add storage_uri to Artifact

plugins/log_analysis/threat_intel_ingester/
    tool.py                     # Use query_with_document for PDFs (Phase 2)
```

### Unchanged

```
framework/cli/shell.py          # connect command works as-is
framework/cloud/interfaces.py   # StorageBackend unchanged
framework/artifacts/registry.py # Populate storage_uri from upload() return value
All other plugins                # No changes until they opt in
All existing tests               # Continue to pass (additive changes only)
```

---

## 12. Backend Registry (explicit, not string-based)

```python
# framework/llm/backends/__init__.py

from .gemini import GeminiBackend

# Explicit registry — no dynamic import from JSON strings.
# New providers add an entry here and a backends/<name>.py file.
BACKEND_REGISTRY: dict[str, type] = {
    "gcp_gemini": GeminiBackend,
}
```

To add a new provider (e.g., Anthropic), a developer:
1. Creates `framework/llm/backends/anthropic.py` with a class implementing `LLMBackend`
2. Creates `framework/llm/providers/anthropic.json` with capability manifest
3. Adds `"anthropic": AnthropicBackend` to `BACKEND_REGISTRY`
4. Sets `EVENTMILL_LLM_PROVIDER=anthropic` and the required API key env vars

No framework core changes. No plugin changes.

---

## 13. Migration Plan

### Phase 1 — Framework ✅ IMPLEMENTED (2026-04-17)

- ✅ Add `LLMBackend` ABC, `GeminiBackend`, `DocumentPart`, `ModelCapabilities`
- ✅ Add `QueryHints` dataclass to `protocol.py`
- ✅ Add `query_with_document()` and `supports_native_document()` to `LLMQueryInterface`
- ✅ Add `storage_uri` to `ArtifactRef` and `Artifact`
- ✅ Add `model_used`, `transport_path`, `fallback_reason` to `LLMResponse`
- ✅ Refactor `TieredLLMClient` → `LLMDispatcher` with intent-based routing
- ✅ Create `gcp_gemini.json` provider manifest
- ✅ All 67 existing tests pass — changes are additive
- See change log: `docs/change_log/2026-04-17-llm-dispatcher-phase1.md`

### Phase 2 — Ingester rewrite

- Update `threat_intel_ingester` to use `query_with_document()` for PDF artifacts
- Keep chunk-based path as fallback
- Update `ArtifactRegistry.register()` to capture `storage_uri` from GCS uploads
- Update `do_load` in shell to populate `storage_uri` for GCS artifacts

### Phase 3 — Post-MVP enhancements

- `needs_structured_output` → enable Gemini `response_schema` for guaranteed JSON
- Lazy GCS download — skip local download when provider reads `gs://` directly
- Additional providers (Anthropic, Azure OpenAI) via backend + manifest
- Plugin manifest `llm_requires` field for early capability validation

---

## 14. Non-Goals (explicit)

- **No multi-provider routing in MVP.** Architecture supports it; implementation is single-provider.
- **No streaming responses.** One-shot only.
- **No multi-document prompts.** Single artifact per `query_with_document()` call.
- **No automatic failover between providers.** If the selected backend fails, the call fails;
  the plugin decides what to do.
- **No cost optimization system.** `max_budget_cents` is a safety net, not a minimizer.
- **No `ArtifactResolver` service.** Backend resolves transport inline. Extract later if needed.
- **No `ArtifactLocation` replacement.** `file_path` stays; `storage_uri` is additive.

---

## 15. Open Questions

1. **`needs_structured_output` + Gemini `response_schema`**: Should Phase 1 include wiring
   `response_schema` into the backend when the hint is set? This would eliminate JSON parse
   failures entirely. Low effort, high impact.

2. **Files API threshold**: For PDFs > 20 MB, should the backend auto-upload via Files API
   instead of sending inline bytes? The manifest declares the path priority; this is just
   following it.

3. **`do_load` lazy download**: Should Phase 2 skip the GCS download entirely when the
   provider can read `gs://` URIs? The `storage_uri` field makes this possible. The
   local cache would only be populated on demand (e.g., when a plugin reads the file
   directly for regex extraction).
