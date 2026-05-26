# LLM Dispatcher — Phase 1 Implementation

Date: 2026-04-17
Design spec: `docs/specs/llm-dispatcher-native-document-handling.md`

---

## Summary

Refactored the LLM client architecture to support native document ingestion
(PDF via Gemini 2.5). `TieredLLMClient` is renamed to `LLMDispatcher` with
intent-based routing via `QueryHints`. Plugins can now call
`query_with_document()` to transparently send PDFs to the model via zero-copy
GCS URI or inline bytes, avoiding the chunked text extraction that lost
document context.

All changes are **additive**. Existing `query_text()` and `query_multimodal()`
calls work unchanged. `TieredLLMClient` is a backward-compatibility alias.
67 existing tests pass with zero modifications.

---

## Changes

### `framework/plugins/protocol.py` — Data Model Updates

- **Added `QueryHints`** — dataclass with `tier`, `needs_reasoning`,
  `needs_structured_output`, `prefers_native_file`, `max_budget_cents`.
  Plugins pass this to guide model selection without knowing provider details.
- **Updated `LLMResponse`** — added `model_used`, `transport_path`,
  `fallback_reason` diagnostic fields. Existing code is unaffected (all new
  fields default to `None`).
- **Updated `ArtifactRef`** — added `storage_uri: str | None = None` for cloud
  storage URIs (e.g. `gs://bucket/report.pdf`). Field is optional and additive.
- **Extended `LLMQueryInterface`** — added `query_with_document()` and
  `supports_native_document()` methods. Added optional `hints` parameter to
  `query_text()`.

### `framework/session/models.py` — Artifact Model

- **Added `storage_uri`** field to `Artifact` dataclass. Updated `to_dict()`
  and `from_dict()` for backward-compatible serialization (`from_dict` uses
  `.get()` so old data without the field loads cleanly).

### `framework/llm/client.py` — LLMDispatcher

- **Renamed `TieredLLMClient` → `LLMDispatcher`**. Added backward-compat alias
  `TieredLLMClient = LLMDispatcher`.
- **Intent-based routing** via `QueryHints`: `needs_reasoning` or
  `tier="heavy"` routes to Pro; otherwise routes to Flash. Falls back to
  token-count heuristic when no hints provided.
- **`query_with_document()`** resolves ingestion path automatically:
  1. GCS URI → `Part.from_uri()` (zero-copy)
  2. Local file → `Part.from_bytes()` (inline)
  3. No data source → returns `ok=False` for plugin fallback
- **`supports_native_document()`** checks if any connected model handles a
  given MIME type natively.
- Imports updated: `QueryHints`, `ArtifactRef`, `DocumentPart`.

### `framework/llm/backends/` — New Package

- **`base.py`** — `LLMBackend` ABC defining `connect()`, `query_text()`,
  `query_with_documents()`, `query_with_images()`, `capabilities()`.
  Supporting dataclasses: `ModelCapabilities`, `DocumentPart`.
- **`gemini.py`** — `GeminiBackend` implementing the ABC for Gemini models.
  Supports `Part.from_uri()` for GCS and `Part.from_bytes()` for local files.
  Exponential backoff retry on transient errors (503, 429).
- **`__init__.py`** — Explicit `BACKEND_REGISTRY` dict (no dynamic import).

### `framework/llm/providers/` — New Package

- **`gcp_gemini.json`** — declarative capability manifest declaring tiers
  (light=Flash, heavy=Pro), file handling (PDF: max 1000 pages, 50 MB,
  ingestion paths), and document strategies (PDF=native, JSON/CSV/text=extract).

### `framework/llm/__init__.py` — Updated Exports

- Exports `LLMDispatcher` and `TieredLLMClient` alongside existing
  `MCPLLMClient` and `ContextBuilder`.

### `framework/cli/shell.py` — Reference Updates

- All 6 references to `TieredLLMClient` updated to `LLMDispatcher`.
- Import, type annotation, instantiation, `isinstance` check, and help text
  all use the new name.

---

## Docs Updated

- **`tool_plugin_spec.md`** — bumped to v0.3.0. Added `QueryHints`,
  `query_with_document()`, `supports_native_document()`, `storage_uri`,
  diagnostic fields on `LLMResponse`.
- **`framework_architecture.md`** — bumped to v0.2.0. Updated `llm/` directory
  tree (backends, providers), component matrix (LLM Dispatcher + Backend), and
  data flow diagram.
- **`plugin_development.md`** — added "Using LLM Capabilities" section with
  `QueryHints`, native document ingestion pattern, `storage_uri` explanation,
  and `LLMResponse` diagnostics.

---

## Test Results

67 tests passing, 0 failures, 0 modifications to existing tests.

---

## What's Next (Phase 2)

- Rewrite `threat_intel_ingester` to use `query_with_document()` for PDFs
- End-to-end test with real PDF artifact and live Gemini connection
- Update `tool_plugin_spec.md` examples to show document ingestion pattern
