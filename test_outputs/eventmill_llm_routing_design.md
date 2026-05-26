# Event Mill — LLM Routing and Native Document Handling

**Design Document**
**Version**: 0.1 (draft for review)
**Scope**: Replace the current tier-only LLM client with a pluggable routing system that supports native document handling. GCP/Gemini is the MVP implementation; architecture supports Anthropic, OpenAI, Azure, and Bedrock as future additions.

---

## 1. Problems to Solve

The current `TieredLLMClient` / `MCPLLMClient` abstraction is too thin for the workflows Event Mill actually runs. Three specific gaps:

**Problem 1: Tier selection is too simple.** `light` vs `heavy` is a useful split but it conflates three different dimensions: model size (Flash vs Pro), reasoning depth (thinking on/off), and capability (text-only vs multimodal vs native-PDF). A plugin that needs native PDF vision is not the same kind of request as one that needs deep reasoning over text.

**Problem 2: No path for native document ingestion.** The interface only exposes `query_text()` and `query_multimodal(image_bytes)`. A plugin that has a PDF artifact cannot tell the framework "this model provider can read PDFs natively — send the bytes instead of extracted text." Every plugin that touches a PDF has to extract text with `pdfplumber` first, losing tables, diagrams, and cross-page context.

**Problem 3: The artifact workflow downloads bucket files to local disk.** The current `do_load` command resolves a file from GCS, downloads it to `workspace/artifacts/<session>/`, and registers the local path. For PDFs this works but is wasteful — GCS-backed deployments should be able to pass the `gs://` URI to Gemini directly without a round-trip download, since Gemini's Files API accepts Cloud Storage URIs natively. For non-GCP providers the download remains correct.

---

## 2. Design Principles

- **Modularity**: The LLM subsystem must allow new providers to be added without changes to plugins or framework core.
- **Declarative capability discovery**: A plugin declares what it needs ("I have a PDF artifact, I want the LLM to read it natively if possible"). The router picks the appropriate model and transport path based on provider capability manifests.
- **Graceful degradation**: If the selected provider cannot handle native PDF, the framework falls back to text extraction. Plugins do not fail — they get the best available path.
- **Same contract for local-backed and cloud-backed artifacts**: A plugin calls `context.llm_query.query_with_document(artifact_ref, prompt)` regardless of whether the artifact lives on local disk or in a GCS bucket. The transport layer decides how to get the bytes to the model.
- **No plugin code knows about provider specifics**: Plugins never import `google.genai` or `anthropic`. They talk to the framework's `LLMRouter`.

---

## 3. Artifact Handling — What Stays and What Changes

The artifact registry stays. The session database stays. The concept of a tracked artifact with a type, an ID, and provenance is correct and should not change. What needs to change is the **resolution contract** — how the framework answers the question "give me the bytes of this artifact" when the caller is the LLM transport layer.

### 3.1 Artifact storage location becomes a provenance field, not a file path

The current `Artifact` model stores a single `file_path` that is always a local path. This needs to become a resolvable reference with multiple possible backends:

```python
@dataclass
class ArtifactLocation:
    """Where an artifact actually lives. Resolution is deferred to transport."""
    scheme: str                # "file", "gs", "s3", "azureblob"
    uri: str                   # full URI including scheme
    local_cache_path: str | None = None   # populated on demand
    size_bytes: int | None = None
    content_hash: str | None = None


@dataclass
class Artifact:
    artifact_id: str
    session_id: str
    artifact_type: str
    location: ArtifactLocation
    source_tool: str | None
    created_at: datetime
    metadata: dict
```

The database schema gains one column (`location_uri`) and one flag (`cached_locally`). Existing rows with a file path get migrated to `file://` URIs automatically.

### 3.2 `do_load` no longer downloads when the target provider can use remote URIs

The current behavior is: GCS file resolved → download to local disk → register local path as artifact. This should become: GCS file resolved → register as `gs://` artifact with `local_cache_path=None`. Download happens lazily when a consumer needs local bytes.

This has two benefits. First, the common case for Gemini workflows (PDF in bucket → Gemini reads it) never downloads the file at all. Second, artifacts produced by one tool that are consumed by another stay as references until needed — so a `json_events` file written to GCS by `threat_intel_ingester` can be consumed by `attack_path_visualizer` without either tool caring about the transport.

### 3.3 The transport decides resolution strategy

A new `ArtifactResolver` service sits between the artifact registry and the LLM transport:

```python
class ArtifactResolver:
    def as_local_bytes(self, artifact: Artifact) -> bytes:
        """Return raw bytes, downloading from cloud storage if needed."""

    def as_local_path(self, artifact: Artifact) -> Path:
        """Return a local filesystem path, caching from cloud if needed."""

    def as_remote_uri(self, artifact: Artifact, provider: str) -> str | None:
        """Return a URI the target provider can fetch directly.
        Returns None if the provider cannot access this URI directly
        (e.g., an s3:// URI when calling a Gemini model).
        """
```

For GCP + Gemini, `as_remote_uri(artifact, "gcp")` returns the original `gs://` URI. The Gemini Files API accepts this directly. No download needed.

For GCP artifact + Anthropic model, `as_remote_uri(artifact, "anthropic")` returns `None`, and the transport falls back to `as_local_bytes()` which triggers a download.

---

## 4. LLM Subsystem — New Architecture

### 4.1 Component breakdown

```
┌─────────────────────────────────────────────────────────────┐
│                    Plugin Code                               │
│  context.llm_query.query_with_document(artifact, prompt)    │
│  context.llm_query.query_text(prompt, tier="heavy")         │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    LLMRouter                                 │
│  - Parses the plugin's requirements                          │
│  - Consults ProviderRegistry for capability matches          │
│  - Selects a ModelBinding (provider + model_id + tier)       │
│  - Delegates to the provider's Transport                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────▼────────┐ ┌───────▼────────┐ ┌──────▼─────────┐
│  GeminiTransport│ │ AnthropicTransp│ │ OpenAITransport│
│  (MVP)          │ │ (post-MVP)     │ │ (post-MVP)     │
│                 │ │                │ │                 │
│  - Files API    │ │  - document    │ │  - file upload │
│  - inline PDF   │ │    beta block  │ │  - assistants  │
│  - gs:// URIs   │ │  - base64 PDF  │ │  - base64 PDF  │
└─────────────────┘ └────────────────┘ └────────────────┘
```

### 4.2 The provider manifest — declarative capability discovery

Each provider ships a JSON manifest at `framework/llm/providers/<provider>.json`. The framework loads these at startup. This is how the "predefined instructions for special file processing" requirement is met.

```json
{
  "provider_id": "gcp_gemini",
  "display_name": "Google Gemini (via GCP)",
  "transport_class": "framework.llm.providers.gemini.GeminiTransport",
  "environment_checks": {
    "required_env": ["GEMINI_FLASH_API_KEY", "GEMINI_PRO_API_KEY"],
    "optional_env": ["GOOGLE_CLOUD_PROJECT"]
  },
  "models": [
    {
      "model_id": "gemini-2.5-flash",
      "tier": "light",
      "context_window": 1000000,
      "max_output_tokens": 8192,
      "capabilities": [
        "text",
        "multimodal_image",
        "native_pdf",
        "native_html",
        "structured_output",
        "function_calling"
      ],
      "file_handling": {
        "native_pdf": {
          "enabled": true,
          "max_pages": 1000,
          "max_size_mb": 50,
          "ingestion_paths": ["inline_bytes", "files_api", "gs_uri"],
          "preferred_ingestion": "gs_uri"
        },
        "native_html": {
          "enabled": true,
          "ingestion_paths": ["inline_bytes"],
          "preferred_ingestion": "inline_bytes"
        }
      },
      "cost_hints": {
        "input_per_1k_tokens": 0.00030,
        "output_per_1k_tokens": 0.00250,
        "relative_cost": "low"
      },
      "auth": {
        "env_var": "GEMINI_FLASH_API_KEY",
        "header_name": "x-goog-api-key"
      }
    },
    {
      "model_id": "gemini-2.5-pro",
      "tier": "heavy",
      "context_window": 1000000,
      "max_output_tokens": 64000,
      "capabilities": [
        "text", "multimodal_image", "native_pdf", "native_html",
        "structured_output", "function_calling", "deep_reasoning"
      ],
      "file_handling": {
        "native_pdf": {
          "enabled": true,
          "max_pages": 1000,
          "max_size_mb": 50,
          "ingestion_paths": ["inline_bytes", "files_api", "gs_uri"],
          "preferred_ingestion": "gs_uri"
        }
      },
      "cost_hints": {
        "input_per_1k_tokens": 0.00125,
        "output_per_1k_tokens": 0.01000,
        "relative_cost": "high"
      },
      "auth": {
        "env_var": "GEMINI_PRO_API_KEY",
        "header_name": "x-goog-api-key"
      }
    }
  ]
}
```

A user who wants to add Anthropic drops a `framework/llm/providers/anthropic.json` with a matching schema. No code changes.

### 4.3 The plugin's query contract — three methods

The existing `LLMQueryInterface` gets a third method and slightly richer options on the existing two:

```python
@dataclass
class LLMResponse:
    ok: bool
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
    model_used: str | None = None          # which model actually ran
    transport_path: str | None = None      # "gs_uri", "inline_bytes", etc.
    fallback_reason: str | None = None     # if preferred path wasn't used


@dataclass
class QueryHints:
    """Plugin hints to the router about what kind of query this is."""
    tier: str = "light"                    # "light" | "heavy"
    needs_reasoning: bool = False          # biases toward Pro/thinking-enabled
    needs_structured_output: bool = False  # ensures JSON-mode capable model
    prefers_native_file: bool = False      # prefer native file > text extraction
    max_budget_cents: float | None = None  # cost ceiling per call


class LLMQueryInterface(Protocol):

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Text-only query. Router selects model based on hints."""

    def query_with_image(
        self,
        prompt: str,
        image_bytes: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Image + text query. Requires multimodal_image capability."""

    def query_with_document(
        self,
        prompt: str,
        artifact: ArtifactRef,
        system_context: str | None = None,
        max_tokens: int = 8192,
        grounding_data: list[str] | None = None,
        hints: QueryHints | None = None,
    ) -> LLMResponse:
        """Document + text query. Router picks the best ingestion path.

        The router will try, in order:
          1. Native document capability + remote URI (if provider supports it)
          2. Native document capability + inline bytes
          3. Fallback: extract text via framework text_extractors, then query_text

        The response's transport_path field records which path was used.
        """
```

### 4.4 Router selection algorithm

```
def select_binding(hints, query_type, artifact_type=None):
    # 1. Filter providers by environment checks (API keys present)
    available = [p for p in registry.providers if p.env_check_ok()]

    # 2. Filter models by required capabilities
    required_caps = derive_required_caps(query_type, artifact_type, hints)
    candidates = [
        (p, m) for p in available for m in p.models
        if required_caps.issubset(set(m.capabilities))
    ]

    # 3. Filter by tier
    candidates = [(p, m) for (p, m) in candidates if m.tier == hints.tier]

    # 4. Apply budget filter if specified
    if hints.max_budget_cents is not None:
        candidates = [
            (p, m) for (p, m) in candidates
            if estimate_cost(m) <= hints.max_budget_cents
        ]

    # 5. Prefer: deep_reasoning (if needs_reasoning) > larger context > lower cost
    candidates.sort(key=lambda pm: (
        -int(hints.needs_reasoning and "deep_reasoning" in pm[1].capabilities),
        -pm[1].context_window,
        cost_rank(pm[1]),
    ))

    if not candidates:
        return None
    return candidates[0]
```

### 4.5 Ingestion path resolution

When a plugin calls `query_with_document(artifact)`, the transport does:

```
def resolve_ingestion(artifact, model):
    fh = model.file_handling.get(matching_key(artifact.type))
    if not fh or not fh.enabled:
        return None  # caller falls back to text extraction

    # Try paths in preferred order
    for path in ordered_paths(fh):
        if path == "gs_uri":
            uri = resolver.as_remote_uri(artifact, "gcp")
            if uri:
                return IngestionPlan(path="gs_uri", uri=uri)
        elif path == "files_api":
            # Upload to Gemini Files API, get back fresh URI
            bytes_ = resolver.as_local_bytes(artifact)
            return IngestionPlan(path="files_api", bytes_=bytes_)
        elif path == "inline_bytes":
            if artifact.location.size_bytes <= 20 * 1024 * 1024:  # 20MB limit
                return IngestionPlan(
                    path="inline_bytes",
                    bytes_=resolver.as_local_bytes(artifact),
                )
    return None
```

---

## 5. MVP Implementation — GCP / Gemini Only

For the BSides launch, only the Gemini transport needs to exist. The architecture supports others; they can be added post-MVP.

### 5.1 Files to create

```
framework/llm/
├── __init__.py
├── router.py                 # LLMRouter class
├── protocol.py               # LLMQueryInterface, LLMResponse, QueryHints
├── registry.py               # ProviderRegistry, loads JSON manifests
├── resolver.py               # ArtifactResolver (works with existing StorageResolver)
└── providers/
    ├── __init__.py
    ├── base.py               # BaseTransport abstract class
    ├── gemini.py             # GeminiTransport — MVP
    └── gcp_gemini.json       # manifest for GCP-hosted Gemini
```

### 5.2 GeminiTransport implementation sketch

```python
class GeminiTransport(BaseTransport):
    def __init__(self, provider_manifest, resolver):
        from google import genai
        self._client_flash = genai.Client(api_key=os.environ["GEMINI_FLASH_API_KEY"])
        self._client_pro = genai.Client(api_key=os.environ["GEMINI_PRO_API_KEY"])
        self.resolver = resolver

    def query_with_document(self, binding, prompt, artifact, **kwargs):
        client = self._client_for_tier(binding.tier)
        plan = resolve_ingestion(artifact, binding.model)

        if plan is None:
            return LLMResponse(
                ok=False,
                error="No native ingestion path for this artifact type",
                fallback_reason="model_lacks_capability",
            )

        if plan.path == "gs_uri":
            part = types.Part.from_uri(file_uri=plan.uri, mime_type=artifact.mime_type)
        elif plan.path == "inline_bytes":
            part = types.Part.from_bytes(data=plan.bytes_, mime_type=artifact.mime_type)
        elif plan.path == "files_api":
            file = client.files.upload(file=io.BytesIO(plan.bytes_))
            part = types.Part.from_uri(file_uri=file.uri, mime_type=artifact.mime_type)

        response = client.models.generate_content(
            model=binding.model.model_id,
            contents=[part, prompt],
            config=types.GenerateContentConfig(
                system_instruction=kwargs.get("system_context"),
                max_output_tokens=kwargs.get("max_tokens", 8192),
            ),
        )

        return LLMResponse(
            ok=True,
            text=response.text,
            token_usage={"total_tokens": response.usage_metadata.total_token_count},
            model_used=binding.model.model_id,
            transport_path=plan.path,
        )
```

### 5.3 Changes to `shell.py`

Minimal. The `connect` command becomes a `providers` discovery command:

```
eventmill > providers
  Provider          Status        Models available              Caps
  gcp_gemini        ✓ ready       gemini-2.5-flash (light)      text, multimodal_image, native_pdf, native_html
                                  gemini-2.5-pro (heavy)         text, multimodal_image, native_pdf, native_html, deep_reasoning

eventmill > connect
  ✓ Loaded provider gcp_gemini (2 models, native PDF support)
```

The `llm_client` attribute becomes `llm_router`. The `ExecutionContext` is built with `llm_router` (which exposes the `LLMQueryInterface` methods). No other command changes.

### 5.4 Plugin-side changes for threat_intel_ingester

The ingester's LLM refinement becomes a single call:

```python
if context.llm_enabled and artifact.artifact_type == "pdf_report":
    response = context.llm_query.query_with_document(
        prompt=LLM_REFINEMENT_PROMPT.format(source_context=source_context),
        artifact=artifact,
        system_context="You are a threat intelligence analyst. Respond only with valid JSON.",
        max_tokens=8192,
        hints=QueryHints(
            tier="heavy",               # use Pro for full-document reasoning
            needs_reasoning=True,       # attack graph inference benefits from thinking
            needs_structured_output=True,
            prefers_native_file=True,
        ),
    )
    # Parse the JSON response as before
```

The chunking code is deleted. `pdfplumber` extraction is kept only for the regex IOC baseline, which runs once per document. The 971-line tool drops to approximately 500 lines.

---

## 6. User Configuration

The user declares their cloud vendor and models once, via environment variables referenced in the provider manifest. For GCP:

```bash
# ~/.eventmill/deploy.env
export EVENTMILL_LLM_PROVIDERS="gcp_gemini"
export GEMINI_FLASH_API_KEY="..."
export GEMINI_PRO_API_KEY="..."
export GOOGLE_CLOUD_PROJECT="my-project"
```

For a future multi-provider setup:

```bash
export EVENTMILL_LLM_PROVIDERS="gcp_gemini,anthropic"
export GEMINI_FLASH_API_KEY="..."
export GEMINI_PRO_API_KEY="..."
export ANTHROPIC_API_KEY="..."
```

The provider registry loads the named providers in order; the router considers all their models when selecting bindings. This means a user can run Gemini Flash for cheap light-tier calls and Claude Opus for heavy reasoning in the same investigation.

---

## 7. What This Changes in the Gap Analysis

This design adds three items to the punch list:

1. **Framework extension — `LLMRouter` and provider manifests**: 3–4 days of work. Gates any plugin that benefits from native file handling.
2. **Artifact model extension — `ArtifactLocation`**: 1 day. Backward-compatible database migration.
3. **Threat intel ingester rewrite — use `query_with_document`**: 1 day. Framework change must land first.

The total is a week of work. It's a significant refactor but it's the right architectural moment — before more plugins are written against the current interface. Every plugin written today would need the same treatment later, which is more expensive than doing this once now.

For the BSides scope recommendation, this confirms the earlier call that plugin work is the bottleneck. Six plugins at two days each is roughly the remaining time. Adding this LLM refactor up front means every plugin gets the native-file path for free.

---

## 8. Non-Goals (explicit)

- Not building a cost-optimization system. `max_budget_cents` is a safety net, not a minimizer.
- Not building automatic failover between providers. If the selected binding fails, the call fails; the plugin decides what to do.
- Not implementing streaming responses. One-shot responses only for MVP.
- Not implementing multi-file prompts (PDF + image + text in one call). Single-artifact prompts only for MVP.
- Not building a web UI for provider management. Config files and the `providers` command are sufficient.

---

## 9. Open Questions for Review

1. **Naming**: `LLMRouter` vs `ModelRouter` vs `LLMOrchestrator`? The framework already has a plugin `Router` — worth disambiguating.
2. **Binding cache lifetime**: Should bindings be recomputed on every call (fresh availability check) or cached for the session? Current sketch recomputes per call; this is safer but slightly slower.
3. **Plugin manifest field**: Should the plugin manifest declare required LLM capabilities explicitly (e.g., `llm_requires: ["native_pdf", "structured_output"]`)? This would let the router reject unsupported bindings at plugin load time rather than at execute time.
4. **Graceful degradation UX**: When a plugin asks for `prefers_native_file=True` but the only available provider doesn't support native PDF, should the framework silently fall back to text extraction, or surface this to the user? My preference is silent fallback with `fallback_reason` reported in the response — the plugin logs it but doesn't fail.
