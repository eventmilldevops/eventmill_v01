# Event Mill — Design Review of Updated Specs

**Date**: April 17, 2026
**Scope**: `eventmill_v1_1.md` (grounding), `framework_architecture.md`, `tool_plugin_spec.md`, `router_design.md`, `manifest_schema.json`, `llm-dispatcher-native-document-handling.md`, and the `threat_intel_ingester` manifest
**Context**: MVP is GCP-only. Three pillars fleshed out. Multi-cloud deferred. Goal is a working first release, not code optimization.

---

## Summary

The dispatcher design is a clean response to the native-PDF problem and should ship. The bigger risk to MVP is not the dispatcher design itself — it's the **documentation and spec drift around it**. Three specs (grounding doc, architecture doc, plugin spec) still describe an LLM integration architecture that doesn't match what the code is building. One bug in the dispatcher ("transparent fallback" that isn't actually transparent) will produce confusing plugin code. Two omissions from Phase 1 (response_schema enforcement, MIME type handling) will reproduce the same class of failure the dispatcher was built to fix.

Problems are grouped by severity. Red = blocks MVP working end-to-end. Yellow = creates confusion and will need fixing before external contributors arrive. Green = noted for completeness, post-MVP.

---

## RED — Blocks MVP

### R1. Grounding doc and architecture doc misrepresent MCP

**Where**: `eventmill_v1_1.md` section 5 ("LLM Integration via MCP") and `framework_architecture.md` section 5.4 ("MCP Message Flow").

**What they say**: Event Mill uses the Model Context Protocol (MCP) as its LLM integration layer to provide model interchangeability between Gemini, Claude, GPT, and other providers. Environment variables are `EVENTMILL_MCP_TRANSPORT` / `EVENTMILL_MCP_ENDPOINT` / `EVENTMILL_MODEL_ID`. Configuration is via an MCP client connected by stdio or SSE.

**What is actually true in 2026**: MCP is a tool-calling protocol, not a model-abstraction protocol. Per current Google AI documentation, "Model Context Protocol (MCP) is an open standard for connecting AI applications with external tools and data. MCP provides a common protocol for models to access context, such as functions (tools), data sources (resources), or predefined prompts. The Gemini SDKs have built-in support for the MCP, reducing boilerplate code and offering automatic tool calling for MCP tools." (https://ai.google.dev/gemini-api/docs/function-calling, updated 2026-04-08)

MCP is the way a model talks **out** to tools and data sources. It is not the way Event Mill talks **to** the model. Every current implementation — including the one in `shell.py` that imports `google.genai` directly — reaches the model via the provider's native SDK. Claude models go via the Anthropic Messages API. Gemini models go via `google.genai`. MCP doesn't sit between them.

**Why this matters for MVP**: The dispatcher design document correctly doesn't mention MCP — it imports `google.genai` directly. This is the right code. But contributors reading the grounding doc will try to build or configure an MCP client to route LLM calls. There is no such thing. The grounding doc's entire section 5 is misinformed.

**Fix**: Replace "LLM Integration via MCP" with "LLM Integration via Provider SDK". Remove `EVENTMILL_MCP_TRANSPORT` / `EVENTMILL_MCP_ENDPOINT` from the configuration table; replace with `EVENTMILL_LLM_PROVIDER=gcp_gemini`, `GEMINI_FLASH_API_KEY`, `GEMINI_PRO_API_KEY` — which match what the code actually reads. In `framework_architecture.md` section 5.4, relabel "MCP Message Construction" as "Prompt Assembly" and "MCP Transport" as "Provider SDK Transport" (google.genai, anthropic, etc.). Keep the three-source grounding model diagram — that part is correct and valuable.

MCP **will** eventually matter for Event Mill, but not here. It belongs in the Roadmap document as "post-MVP: expose Event Mill plugins as an MCP server so agents like Shannon can invoke them as tools" — which is the use case that motivated CTF planning in the first place.

---

### R2. `tool_plugin_spec.md` is not updated for the new dispatcher interface

**Where**: `tool_plugin_spec.md` lines 283–291 (ArtifactRef definition) and lines 301–340 (LLMQueryInterface protocol).

**What it shows**:
```python
@dataclass
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    file_path: str          # Four fields. No storage_uri. No mime_type.
    source_tool: str | None
    metadata: dict

class LLMQueryInterface(Protocol):
    def query_text(...) -> LLMResponse: ...
    def query_multimodal(...) -> LLMResponse: ...
    # No query_with_document. No supports_native_document.
    # No QueryHints in query_text signature.
```

**Why this matters for MVP**: The tool plugin spec is the **normative** contract for plugin development. A contributor writing a new plugin will read this spec, see only `query_text` and `query_multimodal`, and not use the dispatcher's document path. Every plugin written from now until the spec is updated will reimplement the chunking failure the dispatcher was built to eliminate.

**Fix**: Pull the ArtifactRef, LLMQueryInterface, QueryHints, and LLMResponse definitions from `llm-dispatcher-native-document-handling.md` section 4 and 5 into `tool_plugin_spec.md`. The dispatcher doc should become a companion implementation spec; the plugin spec should be authoritative for anyone writing plugins. Bump `tool_plugin_spec.md` to version 0.3.0 to signal the contract change.

---

### R3. `manifest_schema.json` rejects the threat_intel_ingester's own manifest

**Where**: `manifest_schema.json` (full file) vs `manifest.json` line 38.

**What's wrong**: The ingester manifest declares `"model_tier": "light"`. The manifest schema has no `model_tier` property and sets `additionalProperties: false`. Running manifest validation against schema will reject this manifest with an "additional property not allowed" error.

**Why this matters for MVP**: The framework has a `scripts/validate_manifests.py` script. If that script runs against the current manifests, it will fail on the reference plugin. If the script is not running in CI (which the gap analysis flagged), contributors will add plugins with schema-invalid manifests undetected — and the loader will silently ignore fields it doesn't understand, producing runtime behavior that doesn't match the declared contract.

**Fix**: Add `model_tier` to `manifest_schema.json` as an enum of `["light", "heavy"]`. While editing, also add the LLM capability declaration the dispatcher design's open question #2 in section 15 flagged:

```json
"llm_requires": {
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "tier": { "enum": ["light", "heavy"] },
    "needs_reasoning": { "type": "boolean" },
    "needs_structured_output": { "type": "boolean" },
    "prefers_native_file": { "type": "boolean" },
    "native_document_types": {
      "type": "array",
      "items": { "type": "string" },
      "description": "MIME types the plugin prefers to pass natively (e.g., application/pdf)."
    }
  }
}
```

The dispatcher design defers this to Phase 3. That's wrong for MVP. Without it, a plugin that needs native PDF has no way to declare that fact, and the router cannot warn when the active provider doesn't satisfy the requirement. Users will see the failure only at execute time, exactly like today. The fix is a schema addition plus five lines in the loader — not Phase 3 work.

---

### R4. `response_schema` enforcement deferred, but it's the actual fix for parse failures

**Where**: `llm-dispatcher-native-document-handling.md` section 15, open question #1.

**What it says**: "`needs_structured_output` + Gemini `response_schema`: Should Phase 1 include wiring `response_schema` into the backend when the hint is set? This would eliminate JSON parse failures entirely. Low effort, high impact."

**Why this matters for MVP**: This is the only open question in the design doc, and it's flagged as "low effort, high impact." It also happens to be **the actual root cause of the current failure**. The ingester's 43-chunk failure mode is fundamentally JSON parse failures from Gemini. Native PDF handling reduces the count from 43 calls to 1. `response_schema` changes the remaining call from "LLM may or may not return parseable JSON" to "Gemini is forced by the SDK to produce valid JSON matching the schema."

Google's documentation is explicit: https://ai.google.dev/gemini-api/docs/structured-output — you pass a `response_schema` and the model output is guaranteed to conform. No prompt engineering for "please respond in JSON format." No code-fence stripping. No `json.JSONDecodeError` handling.

The design pretends these two fixes (native PDF + structured output) are independent. They are not. Shipping native PDF without `response_schema` means the remaining single call can still return malformed JSON, the plugin falls back to regex, and the attack graph is empty again. Shipping `response_schema` without native PDF means 43 chunks still happen but each one returns valid JSON — still fails because cross-chunk context is destroyed.

**Fix**: Promote open question #1 from "consider for Phase 1" to "Phase 1 requirement". The implementation is about 20 lines. Define a `response_schema` field on the backend call, wire it through when `hints.needs_structured_output` is True, and thread the schema definition from the plugin through the dispatcher. The threat intel ingester then declares its output schema once and passes it with the hint.

Prompt engineering changes come with this — the ingester's current prompt has "Respond ONLY with a JSON object in this exact format:" as a long block. With `response_schema` active, that block becomes noise and the model's behavior is controlled by the schema. Coordinated change needed across prompt and dispatcher.

---

### R5. "Transparent fallback" is not actually transparent

**Where**: `llm-dispatcher-native-document-handling.md` section 2 principle 6 vs section 9.2 implementation vs section 10 plugin code.

**What the principle says**: "If native PDF isn't available, fall back to text extraction silently. The `LLMResponse` reports what path was used via `transport_path` and `fallback_reason` for diagnostics."

**What the implementation does** (section 9.2):
```python
if mime_type in caps.native_document_types:
    # Native path
    return backend.query_with_documents(...)
else:
    return LLMResponse(
        ok=False,
        error="Native document processing not available for this MIME type",
        fallback_reason=f"model {backend.model_id} lacks native_{mime_type}",
    )
```

This is **not a fallback**. This is a hard failure with diagnostic text. The plugin gets `ok=False`. There is no text extraction path in the dispatcher. The plugin has to implement it.

**What the plugin example does** (section 10):
```python
if context.llm_query.supports_native_document("application/pdf"):
    response = context.llm_query.query_with_document(...)
    ...
else:
    # Existing chunk-based approach for non-Gemini providers
    ...
```

So every plugin that wants fallback has to do its own capability check and maintain two code paths. The abstraction has failed — the plugin is still provider-aware.

**Why this matters for MVP**: For MVP this is a minor issue since only Gemini is implemented. But it means every future plugin will copy this branching pattern, and when the second provider lands, removing the duplication will be a painful refactor. The dispatcher should own the fallback, not the plugin.

**Fix**: Either (a) implement genuine fallback in the dispatcher — when the selected backend doesn't support native for this MIME type, extract text via framework-provided extractors and call `query_text()` with the extracted text, OR (b) change the principle. State honestly that the plugin is responsible for fallback and the dispatcher only handles native paths. Document the `supports_native_document()` check as the required pattern.

My recommendation is (a) — the framework already has `extract_text_from_pdf`, `extract_text_from_html`, and `extract_text_from_docx` helpers sitting in the ingester. Move them to `framework/llm/text_extractors.py` and have the dispatcher call them on fallback. The plugin then calls `query_with_document` unconditionally and the dispatcher picks the best available path. That's actually transparent.

---

### R6. MIME type defaults to PDF for every artifact

**Where**: `llm-dispatcher-native-document-handling.md` section 9.2 line ~501.

```python
mime_type = artifact.metadata.get("mime_type", "application/pdf")
```

**What's wrong**: If the ArtifactRef's metadata dict doesn't contain a `mime_type` key (which is the default — the `ArtifactRef` dataclass has no dedicated MIME field), every artifact is treated as a PDF. An HTML report, a JSON file, a CSV — all will attempt the native-PDF path. Gemini will either error or produce nonsense trying to read text as a PDF.

**Why this matters for MVP**: Silent data corruption. The plugin thinks it's getting native HTML processing but is getting treated as PDF.

**Fix**: Promote `mime_type` from metadata to a first-class field on `ArtifactRef` (and `Artifact`). Detect it at load time from the file extension using the existing `_infer_artifact_type` mapping in `shell.py` line 1254. Then change the dispatcher to `mime_type = artifact.mime_type` with no default. If the artifact has no MIME type, raise — don't guess.

```python
@dataclass
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    file_path: str
    storage_uri: str | None = None
    mime_type: str | None = None           # NEW — required for LLM routing
    source_tool: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
```

SQLite migration is another nullable column, same pattern as `storage_uri`.

---

## YELLOW — Fix before external contributors

### Y1. Backend registry granularity doesn't support mixed-provider tiers

**Where**: `llm-dispatcher-native-document-handling.md` section 12.

```python
BACKEND_REGISTRY: dict[str, type] = {
    "gcp_gemini": GeminiBackend,
}
```

This registry keys on provider. The provider manifest keys on tier (light/heavy). So a single provider owns both tiers. Legitimate post-MVP configurations break this:

- Flash for light, Claude Opus for heavy (cost-optimize bulk calls, use strongest model for reasoning)
- Gemini for light, Azure OpenAI for heavy (enterprise compliance for sensitive reasoning workloads)
- Local Llama for light, Gemini for heavy (privacy-first with escalation)

**For MVP**: Single-provider is fine. Flag this so the refactor is expected.

**Fix (post-MVP)**: Key the registry by `provider_id:tier` or by individual model binding. Allow `EVENTMILL_LLM_PROVIDERS=gcp_gemini:light,anthropic:heavy` as config syntax.

---

### Y2. `storage_uri` coexistence with `file_path` has no freshness rule

**Where**: `llm-dispatcher-native-document-handling.md` section 4.1.

"`file_path` remains the primary field. `storage_uri` is populated when the artifact lives in cloud storage. Both can coexist — `file_path` is the local cache, `storage_uri` is the canonical cloud location."

**What's missing**: If a tool writes a new version to `storage_uri` (e.g., an updated threat report pushed to the bucket), there is no mechanism to invalidate the local cache. The next plugin that reads `file_path` gets stale content. The plugin doing a `query_with_document` sees the new content (via `gs://`). Two plugins in the same session get different answers.

**For MVP**: User workflow is "upload once, analyze immediately." Race is unlikely.

**Fix (post-MVP)**: Add `content_hash` field to Artifact. Set at upload/download time. Framework checks hash before using local cache; re-download on mismatch.

---

### Y3. Media resolution parameter unhandled for PDF ingestion

**Where**: Not in any document.

**Gap**: Gemini 3 introduced granular control over PDF tokenization via the `media_resolution` parameter (low/medium/high). See https://ai.google.dev/gemini-api/docs/media-resolution. A dense CrowdStrike report with small fonts and multi-column layouts may need `high` to read correctly. Default resolution may miss content and produce incomplete extractions — which looks just like the failure mode the design is trying to fix.

**For MVP**: Gemini 2.5 is the target. This parameter is a Gemini 3 feature. Not immediately blocking.

**Fix (post-MVP)**: Add `media_resolution` to the provider manifest's `file_handling` block. Add a QueryHint or detect from artifact size. Default `medium` for PDFs, `high` for dense reports the user flags.

---

### Y4. Ingester loses the regex pre-pass under lazy download

**Where**: `llm-dispatcher-native-document-handling.md` section 15 open question #3.

**What it proposes**: "Should Phase 2 skip the GCS download entirely when the provider can read `gs://` URIs?"

**The conflict**: The ingester's regex baseline (`extract_iocs_regex`) runs on local bytes from `pdfplumber`. If the PDF isn't downloaded, the regex pass can't run. The regex pass is what provides the "fallback to regex-only if LLM fails" safety net.

Either (a) always download for local-regex, (b) drop the regex pass entirely (trust native LLM for all IOCs), or (c) run regex on a text extraction of the first-N pages only, downloaded on demand.

**For MVP**: Option (b) — drop the regex pre-pass. Native Gemini PDF reading identifies IOCs better than regex, and the defanging patterns can move into a post-LLM normalization step. This also simplifies the code.

---

### Y5. `document_strategies` manifest block is documented but unused

**Where**: `llm-dispatcher-native-document-handling.md` section 6 provider manifest.

```json
"document_strategies": {
    "application/pdf": "native",
    "application/json": "extract_text",
    "text/csv": "extract_text",
    "text/plain": "extract_text",
    "text/html": "extract_text",
    "default": "extract_and_chunk"
}
```

**What's wrong**: Nothing in the dispatcher code reads this block. The strategy decision in section 9.2 is based on `caps.native_document_types` — not on `document_strategies`. The two declaration mechanisms overlap and contradict.

**For MVP**: Delete `document_strategies` from the manifest. Let `native_document_types` be the single source of truth. If a MIME type is in that list, go native. Otherwise, extract text (per R5 fix above) and call `query_text`.

---

### Y6. Router doc doesn't know about `llm_requires`

**Where**: `router_design.md` scoring formula.

The scoring formula at the top of the router design doesn't include LLM capability matching. If plugin A declares `llm_requires.native_document_types: ["application/pdf"]` and the active provider lacks native PDF, the router should either skip the plugin or flag it with a warning. Currently, the router doesn't see LLM requirements at all.

**For MVP**: Low priority — only one plugin currently needs this.

**Fix (post-MVP)**: Add `llm_capability_match` factor to the scoring formula. Weight: -100 if provider doesn't satisfy the plugin's requires. This makes the plugin effectively invisible when the provider can't support it.

---

## GREEN — Noted for completeness

### G1. Roadmap should add "Event Mill as MCP server"

Shannon and similar autonomous pentesters use MCP to call tools. Exposing Event Mill's plugins as an MCP server makes them directly consumable by these agents during the CTF — participants running Shannon can call `pcap_metadata_summary` or `threat_intel_ingester` as MCP tools without knowing Event Mill exists. This is a compelling BSides demo story (autonomous red team vs Event Mill-augmented blue team) and the protocol-level work is modest since the framework already has a plugin invocation model.

### G2. Cost tracking deferred is correct

`max_budget_cents` in QueryHints is a safety net. Full cost tracking is post-MVP. The provider manifest's decision to use relative `cost_tier` instead of absolute prices per 1k tokens is right — absolute prices go stale in weeks and the relative tier tracks the routing decision correctly.

### G3. Streaming responses deferred is correct

One-shot calls serve the MVP use cases. Streaming adds real complexity (error handling mid-stream, token accounting, partial-result rendering). Post-MVP.

### G4. Multi-document prompts deferred is correct

Single artifact per call is enough for MVP. When you need "compare this PCAP to this threat report," that's a new plugin that takes both as inputs and makes sequential LLM calls internally — not a framework extension.

---

## Recommended Fix Order (before writing more plugin code)

1. **R1, R2** — Documentation fixes. One hour each. Update grounding doc's MCP section, update plugin spec's protocol definitions.
2. **R3** — Add `model_tier` and `llm_requires` to manifest schema. Fifteen minutes.
3. **R6** — Add `mime_type` to ArtifactRef and Artifact, detect at load time. One hour.
4. **R4** — Wire `response_schema` into the Gemini backend when `needs_structured_output` is True. Two hours.
5. **R5** — Decide on transparent fallback policy. If (a) implement fallback in dispatcher. If (b) document the pattern in plugin spec. Two hours either way.
6. **Y4 (option b)** — Delete the ingester's regex pre-pass. Add a post-LLM normalization for defanging. Ninety minutes.

Total: about a day of work. After that the threat intel ingester can be rewritten cleanly against a coherent spec, and subsequent plugins (PCAP metadata summary, event source profiler, etc.) can be written correctly the first time.

The framework and the dispatcher design are in good shape. The remaining work is a cleanup pass to make the specs match the code and to close the three concrete holes (R4, R5, R6) before they bite a second plugin.

---

## References

- Gemini API Document Understanding (updated 2026-03-25): https://ai.google.dev/gemini-api/docs/document-processing
- Gemini API Function Calling and MCP (updated 2026-04-08): https://ai.google.dev/gemini-api/docs/function-calling
- Gemini API Structured Output: https://ai.google.dev/gemini-api/docs/structured-output
- Gemini API Media Resolution: https://ai.google.dev/gemini-api/docs/media-resolution
- Google Cloud MCP support announcement (2025-12-11): https://www.hpcwire.com/bigdatawire/this-just-in/google-cloud-announces-model-context-protocol-support-for-google-services/
- "Why MCP Won" — The New Stack (2026-03-14): https://thenewstack.io/why-the-model-context-protocol-won/
