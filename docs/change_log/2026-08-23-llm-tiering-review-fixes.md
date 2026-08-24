# 2026-08-23 — LLM tiering review fixes

Follow-up to `2026-08-22-manifest-driven-model-tier-routing.md` and
`2026-08-22-gemini-3x-capacity-correction-and-log-sampling.md`, both on the
`llm-tiering-gemini-3x` branch. A review of the branch found guards that could not
fire, a source-of-truth fix that landed on unreachable code, and a default that let
a partial `QueryHints` silently outrank a plugin's manifest. Nothing here was
released; this closes the branch's own gaps before merge.

The organising decision: **plugin manifests drive model selection.** Output size
does not, the analyst's pinned tier is respected, and a tier the caller did not ask
for is never inferred.

---

## Routing

**`QueryHints.tier` now defaults to `None`, not `"light"`.** `TierScopedLLMClient`
injected the manifest tier only when `hints is None`, and `_route()` treated any
non-`None` hints object as an explicit tier choice. A heavy-tier plugin writing
`QueryHints(thinking_level="low")` — saying nothing about tier — was routed to light,
and the analyst's pinned `connect` tier was overridden the same way. `None` means "no
opinion": `_with_default()` now fills in only the tier field via `replace()`, and
`_route()` falls through to the pinned tier or the light default.

No plugin was hitting this — all six call sites set `tier=` explicitly — but the
capacity-correction change added two tier-irrelevant hint fields, which is exactly
what makes a partial `QueryHints` natural to write.

**The `max_tokens > 3500` heuristic is removed.** Its justification was a capacity
gap that no longer exists; both tiers are capacity-identical, so selecting a tier by
output size was choosing cost at random. Framework callers with no preference now get
light. `LLMDispatcher.LIGHT_THRESHOLD` is gone.

**`needs_reasoning=True` still prefers heavy and still implies `high` thinking**, and
still falls back to light when heavy is not connected — the `ask:` shell path and
`threat_report_analyzer`'s synthesis pass both depend on that. The earlier change log
claimed no call site changed behaviour; it has been corrected.

## Both tiers connect by default

A single-model `connect <model_id>` used to leave `self.llm_client` as a bare
`MCPLLMClient` whenever the other tier failed to bind. That client skips token
clamping, the PDF context guard, the retired-model retry, and native document handling
entirely — `query_with_document` returned `ok=False` for every native-PDF request, so
`threat_report_analyzer` and `threat_intel_ingester` silently degraded to text
extraction. It is now always wrapped in `LLMDispatcher`.

A legacy single `GEMINI_API_KEY` now binds **both** tiers rather than light only. One
key reaches both models, so plugin manifests keep driving selection instead of every
tool collapsing onto Flash. The stale `gemini-2.5-flash` literal in that fallback path
is now `gemini-3.5-flash`.

## Guards that could not fire

**PDF page count is recorded at artifact registration** (`shell.py::_artifact_metadata`).
`_pdf_page_count()` read only artifact metadata or a local `PdfReader`, and nothing
populated the metadata — so on Cloud Run, where the preferred ingestion path is a
`gs://` URI and there is no local file, the context-overflow guard was a no-op and the
request failed at the provider with the opaque error the guard exists to prevent. Size
is recorded alongside it, and a page count that still cannot be determined now logs at
`warning` rather than `debug`.

**The 50 MB limit is enforced.** `max_size_mb` was read from the manifest and
interpolated into the page-limit error message, but never compared against anything.

**`pypdf` moved from the `plugins-threat-modeling` extra to base dependencies.** It is
framework code now. Containers install `.[all]` and were unaffected, but a plain
`pip install -e .` raised `ImportError` into a bare `except`, disabling the guard with
only a debug log.

## Single source of truth

`_model_supports_native_doc()` and `supports_native_document()` hardcoded
`application/pdf` while `_prefer_native_capable()` read `native_pdf` from the provider
manifest. Dropping `native_pdf` from a tier demoted it in the routing order and then
waved the PDF through to it anyway. Both now consult the manifest.

**`_clamp_tokens()` clamps to the model that actually runs**, not to the tier it is
registered under. `EVENTMILL_MODEL_LIGHT` / `_HEAVY` override a tier's model id but not
its cap, so pinning light at `gemini-2.5-flash` (8,192) still clamped against 65,536 and
failed at the provider. Caps are now keyed by model id, `EVENTMILL_MAX_OUTPUT_LIGHT` /
`_HEAVY` set a substitute's cap explicitly, and an override without one logs a warning.

**Retired-model retry covers all three query paths.** It existed only on `query_text`,
while `query_with_document` is the path that defaults to the heavy tier — the Preview
endpoint most likely to be retired. Token accounting also survives a substitution now;
the substitute previously started at zero, undercounting session spend.

## Dead code removed

- `framework/llm/backends/gemini.py` — `GeminiBackend` was never instantiated.
  `LLMDispatcher` holds `MCPLLMClient` instances and has no backend registry.
- `LLMBackend`, `ModelCapabilities`, `BACKEND_REGISTRY`. `backends/base.py` keeps
  `DocumentPart`, its only live export.
- `providers.max_output_tokens_for_tier()` — exported, zero callers, duplicate clamp
  logic that would have drifted from `_clamp_tokens()`.
- `TieredLLMClient`, the compatibility alias for `LLMDispatcher`.

`load_provider_manifest()` is now `lru_cache`d — the PDF guard alone re-read and
re-parsed the file five to seven times per call.

## Plugin tiers

Seven plugins that make no LLM calls at all moved from `model_tier: "light"` to
`"none"`, matching `firewall_log_aggregator`: `log_navigator`, `log_searcher`,
`pcap_flow_analyzer`, `pcap_ip_search`, `pcap_metadata_summary`, `pcap_threat_hunter`,
`attack_path_visualizer`. Declaring `light` handed them an `llm_query` they never used
and reported `llm_enabled=True`, which made the field unreliable for auditing LLM
exposure.

`pcap_report_correlator` was missed in the `thinking_level` pass — its IOC extraction is
the same pattern-matching shape as the two sites that got `thinking_level="low"`, and
under 3.x the provider default is `medium`. It now asks for `low`.

`pcap_ai_analyzer`'s comment claimed `max_tokens` was clamped to the tier cap; at 16,384
against 65,536 nothing clamps. Corrected.

Deliberately unchanged: `log_investigator` stays on heavy with its 500-line / 400k-char
sample. Security events are rare against benign volume, so the head/tail/sampled-middle
approach needs the width, and the reasoning the prompt asks for needs the tier.
`log_pattern_analyzer` stays on light — first-pass aggregation over large volumes is
pattern matching, and it only ran on Pro before because 4,096 tripped the old heuristic.

## Second review pass

A follow-up review of the branch found four more, all fixed here:

- **`_is_model_not_found()` matched a bare `404` anywhere in the message.**
  `_retry_on_retired_model()` reacts by permanently rewriting `self._clients[tier]`,
  so a request id or an echoed log line containing `404` inside an unrelated
  `INVALID_ARGUMENT` would demote the heavy tier to Flash for the rest of the
  session. The match is now anchored to status position.
- **`_pdf_context_overflow()` sized against the tier's context window, not the
  running model's.** `_clamp_tokens()` was re-keyed by model id precisely because
  `EVENTMILL_MODEL_*` changes the model without changing the tier; the context
  guard had not been. New `_context_cap()` mirrors `_output_cap()`.
- **A legacy key binding both tiers can lack Pro entitlement.** That returns
  `PERMISSION_DENIED`, which is neither a quota error nor a retired model id, so
  neither fallback fired and the five heavy-tier plugins hard-failed on a key that
  could still serve them from light. New `_is_access_error()` folds it into the
  cross-tier fallback. `_discover_models()`'s docstring, which still described the
  old light-only binding, is corrected.
- **The dispatcher's `tier="heavy"` default for native documents is unreachable
  from a plugin** — every plugin call arrives through `TierScopedLLMClient` with a
  tier already set. The default applies only to direct framework callers; the
  comment claiming otherwise is corrected. Behaviour unchanged.

## Tests

`tests/framework/test_llm_dispatcher.py`: 47 → 63. New coverage for the tier-`None`
contract, partial hints preserving the manifest tier and their other fields, size-blind
routing, clamping by model id, retired-model retry on the multimodal and document paths,
manifest-driven native document capability, the PDF size limit, and page count from
metadata for an artifact with no local file.

Also covered: a 404 outside status position, cross-tier fallback on
`PERMISSION_DENIED`, and the context guard following the running model.

Full suite: 392 passed.
