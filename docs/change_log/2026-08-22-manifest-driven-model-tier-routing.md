# Change Log — Manifest-Driven Model Tier Routing

**Date:** 2026-08-22
**Scope:** `framework/llm/`, `framework/plugins/`, `framework/cli/shell.py`, plugin manifests, specs

---

> **Superseded in part (2026-08-23).** `QueryHints.tier` now defaults to `None`
> rather than `"light"`, so hints that set no tier keep the manifest default; the
> `max_tokens > 3500` heuristic has been removed in favour of a plain `light`
> default; and `_clamp_tokens()` clamps to the cap of the model that actually
> runs rather than the tier's. See
> `2026-08-23-llm-tiering-review-fixes.md`.

## Summary

`model_tier` was declared in all 16 plugin manifests but read by nothing. Tier selection
was effectively decided by a `max_tokens > 3500` heuristic in `LLMDispatcher._route()`, so
which model ran was a side effect of an output-token guess rather than a stated intent.

The manifest's `model_tier` is now the authoritative default for a plugin's LLM calls,
overridable per call with `QueryHints`. The token heuristic is demoted to a last resort for
framework-level callers.

**Precedence:** per-call `QueryHints` > manifest `model_tier` > `max_tokens` heuristic.

---

## Changes

### `docs/specs/manifest_schema.json`

- **Added `model_tier`** (`light` | `heavy` | `none`, default `light`). The schema has
  `additionalProperties: false`, so its absence meant **all 16 manifests failed validation**.
- **Widened `timeout_class`** to include `short` and `long`. The runtime has accepted these
  as aliases for `fast`/`slow` since `TimeoutClass.LIMITS` was written; the schema had drifted.

### `framework/plugins/loader.py`

- `PluginManifest` now parses `model_tier`, defaulting to `light`.

### `framework/plugins/protocol.py`

- `ExecutionContext` gains `model_tier` — informational; the tier is already applied to
  `llm_query`.
- `LLMQueryInterface.query_multimodal()` gains a `hints` parameter, for parity with
  `query_text()`.

### `framework/llm/providers/__init__.py` — now a real module

The `gcp_gemini.json` capability manifest existed but was never loaded. It now backs both
model discovery and token clamping:

- **`load_tier_specs()`** resolves each tier to a `TierSpec` (model id, API-key env var,
  output/context caps, cost tier, capabilities).
- Honours `EVENTMILL_MODEL_LIGHT` / `EVENTMILL_MODEL_HEAVY` as per-tier model-id overrides.
  These were documented in `.env.example` but read by nothing.
- Returns empty / falls back rather than raising when the manifest is missing.

### `framework/llm/client.py`

- **Added `TierScopedLLMClient`** — wraps the shared dispatcher per plugin execution and
  fills in `QueryHints(tier=<manifest tier>)` whenever the plugin passes none. This is the
  single place the manifest default is applied; `LLMDispatcher` stays plugin-agnostic and no
  existing plugin call site had to change.
- **`_route()`**: the pinned-tier branch now guards against non-tier keys; when nothing in
  the preferred order is connected it accepts any connected client instead of raising.
- **Added `_clamp_tokens()`** — clamps `max_tokens` to the selected tier's declared output
  cap. `pcap_ai_analyzer` requests 16384, which Gemini Flash (8192) cannot emit; on a quota
  fallback that call previously became a provider error. (That rationale expired later the
  same day: the capacity correction put light at 65,536, so the clamp no longer fires
  against the real manifest. It still guards `EVENTMILL_MODEL_*` overrides and
  retired-model substitutions.)
- **Added `_prefer_native_capable()`** — the long-unused `document_mime` parameter now
  demotes tiers whose provider manifest lacks native support for the MIME type.
- `MCPLLMClient.query_text()` / `query_multimodal()` accept and ignore `hints`, so
  single-model mode satisfies the same interface.
- `_fallback_client()` logs the tier change, not just the model id.

### `framework/cli/shell.py`

- **Model discovery is now declarative** — `_discover_models()` builds the available-model
  list from the provider manifest instead of hardcoded ids and env var names.
- **Legacy `GEMINI_API_KEY` now binds to the `light` tier.** It previously registered under
  `tier: "default"`, which `_route()` never looks up — bare `connect` produced a dispatcher
  that reported `connected == True` and raised `"No LLM client connected"` on every query.
- **Removed the `ANTHROPIC_API_KEY` model entry.** It advertised `claude-sonnet-4` under
  `tier: "heavy"`, but `MCPLLMClient` is Gemini-only; it could displace Gemini Pro in the
  tier dict. Multi-provider remains an explicit non-goal.
- `ExecutionContext` construction wraps `llm_query` in `TierScopedLLMClient`.
  `model_tier: "none"` now yields `llm_query=None` / `llm_enabled=False`.
- `ask:` passes `QueryHints(tier="heavy", needs_reasoning=True)` explicitly.
- `models` / `connect` output describes manifest-driven routing rather than the threshold.

### Plugins

- **`threat_report_analyzer`** — per-chunk summarization pinned to `light`, synthesis pinned
  to `heavy`. Chunk tier previously flipped with `out_tokens` (3072 → light, ≥3584 → heavy),
  so the model varied per chunk within a single run.
- **`log_pattern_analyzer`** — declared `light`, ran `heavy` (`max_tokens=4096`). Now follows
  its manifest; comment added.
- **`pcap_ai_analyzer`** — comment noting the tier comes from the manifest and `max_tokens`
  is clamped. No import added; this plugin deliberately imports nothing from the framework.

### Tests

- **New `tests/framework/test_llm_dispatcher.py`** (22 tests) covering precedence, manifest
  tier application, override, clamping, cross-tier quota fallback, and degraded setups
  (single client, legacy key, nothing connected).
- `tests/framework/test_plugins.py` asserts `model_tier` parses, defaults to `light`, and is
  valid across all shipped manifests.

Suite: 67 → 91 passing.

---

## Known Issue — Not Addressed

`scripts/validate_manifests.py` still reports 15 errors, all
`'stable' is not one of ['experimental', 'verified', 'core', 'deprecated']`.

These were masked by the `model_tier` `additionalProperties` failure (jsonschema reports one
error per file). 15 of 16 manifests declare `stability: "stable"`, which is not a defined
level. Per `tool_plugin_spec.md`, `stability` governs visibility and auto-invoke policy —
`verified` is "not auto-invokable", `core` "follows safe_for_auto_invoke" — so mapping
`stable` to either changes runtime policy for 15 plugins. Left for a deliberate decision
rather than silently widening the enum.
