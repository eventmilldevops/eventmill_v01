# 2026-10-10 — Anthropic tiers moved to Sonnet 5.5 and Opus 5.5

Operator request. `framework/llm/providers/anthropic.json` now names:

| Tier | Was | Now |
|---|---|---|
| light | `claude-sonnet-5` | `claude-sonnet-5-5` |
| heavy | `claude-opus-5` | `claude-opus-5-5` |

The heavy tier's `fallback_model_id` moved to `claude-sonnet-5-5` with it.
Limits, capabilities, thinking levels and reserves are unchanged.

Also updated: the default `model_id` in `framework/llm/clients/anthropic.py`,
the expected ids in `tests/framework/test_provider_registry.py`, and the model
tables and comments in `README.md`, `AGENTS.md`, `.env.example`,
`cloud_install/Dockerfile.cloudrun` and `docs/specs/multi_provider_llm_clients.md`.

Left as written, because they record which model produced a past output:
`framework/reference_data/telemetry_descriptor_glossary.md`, the sample answer
in the threat report analyzer README, and earlier change log entries.

## Verified

- `providers probe anthropic` from a local shell: both ids visible in the model
  list (14 models) and both pinged clean, served by the id requested.
- Models API `models.retrieve` for both ids: output cap 128,000 and context
  window 1,000,000, the same as the manifest already declared.
- `pytest -q tests/ plugins/`: 2059 passed, 1 skipped.

## Not verified

- No plugin was run on the 5.5 models. The logging compliance repeatability
  figures of the same date were measured on `claude-opus-5`.
- The PDF figures (2,407 tokens a page, 250 pages, 24 MB) and the rejected
  request parameters were measured on the previous models and are carried over
  unchanged. The manifest's `_verified` notes say so.
- Nothing was deployed.
