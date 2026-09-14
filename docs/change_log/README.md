# Change log

One file per significant change, named `YYYY-MM-DD-short-slug.md`. Dates are
UTC, which is why an entry can be dated a day ahead of the local clock it was
written on.

Each entry says what changed, **why it was the right call**, and what was
verified — including what was *not* run. They are written to be read months
later by someone who has lost the context, so an entry that only lists files is
not finished.

Read newest-first. This index covers the current thread only; older entries are
self-describing and listed by filename.

## Multi-provider LLM support — 2026-09-13/14

The thread that took Event Mill from one vendor to three. Plans:
`docs/specs/multi_provider_llm_clients.md` (the framework) and
`docs/specs/projector_three_vendor_run.md` (the demonstration).

| Date | Entry | What landed |
|---|---|---|
| 09-13 | `provider-seam-stage-0.md` | The seam pinned with 7 `xfail(strict=True)` tests |
| 09-13 | `provider-seam-stage-1.md` | `GeminiClient` extracted; dispatcher made vendor-free |
| 09-13 | `multi-vendor-concurrency-correction.md` | **Premise corrected**: concurrent providers and per-module override were requirements, not out of scope. Only automatic failover is forbidden |
| 09-13 | `three-vendor-secret-wiring.md` | All four LLM keys reach the container; unadopted vendors hold `placeholder` |
| 09-13 | `three-provider-connectivity-probe.md` | `probe()` — auth and ping, reported separately |
| 09-13 | `three-provider-clients.md` | Anthropic and OpenAI clients; all six tier clients green live |
| 09-14 | `llm-sdks-to-current-stable.md` | Every LLM SDK pinned to current stable with a major ceiling |
| 09-14 | `provider-tier-rekey.md` | `_clients` keyed by `(provider_id, tier)`; cross-vendor fallback forbidden in code |
| 09-14 | `cloud-run-three-provider-verification.md` | All six tier clients verified **in the container** |
| 09-14 | `connect-binds-every-provider.md` | `connect` binds every configured provider, not just Gemini |
| 09-14 | `use-provider-per-module.md` | `use <provider> [for <tool>]` — the runtime A/B control |
| 09-14 | `run-record-attribution.md` | Projector run record names the vendor that served it; `prompt_sha256` (schema v4) |
| 09-14 | `all-providers-configured-by-default.md` | `EVENTMILL_LLM_PROVIDERS` defaults to all three on every deploy path |
| 09-14 | `group-summary-provider-dimension.md` | Recurrence per provider, agreement across them |

**Next:** the live three-vendor run — Stage E of
`docs/specs/projector_three_vendor_run.md`. Nothing in the code blocks it.

## Earlier threads

- **`adversary_path_projector`** (09-09 to 09-12): phases 1, 2, 3, 3b and 3c,
  the live-run findings, run records, step state, the run-group summary and the
  group report. Phase 4 (`normalize_flow_map`, the plugin README, the manifest
  bump to 0.3.0) is still outstanding.
- **Document handling** (09-04 to 09-06): the profiler, page-range batching,
  and truncation-aware batching.
- **Routing and discovery** (09-05 to 09-08): the `also_useful_in` manifest
  field, pillar-scoped listings, pillar adjacency removed, expansion mode.
- **Model interchange** (09-12): the light tier moved to Gemini 3.8 Flash.
